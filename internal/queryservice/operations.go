package queryservice

import (
	"context"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/sigalx/quordon/internal/audit"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryspec"
)

type ObjectListResult struct {
	PolicyProfile string                  `json:"policy_profile"`
	PolicyVersion string                  `json:"policy_version"`
	Datasource    string                  `json:"datasource"`
	Adapter       string                  `json:"adapter"`
	Schema        string                  `json:"schema"`
	Objects       []database.SchemaObject `json:"objects"`
}

type ObjectDescriptionResult struct {
	PolicyProfile string                       `json:"policy_profile"`
	PolicyVersion string                       `json:"policy_version"`
	Datasource    string                       `json:"datasource"`
	Adapter       string                       `json:"adapter"`
	Schema        string                       `json:"schema"`
	Name          string                       `json:"name"`
	Columns       []database.ColumnDescription `json:"columns"`
}

type SelectResult struct {
	QueryID       string                  `json:"query_id"`
	PolicyProfile string                  `json:"policy_profile"`
	PolicyVersion string                  `json:"policy_version"`
	Datasource    string                  `json:"datasource"`
	Adapter       string                  `json:"adapter"`
	Columns       []database.ResultColumn `json:"columns"`
	Rows          [][]*string             `json:"rows"`
	RowCount      int                     `json:"row_count"`
	Truncated     bool                    `json:"truncated"`
	Limits        domain.Limits           `json:"limits"`
	Warnings      []string                `json:"warnings"`
}

func (s *Service) ListObjects(
	ctx context.Context,
	requestID, principal, clientIdentifier, profileName, datasource, schema string,
) (ObjectListResult, error) {
	profile, limits, adapterName, err := s.prepareSchemaOperation(
		ctx, requestID, principal, clientIdentifier, profileName, datasource,
		domain.OperationListObjects, schema, "",
	)
	if err != nil {
		return ObjectListResult{}, err
	}
	executionContext, cancel := context.WithTimeout(ctx, limits.Deadline())
	defer cancel()
	semanticsStarted := time.Now()
	semantics, err := s.databases.IdentifierSemantics(executionContext, profile.Datasource)
	if err != nil {
		return ObjectListResult{}, s.completeSchemaError(
			ctx, requestID, principal, clientIdentifier, profileName, profile.Datasource,
			adapterName, domain.OperationListObjects, nil, nil, semanticsStarted, err,
		)
	}
	s.observeIdentifierSemantics(profile.Binding.Key(), semantics)
	authorized, err := s.policy.AuthorizeListObjects(
		profile.Binding, schema, semantics,
	)
	if err != nil {
		reason := policy.ReasonDeniedOperation
		policy.IsDenial(err, &reason)
		if auditErr := s.writeDenial(
			ctx, requestID, "", principal, clientIdentifier, profile.Binding.Profile(), profile.Binding.Datasource(),
			domain.OperationListObjects, reason, "",
		); auditErr != nil {
			return ObjectListResult{}, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return ObjectListResult{}, &Error{Kind: ErrorNotFound, Err: err}
	}
	resources := []audit.Resource{{Schema: schema}}
	if err := s.writeAllowDecision(
		ctx, requestID, "", principal, clientIdentifier, profileName, profile.Datasource,
		adapterName, domain.OperationListObjects, resources, nil, "",
	); err != nil {
		return ObjectListResult{}, err
	}
	releaseCapacity, ok := s.acquireCapacity(profile.Binding.Key())
	if !ok {
		return ObjectListResult{}, &Error{Kind: ErrorCapacity}
	}
	defer releaseCapacity()
	started := time.Now()
	objects, adapterName, databaseErr := s.databases.ListObjects(executionContext, authorized)
	if databaseErr != nil {
		return ObjectListResult{}, s.completeSchemaError(
			ctx, requestID, principal, clientIdentifier, profileName, profile.Datasource,
			adapterName, domain.OperationListObjects, resources, nil, started, databaseErr,
		)
	}
	resultBytes, databaseErr := boundedObjectListResult(objects, limits.MaxResultBytes)
	if databaseErr != nil {
		return ObjectListResult{}, s.completeSchemaError(
			ctx, requestID, principal, clientIdentifier, profileName, profile.Datasource,
			adapterName, domain.OperationListObjects, resources, nil, started, databaseErr,
		)
	}
	if err := s.writeAudit(context.WithoutCancel(ctx), audit.Event{
		Type: "operation_completion", RequestID: requestID, Principal: principal,
		ClientIdentifier: clientIdentifier, PolicyProfile: profileName,
		PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: profile.Datasource,
		Adapter: adapterName, Operation: string(domain.OperationListObjects), Outcome: "success",
		DurationMS: durationMilliseconds(started), ResultBytes: resultBytes, Resources: resources,
		Metadata: map[string]any{"object_count": len(objects)},
	}); err != nil {
		return ObjectListResult{}, &Error{Kind: ErrorServiceUnavailable, Err: err}
	}
	return ObjectListResult{
		PolicyProfile: profileName, PolicyVersion: s.policy.Version(), Datasource: profile.Datasource,
		Adapter: adapterName, Schema: schema, Objects: objects,
	}, nil
}

func (s *Service) DescribeObject(
	ctx context.Context,
	requestID, principal, clientIdentifier, profileName, datasource string,
	object queryspec.ResourceRef,
) (ObjectDescriptionResult, error) {
	profile, limits, adapterName, err := s.prepareSchemaOperation(
		ctx, requestID, principal, clientIdentifier, profileName, datasource,
		domain.OperationDescribeObject, object.Schema, object.Name,
	)
	if err != nil {
		return ObjectDescriptionResult{}, err
	}
	executionContext, cancel := context.WithTimeout(ctx, limits.Deadline())
	defer cancel()
	semanticsStarted := time.Now()
	semantics, err := s.databases.IdentifierSemantics(executionContext, profile.Datasource)
	if err != nil {
		return ObjectDescriptionResult{}, s.completeSchemaError(
			ctx, requestID, principal, clientIdentifier, profileName, profile.Datasource,
			adapterName, domain.OperationDescribeObject, nil, nil, semanticsStarted, err,
		)
	}
	s.observeIdentifierSemantics(profile.Binding.Key(), semantics)
	authorized, err := s.policy.AuthorizeDescribeObject(
		profile.Binding, object, semantics,
	)
	if err != nil {
		reason := policy.ReasonDeniedOperation
		policy.IsDenial(err, &reason)
		if auditErr := s.writeDenial(
			ctx, requestID, "", principal, clientIdentifier, profile.Binding.Profile(), profile.Binding.Datasource(),
			domain.OperationDescribeObject, reason, "",
		); auditErr != nil {
			return ObjectDescriptionResult{}, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return ObjectDescriptionResult{}, &Error{Kind: ErrorNotFound, Err: err}
	}
	resources := []audit.Resource{{Schema: object.Schema, Object: object.Name}}
	if err := s.writeAllowDecision(
		ctx, requestID, "", principal, clientIdentifier, profileName, profile.Datasource,
		adapterName, domain.OperationDescribeObject, resources, nil, "",
	); err != nil {
		return ObjectDescriptionResult{}, err
	}
	releaseCapacity, ok := s.acquireCapacity(profile.Binding.Key())
	if !ok {
		return ObjectDescriptionResult{}, &Error{Kind: ErrorCapacity}
	}
	defer releaseCapacity()
	started := time.Now()
	description, adapterName, databaseErr := s.databases.DescribeObject(
		executionContext, authorized,
	)
	if databaseErr != nil {
		completionErr := s.completeSchemaError(
			ctx, requestID, principal, clientIdentifier, profileName, profile.Datasource,
			adapterName, domain.OperationDescribeObject, resources, nil, started, databaseErr,
		)
		if database.IsKind(databaseErr, database.ErrorInvalid) {
			if serviceErr, ok := completionErr.(*Error); ok && serviceErr.Kind == ErrorServiceUnavailable {
				return ObjectDescriptionResult{}, completionErr
			}
			return ObjectDescriptionResult{}, &Error{Kind: ErrorNotFound, Err: databaseErr}
		}
		return ObjectDescriptionResult{}, completionErr
	}
	fields := make([]string, 0, len(description.Columns))
	for _, column := range description.Columns {
		fields = append(fields, column.Name)
	}
	slices.Sort(fields)
	fields = slices.Compact(fields)
	filteredDescription := database.ObjectDescription{
		Schema: description.Schema, Name: description.Name, Columns: description.Columns,
	}
	resultBytes, databaseErr := boundedObjectDescriptionResult(filteredDescription, limits.MaxResultBytes)
	if databaseErr != nil {
		return ObjectDescriptionResult{}, s.completeSchemaError(
			ctx, requestID, principal, clientIdentifier, profileName, profile.Datasource,
			adapterName, domain.OperationDescribeObject, resources, fields, started, databaseErr,
		)
	}
	if err := s.writeAudit(context.WithoutCancel(ctx), audit.Event{
		Type: "operation_completion", RequestID: requestID, Principal: principal,
		ClientIdentifier: clientIdentifier, PolicyProfile: profileName,
		PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: profile.Datasource,
		Adapter: adapterName, Operation: string(domain.OperationDescribeObject), Outcome: "success",
		DurationMS: durationMilliseconds(started), ResultBytes: resultBytes, Resources: resources, Fields: fields,
		Metadata: map[string]any{"column_count": len(description.Columns)},
	}); err != nil {
		return ObjectDescriptionResult{}, &Error{Kind: ErrorServiceUnavailable, Err: err}
	}
	return ObjectDescriptionResult{
		PolicyProfile: profileName, PolicyVersion: s.policy.Version(), Datasource: profile.Datasource,
		Adapter: adapterName, Schema: description.Schema, Name: description.Name, Columns: description.Columns,
	}, nil
}

func boundedObjectListResult(objects []database.SchemaObject, maxResultBytes int) (int, error) {
	size, ok := addBoundedSize(0, len(`{"objects":[]}`), maxResultBytes)
	if !ok {
		return 0, &database.Error{Kind: database.ErrorResultTooLarge}
	}
	for index, object := range objects {
		increment := len(`{"name":}`) + encodedJSONStringSize(object.Name)
		if index != 0 {
			increment++
		}
		size, ok = addBoundedSize(size, increment, maxResultBytes)
		if !ok {
			return 0, &database.Error{Kind: database.ErrorResultTooLarge}
		}
	}
	return size, nil
}

func boundedObjectDescriptionResult(
	description database.ObjectDescription, maxResultBytes int,
) (int, error) {
	size := len(`{"schema":,"name":,"columns":[]}`) +
		encodedJSONStringSize(description.Schema) + encodedJSONStringSize(description.Name)
	if size > maxResultBytes {
		return 0, &database.Error{Kind: database.ErrorResultTooLarge}
	}
	for index, column := range description.Columns {
		increment := encodedColumnDescriptionSize(column)
		if index != 0 {
			increment++
		}
		var ok bool
		size, ok = addBoundedSize(size, increment, maxResultBytes)
		if !ok {
			return 0, &database.Error{Kind: database.ErrorResultTooLarge}
		}
	}
	return size, nil
}

func encodedColumnDescriptionSize(column database.ColumnDescription) int {
	size := len(`{"name":,"type":,"native_type":,"nullable":,"primary_key":,"indexed":}`)
	size += encodedJSONStringSize(column.Name)
	size += encodedJSONStringSize(column.Type)
	size += encodedJSONStringSize(column.NativeType)
	size += encodedJSONBooleanSize(column.Nullable)
	size += encodedJSONBooleanSize(column.PrimaryKey)
	size += encodedJSONBooleanSize(column.Indexed)
	return size
}

func encodedJSONBooleanSize(value bool) int {
	if value {
		return len("true")
	}
	return len("false")
}

// encodedJSONStringSize mirrors encoding/json's default string escaping without
// allocating the encoded string.
func encodedJSONStringSize(value string) int {
	size := 2 // JSON string quotes.
	for index := 0; index < len(value); {
		width := 1
		encodedBytes := 1
		character := value[index]
		if character < utf8.RuneSelf {
			switch character {
			case '\\', '"', '\b', '\f', '\n', '\r', '\t':
				encodedBytes = 2
			case '<', '>', '&':
				encodedBytes = 6
			default:
				if character < 0x20 {
					encodedBytes = 6
				}
			}
		} else {
			runeValue, runeWidth := utf8.DecodeRuneInString(value[index:])
			width = runeWidth
			switch {
			case runeValue == utf8.RuneError && runeWidth == 1:
				encodedBytes = 6
			case runeValue == '\u2028' || runeValue == '\u2029':
				encodedBytes = 6
			default:
				encodedBytes = runeWidth
			}
		}
		size += encodedBytes
		index += width
	}
	return size
}

func addBoundedSize(current, increment, maximum int) (int, bool) {
	if current < 0 || increment < 0 || current > maximum || increment > maximum-current {
		return 0, false
	}
	return current + increment, true
}

func (s *Service) Select(
	ctx context.Context,
	requestID, queryID, principal, clientIdentifier string,
	bodyBytes int,
	request queryspec.Request,
) (SelectResult, error) {
	binding, assigned := s.assignedBinding(principal, request.Profile, request.Datasource, domain.OperationSelect)
	if !assigned {
		if err := s.writeDenial(
			ctx, requestID, queryID, principal, clientIdentifier, request.Profile, request.Datasource,
			domain.OperationSelect, policy.ReasonDeniedOperation, "",
		); err != nil {
			return SelectResult{}, &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return SelectResult{}, &Error{Kind: ErrorDenied, ReasonCode: policy.ReasonDeniedOperation}
	}
	limits := binding.Limits()
	if bodyBytes > limits.MaxRequestBytes {
		return SelectResult{}, &Error{Kind: ErrorTooLarge}
	}
	validated, err := queryspec.Validate(
		request.Query, limits.MaxProjectionFields, limits.MaxGroupByFields, limits.MaxOrderByFields,
		limits.MaxPredicates, limits.MaxExpressionDepth, limits.MaxParameters,
		limits.MaxRows, limits.MaxOffset,
	)
	if err != nil {
		return SelectResult{}, &Error{Kind: ErrorInvalid, Err: err}
	}
	if err := queryspec.ValidateSimpleSelect(validated); err != nil {
		return SelectResult{}, &Error{Kind: ErrorInvalid, Err: err}
	}
	queryShapeHash := queryspec.ShapeHash(validated.Spec())
	if err := s.precheckSourceText(ctx, requestID, queryID, principal, clientIdentifier, binding, domain.OperationSelect, queryShapeHash, queryspec.UsesSourceText(validated.Spec())); err != nil {
		return SelectResult{}, err
	}
	adapterName := s.databases.AdapterName(binding.Datasource())
	if !slices.Contains(s.databases.Capabilities(binding.Datasource()), domain.OperationSelect) {
		if err := s.writeAudit(context.WithoutCancel(ctx), audit.Event{
			Type: "query_completion", RequestID: requestID, QueryID: queryID, Principal: principal,
			ClientIdentifier: clientIdentifier, PolicyProfile: request.Profile,
			PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: binding.Datasource(),
			Adapter: adapterName, Operation: string(domain.OperationSelect), Outcome: "not_implemented",
			QueryShapeHash: queryShapeHash,
		}); err != nil {
			return SelectResult{}, &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return SelectResult{}, &Error{Kind: ErrorNotImplemented}
	}
	executionContext, cancel := context.WithTimeout(ctx, limits.Deadline())
	defer cancel()
	semanticsStarted := time.Now()
	semantics, err := s.databases.IdentifierSemantics(executionContext, binding.Datasource())
	if err != nil {
		return SelectResult{}, s.completeQueryError(
			ctx, requestID, queryID, principal, clientIdentifier, request.Profile,
			binding.Datasource(), adapterName, domain.OperationSelect, queryShapeHash,
			nil, nil, nil, semanticsStarted, err,
		)
	}
	s.observeIdentifierSemantics(binding.Key(), semantics)
	authorized, err := s.policy.AuthorizeSelect(binding, validated, semantics)
	if err != nil {
		reason := policy.ReasonDeniedOperation
		policy.IsDenial(err, &reason)
		if auditErr := s.writeDenial(
			ctx, requestID, queryID, principal, clientIdentifier, binding.Profile(), binding.Datasource(),
			domain.OperationSelect, reason, queryShapeHash,
		); auditErr != nil {
			return SelectResult{}, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return SelectResult{}, &Error{Kind: ErrorDenied, ReasonCode: reason, Err: err}
	}
	authorizedSpec := authorized.Query()
	resources := []audit.Resource{{Schema: authorizedSpec.Source.Schema, Object: authorizedSpec.Source.Name}}
	fields := authorized.ReferencedFields()
	if err := s.writeAllowDecision(
		ctx, requestID, queryID, principal, clientIdentifier, request.Profile,
		binding.Datasource(), adapterName, domain.OperationSelect, resources, fields, queryShapeHash,
	); err != nil {
		return SelectResult{}, err
	}
	releaseCapacity, ok := s.acquireCapacity(binding.Key())
	if !ok {
		return SelectResult{}, &Error{Kind: ErrorCapacity}
	}
	defer releaseCapacity()
	started := time.Now()
	databaseResult, adapterName, databaseErr := s.databases.Select(executionContext, authorized)
	if databaseErr != nil {
		return SelectResult{}, s.completeQueryError(
			ctx, requestID, queryID, principal, clientIdentifier, request.Profile,
			binding.Datasource(), adapterName, domain.OperationSelect, queryShapeHash,
			resources, fields, nil, started, databaseErr,
		)
	}
	if err := s.writeAudit(context.WithoutCancel(ctx), audit.Event{
		Type: "query_completion", RequestID: requestID, QueryID: queryID, Principal: principal,
		ClientIdentifier: clientIdentifier, PolicyProfile: request.Profile,
		PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: binding.Datasource(),
		Adapter: adapterName, Operation: string(domain.OperationSelect), Outcome: "success",
		DurationMS: durationMilliseconds(started), QueryShapeHash: queryShapeHash,
		ResultBytes: databaseResult.ResultBytes, Resources: resources, Fields: fields,
		Metadata: map[string]any{"row_count": databaseResult.RowCount, "truncated": databaseResult.Truncated},
	}); err != nil {
		return SelectResult{}, &Error{Kind: ErrorServiceUnavailable, Err: err}
	}
	return SelectResult{
		QueryID: queryID, PolicyProfile: request.Profile, PolicyVersion: s.policy.Version(),
		Datasource: binding.Datasource(), Adapter: adapterName, Columns: databaseResult.Columns,
		Rows: databaseResult.Rows, RowCount: databaseResult.RowCount, Truncated: databaseResult.Truncated,
		Limits: limits, Warnings: []string{},
	}, nil
}

func (s *Service) prepareSchemaOperation(
	ctx context.Context,
	requestID, principal, clientIdentifier, profileName, datasource string,
	operation domain.Operation,
	schema, object string,
) (profileResult profileState, limits domain.Limits, adapterName string, resultErr error) {
	if !validSchemaCoordinates(operation, schema, object) {
		return profileState{}, domain.Limits{}, "", &Error{Kind: ErrorInvalid}
	}
	binding, assigned := s.assignedBinding(principal, profileName, datasource, operation)
	if !assigned {
		if err := s.writeDenial(
			ctx, requestID, "", principal, clientIdentifier, profileName, datasource,
			operation, policy.ReasonDeniedOperation, "",
		); err != nil {
			return profileState{}, domain.Limits{}, "", &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return profileState{}, domain.Limits{}, "", &Error{Kind: ErrorDenied, ReasonCode: policy.ReasonDeniedOperation}
	}
	limits = binding.Limits()
	adapterName = s.databases.AdapterName(binding.Datasource())
	if !slices.Contains(s.databases.Capabilities(binding.Datasource()), operation) {
		if err := s.writeAudit(context.WithoutCancel(ctx), audit.Event{
			Type: "operation_completion", RequestID: requestID, Principal: principal,
			ClientIdentifier: clientIdentifier, PolicyProfile: profileName,
			PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: binding.Datasource(),
			Adapter: adapterName, Operation: string(operation), Outcome: "not_implemented",
		}); err != nil {
			return profileState{}, domain.Limits{}, "", &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return profileState{}, domain.Limits{}, "", &Error{Kind: ErrorNotImplemented}
	}
	return profileState{Datasource: binding.Datasource(), Binding: binding}, limits, adapterName, nil
}

func validSchemaCoordinates(operation domain.Operation, schema, object string) bool {
	switch operation {
	case domain.OperationListObjects:
		return queryspec.IsIdentifier(schema) && object == ""
	case domain.OperationDescribeObject:
		return queryspec.IsIdentifier(schema) && queryspec.IsIdentifier(object)
	default:
		return false
	}
}

type profileState struct {
	Datasource string
	Binding    policy.AuthorizedBinding
}

func (s *Service) writeAllowDecision(
	ctx context.Context,
	requestID, queryID, principal, clientIdentifier, profileName, datasource, adapterName string,
	operation domain.Operation,
	resources []audit.Resource,
	fields []string,
	queryShapeHash string,
) error {
	return s.writeAllowDecisionWithMetadata(
		ctx, requestID, queryID, principal, clientIdentifier, profileName, datasource, adapterName,
		operation, resources, fields, queryShapeHash, nil,
	)
}

func (s *Service) writeAllowDecisionWithMetadata(
	ctx context.Context,
	requestID, queryID, principal, clientIdentifier, profileName, datasource, adapterName string,
	operation domain.Operation,
	resources []audit.Resource,
	fields []string,
	queryShapeHash string,
	metadata map[string]any,
) error {
	eventType := "operation_decision"
	if queryID != "" {
		eventType = "query_decision"
	}
	if err := s.writeAudit(ctx, audit.Event{
		Type: eventType, RequestID: requestID, QueryID: queryID, Principal: principal,
		ClientIdentifier: clientIdentifier, PolicyProfile: profileName,
		PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: datasource,
		Adapter: adapterName, Operation: string(operation), Decision: "allow",
		QueryShapeHash: queryShapeHash, Resources: resources, Fields: fields, Metadata: metadata,
	}); err != nil {
		return &Error{Kind: ErrorServiceUnavailable, Err: err}
	}
	return nil
}

func (s *Service) completeQueryError(
	ctx context.Context,
	requestID, queryID, principal, clientIdentifier, profileName, datasource, adapterName string,
	operation domain.Operation,
	queryShapeHash string,
	resources []audit.Resource,
	fields []string,
	metadata map[string]any,
	started time.Time,
	databaseErr error,
) error {
	if err := s.writeAudit(context.WithoutCancel(ctx), audit.Event{
		Type: "query_completion", RequestID: requestID, QueryID: queryID, Principal: principal,
		ClientIdentifier: clientIdentifier, PolicyProfile: profileName,
		PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: datasource,
		Adapter: adapterName, Operation: string(operation), Outcome: "error",
		ErrorKind: string(classifyDatabaseAuditError(databaseErr)), DurationMS: durationMilliseconds(started),
		QueryShapeHash: queryShapeHash, Resources: resources, Fields: fields, Metadata: metadata,
	}); err != nil {
		return &Error{Kind: ErrorServiceUnavailable, Err: err}
	}
	return mapDatabaseError(databaseErr)
}

func (s *Service) completeSchemaError(
	ctx context.Context,
	requestID, principal, clientIdentifier, profileName, datasource, adapterName string,
	operation domain.Operation,
	resources []audit.Resource,
	fields []string,
	started time.Time,
	databaseErr error,
) error {
	if err := s.writeAudit(context.WithoutCancel(ctx), audit.Event{
		Type: "operation_completion", RequestID: requestID, Principal: principal,
		ClientIdentifier: clientIdentifier, PolicyProfile: profileName,
		PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: datasource,
		Adapter: adapterName, Operation: string(operation), Outcome: "error",
		ErrorKind: string(classifyDatabaseAuditError(databaseErr)), DurationMS: durationMilliseconds(started),
		Resources: resources, Fields: fields,
	}); err != nil {
		return &Error{Kind: ErrorServiceUnavailable, Err: err}
	}
	return mapDatabaseError(databaseErr)
}

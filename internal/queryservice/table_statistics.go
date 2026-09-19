package queryservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sigalx/quordon/internal/audit"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryspec"
)

type tableStatisticsResponse struct {
	PolicyProfile string                      `json:"policy_profile"`
	PolicyVersion string                      `json:"policy_version"`
	Datasource    string                      `json:"datasource"`
	Adapter       string                      `json:"adapter"`
	Schema        string                      `json:"schema"`
	Name          string                      `json:"name"`
	ObservedAt    string                      `json:"observed_at"`
	Engine        string                      `json:"engine"`
	Table         database.TableStatistics    `json:"table"`
	Partitioning  database.PartitioningResult `json:"partitioning"`
}

func (s *Service) DescribeObjectStatistics(
	ctx context.Context,
	requestID, principal, clientIdentifier, profileName, datasource string,
	object queryspec.ResourceRef,
) ([]byte, error) {
	started := time.Now()
	if !queryspec.IsIdentifier(object.Schema) || !queryspec.IsIdentifier(object.Name) {
		return nil, &Error{Kind: ErrorInvalid}
	}
	binding, assigned := s.assignedBinding(principal, profileName, datasource, domain.OperationDescribeObjectStatistics)
	if !assigned {
		if err := s.writeDenial(
			ctx, requestID, "", principal, clientIdentifier, profileName, datasource,
			domain.OperationDescribeObjectStatistics, policy.ReasonDeniedOperation, "",
		); err != nil {
			return nil, &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return nil, &Error{Kind: ErrorDenied, ReasonCode: policy.ReasonDeniedOperation}
	}
	limits := binding.Limits()
	adapterName := s.databases.AdapterName(binding.Datasource())
	if !slices.Contains(s.databases.Capabilities(binding.Datasource()), domain.OperationDescribeObjectStatistics) {
		if err := s.completeObjectStatistics(
			ctx, requestID, principal, clientIdentifier, profileName, binding.Datasource(), adapterName,
			"not_implemented", "", started, 0, nil, 0, 0,
		); err != nil {
			return nil, &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return nil, &Error{Kind: ErrorNotImplemented}
	}
	executionContext, cancel := context.WithTimeout(ctx, limits.Deadline())
	defer cancel()
	semantics, err := s.databases.IdentifierSemantics(executionContext, binding.Datasource())
	if err != nil {
		if auditErr := s.completeObjectStatistics(
			ctx, requestID, principal, clientIdentifier, profileName, binding.Datasource(), adapterName,
			"error", string(classifyDatabaseAuditError(err)), started, 0, nil, 0, 0,
		); auditErr != nil {
			return nil, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return nil, mapDatabaseError(err)
	}
	s.observeIdentifierSemantics(binding.Key(), semantics)
	authorized, err := s.policy.AuthorizeObjectStatistics(
		binding, clientIdentifier, adapterName, object, semantics,
	)
	if err != nil {
		reason := policy.ReasonDeniedOperation
		policy.IsDenial(err, &reason)
		if auditErr := s.writeObjectStatisticsDenial(
			ctx, requestID, principal, clientIdentifier, profileName,
			binding.Datasource(), adapterName, reason,
		); auditErr != nil {
			return nil, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		if reason == policy.ReasonDeniedResource {
			return nil, &Error{Kind: ErrorNotFound, Err: err}
		}
		return nil, &Error{Kind: ErrorDenied, ReasonCode: reason, Err: err}
	}
	resources := []audit.Resource{{Schema: authorized.Schema(), Object: authorized.Object()}}
	if err := s.writeAllowDecision(
		ctx, requestID, "", principal, clientIdentifier, profileName, authorized.Datasource(),
		authorized.Adapter(), domain.OperationDescribeObjectStatistics, resources, nil, "",
	); err != nil {
		return nil, err
	}
	envelopeBaseBytes, ok := tableStatisticsMinimumEnvelopeSize(
		profileName, s.policy.Version(), authorized.Datasource(), authorized.Adapter(),
		authorized.Schema(), authorized.Object(), limits.MaxResultBytes,
	)
	if !ok {
		databaseErr := &database.Error{Kind: database.ErrorResultTooLarge}
		if auditErr := s.completeObjectStatistics(
			ctx, requestID, principal, clientIdentifier, profileName, authorized.Datasource(), authorized.Adapter(),
			"error", string(classifyDatabaseAuditError(databaseErr)), started, 0, resources, 0, 0,
		); auditErr != nil {
			return nil, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return nil, mapDatabaseError(databaseErr)
	}
	releaseCapacity, capacityOK := s.acquireCapacity(binding.Key())
	if !capacityOK {
		if auditErr := s.completeObjectStatistics(
			ctx, requestID, principal, clientIdentifier, profileName, authorized.Datasource(), authorized.Adapter(),
			"error", "capacity", started, 0, resources, 0, 0,
		); auditErr != nil {
			return nil, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return nil, &Error{Kind: ErrorCapacity}
	}
	defer releaseCapacity()
	databaseResult, adapterName, databaseErr := s.databases.DescribeObjectStatistics(
		executionContext, authorized, envelopeBaseBytes,
	)
	if databaseErr != nil {
		if auditErr := s.completeObjectStatistics(
			ctx, requestID, principal, clientIdentifier, profileName, authorized.Datasource(), adapterName,
			"error", string(classifyDatabaseAuditError(databaseErr)), started, 0, resources, 0, 0,
		); auditErr != nil {
			return nil, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return nil, mapDatabaseError(databaseErr)
	}
	if err := validateObjectStatisticsResult(databaseResult); err != nil {
		if auditErr := s.completeObjectStatistics(
			ctx, requestID, principal, clientIdentifier, profileName, authorized.Datasource(), adapterName,
			"error", "internal", started, 0, resources, 0, 0,
		); auditErr != nil {
			return nil, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return nil, &Error{Kind: ErrorInternal, Err: err}
	}
	response := tableStatisticsResponse{
		PolicyProfile: profileName, PolicyVersion: s.policy.Version(), Datasource: authorized.Datasource(),
		Adapter: adapterName, Schema: authorized.Schema(), Name: authorized.Object(),
		ObservedAt: databaseResult.ObservedAt, Engine: databaseResult.Engine,
		Table: databaseResult.Table, Partitioning: databaseResult.Partitioning,
	}
	payload, err := json.Marshal(response)
	if err != nil || len(payload) != databaseResult.ResultBytes || len(payload) > limits.MaxResultBytes {
		invariantErr := errors.New("table statistics response encoding invariant failed")
		if auditErr := s.completeObjectStatistics(
			ctx, requestID, principal, clientIdentifier, profileName, authorized.Datasource(), adapterName,
			"error", "internal", started, 0, resources, 0, 0,
		); auditErr != nil {
			return nil, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return nil, &Error{Kind: ErrorInternal, Err: invariantErr}
	}
	if err := s.completeObjectStatistics(
		ctx, requestID, principal, clientIdentifier, profileName, authorized.Datasource(), adapterName,
		"success", "", started, len(payload), resources,
		databaseResult.PartitionCount, databaseResult.SubpartitionCount,
	); err != nil {
		return nil, &Error{Kind: ErrorServiceUnavailable, Err: err}
	}
	return payload, nil
}

func validateObjectStatisticsResult(result database.ObjectStatisticsResult) error {
	if len(result.ObservedAt) < len("0000-00-00T00:00:00Z") || len(result.ObservedAt) > len("0000-00-00T00:00:00.000000000Z") {
		return errors.New("adapter returned a noncanonical statistics timestamp")
	}
	observedAt, err := time.Parse(time.RFC3339Nano, result.ObservedAt)
	if err != nil || observedAt.Location() != time.UTC || observedAt.Format(time.RFC3339Nano) != result.ObservedAt {
		return errors.New("adapter returned a noncanonical statistics timestamp")
	}
	if result.Engine != "InnoDB" ||
		!validStatisticsMetric(result.Table.EstimatedRows, true) ||
		!validStatisticsMetric(result.Table.DataBytes, true) ||
		!validStatisticsMetric(result.Table.IndexBytes, true) ||
		!validStatisticsMetric(result.Table.AutoIncrement, false) {
		return errors.New("adapter returned invalid table statistics")
	}
	partitionCount, subpartitionCount, err := validatePartitioningResult(result.Partitioning)
	if err != nil {
		return err
	}
	if result.PartitionCount != partitionCount || result.SubpartitionCount != subpartitionCount {
		return errors.New("adapter returned inconsistent partition counts")
	}
	return nil
}

func validatePartitioningResult(partitioning database.PartitioningResult) (int, int, error) {
	partitionNames := make(map[string]struct{})
	subpartitionNames := make(map[string]struct{})
	switch partitioning.Kind {
	case "none":
		if partitioning.Method != "" || partitioning.SubpartitionMethod != "" ||
			len(partitioning.Partitions) != 0 || len(partitioning.PartitionGroups) != 0 {
			return 0, 0, errors.New("adapter returned an invalid unpartitioned branch")
		}
		return 0, 0, nil
	case "partitioned":
		if !validStatisticsPartitionMethod(partitioning.Method) || partitioning.SubpartitionMethod != "" ||
			len(partitioning.PartitionGroups) != 0 || len(partitioning.Partitions) == 0 ||
			len(partitioning.Partitions) > maxPhysicalPartitionAuditCount {
			return 0, 0, errors.New("adapter returned an invalid partitioned branch")
		}
		for index, entry := range partitioning.Partitions {
			if entry.Ordinal != index+1 || !validStatisticsMetadataName(entry.Name) ||
				!insertStatisticsMetadataName(partitionNames, entry.Name) ||
				!validPartitionStatistics(entry.Statistics) {
				return 0, 0, errors.New("adapter returned an invalid partition entry")
			}
		}
		return len(partitioning.Partitions), 0, nil
	case "subpartitioned":
		if !validStatisticsSubpartitionParentMethod(partitioning.Method) ||
			!validStatisticsSubpartitionMethod(partitioning.SubpartitionMethod) ||
			len(partitioning.Partitions) != 0 || len(partitioning.PartitionGroups) == 0 ||
			len(partitioning.PartitionGroups) > maxPhysicalPartitionAuditCount {
			return 0, 0, errors.New("adapter returned an invalid subpartitioned branch")
		}
		leafCount := 0
		for groupIndex, group := range partitioning.PartitionGroups {
			if group.Ordinal != groupIndex+1 || !validStatisticsMetadataName(group.Name) ||
				!insertStatisticsMetadataName(partitionNames, group.Name) || len(group.Subpartitions) == 0 {
				return 0, 0, errors.New("adapter returned an invalid partition group")
			}
			if len(group.Subpartitions) > maxPhysicalPartitionAuditCount-leafCount {
				return 0, 0, errors.New("adapter returned too many subpartitions")
			}
			for entryIndex, entry := range group.Subpartitions {
				if entry.Ordinal != entryIndex+1 || !validStatisticsMetadataName(entry.Name) ||
					!insertStatisticsMetadataName(subpartitionNames, entry.Name) ||
					!validPartitionStatistics(entry.Statistics) {
					return 0, 0, errors.New("adapter returned an invalid subpartition entry")
				}
			}
			leafCount += len(group.Subpartitions)
		}
		return len(partitioning.PartitionGroups), leafCount, nil
	default:
		return 0, 0, errors.New("adapter returned an unknown partitioning branch")
	}
}

func validStatisticsMetric(metric *database.UnsignedMetric, estimated bool) bool {
	if metric == nil {
		return true
	}
	if metric.Estimated != estimated || len(metric.Value) == 0 || len(metric.Value) > 20 ||
		(len(metric.Value) > 1 && metric.Value[0] == '0') {
		return false
	}
	for _, character := range metric.Value {
		if character < '0' || character > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(metric.Value, 10, 64)
	return err == nil
}

func validPartitionStatistics(statistics database.PartitionStatistics) bool {
	return validStatisticsMetric(statistics.EstimatedRows, true) &&
		validStatisticsMetric(statistics.DataBytes, true) &&
		validStatisticsMetric(statistics.IndexBytes, true)
}

func validStatisticsMetadataName(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 64 {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u061c' || character == '\u200e' || character == '\u200f' ||
			(character >= '\u202a' && character <= '\u202e') ||
			(character >= '\u2066' && character <= '\u2069') {
			return false
		}
	}
	return true
}

func insertStatisticsMetadataName(names map[string]struct{}, value string) bool {
	var key strings.Builder
	key.Grow(len(value))
	for _, character := range value {
		canonical := character
		for folded := unicode.SimpleFold(character); folded != character; folded = unicode.SimpleFold(folded) {
			if folded < canonical {
				canonical = folded
			}
		}
		key.WriteRune(canonical)
	}
	canonical := key.String()
	if _, exists := names[canonical]; exists {
		return false
	}
	names[canonical] = struct{}{}
	return true
}

func validStatisticsPartitionMethod(value string) bool {
	return value == "hash" || value == "linear_hash" || value == "key" || value == "linear_key" ||
		value == "range" || value == "range_columns" || value == "list" || value == "list_columns"
}

func validStatisticsSubpartitionParentMethod(value string) bool {
	return value == "range" || value == "range_columns" || value == "list" || value == "list_columns"
}

func validStatisticsSubpartitionMethod(value string) bool {
	return value == "hash" || value == "linear_hash" || value == "key" || value == "linear_key"
}

func (s *Service) writeObjectStatisticsDenial(
	ctx context.Context,
	requestID, principal, clientIdentifier, profileName, datasource, adapterName, reason string,
) error {
	return s.writeAudit(context.WithoutCancel(ctx), audit.Event{
		Type: "operation_decision", RequestID: requestID, Principal: principal,
		ClientIdentifier: clientIdentifier, PolicyProfile: profileName,
		PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: datasource,
		Adapter: adapterName, Operation: string(domain.OperationDescribeObjectStatistics),
		Decision: "deny", ReasonCode: reason,
	})
}

func (s *Service) validateTableStatisticsAuditBounds(maximum int) error {
	maximumDuration := int64(math.MaxInt64)
	requestID := strings.Repeat("r", 64)
	maximumIdentifier := strings.Repeat("i", queryspec.ProtocolMaxIdentifierBytes)
	identity := s.queryShapeAuditIdentity
	if identity.principal != "" && identity.clientIdentifier != "" {
		denial := audit.Event{
			Timestamp: time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC),
			Type:      "operation_decision", RequestID: requestID,
			Principal: identity.principal, ClientIdentifier: identity.clientIdentifier,
			PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(),
			Operation: string(domain.OperationDescribeObjectStatistics),
			Decision:  "deny", ReasonCode: policy.ReasonDeniedOperation,
		}
		if err := requireAuditEventBound(denial, maximum); err != nil {
			return fmt.Errorf("table-statistics denial audit bound: %w", err)
		}
	}
	for key, identity := range s.bindingAuditIdentities {
		_, operations, _, ok := s.policy.ProfileBinding(key.Profile)
		if !ok || !slices.Contains(operations, domain.OperationDescribeObjectStatistics) {
			continue
		}
		adapterName := s.databases.AdapterName(key.Datasource)
		resourceDenial := audit.Event{
			Timestamp: time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC),
			Type:      "operation_decision", RequestID: requestID,
			Principal: identity.principal, ClientIdentifier: identity.clientIdentifier,
			PolicyProfile: key.Profile, PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(),
			Datasource: key.Datasource, Adapter: adapterName,
			Operation: string(domain.OperationDescribeObjectStatistics),
			Decision:  "deny", ReasonCode: policy.ReasonDeniedResource,
		}
		if err := requireAuditEventBound(resourceDenial, maximum); err != nil {
			return fmt.Errorf("table-statistics resource-denial audit bound: %w", err)
		}
		base := audit.Event{
			Timestamp: resourceDenial.Timestamp, Type: "operation_completion", RequestID: requestID,
			Principal: identity.principal, ClientIdentifier: identity.clientIdentifier,
			PolicyProfile: key.Profile, PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(),
			Datasource: key.Datasource, Adapter: adapterName,
			Operation: string(domain.OperationDescribeObjectStatistics),
			Outcome:   "error", ErrorKind: "upstream", DurationMS: &maximumDuration,
		}
		if err := requireAuditEventBound(base, maximum); err != nil {
			return fmt.Errorf("table-statistics pre-token audit bound: %w", err)
		}
		base.Resources = []audit.Resource{{Schema: maximumIdentifier, Object: maximumIdentifier}}
		if err := requireAuditEventBound(base, maximum); err != nil {
			return fmt.Errorf("table-statistics post-token audit bound: %w", err)
		}
		base.Outcome, base.ErrorKind, base.ResultBytes = "success", "", maximum
		base.Metadata = map[string]any{
			"partition_count":    maxPhysicalPartitionAuditCount,
			"subpartition_count": maxPhysicalPartitionAuditCount,
		}
		if err := requireAuditEventBound(base, maximum); err != nil {
			return fmt.Errorf("table-statistics success audit bound: %w", err)
		}
	}
	return nil
}

const maxPhysicalPartitionAuditCount = 8192

func requireAuditEventBound(event audit.Event, maximum int) error {
	size, within, err := queryShapeAuditEventJSONSizeWithin(event, maximum-1) // JSONSink appends a newline.
	if err != nil {
		return err
	}
	if !within {
		return fmt.Errorf("event exceeds %d bytes after %d counted bytes", maximum, size)
	}
	return nil
}

func tableStatisticsMinimumEnvelopeSize(
	profile, policyVersion, datasource, adapter, schema, object string, maximum int,
) (int, bool) {
	size := len(`{"policy_profile":,"policy_version":,"datasource":,"adapter":,"schema":,"name":,"observed_at":,"engine":,"table":{"estimated_rows":null,"data_bytes":null,"index_bytes":null,"auto_increment":null},"partitioning":{"kind":"none"}}`)
	if size > maximum {
		return 0, false
	}
	for _, value := range []string{
		profile, policyVersion, datasource, adapter, schema, object,
		"0000-00-00T00:00:00Z", "InnoDB",
	} {
		var ok bool
		size, ok = addBoundedSize(size, encodedJSONStringSize(value), maximum)
		if !ok {
			return 0, false
		}
	}
	return size, true
}

func (s *Service) completeObjectStatistics(
	ctx context.Context,
	requestID, principal, clientIdentifier, profileName, datasource, adapterName,
	outcome, errorKind string,
	started time.Time,
	resultBytes int,
	resources []audit.Resource,
	partitionCount, subpartitionCount int,
) error {
	event := audit.Event{
		Type: "operation_completion", RequestID: requestID, Principal: principal,
		ClientIdentifier: clientIdentifier, PolicyProfile: profileName,
		PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: datasource,
		Adapter: adapterName, Operation: string(domain.OperationDescribeObjectStatistics),
		Outcome: outcome, ErrorKind: errorKind, DurationMS: durationMilliseconds(started),
		ResultBytes: resultBytes, Resources: resources,
	}
	if outcome == "success" {
		event.Metadata = map[string]any{
			"partition_count": partitionCount, "subpartition_count": subpartitionCount,
		}
	}
	return s.writeAudit(context.WithoutCancel(ctx), event)
}

package queryservice

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sigalx/quordon/internal/audit"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryspec"
)

type KeysetPageResult struct {
	HasMore    bool                           `json:"has_more"`
	NextCursor *[]queryspec.KeysetCursorValue `json:"next_cursor,omitempty"`
}

type KeysetSelectResult struct {
	Kind          string                  `json:"kind"`
	QueryID       string                  `json:"query_id"`
	PolicyProfile string                  `json:"policy_profile"`
	PolicyVersion string                  `json:"policy_version"`
	Shape         string                  `json:"shape"`
	Datasource    string                  `json:"datasource"`
	Adapter       string                  `json:"adapter"`
	Columns       []database.ResultColumn `json:"columns"`
	Rows          [][]*string             `json:"rows"`
	RowCount      int                     `json:"row_count"`
	Truncated     bool                    `json:"truncated"`
	Page          KeysetPageResult        `json:"page"`
	Limits        domain.Limits           `json:"limits"`
	Warnings      []string                `json:"warnings"`
	encodedJSON   []byte
}

// EncodedJSON returns the already validated, byte-budgeted response produced
// by SelectKeyset. HTTP transport must treat the returned bytes as read-only so
// it does not marshal a near-limit result a second time.
func (r KeysetSelectResult) EncodedJSON() []byte { return r.encodedJSON }

func (s *Service) SelectKeyset(
	ctx context.Context,
	requestID, queryID, principal, clientIdentifier string,
	bodyBytes int,
	request queryspec.KeysetRequest,
) (KeysetSelectResult, error) {
	if bodyBytes < 0 {
		return KeysetSelectResult{}, &Error{Kind: ErrorInvalid, Err: errors.New("invalid request byte count")}
	}
	hard := s.policy.HardLimits()
	validated, err := queryspec.ValidateKeyset(
		request, hard.MaxProjectionFields, hard.MaxOrderByFields,
		hard.MaxPredicates, hard.MaxExpressionDepth, hard.MaxParameters, hard.MaxRows,
	)
	if err != nil {
		return KeysetSelectResult{}, &Error{Kind: ErrorInvalid, Err: err}
	}
	profile, assigned := s.assignedProfile(principal, request.Profile)
	if !assigned || !slices.Contains(profile.Operations, domain.OperationSelectKeyset) {
		if auditErr := s.writeKeysetOperationDenial(
			ctx, requestID, queryID, principal, clientIdentifier, request.Profile,
		); auditErr != nil {
			return KeysetSelectResult{}, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return KeysetSelectResult{}, &Error{Kind: ErrorDenied, ReasonCode: policy.ReasonDeniedOperation}
	}
	limits := hard.Min(profile.Limits)
	if bodyBytes > limits.MaxRequestBytes {
		return KeysetSelectResult{}, &Error{Kind: ErrorTooLarge}
	}
	validated, err = queryspec.RevalidateKeyset(
		validated, limits.MaxProjectionFields, limits.MaxOrderByFields,
		limits.MaxPredicates, limits.MaxExpressionDepth, limits.MaxParameters, limits.MaxRows,
	)
	if err != nil {
		return KeysetSelectResult{}, &Error{Kind: ErrorInvalid, Err: err}
	}
	queryShapeHash := preAuthorizationKeysetShapeHash(validated)
	if err := s.policy.PrecheckKeysetSelect(principal, request.Profile, validated); err != nil {
		reason := policy.ReasonDeniedQueryFeature
		if !policy.IsDenial(err, &reason) {
			return KeysetSelectResult{}, &Error{Kind: ErrorInvalid, Err: err}
		}
		if auditErr := s.writeDenial(
			ctx, requestID, queryID, principal, clientIdentifier, request.Profile,
			domain.OperationSelectKeyset, reason, queryShapeHash,
		); auditErr != nil {
			return KeysetSelectResult{}, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return KeysetSelectResult{}, &Error{Kind: ErrorDenied, ReasonCode: reason, Err: err}
	}
	adapterName := s.databases.AdapterName(profile.Datasource)
	started := time.Now()
	if !slices.Contains(s.databases.Capabilities(profile.Datasource), domain.OperationSelectKeyset) {
		if auditErr := s.audit.Write(context.WithoutCancel(ctx), audit.Event{
			Type: "query_completion", RequestID: requestID, QueryID: queryID,
			Principal: principal, ClientIdentifier: clientIdentifier, PolicyProfile: request.Profile,
			PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: profile.Datasource,
			Adapter: adapterName, Operation: string(domain.OperationSelectKeyset), Outcome: "not_implemented",
			DurationMS: durationMilliseconds(started), QueryShapeHash: queryShapeHash,
			Metadata: map[string]any{"keyset_shape": request.Shape},
		}); auditErr != nil {
			return KeysetSelectResult{}, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return KeysetSelectResult{}, &Error{Kind: ErrorNotImplemented}
	}
	budget, err := keysetEnvelopeBudget(
		queryID, request.Profile, s.policy.Version(), request.Shape,
		profile.Datasource, adapterName, limits,
	)
	if err != nil {
		if auditErr := s.audit.Write(context.WithoutCancel(ctx), audit.Event{
			Type: "query_completion", RequestID: requestID, QueryID: queryID,
			Principal: principal, ClientIdentifier: clientIdentifier, PolicyProfile: request.Profile,
			PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: profile.Datasource,
			Adapter: adapterName, Operation: string(domain.OperationSelectKeyset), Outcome: "error",
			ErrorKind: string(ErrorInternal), DurationMS: durationMilliseconds(started),
			QueryShapeHash: queryShapeHash, Metadata: map[string]any{"keyset_shape": request.Shape},
		}); auditErr != nil {
			return KeysetSelectResult{}, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return KeysetSelectResult{}, &Error{Kind: ErrorInternal, Err: err}
	}
	if budget.FinalBaseBytes > limits.MaxResultBytes || budget.MoreBaseBytes > limits.MaxResultBytes {
		return KeysetSelectResult{}, s.completeQueryError(
			ctx, requestID, queryID, principal, clientIdentifier, request.Profile,
			profile.Datasource, adapterName, domain.OperationSelectKeyset, queryShapeHash,
			nil, nil, map[string]any{"keyset_shape": request.Shape}, started,
			&database.Error{Kind: database.ErrorResultTooLarge},
		)
	}
	executionContext, cancel := context.WithTimeout(ctx, limits.Deadline())
	defer cancel()
	semantics, err := s.databases.IdentifierSemantics(executionContext, profile.Datasource)
	if err != nil {
		return KeysetSelectResult{}, s.completeQueryError(
			ctx, requestID, queryID, principal, clientIdentifier, request.Profile,
			profile.Datasource, adapterName, domain.OperationSelectKeyset, queryShapeHash,
			nil, nil, map[string]any{"keyset_shape": request.Shape}, started, err,
		)
	}
	s.observeIdentifierSemantics(request.Profile, semantics)
	authorized, err := s.policy.AuthorizeKeysetSelect(
		principal, clientIdentifier, request.Profile, adapterName, validated, semantics,
	)
	if err != nil {
		reason := ""
		if !policy.IsDenial(err, &reason) {
			return KeysetSelectResult{}, s.completeQueryError(
				ctx, requestID, queryID, principal, clientIdentifier, request.Profile,
				profile.Datasource, adapterName, domain.OperationSelectKeyset, queryShapeHash,
				nil, nil, map[string]any{"keyset_shape": request.Shape}, started,
				&database.Error{Kind: database.ErrorInvalid, Err: err},
			)
		}
		if auditErr := s.writeDenial(
			ctx, requestID, queryID, principal, clientIdentifier, request.Profile,
			domain.OperationSelectKeyset, reason, queryShapeHash,
		); auditErr != nil {
			return KeysetSelectResult{}, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return KeysetSelectResult{}, &Error{Kind: ErrorDenied, ReasonCode: reason, Err: err}
	}
	authorizedRequest := authorized.Query()
	queryShapeHash = queryspec.KeysetShapeHash(authorizedRequest)
	resources := []audit.Resource{{Schema: authorizedRequest.Query.Source.Schema, Object: authorizedRequest.Query.Source.Name}}
	fields := authorized.ReferencedFields()
	metadata := keysetShapeAuditMetadata(authorized.ShapeName())
	if err := s.writeAllowDecisionWithMetadata(
		ctx, requestID, queryID, principal, clientIdentifier, request.Profile,
		authorized.Datasource(), authorized.Adapter(), domain.OperationSelectKeyset,
		resources, fields, queryShapeHash, metadata,
	); err != nil {
		return KeysetSelectResult{}, err
	}
	releaseCapacity, ok := s.acquireCapacity(request.Profile)
	if !ok {
		if auditErr := s.audit.Write(context.WithoutCancel(ctx), audit.Event{
			Type: "query_completion", RequestID: requestID, QueryID: queryID,
			Principal: principal, ClientIdentifier: clientIdentifier, PolicyProfile: request.Profile,
			PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: authorized.Datasource(),
			Adapter: authorized.Adapter(), Operation: string(domain.OperationSelectKeyset), Outcome: "error",
			ErrorKind: string(ErrorCapacity), DurationMS: durationMilliseconds(started),
			QueryShapeHash: queryShapeHash, Resources: resources, Fields: fields, Metadata: metadata,
		}); auditErr != nil {
			return KeysetSelectResult{}, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return KeysetSelectResult{}, &Error{Kind: ErrorCapacity}
	}
	defer releaseCapacity()
	databaseResult, adapterName, databaseErr := s.databases.SelectKeyset(executionContext, authorized, budget)
	if databaseErr != nil {
		return KeysetSelectResult{}, s.completeQueryError(
			ctx, requestID, queryID, principal, clientIdentifier, request.Profile,
			authorized.Datasource(), adapterName, domain.OperationSelectKeyset,
			queryShapeHash, resources, fields, metadata, started, databaseErr,
		)
	}
	response := makeKeysetResponse(
		queryID, request.Profile, s.policy.Version(), authorized.ShapeName(),
		authorized.Datasource(), adapterName, limits, databaseResult,
	)
	validationErr := validateKeysetResponse(response, authorizedRequest)
	var payload []byte
	if validationErr == nil {
		payload, err = json.Marshal(response)
	}
	if validationErr != nil || err != nil || len(payload) != databaseResult.ResultBytes || len(payload) > limits.MaxResultBytes {
		invariantErr := errors.New("keyset response encoding invariant failed")
		if auditErr := s.audit.Write(context.WithoutCancel(ctx), audit.Event{
			Type: "query_completion", RequestID: requestID, QueryID: queryID,
			Principal: principal, ClientIdentifier: clientIdentifier, PolicyProfile: request.Profile,
			PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: authorized.Datasource(),
			Adapter: adapterName, Operation: string(domain.OperationSelectKeyset), Outcome: "error",
			ErrorKind: string(ErrorInternal), DurationMS: durationMilliseconds(started),
			QueryShapeHash: queryShapeHash, Resources: resources, Fields: fields, Metadata: metadata,
		}); auditErr != nil {
			return KeysetSelectResult{}, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return KeysetSelectResult{}, &Error{Kind: ErrorInternal, Err: invariantErr}
	}
	response.encodedJSON = payload
	metadata = keysetSuccessAuditMetadata(authorized.ShapeName(), databaseResult.HasMore, databaseResult.RowCount)
	if auditErr := s.audit.Write(context.WithoutCancel(ctx), audit.Event{
		Type: "query_completion", RequestID: requestID, QueryID: queryID,
		Principal: principal, ClientIdentifier: clientIdentifier, PolicyProfile: request.Profile,
		PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: authorized.Datasource(),
		Adapter: adapterName, Operation: string(domain.OperationSelectKeyset), Outcome: "success",
		DurationMS: durationMilliseconds(started), ResultBytes: databaseResult.ResultBytes,
		QueryShapeHash: queryShapeHash, Resources: resources, Fields: fields, Metadata: metadata,
	}); auditErr != nil {
		return KeysetSelectResult{}, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
	}
	return response, nil
}

// Before datasource semantics are available, use the same conservative
// case-insensitive normalization as the policy precheck. This keeps denial
// hashes stable for equivalent MySQL field spellings and commutative filter
// order without claiming that any resource has already been authorized.
func preAuthorizationKeysetShapeHash(request queryspec.ValidatedKeyset) string {
	semantics := domain.IdentifierSemantics{
		CaseInsensitiveSchemas: true,
		CaseInsensitiveObjects: true,
		CaseInsensitiveFields:  true,
	}
	if normalized, err := queryspec.NormalizeKeysetIdentifiers(request, semantics); err == nil {
		return queryspec.KeysetShapeHash(normalized.Request())
	}
	return queryspec.KeysetShapeHash(request.Request())
}

func makeKeysetResponse(
	queryID, profile, policyVersion, shape, datasource, adapter string,
	limits domain.Limits,
	result database.KeysetSelectResult,
) KeysetSelectResult {
	page := KeysetPageResult{HasMore: result.HasMore}
	if result.HasMore {
		cursor := slices.Clone(result.NextCursor)
		page.NextCursor = &cursor
	}
	return KeysetSelectResult{
		Kind: "keyset", QueryID: queryID, PolicyProfile: profile, PolicyVersion: policyVersion,
		Shape: shape, Datasource: datasource, Adapter: adapter, Columns: result.Columns, Rows: result.Rows,
		RowCount: result.RowCount, Truncated: result.HasMore, Page: page, Limits: limits, Warnings: []string{},
	}
}

func keysetEnvelopeBudget(
	queryID, profile, policyVersion, shape, datasource, adapter string,
	limits domain.Limits,
) (database.KeysetEnvelopeBudget, error) {
	base := database.KeysetSelectResult{Columns: []database.ResultColumn{}, Rows: [][]*string{}}
	finalPayload, err := json.Marshal(makeKeysetResponse(
		queryID, profile, policyVersion, shape, datasource, adapter, limits, base,
	))
	if err != nil {
		return database.KeysetEnvelopeBudget{}, err
	}
	base.HasMore = true
	base.NextCursor = []queryspec.KeysetCursorValue{}
	morePayload, err := json.Marshal(makeKeysetResponse(
		queryID, profile, policyVersion, shape, datasource, adapter, limits, base,
	))
	if err != nil {
		return database.KeysetEnvelopeBudget{}, err
	}
	return database.KeysetEnvelopeBudget{FinalBaseBytes: len(finalPayload), MoreBaseBytes: len(morePayload)}, nil
}

func validateKeysetResponse(result KeysetSelectResult, request queryspec.NormalizedKeysetRequest) error {
	if result.Kind != "keyset" || result.QueryID == "" || result.PolicyProfile == "" || result.PolicyVersion == "" ||
		result.PolicyProfile != request.Profile || result.Shape != request.Shape ||
		result.Datasource == "" || result.Adapter != string(domain.AdapterMySQL8) ||
		result.Rows == nil ||
		len(result.Columns) != len(request.Query.Projection) || result.RowCount != len(result.Rows) ||
		len(result.Rows) > request.Query.Limit ||
		result.Truncated != result.Page.HasMore || result.Page.HasMore != (result.Page.NextCursor != nil) {
		return errors.New("invalid keyset result envelope")
	}
	if result.Page.HasMore && (len(result.Rows) == 0 || len(*result.Page.NextCursor) != len(request.Query.OrderBy)) {
		return errors.New("invalid keyset continuation state")
	}
	outputs := make(map[string]struct{}, len(result.Columns))
	for index, column := range result.Columns {
		expected := request.Query.Projection[index].Field
		if request.Query.Projection[index].Alias != "" {
			expected = request.Query.Projection[index].Alias
		}
		if column.Name != expected || !queryspec.IsIdentifier(column.Name) {
			return errors.New("invalid keyset result column")
		}
		if _, duplicate := outputs[column.Name]; duplicate {
			return errors.New("duplicate keyset result column")
		}
		outputs[column.Name] = struct{}{}
		if column.Type == "bytes" {
			if column.Encoding != "base64" {
				return errors.New("invalid binary keyset result encoding")
			}
		} else if !slices.Contains([]string{"integer", "decimal", "string", "date", "datetime", "time", "json"}, column.Type) || column.Encoding != "string" {
			return errors.New("invalid keyset result encoding")
		}
	}
	for _, row := range result.Rows {
		if len(row) != len(result.Columns) {
			return errors.New("invalid keyset row width")
		}
		for index, value := range row {
			if value == nil {
				if !result.Columns[index].Nullable {
					return errors.New("invalid null keyset cell")
				}
				continue
			}
			if !validKeysetResponseCell(*value, result.Columns[index]) {
				return errors.New("invalid keyset cell")
			}
		}
	}
	if result.Page.HasMore {
		cursor := *result.Page.NextCursor
		lastRow := result.Rows[len(result.Rows)-1]
		for keyIndex, order := range request.Query.OrderBy {
			projectionIndex := -1
			for index, projection := range request.Query.Projection {
				if projection.Field == order.Field {
					if projectionIndex != -1 {
						return errors.New("ambiguous keyset response key field")
					}
					projectionIndex = index
				}
			}
			if projectionIndex == -1 || lastRow[projectionIndex] == nil {
				return errors.New("missing keyset response key field")
			}
			expectedType := result.Columns[projectionIndex].Type
			if expectedType != "integer" && expectedType != "string" && expectedType != "bytes" {
				return errors.New("unsupported keyset response cursor type")
			}
			if cursor[keyIndex].Type != expectedType || cursor[keyIndex].Value != *lastRow[projectionIndex] {
				return errors.New("keyset response cursor does not match the last row")
			}
			if !validKeysetResponseCursor(cursor[keyIndex]) {
				return errors.New("keyset response cursor violates the transport contract")
			}
		}
	}
	return nil
}

func validKeysetResponseCursor(value queryspec.KeysetCursorValue) bool {
	switch value.Type {
	case "integer":
		return validKeysetResponseCell(value.Value, database.ResultColumn{Type: "integer"})
	case "string":
		return utf8.ValidString(value.Value) &&
			utf8.RuneCountInString(value.Value) <= queryspec.ProtocolMaxCursorStringRunes
	case "bytes":
		decoded, err := base64.StdEncoding.Strict().DecodeString(value.Value)
		return err == nil && len(decoded) <= queryspec.ProtocolMaxCursorBytes &&
			base64.StdEncoding.EncodeToString(decoded) == value.Value
	default:
		return false
	}
}

func validKeysetResponseCell(value string, column database.ResultColumn) bool {
	switch column.Type {
	case "bytes":
		decoded, err := base64.StdEncoding.Strict().DecodeString(value)
		return err == nil && base64.StdEncoding.EncodeToString(decoded) == value
	case "integer":
		if value == "" || value[0] == '+' || value == "-0" || len(value) > 20 || len(value) > 1 && value[0] == '0' {
			return false
		}
		if value[0] == '-' {
			_, err := strconv.ParseInt(value, 10, 64)
			return err == nil && len(value) > 1 && value[1] != '0'
		}
		_, err := strconv.ParseUint(value, 10, 64)
		return err == nil
	case "decimal":
		if value == "" || strings.ContainsAny(value, "eE+") {
			return false
		}
		negative := strings.HasPrefix(value, "-")
		text := strings.TrimPrefix(value, "-")
		parts := strings.Split(text, ".")
		if len(parts) > 2 || parts[0] == "" || len(parts) > 1 && parts[1] == "" ||
			len(parts[0]) > 1 && parts[0][0] == '0' {
			return false
		}
		nonzero := false
		for _, part := range parts {
			for _, character := range part {
				if character < '0' || character > '9' {
					return false
				}
				if character != '0' {
					nonzero = true
				}
			}
		}
		return !negative || nonzero
	case "string":
		return utf8.ValidString(value)
	case "date":
		return database.ValidDateCell(value)
	case "datetime":
		return database.ValidDateTimeCell(value)
	case "time":
		return database.ValidTimeCell(value)
	case "json":
		return utf8.ValidString(value) && json.Valid([]byte(value))
	default:
		return false
	}
}

func keysetShapeAuditMetadata(shapeName string) map[string]any {
	return map[string]any{"keyset_shape": shapeName}
}

func keysetSuccessAuditMetadata(shapeName string, hasMore bool, rowCount int) map[string]any {
	return map[string]any{
		"keyset_shape": shapeName, "row_count": rowCount,
		"has_more": hasMore, "truncated": hasMore,
	}
}

const requestedKeysetProfileHashDomain = "quordon/keyset-requested-profile/v1\x00"

func (s *Service) writeKeysetOperationDenial(
	ctx context.Context,
	requestID, queryID, principal, clientIdentifier, requestedProfile string,
) error {
	digest := sha256.New()
	_, _ = io.WriteString(digest, requestedKeysetProfileHashDomain)
	_, _ = io.WriteString(digest, requestedProfile)
	return s.audit.Write(context.WithoutCancel(ctx), s.keysetOperationDenialEvent(
		requestID, queryID, principal, clientIdentifier,
		hex.EncodeToString(digest.Sum(nil)), len(requestedProfile),
	))
}

func (s *Service) keysetOperationDenialEvent(
	requestID, queryID, principal, clientIdentifier, requestedProfileHash string,
	requestedProfileBytes int,
) audit.Event {
	return audit.Event{
		Type: "query_decision", RequestID: requestID, QueryID: queryID,
		Principal: principal, ClientIdentifier: clientIdentifier,
		PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(),
		Operation: string(domain.OperationSelectKeyset), Decision: "deny",
		ReasonCode: policy.ReasonDeniedOperation, RequestedProfileHash: requestedProfileHash,
		RequestedProfileBytes: requestedProfileBytes,
	}
}

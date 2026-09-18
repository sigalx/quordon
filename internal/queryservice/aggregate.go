package queryservice

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/sigalx/quordon/internal/audit"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryspec"
)

type AggregateResult struct {
	Mode          string                  `json:"mode"`
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

func (s *Service) Aggregate(
	ctx context.Context,
	requestID, queryID, principal, clientIdentifier string,
	bodyBytes int,
	request queryspec.AggregateRequest,
) (AggregateResult, error) {
	hardLimits := s.policy.HardLimits()
	validated, err := queryspec.ValidateAggregate(
		request.Query,
		hardLimits.MaxProjectionFields,
		hardLimits.MaxGroupByFields,
		hardLimits.MaxOrderByFields,
		hardLimits.MaxPredicates,
		hardLimits.MaxExpressionDepth,
		hardLimits.MaxParameters,
		hardLimits.MaxRows,
	)
	if err != nil {
		return AggregateResult{}, &Error{Kind: ErrorInvalid, Err: err}
	}
	profile, assigned := s.assignedProfile(principal, request.Profile)
	if !assigned || !slices.Contains(profile.Operations, domain.OperationAggregate) {
		if err := s.writeDenial(
			ctx, requestID, queryID, principal, clientIdentifier, request.Profile,
			domain.OperationAggregate, policy.ReasonDeniedOperation, "",
		); err != nil {
			return AggregateResult{}, &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return AggregateResult{}, &Error{Kind: ErrorDenied, ReasonCode: policy.ReasonDeniedOperation}
	}
	limits := s.policy.HardLimits().Min(profile.Limits)
	if bodyBytes > limits.MaxRequestBytes {
		return AggregateResult{}, &Error{Kind: ErrorTooLarge}
	}
	validated, err = queryspec.RevalidateAggregate(
		validated,
		limits.MaxProjectionFields,
		limits.MaxGroupByFields,
		limits.MaxOrderByFields,
		limits.MaxPredicates,
		limits.MaxExpressionDepth,
		limits.MaxParameters,
		limits.MaxRows,
	)
	if err != nil {
		return AggregateResult{}, &Error{Kind: ErrorInvalid, Err: err}
	}
	queryShapeHash := queryspec.AggregateShapeHash(validated.Spec())
	if err := s.precheckSourceText(ctx, requestID, queryID, principal, clientIdentifier, request.Profile, profile, domain.OperationAggregate, queryShapeHash, queryspec.AggregateUsesSourceText(validated.Spec())); err != nil {
		return AggregateResult{}, err
	}
	adapterName := s.databases.AdapterName(profile.Datasource)
	if !slices.Contains(s.databases.Capabilities(profile.Datasource), domain.OperationAggregate) ||
		queryspec.AggregateUsesTimeBucket(validated.Spec()) &&
			!slices.Contains(s.databases.Features(profile.Datasource), domain.FeatureTimeBucketUTC) {
		if err := s.writeAudit(context.WithoutCancel(ctx), audit.Event{
			Type: "query_completion", RequestID: requestID, QueryID: queryID, Principal: principal,
			ClientIdentifier: clientIdentifier, PolicyProfile: request.Profile,
			PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: profile.Datasource,
			Adapter: adapterName, Operation: string(domain.OperationAggregate), Outcome: "not_implemented",
			QueryShapeHash: queryShapeHash,
		}); err != nil {
			return AggregateResult{}, &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return AggregateResult{}, &Error{Kind: ErrorNotImplemented}
	}
	executionContext, cancel := context.WithTimeout(ctx, limits.Deadline())
	defer cancel()
	semanticsStarted := time.Now()
	semantics, err := s.databases.IdentifierSemantics(executionContext, profile.Datasource)
	if err != nil {
		return AggregateResult{}, s.completeQueryError(
			ctx, requestID, queryID, principal, clientIdentifier, request.Profile,
			profile.Datasource, adapterName, domain.OperationAggregate, queryShapeHash,
			nil, nil, map[string]any{"mode": request.Query.Mode}, semanticsStarted, err,
		)
	}
	s.observeIdentifierSemantics(request.Profile, semantics)
	normalized, err := queryspec.NormalizeAggregateIdentifiers(validated, semantics)
	if err != nil {
		return AggregateResult{}, s.completeQueryError(
			ctx, requestID, queryID, principal, clientIdentifier, request.Profile,
			profile.Datasource, adapterName, domain.OperationAggregate, queryShapeHash,
			nil, nil, map[string]any{"mode": request.Query.Mode}, semanticsStarted,
			&database.Error{Kind: database.ErrorInvalid, Err: err},
		)
	}
	queryShapeHash = queryspec.AggregateShapeHash(normalized.Spec())
	authorized, err := s.policy.AuthorizeAggregate(principal, request.Profile, normalized, semantics)
	if err != nil {
		reason := ""
		if !policy.IsDenial(err, &reason) {
			return AggregateResult{}, s.completeQueryError(
				ctx, requestID, queryID, principal, clientIdentifier, request.Profile,
				profile.Datasource, adapterName, domain.OperationAggregate, queryShapeHash,
				nil, nil, map[string]any{"mode": request.Query.Mode}, semanticsStarted,
				&database.Error{Kind: database.ErrorInvalid, Err: err},
			)
		}
		if auditErr := s.writeDenial(
			ctx, requestID, queryID, principal, clientIdentifier, request.Profile,
			domain.OperationAggregate, reason, queryShapeHash,
		); auditErr != nil {
			return AggregateResult{}, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return AggregateResult{}, &Error{Kind: ErrorDenied, ReasonCode: reason, Err: err}
	}
	authorizedSpec := authorized.Query()
	queryShapeHash = queryspec.AggregateShapeHash(authorizedSpec)
	resources := []audit.Resource{{Schema: authorizedSpec.Source.Schema, Object: authorizedSpec.Source.Name}}
	fields := authorized.ReferencedFields()
	if err := s.writeAllowDecision(
		ctx, requestID, queryID, principal, clientIdentifier, request.Profile,
		profile.Datasource, adapterName, domain.OperationAggregate, resources, fields, queryShapeHash,
	); err != nil {
		return AggregateResult{}, err
	}
	baseBytes, err := aggregateEnvelopeBaseBytes(
		authorizedSpec.Mode, queryID, request.Profile, s.policy.Version(),
		profile.Datasource, adapterName, limits,
	)
	if err != nil || baseBytes > limits.MaxResultBytes {
		databaseErr := &database.Error{Kind: database.ErrorResultTooLarge, Err: err}
		return AggregateResult{}, s.completeQueryError(
			ctx, requestID, queryID, principal, clientIdentifier, request.Profile,
			profile.Datasource, adapterName, domain.OperationAggregate, queryShapeHash,
			resources, fields, aggregateAuditMetadata(authorized, authorizedSpec.Mode), time.Now(), databaseErr,
		)
	}
	releaseCapacity, ok := s.acquireCapacity(request.Profile)
	if !ok {
		capacityStarted := time.Now()
		if err := s.writeAudit(context.WithoutCancel(ctx), audit.Event{
			Type: "query_completion", RequestID: requestID, QueryID: queryID, Principal: principal,
			ClientIdentifier: clientIdentifier, PolicyProfile: request.Profile,
			PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: profile.Datasource,
			Adapter: adapterName, Operation: string(domain.OperationAggregate), Outcome: "error",
			ErrorKind: string(ErrorCapacity), DurationMS: durationMilliseconds(capacityStarted),
			QueryShapeHash: queryShapeHash, Resources: resources, Fields: fields,
			Metadata: aggregateAuditMetadata(authorized, authorizedSpec.Mode),
		}); err != nil {
			return AggregateResult{}, &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return AggregateResult{}, &Error{Kind: ErrorCapacity}
	}
	defer releaseCapacity()
	started := time.Now()
	databaseResult, adapterName, databaseErr := s.databases.Aggregate(
		executionContext, authorized, baseBytes,
	)
	if databaseErr != nil {
		return AggregateResult{}, s.completeQueryError(
			ctx, requestID, queryID, principal, clientIdentifier, request.Profile,
			profile.Datasource, adapterName, domain.OperationAggregate, queryShapeHash,
			resources, fields, aggregateAuditMetadata(authorized, authorizedSpec.Mode), started, databaseErr,
		)
	}
	if err := s.writeAudit(context.WithoutCancel(ctx), audit.Event{
		Type: "query_completion", RequestID: requestID, QueryID: queryID, Principal: principal,
		ClientIdentifier: clientIdentifier, PolicyProfile: request.Profile,
		PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: profile.Datasource,
		Adapter: adapterName, Operation: string(domain.OperationAggregate), Outcome: "success",
		DurationMS: durationMilliseconds(started), QueryShapeHash: queryShapeHash,
		ResultBytes: databaseResult.ResultBytes, Resources: resources, Fields: fields,
		Metadata: map[string]any{
			"mode": databaseResult.Mode, "row_count": databaseResult.RowCount,
			"truncated": databaseResult.Truncated, "aggregate_shape": authorized.ShapeName(),
		},
	}); err != nil {
		return AggregateResult{}, &Error{Kind: ErrorServiceUnavailable, Err: err}
	}
	return AggregateResult{
		Mode: databaseResult.Mode, QueryID: queryID, PolicyProfile: request.Profile,
		PolicyVersion: s.policy.Version(), Datasource: profile.Datasource, Adapter: adapterName,
		Columns: databaseResult.Columns, Rows: databaseResult.Rows, RowCount: databaseResult.RowCount,
		Truncated: databaseResult.Truncated, Limits: limits, Warnings: []string{},
	}, nil
}

func aggregateAuditMetadata(authorized policy.AuthorizedAggregate, mode string) map[string]any {
	return map[string]any{"mode": mode, "aggregate_shape": authorized.ShapeName()}
}

func aggregateEnvelopeBaseBytes(
	mode, queryID, profile, policyVersion, datasource, adapter string,
	limits domain.Limits,
) (int, error) {
	rowCount := 0
	if mode == queryspec.AggregateModeScalar {
		rowCount = 1
	}
	encoded, err := json.Marshal(AggregateResult{
		Mode: mode, QueryID: queryID, PolicyProfile: profile, PolicyVersion: policyVersion,
		Datasource: datasource, Adapter: adapter,
		Columns: []database.ResultColumn{}, Rows: [][]*string{}, RowCount: rowCount,
		Truncated: false, Limits: limits, Warnings: []string{},
	})
	if err != nil {
		return 0, err
	}
	return len(encoded), nil
}

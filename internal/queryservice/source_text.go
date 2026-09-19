package queryservice

import (
	"context"
	"slices"
	"time"

	"github.com/sigalx/quordon/internal/audit"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
)

// precheckSourceText runs before identifier semantics or any datasource call.
func (s *Service) precheckSourceText(ctx context.Context, requestID, queryID, principal, credential string, binding policy.AuthorizedBinding, operation domain.Operation, shapeHash string, used bool) error {
	if !used {
		return nil
	}
	started := time.Now()
	if !s.policy.AllowsSourceText(binding.Profile()) {
		if err := s.writeDenial(ctx, requestID, queryID, principal, credential, binding.Profile(), binding.Datasource(), operation, policy.ReasonDeniedQueryFeature, shapeHash); err != nil {
			return &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return &Error{Kind: ErrorDenied, ReasonCode: policy.ReasonDeniedQueryFeature}
	}
	if !slices.Contains(s.databases.Features(binding.Datasource()), domain.FeatureSourceText) {
		if err := s.writeAudit(context.WithoutCancel(ctx), audit.Event{
			Type: "query_completion", RequestID: requestID, QueryID: queryID, Principal: principal,
			ClientIdentifier: credential, PolicyProfile: binding.Profile(), PolicyVersion: s.policy.Version(),
			PolicyHash: s.policy.Hash(), Datasource: binding.Datasource(), Adapter: s.databases.AdapterName(binding.Datasource()),
			Operation: string(operation), Outcome: "not_implemented", QueryShapeHash: shapeHash,
			DurationMS: durationMilliseconds(started),
		}); err != nil {
			return &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return &Error{Kind: ErrorNotImplemented}
	}
	return nil
}

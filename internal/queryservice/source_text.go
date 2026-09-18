package queryservice

import (
	"context"
	"slices"
	"time"

	"github.com/sigalx/quordon/internal/audit"
	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
)

// precheckSourceText runs before identifier semantics or any datasource call.
func (s *Service) precheckSourceText(ctx context.Context, requestID, queryID, principal, credential, profileName string, profile config.Profile, operation domain.Operation, shapeHash string, used bool) error {
	if !used {
		return nil
	}
	started := time.Now()
	if !s.policy.AllowsSourceText(profileName) {
		if err := s.writeDenial(ctx, requestID, queryID, principal, credential, profileName, operation, policy.ReasonDeniedQueryFeature, shapeHash); err != nil {
			return &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return &Error{Kind: ErrorDenied, ReasonCode: policy.ReasonDeniedQueryFeature}
	}
	if !slices.Contains(s.databases.Features(profile.Datasource), domain.FeatureSourceText) {
		if err := s.writeAudit(context.WithoutCancel(ctx), audit.Event{
			Type: "query_completion", RequestID: requestID, QueryID: queryID, Principal: principal,
			ClientIdentifier: credential, PolicyProfile: profileName, PolicyVersion: s.policy.Version(),
			PolicyHash: s.policy.Hash(), Datasource: profile.Datasource, Adapter: s.databases.AdapterName(profile.Datasource),
			Operation: string(operation), Outcome: "not_implemented", QueryShapeHash: shapeHash,
			DurationMS: durationMilliseconds(started),
		}); err != nil {
			return &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return &Error{Kind: ErrorNotImplemented}
	}
	return nil
}

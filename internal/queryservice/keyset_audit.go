package queryservice

import (
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/sigalx/quordon/internal/audit"
	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/domain"
)

// validateKeysetAuditBounds rejects policies whose configured identities or
// authorized keyset scope could make JSONSink materialize an audit event above
// the process-wide audit bound. It runs before discovery probes or listener
// startup and constructs only bounded metadata; no datasource is consulted.
func (s *Service) validateKeysetAuditBounds(maximum int) error {
	identity := s.queryShapeAuditIdentity
	if identity.principal != "" && identity.clientIdentifier != "" {
		event := s.keysetOperationDenialEvent(
			strings.Repeat("r", 64), strings.Repeat("q", 64),
			identity.principal, identity.clientIdentifier,
			strings.Repeat("f", 64), s.policy.HardLimits().MaxRequestBytes,
			strings.Repeat("d", 64), s.policy.HardLimits().MaxRequestBytes,
		)
		within, err := queryShapeAuditEventWithinBound(event, maximum)
		if err != nil {
			return fmt.Errorf("size keyset denial audit bound: %w", err)
		}
		if !within {
			return fmt.Errorf("keyset denial audit event exceeds %d bytes", maximum)
		}
	}

	maximumDuration := int64(math.MaxInt64)
	for key, identity := range s.bindingAuditIdentities {
		profile, ok := s.policy.Profile(key.Profile)
		if !ok {
			return fmt.Errorf("keyset audit profile %q disappeared from the policy snapshot", key.Profile)
		}
		if !slices.Contains(profile.Operations, domain.OperationSelectKeyset) {
			continue
		}
		adapterName := s.databases.AdapterName(key.Datasource)
		for _, shape := range profile.Query.KeysetSelectShapes {
			resources, fields := configuredKeysetAuditScope(shape)
			metadata := keysetSuccessAuditMetadata(shape.Name, true, profile.Limits.MaxRows)
			// This deliberately combines every optional field used by the
			// reachable decision/completion variants. It is a conservative
			// upper bound, while retaining the exact configured strings and
			// collection cardinalities that dominate the event size.
			event := audit.Event{
				Type: "query_completion", RequestID: strings.Repeat("r", 64), QueryID: strings.Repeat("q", 64),
				Principal: identity.principal, ClientIdentifier: identity.clientIdentifier,
				PolicyProfile: key.Profile, PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(),
				Datasource: key.Datasource, Adapter: adapterName,
				Operation: string(domain.OperationSelectKeyset), Decision: "allow",
				ReasonCode: "DENIED_QUERY_FEATURE", Outcome: "not_implemented",
				ErrorKind: "service_unavailable", DurationMS: &maximumDuration,
				ResultBytes: profile.Limits.MaxResultBytes, QueryShapeHash: strings.Repeat("f", 64),
				Resources: resources, Fields: fields, Metadata: metadata,
			}
			within, err := queryShapeAuditEventWithinBound(event, maximum)
			if err != nil {
				return fmt.Errorf("size keyset audit bound for profile %q: %w", key.Profile, err)
			}
			if !within {
				return fmt.Errorf("keyset audit event for profile %q exceeds %d bytes", key.Profile, maximum)
			}
		}
	}
	return nil
}

func configuredKeysetAuditScope(shape config.KeysetSelectShape) ([]audit.Resource, []string) {
	fields := make([]string, 0, len(shape.Projection)+len(shape.OrderBy))
	for _, projection := range shape.Projection {
		fields = append(fields, strings.ToLower(projection.Field))
	}
	if shape.Filter != nil {
		collectConfiguredKeysetAuditFilterFields(*shape.Filter, &fields)
	}
	for _, order := range shape.OrderBy {
		fields = append(fields, strings.ToLower(order.Field))
	}
	slices.Sort(fields)
	fields = slices.Compact(fields)
	return []audit.Resource{{
		Schema: strings.ToLower(shape.Source.Schema), Object: strings.ToLower(shape.Source.Name),
	}}, fields
}

func collectConfiguredKeysetAuditFilterFields(filter config.AggregateShapeFilter, fields *[]string) {
	if filter.Kind == "predicate" {
		*fields = append(*fields, strings.ToLower(filter.Field))
		return
	}
	for _, child := range filter.Expressions {
		collectConfiguredKeysetAuditFilterFields(child, fields)
	}
}

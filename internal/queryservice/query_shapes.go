package queryservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sigalx/quordon/internal/audit"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
)

const requestedProfileHashDomain = "quordon/requested-profile/v1\x00"

const maxQueryShapeAuditEventBytes = domain.MaxSupportedResultBytes

type queryShapeAuditIdentity struct {
	principal        string
	clientIdentifier string
}

type semanticsInitialization struct {
	value domain.IdentifierSemantics
	err   error
}

// InitializeQueryShapeDiscovery builds every disclosure-safe snapshot before
// the HTTP listener starts. Dependency failures leave the corresponding
// snapshot unpublished; policy/disclosure invariant failures reject startup.
func (s *Service) InitializeQueryShapeDiscovery(ctx context.Context) ([]error, error) {
	s.discoveryMu.Lock()
	if s.discoveryInit {
		s.discoveryMu.Unlock()
		return nil, errors.New("query-shape discovery is already initialized")
	}
	s.discoveryInit = true
	s.discoveryMu.Unlock()
	profileNames := make([]string, 0, len(s.discoveryNeeded))
	for profileName := range s.discoveryNeeded {
		profileNames = append(profileNames, profileName)
	}
	sort.Strings(profileNames)
	if err := s.validateQueryShapePreTokenAuditBounds(profileNames, maxQueryShapeAuditEventBytes); err != nil {
		return nil, err
	}
	if err := s.validateTableStatisticsAuditBounds(maxQueryShapeAuditEventBytes); err != nil {
		return nil, err
	}
	if err := s.validateKeysetAuditBounds(maxQueryShapeAuditEventBytes); err != nil {
		return nil, err
	}
	for _, profileName := range profileNames {
		datasource, _, _, ok := s.policy.ProfileBinding(profileName)
		if !ok {
			return nil, fmt.Errorf("query-shape profile %q disappeared from the policy snapshot", profileName)
		}
		if !s.supportsConfiguredQueryShapes(profileName, datasource) {
			continue
		}
		if err := s.policy.ValidateQueryShapeDiscoveryStatic(
			profileName, s.databases.AdapterName(datasource),
		); err != nil {
			return nil, fmt.Errorf("validate query-shape discovery for profile %q: %w", profileName, err)
		}
	}

	initialized := make(map[string]*policy.QueryShapeDiscovery, len(profileNames))
	semanticsByDatasource := make(map[string]semanticsInitialization)
	var problems []error
	for _, profileName := range profileNames {
		datasource, _, _, ok := s.policy.ProfileBinding(profileName)
		if !ok {
			return nil, fmt.Errorf("query-shape profile %q disappeared from the policy snapshot", profileName)
		}
		if !s.supportsConfiguredQueryShapes(profileName, datasource) {
			continue
		}
		initialization, exists := semanticsByDatasource[datasource]
		if !exists {
			probeContext, cancel := context.WithTimeout(ctx, 2*time.Second)
			semantics, err := s.databases.IdentifierSemantics(probeContext, datasource)
			cancel()
			initialization = semanticsInitialization{value: semantics, err: err}
			semanticsByDatasource[datasource] = initialization
		}
		if initialization.err != nil {
			problems = append(problems, fmt.Errorf(
				"query-shape discovery for profile %q is unavailable", profileName,
			))
			continue
		}
		discovery, err := s.policy.BuildQueryShapeDiscovery(
			profileName, s.databases.AdapterName(datasource), initialization.value,
		)
		if err != nil {
			return nil, fmt.Errorf("build query-shape discovery for profile %q: %w", profileName, err)
		}
		if err := s.validateQueryShapeAuditBound(profileName, &discovery, maxQueryShapeAuditEventBytes); err != nil {
			return nil, err
		}
		initialized[profileName] = &discovery
	}

	s.discoveryMu.Lock()
	s.queryShapes = initialized
	s.discoveryMu.Unlock()
	return problems, nil
}

func (s *Service) hasQueryShapeDiscovery(profileName string) bool {
	s.discoveryMu.RLock()
	defer s.discoveryMu.RUnlock()
	return s.queryShapes[profileName] != nil
}

// observeIdentifierSemantics invalidates every discovery snapshot for the
// datasource after another operation observes different server semantics.
// Restart is deliberately required to publish a new generation.
func (s *Service) observeIdentifierSemantics(profileName string, semantics domain.IdentifierSemantics) {
	datasource := s.profileDatasource(profileName)
	if datasource == "" {
		return
	}
	s.discoveryMu.Lock()
	defer s.discoveryMu.Unlock()
	for candidate, discovery := range s.queryShapes {
		if discovery == nil || discovery.Datasource() != datasource {
			continue
		}
		if !discovery.MatchesSemantics(semantics) {
			delete(s.queryShapes, candidate)
		}
	}
}

// ListQueryShapes returns a prebuilt response payload. The discovery lock only
// protects lookup and token minting: the token retains its immutable snapshot,
// so audit, capacity handling, and payload cloning cannot delay invalidation or
// unrelated datasource operations.
func (s *Service) ListQueryShapes(
	ctx context.Context,
	requestID, principal, clientIdentifier, profileName string,
) ([]byte, error) {
	started := time.Now()
	if profileName == "" || !utf8.ValidString(profileName) {
		return nil, &Error{Kind: ErrorInvalid}
	}
	profile, assigned := s.assignedProfile(principal, profileName)
	configuredShapes, configured := s.queryShapeSupport[profileName]
	if !assigned || !configured || configuredShapes.count == 0 ||
		!slices.Contains(profile.Operations, domain.OperationListQueryShapes) {
		if err := s.writeQueryShapeDenial(
			ctx, requestID, principal, clientIdentifier, profileName,
		); err != nil {
			return nil, &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return nil, &Error{Kind: ErrorDenied, ReasonCode: policy.ReasonDeniedOperation}
	}
	if !s.supportsConfiguredQueryShapes(profileName, profile.Datasource) {
		adapterName := s.databases.AdapterName(profile.Datasource)
		if err := s.writeQueryShapeCompletion(
			ctx, requestID, principal, clientIdentifier, profileName, profile.Datasource,
			adapterName, "not_implemented", "", started, nil,
		); err != nil {
			return nil, &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return nil, &Error{Kind: ErrorNotImplemented}
	}
	adapterName := s.databases.AdapterName(profile.Datasource)

	s.discoveryMu.RLock()
	discovery := s.queryShapes[profileName]
	if discovery == nil {
		s.discoveryMu.RUnlock()
		if err := s.writeQueryShapeCompletion(
			ctx, requestID, principal, clientIdentifier, profileName, profile.Datasource,
			adapterName, "error", "unavailable", started, nil,
		); err != nil {
			return nil, &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return nil, &Error{Kind: ErrorServiceUnavailable}
	}
	authorized, err := s.policy.AuthorizeQueryShapeList(
		principal, clientIdentifier, profileName, discovery,
	)
	s.discoveryMu.RUnlock()
	if err != nil {
		if auditErr := s.writeQueryShapeCompletion(
			ctx, requestID, principal, clientIdentifier, profileName, profile.Datasource,
			adapterName, "error", "internal", started, nil,
		); auditErr != nil {
			return nil, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return nil, &Error{Kind: ErrorInternal, Err: err}
	}
	resources, fields := queryShapeAuditScope(authorized)
	postToken := &queryShapeAuditData{
		resources: resources, fields: fields, shapeSetHash: authorized.ShapeSetHash(),
		shapeCount: authorized.ShapeCount(), resultBytes: authorized.ResultBytes(),
	}
	if err := s.writeAudit(ctx, s.queryShapeAllowEvent(
		requestID, principal, clientIdentifier, profileName, authorized, postToken,
	)); err != nil {
		return nil, &Error{Kind: ErrorServiceUnavailable, Err: err}
	}
	releaseCapacity, ok := s.acquireCapacity(profileName)
	if !ok {
		if err := s.writeQueryShapeCompletion(
			ctx, requestID, principal, clientIdentifier, profileName, authorized.Datasource(),
			authorized.Adapter(), "error", "capacity", started, postToken,
		); err != nil {
			return nil, &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return nil, &Error{Kind: ErrorCapacity}
	}
	defer releaseCapacity()
	payload, err := authorized.ResponsePayload()
	if err != nil {
		if auditErr := s.writeQueryShapeCompletion(
			ctx, requestID, principal, clientIdentifier, profileName, authorized.Datasource(),
			authorized.Adapter(), "error", "internal", started, postToken,
		); auditErr != nil {
			return nil, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return nil, &Error{Kind: ErrorInternal, Err: err}
	}
	if len(payload) != authorized.ResultBytes() {
		invariantErr := errors.New("query-shape response size invariant failed")
		if auditErr := s.writeQueryShapeCompletion(
			ctx, requestID, principal, clientIdentifier, profileName, authorized.Datasource(),
			authorized.Adapter(), "error", "internal", started, postToken,
		); auditErr != nil {
			return nil, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return nil, &Error{Kind: ErrorInternal, Err: invariantErr}
	}
	if err := s.writeQueryShapeCompletion(
		ctx, requestID, principal, clientIdentifier, profileName, authorized.Datasource(),
		authorized.Adapter(), "success", "", started, postToken,
	); err != nil {
		return nil, &Error{Kind: ErrorServiceUnavailable, Err: err}
	}
	return payload, nil
}

type queryShapeAuditData struct {
	resources    []audit.Resource
	fields       []string
	shapeSetHash string
	shapeCount   int
	resultBytes  int
}

func queryShapeAuditScope(authorized policy.AuthorizedQueryShapeList) ([]audit.Resource, []string) {
	authorizedResources := authorized.Resources()
	resources := make([]audit.Resource, 0, len(authorizedResources))
	for _, resource := range authorizedResources {
		resources = append(resources, audit.Resource{Schema: resource.Schema, Object: resource.Object})
	}
	return resources, authorized.Fields()
}

func (s *Service) queryShapeAllowEvent(
	requestID, principal, clientIdentifier, profileName string,
	authorized policy.AuthorizedQueryShapeList,
	data *queryShapeAuditData,
) audit.Event {
	return audit.Event{
		Type: "operation_decision", RequestID: requestID, Principal: principal,
		ClientIdentifier: clientIdentifier, PolicyProfile: profileName,
		PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: authorized.Datasource(),
		Adapter: authorized.Adapter(), Operation: string(domain.OperationListQueryShapes), Decision: "allow",
		PublicShapeSetHash: data.shapeSetHash, ShapeCount: data.shapeCount,
		ResultBytes: data.resultBytes, Resources: data.resources, Fields: data.fields,
	}
}

func (s *Service) validateQueryShapeAuditBound(
	profileName string,
	discovery *policy.QueryShapeDiscovery,
	maximum int,
) error {
	identities := s.discoveryAuditIdentities[profileName]
	if len(identities) == 0 {
		// A profile without an assigned configured Basic credential has no
		// authenticated HTTP path and therefore no attributed event to bound.
		return nil
	}
	if maximum < 1 {
		return fmt.Errorf("configured-profile query-shape audit event exceeds %d bytes", maximum)
	}
	for _, identity := range identities {
		authorized, err := s.policy.AuthorizeQueryShapeList(
			identity.principal, identity.clientIdentifier, profileName, discovery,
		)
		if err != nil {
			return fmt.Errorf("authorize query-shape audit bound for profile %q: %w", profileName, err)
		}
		resources, fields := queryShapeAuditScope(authorized)
		data := &queryShapeAuditData{
			resources: resources, fields: fields, shapeSetHash: authorized.ShapeSetHash(),
			shapeCount: authorized.ShapeCount(), resultBytes: authorized.ResultBytes(),
		}
		maximumDuration := int64(math.MaxInt64)
		errorKind := "internal"
		completionData := *data
		events := []audit.Event{
			s.queryShapeAllowEvent(
				strings.Repeat("r", 64), identity.principal, identity.clientIdentifier,
				profileName, authorized, data,
			),
			s.queryShapeCompletionEvent(
				strings.Repeat("r", 64), identity.principal, identity.clientIdentifier,
				profileName, authorized.Datasource(), authorized.Adapter(), "error", errorKind,
				&maximumDuration, &completionData,
			),
		}
		for _, event := range events {
			withinBound, err := queryShapeAuditEventWithinBound(event, maximum)
			if err != nil {
				return fmt.Errorf("size query-shape audit bound for profile %q: %w", profileName, err)
			}
			if !withinBound {
				return fmt.Errorf("configured-profile query-shape audit event exceeds %d bytes", maximum)
			}
		}
	}
	return nil
}

func (s *Service) validateQueryShapePreTokenAuditBounds(profileNames []string, maximum int) error {
	maximumRequestProfileBytes := int(^uint(0) >> 1)
	for _, identity := range s.queryShapeAuditIdentities {
		event := s.queryShapeDenialEvent(
			strings.Repeat("r", 64), identity.principal, identity.clientIdentifier,
			strings.Repeat("f", sha256.Size*2), maximumRequestProfileBytes,
		)
		withinBound, err := queryShapeAuditEventWithinBound(event, maximum)
		if err != nil {
			return fmt.Errorf("size query-shape denial audit bound: %w", err)
		}
		if !withinBound {
			return fmt.Errorf("query-shape denial audit event exceeds %d bytes", maximum)
		}
	}

	maximumDuration := int64(math.MaxInt64)
	for _, profileName := range profileNames {
		identities := s.discoveryAuditIdentities[profileName]
		if len(identities) == 0 {
			continue
		}
		datasource, _, _, ok := s.policy.ProfileBinding(profileName)
		if !ok {
			return errors.New("query-shape audit profile disappeared from the policy snapshot")
		}
		adapterName := s.databases.AdapterName(datasource)
		for _, identity := range identities {
			for _, outcome := range []struct{ outcome, errorKind string }{
				{outcome: "not_implemented"},
				{outcome: "error", errorKind: "unavailable"},
				{outcome: "error", errorKind: "internal"},
			} {
				event := s.queryShapeCompletionEvent(
					strings.Repeat("r", 64), identity.principal, identity.clientIdentifier,
					profileName, datasource, adapterName, outcome.outcome, outcome.errorKind,
					&maximumDuration, nil,
				)
				withinBound, err := queryShapeAuditEventWithinBound(event, maximum)
				if err != nil {
					return fmt.Errorf("size query-shape pre-token audit bound: %w", err)
				}
				if !withinBound {
					return fmt.Errorf("query-shape pre-token audit event exceeds %d bytes", maximum)
				}
			}
		}
	}
	return nil
}

func queryShapeAuditEventWithinBound(event audit.Event, maximum int) (bool, error) {
	if maximum < 1 {
		return false, nil
	}
	event.Timestamp = time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	_, withinBound, err := queryShapeAuditEventJSONSizeWithin(event, maximum-1)
	return withinBound, err
}

func (s *Service) writeQueryShapeDenial(
	ctx context.Context,
	requestID, principal, clientIdentifier, requestedProfile string,
) error {
	digest := sha256.New()
	_, _ = io.WriteString(digest, requestedProfileHashDomain)
	_, _ = io.WriteString(digest, requestedProfile)
	return s.writeAudit(context.WithoutCancel(ctx), s.queryShapeDenialEvent(
		requestID, principal, clientIdentifier, hex.EncodeToString(digest.Sum(nil)), len(requestedProfile),
	))
}

func (s *Service) queryShapeDenialEvent(
	requestID, principal, clientIdentifier, requestedProfileHash string,
	requestedProfileBytes int,
) audit.Event {
	return audit.Event{
		Type: "operation_decision", RequestID: requestID, Principal: principal,
		ClientIdentifier: clientIdentifier, PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(),
		Operation: string(domain.OperationListQueryShapes), Decision: "deny",
		ReasonCode: policy.ReasonDeniedOperation, RequestedProfileHash: requestedProfileHash,
		RequestedProfileBytes: requestedProfileBytes,
	}
}

func (s *Service) writeQueryShapeCompletion(
	ctx context.Context,
	requestID, principal, clientIdentifier, profileName, datasource, adapterName string,
	outcome, errorKind string,
	started time.Time,
	data *queryShapeAuditData,
) error {
	duration := durationMilliseconds(started)
	event := s.queryShapeCompletionEvent(
		requestID, principal, clientIdentifier, profileName, datasource, adapterName,
		outcome, errorKind, duration, data,
	)
	return s.writeAudit(context.WithoutCancel(ctx), event)
}

func (s *Service) queryShapeCompletionEvent(
	requestID, principal, clientIdentifier, profileName, datasource, adapterName string,
	outcome, errorKind string,
	duration *int64,
	data *queryShapeAuditData,
) audit.Event {
	event := audit.Event{
		Type: "operation_completion", RequestID: requestID, Principal: principal,
		ClientIdentifier: clientIdentifier, PolicyProfile: profileName,
		PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(), Datasource: datasource,
		Adapter: adapterName, Operation: string(domain.OperationListQueryShapes), Outcome: outcome,
		ErrorKind: errorKind, DurationMS: duration,
	}
	if data != nil {
		event.Resources = data.resources
		event.Fields = data.fields
		event.PublicShapeSetHash = data.shapeSetHash
		event.ShapeCount = data.shapeCount
		event.ResultBytes = data.resultBytes
	}
	return event
}

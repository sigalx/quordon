package queryservice

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sigalx/quordon/internal/audit"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
)

const maxQueryShapeAuditEventBytes = domain.MaxSupportedResultBytes

type queryShapeAuditIdentity struct {
	principal        string
	clientIdentifier string
}

type semanticsInitialization struct {
	value domain.IdentifierSemantics
	err   error
}

type queryShapeDocumentKey struct {
	profile   string
	semantics domain.IdentifierSemantics
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
	bindings := make([]policy.BindingKey, 0, len(s.discoveryNeeded))
	for key := range s.discoveryNeeded {
		bindings = append(bindings, key)
	}
	slices.SortFunc(bindings, func(a, b policy.BindingKey) int {
		if comparison := strings.Compare(a.Profile, b.Profile); comparison != 0 {
			return comparison
		}
		return strings.Compare(a.Datasource, b.Datasource)
	})
	if err := s.validateQueryShapePreTokenAuditBounds(bindings, maxQueryShapeAuditEventBytes); err != nil {
		return nil, err
	}
	if err := s.validateTableStatisticsAuditBounds(maxQueryShapeAuditEventBytes); err != nil {
		return nil, err
	}
	if err := s.validateKeysetAuditBounds(maxQueryShapeAuditEventBytes); err != nil {
		return nil, err
	}
	documents := make(map[queryShapeDocumentKey]*policy.QueryShapeDocument)
	for _, key := range bindings {
		if !s.supportsConfiguredQueryShapes(key) {
			continue
		}
		documentKey := queryShapeDocumentKey{profile: key.Profile}
		document := documents[documentKey]
		if document == nil {
			var err error
			document, err = s.policy.BuildQueryShapeDocument(key.Profile, domain.IdentifierSemantics{})
			if err != nil {
				return nil, fmt.Errorf("validate query-shape discovery for profile %q: %w", key.Profile, err)
			}
			documents[documentKey] = document
		}
		if _, err := s.policy.BuildQueryShapeDiscoveryFromDocument(
			key.Profile, key.Datasource, s.databases.AdapterName(key.Datasource), document,
		); err != nil {
			return nil, fmt.Errorf("validate query-shape discovery for profile %q: %w", key.Profile, err)
		}
	}

	initialized := make(map[policy.BindingKey]*policy.QueryShapeDiscovery, len(bindings))
	semanticsByDatasource := make(map[string]semanticsInitialization)
	var problems []error
	for _, key := range bindings {
		if !s.supportsConfiguredQueryShapes(key) {
			continue
		}
		initialization, exists := semanticsByDatasource[key.Datasource]
		if !exists {
			probeContext, cancel := context.WithTimeout(ctx, 2*time.Second)
			semantics, err := s.databases.IdentifierSemantics(probeContext, key.Datasource)
			cancel()
			initialization = semanticsInitialization{value: semantics, err: err}
			semanticsByDatasource[key.Datasource] = initialization
		}
		if initialization.err != nil {
			problems = append(problems, fmt.Errorf(
				"query-shape discovery for profile %q is unavailable", key.Profile,
			))
			continue
		}
		documentKey := queryShapeDocumentKey{profile: key.Profile, semantics: initialization.value}
		document := documents[documentKey]
		if document == nil {
			var err error
			document, err = s.policy.BuildQueryShapeDocument(key.Profile, initialization.value)
			if err != nil {
				return nil, fmt.Errorf("build query-shape discovery for profile %q: %w", key.Profile, err)
			}
			documents[documentKey] = document
		}
		discovery, err := s.policy.BuildQueryShapeDiscoveryFromDocument(
			key.Profile, key.Datasource, s.databases.AdapterName(key.Datasource), document,
		)
		if err != nil {
			return nil, fmt.Errorf("build query-shape discovery for profile %q: %w", key.Profile, err)
		}
		if err := s.validateQueryShapeAuditBound(key, &discovery, maxQueryShapeAuditEventBytes); err != nil {
			return nil, err
		}
		initialized[key] = &discovery
	}

	s.discoveryMu.Lock()
	s.queryShapes = initialized
	s.discoveryMu.Unlock()
	return problems, nil
}

func (s *Service) hasQueryShapeDiscovery(key policy.BindingKey) bool {
	s.discoveryMu.RLock()
	defer s.discoveryMu.RUnlock()
	return s.queryShapes[key] != nil
}

// observeIdentifierSemantics invalidates every discovery snapshot for the
// datasource after another operation observes different server semantics.
// Restart is deliberately required to publish a new generation.
func (s *Service) observeIdentifierSemantics(key policy.BindingKey, semantics domain.IdentifierSemantics) {
	s.discoveryMu.Lock()
	defer s.discoveryMu.Unlock()
	for candidate, discovery := range s.queryShapes {
		if discovery == nil || discovery.Datasource() != key.Datasource {
			continue
		}
		if !discovery.MatchesSemantics(semantics) {
			delete(s.queryShapes, candidate)
		}
	}
}

// ListQueryShapes returns a response assembled from a prebuilt immutable
// document and its binding-specific envelope. The discovery lock only protects
// lookup and token minting: audit, capacity handling, and response
// materialization cannot delay invalidation or unrelated datasource operations.
func (s *Service) ListQueryShapes(
	ctx context.Context,
	requestID, principal, clientIdentifier, profileName, datasource string,
) ([]byte, error) {
	started := time.Now()
	if profileName == "" || !utf8.ValidString(profileName) {
		return nil, &Error{Kind: ErrorInvalid}
	}
	binding, assigned := s.assignedBinding(principal, profileName, datasource, domain.OperationListQueryShapes)
	key := policy.BindingKey{Profile: profileName, Datasource: datasource}
	configuredShapes, configured := s.queryShapeSupport[key]
	if !assigned || !configured || configuredShapes.count == 0 ||
		binding.Operation() != domain.OperationListQueryShapes {
		if err := s.writeQueryShapeDenial(
			ctx, requestID, principal, clientIdentifier, profileName, datasource,
		); err != nil {
			return nil, &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return nil, &Error{Kind: ErrorDenied, ReasonCode: policy.ReasonDeniedOperation}
	}
	if !s.supportsConfiguredQueryShapes(key) {
		adapterName := s.databases.AdapterName(binding.Datasource())
		if err := s.writeQueryShapeCompletion(
			ctx, requestID, principal, clientIdentifier, profileName, binding.Datasource(),
			adapterName, "not_implemented", "", started, nil,
		); err != nil {
			return nil, &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return nil, &Error{Kind: ErrorNotImplemented}
	}
	adapterName := s.databases.AdapterName(binding.Datasource())

	s.discoveryMu.RLock()
	discovery := s.queryShapes[key]
	if discovery == nil {
		s.discoveryMu.RUnlock()
		if err := s.writeQueryShapeCompletion(
			ctx, requestID, principal, clientIdentifier, profileName, binding.Datasource(),
			adapterName, "error", "unavailable", started, nil,
		); err != nil {
			return nil, &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return nil, &Error{Kind: ErrorServiceUnavailable}
	}
	authorized, err := s.policy.AuthorizeQueryShapeList(
		binding, clientIdentifier, discovery,
	)
	s.discoveryMu.RUnlock()
	if err != nil {
		if auditErr := s.writeQueryShapeCompletion(
			ctx, requestID, principal, clientIdentifier, profileName, binding.Datasource(),
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
	releaseCapacity, ok := s.acquireCapacity(binding.Key())
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
	key policy.BindingKey,
	discovery *policy.QueryShapeDiscovery,
	maximum int,
) error {
	identity, reachable := s.bindingAuditIdentities[key]
	if !reachable {
		// A profile without an assigned configured Basic credential has no
		// authenticated HTTP path and therefore no attributed event to bound.
		return nil
	}
	if maximum < 1 {
		return fmt.Errorf("configured-profile query-shape audit event exceeds %d bytes", maximum)
	}
	binding, err := s.policy.AuthorizeBinding(identity.principal, key.Profile, key.Datasource, domain.OperationListQueryShapes)
	if err != nil {
		return fmt.Errorf("authorize query-shape binding for profile %q: %w", key.Profile, err)
	}
	authorized, err := s.policy.AuthorizeQueryShapeList(
		binding, identity.clientIdentifier, discovery,
	)
	if err != nil {
		return fmt.Errorf("authorize query-shape audit bound for profile %q: %w", key.Profile, err)
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
			key.Profile, authorized, data,
		),
		s.queryShapeCompletionEvent(
			strings.Repeat("r", 64), identity.principal, identity.clientIdentifier,
			key.Profile, authorized.Datasource(), authorized.Adapter(), "error", errorKind,
			&maximumDuration, &completionData,
		),
	}
	for _, event := range events {
		withinBound, err := queryShapeAuditEventWithinBound(event, maximum)
		if err != nil {
			return fmt.Errorf("size query-shape audit bound for profile %q: %w", key.Profile, err)
		}
		if !withinBound {
			return fmt.Errorf("configured-profile query-shape audit event exceeds %d bytes", maximum)
		}
	}
	return nil
}

func (s *Service) validateQueryShapePreTokenAuditBounds(bindings []policy.BindingKey, maximum int) error {
	maximumRequestProfileBytes := int(^uint(0) >> 1)
	identity := s.queryShapeAuditIdentity
	if identity.principal != "" && identity.clientIdentifier != "" {
		event := s.queryShapeDenialEvent(
			strings.Repeat("r", 64), identity.principal, identity.clientIdentifier,
			strings.Repeat("f", sha256.Size*2), maximumRequestProfileBytes,
			strings.Repeat("d", sha256.Size*2), maximumRequestProfileBytes,
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
	for _, key := range bindings {
		identity, reachable := s.bindingAuditIdentities[key]
		if !reachable {
			continue
		}
		adapterName := s.databases.AdapterName(key.Datasource)
		for _, outcome := range []struct{ outcome, errorKind string }{
			{outcome: "not_implemented"},
			{outcome: "error", errorKind: "unavailable"},
			{outcome: "error", errorKind: "internal"},
		} {
			event := s.queryShapeCompletionEvent(
				strings.Repeat("r", 64), identity.principal, identity.clientIdentifier,
				key.Profile, key.Datasource, adapterName, outcome.outcome, outcome.errorKind,
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
	requestID, principal, clientIdentifier, requestedProfile, requestedDatasource string,
) error {
	return s.writeAudit(context.WithoutCancel(ctx), s.queryShapeDenialEvent(
		requestID, principal, clientIdentifier,
		auditIdentifierHash(requestedProfileHashDomain, requestedProfile), len(requestedProfile),
		auditIdentifierHash(requestedDatasourceHashDomain, requestedDatasource), len(requestedDatasource),
	))
}

func (s *Service) queryShapeDenialEvent(
	requestID, principal, clientIdentifier, requestedProfileHash string,
	requestedProfileBytes int, requestedDatasourceHash string, requestedDatasourceBytes int,
) audit.Event {
	return audit.Event{
		Type: "operation_decision", RequestID: requestID, Principal: principal,
		ClientIdentifier: clientIdentifier, PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(),
		Operation: string(domain.OperationListQueryShapes), Decision: "deny",
		ReasonCode: policy.ReasonDeniedOperation, RequestedProfileHash: requestedProfileHash,
		RequestedProfileBytes: requestedProfileBytes, RequestedDatasourceHash: requestedDatasourceHash,
		RequestedDatasourceBytes: requestedDatasourceBytes,
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

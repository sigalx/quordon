package queryservice

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sigalx/quordon/internal/audit"
	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryspec"
)

type ErrorKind string

const (
	ErrorInvalid            ErrorKind = "invalid"
	ErrorDenied             ErrorKind = "denied"
	ErrorNotFound           ErrorKind = "not_found"
	ErrorTooLarge           ErrorKind = "too_large"
	ErrorCapacity           ErrorKind = "capacity"
	ErrorNotImplemented     ErrorKind = "not_implemented"
	ErrorServiceUnavailable ErrorKind = "service_unavailable"
	ErrorUnavailable        ErrorKind = "unavailable"
	ErrorTimeout            ErrorKind = "timeout"
	ErrorUpstream           ErrorKind = "upstream"
	ErrorResultTooLarge     ErrorKind = "result_too_large"
	ErrorInternal           ErrorKind = "internal"
)

type Error struct {
	Kind       ErrorKind
	ReasonCode string
	Err        error
}

func (e *Error) Error() string { return string(e.Kind) }
func (e *Error) Unwrap() error { return e.Err }

type ProfileCapability struct {
	Name        string                 `json:"name"`
	Limits      domain.Limits          `json:"limits"`
	Datasources []DatasourceCapability `json:"datasources"`
}

type DatasourceCapability struct {
	Name       string             `json:"name"`
	Adapter    string             `json:"adapter"`
	Operations []domain.Operation `json:"operations"`
}

type configuredQueryShapeSupport struct {
	count     int
	supported bool
}

type Capabilities struct {
	APIVersion     string              `json:"api_version"`
	ServiceVersion string              `json:"service_version"`
	PolicyVersion  string              `json:"policy_version"`
	Profiles       []ProfileCapability `json:"profiles"`
}

type ExplainResult struct {
	QueryID       string          `json:"query_id"`
	PolicyProfile string          `json:"policy_profile"`
	PolicyVersion string          `json:"policy_version"`
	Datasource    string          `json:"datasource"`
	Adapter       string          `json:"adapter"`
	Format        string          `json:"format"`
	Plan          json.RawMessage `json:"plan"`
	Limits        domain.Limits   `json:"limits"`
	Warnings      []string        `json:"warnings"`
}

type Service struct {
	policy                  *policy.Snapshot
	databases               *database.Manager
	audit                   audit.Sink
	serviceVersion          string
	globalCapacity          chan struct{}
	bindingCapacity         map[policy.BindingKey]chan struct{}
	discoveryMu             sync.RWMutex
	queryShapes             map[policy.BindingKey]*policy.QueryShapeDiscovery
	discoveryNeeded         map[policy.BindingKey]bool
	queryShapeSupport       map[policy.BindingKey]configuredQueryShapeSupport
	queryShapeAuditIdentity queryShapeAuditIdentity
	bindingAuditIdentities  map[policy.BindingKey]queryShapeAuditIdentity
	discoveryInit           bool
}

func New(snapshot *policy.Snapshot, databases *database.Manager, sink audit.Sink, cfg config.Config, serviceVersion string) *Service {
	bindingCapacity := make(map[policy.BindingKey]chan struct{})
	discoveryNeeded := make(map[policy.BindingKey]bool)
	queryShapeSupport := make(map[policy.BindingKey]configuredQueryShapeSupport)
	bindingAuditIdentities := make(map[policy.BindingKey]queryShapeAuditIdentity)
	auditIdentityByPrincipal := make(map[string]queryShapeAuditIdentity)
	var worstAuditIdentity queryShapeAuditIdentity
	for username, user := range cfg.Authentication.Basic.Users {
		identity := queryShapeAuditIdentity{
			principal: user.Principal, clientIdentifier: username,
		}
		if moreConservativeAuditIdentity(identity, worstAuditIdentity) {
			worstAuditIdentity = identity
		}
		if moreConservativeAuditIdentity(identity, auditIdentityByPrincipal[user.Principal]) {
			auditIdentityByPrincipal[user.Principal] = identity
		}
	}
	for name, profile := range cfg.Profiles {
		limits := cfg.HardLimits.Min(profile.Limits)
		hasTimeBucket := false
		hasNumericBucket := false
		for _, shape := range profile.Query.AggregateShapes {
			for _, output := range shape.Projection {
				if output.Kind == "numeric_bucket" {
					hasNumericBucket = true
				}
				if output.Kind == "time_bucket" {
					hasTimeBucket = true
				}
			}
		}
		aggregateCount := len(profile.Query.AggregateShapes)
		keysetCount := len(profile.Query.KeysetSelectShapes)
		for _, datasource := range profile.Datasources {
			key := policy.BindingKey{Profile: name, Datasource: datasource}
			bindingCapacity[key] = make(chan struct{}, limits.MaxConcurrency)
			if slices.Contains(profile.Operations, domain.OperationListQueryShapes) {
				discoveryNeeded[key] = cfg.Datasources[datasource].RequiredForReadiness
			}
			if aggregateCount+keysetCount == 0 {
				continue
			}
			capabilities := databases.Capabilities(datasource)
			features := databases.Features(datasource)
			supported := (aggregateCount == 0 ||
				slices.Contains(capabilities, domain.OperationAggregate) &&
					(!hasTimeBucket || slices.Contains(features, domain.FeatureTimeBucketUTC)) &&
					(!hasNumericBucket || slices.Contains(features, domain.FeatureNumericBucketExact))) &&
				(keysetCount == 0 || slices.Contains(capabilities, domain.OperationSelectKeyset))
			queryShapeSupport[key] = configuredQueryShapeSupport{
				count:     aggregateCount + keysetCount,
				supported: supported,
			}
		}
	}
	for principalName, principal := range cfg.Principals {
		identity, hasCredential := auditIdentityByPrincipal[principalName]
		if !hasCredential {
			continue
		}
		principalDatasources := stringMembershipSet(principal.Datasources)
		for _, profileName := range principal.Profiles {
			profile, configured := cfg.Profiles[profileName]
			if !configured {
				continue
			}
			for _, datasource := range profile.Datasources {
				if _, assigned := principalDatasources[datasource]; !assigned {
					continue
				}
				key := policy.BindingKey{Profile: profileName, Datasource: datasource}
				if moreConservativeAuditIdentity(identity, bindingAuditIdentities[key]) {
					bindingAuditIdentities[key] = identity
				}
			}
		}
	}
	return &Service{
		policy: snapshot, databases: databases, audit: sink,
		serviceVersion:          serviceVersion,
		globalCapacity:          make(chan struct{}, cfg.HardLimits.MaxConcurrency),
		bindingCapacity:         bindingCapacity,
		queryShapes:             make(map[policy.BindingKey]*policy.QueryShapeDiscovery),
		discoveryNeeded:         discoveryNeeded,
		queryShapeSupport:       queryShapeSupport,
		queryShapeAuditIdentity: worstAuditIdentity,
		bindingAuditIdentities:  bindingAuditIdentities,
	}
}

func (s *Service) HardLimits() domain.Limits { return s.policy.HardLimits() }
func (s *Service) PolicyVersion() string     { return s.policy.Version() }

func (s *Service) writeAudit(ctx context.Context, event audit.Event) error {
	return s.audit.Write(ctx, event)
}

func (s *Service) Capabilities(principal string) Capabilities {
	result := Capabilities{
		APIVersion: domain.APIMajorVersion, ServiceVersion: s.serviceVersion,
		PolicyVersion: s.policy.Version(), Profiles: make([]ProfileCapability, 0),
	}
	principalDatasources := stringMembershipSet(s.policy.PrincipalDatasources(principal))
	for _, name := range s.policy.PrincipalProfiles(principal) {
		datasources, configuredOperations, profileLimits, ok := s.policy.ProfileBinding(name)
		if !ok {
			continue
		}
		profileCapability := ProfileCapability{
			Name: name, Limits: s.policy.HardLimits().Min(profileLimits),
			Datasources: make([]DatasourceCapability, 0),
		}
		for _, datasource := range datasources {
			if _, assigned := principalDatasources[datasource]; !assigned {
				continue
			}
			key := policy.BindingKey{Profile: name, Datasource: datasource}
			adapterCapabilities := s.databases.Capabilities(datasource)
			operations := make([]domain.Operation, 0, len(configuredOperations))
			for _, operation := range configuredOperations {
				if operation == domain.OperationListQueryShapes {
					if s.supportsConfiguredQueryShapes(key) && s.hasQueryShapeDiscovery(key) {
						operations = append(operations, operation)
					}
					continue
				}
				if slices.Contains(adapterCapabilities, operation) {
					operations = append(operations, operation)
				}
			}
			profileCapability.Datasources = append(profileCapability.Datasources, DatasourceCapability{
				Name: datasource, Adapter: s.databases.AdapterName(datasource), Operations: operations,
			})
		}
		slices.SortFunc(profileCapability.Datasources, func(a, b DatasourceCapability) int {
			return strings.Compare(a.Name, b.Name)
		})
		if len(profileCapability.Datasources) != 0 {
			result.Profiles = append(result.Profiles, profileCapability)
		}
	}
	slices.SortFunc(result.Profiles, func(a, b ProfileCapability) int {
		return strings.Compare(a.Name, b.Name)
	})
	return result
}

func (s *Service) Explain(
	ctx context.Context,
	requestID, queryID, principal, clientIdentifier string,
	bodyBytes int,
	request queryspec.Request,
) (ExplainResult, error) {
	binding, assigned := s.assignedBinding(principal, request.Profile, request.Datasource, domain.OperationExplainSelect)
	if !assigned {
		if err := s.writeDenial(ctx, requestID, queryID, principal, clientIdentifier, request.Profile, request.Datasource, domain.OperationExplainSelect, policy.ReasonDeniedOperation, ""); err != nil {
			return ExplainResult{}, &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return ExplainResult{}, &Error{Kind: ErrorDenied, ReasonCode: policy.ReasonDeniedOperation}
	}
	limits := binding.Limits()
	if bodyBytes > limits.MaxRequestBytes {
		return ExplainResult{}, &Error{Kind: ErrorTooLarge}
	}
	validated, err := queryspec.Validate(
		request.Query, limits.MaxProjectionFields, limits.MaxGroupByFields, limits.MaxOrderByFields, limits.MaxPredicates,
		limits.MaxExpressionDepth, limits.MaxParameters, limits.MaxRows, limits.MaxOffset,
	)
	if err != nil {
		return ExplainResult{}, &Error{Kind: ErrorInvalid, Err: err}
	}
	queryShapeHash := queryspec.ShapeHash(validated.Spec())
	if err := s.precheckSourceText(ctx, requestID, queryID, principal, clientIdentifier, binding, domain.OperationExplainSelect, queryShapeHash, queryspec.UsesSourceText(validated.Spec())); err != nil {
		return ExplainResult{}, err
	}
	adapterName := s.databases.AdapterName(binding.Datasource())
	if !slices.Contains(s.databases.Capabilities(binding.Datasource()), domain.OperationExplainSelect) {
		if err := s.writeAudit(context.WithoutCancel(ctx), audit.Event{
			Type: "query_completion", RequestID: requestID, QueryID: queryID, Principal: principal,
			ClientIdentifier: clientIdentifier,
			PolicyProfile:    request.Profile, PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(),
			Datasource: binding.Datasource(), Adapter: adapterName, Operation: string(domain.OperationExplainSelect),
			Outcome: "not_implemented", QueryShapeHash: queryShapeHash,
		}); err != nil {
			return ExplainResult{}, &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return ExplainResult{}, &Error{Kind: ErrorNotImplemented}
	}
	executionContext, cancel := context.WithTimeout(ctx, limits.Deadline())
	defer cancel()
	semanticsStarted := time.Now()
	semantics, err := s.databases.IdentifierSemantics(executionContext, binding.Datasource())
	if err != nil {
		errorKind := classifyDatabaseAuditError(err)
		if auditErr := s.writeAudit(context.WithoutCancel(ctx), audit.Event{
			Type: "query_completion", RequestID: requestID, QueryID: queryID, Principal: principal,
			ClientIdentifier: clientIdentifier,
			PolicyProfile:    request.Profile, PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(),
			Datasource: binding.Datasource(), Adapter: adapterName, Operation: string(domain.OperationExplainSelect),
			Outcome: "error", ErrorKind: string(errorKind),
			DurationMS: durationMilliseconds(semanticsStarted), QueryShapeHash: queryShapeHash,
		}); auditErr != nil {
			return ExplainResult{}, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return ExplainResult{}, mapDatabaseError(err)
	}
	s.observeIdentifierSemantics(binding.Key(), semantics)
	authorized, err := s.policy.AuthorizeExplain(
		binding,
		validated,
		semantics,
	)
	if err != nil {
		reason := policy.ReasonDeniedOperation
		policy.IsDenial(err, &reason)
		if auditErr := s.writeDenial(ctx, requestID, queryID, principal, clientIdentifier, binding.Profile(), binding.Datasource(), domain.OperationExplainSelect, reason, queryShapeHash); auditErr != nil {
			return ExplainResult{}, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return ExplainResult{}, &Error{Kind: ErrorDenied, ReasonCode: reason, Err: err}
	}
	authorizedSpec := authorized.Query()
	resources := []audit.Resource{{Schema: authorizedSpec.Source.Schema, Object: authorizedSpec.Source.Name}}
	fields := authorized.ReferencedFields()

	decision := audit.Event{
		Type: "query_decision", RequestID: requestID, QueryID: queryID, Principal: principal,
		ClientIdentifier: clientIdentifier,
		PolicyProfile:    request.Profile, PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(),
		Datasource: binding.Datasource(), Adapter: adapterName, Operation: string(domain.OperationExplainSelect),
		Decision: "allow", QueryShapeHash: queryShapeHash, Resources: resources, Fields: fields,
	}
	if err := s.writeAudit(ctx, decision); err != nil {
		return ExplainResult{}, &Error{Kind: ErrorServiceUnavailable, Err: err}
	}
	releaseCapacity, ok := s.acquireCapacity(binding.Key())
	if !ok {
		return ExplainResult{}, &Error{Kind: ErrorCapacity}
	}
	defer releaseCapacity()
	started := time.Now()
	databaseResult, adapterName, databaseErr := s.databases.Explain(executionContext, authorized)
	outcome := "success"
	errorKind := ""
	if databaseErr != nil {
		outcome = "error"
		errorKind = string(classifyDatabaseAuditError(databaseErr))
	}
	completion := audit.Event{
		Type: "query_completion", RequestID: requestID, QueryID: queryID, Principal: principal,
		ClientIdentifier: clientIdentifier,
		PolicyProfile:    request.Profile, PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(),
		Datasource: binding.Datasource(), Adapter: adapterName, Operation: string(domain.OperationExplainSelect),
		Outcome: outcome, ErrorKind: errorKind,
		DurationMS: durationMilliseconds(started), QueryShapeHash: queryShapeHash,
		ResultBytes: len(databaseResult.Plan), Resources: resources, Fields: fields,
	}
	if err := s.writeAudit(context.WithoutCancel(ctx), completion); err != nil {
		return ExplainResult{}, &Error{Kind: ErrorServiceUnavailable, Err: err}
	}
	if databaseErr != nil {
		return ExplainResult{}, mapDatabaseError(databaseErr)
	}
	return ExplainResult{
		QueryID: queryID, PolicyProfile: request.Profile, PolicyVersion: s.policy.Version(),
		Datasource: binding.Datasource(), Adapter: adapterName, Format: databaseResult.Format,
		Plan: databaseResult.Plan, Limits: limits, Warnings: []string{},
	}, nil
}

func (s *Service) Ready(ctx context.Context) error {
	if !s.audit.Ready() {
		return errors.New("audit sink is unavailable")
	}
	if err := s.databases.Ready(ctx); err != nil {
		return err
	}
	requiredByDatasource := make(map[string]policy.BindingKey)
	for key, required := range s.discoveryNeeded {
		if !required {
			continue
		}
		if !s.supportsConfiguredQueryShapes(key) {
			continue
		}
		requiredByDatasource[key.Datasource] = key
	}
	for datasource, key := range requiredByDatasource {
		probeContext, cancel := context.WithTimeout(ctx, 2*time.Second)
		semantics, err := s.databases.IdentifierSemantics(probeContext, datasource)
		cancel()
		if err != nil {
			return err
		}
		s.observeIdentifierSemantics(key, semantics)
	}
	s.discoveryMu.RLock()
	defer s.discoveryMu.RUnlock()
	for key, required := range s.discoveryNeeded {
		if !required || !s.supportsConfiguredQueryShapes(key) {
			continue
		}
		if s.queryShapes[key] == nil {
			return errors.New("required query-shape discovery snapshot is unavailable")
		}
	}
	return nil
}

func (s *Service) supportsConfiguredQueryShapes(key policy.BindingKey) bool {
	configured, ok := s.queryShapeSupport[key]
	return ok && configured.count != 0 && configured.supported
}

func (s *Service) assignedBinding(
	principal, profileName, datasource string, operation domain.Operation,
) (policy.AuthorizedBinding, bool) {
	binding, err := s.policy.AuthorizeBinding(principal, profileName, datasource, operation)
	return binding, err == nil
}

func (s *Service) acquireCapacity(key policy.BindingKey) (func(), bool) {
	select {
	case s.globalCapacity <- struct{}{}:
	default:
		return nil, false
	}
	profileGate, ok := s.bindingCapacity[key]
	if !ok {
		<-s.globalCapacity
		return nil, false
	}
	select {
	case profileGate <- struct{}{}:
		return func() {
			<-profileGate
			<-s.globalCapacity
		}, true
	default:
		<-s.globalCapacity
		return nil, false
	}
}

func (s *Service) writeDenial(
	ctx context.Context,
	requestID, queryID, principal, clientIdentifier, profile, datasource string,
	operation domain.Operation,
	reason, queryShapeHash string,
) error {
	eventType := "operation_decision"
	if queryID != "" {
		eventType = "query_decision"
	}
	event := audit.Event{
		Type: eventType, RequestID: requestID, QueryID: queryID, Principal: principal,
		ClientIdentifier: clientIdentifier,
		PolicyVersion:    s.policy.Version(), PolicyHash: s.policy.Hash(),
		Operation: string(operation), Decision: "deny", ReasonCode: reason,
		QueryShapeHash: queryShapeHash,
	}
	if binding, err := s.policy.AuthorizeBinding(principal, profile, datasource, operation); err == nil {
		event.PolicyProfile = binding.Profile()
		event.Datasource = binding.Datasource()
		event.Adapter = s.databases.AdapterName(binding.Datasource())
	} else {
		event.RequestedProfileHash = auditIdentifierHash(requestedProfileHashDomain, profile)
		event.RequestedProfileBytes = len(profile)
		event.RequestedDatasourceHash = auditIdentifierHash(requestedDatasourceHashDomain, datasource)
		event.RequestedDatasourceBytes = len(datasource)
	}
	return s.writeAudit(context.WithoutCancel(ctx), event)
}

func stringMembershipSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func durationMilliseconds(started time.Time) *int64 {
	duration := time.Since(started).Milliseconds()
	return &duration
}

func mapDatabaseError(err error) error {
	return &Error{Kind: classifyDatabaseError(err), Err: err}
}

// classifyDatabaseAuditError keeps database-completion audits on their
// documented stable vocabulary. A continuation request that cannot fit the
// request budget remains HTTP 413 externally, but is a deterministic
// admission/input failure rather than a result-materialization failure.
func classifyDatabaseAuditError(err error) ErrorKind {
	if database.IsKind(err, database.ErrorRequestTooLarge) || database.IsKind(err, database.ErrorNotFound) {
		return ErrorInvalid
	}
	return classifyDatabaseError(err)
}

func classifyDatabaseError(err error) ErrorKind {
	switch {
	case database.IsKind(err, database.ErrorNotFound):
		return ErrorNotFound
	case database.IsKind(err, database.ErrorInvalid):
		return ErrorInvalid
	case database.IsKind(err, database.ErrorNotImplemented):
		return ErrorNotImplemented
	case database.IsKind(err, database.ErrorUnavailable):
		return ErrorUnavailable
	case database.IsKind(err, database.ErrorTimeout):
		return ErrorTimeout
	case database.IsKind(err, database.ErrorRequestTooLarge):
		return ErrorTooLarge
	case database.IsKind(err, database.ErrorResultTooLarge):
		return ErrorResultTooLarge
	default:
		return ErrorUpstream
	}
}

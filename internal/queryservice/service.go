package queryservice

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
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
	Name       string             `json:"name"`
	Datasource string             `json:"datasource"`
	Adapter    string             `json:"adapter"`
	Operations []domain.Operation `json:"operations"`
	Limits     domain.Limits      `json:"limits"`
}

type configuredQueryShapeSupport struct {
	datasource string
	count      int
	supported  bool
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
	policy                    *policy.Snapshot
	databases                 *database.Manager
	audit                     audit.Sink
	serviceVersion            string
	globalCapacity            chan struct{}
	profileCapacity           map[string]chan struct{}
	discoveryMu               sync.RWMutex
	queryShapes               map[string]*policy.QueryShapeDiscovery
	discoveryNeeded           map[string]bool
	queryShapeSupport         map[string]configuredQueryShapeSupport
	queryShapeAuditIdentities []queryShapeAuditIdentity
	discoveryAuditIdentities  map[string][]queryShapeAuditIdentity
	keysetAuditIdentities     map[string][]queryShapeAuditIdentity
	discoveryInit             bool
}

func New(snapshot *policy.Snapshot, databases *database.Manager, sink audit.Sink, cfg config.Config, serviceVersion string) *Service {
	profileCapacity := make(map[string]chan struct{}, len(cfg.Profiles))
	discoveryNeeded := make(map[string]bool)
	queryShapeSupport := make(map[string]configuredQueryShapeSupport)
	queryShapeAuditIdentities := make([]queryShapeAuditIdentity, 0, len(cfg.Authentication.Basic.Users))
	discoveryAuditIdentities := make(map[string][]queryShapeAuditIdentity)
	keysetAuditIdentities := make(map[string][]queryShapeAuditIdentity)
	clientIdentifiersByPrincipal := make(map[string][]string)
	for username, user := range cfg.Authentication.Basic.Users {
		queryShapeAuditIdentities = append(queryShapeAuditIdentities, queryShapeAuditIdentity{
			principal: user.Principal, clientIdentifier: username,
		})
		clientIdentifiersByPrincipal[user.Principal] = append(
			clientIdentifiersByPrincipal[user.Principal], username,
		)
	}
	for name, profile := range cfg.Profiles {
		limits := cfg.HardLimits.Min(profile.Limits)
		profileCapacity[name] = make(chan struct{}, limits.MaxConcurrency)
		if slices.Contains(profile.Operations, domain.OperationListQueryShapes) {
			discoveryNeeded[name] = cfg.Datasources[profile.Datasource].RequiredForReadiness
		}
		hasTimeBucket := false
		for _, shape := range profile.Query.AggregateShapes {
			for _, output := range shape.Projection {
				if output.Kind == "time_bucket" {
					hasTimeBucket = true
				}
			}
		}
		aggregateCount := len(profile.Query.AggregateShapes)
		keysetCount := len(profile.Query.KeysetSelectShapes)
		if aggregateCount+keysetCount != 0 {
			capabilities := databases.Capabilities(profile.Datasource)
			features := databases.Features(profile.Datasource)
			supported := (aggregateCount == 0 ||
				slices.Contains(capabilities, domain.OperationAggregate) &&
					(!hasTimeBucket || slices.Contains(features, domain.FeatureTimeBucketUTC))) &&
				(keysetCount == 0 || slices.Contains(capabilities, domain.OperationSelectKeyset))
			queryShapeSupport[name] = configuredQueryShapeSupport{
				datasource: profile.Datasource,
				count:      aggregateCount + keysetCount,
				supported:  supported,
			}
		}
	}
	for principalName, principal := range cfg.Principals {
		clientIdentifiers := clientIdentifiersByPrincipal[principalName]
		if len(clientIdentifiers) == 0 {
			continue
		}
		slices.Sort(clientIdentifiers)
		for _, profileName := range principal.Profiles {
			profile, configured := cfg.Profiles[profileName]
			if !configured {
				continue
			}
			for _, clientIdentifier := range clientIdentifiers {
				identity := queryShapeAuditIdentity{principal: principalName, clientIdentifier: clientIdentifier}
				if _, publishesShapes := discoveryNeeded[profileName]; publishesShapes {
					discoveryAuditIdentities[profileName] = append(
						discoveryAuditIdentities[profileName], identity,
					)
				}
				if slices.Contains(profile.Operations, domain.OperationSelectKeyset) {
					keysetAuditIdentities[profileName] = append(keysetAuditIdentities[profileName], identity)
				}
			}
		}
	}
	return &Service{
		policy: snapshot, databases: databases, audit: sink,
		serviceVersion:            serviceVersion,
		globalCapacity:            make(chan struct{}, cfg.HardLimits.MaxConcurrency),
		profileCapacity:           profileCapacity,
		queryShapes:               make(map[string]*policy.QueryShapeDiscovery),
		discoveryNeeded:           discoveryNeeded,
		queryShapeSupport:         queryShapeSupport,
		queryShapeAuditIdentities: queryShapeAuditIdentities,
		discoveryAuditIdentities:  discoveryAuditIdentities,
		keysetAuditIdentities:     keysetAuditIdentities,
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
	for _, name := range s.policy.PrincipalProfiles(principal) {
		datasource, configuredOperations, profileLimits, ok := s.policy.ProfileBinding(name)
		if !ok {
			continue
		}
		adapterCapabilities := s.databases.Capabilities(datasource)
		operations := make([]domain.Operation, 0, len(configuredOperations))
		for _, operation := range configuredOperations {
			if operation == domain.OperationListQueryShapes {
				if s.supportsConfiguredQueryShapes(name, datasource) && s.hasQueryShapeDiscovery(name) {
					operations = append(operations, operation)
				}
				continue
			}
			if slices.Contains(adapterCapabilities, operation) {
				operations = append(operations, operation)
			}
		}
		result.Profiles = append(result.Profiles, ProfileCapability{
			Name: name, Datasource: datasource, Adapter: s.databases.AdapterName(datasource),
			Operations: operations, Limits: s.policy.HardLimits().Min(profileLimits),
		})
	}
	slices.SortFunc(result.Profiles, func(a, b ProfileCapability) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return result
}

func (s *Service) Explain(
	ctx context.Context,
	requestID, queryID, principal, clientIdentifier string,
	bodyBytes int,
	request queryspec.Request,
) (ExplainResult, error) {
	profile, assigned := s.assignedProfile(principal, request.Profile)
	if !assigned || !slices.Contains(profile.Operations, domain.OperationExplainSelect) {
		if err := s.writeDenial(ctx, requestID, queryID, principal, clientIdentifier, request.Profile, domain.OperationExplainSelect, policy.ReasonDeniedOperation, ""); err != nil {
			return ExplainResult{}, &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return ExplainResult{}, &Error{Kind: ErrorDenied, ReasonCode: policy.ReasonDeniedOperation}
	}
	limits := s.policy.HardLimits().Min(profile.Limits)
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
	if err := s.precheckSourceText(ctx, requestID, queryID, principal, clientIdentifier, request.Profile, profile, domain.OperationExplainSelect, queryShapeHash, queryspec.UsesSourceText(validated.Spec())); err != nil {
		return ExplainResult{}, err
	}
	adapterName := s.databases.AdapterName(profile.Datasource)
	if !slices.Contains(s.databases.Capabilities(profile.Datasource), domain.OperationExplainSelect) {
		if err := s.writeAudit(context.WithoutCancel(ctx), audit.Event{
			Type: "query_completion", RequestID: requestID, QueryID: queryID, Principal: principal,
			ClientIdentifier: clientIdentifier,
			PolicyProfile:    request.Profile, PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(),
			Datasource: profile.Datasource, Adapter: adapterName, Operation: string(domain.OperationExplainSelect),
			Outcome: "not_implemented", QueryShapeHash: queryShapeHash,
		}); err != nil {
			return ExplainResult{}, &Error{Kind: ErrorServiceUnavailable, Err: err}
		}
		return ExplainResult{}, &Error{Kind: ErrorNotImplemented}
	}
	executionContext, cancel := context.WithTimeout(ctx, limits.Deadline())
	defer cancel()
	semanticsStarted := time.Now()
	semantics, err := s.databases.IdentifierSemantics(executionContext, profile.Datasource)
	if err != nil {
		errorKind := classifyDatabaseAuditError(err)
		if auditErr := s.writeAudit(context.WithoutCancel(ctx), audit.Event{
			Type: "query_completion", RequestID: requestID, QueryID: queryID, Principal: principal,
			ClientIdentifier: clientIdentifier,
			PolicyProfile:    request.Profile, PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(),
			Datasource: profile.Datasource, Adapter: adapterName, Operation: string(domain.OperationExplainSelect),
			Outcome: "error", ErrorKind: string(errorKind),
			DurationMS: durationMilliseconds(semanticsStarted), QueryShapeHash: queryShapeHash,
		}); auditErr != nil {
			return ExplainResult{}, &Error{Kind: ErrorServiceUnavailable, Err: auditErr}
		}
		return ExplainResult{}, mapDatabaseError(err)
	}
	s.observeIdentifierSemantics(request.Profile, semantics)
	authorized, err := s.policy.AuthorizeExplain(
		principal,
		request.Profile,
		validated,
		semantics,
	)
	if err != nil {
		reason := policy.ReasonDeniedOperation
		policy.IsDenial(err, &reason)
		if auditErr := s.writeDenial(ctx, requestID, queryID, principal, clientIdentifier, request.Profile, domain.OperationExplainSelect, reason, queryShapeHash); auditErr != nil {
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
		Datasource: profile.Datasource, Adapter: adapterName, Operation: string(domain.OperationExplainSelect),
		Decision: "allow", QueryShapeHash: queryShapeHash, Resources: resources, Fields: fields,
	}
	if err := s.writeAudit(ctx, decision); err != nil {
		return ExplainResult{}, &Error{Kind: ErrorServiceUnavailable, Err: err}
	}
	releaseCapacity, ok := s.acquireCapacity(request.Profile)
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
		Datasource: profile.Datasource, Adapter: adapterName, Operation: string(domain.OperationExplainSelect),
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
		Datasource: profile.Datasource, Adapter: adapterName, Format: databaseResult.Format,
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
	requiredByDatasource := make(map[string]string)
	for profileName, required := range s.discoveryNeeded {
		if !required {
			continue
		}
		datasource := s.profileDatasource(profileName)
		if !s.supportsConfiguredQueryShapes(profileName, datasource) {
			continue
		}
		requiredByDatasource[datasource] = profileName
	}
	for datasource, profileName := range requiredByDatasource {
		probeContext, cancel := context.WithTimeout(ctx, 2*time.Second)
		semantics, err := s.databases.IdentifierSemantics(probeContext, datasource)
		cancel()
		if err != nil {
			return err
		}
		s.observeIdentifierSemantics(profileName, semantics)
	}
	s.discoveryMu.RLock()
	defer s.discoveryMu.RUnlock()
	for profile, required := range s.discoveryNeeded {
		datasource := s.profileDatasource(profile)
		if !required || !s.supportsConfiguredQueryShapes(profile, datasource) {
			continue
		}
		if s.queryShapes[profile] == nil {
			return errors.New("required query-shape discovery snapshot is unavailable")
		}
	}
	return nil
}

func (s *Service) supportsConfiguredQueryShapes(profileName, datasource string) bool {
	configured, ok := s.queryShapeSupport[profileName]
	return ok && configured.count != 0 && configured.datasource == datasource && configured.supported
}

func (s *Service) profileDatasource(profileName string) string {
	datasource, _, _, ok := s.policy.ProfileBinding(profileName)
	if !ok {
		return ""
	}
	return datasource
}

func (s *Service) assignedProfile(principal, name string) (config.Profile, bool) {
	if !slices.Contains(s.policy.PrincipalProfiles(principal), name) {
		return config.Profile{}, false
	}
	datasource, operations, limits, ok := s.policy.ProfileBinding(name)
	if !ok {
		return config.Profile{}, false
	}
	return config.Profile{Datasource: datasource, Operations: operations, Limits: limits}, true
}

func (s *Service) acquireCapacity(profile string) (func(), bool) {
	select {
	case s.globalCapacity <- struct{}{}:
	default:
		return nil, false
	}
	profileGate, ok := s.profileCapacity[profile]
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
	requestID, queryID, principal, clientIdentifier, profile string,
	operation domain.Operation,
	reason, queryShapeHash string,
) error {
	datasource, _, _, _ := s.policy.ProfileBinding(profile)
	eventType := "operation_decision"
	if queryID != "" {
		eventType = "query_decision"
	}
	return s.writeAudit(context.WithoutCancel(ctx), audit.Event{
		Type: eventType, RequestID: requestID, QueryID: queryID, Principal: principal,
		ClientIdentifier: clientIdentifier,
		PolicyProfile:    profile, PolicyVersion: s.policy.Version(), PolicyHash: s.policy.Hash(),
		Datasource: datasource, Adapter: s.databases.AdapterName(datasource),
		Operation: string(operation), Decision: "deny", ReasonCode: reason,
		QueryShapeHash: queryShapeHash,
	})
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

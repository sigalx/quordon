package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/queryspec"
)

const (
	ReasonDeniedOperation    = "DENIED_OPERATION"
	ReasonDeniedResource     = "DENIED_RESOURCE"
	ReasonDeniedField        = "DENIED_FIELD"
	ReasonDeniedQueryFeature = "DENIED_QUERY_FEATURE"
)

type Denial struct {
	ReasonCode string
}

func (d *Denial) Error() string { return d.ReasonCode }

type Snapshot struct {
	version    string
	hash       string
	hardLimits domain.Limits
	principals map[string]config.Principal
	profiles   map[string]config.Profile
}

// BindingKey identifies one configured policy route. It is a derived key used
// for bounded runtime state, not a separately configurable policy entity.
type BindingKey struct {
	Profile    string
	Datasource string
}

// AuthorizedBinding is minted only after all three assignment checks pass:
// principal -> profile, principal -> datasource, and profile -> datasource.
// Its fields remain private so callers cannot change routing after approval.
type AuthorizedBinding struct {
	owner      *Snapshot
	principal  string
	key        BindingKey
	operation  domain.Operation
	limits     domain.Limits
	policyHash string
}

func (a AuthorizedBinding) Principal() string           { return a.principal }
func (a AuthorizedBinding) Profile() string             { return a.key.Profile }
func (a AuthorizedBinding) Datasource() string          { return a.key.Datasource }
func (a AuthorizedBinding) Operation() domain.Operation { return a.operation }
func (a AuthorizedBinding) Limits() domain.Limits       { return a.limits }
func (a AuthorizedBinding) Key() BindingKey             { return a.key }

func NewSnapshot(cfg config.Config) *Snapshot {
	return &Snapshot{
		version:    cfg.PolicyVersion(),
		hash:       cfg.PolicyHash,
		hardLimits: cfg.HardLimits,
		principals: clonePrincipals(cfg.Principals),
		profiles:   cloneProfiles(cfg.Profiles),
	}
}

func (s *Snapshot) Version() string           { return s.version }
func (s *Snapshot) Hash() string              { return s.hash }
func (s *Snapshot) HardLimits() domain.Limits { return s.hardLimits }

func (s *Snapshot) PrincipalProfiles(principal string) []string {
	configured, ok := s.principals[principal]
	if !ok {
		return nil
	}
	return append([]string(nil), configured.Profiles...)
}

func (s *Snapshot) PrincipalDatasources(principal string) []string {
	configured, ok := s.principals[principal]
	if !ok {
		return nil
	}
	return slices.Clone(configured.Datasources)
}

func (s *Snapshot) Profile(name string) (config.Profile, bool) {
	profile, ok := s.profiles[name]
	if !ok {
		return config.Profile{}, false
	}
	return cloneProfile(profile), true
}

// ProfileBinding exposes only the immutable routing and limit fields needed by
// the service before operation-specific authorization. It deliberately avoids
// cloning the potentially large aggregate shape policy on every request.
func (s *Snapshot) ProfileBinding(name string) ([]string, []domain.Operation, domain.Limits, bool) {
	profile, ok := s.profiles[name]
	if !ok {
		return nil, nil, domain.Limits{}, false
	}
	return slices.Clone(profile.Datasources), slices.Clone(profile.Operations), profile.Limits, true
}

func (s *Snapshot) AuthorizeBinding(
	principal, profileName, datasource string, operation domain.Operation,
) (AuthorizedBinding, error) {
	principalConfig, ok := s.principals[principal]
	if !ok || !slices.Contains(principalConfig.Profiles, profileName) ||
		!slices.Contains(principalConfig.Datasources, datasource) {
		return AuthorizedBinding{}, &Denial{ReasonCode: ReasonDeniedOperation}
	}
	profile, ok := s.profiles[profileName]
	if !ok || !slices.Contains(profile.Datasources, datasource) ||
		!slices.Contains(profile.Operations, operation) {
		return AuthorizedBinding{}, &Denial{ReasonCode: ReasonDeniedOperation}
	}
	return AuthorizedBinding{
		owner: s, principal: principal,
		key:       BindingKey{Profile: profileName, Datasource: datasource},
		operation: operation, limits: s.hardLimits.Min(profile.Limits), policyHash: s.hash,
	}, nil
}

func (s *Snapshot) profileForBinding(binding AuthorizedBinding, operation domain.Operation) (config.Profile, error) {
	if binding.owner != s || binding.policyHash != s.hash || binding.principal == "" ||
		binding.key.Profile == "" || binding.key.Datasource == "" || binding.operation != operation {
		return config.Profile{}, &Denial{ReasonCode: ReasonDeniedOperation}
	}
	principal, ok := s.principals[binding.principal]
	if !ok || !slices.Contains(principal.Profiles, binding.key.Profile) ||
		!slices.Contains(principal.Datasources, binding.key.Datasource) {
		return config.Profile{}, &Denial{ReasonCode: ReasonDeniedOperation}
	}
	profile, ok := s.profiles[binding.key.Profile]
	if !ok || !slices.Contains(profile.Datasources, binding.key.Datasource) ||
		!slices.Contains(profile.Operations, operation) {
		return config.Profile{}, &Denial{ReasonCode: ReasonDeniedOperation}
	}
	return profile, nil
}

// AllowsSourceText exposes a scalar feature setting without cloning the
// profile's potentially large immutable shape policy.
func (s *Snapshot) AllowsSourceText(name string) bool {
	profile, ok := s.profiles[name]
	return ok && profile.Query.AllowSourceText
}

func clonePrincipals(source map[string]config.Principal) map[string]config.Principal {
	if source == nil {
		return nil
	}
	cloned := make(map[string]config.Principal, len(source))
	for name, principal := range source {
		principal.Profiles = slices.Clone(principal.Profiles)
		principal.Datasources = slices.Clone(principal.Datasources)
		cloned[name] = principal
	}
	return cloned
}

func cloneProfiles(source map[string]config.Profile) map[string]config.Profile {
	if source == nil {
		return nil
	}
	cloned := make(map[string]config.Profile, len(source))
	for name, profile := range source {
		cloned[name] = cloneProfile(profile)
	}
	return cloned
}

func cloneProfile(profile config.Profile) config.Profile {
	profile.Datasources = slices.Clone(profile.Datasources)
	profile.Operations = slices.Clone(profile.Operations)
	profile.Resources.Schemas.Allow = slices.Clone(profile.Resources.Schemas.Allow)
	profile.Resources.Schemas.Deny = slices.Clone(profile.Resources.Schemas.Deny)
	profile.Resources.Objects.Allow = slices.Clone(profile.Resources.Objects.Allow)
	profile.Resources.Objects.Deny = slices.Clone(profile.Resources.Objects.Deny)
	profile.Resources.Fields.Allow = slices.Clone(profile.Resources.Fields.Allow)
	profile.Resources.Fields.Deny = slices.Clone(profile.Resources.Fields.Deny)
	profile.Query.AllowedFilterOperators = slices.Clone(profile.Query.AllowedFilterOperators)
	profile.Query.AllowedAggregates = slices.Clone(profile.Query.AllowedAggregates)
	profile.Query.AggregateShapes = cloneAggregateShapes(profile.Query.AggregateShapes)
	profile.Query.KeysetSelectShapes = cloneKeysetSelectShapes(profile.Query.KeysetSelectShapes)
	return profile
}

func cloneKeysetSelectShapes(shapes []config.KeysetSelectShape) []config.KeysetSelectShape {
	cloned := make([]config.KeysetSelectShape, len(shapes))
	for index, shape := range shapes {
		shape.AllowTemporaryTable = cloneBool(shape.AllowTemporaryTable)
		shape.AllowFilesort = cloneBool(shape.AllowFilesort)
		if shape.PublicDescription != nil {
			description := *shape.PublicDescription
			shape.PublicDescription = &description
		}
		shape.Projection = slices.Clone(shape.Projection)
		shape.Filter = cloneAggregateShapeFilter(shape.Filter)
		shape.OrderBy = slices.Clone(shape.OrderBy)
		cloned[index] = shape
	}
	return cloned
}

func cloneAggregateShapes(shapes []config.AggregateShape) []config.AggregateShape {
	cloned := make([]config.AggregateShape, len(shapes))
	for index, shape := range shapes {
		if shape.PublicDescription != nil {
			description := *shape.PublicDescription
			shape.PublicDescription = &description
		}
		shape.Projection = slices.Clone(shape.Projection)
		for i := range shape.Projection {
			shape.Projection[i].Boundaries = slices.Clone(shape.Projection[i].Boundaries)
		}
		shape.OrderBy = slices.Clone(shape.OrderBy)
		shape.Filter = cloneAggregateShapeFilter(shape.Filter)
		shape.AllowTemporaryTable = cloneBool(shape.AllowTemporaryTable)
		shape.AllowFilesort = cloneBool(shape.AllowFilesort)
		cloned[index] = shape
	}
	return cloned
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneAggregateShapeFilter(filter *config.AggregateShapeFilter) *config.AggregateShapeFilter {
	if filter == nil {
		return nil
	}
	cloned := *filter
	if filter.ValueTypes != nil {
		values := slices.Clone(*filter.ValueTypes)
		cloned.ValueTypes = &values
	}
	cloned.Expressions = make([]config.AggregateShapeFilter, len(filter.Expressions))
	for index := range filter.Expressions {
		cloned.Expressions[index] = *cloneAggregateShapeFilter(&filter.Expressions[index])
	}
	return &cloned
}

type AuthorizedQuery struct {
	principal  string
	profile    string
	datasource string
	operation  domain.Operation
	limits     domain.Limits
	query      queryspec.Validated
}

type AuthorizedAggregate struct {
	numericBoundaries          map[string][]string
	parameterCount             int
	principal                  string
	profile                    string
	datasource                 string
	operation                  domain.Operation
	limits                     domain.Limits
	query                      queryspec.ValidatedAggregate
	requiredIndex              string
	maximumRowsExaminedPerScan uint64
	shapeName                  string
	allowTemporaryTable        bool
	allowFilesort              bool
}

func (a AuthorizedAggregate) Principal() string           { return a.principal }
func (a AuthorizedAggregate) Profile() string             { return a.profile }
func (a AuthorizedAggregate) Datasource() string          { return a.datasource }
func (a AuthorizedAggregate) Operation() domain.Operation { return a.operation }
func (a AuthorizedAggregate) Limits() domain.Limits       { return a.limits }
func (a AuthorizedAggregate) Query() queryspec.NormalizedAggregateSpec {
	return a.query.Spec()
}

// ParameterCount includes all policy-owned numeric bucket bind occurrences.
func (a AuthorizedAggregate) ParameterCount() int { return a.parameterCount }

// NumericBoundaries returns independent policy-owned data, keyed by normalized alias.
func (a AuthorizedAggregate) NumericBoundaries() map[string][]string {
	result := make(map[string][]string, len(a.numericBoundaries))
	for alias, boundaries := range a.numericBoundaries {
		result[alias] = slices.Clone(boundaries)
	}
	return result
}
func (a AuthorizedAggregate) RequiredIndex() string { return a.requiredIndex }
func (a AuthorizedAggregate) MaximumRowsExaminedPerScan() uint64 {
	return a.maximumRowsExaminedPerScan
}
func (a AuthorizedAggregate) ShapeName() string         { return a.shapeName }
func (a AuthorizedAggregate) AllowTemporaryTable() bool { return a.allowTemporaryTable }
func (a AuthorizedAggregate) AllowFilesort() bool       { return a.allowFilesort }
func (a AuthorizedAggregate) ReferencedFields() []string {
	return queryspec.AggregateReferencedFields(a.query.Spec())
}

func (q AuthorizedQuery) Principal() string               { return q.principal }
func (q AuthorizedQuery) Profile() string                 { return q.profile }
func (q AuthorizedQuery) Datasource() string              { return q.datasource }
func (q AuthorizedQuery) Operation() domain.Operation     { return q.operation }
func (q AuthorizedQuery) Limits() domain.Limits           { return q.limits }
func (q AuthorizedQuery) Query() queryspec.NormalizedSpec { return q.query.Spec() }
func (q AuthorizedQuery) ReferencedFields() []string      { return referencedFields(q.query.Spec()) }

func (s *Snapshot) AuthorizeExplain(
	binding AuthorizedBinding,
	query queryspec.Validated,
	semantics domain.IdentifierSemantics,
) (AuthorizedQuery, error) {
	return s.authorizeQuery(binding, domain.OperationExplainSelect, query, semantics)
}

func (s *Snapshot) AuthorizeSelect(
	binding AuthorizedBinding,
	query queryspec.Validated,
	semantics domain.IdentifierSemantics,
) (AuthorizedQuery, error) {
	return s.authorizeQuery(binding, domain.OperationSelect, query, semantics)
}

func (s *Snapshot) AuthorizeAggregate(
	binding AuthorizedBinding,
	query queryspec.ValidatedAggregate,
	semantics domain.IdentifierSemantics,
) (AuthorizedAggregate, error) {
	profile, err := s.profileForBinding(binding, domain.OperationAggregate)
	if err != nil {
		return AuthorizedAggregate{}, &Denial{ReasonCode: ReasonDeniedOperation}
	}
	effectiveLimits := s.hardLimits.Min(profile.Limits)
	revalidated, err := queryspec.RevalidateAggregate(
		query,
		effectiveLimits.MaxProjectionFields,
		effectiveLimits.MaxGroupByFields,
		effectiveLimits.MaxOrderByFields,
		effectiveLimits.MaxPredicates,
		effectiveLimits.MaxExpressionDepth,
		effectiveLimits.MaxParameters,
		effectiveLimits.MaxRows,
	)
	if err != nil {
		return AuthorizedAggregate{}, err
	}
	normalized, err := queryspec.NormalizeAggregateIdentifiers(revalidated, semantics)
	if err != nil {
		return AuthorizedAggregate{}, err
	}
	spec := normalized.Spec()
	if !allowed(
		profile.Resources.Schemas,
		[]string{spec.Source.Schema},
		[]bool{semantics.CaseInsensitiveSchemas},
	) || !allowed(
		profile.Resources.Objects,
		[]string{spec.Source.Schema, spec.Source.Name},
		[]bool{semantics.CaseInsensitiveSchemas, semantics.CaseInsensitiveObjects},
	) {
		return AuthorizedAggregate{}, &Denial{ReasonCode: ReasonDeniedResource}
	}
	for _, field := range queryspec.AggregateReferencedFields(spec) {
		if !allowed(
			profile.Resources.Fields,
			[]string{spec.Source.Schema, spec.Source.Name, field},
			[]bool{
				semantics.CaseInsensitiveSchemas,
				semantics.CaseInsensitiveObjects,
				semantics.CaseInsensitiveFields,
			},
		) {
			return AuthorizedAggregate{}, &Denial{ReasonCode: ReasonDeniedField}
		}
	}
	if err := authorizeAggregateFeatures(profile.Query, spec); err != nil {
		return AuthorizedAggregate{}, err
	}
	shape, ok := matchAggregateShape(profile.Query.AggregateShapes, spec, semantics)
	if !ok {
		return AuthorizedAggregate{}, &Denial{ReasonCode: ReasonDeniedQueryFeature}
	}
	if (queryspec.AggregateUsesTimeBucket(spec) || queryspec.AggregateUsesNumericBucket(spec)) &&
		(shape.AllowTemporaryTable == nil || shape.AllowFilesort == nil) {
		return AuthorizedAggregate{}, errors.New("aggregate bucket execution controls are missing")
	}
	counts := make(map[string]int)
	for _, output := range shape.Projection {
		if output.Kind == "numeric_bucket" {
			counts[strings.ToLower(output.Alias)] = len(output.Boundaries)
		}
	}
	parameterCount, err := queryspec.NumericBucketParameters(spec, counts, normalized.Stats().Parameters, effectiveLimits.MaxParameters)
	if err != nil {
		return AuthorizedAggregate{}, err
	}
	boundaries := make(map[string][]string, len(counts))
	for _, output := range shape.Projection {
		if output.Kind == "numeric_bucket" {
			canonical, err := queryspec.NormalizeNumericBoundaries(output.Boundaries)
			if err != nil {
				return AuthorizedAggregate{}, errors.New("invalid numeric bucket policy")
			}
			boundaries[strings.ToLower(output.Alias)] = canonical
		}
	}
	allowTemporaryTable := shape.AllowTemporaryTable != nil && *shape.AllowTemporaryTable
	allowFilesort := shape.AllowFilesort != nil && *shape.AllowFilesort
	return AuthorizedAggregate{
		principal: binding.Principal(), profile: binding.Profile(), datasource: binding.Datasource(),
		operation: domain.OperationAggregate, limits: effectiveLimits, query: normalized, numericBoundaries: boundaries, parameterCount: parameterCount,
		requiredIndex:              shape.RequiredIndex,
		maximumRowsExaminedPerScan: shape.MaximumRowsExaminedPerScan,
		shapeName:                  shape.Name,
		allowTemporaryTable:        allowTemporaryTable,
		allowFilesort:              allowFilesort,
	}, nil
}

func (s *Snapshot) authorizeQuery(
	binding AuthorizedBinding,
	operation domain.Operation,
	query queryspec.Validated,
	semantics domain.IdentifierSemantics,
) (AuthorizedQuery, error) {
	profile, err := s.profileForBinding(binding, operation)
	if err != nil {
		return AuthorizedQuery{}, &Denial{ReasonCode: ReasonDeniedOperation}
	}
	effectiveLimits := s.hardLimits.Min(profile.Limits)
	revalidated, err := queryspec.Revalidate(
		query,
		effectiveLimits.MaxProjectionFields,
		effectiveLimits.MaxGroupByFields,
		effectiveLimits.MaxOrderByFields,
		effectiveLimits.MaxPredicates,
		effectiveLimits.MaxExpressionDepth,
		effectiveLimits.MaxParameters,
		effectiveLimits.MaxRows,
		effectiveLimits.MaxOffset,
	)
	if err != nil {
		return AuthorizedQuery{}, err
	}
	if operation == domain.OperationSelect {
		if err := queryspec.ValidateSimpleSelect(revalidated); err != nil {
			return AuthorizedQuery{}, err
		}
	}

	spec := revalidated.Spec()
	if !allowed(
		profile.Resources.Schemas,
		[]string{spec.Source.Schema},
		[]bool{semantics.CaseInsensitiveSchemas},
	) || !allowed(
		profile.Resources.Objects,
		[]string{spec.Source.Schema, spec.Source.Name},
		[]bool{semantics.CaseInsensitiveSchemas, semantics.CaseInsensitiveObjects},
	) {
		return AuthorizedQuery{}, &Denial{ReasonCode: ReasonDeniedResource}
	}
	for _, field := range referencedFields(spec) {
		if !allowed(
			profile.Resources.Fields,
			[]string{spec.Source.Schema, spec.Source.Name, field},
			[]bool{
				semantics.CaseInsensitiveSchemas,
				semantics.CaseInsensitiveObjects,
				semantics.CaseInsensitiveFields,
			},
		) {
			return AuthorizedQuery{}, &Denial{ReasonCode: ReasonDeniedField}
		}
	}
	if err := authorizeFeatures(profile.Query, spec); err != nil {
		return AuthorizedQuery{}, err
	}

	return AuthorizedQuery{
		principal:  binding.Principal(),
		profile:    binding.Profile(),
		datasource: binding.Datasource(),
		operation:  operation,
		limits:     effectiveLimits,
		query:      revalidated,
	}, nil
}

type AuthorizedSchema struct {
	principal  string
	profile    string
	datasource string
	operation  domain.Operation
	schema     string
	object     string
	limits     domain.Limits
	resources  config.ResourcePolicy
	semantics  domain.IdentifierSemantics
}

// AuthorizedObjectStatistics is an immutable, operation-specific grant. It is
// intentionally distinct from AuthorizedSchema: permission to describe fields
// must never imply permission to disclose table or partition statistics.
type AuthorizedObjectStatistics struct {
	principal            string
	credentialIdentifier string
	profile              string
	policyVersion        string
	policyHash           string
	datasource           string
	adapter              string
	operation            domain.Operation
	schema               string
	object               string
	limits               domain.Limits
	semantics            domain.IdentifierSemantics
	semanticsGeneration  string
}

func (a AuthorizedObjectStatistics) Principal() string            { return a.principal }
func (a AuthorizedObjectStatistics) CredentialIdentifier() string { return a.credentialIdentifier }
func (a AuthorizedObjectStatistics) Profile() string              { return a.profile }
func (a AuthorizedObjectStatistics) PolicyVersion() string        { return a.policyVersion }
func (a AuthorizedObjectStatistics) PolicyHash() string           { return a.policyHash }
func (a AuthorizedObjectStatistics) Datasource() string           { return a.datasource }
func (a AuthorizedObjectStatistics) Adapter() string              { return a.adapter }
func (a AuthorizedObjectStatistics) Operation() domain.Operation  { return a.operation }
func (a AuthorizedObjectStatistics) Schema() string               { return a.schema }
func (a AuthorizedObjectStatistics) Object() string               { return a.object }
func (a AuthorizedObjectStatistics) Limits() domain.Limits        { return a.limits }
func (a AuthorizedObjectStatistics) IdentifierSemantics() domain.IdentifierSemantics {
	return a.semantics
}
func (a AuthorizedObjectStatistics) IdentifierSemanticsGeneration() string {
	return a.semanticsGeneration
}

func (s *Snapshot) AuthorizeObjectStatistics(
	binding AuthorizedBinding, credentialIdentifier, adapterName string,
	resource queryspec.ResourceRef,
	semantics domain.IdentifierSemantics,
) (AuthorizedObjectStatistics, error) {
	if binding.Principal() == "" || credentialIdentifier == "" || binding.Profile() == "" || adapterName == "" {
		return AuthorizedObjectStatistics{}, &Denial{ReasonCode: ReasonDeniedOperation}
	}
	if !queryspec.IsIdentifier(resource.Schema) || !queryspec.IsIdentifier(resource.Name) {
		return AuthorizedObjectStatistics{}, &Denial{ReasonCode: ReasonDeniedResource}
	}
	profile, err := s.profileForBinding(binding, domain.OperationDescribeObjectStatistics)
	if err != nil {
		return AuthorizedObjectStatistics{}, &Denial{ReasonCode: ReasonDeniedOperation}
	}
	if !allowed(
		profile.Resources.Schemas,
		[]string{resource.Schema},
		[]bool{semantics.CaseInsensitiveSchemas},
	) || !allowed(
		profile.Resources.Objects,
		[]string{resource.Schema, resource.Name},
		[]bool{semantics.CaseInsensitiveSchemas, semantics.CaseInsensitiveObjects},
	) {
		return AuthorizedObjectStatistics{}, &Denial{ReasonCode: ReasonDeniedResource}
	}
	generationInput := fmt.Sprintf(
		"%s\x00%s\x00%s\x00%t%t%t",
		s.hash, binding.Profile()+"\x00"+binding.Datasource(), adapterName,
		semantics.CaseInsensitiveSchemas,
		semantics.CaseInsensitiveObjects,
		semantics.CaseInsensitiveFields,
	)
	generationDigest := sha256.Sum256([]byte(generationInput))
	return AuthorizedObjectStatistics{
		principal: binding.Principal(), credentialIdentifier: credentialIdentifier,
		profile: binding.Profile(), policyVersion: s.version, policyHash: s.hash,
		datasource: binding.Datasource(), adapter: adapterName,
		operation: domain.OperationDescribeObjectStatistics,
		schema:    canonicalPolicyIdentifier(resource.Schema, semantics.CaseInsensitiveSchemas),
		object:    canonicalPolicyIdentifier(resource.Name, semantics.CaseInsensitiveObjects),
		limits:    s.hardLimits.Min(profile.Limits), semantics: semantics,
		semanticsGeneration: hex.EncodeToString(generationDigest[:]),
	}, nil
}

func (a AuthorizedSchema) Principal() string           { return a.principal }
func (a AuthorizedSchema) Profile() string             { return a.profile }
func (a AuthorizedSchema) Datasource() string          { return a.datasource }
func (a AuthorizedSchema) Operation() domain.Operation { return a.operation }
func (a AuthorizedSchema) Schema() string              { return a.schema }
func (a AuthorizedSchema) Object() string              { return a.object }
func (a AuthorizedSchema) Limits() domain.Limits       { return a.limits }

func (a AuthorizedSchema) AllowsObject(object string) bool {
	if a.operation != domain.OperationListObjects || a.object != "" {
		return false
	}
	return allowed(
		a.resources.Objects,
		[]string{a.schema, object},
		[]bool{a.semantics.CaseInsensitiveSchemas, a.semantics.CaseInsensitiveObjects},
	)
}

func (a AuthorizedSchema) AllowsField(field string) bool {
	if a.operation != domain.OperationDescribeObject || a.object == "" {
		return false
	}
	return allowed(
		a.resources.Fields,
		[]string{a.schema, a.object, field},
		[]bool{
			a.semantics.CaseInsensitiveSchemas,
			a.semantics.CaseInsensitiveObjects,
			a.semantics.CaseInsensitiveFields,
		},
	)
}

func (s *Snapshot) AuthorizeListObjects(
	binding AuthorizedBinding, schema string,
	semantics domain.IdentifierSemantics,
) (AuthorizedSchema, error) {
	return s.authorizeSchema(
		binding, domain.OperationListObjects,
		queryspec.ResourceRef{Schema: schema}, semantics,
	)
}

func (s *Snapshot) AuthorizeDescribeObject(
	binding AuthorizedBinding,
	object queryspec.ResourceRef,
	semantics domain.IdentifierSemantics,
) (AuthorizedSchema, error) {
	return s.authorizeSchema(
		binding, domain.OperationDescribeObject, object, semantics,
	)
}

func (s *Snapshot) authorizeSchema(
	binding AuthorizedBinding,
	operation domain.Operation,
	resource queryspec.ResourceRef,
	semantics domain.IdentifierSemantics,
) (AuthorizedSchema, error) {
	switch operation {
	case domain.OperationListObjects:
		if !queryspec.IsIdentifier(resource.Schema) || resource.Name != "" {
			return AuthorizedSchema{}, &Denial{ReasonCode: ReasonDeniedResource}
		}
	case domain.OperationDescribeObject:
		if !queryspec.IsIdentifier(resource.Schema) || !queryspec.IsIdentifier(resource.Name) {
			return AuthorizedSchema{}, &Denial{ReasonCode: ReasonDeniedResource}
		}
	default:
		return AuthorizedSchema{}, &Denial{ReasonCode: ReasonDeniedOperation}
	}
	profile, err := s.profileForBinding(binding, operation)
	if err != nil {
		return AuthorizedSchema{}, &Denial{ReasonCode: ReasonDeniedOperation}
	}
	if !allowed(
		profile.Resources.Schemas,
		[]string{resource.Schema},
		[]bool{semantics.CaseInsensitiveSchemas},
	) {
		return AuthorizedSchema{}, &Denial{ReasonCode: ReasonDeniedResource}
	}
	if resource.Name != "" && !allowed(
		profile.Resources.Objects,
		[]string{resource.Schema, resource.Name},
		[]bool{semantics.CaseInsensitiveSchemas, semantics.CaseInsensitiveObjects},
	) {
		return AuthorizedSchema{}, &Denial{ReasonCode: ReasonDeniedResource}
	}
	return AuthorizedSchema{
		principal: binding.Principal(), profile: binding.Profile(), datasource: binding.Datasource(),
		operation: operation, schema: resource.Schema, object: resource.Name,
		limits:    s.hardLimits.Min(profile.Limits),
		resources: cloneResourcePolicy(profile.Resources), semantics: semantics,
	}, nil
}

func cloneResourcePolicy(resources config.ResourcePolicy) config.ResourcePolicy {
	resources.Schemas.Allow = slices.Clone(resources.Schemas.Allow)
	resources.Schemas.Deny = slices.Clone(resources.Schemas.Deny)
	resources.Objects.Allow = slices.Clone(resources.Objects.Allow)
	resources.Objects.Deny = slices.Clone(resources.Objects.Deny)
	resources.Fields.Allow = slices.Clone(resources.Fields.Allow)
	resources.Fields.Deny = slices.Clone(resources.Fields.Deny)
	return resources
}

func authorizeFeatures(policy config.QueryPolicy, spec queryspec.NormalizedSpec) error {
	if queryspec.UsesSourceText(spec) && !policy.AllowSourceText {
		return &Denial{ReasonCode: ReasonDeniedQueryFeature}
	}
	if spec.Filter != nil {
		if !policy.AllowFiltering {
			return &Denial{ReasonCode: ReasonDeniedQueryFeature}
		}
		var operators []string
		collectOperators(*spec.Filter, &operators)
		for _, operator := range operators {
			if !slices.Contains(policy.AllowedFilterOperators, operator) {
				return &Denial{ReasonCode: ReasonDeniedQueryFeature}
			}
		}
	}
	if len(spec.GroupBy) > 0 && !policy.AllowGroupBy {
		return &Denial{ReasonCode: ReasonDeniedQueryFeature}
	}
	if len(spec.OrderBy) > 0 && !policy.AllowSorting {
		return &Denial{ReasonCode: ReasonDeniedQueryFeature}
	}
	for _, selection := range spec.Projection {
		if selection.Kind == "aggregate" && !slices.Contains(policy.AllowedAggregates, selection.Function) {
			return &Denial{ReasonCode: ReasonDeniedQueryFeature}
		}
	}
	return nil
}

func authorizeAggregateFeatures(policy config.QueryPolicy, spec queryspec.NormalizedAggregateSpec) error {
	if queryspec.AggregateUsesSourceText(spec) && !policy.AllowSourceText {
		return &Denial{ReasonCode: ReasonDeniedQueryFeature}
	}
	if spec.Filter != nil {
		if !policy.AllowFiltering {
			return &Denial{ReasonCode: ReasonDeniedQueryFeature}
		}
		var operators []string
		collectOperators(*spec.Filter, &operators)
		for _, operator := range operators {
			if !slices.Contains(policy.AllowedFilterOperators, operator) {
				return &Denial{ReasonCode: ReasonDeniedQueryFeature}
			}
		}
	}
	if spec.Mode == queryspec.AggregateModeGrouped && !policy.AllowGroupBy {
		return &Denial{ReasonCode: ReasonDeniedQueryFeature}
	}
	if len(spec.OrderBy) != 0 && !policy.AllowSorting {
		return &Denial{ReasonCode: ReasonDeniedQueryFeature}
	}
	for _, output := range spec.Projection {
		if output.Kind != "measure" {
			continue
		}
		function := output.Function
		if function == "count_all" {
			function = "count"
		}
		if !slices.Contains(policy.AllowedAggregates, function) {
			return &Denial{ReasonCode: ReasonDeniedQueryFeature}
		}
	}
	return nil
}

type aggregateShapeProjection struct {
	Representation queryspec.Representation `json:"representation,omitempty"`
	Kind           string                   `json:"kind"`
	Field          string                   `json:"field,omitempty"`
	Function       string                   `json:"function,omitempty"`
	Alias          string                   `json:"alias,omitempty"`
	Unit           string                   `json:"unit,omitempty"`
	Timezone       string                   `json:"timezone,omitempty"`
}

type aggregateShapeOrder struct {
	Representation queryspec.Representation `json:"representation,omitempty"`
	Kind           string                   `json:"kind"`
	Field          string                   `json:"field,omitempty"`
	Alias          string                   `json:"alias,omitempty"`
	Direction      string                   `json:"direction"`
}

type aggregateShapeFilter struct {
	Representation queryspec.Representation `json:"representation,omitempty"`
	Kind           string                   `json:"kind"`
	Field          string                   `json:"field,omitempty"`
	Operator       string                   `json:"operator"`
	ValueTypes     []string                 `json:"value_types,omitempty"`
	Expressions    []aggregateShapeFilter   `json:"expressions,omitempty"`
}

type aggregateShapeSignature struct {
	Mode       string                     `json:"mode"`
	Schema     string                     `json:"schema"`
	Object     string                     `json:"object"`
	Projection []aggregateShapeProjection `json:"projection"`
	Filter     *aggregateShapeFilter      `json:"filter,omitempty"`
	OrderBy    []aggregateShapeOrder      `json:"order_by,omitempty"`
}

func matchAggregateShape(
	shapes []config.AggregateShape,
	spec queryspec.NormalizedAggregateSpec,
	semantics domain.IdentifierSemantics,
) (config.AggregateShape, bool) {
	querySignature := aggregateQuerySignature(spec)
	queryJSON, err := json.Marshal(querySignature)
	if err != nil {
		return config.AggregateShape{}, false
	}
	var matched *config.AggregateShape
	for index := range shapes {
		shape := shapes[index]
		if spec.Mode == queryspec.AggregateModeGrouped && spec.Limit > shape.MaximumLimit {
			continue
		}
		shapeSignature, ok := configuredAggregateShapeSignature(shape, semantics)
		if !ok {
			continue
		}
		shapeJSON, err := json.Marshal(shapeSignature)
		if err != nil || string(shapeJSON) != string(queryJSON) {
			continue
		}
		if matched != nil {
			return config.AggregateShape{}, false
		}
		copy := shape
		matched = &copy
	}
	if matched == nil {
		return config.AggregateShape{}, false
	}
	return *matched, true
}

func aggregateQuerySignature(spec queryspec.NormalizedAggregateSpec) aggregateShapeSignature {
	result := aggregateShapeSignature{
		Mode: spec.Mode, Schema: spec.Source.Schema, Object: spec.Source.Name,
		Projection: make([]aggregateShapeProjection, len(spec.Projection)),
		OrderBy:    make([]aggregateShapeOrder, len(spec.OrderBy)),
	}
	for index, output := range spec.Projection {
		result.Projection[index] = aggregateShapeProjection{
			Representation: output.Representation, Kind: output.Kind, Field: output.Field, Function: output.Function, Alias: output.Alias,
			Unit: output.Unit, Timezone: output.Timezone,
		}
	}
	result.Filter = queryAggregateShapeFilter(spec.Filter)
	for index, order := range spec.OrderBy {
		result.OrderBy[index] = aggregateShapeOrder{
			Representation: order.Representation, Kind: order.Kind, Field: order.Field, Alias: order.Alias, Direction: order.Direction,
		}
	}
	if spec.OrderBy == nil {
		result.OrderBy = nil
	}
	return result
}

func queryAggregateShapeFilter(filter *queryspec.Filter) *aggregateShapeFilter {
	if filter == nil {
		return nil
	}
	result := &aggregateShapeFilter{Representation: filter.Representation, Kind: filter.Kind, Field: filter.Field, Operator: filter.Operator}
	if filter.Kind == "predicate" {
		result.ValueTypes = make([]string, len(filter.Values))
		for index, value := range filter.Values {
			result.ValueTypes[index] = value.Type
		}
		return result
	}
	result.Expressions = make([]aggregateShapeFilter, len(filter.Expressions))
	for index := range filter.Expressions {
		result.Expressions[index] = *queryAggregateShapeFilter(&filter.Expressions[index])
	}
	// NormalizeAggregateIdentifiers has already ordered these children with the
	// shared queryspec shape digest and value tie-breaker.
	return result
}

func configuredAggregateShapeSignature(
	shape config.AggregateShape, semantics domain.IdentifierSemantics,
) (aggregateShapeSignature, bool) {
	result := aggregateShapeSignature{
		Mode:       shape.Mode,
		Schema:     canonicalPolicyIdentifier(shape.Source.Schema, semantics.CaseInsensitiveSchemas),
		Object:     canonicalPolicyIdentifier(shape.Source.Name, semantics.CaseInsensitiveObjects),
		Projection: make([]aggregateShapeProjection, len(shape.Projection)),
		OrderBy:    make([]aggregateShapeOrder, len(shape.OrderBy)),
	}
	for index, output := range shape.Projection {
		result.Projection[index] = aggregateShapeProjection{
			Representation: output.Representation, Kind: output.Kind,
			Field:    canonicalPolicyIdentifier(output.Field, semantics.CaseInsensitiveFields),
			Function: output.Function,
			Alias:    canonicalPolicyIdentifier(output.Alias, true),
			Unit:     output.Unit,
			Timezone: output.Timezone,
		}
	}
	var ok bool
	result.Filter, ok = configuredAggregateShapeFilter(shape.Filter, semantics.CaseInsensitiveFields)
	if !ok {
		return aggregateShapeSignature{}, false
	}
	for index, order := range shape.OrderBy {
		result.OrderBy[index] = aggregateShapeOrder{
			Representation: order.Representation, Kind: order.Kind,
			Field:     canonicalPolicyIdentifier(order.Field, semantics.CaseInsensitiveFields),
			Alias:     canonicalPolicyIdentifier(order.Alias, true),
			Direction: order.Direction,
		}
	}
	if shape.OrderBy == nil {
		result.OrderBy = nil
	}
	return result, true
}

func configuredAggregateShapeFilter(
	filter *config.AggregateShapeFilter, caseInsensitiveFields bool,
) (*aggregateShapeFilter, bool) {
	if filter == nil {
		return nil, true
	}
	result := &aggregateShapeFilter{
		Representation: filter.Representation, Kind: filter.Kind, Field: canonicalPolicyIdentifier(filter.Field, caseInsensitiveFields),
		Operator: filter.Operator,
	}
	if filter.Kind == "predicate" {
		if filter.ValueTypes == nil {
			return nil, false
		}
		result.ValueTypes = slices.Clone(*filter.ValueTypes)
		return result, true
	}
	result.Expressions = make([]aggregateShapeFilter, len(filter.Expressions))
	for index := range filter.Expressions {
		child, ok := configuredAggregateShapeFilter(&filter.Expressions[index], caseInsensitiveFields)
		if !ok || child == nil {
			return nil, false
		}
		result.Expressions[index] = *child
	}
	keys := sortAggregateShapeFilters(result.Expressions)
	for index := 1; index < len(keys); index++ {
		if keys[index-1] == keys[index] {
			return nil, false
		}
	}
	return result, true
}

func sortAggregateShapeFilters(filters []aggregateShapeFilter) []queryspec.AggregateFilterDigest {
	type keyedFilter struct {
		filter aggregateShapeFilter
		key    queryspec.AggregateFilterDigest
	}
	keyed := make([]keyedFilter, len(filters))
	for index, filter := range filters {
		keyed[index] = keyedFilter{filter: filter, key: aggregateShapeFilterKey(filter)}
	}
	slices.SortFunc(keyed, func(a, b keyedFilter) int {
		return bytes.Compare(a.key[:], b.key[:])
	})
	keys := make([]queryspec.AggregateFilterDigest, len(keyed))
	for index, item := range keyed {
		filters[index] = item.filter
		keys[index] = item.key
	}
	return keys
}

func aggregateShapeFilterKey(filter aggregateShapeFilter) queryspec.AggregateFilterDigest {
	converted := queryspec.Filter{Representation: filter.Representation, Kind: filter.Kind, Field: filter.Field, Operator: filter.Operator}
	if filter.Kind == "predicate" {
		converted.Values = make([]queryspec.TypedValue, len(filter.ValueTypes))
		for index, valueType := range filter.ValueTypes {
			converted.Values[index].Type = valueType
		}
	} else {
		converted.Expressions = make([]queryspec.Filter, len(filter.Expressions))
		for index, child := range filter.Expressions {
			converted.Expressions[index] = aggregateShapeFilterQuerySpec(child)
		}
	}
	return queryspec.AggregateFilterShapeDigest(converted)
}

func aggregateShapeFilterQuerySpec(filter aggregateShapeFilter) queryspec.Filter {
	converted := queryspec.Filter{Representation: filter.Representation, Kind: filter.Kind, Field: filter.Field, Operator: filter.Operator}
	converted.Values = make([]queryspec.TypedValue, len(filter.ValueTypes))
	for index, valueType := range filter.ValueTypes {
		converted.Values[index].Type = valueType
	}
	converted.Expressions = make([]queryspec.Filter, len(filter.Expressions))
	for index, child := range filter.Expressions {
		converted.Expressions[index] = aggregateShapeFilterQuerySpec(child)
	}
	return converted
}

func canonicalPolicyIdentifier(value string, insensitive bool) string {
	if insensitive {
		return strings.ToLower(value)
	}
	return value
}

func referencedFields(spec queryspec.NormalizedSpec) []string {
	seen := make(map[string]struct{})
	add := func(field string) {
		if field != "" {
			seen[field] = struct{}{}
		}
	}
	for _, selection := range spec.Projection {
		add(selection.Field)
	}
	if spec.Filter != nil {
		collectFields(*spec.Filter, add)
	}
	for _, field := range spec.GroupBy {
		add(field)
	}
	for _, sort := range spec.OrderBy {
		add(sort.Field)
	}
	fields := make([]string, 0, len(seen))
	for field := range seen {
		fields = append(fields, field)
	}
	slices.Sort(fields)
	return fields
}

func collectFields(filter queryspec.Filter, add func(string)) {
	if filter.Kind == "predicate" {
		add(filter.Field)
		return
	}
	for _, expression := range filter.Expressions {
		collectFields(expression, add)
	}
}

func collectOperators(filter queryspec.Filter, operators *[]string) {
	if filter.Kind == "predicate" {
		*operators = append(*operators, filter.Operator)
		return
	}
	for _, expression := range filter.Expressions {
		collectOperators(expression, operators)
	}
}

func allowed(policy config.PatternPolicy, value []string, caseInsensitive []bool) bool {
	for _, pattern := range policy.Deny {
		if match(pattern, value, caseInsensitive) {
			return false
		}
	}
	if len(policy.Allow) == 0 {
		return true
	}
	for _, pattern := range policy.Allow {
		if match(pattern, value, caseInsensitive) {
			return true
		}
	}
	return false
}

func match(pattern string, value []string, caseInsensitive []bool) bool {
	parts := strings.Split(pattern, ".")
	if len(parts) != len(value) {
		return false
	}
	for i, part := range parts {
		if part == "*" {
			continue
		}
		if i < len(caseInsensitive) && caseInsensitive[i] {
			if !strings.EqualFold(part, value[i]) {
				return false
			}
			continue
		}
		if part != value[i] {
			return false
		}
	}
	return true
}

func IsDenial(err error, reason *string) bool {
	var denial *Denial
	if !errors.As(err, &denial) {
		return false
	}
	if reason != nil {
		*reason = denial.ReasonCode
	}
	return true
}

func (q AuthorizedQuery) String() string {
	return fmt.Sprintf("authorized query for profile %q", q.profile)
}

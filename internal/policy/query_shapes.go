package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/queryspec"
)

const queryShapeHashDomain = "quordon/query-shapes\x00"

type QueryShapeResource struct {
	Schema string
	Object string
}

type QueryShapeDiscovery struct {
	owner         *Snapshot
	profile       string
	policyVersion string
	policyHash    string
	datasource    string
	adapter       string
	generation    string
	shapeSetHash  string
	semantics     domain.IdentifierSemantics
	limits        domain.Limits
	payload       []byte
	resources     []QueryShapeResource
	fields        []string
	shapeCount    int
}

type AuthorizedQueryShapeList struct {
	principal            string
	credentialIdentifier string
	operation            domain.Operation
	discovery            *QueryShapeDiscovery
}

func (a AuthorizedQueryShapeList) Principal() string            { return a.principal }
func (a AuthorizedQueryShapeList) CredentialIdentifier() string { return a.credentialIdentifier }
func (a AuthorizedQueryShapeList) Profile() string {
	if a.discovery == nil {
		return ""
	}
	return a.discovery.profile
}
func (a AuthorizedQueryShapeList) Datasource() string {
	if a.discovery == nil {
		return ""
	}
	return a.discovery.datasource
}
func (a AuthorizedQueryShapeList) Adapter() string {
	if a.discovery == nil {
		return ""
	}
	return a.discovery.adapter
}
func (a AuthorizedQueryShapeList) Operation() domain.Operation { return a.operation }
func (a AuthorizedQueryShapeList) Limits() domain.Limits {
	if a.discovery == nil {
		return domain.Limits{}
	}
	return a.discovery.limits
}
func (a AuthorizedQueryShapeList) Generation() string {
	if a.discovery == nil {
		return ""
	}
	return a.discovery.generation
}
func (a AuthorizedQueryShapeList) ShapeSetHash() string {
	if a.discovery == nil {
		return ""
	}
	return a.discovery.shapeSetHash
}
func (a AuthorizedQueryShapeList) ShapeCount() int {
	if a.discovery == nil {
		return 0
	}
	return a.discovery.shapeCount
}
func (a AuthorizedQueryShapeList) ResultBytes() int {
	if a.discovery == nil {
		return 0
	}
	return len(a.responsePayload())
}
func (a AuthorizedQueryShapeList) Resources() []QueryShapeResource {
	if a.discovery == nil {
		return nil
	}
	return slices.Clone(a.discovery.resources)
}
func (a AuthorizedQueryShapeList) Fields() []string {
	if a.discovery == nil {
		return nil
	}
	return slices.Clone(a.discovery.fields)
}
func (a AuthorizedQueryShapeList) ResponsePayload() ([]byte, error) {
	payload := a.responsePayload()
	if a.operation != domain.OperationListQueryShapes || a.discovery == nil ||
		a.ShapeCount() == 0 || len(payload) == 0 ||
		len(payload) > a.discovery.limits.MaxResultBytes {
		return nil, errors.New("invalid list_query_shapes authorization")
	}
	return slices.Clone(payload), nil
}

func (a AuthorizedQueryShapeList) responsePayload() []byte {
	if a.discovery == nil {
		return nil
	}
	return a.discovery.payload
}

func (d QueryShapeDiscovery) MatchesSemantics(semantics domain.IdentifierSemantics) bool {
	return d.semantics == semantics
}

func (d QueryShapeDiscovery) Datasource() string { return d.datasource }

// ValidateQueryShapeDiscoveryStatic rejects disclosure errors that do not
// depend on server identifier semantics. Callers use it for every publishing
// profile before the first datasource probe.
func (s *Snapshot) ValidateQueryShapeDiscoveryStatic(profileName, adapter string) error {
	profile, ok := s.profiles[profileName]
	if !ok || !slices.Contains(profile.Operations, domain.OperationListQueryShapes) ||
		len(profile.Query.AggregateShapes)+len(profile.Query.KeysetSelectShapes) == 0 {
		return fmt.Errorf("profile %q does not configure publishable query shapes", profileName)
	}
	if adapter == "" {
		return fmt.Errorf("profile %q cannot publish query shapes", profileName)
	}
	configuredShapes := cloneAggregateShapes(profile.Query.AggregateShapes)
	slices.SortFunc(configuredShapes, func(a, b config.AggregateShape) int {
		return strings.Compare(a.Name, b.Name)
	})
	publicShapes := make([]publicAggregateQueryShape, 0, len(configuredShapes))
	for index := range configuredShapes {
		shape := configuredShapes[index]
		if !aggregateShapeFeaturesAllowed(profile.Query, shape) {
			return fmt.Errorf("profile %q aggregate shape %q references a denied query feature", profileName, shape.Name)
		}
		publicShape, err := buildPublicAggregateQueryShape(shape, domain.IdentifierSemantics{})
		if err != nil {
			return fmt.Errorf("profile %q aggregate shape %q: %w", profileName, shape.Name, err)
		}
		publicShapes = append(publicShapes, publicShape)
	}
	maximum := s.hardLimits.Min(profile.Limits).MaxResultBytes
	keysetShapes, err := buildPublicKeysetQueryShapes(profile.Query.KeysetSelectShapes, domain.IdentifierSemantics{})
	if err != nil {
		return err
	}
	_, _, err = encodeQueryShapeResponse(
		profileName, s.version, profile.Datasource, adapter, publicShapes, keysetShapes, maximum,
	)
	return err
}

func (s *Snapshot) BuildQueryShapeDiscovery(
	profileName, adapter string,
	semantics domain.IdentifierSemantics,
) (QueryShapeDiscovery, error) {
	profile, ok := s.profiles[profileName]
	if !ok || !slices.Contains(profile.Operations, domain.OperationListQueryShapes) ||
		len(profile.Query.AggregateShapes)+len(profile.Query.KeysetSelectShapes) == 0 {
		return QueryShapeDiscovery{}, fmt.Errorf("profile %q does not configure publishable query shapes", profileName)
	}
	if adapter == "" {
		return QueryShapeDiscovery{}, fmt.Errorf("profile %q cannot publish query shapes", profileName)
	}

	configuredShapes := cloneAggregateShapes(profile.Query.AggregateShapes)
	slices.SortFunc(configuredShapes, func(a, b config.AggregateShape) int {
		return strings.Compare(a.Name, b.Name)
	})
	publicShapes := make([]publicAggregateQueryShape, 0, len(configuredShapes))
	resourcesByKey := make(map[string]QueryShapeResource)
	fieldsByKey := make(map[string]string)
	for index := range configuredShapes {
		shape := configuredShapes[index]
		if !aggregateShapeFeaturesAllowed(profile.Query, shape) {
			return QueryShapeDiscovery{}, fmt.Errorf("profile %q aggregate shape %q references a denied query feature", profileName, shape.Name)
		}
		if !allowed(
			profile.Resources.Schemas,
			[]string{shape.Source.Schema},
			[]bool{semantics.CaseInsensitiveSchemas},
		) || !allowed(
			profile.Resources.Objects,
			[]string{shape.Source.Schema, shape.Source.Name},
			[]bool{semantics.CaseInsensitiveSchemas, semantics.CaseInsensitiveObjects},
		) {
			return QueryShapeDiscovery{}, fmt.Errorf("profile %q aggregate shape %q references a denied resource", profileName, shape.Name)
		}
		fields := configuredAggregateShapeFields(shape)
		for _, field := range fields {
			if !allowed(
				profile.Resources.Fields,
				[]string{shape.Source.Schema, shape.Source.Name, field},
				[]bool{
					semantics.CaseInsensitiveSchemas,
					semantics.CaseInsensitiveObjects,
					semantics.CaseInsensitiveFields,
				},
			) {
				return QueryShapeDiscovery{}, fmt.Errorf("profile %q aggregate shape %q references a denied field", profileName, shape.Name)
			}
			key := canonicalPolicyIdentifier(field, semantics.CaseInsensitiveFields)
			if _, exists := fieldsByKey[key]; !exists {
				fieldsByKey[key] = key
			}
		}
		canonicalSchema := canonicalPolicyIdentifier(shape.Source.Schema, semantics.CaseInsensitiveSchemas)
		canonicalObject := canonicalPolicyIdentifier(shape.Source.Name, semantics.CaseInsensitiveObjects)
		resourceKey := canonicalSchema + "\x00" + canonicalObject
		if _, exists := resourcesByKey[resourceKey]; !exists {
			resourcesByKey[resourceKey] = QueryShapeResource{Schema: canonicalSchema, Object: canonicalObject}
		}
		publicShape, err := buildPublicAggregateQueryShape(shape, semantics)
		if err != nil {
			return QueryShapeDiscovery{}, fmt.Errorf("profile %q aggregate shape %q: %w", profileName, shape.Name, err)
		}
		publicShapes = append(publicShapes, publicShape)
	}
	publicKeysetShapes, err := buildPublicKeysetQueryShapes(profile.Query.KeysetSelectShapes, semantics)
	if err != nil {
		return QueryShapeDiscovery{}, err
	}
	for _, shape := range profile.Query.KeysetSelectShapes {
		if !allowed(
			profile.Resources.Schemas, []string{shape.Source.Schema},
			[]bool{semantics.CaseInsensitiveSchemas},
		) || !allowed(
			profile.Resources.Objects, []string{shape.Source.Schema, shape.Source.Name},
			[]bool{semantics.CaseInsensitiveSchemas, semantics.CaseInsensitiveObjects},
		) {
			return QueryShapeDiscovery{}, fmt.Errorf("profile %q keyset shape %q references a denied resource", profileName, shape.Name)
		}
		for _, field := range configuredKeysetShapeFields(shape) {
			if !allowed(
				profile.Resources.Fields, []string{shape.Source.Schema, shape.Source.Name, field},
				[]bool{semantics.CaseInsensitiveSchemas, semantics.CaseInsensitiveObjects, semantics.CaseInsensitiveFields},
			) {
				return QueryShapeDiscovery{}, fmt.Errorf("profile %q keyset shape %q references a denied field", profileName, shape.Name)
			}
			key := canonicalPolicyIdentifier(field, semantics.CaseInsensitiveFields)
			fieldsByKey[key] = key
		}
		canonicalSchema := canonicalPolicyIdentifier(shape.Source.Schema, semantics.CaseInsensitiveSchemas)
		canonicalObject := canonicalPolicyIdentifier(shape.Source.Name, semantics.CaseInsensitiveObjects)
		resourcesByKey[canonicalSchema+"\x00"+canonicalObject] = QueryShapeResource{
			Schema: canonicalSchema, Object: canonicalObject,
		}
	}

	resources := make([]QueryShapeResource, 0, len(resourcesByKey))
	for _, resource := range resourcesByKey {
		resources = append(resources, resource)
	}
	slices.SortFunc(resources, func(a, b QueryShapeResource) int {
		if comparison := strings.Compare(a.Schema, b.Schema); comparison != 0 {
			return comparison
		}
		return strings.Compare(a.Object, b.Object)
	})
	fields := make([]string, 0, len(fieldsByKey))
	for _, field := range fieldsByKey {
		fields = append(fields, field)
	}
	slices.Sort(fields)

	limits := s.hardLimits.Min(profile.Limits)
	payload, shapeSetHash, err := encodeQueryShapeResponse(
		profileName, s.version, profile.Datasource, adapter, publicShapes, publicKeysetShapes, limits.MaxResultBytes,
	)
	if err != nil {
		return QueryShapeDiscovery{}, err
	}
	generationInput := fmt.Sprintf(
		"%s\x00%s\x00%s\x00%t%t%t",
		s.hash, profileName, adapter,
		semantics.CaseInsensitiveSchemas,
		semantics.CaseInsensitiveObjects,
		semantics.CaseInsensitiveFields,
	)
	generationDigest := sha256.Sum256([]byte(generationInput))
	discovery := QueryShapeDiscovery{
		owner:   s,
		profile: profileName, policyVersion: s.version, policyHash: s.hash,
		datasource: profile.Datasource, adapter: adapter,
		generation: hex.EncodeToString(generationDigest[:]), shapeSetHash: shapeSetHash,
		semantics: semantics, limits: limits,
		payload:   payload,
		resources: resources, fields: fields, shapeCount: len(publicShapes) + len(publicKeysetShapes),
	}
	return discovery, nil
}

func aggregateShapeFeaturesAllowed(policy config.QueryPolicy, shape config.AggregateShape) bool {
	if shape.Mode == queryspec.AggregateModeGrouped && !policy.AllowGroupBy ||
		len(shape.OrderBy) != 0 && !policy.AllowSorting {
		return false
	}
	for _, output := range shape.Projection {
		if output.Kind != "measure" {
			continue
		}
		function := output.Function
		if function == "count_all" {
			function = "count"
		}
		if !slices.Contains(policy.AllowedAggregates, function) {
			return false
		}
	}
	if shape.Filter == nil {
		return true
	}
	if !policy.AllowFiltering {
		return false
	}
	var allowedFilter func(config.AggregateShapeFilter) bool
	allowedFilter = func(filter config.AggregateShapeFilter) bool {
		if filter.Kind == "predicate" {
			return slices.Contains(policy.AllowedFilterOperators, filter.Operator)
		}
		for _, expression := range filter.Expressions {
			if !allowedFilter(expression) {
				return false
			}
		}
		return true
	}
	return allowedFilter(*shape.Filter)
}

func aggregateShapesContainTimeBucket(shapes []config.AggregateShape) bool {
	for _, shape := range shapes {
		for _, output := range shape.Projection {
			if output.Kind == "time_bucket" {
				return true
			}
		}
	}
	return false
}

func (s *Snapshot) AuthorizeQueryShapeList(
	principal, credentialIdentifier, profileName string,
	discovery *QueryShapeDiscovery,
) (AuthorizedQueryShapeList, error) {
	if credentialIdentifier == "" {
		return AuthorizedQueryShapeList{}, errors.New("query-shape authorization requires a credential identifier")
	}
	principalConfig, ok := s.principals[principal]
	if !ok || !slices.Contains(principalConfig.Profiles, profileName) {
		return AuthorizedQueryShapeList{}, &Denial{ReasonCode: ReasonDeniedOperation}
	}
	profile, ok := s.profiles[profileName]
	if !ok || !slices.Contains(profile.Operations, domain.OperationListQueryShapes) ||
		len(profile.Query.AggregateShapes)+len(profile.Query.KeysetSelectShapes) == 0 {
		return AuthorizedQueryShapeList{}, &Denial{ReasonCode: ReasonDeniedOperation}
	}
	if discovery == nil || discovery.owner != s || discovery.profile != profileName || discovery.policyVersion != s.version ||
		discovery.policyHash != s.hash || discovery.datasource != profile.Datasource ||
		discovery.shapeCount == 0 || len(discovery.payload) == 0 {
		return AuthorizedQueryShapeList{}, errors.New("query-shape discovery snapshot does not match policy")
	}
	return AuthorizedQueryShapeList{
		principal: principal, credentialIdentifier: credentialIdentifier,
		operation: domain.OperationListQueryShapes, discovery: discovery,
	}, nil
}

type publicAggregateQueryShape struct {
	Name        string                   `json:"name"`
	Description *string                  `json:"description,omitempty"`
	Operation   domain.Operation         `json:"operation"`
	Query       publicAggregateShapeSpec `json:"query"`
}

type publicAggregateShapeSpec struct {
	Mode         string                  `json:"mode"`
	Source       queryspec.ResourceRef   `json:"source"`
	Projection   []publicAggregateOutput `json:"projection"`
	Filter       *publicAggregateFilter  `json:"filter,omitempty"`
	OrderBy      []publicAggregateOrder  `json:"order_by,omitempty"`
	MaximumLimit int                     `json:"maximum_limit,omitempty"`
}

type publicAggregateOutput struct {
	Representation queryspec.Representation `json:"representation,omitempty"`
	Kind           string                   `json:"kind"`
	Field          string                   `json:"field,omitempty"`
	Function       string                   `json:"function,omitempty"`
	Alias          string                   `json:"alias,omitempty"`
	Unit           string                   `json:"unit,omitempty"`
	Timezone       string                   `json:"timezone,omitempty"`
}

type publicAggregateOrder struct {
	Representation queryspec.Representation `json:"representation,omitempty"`
	Kind           string                   `json:"kind"`
	Field          string                   `json:"field,omitempty"`
	Alias          string                   `json:"alias,omitempty"`
	Direction      string                   `json:"direction"`
}

type publicAggregateFilter struct {
	Representation queryspec.Representation
	Kind           string
	Field          string
	Operator       string
	ValueTypes     []string
	Expressions    []publicAggregateFilter
}

func (f publicAggregateFilter) MarshalJSON() ([]byte, error) {
	if f.Kind == "predicate" {
		return json.Marshal(struct {
			Representation queryspec.Representation `json:"representation,omitempty"`
			Kind           string                   `json:"kind"`
			Field          string                   `json:"field"`
			Operator       string                   `json:"operator"`
			ValueTypes     []string                 `json:"value_types"`
		}{Representation: f.Representation, Kind: f.Kind, Field: f.Field, Operator: f.Operator, ValueTypes: f.ValueTypes})
	}
	if f.Kind == "group" {
		return json.Marshal(struct {
			Kind        string                  `json:"kind"`
			Operator    string                  `json:"operator"`
			Expressions []publicAggregateFilter `json:"expressions"`
		}{Kind: f.Kind, Operator: f.Operator, Expressions: f.Expressions})
	}
	return nil, errors.New("unknown public aggregate filter kind")
}

func buildPublicAggregateQueryShape(
	shape config.AggregateShape,
	semantics domain.IdentifierSemantics,
) (publicAggregateQueryShape, error) {
	if !queryspec.IsIdentifier(shape.Name) || !queryspec.IsIdentifier(shape.Source.Schema) ||
		!queryspec.IsIdentifier(shape.Source.Name) {
		return publicAggregateQueryShape{}, errors.New("invalid public identifiers")
	}
	result := publicAggregateQueryShape{
		Name: shape.Name, Description: shape.PublicDescription,
		Operation: domain.OperationAggregate,
		Query: publicAggregateShapeSpec{
			Mode:         shape.Mode,
			Source:       queryspec.ResourceRef{Schema: shape.Source.Schema, Name: shape.Source.Name},
			Projection:   make([]publicAggregateOutput, len(shape.Projection)),
			OrderBy:      make([]publicAggregateOrder, len(shape.OrderBy)),
			MaximumLimit: shape.MaximumLimit,
		},
	}
	if shape.Mode == queryspec.AggregateModeScalar {
		result.Query.OrderBy = nil
		result.Query.MaximumLimit = 0
	} else if shape.Mode != queryspec.AggregateModeGrouped || shape.MaximumLimit <= 0 {
		return publicAggregateQueryShape{}, errors.New("invalid aggregate mode or maximum limit")
	}
	outputNames := make(map[string]struct{}, len(shape.Projection))
	for index, output := range shape.Projection {
		publicOutput := publicAggregateOutput{
			Representation: output.Representation, Kind: output.Kind, Field: output.Field, Function: output.Function, Alias: output.Alias,
			Unit: output.Unit, Timezone: output.Timezone,
		}
		name := output.Field
		if output.Kind == "measure" || output.Kind == "time_bucket" {
			name = output.Alias
		}
		canonicalName := canonicalPolicyIdentifier(name, true)
		if !queryspec.IsIdentifier(name) {
			return publicAggregateQueryShape{}, errors.New("invalid aggregate output name")
		}
		if _, duplicate := outputNames[canonicalName]; duplicate {
			return publicAggregateQueryShape{}, errors.New("colliding aggregate output names")
		}
		outputNames[canonicalName] = struct{}{}
		result.Query.Projection[index] = publicOutput
	}
	if shape.Filter != nil {
		filter, _, err := buildPublicAggregateFilter(*shape.Filter, semantics.CaseInsensitiveFields)
		if err != nil {
			return publicAggregateQueryShape{}, err
		}
		result.Query.Filter = &filter
	}
	for index, order := range shape.OrderBy {
		result.Query.OrderBy[index] = publicAggregateOrder{
			Representation: order.Representation, Kind: order.Kind, Field: order.Field, Alias: order.Alias, Direction: order.Direction,
		}
	}
	if shape.OrderBy == nil {
		result.Query.OrderBy = nil
	}
	return result, nil
}

func buildPublicAggregateFilter(
	filter config.AggregateShapeFilter,
	caseInsensitiveFields bool,
) (publicAggregateFilter, queryspec.AggregateFilterDigest, error) {
	canonical, ok := configuredAggregateShapeFilter(&filter, caseInsensitiveFields)
	if !ok || canonical == nil {
		return publicAggregateFilter{}, queryspec.AggregateFilterDigest{}, errors.New("invalid aggregate filter shape")
	}
	result := publicAggregateFilter{
		Representation: filter.Representation, Kind: filter.Kind, Field: filter.Field, Operator: filter.Operator,
	}
	if filter.Kind == "predicate" {
		if filter.ValueTypes == nil {
			return publicAggregateFilter{}, queryspec.AggregateFilterDigest{}, errors.New("missing filter value types")
		}
		result.ValueTypes = slices.Clone(*filter.ValueTypes)
		return result, aggregateShapeFilterKey(*canonical), nil
	}
	type keyedFilter struct {
		filter publicAggregateFilter
		key    queryspec.AggregateFilterDigest
	}
	children := make([]keyedFilter, len(filter.Expressions))
	for index, expression := range filter.Expressions {
		child, key, err := buildPublicAggregateFilter(expression, caseInsensitiveFields)
		if err != nil {
			return publicAggregateFilter{}, queryspec.AggregateFilterDigest{}, err
		}
		children[index] = keyedFilter{filter: child, key: key}
	}
	slices.SortFunc(children, func(a, b keyedFilter) int { return bytes.Compare(a.key[:], b.key[:]) })
	result.Expressions = make([]publicAggregateFilter, len(children))
	for index, child := range children {
		if index > 0 && child.key == children[index-1].key {
			return publicAggregateFilter{}, queryspec.AggregateFilterDigest{}, errors.New("duplicate aggregate filter shapes")
		}
		result.Expressions[index] = child.filter
	}
	canonicalResult := aggregateShapeFilter{
		Kind: result.Kind, Operator: result.Operator,
		Expressions: make([]aggregateShapeFilter, len(result.Expressions)),
	}
	for index, child := range result.Expressions {
		canonicalResult.Expressions[index] = publicFilterSignature(child, caseInsensitiveFields)
	}
	return result, aggregateShapeFilterKey(canonicalResult), nil
}

func publicFilterSignature(filter publicAggregateFilter, caseInsensitiveFields bool) aggregateShapeFilter {
	result := aggregateShapeFilter{
		Representation: filter.Representation, Kind: filter.Kind, Field: canonicalPolicyIdentifier(filter.Field, caseInsensitiveFields),
		Operator: filter.Operator, ValueTypes: slices.Clone(filter.ValueTypes),
		Expressions: make([]aggregateShapeFilter, len(filter.Expressions)),
	}
	for index, child := range filter.Expressions {
		result.Expressions[index] = publicFilterSignature(child, caseInsensitiveFields)
	}
	return result
}

func configuredAggregateShapeFields(shape config.AggregateShape) []string {
	fields := make(map[string]struct{})
	for _, output := range shape.Projection {
		if output.Field != "" {
			fields[output.Field] = struct{}{}
		}
	}
	var collectFilterFields func(config.AggregateShapeFilter)
	collectFilterFields = func(filter config.AggregateShapeFilter) {
		if filter.Kind == "predicate" {
			fields[filter.Field] = struct{}{}
			return
		}
		for _, expression := range filter.Expressions {
			collectFilterFields(expression)
		}
	}
	if shape.Filter != nil {
		collectFilterFields(*shape.Filter)
	}
	for _, order := range shape.OrderBy {
		if order.Kind == "dimension" && order.Field != "" {
			fields[order.Field] = struct{}{}
		}
	}
	result := make([]string, 0, len(fields))
	for field := range fields {
		result = append(result, field)
	}
	slices.Sort(result)
	return result
}

type boundedSize struct {
	value   int
	maximum int
	ok      bool
}

func newBoundedSize(maximum int) *boundedSize {
	return &boundedSize{maximum: maximum, ok: maximum >= 0}
}
func (s *boundedSize) add(value int) {
	if !s.ok || value < 0 || s.value > s.maximum || value > s.maximum-s.value {
		s.ok = false
		return
	}
	s.value += value
}
func (s *boundedSize) string(value string) { s.add(encodedJSONStringSize(value)) }

func queryShapeEncodedSize(size *boundedSize, shape publicAggregateQueryShape) {
	size.add(len(`{"name":`))
	size.string(shape.Name)
	if shape.Description != nil {
		size.add(len(`,"description":`))
		size.string(*shape.Description)
	}
	size.add(len(`,"operation":`))
	size.string(string(shape.Operation))
	size.add(len(`,"query":`))
	queryShapeSpecEncodedSize(size, shape.Query)
	size.add(1)
}

func queryShapeSpecEncodedSize(size *boundedSize, spec publicAggregateShapeSpec) {
	size.add(len(`{"mode":`))
	size.string(spec.Mode)
	size.add(len(`,"source":{"schema":`))
	size.string(spec.Source.Schema)
	size.add(len(`,"name":`))
	size.string(spec.Source.Name)
	size.add(len(`},"projection":[`))
	for index, output := range spec.Projection {
		if index != 0 {
			size.add(1)
		}
		queryShapeOutputEncodedSize(size, output)
	}
	size.add(1)
	if spec.Filter != nil {
		size.add(len(`,"filter":`))
		queryShapeFilterEncodedSize(size, *spec.Filter)
	}
	if spec.OrderBy != nil {
		size.add(len(`,"order_by":[`))
		for index, order := range spec.OrderBy {
			if index != 0 {
				size.add(1)
			}
			queryShapeOrderEncodedSize(size, order)
		}
		size.add(1)
	}
	if spec.MaximumLimit != 0 {
		size.add(len(`,"maximum_limit":`))
		size.add(len(strconv.Itoa(spec.MaximumLimit)))
	}
	size.add(1)
}

func queryShapeOutputEncodedSize(size *boundedSize, output publicAggregateOutput) {
	if output.Representation != "" {
		size.add(len(`,"representation":"source_text"`))
	}
	size.add(len(`{"kind":`))
	size.string(output.Kind)
	if output.Field != "" {
		size.add(len(`,"field":`))
		size.string(output.Field)
	}
	if output.Function != "" {
		size.add(len(`,"function":`))
		size.string(output.Function)
	}
	if output.Alias != "" {
		size.add(len(`,"alias":`))
		size.string(output.Alias)
	}
	if output.Unit != "" {
		size.add(len(`,"unit":`))
		size.string(output.Unit)
	}
	if output.Timezone != "" {
		size.add(len(`,"timezone":`))
		size.string(output.Timezone)
	}
	size.add(1)
}

func queryShapeOrderEncodedSize(size *boundedSize, order publicAggregateOrder) {
	if order.Representation != "" {
		size.add(len(`,"representation":"source_text"`))
	}
	size.add(len(`{"kind":`))
	size.string(order.Kind)
	if order.Field != "" {
		size.add(len(`,"field":`))
		size.string(order.Field)
	}
	if order.Alias != "" {
		size.add(len(`,"alias":`))
		size.string(order.Alias)
	}
	size.add(len(`,"direction":`))
	size.string(order.Direction)
	size.add(1)
}

func queryShapeFilterEncodedSize(size *boundedSize, filter publicAggregateFilter) {
	if filter.Representation != "" {
		size.add(len(`,"representation":"source_text"`))
	}
	size.add(len(`{"kind":`))
	size.string(filter.Kind)
	if filter.Kind == "predicate" {
		size.add(len(`,"field":`))
		size.string(filter.Field)
		size.add(len(`,"operator":`))
		size.string(filter.Operator)
		size.add(len(`,"value_types":[`))
		for index, valueType := range filter.ValueTypes {
			if index != 0 {
				size.add(1)
			}
			size.string(valueType)
		}
		size.add(len(`]}`))
		return
	}
	size.add(len(`,"operator":`))
	size.string(filter.Operator)
	size.add(len(`,"expressions":[`))
	for index, expression := range filter.Expressions {
		if index != 0 {
			size.add(1)
		}
		queryShapeFilterEncodedSize(size, expression)
	}
	size.add(len(`]}`))
}

func encodedJSONStringSize(value string) int {
	size := 2
	for index := 0; index < len(value); {
		width := 1
		encodedBytes := 1
		character := value[index]
		if character < utf8.RuneSelf {
			switch character {
			case '\\', '"', '\b', '\f', '\n', '\r', '\t':
				encodedBytes = 2
			case '<', '>', '&':
				encodedBytes = 6
			default:
				if character < 0x20 {
					encodedBytes = 6
				}
			}
		} else {
			runeValue, runeWidth := utf8.DecodeRuneInString(value[index:])
			width = runeWidth
			switch {
			case runeValue == utf8.RuneError && runeWidth == 1:
				encodedBytes = 6
			case runeValue == '\u2028' || runeValue == '\u2029':
				encodedBytes = 6
			default:
				encodedBytes = runeWidth
			}
		}
		size += encodedBytes
		index += width
	}
	return size
}

func writeJCSShape(writer hash.Hash, shape publicAggregateQueryShape) error {
	_, _ = io.WriteString(writer, "{")
	separator := ""
	if shape.Description != nil {
		_, _ = io.WriteString(writer, `"description":`)
		if err := writeJCSString(writer, *shape.Description); err != nil {
			return err
		}
		separator = ","
	}
	_, _ = io.WriteString(writer, separator+`"name":`)
	if err := writeJCSString(writer, shape.Name); err != nil {
		return err
	}
	_, _ = io.WriteString(writer, `,"operation":"aggregate","query":`)
	if err := writeJCSQuery(writer, shape.Query); err != nil {
		return err
	}
	_, _ = io.WriteString(writer, "}")
	return nil
}

func writeJCSQuery(writer hash.Hash, spec publicAggregateShapeSpec) error {
	_, _ = io.WriteString(writer, "{")
	separator := ""
	if spec.Filter != nil {
		_, _ = io.WriteString(writer, `"filter":`)
		if err := writeJCSFilter(writer, *spec.Filter); err != nil {
			return err
		}
		separator = ","
	}
	if spec.MaximumLimit != 0 {
		_, _ = io.WriteString(writer, separator+`"maximum_limit":`+strconv.Itoa(spec.MaximumLimit))
		separator = ","
	}
	_, _ = io.WriteString(writer, separator+`"mode":`)
	if err := writeJCSString(writer, spec.Mode); err != nil {
		return err
	}
	if spec.OrderBy != nil {
		_, _ = io.WriteString(writer, `,"order_by":[`)
		for index, order := range spec.OrderBy {
			if index != 0 {
				_, _ = io.WriteString(writer, ",")
			}
			if err := writeJCSOrder(writer, order); err != nil {
				return err
			}
		}
		_, _ = io.WriteString(writer, "]")
	}
	_, _ = io.WriteString(writer, `,"projection":[`)
	for index, output := range spec.Projection {
		if index != 0 {
			_, _ = io.WriteString(writer, ",")
		}
		if err := writeJCSOutput(writer, output); err != nil {
			return err
		}
	}
	_, _ = io.WriteString(writer, `],"source":{"name":`)
	if err := writeJCSString(writer, spec.Source.Name); err != nil {
		return err
	}
	_, _ = io.WriteString(writer, `,"schema":`)
	if err := writeJCSString(writer, spec.Source.Schema); err != nil {
		return err
	}
	_, _ = io.WriteString(writer, "}}")
	return nil
}

func writeJCSOutput(writer hash.Hash, output publicAggregateOutput) error {
	_, _ = io.WriteString(writer, "{")
	separator := ""
	if output.Alias != "" {
		_, _ = io.WriteString(writer, `"alias":`)
		if err := writeJCSString(writer, output.Alias); err != nil {
			return err
		}
		separator = ","
	}
	if output.Field != "" {
		_, _ = io.WriteString(writer, separator+`"field":`)
		if err := writeJCSString(writer, output.Field); err != nil {
			return err
		}
		separator = ","
	}
	if output.Function != "" {
		_, _ = io.WriteString(writer, separator+`"function":`)
		if err := writeJCSString(writer, output.Function); err != nil {
			return err
		}
		separator = ","
	}
	_, _ = io.WriteString(writer, separator+`"kind":`)
	if err := writeJCSString(writer, output.Kind); err != nil {
		return err
	}
	if output.Representation != "" {
		_, _ = io.WriteString(writer, `,"representation":`)
		if err := writeJCSString(writer, string(output.Representation)); err != nil {
			return err
		}
	}
	if output.Timezone != "" {
		_, _ = io.WriteString(writer, `,"timezone":`)
		if err := writeJCSString(writer, output.Timezone); err != nil {
			return err
		}
	}
	if output.Unit != "" {
		_, _ = io.WriteString(writer, `,"unit":`)
		if err := writeJCSString(writer, output.Unit); err != nil {
			return err
		}
	}
	_, _ = io.WriteString(writer, "}")
	return nil
}

func writeJCSOrder(writer hash.Hash, order publicAggregateOrder) error {
	_, _ = io.WriteString(writer, "{")
	separator := ""
	if order.Alias != "" {
		_, _ = io.WriteString(writer, `"alias":`)
		if err := writeJCSString(writer, order.Alias); err != nil {
			return err
		}
		separator = ","
	}
	_, _ = io.WriteString(writer, separator+`"direction":`)
	if err := writeJCSString(writer, order.Direction); err != nil {
		return err
	}
	if order.Field != "" {
		_, _ = io.WriteString(writer, `,"field":`)
		if err := writeJCSString(writer, order.Field); err != nil {
			return err
		}
	}
	_, _ = io.WriteString(writer, `,"kind":`)
	if err := writeJCSString(writer, order.Kind); err != nil {
		return err
	}
	if order.Representation != "" {
		_, _ = io.WriteString(writer, `,"representation":`)
		if err := writeJCSString(writer, string(order.Representation)); err != nil {
			return err
		}
	}
	_, _ = io.WriteString(writer, "}")
	return nil
}

func writeJCSFilter(writer hash.Hash, filter publicAggregateFilter) error {
	_, _ = io.WriteString(writer, "{")
	if filter.Kind == "predicate" {
		_, _ = io.WriteString(writer, `"field":`)
		if err := writeJCSString(writer, filter.Field); err != nil {
			return err
		}
		_, _ = io.WriteString(writer, `,"kind":"predicate","operator":`)
		if err := writeJCSString(writer, filter.Operator); err != nil {
			return err
		}
		if filter.Representation != "" {
			_, _ = io.WriteString(writer, `,"representation":`)
			if err := writeJCSString(writer, string(filter.Representation)); err != nil {
				return err
			}
		}
		_, _ = io.WriteString(writer, `,"value_types":[`)
		for index, valueType := range filter.ValueTypes {
			if index != 0 {
				_, _ = io.WriteString(writer, ",")
			}
			if err := writeJCSString(writer, valueType); err != nil {
				return err
			}
		}
		_, _ = io.WriteString(writer, "]}")
		return nil
	}
	_, _ = io.WriteString(writer, `"expressions":[`)
	for index, expression := range filter.Expressions {
		if index != 0 {
			_, _ = io.WriteString(writer, ",")
		}
		if err := writeJCSFilter(writer, expression); err != nil {
			return err
		}
	}
	_, _ = io.WriteString(writer, `],"kind":"group","operator":`)
	if err := writeJCSString(writer, filter.Operator); err != nil {
		return err
	}
	_, _ = io.WriteString(writer, "}")
	return nil
}

func writeJCSString(writer hash.Hash, value string) error {
	if !utf8.ValidString(value) {
		return errors.New("invalid UTF-8 string")
	}
	_, _ = io.WriteString(writer, `"`)
	start := 0
	for index := 0; index < len(value); index++ {
		if value[index] != '"' && value[index] != '\\' {
			continue
		}
		_, _ = io.WriteString(writer, value[start:index])
		_, _ = io.WriteString(writer, `\`+value[index:index+1])
		start = index + 1
	}
	_, _ = io.WriteString(writer, value[start:])
	_, _ = io.WriteString(writer, `"`)
	return nil
}

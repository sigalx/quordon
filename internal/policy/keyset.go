package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/queryspec"
)

type AuthorizedKeysetSelect struct {
	owner                      *Snapshot
	principal                  string
	credentialIdentifier       string
	profile                    string
	policyVersion              string
	policyHash                 string
	datasource                 string
	adapter                    string
	operation                  domain.Operation
	limits                     domain.Limits
	query                      queryspec.ValidatedKeyset
	requiredIndex              string
	allowTemporaryTable        bool
	allowFilesort              bool
	maximumRowsExaminedPerScan uint64
	shapeName                  string
	identifierSemantics        domain.IdentifierSemantics
	semanticsGeneration        string
}

func (a AuthorizedKeysetSelect) Principal() string                        { return a.principal }
func (a AuthorizedKeysetSelect) CredentialIdentifier() string             { return a.credentialIdentifier }
func (a AuthorizedKeysetSelect) Profile() string                          { return a.profile }
func (a AuthorizedKeysetSelect) PolicyVersion() string                    { return a.policyVersion }
func (a AuthorizedKeysetSelect) PolicyHash() string                       { return a.policyHash }
func (a AuthorizedKeysetSelect) Datasource() string                       { return a.datasource }
func (a AuthorizedKeysetSelect) Adapter() string                          { return a.adapter }
func (a AuthorizedKeysetSelect) Operation() domain.Operation              { return a.operation }
func (a AuthorizedKeysetSelect) Limits() domain.Limits                    { return a.limits }
func (a AuthorizedKeysetSelect) Query() queryspec.NormalizedKeysetRequest { return a.query.Request() }
func (a AuthorizedKeysetSelect) RequiredIndex() string                    { return a.requiredIndex }
func (a AuthorizedKeysetSelect) MaximumRowsExaminedPerScan() uint64 {
	return a.maximumRowsExaminedPerScan
}
func (a AuthorizedKeysetSelect) AllowTemporaryTable() bool { return a.allowTemporaryTable }
func (a AuthorizedKeysetSelect) AllowFilesort() bool       { return a.allowFilesort }
func (a AuthorizedKeysetSelect) ShapeName() string         { return a.shapeName }
func (a AuthorizedKeysetSelect) IdentifierSemantics() domain.IdentifierSemantics {
	return a.identifierSemantics
}
func (a AuthorizedKeysetSelect) IdentifierSemanticsGeneration() string {
	return a.semanticsGeneration
}
func (a AuthorizedKeysetSelect) ReferencedFields() []string {
	return queryspec.KeysetReferencedFields(a.query.Request())
}

// PrecheckKeysetSelect rejects every mismatch that is independent of the
// datasource's identifier semantics. It deliberately mints no authorization
// token and performs no external work.
func (s *Snapshot) PrecheckKeysetSelect(
	binding AuthorizedBinding, query queryspec.ValidatedKeyset,
) error {
	profile, err := s.profileForBinding(binding, domain.OperationSelectKeyset)
	if err != nil {
		return &Denial{ReasonCode: ReasonDeniedOperation}
	}
	effective := s.hardLimits.Min(profile.Limits)
	revalidated, err := queryspec.RevalidateKeyset(
		query, effective.MaxProjectionFields, effective.MaxOrderByFields,
		effective.MaxPredicates, effective.MaxExpressionDepth, effective.MaxParameters, effective.MaxRows,
	)
	if err != nil {
		return err
	}
	request := revalidated.Request()
	shape, ok := findKeysetShape(profile.Query.KeysetSelectShapes, request.Shape)
	if !ok || request.Query.Limit > shape.MaximumLimit || !potentialKeysetShapeMatch(shape, revalidated) {
		return &Denial{ReasonCode: ReasonDeniedQueryFeature}
	}
	if err := authorizeKeysetFeatures(profile.Query, request); err != nil {
		return err
	}
	return nil
}

func (s *Snapshot) AuthorizeKeysetSelect(
	binding AuthorizedBinding, credentialIdentifier, adapterName string,
	query queryspec.ValidatedKeyset,
	semantics domain.IdentifierSemantics,
) (AuthorizedKeysetSelect, error) {
	if binding.Principal() == "" || credentialIdentifier == "" || binding.Profile() == "" || adapterName == "" {
		return AuthorizedKeysetSelect{}, &Denial{ReasonCode: ReasonDeniedOperation}
	}
	if err := s.PrecheckKeysetSelect(binding, query); err != nil {
		return AuthorizedKeysetSelect{}, err
	}
	profile := s.profiles[binding.Profile()]
	effective := s.hardLimits.Min(profile.Limits)
	revalidated, err := queryspec.RevalidateKeyset(
		query, effective.MaxProjectionFields, effective.MaxOrderByFields,
		effective.MaxPredicates, effective.MaxExpressionDepth, effective.MaxParameters, effective.MaxRows,
	)
	if err != nil {
		return AuthorizedKeysetSelect{}, err
	}
	normalized, err := queryspec.NormalizeKeysetIdentifiers(revalidated, semantics)
	if err != nil {
		return AuthorizedKeysetSelect{}, err
	}
	request := normalized.Request()
	shape, ok := matchKeysetShape(profile.Query.KeysetSelectShapes, request, semantics)
	if !ok || request.Query.Limit > shape.MaximumLimit {
		return AuthorizedKeysetSelect{}, &Denial{ReasonCode: ReasonDeniedQueryFeature}
	}
	if !allowed(
		profile.Resources.Schemas, []string{request.Query.Source.Schema},
		[]bool{semantics.CaseInsensitiveSchemas},
	) || !allowed(
		profile.Resources.Objects, []string{request.Query.Source.Schema, request.Query.Source.Name},
		[]bool{semantics.CaseInsensitiveSchemas, semantics.CaseInsensitiveObjects},
	) {
		return AuthorizedKeysetSelect{}, &Denial{ReasonCode: ReasonDeniedResource}
	}
	for _, field := range queryspec.KeysetReferencedFields(request) {
		if !allowed(
			profile.Resources.Fields,
			[]string{request.Query.Source.Schema, request.Query.Source.Name, field},
			[]bool{semantics.CaseInsensitiveSchemas, semantics.CaseInsensitiveObjects, semantics.CaseInsensitiveFields},
		) {
			return AuthorizedKeysetSelect{}, &Denial{ReasonCode: ReasonDeniedField}
		}
	}
	if err := authorizeKeysetFeatures(profile.Query, request); err != nil {
		return AuthorizedKeysetSelect{}, err
	}
	generationInput := fmt.Sprintf(
		"%s\x00%s\x00%s\x00%s\x00%t%t%t", s.hash, binding.Profile(), binding.Datasource(), adapterName,
		semantics.CaseInsensitiveSchemas, semantics.CaseInsensitiveObjects, semantics.CaseInsensitiveFields,
	)
	generation := sha256.Sum256([]byte(generationInput))
	return AuthorizedKeysetSelect{
		owner: s, principal: binding.Principal(), credentialIdentifier: credentialIdentifier,
		profile: binding.Profile(), policyVersion: s.version, policyHash: s.hash,
		datasource: binding.Datasource(), adapter: adapterName, operation: domain.OperationSelectKeyset,
		limits: effective, query: normalized, requiredIndex: shape.RequiredIndex,
		maximumRowsExaminedPerScan: shape.MaximumRowsExaminedPerScan,
		allowTemporaryTable:        shape.AllowTemporaryTable != nil && *shape.AllowTemporaryTable,
		allowFilesort:              shape.AllowFilesort != nil && *shape.AllowFilesort,
		shapeName:                  shape.Name, identifierSemantics: semantics,
		semanticsGeneration: hex.EncodeToString(generation[:]),
	}, nil
}

func findKeysetShape(shapes []config.KeysetSelectShape, name string) (config.KeysetSelectShape, bool) {
	for _, shape := range shapes {
		if shape.Name == name {
			return shape, true
		}
	}
	return config.KeysetSelectShape{}, false
}

func potentialKeysetShapeMatch(shape config.KeysetSelectShape, request queryspec.ValidatedKeyset) bool {
	semantics := domain.IdentifierSemantics{
		CaseInsensitiveSchemas: true, CaseInsensitiveObjects: true, CaseInsensitiveFields: true,
	}
	normalized, err := queryspec.NormalizeKeysetIdentifiers(request, semantics)
	if err != nil {
		return false
	}
	return configuredKeysetSignatureEqual(shape, normalized.Request(), semantics)
}

func matchKeysetShape(
	shapes []config.KeysetSelectShape,
	request queryspec.NormalizedKeysetRequest,
	semantics domain.IdentifierSemantics,
) (config.KeysetSelectShape, bool) {
	shape, ok := findKeysetShape(shapes, request.Shape)
	if !ok || !configuredKeysetSignatureEqual(shape, request, semantics) {
		return config.KeysetSelectShape{}, false
	}
	return shape, true
}

type keysetProjectionSignature struct {
	Representation queryspec.Representation `json:"representation,omitempty"`
	Field          string                   `json:"field"`
	Alias          string                   `json:"alias,omitempty"`
}

type keysetOrderSignature struct {
	Representation queryspec.Representation `json:"representation,omitempty"`
	Field          string                   `json:"field"`
	Direction      string                   `json:"direction"`
}

type keysetSignature struct {
	Schema     string                      `json:"schema"`
	Object     string                      `json:"object"`
	Projection []keysetProjectionSignature `json:"projection"`
	Filter     *aggregateShapeFilter       `json:"filter,omitempty"`
	OrderBy    []keysetOrderSignature      `json:"order_by"`
}

func configuredKeysetSignatureEqual(
	shape config.KeysetSelectShape,
	request queryspec.NormalizedKeysetRequest,
	semantics domain.IdentifierSemantics,
) bool {
	configured, ok := configuredKeysetSignature(shape, semantics)
	if !ok {
		return false
	}
	actual := requestKeysetSignature(request, semantics)
	left, err := json.Marshal(configured)
	if err != nil {
		return false
	}
	right, err := json.Marshal(actual)
	return err == nil && bytes.Equal(left, right)
}

func configuredKeysetSignature(
	shape config.KeysetSelectShape, semantics domain.IdentifierSemantics,
) (keysetSignature, bool) {
	result := keysetSignature{
		Schema:     canonicalPolicyIdentifier(shape.Source.Schema, semantics.CaseInsensitiveSchemas),
		Object:     canonicalPolicyIdentifier(shape.Source.Name, semantics.CaseInsensitiveObjects),
		Projection: make([]keysetProjectionSignature, len(shape.Projection)),
		OrderBy:    make([]keysetOrderSignature, len(shape.OrderBy)),
	}
	for index, output := range shape.Projection {
		result.Projection[index] = keysetProjectionSignature{
			Representation: output.Representation, Field: canonicalPolicyIdentifier(output.Field, semantics.CaseInsensitiveFields),
			Alias: canonicalPolicyIdentifier(output.Alias, true),
		}
	}
	var ok bool
	result.Filter, ok = configuredAggregateShapeFilter(shape.Filter, semantics.CaseInsensitiveFields)
	if !ok {
		return keysetSignature{}, false
	}
	for index, order := range shape.OrderBy {
		result.OrderBy[index] = keysetOrderSignature{
			Representation: order.Representation, Field: canonicalPolicyIdentifier(order.Field, semantics.CaseInsensitiveFields), Direction: order.Direction,
		}
	}
	return result, true
}

func requestKeysetSignature(
	request queryspec.NormalizedKeysetRequest, semantics domain.IdentifierSemantics,
) keysetSignature {
	result := keysetSignature{
		Schema:     canonicalPolicyIdentifier(request.Query.Source.Schema, semantics.CaseInsensitiveSchemas),
		Object:     canonicalPolicyIdentifier(request.Query.Source.Name, semantics.CaseInsensitiveObjects),
		Projection: make([]keysetProjectionSignature, len(request.Query.Projection)),
		OrderBy:    make([]keysetOrderSignature, len(request.Query.OrderBy)),
	}
	for index, output := range request.Query.Projection {
		result.Projection[index] = keysetProjectionSignature{
			Representation: output.Representation, Field: canonicalPolicyIdentifier(output.Field, semantics.CaseInsensitiveFields),
			Alias: canonicalPolicyIdentifier(output.Alias, true),
		}
	}
	result.Filter = queryKeysetShapeFilter(request.Query.Filter, semantics.CaseInsensitiveFields)
	for index, order := range request.Query.OrderBy {
		result.OrderBy[index] = keysetOrderSignature{
			Representation: order.Representation, Field: canonicalPolicyIdentifier(order.Field, semantics.CaseInsensitiveFields), Direction: order.Direction,
		}
	}
	return result
}

func queryKeysetShapeFilter(filter *queryspec.Filter, caseInsensitiveFields bool) *aggregateShapeFilter {
	if filter == nil {
		return nil
	}
	result := &aggregateShapeFilter{
		Kind:     filter.Kind,
		Field:    canonicalPolicyIdentifier(filter.Field, caseInsensitiveFields),
		Operator: filter.Operator,
	}
	if filter.Kind == "predicate" {
		result.ValueTypes = make([]string, len(filter.Values))
		for index, value := range filter.Values {
			result.ValueTypes[index] = value.Type
		}
		return result
	}
	result.Expressions = make([]aggregateShapeFilter, len(filter.Expressions))
	for index := range filter.Expressions {
		result.Expressions[index] = *queryKeysetShapeFilter(&filter.Expressions[index], caseInsensitiveFields)
	}
	return result
}

func authorizeKeysetFeatures(policy config.QueryPolicy, request queryspec.NormalizedKeysetRequest) error {
	if queryspec.KeysetUsesSourceText(request) && !policy.AllowSourceText {
		return &Denial{ReasonCode: ReasonDeniedQueryFeature}
	}
	if !policy.AllowSorting {
		return &Denial{ReasonCode: ReasonDeniedQueryFeature}
	}
	if request.Query.Filter == nil {
		return nil
	}
	if !policy.AllowFiltering {
		return &Denial{ReasonCode: ReasonDeniedQueryFeature}
	}
	var operators []string
	collectOperators(*request.Query.Filter, &operators)
	for _, operator := range operators {
		if !slices.Contains(policy.AllowedFilterOperators, operator) {
			return &Denial{ReasonCode: ReasonDeniedQueryFeature}
		}
	}
	return nil
}

func keysetShapeFilterFromConfig(filter *config.AggregateShapeFilter) *queryspec.Filter {
	if filter == nil {
		return nil
	}
	result := &queryspec.Filter{Representation: filter.Representation, Kind: filter.Kind, Field: filter.Field, Operator: filter.Operator}
	if filter.ValueTypes != nil {
		result.Values = make([]queryspec.TypedValue, len(*filter.ValueTypes))
		for index, valueType := range *filter.ValueTypes {
			result.Values[index] = queryspec.TypedValue{Type: valueType, Value: json.RawMessage("null")}
		}
	}
	result.Expressions = make([]queryspec.Filter, len(filter.Expressions))
	for index := range filter.Expressions {
		result.Expressions[index] = *keysetShapeFilterFromConfig(&filter.Expressions[index])
	}
	return result
}

func keysetShapeHasFields(shape config.KeysetSelectShape, fields []string) bool {
	wanted := slices.Clone(fields)
	slices.Sort(wanted)
	configured := make([]string, 0, len(shape.Projection)+len(shape.OrderBy))
	for _, projection := range shape.Projection {
		configured = append(configured, strings.ToLower(projection.Field))
	}
	if shape.Filter != nil {
		collectConfiguredFilterFields(*shape.Filter, &configured)
	}
	for _, order := range shape.OrderBy {
		configured = append(configured, strings.ToLower(order.Field))
	}
	slices.Sort(configured)
	configured = slices.Compact(configured)
	return slices.Equal(configured, wanted)
}

func collectConfiguredFilterFields(filter config.AggregateShapeFilter, result *[]string) {
	if filter.Kind == "predicate" {
		*result = append(*result, strings.ToLower(filter.Field))
		return
	}
	for _, child := range filter.Expressions {
		collectConfiguredFilterFields(child, result)
	}
}

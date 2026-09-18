package queryspec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

type wireString struct {
	Value string
	Set   bool
}

func (v *wireString) UnmarshalJSON(data []byte) error {
	v.Set = true
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("must not be null")
	}
	return json.Unmarshal(data, &v.Value)
}

type wireInt struct {
	Value int
	Set   bool
}

func (v *wireInt) UnmarshalJSON(data []byte) error {
	v.Set = true
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("must not be null")
	}
	value, err := parseJSONInteger(data)
	if err != nil {
		return errors.New("must be an integral JSON number in range")
	}
	v.Value = int(value)
	if int64(v.Value) != value {
		return errors.New("integer is outside the platform range")
	}
	return nil
}

type requestWire struct {
	Profile wireString `json:"profile"`
	Query   *specWire  `json:"query"`
}

type specWire struct {
	Source     *resourceWire    `json:"source"`
	Projection *[]selectionWire `json:"projection"`
	Filter     *filterWire      `json:"filter,omitempty"`
	GroupBy    *[]wireString    `json:"group_by,omitempty"`
	OrderBy    *[]sortWire      `json:"order_by,omitempty"`
	Limit      wireInt          `json:"limit,omitempty"`
	Offset     wireInt          `json:"offset,omitempty"`
}

type resourceWire struct {
	Schema wireString `json:"schema"`
	Name   wireString `json:"name"`
}

type selectionWire struct {
	Representation wireString `json:"representation,omitempty"`
	Kind           wireString `json:"kind"`
	Field          wireString `json:"field,omitempty"`
	Function       wireString `json:"function,omitempty"`
	Alias          wireString `json:"alias,omitempty"`
}

type filterWire struct {
	Representation wireString        `json:"representation,omitempty"`
	Kind           wireString        `json:"kind"`
	Field          wireString        `json:"field,omitempty"`
	Operator       wireString        `json:"operator"`
	Values         *[]typedValueWire `json:"values,omitempty"`
	Expressions    *[]filterWire     `json:"expressions,omitempty"`
}

type sortWire struct {
	Representation wireString `json:"representation,omitempty"`
	Field          wireString `json:"field"`
	Direction      wireString `json:"direction"`
}

type typedValueWire struct {
	Type  wireString      `json:"type"`
	Value json.RawMessage `json:"value"`
}

func DecodeStrict(data []byte, maxFilterDepth int) (Request, error) {
	return decodeStrictRequest(data, maxFilterDepth, false)
}

// DecodeStrictSelect enforces the narrower SimpleSelectQuerySpec transport
// contract before the service applies effective profile limits and policy.
func DecodeStrictSelect(data []byte, maxFilterDepth int) (Request, error) {
	return decodeStrictRequest(data, maxFilterDepth, true)
}

func decodeStrictRequest(data []byte, maxFilterDepth int, selectOnly bool) (Request, error) {
	if !utf8.Valid(data) {
		return Request{}, errors.New("request body must be valid UTF-8")
	}
	if err := scanRequestShape(data, maxFilterDepth, selectOnly); err != nil {
		return Request{}, err
	}
	var wire *requestWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return Request{}, err
	}
	if wire == nil {
		return Request{}, errors.New("request body must contain a JSON object")
	}
	if !wire.Profile.Set {
		return Request{}, errors.New("profile is required")
	}
	if wire.Profile.Value == "" {
		return Request{}, errors.New("profile must not be empty")
	}
	if wire.Query == nil {
		return Request{}, errors.New("query is required")
	}
	query, err := wire.Query.decode(maxFilterDepth)
	if err != nil {
		return Request{}, err
	}
	if selectOnly {
		if err := validateSimpleSelectTransport(query, maxFilterDepth); err != nil {
			return Request{}, err
		}
	}
	return Request{Profile: wire.Profile.Value, Query: query}, nil
}

// validateSimpleSelectTransport applies every SimpleSelectQuerySpec constraint
// that is independent of the selected policy profile. Validate is deliberately
// called with protocol maxima here; the service repeats validation with the
// smaller effective limits before authorization or database work.
func validateSimpleSelectTransport(query Spec, maxFilterDepth int) error {
	maxInt := int(^uint(0) >> 1)
	validated, err := Validate(
		query,
		ProtocolMaxProjectionFields,
		ProtocolMaxGroupByFields,
		ProtocolMaxOrderByFields,
		maxInt,
		maxFilterDepth,
		maxInt,
		ProtocolMaxRows,
		ProtocolMaxOffset,
	)
	if err != nil {
		return err
	}
	return ValidateSimpleSelect(validated)
}

func (w specWire) decode(maxFilterDepth int) (Spec, error) {
	if w.Source == nil {
		return Spec{}, errors.New("query.source is required")
	}
	source, err := w.Source.decode()
	if err != nil {
		return Spec{}, err
	}
	if w.Projection == nil {
		return Spec{}, errors.New("query.projection is required")
	}
	if len(*w.Projection) > ProtocolMaxProjectionFields {
		return Spec{}, errors.New("query.projection exceeds the protocol projection limit")
	}
	projection := make([]Selection, len(*w.Projection))
	for index, selection := range *w.Projection {
		projection[index], err = selection.decode()
		if err != nil {
			return Spec{}, fmt.Errorf("query.projection[%d]: %w", index, err)
		}
	}
	result := Spec{Source: source, Projection: projection}
	if w.Filter != nil {
		filter, err := w.Filter.decode(1, maxFilterDepth)
		if err != nil {
			return Spec{}, fmt.Errorf("query.filter: %w", err)
		}
		result.Filter = &filter
	}
	if w.GroupBy != nil {
		if len(*w.GroupBy) > ProtocolMaxGroupByFields {
			return Spec{}, errors.New("query.group_by exceeds the protocol group-by limit")
		}
		result.GroupBy = make([]string, len(*w.GroupBy))
		for index, field := range *w.GroupBy {
			if !field.Set {
				return Spec{}, fmt.Errorf("query.group_by[%d] is required", index)
			}
			result.GroupBy[index] = field.Value
		}
	}
	if w.OrderBy != nil {
		if len(*w.OrderBy) > ProtocolMaxOrderByFields {
			return Spec{}, errors.New("query.order_by exceeds the protocol order-by limit")
		}
		result.OrderBy = make([]Sort, len(*w.OrderBy))
		for index, sort := range *w.OrderBy {
			result.OrderBy[index], err = sort.decode()
			if err != nil {
				return Spec{}, fmt.Errorf("query.order_by[%d]: %w", index, err)
			}
		}
	}
	if w.Limit.Set {
		if w.Limit.Value < 1 || w.Limit.Value > ProtocolMaxRows {
			return Spec{}, fmt.Errorf("query.limit must be between 1 and %d", ProtocolMaxRows)
		}
		result.Limit = &w.Limit.Value
	}
	if w.Offset.Set {
		if w.Offset.Value < 0 || w.Offset.Value > ProtocolMaxOffset {
			return Spec{}, fmt.Errorf("query.offset must be between 0 and %d", ProtocolMaxOffset)
		}
		result.Offset = &w.Offset.Value
	}
	return result, nil
}

func (w resourceWire) decode() (ResourceRef, error) {
	if !w.Schema.Set {
		return ResourceRef{}, errors.New("query.source.schema is required")
	}
	if !w.Name.Set {
		return ResourceRef{}, errors.New("query.source.name is required")
	}
	return ResourceRef{Schema: w.Schema.Value, Name: w.Name.Value}, nil
}

func (w selectionWire) decode() (Selection, error) {
	representation, err := decodeRepresentation(w.Representation, w.Kind.Value == "field")
	if err != nil {
		return Selection{}, err
	}
	if !w.Kind.Set {
		return Selection{}, errors.New("kind is required")
	}
	if w.Field.Set && w.Field.Value == "" {
		return Selection{}, errors.New("field must not be empty when present")
	}
	if w.Alias.Set && w.Alias.Value == "" {
		return Selection{}, errors.New("alias must not be empty when present")
	}
	switch w.Kind.Value {
	case "field":
		if !w.Field.Set {
			return Selection{}, errors.New("field selection requires field")
		}
		if w.Function.Set {
			return Selection{}, errors.New("field selection must not contain function")
		}
	case "aggregate":
		if !w.Function.Set {
			return Selection{}, errors.New("aggregate selection requires function")
		}
	default:
		return Selection{}, fmt.Errorf("kind %q is not supported", w.Kind.Value)
	}
	return Selection{
		Representation: representation, Kind: w.Kind.Value, Field: w.Field.Value, Function: w.Function.Value, Alias: w.Alias.Value,
	}, nil
}

func (w filterWire) decode(depth, maxDepth int) (Filter, error) {
	if depth > maxDepth {
		return Filter{}, errors.New("exceeds the effective expression depth limit")
	}
	if !w.Kind.Set {
		return Filter{}, errors.New("kind is required")
	}
	if !w.Operator.Set {
		return Filter{}, errors.New("operator is required")
	}
	representation, err := decodeRepresentation(w.Representation, w.Kind.Value == "predicate")
	if err != nil {
		return Filter{}, err
	}
	result := Filter{Representation: representation, Kind: w.Kind.Value, Field: w.Field.Value, Operator: w.Operator.Value}
	switch w.Kind.Value {
	case "predicate":
		if !w.Field.Set {
			return Filter{}, errors.New("predicate requires field")
		}
		if w.Values == nil {
			return Filter{}, errors.New("predicate requires values")
		}
		if w.Expressions != nil {
			return Filter{}, errors.New("predicate must not contain expressions")
		}
		if len(*w.Values) > ProtocolMaxFilterItems {
			return Filter{}, errors.New("values exceed the protocol array limit")
		}
		result.Values = make([]TypedValue, len(*w.Values))
		for index, value := range *w.Values {
			decoded, err := value.decode()
			if err != nil {
				return Filter{}, fmt.Errorf("values[%d]: %w", index, err)
			}
			result.Values[index] = decoded
		}
	case "group":
		if w.Expressions == nil {
			return Filter{}, errors.New("group requires expressions")
		}
		if w.Field.Set || w.Values != nil {
			return Filter{}, errors.New("group must not contain field or values")
		}
		if len(*w.Expressions) > ProtocolMaxFilterItems {
			return Filter{}, errors.New("expressions exceed the protocol array limit")
		}
		result.Expressions = make([]Filter, len(*w.Expressions))
		for index, expression := range *w.Expressions {
			decoded, err := expression.decode(depth+1, maxDepth)
			if err != nil {
				// Do not recursively prefix paths here: a deeply nested invalid
				// request would otherwise create quadratic error strings before
				// the configured validation depth limit is applied.
				return Filter{}, err
			}
			result.Expressions[index] = decoded
		}
	default:
		return Filter{}, fmt.Errorf("kind %q is not supported", w.Kind.Value)
	}
	return result, nil
}

// scanRequestShape enforces exact property names plus recursive and per-array
// protocol bounds before encoding/json materializes the complete request tree.
// encoding/json accepts case-folded struct field names, so the token scanner
// must reject every non-exact key before the two decoders can disagree about
// which subtrees are subject to structural limits.
func scanRequestShape(data []byte, maxFilterDepth int, selectOnly bool) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return nil // The strict object decoder returns the request-contract error.
	}
	seen := make(map[string]struct{}, 2)
	for decoder.More() {
		key, err := nextUniqueObjectKey(decoder, seen)
		if err != nil {
			return err
		}
		switch key {
		case "profile":
			err = skipJSONValue(decoder)
		case "query":
			err = scanQueryShape(decoder, maxFilterDepth, selectOnly)
		default:
			return unknownJSONField(key)
		}
		if err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func scanQueryShape(decoder *json.Decoder, maxFilterDepth int, selectOnly bool) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return nil
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return errors.New("query must contain a JSON object")
	}
	seen := make(map[string]struct{}, 7)
	for decoder.More() {
		key, err := nextUniqueObjectKey(decoder, seen)
		if err != nil {
			return err
		}
		switch key {
		case "source":
			err = scanResourceShape(decoder)
		case "projection":
			err = scanBoundedArray(decoder, ProtocolMaxProjectionFields, "query.projection", func() error {
				return scanSelectionShape(decoder, selectOnly)
			})
		case "filter":
			err = scanFilterShape(decoder, 1, maxFilterDepth, nil)
		case "group_by":
			if selectOnly {
				return unknownJSONField(key)
			}
			err = scanBoundedArray(decoder, ProtocolMaxGroupByFields, "query.group_by", func() error {
				return skipJSONValue(decoder)
			})
		case "order_by":
			err = scanBoundedArray(decoder, ProtocolMaxOrderByFields, "query.order_by", func() error {
				return scanSortShape(decoder)
			})
		case "limit", "offset":
			err = skipJSONValue(decoder)
		default:
			return unknownJSONField(key)
		}
		if err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func scanResourceShape(decoder *json.Decoder) error {
	return scanObjectShape(decoder, "query.source", func(key string) error {
		switch key {
		case "schema", "name":
			return skipJSONValue(decoder)
		default:
			return unknownJSONField(key)
		}
	})
}

func scanSelectionShape(decoder *json.Decoder, selectOnly bool) error {
	return scanObjectShape(decoder, "query.projection item", func(key string) error {
		switch key {
		case "kind", "field", "alias", "representation":
			return skipJSONValue(decoder)
		case "function":
			if selectOnly {
				return unknownJSONField(key)
			}
			return skipJSONValue(decoder)
		default:
			return unknownJSONField(key)
		}
	})
}

func scanSortShape(decoder *json.Decoder) error {
	return scanObjectShape(decoder, "query.order_by item", func(key string) error {
		switch key {
		case "field", "direction", "representation":
			return skipJSONValue(decoder)
		default:
			return unknownJSONField(key)
		}
	})
}

type filterShapeScanBudget struct {
	maxPredicates int
	maxParameters int
	maxNodes      int
	predicates    int
	parameters    int
	nodes         int
}

func newFilterShapeScanBudget(maxPredicates, maxParameters int) *filterShapeScanBudget {
	maxNodes := maxPredicates
	maxInt := int(^uint(0) >> 1)
	if maxPredicates > 0 && maxPredicates <= maxInt/2 {
		// Every contract-valid group has at least two children, so a tree with P
		// predicate leaves has no more than 2*P-1 total filter objects.
		maxNodes = 2*maxPredicates - 1
	}
	return &filterShapeScanBudget{
		maxPredicates: maxPredicates,
		maxParameters: maxParameters,
		maxNodes:      maxNodes,
	}
}

func (b *filterShapeScanBudget) enterFilter() error {
	if b == nil {
		return nil
	}
	b.nodes++
	if b.nodes > b.maxNodes {
		return errors.New("query.filter exceeds the effective predicate limit")
	}
	return nil
}

func (b *filterShapeScanBudget) addPredicate() error {
	if b == nil {
		return nil
	}
	b.predicates++
	if b.predicates > b.maxPredicates {
		return errors.New("query.filter exceeds the effective predicate limit")
	}
	return nil
}

func (b *filterShapeScanBudget) addParameter() error {
	if b == nil {
		return nil
	}
	b.parameters++
	if b.parameters > b.maxParameters {
		return errors.New("query.filter exceeds the effective parameter limit")
	}
	return nil
}

func (b *filterShapeScanBudget) addServerParameter() error {
	if b == nil {
		return nil
	}
	b.parameters++
	if b.parameters > b.maxParameters {
		return errors.New("query exceeds the effective parameter limit")
	}
	return nil
}

func scanFilterShape(
	decoder *json.Decoder, depth, maxDepth int, budget *filterShapeScanBudget,
) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return errors.New("query.filter must not be null")
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return errors.New("query.filter must contain a JSON object")
	}
	if depth > maxDepth {
		return errors.New("query.filter exceeds the effective expression depth limit")
	}
	if err := budget.enterFilter(); err != nil {
		return err
	}
	seen := make(map[string]struct{}, 5)
	for decoder.More() {
		key, err := nextUniqueObjectKey(decoder, seen)
		if err != nil {
			return err
		}
		switch key {
		case "kind":
			token, tokenErr := decoder.Token()
			if tokenErr != nil {
				err = tokenErr
				break
			}
			if kind, ok := token.(string); ok && kind == "predicate" {
				err = budget.addPredicate()
			}
			if err == nil {
				err = skipJSONToken(decoder, token)
			}
		case "field", "operator", "representation":
			err = skipJSONValue(decoder)
		case "values":
			err = scanBoundedArray(decoder, ProtocolMaxFilterItems, "filter values", func() error {
				if err := budget.addParameter(); err != nil {
					return err
				}
				return scanTypedValueShape(decoder)
			})
		case "expressions":
			err = scanBoundedArray(decoder, ProtocolMaxFilterItems, "filter expressions", func() error {
				return scanFilterShape(decoder, depth+1, maxDepth, budget)
			})
		default:
			return unknownJSONField(key)
		}
		if err != nil {
			return err
		}
	}
	if _, err = decoder.Token(); err != nil {
		return err
	}
	return nil
}

func scanTypedValueShape(decoder *json.Decoder) error {
	return scanObjectShape(decoder, "filter value", func(key string) error {
		switch key {
		case "type", "value":
			return skipJSONValue(decoder)
		default:
			return unknownJSONField(key)
		}
	})
}

func scanObjectShape(decoder *json.Decoder, name string, scanField func(string) error) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return nil // The strict object decoder returns the request-contract error.
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return fmt.Errorf("%s must contain a JSON object", name)
	}
	seen := make(map[string]struct{}, 4)
	for decoder.More() {
		key, err := nextUniqueObjectKey(decoder, seen)
		if err != nil {
			return err
		}
		if err := scanField(key); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func unknownJSONField(key string) error {
	return fmt.Errorf("json: unknown field %q", key)
}

func scanBoundedArray(decoder *json.Decoder, maximum int, name string, scanItem func() error) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '[' {
		return fmt.Errorf("%s must contain a JSON array", name)
	}
	count := 0
	for decoder.More() {
		count++
		if count > maximum {
			return fmt.Errorf("%s exceeds the protocol limit of %d items", name, maximum)
		}
		if err := scanItem(); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func nextObjectKey(decoder *json.Decoder) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", err
	}
	key, ok := token.(string)
	if !ok {
		return "", errors.New("JSON object key must be a string")
	}
	return key, nil
}

func nextUniqueObjectKey(decoder *json.Decoder, seen map[string]struct{}) (string, error) {
	key, err := nextObjectKey(decoder)
	if err != nil {
		return "", err
	}
	if _, exists := seen[key]; exists {
		return "", fmt.Errorf("duplicate JSON field %q", key)
	}
	seen[key] = struct{}{}
	return key, nil
}

func skipJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	return skipJSONToken(decoder, token)
}

func skipJSONToken(decoder *json.Decoder, token json.Token) error {
	delimiter, ok := token.(json.Delim)
	if !ok || (delimiter != '{' && delimiter != '[') {
		return nil
	}
	depth := 1
	for depth > 0 {
		next, err := decoder.Token()
		if err != nil {
			return err
		}
		token = next
		delimiter, ok = token.(json.Delim)
		if !ok {
			continue
		}
		switch delimiter {
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		}
	}
	return nil
}

func (w sortWire) decode() (Sort, error) {
	representation, err := decodeRepresentation(w.Representation, true)
	if err != nil {
		return Sort{}, err
	}
	if !w.Field.Set {
		return Sort{}, errors.New("field is required")
	}
	if !w.Direction.Set {
		return Sort{}, errors.New("direction is required")
	}
	return Sort{Representation: representation, Field: w.Field.Value, Direction: w.Direction.Value}, nil
}

func (w typedValueWire) decode() (TypedValue, error) {
	if !w.Type.Set {
		return TypedValue{}, errors.New("type is required")
	}
	if w.Value == nil {
		return TypedValue{}, errors.New("value is required")
	}
	return TypedValue{Type: w.Type.Value, Value: append(json.RawMessage(nil), w.Value...)}, nil
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain exactly one JSON object")
		}
		return err
	}
	return nil
}

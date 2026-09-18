package queryspec

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	defaultLimit                = 100
	ProtocolMaxIdentifierBytes  = 128
	ProtocolMaxProjectionFields = 100
	ProtocolMaxGroupByFields    = 100
	ProtocolMaxOrderByFields    = 100
	ProtocolMaxFilterItems      = 200
	ProtocolMaxRows             = 1_000_000
	ProtocolMaxOffset           = 1_000_000_000
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	uuidPattern       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	decimalPattern    = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$`)
	jsonNumberPattern = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$`)
)

type Request struct {
	Profile string `json:"profile"`
	Query   Spec   `json:"query"`
}

type Spec struct {
	Source     ResourceRef `json:"source"`
	Projection []Selection `json:"projection"`
	Filter     *Filter     `json:"filter,omitempty"`
	GroupBy    []string    `json:"group_by,omitempty"`
	OrderBy    []Sort      `json:"order_by,omitempty"`
	Limit      *int        `json:"limit,omitempty"`
	Offset     *int        `json:"offset,omitempty"`
}

type ResourceRef struct {
	Schema string `json:"schema"`
	Name   string `json:"name"`
}

type Selection struct {
	Representation Representation `json:"representation,omitempty"`
	Kind           string         `json:"kind"`
	Field          string         `json:"field,omitempty"`
	Function       string         `json:"function,omitempty"`
	Alias          string         `json:"alias,omitempty"`
}

type Filter struct {
	Representation Representation `json:"representation,omitempty"`
	Kind           string         `json:"kind"`
	Field          string         `json:"field,omitempty"`
	Operator       string         `json:"operator"`
	Values         []TypedValue   `json:"values,omitempty"`
	Expressions    []Filter       `json:"expressions,omitempty"`
}

type Sort struct {
	Representation Representation `json:"representation,omitempty"`
	Field          string         `json:"field"`
	Direction      string         `json:"direction"`
}

type TypedValue struct {
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

type NormalizedSpec struct {
	Source     ResourceRef
	Projection []Selection
	Filter     *Filter
	GroupBy    []string
	OrderBy    []Sort
	Limit      int
	Offset     int
}

type Stats struct {
	Predicates      int
	ExpressionDepth int
	Parameters      int
}

type Validated struct {
	spec  NormalizedSpec
	stats Stats
	valid bool
}

func (v Validated) Spec() NormalizedSpec { return cloneNormalized(v.spec) }
func (v Validated) Stats() Stats         { return v.stats }

func IsIdentifier(value string) bool {
	return validateIdentifier("identifier", value) == nil
}

func ValidateSimpleSelect(query Validated) error {
	if !query.valid {
		return validationError("query", "has not been validated")
	}
	spec := query.spec
	if len(spec.GroupBy) != 0 {
		return validationError("query.group_by", "is not supported for executable select")
	}
	for index, selection := range spec.Projection {
		if selection.Kind != "field" {
			return validationError(
				fmt.Sprintf("query.projection[%d]", index),
				"only field projections are supported for executable select",
			)
		}
	}
	return nil
}

type ValidationError struct {
	Path    string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Path + ": " + e.Message
}

func Validate(
	spec Spec,
	maxProjection, maxGroupBy, maxOrderBy, maxPredicates, maxDepth, maxParameters, maxRows, maxOffset int,
) (Validated, error) {
	if err := validateIdentifier("query.source.schema", spec.Source.Schema); err != nil {
		return Validated{}, err
	}
	if err := validateIdentifier("query.source.name", spec.Source.Name); err != nil {
		return Validated{}, err
	}
	if len(spec.Projection) == 0 {
		return Validated{}, validationError("query.projection", "must contain at least one selection")
	}
	if len(spec.Projection) > ProtocolMaxProjectionFields {
		return Validated{}, validationError("query.projection", "exceeds the protocol projection limit")
	}
	if len(spec.Projection) > maxProjection {
		return Validated{}, validationError("query.projection", "exceeds the effective projection limit")
	}

	for i, selection := range spec.Projection {
		path := fmt.Sprintf("query.projection[%d]", i)
		if err := validateSelection(path, selection); err != nil {
			return Validated{}, err
		}
	}

	stats := Stats{Parameters: 2} // LIMIT and OFFSET are always bound.
	if stats.Parameters > maxParameters {
		return Validated{}, validationError("query", "exceeds the effective parameter limit")
	}
	if spec.Filter != nil {
		filterLimits := filterValidationLimits{
			maxPredicates: maxPredicates,
			maxDepth:      maxDepth,
			maxParameters: maxParameters,
		}
		if err := validateFilter("query.filter", *spec.Filter, 1, &stats, filterLimits); err != nil {
			return Validated{}, err
		}
	}

	if len(spec.GroupBy) > ProtocolMaxGroupByFields {
		return Validated{}, validationError("query.group_by", "exceeds the protocol group-by limit")
	}
	if len(spec.GroupBy) > maxGroupBy {
		return Validated{}, validationError("query.group_by", "exceeds the effective group-by limit")
	}
	for i, field := range spec.GroupBy {
		if err := validateIdentifier(fmt.Sprintf("query.group_by[%d]", i), field); err != nil {
			return Validated{}, err
		}
	}
	if len(spec.OrderBy) > ProtocolMaxOrderByFields {
		return Validated{}, validationError("query.order_by", "exceeds the protocol order-by limit")
	}
	if len(spec.OrderBy) > maxOrderBy {
		return Validated{}, validationError("query.order_by", "exceeds the effective order-by limit")
	}
	for i, sort := range spec.OrderBy {
		path := fmt.Sprintf("query.order_by[%d]", i)
		if err := validateRepresentation(path, sort.Representation); err != nil {
			return Validated{}, err
		}
		if err := validateIdentifier(path+".field", sort.Field); err != nil {
			return Validated{}, err
		}
		if sort.Direction != "asc" && sort.Direction != "desc" {
			return Validated{}, validationError(path+".direction", "must be asc or desc")
		}
	}
	if err := validateGroupedShape(spec.Projection, spec.GroupBy, spec.OrderBy); err != nil {
		return Validated{}, err
	}

	limit := defaultLimit
	if spec.Limit != nil {
		limit = *spec.Limit
		if limit < 1 {
			return Validated{}, validationError("query.limit", "must be at least 1")
		}
		if limit > ProtocolMaxRows {
			return Validated{}, validationError("query.limit", "exceeds the protocol row limit")
		}
	}
	if limit > maxRows {
		limit = maxRows
	}
	offset := 0
	if spec.Offset != nil {
		offset = *spec.Offset
		if offset < 0 {
			return Validated{}, validationError("query.offset", "must not be negative")
		}
		if offset > ProtocolMaxOffset {
			return Validated{}, validationError("query.offset", "exceeds the protocol offset limit")
		}
	}
	if offset > maxOffset {
		return Validated{}, validationError("query.offset", "exceeds the effective offset limit")
	}

	normalized := NormalizedSpec{
		Source:     spec.Source,
		Projection: append([]Selection(nil), spec.Projection...),
		Filter:     cloneFilter(spec.Filter),
		GroupBy:    append([]string(nil), spec.GroupBy...),
		OrderBy:    append([]Sort(nil), spec.OrderBy...),
		Limit:      limit,
		Offset:     offset,
	}
	return Validated{spec: normalized, stats: stats, valid: true}, nil
}

// Revalidate applies a new, potentially stricter set of limits to an already
// validated query. Authorization boundaries use it before minting a token so
// callers cannot carry normalization performed under looser limits into an
// executor. Semantic/type validation has already established the Validated
// invariant; this pass uses stored structure and never reparses bind values.
func Revalidate(
	query Validated,
	maxProjection, maxGroupBy, maxOrderBy, maxPredicates, maxDepth, maxParameters, maxRows, maxOffset int,
) (Validated, error) {
	if !query.valid {
		return Validated{}, validationError("query", "has not been validated")
	}
	if len(query.spec.Projection) > maxProjection {
		return Validated{}, validationError("query.projection", "exceeds the effective projection limit")
	}
	if len(query.spec.GroupBy) > maxGroupBy {
		return Validated{}, validationError("query.group_by", "exceeds the effective group-by limit")
	}
	if len(query.spec.OrderBy) > maxOrderBy {
		return Validated{}, validationError("query.order_by", "exceeds the effective order-by limit")
	}
	if query.stats.Predicates > maxPredicates {
		return Validated{}, validationError("query.filter", "exceeds the effective predicate limit")
	}
	if query.stats.ExpressionDepth > maxDepth {
		return Validated{}, validationError("query.filter", "exceeds the effective expression depth limit")
	}
	if query.stats.Parameters > maxParameters {
		return Validated{}, validationError("query.filter", "exceeds the effective parameter limit")
	}
	if query.spec.Offset > maxOffset {
		return Validated{}, validationError("query.offset", "exceeds the effective offset limit")
	}
	if maxRows < 1 {
		return Validated{}, validationError("query.limit", "effective row limit must be at least 1")
	}
	normalized := query.spec
	if normalized.Limit > maxRows {
		normalized.Limit = maxRows
	}
	return Validated{spec: normalized, stats: query.stats, valid: true}, nil
}

func validateGroupedShape(projection []Selection, groupBy []string, orderBy []Sort) error {
	hasAggregate := false
	fields := make([]string, 0, len(projection))
	for _, selection := range projection {
		if selection.Kind == "aggregate" {
			hasAggregate = true
			continue
		}
		fields = append(fields, selection.Field)
	}
	if hasAggregate && len(groupBy) == 0 && len(fields) != 0 {
		return validationError("query.projection", "non-aggregate fields require query.group_by when aggregates are projected")
	}
	if len(groupBy) != 0 || hasAggregate {
		for _, selection := range projection {
			if selection.Representation != "" {
				return validationError("query.projection", "source_text is unsupported in legacy grouped EXPLAIN")
			}
		}
	}
	if len(groupBy) == 0 && !hasAggregate {
		return nil
	}
	for _, field := range fields {
		grouped := false
		for _, groupField := range groupBy {
			if strings.EqualFold(field, groupField) {
				grouped = true
				break
			}
		}
		if !grouped {
			return validationError("query.projection", fmt.Sprintf("field %q must be listed in query.group_by", field))
		}
	}
	for i, sort := range orderBy {
		if !containsIdentifier(groupBy, sort.Field) {
			return validationError(
				fmt.Sprintf("query.order_by[%d].field", i),
				"must be listed in query.group_by for a grouped or aggregate query",
			)
		}
	}
	return nil
}

func containsIdentifier(identifiers []string, value string) bool {
	for _, identifier := range identifiers {
		if strings.EqualFold(identifier, value) {
			return true
		}
	}
	return false
}

func validateSelection(path string, selection Selection) error {
	if err := validateRepresentation(path, selection.Representation); err != nil {
		return err
	}
	if selection.Kind != "field" && selection.Representation != "" {
		return validationError(path, "representation requires a field")
	}
	switch selection.Kind {
	case "field":
		if selection.Function != "" {
			return validationError(path+".function", "is only valid for aggregate selections")
		}
		if err := validateIdentifier(path+".field", selection.Field); err != nil {
			return err
		}
	case "aggregate":
		switch selection.Function {
		case "count":
			if selection.Field != "" {
				if err := validateIdentifier(path+".field", selection.Field); err != nil {
					return err
				}
			}
		case "min", "max", "sum", "avg":
			if err := validateIdentifier(path+".field", selection.Field); err != nil {
				return err
			}
		default:
			return validationError(path+".function", "contains an unsupported aggregate")
		}
	default:
		return validationError(path+".kind", "must be field or aggregate")
	}
	if selection.Alias != "" {
		if err := validateIdentifier(path+".alias", selection.Alias); err != nil {
			return err
		}
	}
	return nil
}

type filterValidationLimits struct {
	maxPredicates int
	maxDepth      int
	maxParameters int
}

func validateFilter(path string, filter Filter, depth int, stats *Stats, limits filterValidationLimits) error {
	if err := validateRepresentation(path, filter.Representation); err != nil {
		return err
	}
	if filter.Kind != "predicate" && filter.Representation != "" {
		return validationError(path, "representation requires a predicate")
	}
	if depth > limits.maxDepth {
		return validationError(path, "exceeds the effective expression depth limit")
	}
	stats.ExpressionDepth = max(stats.ExpressionDepth, depth)
	switch filter.Kind {
	case "predicate":
		if len(filter.Expressions) != 0 {
			return validationError(path+".expressions", "is only valid for filter groups")
		}
		if len(filter.Values) > ProtocolMaxFilterItems {
			return validationError(path+".values", "exceeds the protocol array limit")
		}
		if err := validateIdentifier(path+".field", filter.Field); err != nil {
			return err
		}
		expectedValues := 1
		switch filter.Operator {
		case "eq", "ne", "lt", "lte", "gt", "gte", "like":
		case "in", "not_in":
			expectedValues = -1
		case "is_null", "is_not_null":
			expectedValues = 0
		default:
			return validationError(path+".operator", "contains an unsupported operator")
		}
		if filter.Values == nil {
			return validationError(path+".values", "is required")
		}
		if expectedValues >= 0 && len(filter.Values) != expectedValues {
			return validationError(path+".values", fmt.Sprintf("must contain %d values", expectedValues))
		}
		if expectedValues == -1 && len(filter.Values) == 0 {
			return validationError(path+".values", "must contain at least one value")
		}
		if stats.Predicates >= limits.maxPredicates {
			return validationError(path, "exceeds the effective predicate limit")
		}
		if stats.Parameters > limits.maxParameters-len(filter.Values) {
			return validationError(path+".values", "exceeds the effective parameter limit")
		}
		stats.Predicates++
		stats.Parameters += len(filter.Values)
		for i, value := range filter.Values {
			if filter.Representation == RepresentationSourceText && value.Type != "string" {
				return validationError(path+".values", "source_text requires string values")
			}
			if _, err := value.BindValue(); err != nil {
				return validationError(fmt.Sprintf("%s.values[%d]", path, i), err.Error())
			}
		}
		return nil
	case "group":
		if filter.Field != "" || filter.Values != nil {
			return validationError(path, "group must not contain field or values")
		}
		if len(filter.Expressions) > ProtocolMaxFilterItems {
			return validationError(path+".expressions", "exceeds the protocol array limit")
		}
		if filter.Operator != "and" && filter.Operator != "or" {
			return validationError(path+".operator", "must be and or or")
		}
		if len(filter.Expressions) < 2 {
			return validationError(path+".expressions", "must contain at least two expressions")
		}
		for i, expression := range filter.Expressions {
			if err := validateFilter(
				fmt.Sprintf("%s.expressions[%d]", path, i), expression, depth+1, stats, limits,
			); err != nil {
				return err
			}
		}
		return nil
	default:
		return validationError(path+".kind", "must be predicate or group")
	}
}

func (v TypedValue) BindValue() (any, error) {
	if v.Value == nil {
		return nil, errors.New("value is required")
	}
	rawValue := bytes.TrimSpace(v.Value)
	if bytes.Equal(rawValue, []byte("null")) {
		return nil, errors.New("typed bind values do not accept JSON null; use is_null or is_not_null")
	}
	switch v.Type {
	case "boolean":
		var value bool
		if err := json.Unmarshal(v.Value, &value); err != nil {
			return nil, errors.New("boolean type requires a JSON boolean")
		}
		return value, nil
	case "integer":
		value, err := parseJSONInteger(rawValue)
		if err != nil {
			return nil, errors.New("integer type requires an integral JSON number in the signed 64-bit range")
		}
		return value, nil
	case "decimal":
		var text string
		if err := json.Unmarshal(v.Value, &text); err == nil {
			if !decimalPattern.MatchString(text) {
				return nil, errors.New("decimal string requires a finite fixed-point base-10 number")
			}
			return text, nil
		}
		if !jsonNumberPattern.Match(rawValue) {
			return nil, errors.New("decimal type requires a finite JSON number or fixed-point string")
		}
		return string(rawValue), nil
	case "string":
		var value string
		if err := json.Unmarshal(v.Value, &value); err != nil {
			return nil, errors.New("string type requires a JSON string")
		}
		return value, nil
	case "uuid":
		var value string
		if err := json.Unmarshal(v.Value, &value); err != nil || !uuidPattern.MatchString(value) {
			return nil, errors.New("uuid type requires a canonical UUID string")
		}
		return value, nil
	case "date":
		var value string
		if err := json.Unmarshal(v.Value, &value); err != nil {
			return nil, errors.New("date type requires a JSON string")
		}
		if _, ok := ParsePortableDate(value); !ok {
			return nil, errors.New("date must use YYYY-MM-DD")
		}
		return value, nil
	case "datetime":
		var value string
		if err := json.Unmarshal(v.Value, &value); err != nil {
			return nil, errors.New("datetime type requires a JSON string")
		}
		if err := validateRFC3339DateTime(value); err != nil {
			return nil, errors.New("datetime must use RFC 3339")
		}
		return value, nil
	case "bytes":
		var value string
		if err := json.Unmarshal(v.Value, &value); err != nil {
			return nil, errors.New("bytes type requires a base64 JSON string")
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
			return nil, errors.New("bytes must use canonical standard base64 encoding")
		}
		return decoded, nil
	default:
		return nil, errors.New("contains an unsupported type")
	}
}

// validateRFC3339DateTime accepts the complete RFC 3339 separator spelling
// used by OpenAPI's date-time format. RFC 3339 permits lower-case "t" and
// "z", while Go's time.RFC3339Nano layout accepts only their upper-case
// spellings. Only a validation copy is normalized: the original value remains
// the bind value and is never silently rewritten.
func validateRFC3339DateTime(value string) error {
	if len(value) <= len("2006-01-02T") || value[:4] == "0000" {
		return errors.New("date-time is too short")
	}
	separatorIsLower := value[10] == 't'
	zoneIsLower := value[len(value)-1] == 'z'
	if !separatorIsLower && !zoneIsLower {
		_, err := time.Parse(time.RFC3339Nano, value)
		return err
	}

	normalized := []byte(value)
	if separatorIsLower {
		normalized[10] = 'T'
	}
	if zoneIsLower {
		normalized[len(normalized)-1] = 'Z'
	}
	_, err := time.Parse(time.RFC3339Nano, string(normalized))
	return err
}

// parseJSONInteger follows the OpenAPI 3.1 / JSON Schema numeric data model:
// 1, 1.0, and 1e0 are the same integral JSON number. It never accepts a JSON
// string and avoids float64 so neither precision nor range can be lost.
func parseJSONInteger(raw []byte) (int64, error) {
	raw = bytes.TrimSpace(raw)
	if !jsonNumberPattern.Match(raw) {
		return 0, errors.New("value is not a JSON number")
	}
	negative := raw[0] == '-'
	if negative {
		raw = raw[1:]
	}

	exponentIndex := bytes.IndexAny(raw, "eE")
	mantissa := raw
	var exponentBytes []byte
	if exponentIndex >= 0 {
		mantissa = raw[:exponentIndex]
		exponentBytes = raw[exponentIndex+1:]
	}
	dotIndex := bytes.IndexByte(mantissa, '.')
	fractionalDigits := 0
	if dotIndex >= 0 {
		fractionalDigits = len(mantissa) - dotIndex - 1
	}
	digits := make([]byte, 0, len(mantissa))
	for _, digit := range mantissa {
		if digit != '.' {
			digits = append(digits, digit)
		}
	}
	for len(digits) != 0 && digits[0] == '0' {
		digits = digits[1:]
	}
	if len(digits) == 0 {
		return 0, nil
	}

	exponent := 0
	if len(exponentBytes) != 0 {
		exponent = parseSaturatedDecimalExponent(exponentBytes, len(raw)+20)
	}
	effectiveExponent := exponent - fractionalDigits
	if effectiveExponent < 0 {
		trailingZeros := -effectiveExponent
		if trailingZeros > len(digits) {
			return 0, errors.New("JSON number is not integral")
		}
		for _, digit := range digits[len(digits)-trailingZeros:] {
			if digit != '0' {
				return 0, errors.New("JSON number is not integral")
			}
		}
		digits = digits[:len(digits)-trailingZeros]
		effectiveExponent = 0
	}

	limit := uint64(^uint64(0) >> 1)
	if negative {
		limit++ // The absolute value of MinInt64 is one larger than MaxInt64.
	}
	magnitude := uint64(0)
	appendDigit := func(digit byte) bool {
		value := uint64(digit - '0')
		if magnitude > (limit-value)/10 {
			return false
		}
		magnitude = magnitude*10 + value
		return true
	}
	for _, digit := range digits {
		if !appendDigit(digit) {
			return 0, errors.New("JSON integer is outside the signed 64-bit range")
		}
	}
	if effectiveExponent > 19 {
		return 0, errors.New("JSON integer is outside the signed 64-bit range")
	}
	for range effectiveExponent {
		if !appendDigit('0') {
			return 0, errors.New("JSON integer is outside the signed 64-bit range")
		}
	}
	if negative {
		if magnitude == uint64(1)<<63 {
			return -1 << 63, nil
		}
		return -int64(magnitude), nil
	}
	return int64(magnitude), nil
}

func parseSaturatedDecimalExponent(raw []byte, maximum int) int {
	negative := raw[0] == '-'
	if raw[0] == '-' || raw[0] == '+' {
		raw = raw[1:]
	}
	value := 0
	for _, digit := range raw {
		decimal := int(digit - '0')
		if value > (maximum-decimal)/10 {
			value = maximum
			break
		}
		value = value*10 + decimal
	}
	if negative {
		return -value
	}
	return value
}

func validateIdentifier(path, value string) error {
	if value == "" {
		return validationError(path, "must not be empty")
	}
	if len(value) > ProtocolMaxIdentifierBytes {
		return validationError(path, "exceeds 128 bytes")
	}
	if !identifierPattern.MatchString(value) {
		return validationError(path, "must be a portable SQL identifier")
	}
	return nil
}

func validationError(path, message string) error {
	return &ValidationError{Path: path, Message: message}
}

func cloneFilter(filter *Filter) *Filter {
	if filter == nil {
		return nil
	}
	cloned := *filter
	cloned.Values = cloneTypedValues(filter.Values)
	cloned.Expressions = make([]Filter, len(filter.Expressions))
	for i := range filter.Expressions {
		child := cloneFilter(&filter.Expressions[i])
		cloned.Expressions[i] = *child
	}
	return &cloned
}

func cloneTypedValues(values []TypedValue) []TypedValue {
	if values == nil {
		return nil
	}
	cloned := make([]TypedValue, len(values))
	for index, value := range values {
		cloned[index] = value
		cloned[index].Value = append(json.RawMessage(nil), value.Value...)
	}
	return cloned
}

func cloneNormalized(spec NormalizedSpec) NormalizedSpec {
	spec.Projection = append([]Selection(nil), spec.Projection...)
	spec.Filter = cloneFilter(spec.Filter)
	spec.GroupBy = append([]string(nil), spec.GroupBy...)
	spec.OrderBy = append([]Sort(nil), spec.OrderBy...)
	return spec
}

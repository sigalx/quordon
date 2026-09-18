package queryspec

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/sigalx/quordon/internal/domain"
)

const (
	ProtocolMaxKeysetFields      = 8
	ProtocolMaxCursorStringRunes = 3072
	ProtocolMaxCursorBytes       = 3072
)

type SelectRequestVNext struct {
	legacy *Request
	keyset *KeysetRequest
}

func NewLegacySelectRequest(request Request) SelectRequestVNext {
	copy := request
	return SelectRequestVNext{legacy: &copy}
}

func NewKeysetSelectRequest(request KeysetRequest) SelectRequestVNext {
	copy := cloneKeysetRequest(request)
	return SelectRequestVNext{keyset: &copy}
}

func (r SelectRequestVNext) Legacy() (Request, bool) {
	if r.legacy == nil || r.keyset != nil {
		return Request{}, false
	}
	return *r.legacy, true
}

func (r SelectRequestVNext) Keyset() (KeysetRequest, bool) {
	if r.keyset == nil || r.legacy != nil {
		return KeysetRequest{}, false
	}
	return cloneKeysetRequest(*r.keyset), true
}

type KeysetRequest struct {
	Kind    string     `json:"kind"`
	Profile string     `json:"profile"`
	Shape   string     `json:"shape"`
	Query   KeysetSpec `json:"query"`
	Page    KeysetPage `json:"page"`
}

type KeysetSpec struct {
	Source     ResourceRef `json:"source"`
	Projection []Selection `json:"projection"`
	Filter     *Filter     `json:"filter,omitempty"`
	OrderBy    []Sort      `json:"order_by"`
	Limit      int         `json:"limit"`
}

type KeysetPage struct {
	Kind   string              `json:"kind"`
	Cursor []KeysetCursorValue `json:"cursor,omitempty"`
}

type KeysetCursorValue struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type NormalizedKeysetRequest struct {
	Profile string
	Shape   string
	Query   KeysetSpec
	Page    KeysetPage
}

type ValidatedKeyset struct {
	request NormalizedKeysetRequest
	stats   Stats
	valid   bool
}

func (v ValidatedKeyset) Request() NormalizedKeysetRequest {
	return cloneNormalizedKeysetRequest(v.request)
}

func (v ValidatedKeyset) Stats() Stats { return v.stats }

func ValidateKeyset(
	request KeysetRequest,
	maxProjection, maxOrderBy, maxPredicates, maxDepth, maxParameters, maxRows int,
) (ValidatedKeyset, error) {
	if request.Kind != "keyset" {
		return ValidatedKeyset{}, validationError("kind", "must be keyset")
	}
	if request.Profile == "" || !utf8.ValidString(request.Profile) {
		return ValidatedKeyset{}, validationError("profile", "must be a nonempty UTF-8 string")
	}
	if err := validateIdentifier("shape", request.Shape); err != nil {
		return ValidatedKeyset{}, err
	}
	if err := validateIdentifier("query.source.schema", request.Query.Source.Schema); err != nil {
		return ValidatedKeyset{}, err
	}
	if err := validateIdentifier("query.source.name", request.Query.Source.Name); err != nil {
		return ValidatedKeyset{}, err
	}
	if len(request.Query.Projection) == 0 || len(request.Query.Projection) > ProtocolMaxProjectionFields ||
		len(request.Query.Projection) > maxProjection {
		return ValidatedKeyset{}, validationError("query.projection", "is outside the effective bounds")
	}
	seenProjection := make(map[string]struct{}, len(request.Query.Projection))
	seenOutputs := make(map[string]struct{}, len(request.Query.Projection))
	for index, selection := range request.Query.Projection {
		path := fmt.Sprintf("query.projection[%d]", index)
		if err := validateRepresentation(path, selection.Representation); err != nil {
			return ValidatedKeyset{}, err
		}
		if selection.Kind != "field" || selection.Function != "" {
			return ValidatedKeyset{}, validationError(path, "must be a field selection")
		}
		if err := validateIdentifier(path+".field", selection.Field); err != nil {
			return ValidatedKeyset{}, err
		}
		if selection.Alias != "" {
			if err := validateIdentifier(path+".alias", selection.Alias); err != nil {
				return ValidatedKeyset{}, err
			}
		}
		term := selection.Field + "\x00" + selection.Alias
		if _, duplicate := seenProjection[term]; duplicate {
			return ValidatedKeyset{}, validationError("query.projection", "contains duplicate terms")
		}
		seenProjection[term] = struct{}{}
		output := selection.Field
		if selection.Alias != "" {
			output = selection.Alias
		}
		output = strings.ToLower(output)
		if _, duplicate := seenOutputs[output]; duplicate {
			return ValidatedKeyset{}, validationError("query.projection", "contains colliding output names")
		}
		seenOutputs[output] = struct{}{}
	}
	if len(request.Query.OrderBy) == 0 || len(request.Query.OrderBy) > ProtocolMaxKeysetFields ||
		len(request.Query.OrderBy) > ProtocolMaxOrderByFields || len(request.Query.OrderBy) > maxOrderBy {
		return ValidatedKeyset{}, validationError("query.order_by", "is outside the effective bounds")
	}
	seenOrder := make(map[string]struct{}, len(request.Query.OrderBy))
	for index, order := range request.Query.OrderBy {
		path := fmt.Sprintf("query.order_by[%d]", index)
		if err := validateRepresentation(path, order.Representation); err != nil {
			return ValidatedKeyset{}, err
		}
		if err := validateIdentifier(path+".field", order.Field); err != nil {
			return ValidatedKeyset{}, err
		}
		if order.Direction != "asc" && order.Direction != "desc" {
			return ValidatedKeyset{}, validationError(path+".direction", "must be asc or desc")
		}
		if _, duplicate := seenOrder[order.Field]; duplicate {
			return ValidatedKeyset{}, validationError("query.order_by", "contains repeated fields")
		}
		seenOrder[order.Field] = struct{}{}
	}
	if request.Query.Limit < 1 || request.Query.Limit > ProtocolMaxRows || request.Query.Limit > maxRows {
		return ValidatedKeyset{}, validationError("query.limit", "is outside the effective bounds")
	}

	stats := Stats{}
	if request.Query.Filter != nil {
		if err := validateFilter(
			"query.filter", *request.Query.Filter, 1, &stats,
			filterValidationLimits{maxPredicates: maxPredicates, maxDepth: maxDepth, maxParameters: maxParameters},
		); err != nil {
			return ValidatedKeyset{}, err
		}
		if err := rejectExactFilterDuplicates(*request.Query.Filter); err != nil {
			return ValidatedKeyset{}, err
		}
	}
	cursorParameters := 0
	switch request.Page.Kind {
	case "first":
		if request.Page.Cursor != nil {
			return ValidatedKeyset{}, validationError("page.cursor", "is forbidden for the first page")
		}
	case "after":
		if len(request.Page.Cursor) == 0 || len(request.Page.Cursor) > ProtocolMaxKeysetFields {
			return ValidatedKeyset{}, validationError("page.cursor", "is outside the protocol bounds")
		}
		if len(request.Page.Cursor) != len(request.Query.OrderBy) {
			return ValidatedKeyset{}, validationError("page.cursor", "must match query.order_by arity")
		}
		for index, cursor := range request.Page.Cursor {
			if request.Query.OrderBy[index].Representation == RepresentationSourceText && cursor.Type != "string" {
				return ValidatedKeyset{}, validationError("page.cursor", "source_text requires a string cursor")
			}
			if err := validateKeysetCursorValue(fmt.Sprintf("page.cursor[%d]", index), cursor); err != nil {
				return ValidatedKeyset{}, err
			}
		}
		cursorParameters = keysetCursorParameterCount(len(request.Page.Cursor))
	default:
		return ValidatedKeyset{}, validationError("page.kind", "must be first or after")
	}
	if stats.Parameters > maxParameters-1 || cursorParameters > maxParameters-1-stats.Parameters {
		return ValidatedKeyset{}, validationError("query", "exceeds the effective parameter limit")
	}
	stats.Parameters += cursorParameters + 1 // One server-owned LIMIT binding.

	normalized := NormalizedKeysetRequest{
		Profile: request.Profile,
		Shape:   request.Shape,
		Query: KeysetSpec{
			Source: request.Query.Source, Projection: slices.Clone(request.Query.Projection),
			Filter: cloneFilter(request.Query.Filter), OrderBy: slices.Clone(request.Query.OrderBy),
			Limit: request.Query.Limit,
		},
		Page: KeysetPage{Kind: request.Page.Kind, Cursor: cloneKeysetCursor(request.Page.Cursor)},
	}
	return ValidatedKeyset{request: normalized, stats: stats, valid: true}, nil
}

func RevalidateKeyset(
	request ValidatedKeyset,
	maxProjection, maxOrderBy, maxPredicates, maxDepth, maxParameters, maxRows int,
) (ValidatedKeyset, error) {
	if !request.valid {
		return ValidatedKeyset{}, validationError("query", "has not been validated")
	}
	normalized := request.Request()
	if len(normalized.Query.Projection) > maxProjection || len(normalized.Query.OrderBy) > maxOrderBy ||
		request.stats.Predicates > maxPredicates || request.stats.ExpressionDepth > maxDepth ||
		request.stats.Parameters > maxParameters || normalized.Query.Limit > maxRows {
		return ValidatedKeyset{}, validationError("query", "exceeds the effective limits")
	}
	return ValidatedKeyset{request: normalized, stats: request.stats, valid: true}, nil
}

func NormalizeKeysetIdentifiers(
	request ValidatedKeyset, semantics domain.IdentifierSemantics,
) (ValidatedKeyset, error) {
	if !request.valid {
		return ValidatedKeyset{}, validationError("query", "has not been validated")
	}
	normalized := request.Request()
	normalized.Query.Source.Schema = canonicalIdentifier(normalized.Query.Source.Schema, semantics.CaseInsensitiveSchemas)
	normalized.Query.Source.Name = canonicalIdentifier(normalized.Query.Source.Name, semantics.CaseInsensitiveObjects)
	fields := make(map[string]int, len(normalized.Query.Projection))
	outputs := make(map[string]struct{}, len(normalized.Query.Projection))
	for index := range normalized.Query.Projection {
		selection := &normalized.Query.Projection[index]
		selection.Field = canonicalIdentifier(selection.Field, semantics.CaseInsensitiveFields)
		selection.Alias = canonicalIdentifier(selection.Alias, true)
		fields[selection.Field]++
		output := selection.Field
		if selection.Alias != "" {
			output = selection.Alias
		}
		if _, duplicate := outputs[output]; duplicate {
			return ValidatedKeyset{}, validationError("query.projection", "contains normalized output collisions")
		}
		outputs[output] = struct{}{}
	}
	if normalized.Query.Filter != nil {
		filter, err := normalizeAggregateFilter(*normalized.Query.Filter, semantics.CaseInsensitiveFields)
		if err != nil {
			return ValidatedKeyset{}, err
		}
		normalized.Query.Filter = &filter
	}
	seenOrder := make(map[string]struct{}, len(normalized.Query.OrderBy))
	for index := range normalized.Query.OrderBy {
		order := &normalized.Query.OrderBy[index]
		order.Field = canonicalIdentifier(order.Field, semantics.CaseInsensitiveFields)
		if _, duplicate := seenOrder[order.Field]; duplicate {
			return ValidatedKeyset{}, validationError("query.order_by", "contains normalized field collisions")
		}
		seenOrder[order.Field] = struct{}{}
		for _, selection := range normalized.Query.Projection {
			if selection.Field == order.Field && selection.Representation != order.Representation {
				return ValidatedKeyset{}, validationError("query.order_by", "representation must match projected key")
			}
		}
		if fields[order.Field] != 1 {
			return ValidatedKeyset{}, validationError("query.order_by", "fields must be projected exactly once")
		}
	}
	return ValidatedKeyset{request: normalized, stats: request.stats, valid: true}, nil
}

func KeysetReferencedFields(request NormalizedKeysetRequest) []string {
	fields := make([]string, 0, len(request.Query.Projection)+len(request.Query.OrderBy))
	for _, selection := range request.Query.Projection {
		fields = append(fields, selection.Field)
	}
	if request.Query.Filter != nil {
		collectFilterFields(*request.Query.Filter, &fields)
	}
	for _, order := range request.Query.OrderBy {
		fields = append(fields, order.Field)
	}
	slices.Sort(fields)
	return slices.Compact(fields)
}

func KeysetShapeHash(request NormalizedKeysetRequest) string {
	type cursorShape struct {
		Type string `json:"type"`
	}
	type hashShape struct {
		Shape    string        `json:"shape"`
		Query    KeysetSpec    `json:"query"`
		PageKind string        `json:"page_kind"`
		Cursor   []cursorShape `json:"cursor,omitempty"`
	}
	query := request.Query
	query.Filter = filterWithoutValues(query.Filter)
	shape := hashShape{Shape: request.Shape, Query: query, PageKind: request.Page.Kind}
	for _, value := range request.Page.Cursor {
		shape.Cursor = append(shape.Cursor, cursorShape{Type: value.Type})
	}
	encoded, _ := json.Marshal(shape)
	digest := sha256.Sum256(append([]byte("quordon/keyset-shape/v1\x00"), encoded...))
	return hex.EncodeToString(digest[:])
}

func validateKeysetCursorValue(path string, cursor KeysetCursorValue) error {
	switch cursor.Type {
	case "integer":
		if err := validatePortableInteger(cursor.Value); err != nil {
			return validationError(path+".value", err.Error())
		}
	case "string":
		if !utf8.ValidString(cursor.Value) || utf8.RuneCountInString(cursor.Value) > ProtocolMaxCursorStringRunes {
			return validationError(path+".value", "exceeds the string cursor limit")
		}
	case "bytes":
		decoded, err := base64.StdEncoding.Strict().DecodeString(cursor.Value)
		if err != nil || base64.StdEncoding.EncodeToString(decoded) != cursor.Value || len(decoded) > ProtocolMaxCursorBytes {
			return validationError(path+".value", "must be canonical bounded standard base64")
		}
	case "date":
		if _, ok := ParsePortableDate(cursor.Value); !ok {
			return validationError(path+".value", "must be a canonical finite portable date")
		}
	case "datetime":
		if _, _, ok := ParsePortableDateTime(cursor.Value); !ok {
			return validationError(path+".value", "must be a canonical finite portable wall-clock datetime")
		}
	case "timestamp":
		if _, _, ok := ParsePortableTimestamp(cursor.Value); !ok {
			return validationError(path+".value", "must be a canonical finite portable UTC timestamp")
		}
	default:
		return validationError(path+".type", "contains an unsupported cursor type")
	}
	return nil
}

func validatePortableInteger(value string) error {
	if value == "" || value[0] == '+' || value == "-0" || len(value) > 20 {
		return errors.New("must be a canonical portable integer")
	}
	if value[0] == '-' {
		if len(value) < 2 || value[1] == '0' {
			return errors.New("must be a canonical portable integer")
		}
		if _, err := strconv.ParseInt(value, 10, 64); err != nil {
			return errors.New("is outside the portable integer range")
		}
		return nil
	}
	if len(value) > 1 && value[0] == '0' {
		return errors.New("must be a canonical portable integer")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return errors.New("must be a canonical portable integer")
		}
	}
	if _, err := strconv.ParseUint(value, 10, 64); err != nil {
		return errors.New("is outside the portable integer range")
	}
	return nil
}

func keysetCursorParameterCount(width int) int {
	return width * (width + 1) / 2
}

func cloneKeysetCursor(values []KeysetCursorValue) []KeysetCursorValue {
	return slices.Clone(values)
}

func cloneKeysetRequest(request KeysetRequest) KeysetRequest {
	request.Query.Projection = slices.Clone(request.Query.Projection)
	request.Query.Filter = cloneFilter(request.Query.Filter)
	request.Query.OrderBy = slices.Clone(request.Query.OrderBy)
	request.Page.Cursor = cloneKeysetCursor(request.Page.Cursor)
	return request
}

func cloneNormalizedKeysetRequest(request NormalizedKeysetRequest) NormalizedKeysetRequest {
	request.Query.Projection = slices.Clone(request.Query.Projection)
	request.Query.Filter = cloneFilter(request.Query.Filter)
	request.Query.OrderBy = slices.Clone(request.Query.OrderBy)
	request.Page.Cursor = cloneKeysetCursor(request.Page.Cursor)
	return request
}

func filterWithoutValues(filter *Filter) *Filter {
	if filter == nil {
		return nil
	}
	result := *filter
	if result.Kind == "predicate" {
		result.Values = make([]TypedValue, len(filter.Values))
		for index, value := range filter.Values {
			result.Values[index] = TypedValue{Type: value.Type, Value: json.RawMessage("null")}
		}
		return &result
	}
	result.Expressions = make([]Filter, len(filter.Expressions))
	for index := range filter.Expressions {
		result.Expressions[index] = *filterWithoutValues(&filter.Expressions[index])
	}
	return &result
}

func collectFilterFields(filter Filter, fields *[]string) {
	if filter.Kind == "predicate" {
		*fields = append(*fields, filter.Field)
		return
	}
	for _, child := range filter.Expressions {
		collectFilterFields(child, fields)
	}
}

func filtersEqualShape(left, right *Filter) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	leftDigest := AggregateFilterShapeDigest(*left)
	rightDigest := AggregateFilterShapeDigest(*right)
	return bytes.Equal(leftDigest[:], rightDigest[:])
}

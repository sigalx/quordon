package queryspec

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math/big"
	"slices"
	"strconv"
	"strings"

	"github.com/sigalx/quordon/internal/domain"
)

const (
	AggregateModeScalar  = "scalar"
	AggregateModeGrouped = "grouped"
)

type AggregateRequest struct {
	Profile    string        `json:"profile"`
	Datasource string        `json:"datasource"`
	Query      AggregateSpec `json:"query"`
}

type AggregateSpec struct {
	Mode       string            `json:"mode"`
	Source     ResourceRef       `json:"source"`
	Projection []AggregateOutput `json:"projection"`
	Filter     *Filter           `json:"filter,omitempty"`
	OrderBy    []AggregateSort   `json:"order_by,omitempty"`
	Limit      *int              `json:"limit,omitempty"`
}

type AggregateOutput struct {
	Representation Representation `json:"representation,omitempty"`
	Kind           string         `json:"kind"`
	Field          string         `json:"field,omitempty"`
	Function       string         `json:"function,omitempty"`
	Alias          string         `json:"alias,omitempty"`
	Unit           string         `json:"unit,omitempty"`
	Timezone       string         `json:"timezone,omitempty"`
}

type AggregateSort struct {
	Representation Representation `json:"representation,omitempty"`
	Kind           string         `json:"kind"`
	Field          string         `json:"field,omitempty"`
	Alias          string         `json:"alias,omitempty"`
	Direction      string         `json:"direction"`
}

type NormalizedAggregateSpec struct {
	Mode       string
	Source     ResourceRef
	Projection []AggregateOutput
	Filter     *Filter
	OrderBy    []AggregateSort
	Limit      int
}

type ValidatedAggregate struct {
	spec  NormalizedAggregateSpec
	stats Stats
	valid bool
}

func (v ValidatedAggregate) Spec() NormalizedAggregateSpec { return cloneNormalizedAggregate(v.spec) }
func (v ValidatedAggregate) Stats() Stats                  { return v.stats }
func (v ValidatedAggregate) Valid() bool                   { return v.valid }

func ValidateAggregate(
	spec AggregateSpec,
	maxProjection, maxGroupBy, maxOrderBy, maxPredicates, maxDepth, maxParameters, maxRows int,
) (ValidatedAggregate, error) {
	return validateAggregate(
		spec, maxProjection, maxGroupBy, maxOrderBy, maxPredicates, maxDepth, maxParameters, maxRows, true,
	)
}

func validateAggregate(
	spec AggregateSpec,
	maxProjection, maxGroupBy, maxOrderBy, maxPredicates, maxDepth, maxParameters, maxRows int,
	checkOutputSemantics bool,
) (ValidatedAggregate, error) {
	if err := validateIdentifier("query.source.schema", spec.Source.Schema); err != nil {
		return ValidatedAggregate{}, err
	}
	if err := validateIdentifier("query.source.name", spec.Source.Name); err != nil {
		return ValidatedAggregate{}, err
	}
	if spec.Mode != AggregateModeScalar && spec.Mode != AggregateModeGrouped {
		return ValidatedAggregate{}, validationError("query.mode", "must be scalar or grouped")
	}
	if len(spec.Projection) == 0 {
		return ValidatedAggregate{}, validationError("query.projection", "must contain at least one output")
	}
	if len(spec.Projection) > ProtocolMaxProjectionFields {
		return ValidatedAggregate{}, validationError("query.projection", "exceeds the protocol projection limit")
	}
	if len(spec.Projection) > maxProjection {
		return ValidatedAggregate{}, validationError("query.projection", "exceeds the effective projection limit")
	}

	dimensions := 0
	measures := 0
	outputNames := make(map[string]struct{}, len(spec.Projection))
	timeBucketFields := make(map[string]struct{})
	for index, output := range spec.Projection {
		if err := validateAggregateOutput(fmt.Sprintf("query.projection[%d]", index), spec.Mode, output); err != nil {
			return ValidatedAggregate{}, err
		}
		if output.Kind == "dimension" || output.Kind == "time_bucket" || output.Kind == "numeric_bucket" {
			dimensions++
		} else {
			measures++
		}
		if checkOutputSemantics && output.Kind == "time_bucket" {
			if _, duplicate := timeBucketFields[output.Field]; duplicate {
				return ValidatedAggregate{}, validationError("query.projection", "contains repeated time-bucket source fields")
			}
			timeBucketFields[output.Field] = struct{}{}
		}
		if checkOutputSemantics {
			outputName := output.Field
			if output.Kind == "measure" || output.Kind == "time_bucket" || output.Kind == "numeric_bucket" {
				outputName = output.Alias
			}
			outputName = strings.ToLower(outputName)
			if _, duplicate := outputNames[outputName]; duplicate {
				return ValidatedAggregate{}, validationError("query.projection", "contains colliding output names")
			}
			outputNames[outputName] = struct{}{}
		}
	}
	if spec.Mode == AggregateModeScalar && dimensions != 0 {
		return ValidatedAggregate{}, validationError("query.projection", "scalar mode accepts only measures")
	}
	if spec.Mode == AggregateModeGrouped && (dimensions == 0 || measures == 0) {
		return ValidatedAggregate{}, validationError("query.projection", "grouped mode requires at least one dimension and one measure")
	}
	if dimensions > maxGroupBy {
		return ValidatedAggregate{}, validationError("query.projection", "exceeds the effective group-by limit")
	}

	stats := Stats{}
	if spec.Mode == AggregateModeGrouped {
		stats.Parameters = 1 // The server-owned group prefix LIMIT is bound.
	}
	if stats.Parameters > maxParameters {
		return ValidatedAggregate{}, validationError("query", "exceeds the effective parameter limit")
	}
	if spec.Filter != nil {
		limits := filterValidationLimits{
			maxPredicates: maxPredicates,
			maxDepth:      maxDepth,
			maxParameters: maxParameters,
		}
		if err := validateFilter("query.filter", *spec.Filter, 1, &stats, limits); err != nil {
			return ValidatedAggregate{}, err
		}
	}

	if len(spec.OrderBy) > ProtocolMaxOrderByFields {
		return ValidatedAggregate{}, validationError("query.order_by", "exceeds the protocol order-by limit")
	}
	if len(spec.OrderBy) > maxOrderBy {
		return ValidatedAggregate{}, validationError("query.order_by", "exceeds the effective order-by limit")
	}
	if spec.Mode == AggregateModeScalar && spec.OrderBy != nil {
		return ValidatedAggregate{}, validationError("query.order_by", "is not supported in scalar mode")
	}
	seenNumericOrder := make(map[string]struct{})
	for index, order := range spec.OrderBy {
		path := fmt.Sprintf("query.order_by[%d]", index)
		if err := validateRepresentation(path, order.Representation); err != nil {
			return ValidatedAggregate{}, err
		}
		if order.Kind != "dimension" && order.Representation != "" {
			return ValidatedAggregate{}, validationError(path, "representation requires dimension order")
		}
		if order.Direction != "asc" && order.Direction != "desc" {
			return ValidatedAggregate{}, validationError(path+".direction", "must be asc or desc")
		}
		switch order.Kind {
		case "dimension":
			if order.Alias != "" {
				return ValidatedAggregate{}, validationError(path+".alias", "is not valid for dimension order")
			}
			if err := validateIdentifier(path+".field", order.Field); err != nil {
				return ValidatedAggregate{}, err
			}
			if checkOutputSemantics {
				// Identifier semantics can change field matching, but cannot
				// make mismatched representations compatible. Reject when no
				// potentially matching dimension has this representation.
				potential, compatible := false, false
				for _, output := range spec.Projection {
					if output.Kind == "dimension" && strings.EqualFold(output.Field, order.Field) {
						potential = true
						compatible = compatible || output.Representation == order.Representation
					}
				}
				if potential && !compatible {
					return ValidatedAggregate{}, validationError(path+".representation", "must match the projected dimension")
				}
			}
		case "measure":
			if order.Field != "" {
				return ValidatedAggregate{}, validationError(path+".field", "is not valid for measure order")
			}
			if err := validateIdentifier(path+".alias", order.Alias); err != nil {
				return ValidatedAggregate{}, err
			}
		case "time_bucket", "numeric_bucket":
			if order.Field != "" {
				return ValidatedAggregate{}, validationError(path+".field", "is not valid for bucket order")
			}
			if err := validateIdentifier(path+".alias", order.Alias); err != nil {
				return ValidatedAggregate{}, err
			}
			if checkOutputSemantics && order.Kind == "numeric_bucket" {
				projected := false
				for _, output := range spec.Projection {
					projected = projected || output.Kind == "numeric_bucket" && strings.EqualFold(output.Alias, order.Alias)
				}
				if !projected {
					return ValidatedAggregate{}, validationError(path+".alias", "must reference one projected numeric bucket")
				}
				alias := strings.ToLower(order.Alias)
				if _, duplicate := seenNumericOrder[alias]; duplicate {
					return ValidatedAggregate{}, validationError("query.order_by", "contains repeated numeric bucket targets")
				}
				seenNumericOrder[alias] = struct{}{}
			}
		default:
			return ValidatedAggregate{}, validationError(path+".kind", "must be dimension, time_bucket, numeric_bucket, or measure")
		}
	}

	limit := 0
	if spec.Mode == AggregateModeScalar {
		if spec.Limit != nil {
			return ValidatedAggregate{}, validationError("query.limit", "is not supported in scalar mode")
		}
	} else {
		if spec.Limit == nil {
			return ValidatedAggregate{}, validationError("query.limit", "is required in grouped mode")
		}
		limit = *spec.Limit
		if limit < 1 || limit > ProtocolMaxRows {
			return ValidatedAggregate{}, validationError("query.limit", fmt.Sprintf("must be between 1 and %d", ProtocolMaxRows))
		}
		if limit > maxRows {
			return ValidatedAggregate{}, validationError("query.limit", "exceeds the effective row limit")
		}
	}

	normalized := NormalizedAggregateSpec{
		Mode: spec.Mode, Source: spec.Source,
		Projection: append([]AggregateOutput(nil), spec.Projection...),
		Filter:     cloneFilter(spec.Filter), OrderBy: append([]AggregateSort(nil), spec.OrderBy...), Limit: limit,
	}
	return ValidatedAggregate{spec: normalized, stats: stats, valid: true}, nil
}

func RevalidateAggregate(
	query ValidatedAggregate,
	maxProjection, maxGroupBy, maxOrderBy, maxPredicates, maxDepth, maxParameters, maxRows int,
) (ValidatedAggregate, error) {
	if !query.valid {
		return ValidatedAggregate{}, validationError("query", "has not been validated")
	}
	if len(query.spec.Projection) > maxProjection {
		return ValidatedAggregate{}, validationError("query.projection", "exceeds the effective projection limit")
	}
	if len(query.spec.OrderBy) > maxOrderBy {
		return ValidatedAggregate{}, validationError("query.order_by", "exceeds the effective order-by limit")
	}
	dimensions := 0
	for _, output := range query.spec.Projection {
		if output.Kind == "dimension" || output.Kind == "time_bucket" || output.Kind == "numeric_bucket" {
			dimensions++
		}
	}
	if dimensions > maxGroupBy {
		return ValidatedAggregate{}, validationError("query.projection", "exceeds the effective group-by limit")
	}
	if query.stats.Predicates > maxPredicates {
		return ValidatedAggregate{}, validationError("query.filter", "exceeds the effective predicate limit")
	}
	if query.stats.ExpressionDepth > maxDepth {
		return ValidatedAggregate{}, validationError("query.filter", "exceeds the effective expression depth limit")
	}
	if query.stats.Parameters > maxParameters {
		return ValidatedAggregate{}, validationError("query.filter", "exceeds the effective parameter limit")
	}
	if query.spec.Mode == AggregateModeGrouped && query.spec.Limit > maxRows {
		return ValidatedAggregate{}, validationError("query.limit", "exceeds the effective row limit")
	}
	return ValidatedAggregate{spec: cloneNormalizedAggregate(query.spec), stats: query.stats, valid: true}, nil
}

func NormalizeAggregateIdentifiers(
	query ValidatedAggregate, semantics domain.IdentifierSemantics,
) (ValidatedAggregate, error) {
	if !query.valid {
		return ValidatedAggregate{}, validationError("query", "has not been validated")
	}
	normalized := cloneNormalizedAggregate(query.spec)
	normalized.Source.Schema = canonicalIdentifier(normalized.Source.Schema, semantics.CaseInsensitiveSchemas)
	normalized.Source.Name = canonicalIdentifier(normalized.Source.Name, semantics.CaseInsensitiveObjects)
	outputNames := make(map[string]struct{}, len(normalized.Projection))
	dimensions := make(map[string]Representation)
	measures := make(map[string]struct{})
	timeBuckets := make(map[string]struct{})
	numericBuckets := make(map[string]struct{})
	timeBucketFields := make(map[string]struct{})
	for index := range normalized.Projection {
		output := &normalized.Projection[index]
		output.Field = canonicalIdentifier(output.Field, semantics.CaseInsensitiveFields)
		output.Alias = canonicalIdentifier(output.Alias, true)
		name := output.Field
		if output.Kind == "measure" {
			name = output.Alias
			measures[name] = struct{}{}
		} else if output.Kind == "numeric_bucket" {
			name = output.Alias
			numericBuckets[name] = struct{}{}
		} else if output.Kind == "time_bucket" {
			name = output.Alias
			timeBuckets[name] = struct{}{}
			if _, duplicate := timeBucketFields[output.Field]; duplicate {
				return ValidatedAggregate{}, validationError("query.projection", "contains repeated normalized time-bucket source fields")
			}
			timeBucketFields[output.Field] = struct{}{}
		} else {
			dimensions[name] = output.Representation
		}
		if _, duplicate := outputNames[name]; duplicate {
			return ValidatedAggregate{}, validationError("query.projection", "contains colliding output names")
		}
		outputNames[name] = struct{}{}
	}
	if normalized.Filter != nil {
		filter, err := normalizeAggregateFilter(*normalized.Filter, semantics.CaseInsensitiveFields)
		if err != nil {
			return ValidatedAggregate{}, err
		}
		normalized.Filter = &filter
	}
	seenOrder := make(map[string]struct{}, len(normalized.OrderBy))
	for index := range normalized.OrderBy {
		order := &normalized.OrderBy[index]
		var target string
		if order.Kind == "dimension" {
			order.Field = canonicalIdentifier(order.Field, semantics.CaseInsensitiveFields)
			target = "dimension:" + order.Field
			if representation, ok := dimensions[order.Field]; !ok || representation != order.Representation {
				return ValidatedAggregate{}, validationError(fmt.Sprintf("query.order_by[%d].field", index), "must reference one projected dimension")
			}
		} else if order.Kind == "measure" {
			order.Alias = canonicalIdentifier(order.Alias, true)
			target = "measure:" + order.Alias
			if _, ok := measures[order.Alias]; !ok {
				return ValidatedAggregate{}, validationError(fmt.Sprintf("query.order_by[%d].alias", index), "must reference one projected measure")
			}
		} else if order.Kind == "numeric_bucket" {
			order.Alias = canonicalIdentifier(order.Alias, true)
			target = "numeric_bucket:" + order.Alias
			if _, ok := numericBuckets[order.Alias]; !ok {
				return ValidatedAggregate{}, validationError(fmt.Sprintf("query.order_by[%d].alias", index), "must reference one projected numeric bucket")
			}
		} else {
			order.Alias = canonicalIdentifier(order.Alias, true)
			target = "time_bucket:" + order.Alias
			if _, ok := timeBuckets[order.Alias]; !ok {
				return ValidatedAggregate{}, validationError(fmt.Sprintf("query.order_by[%d].alias", index), "must reference one projected time bucket")
			}
		}
		if _, duplicate := seenOrder[target]; duplicate {
			return ValidatedAggregate{}, validationError("query.order_by", "contains repeated normalized targets")
		}
		seenOrder[target] = struct{}{}
	}
	return ValidatedAggregate{spec: normalized, stats: query.stats, valid: true}, nil
}

func validateAggregateOutput(path, mode string, output AggregateOutput) error {
	if err := validateRepresentation(path, output.Representation); err != nil {
		return err
	}
	if output.Kind != "dimension" && output.Representation != "" {
		return validationError(path, "representation requires a dimension")
	}
	switch output.Kind {
	case "dimension":
		if mode != AggregateModeGrouped {
			return validationError(path+".kind", "dimension is supported only in grouped mode")
		}
		if output.Function != "" || output.Alias != "" || output.Unit != "" || output.Timezone != "" {
			return validationError(path, "dimension accepts only kind and field")
		}
		return validateIdentifier(path+".field", output.Field)
	case "numeric_bucket":
		if mode != AggregateModeGrouped || output.Function != "" || output.Unit != "" || output.Timezone != "" {
			return validationError(path, "numeric_bucket requires grouped mode, field, and alias only")
		}
		if err := validateIdentifier(path+".field", output.Field); err != nil {
			return err
		}
		return validateIdentifier(path+".alias", output.Alias)
	case "time_bucket":
		if mode != AggregateModeGrouped {
			return validationError(path+".kind", "time_bucket is supported only in grouped mode")
		}
		if output.Function != "" {
			return validationError(path+".function", "is not valid for time_bucket")
		}
		if err := validateIdentifier(path+".field", output.Field); err != nil {
			return err
		}
		if err := validateIdentifier(path+".alias", output.Alias); err != nil {
			return err
		}
		if !slices.Contains([]string{"hour", "day", "week", "month"}, output.Unit) {
			return validationError(path+".unit", "must be hour, day, week, or month")
		}
		if output.Timezone != "UTC" {
			return validationError(path+".timezone", "must be UTC")
		}
		return nil
	case "measure":
		if output.Unit != "" || output.Timezone != "" {
			return validationError(path, "measure does not accept unit or timezone")
		}
		if err := validateIdentifier(path+".alias", output.Alias); err != nil {
			return err
		}
		switch output.Function {
		case "count_all":
			if output.Field != "" {
				return validationError(path+".field", "count_all must not contain field")
			}
		case "count", "count_distinct", "min", "max", "sum", "avg":
			if err := validateIdentifier(path+".field", output.Field); err != nil {
				return err
			}
		default:
			return validationError(path+".function", "contains an unsupported aggregate")
		}
		return nil
	default:
		return validationError(path+".kind", "must be dimension, time_bucket, numeric_bucket, or measure")
	}
}

func normalizeAggregateFilter(filter Filter, caseInsensitiveFields bool) (Filter, error) {
	result, _, _, err := normalizeAggregateFilterNode(filter, caseInsensitiveFields)
	return result, err
}

type AggregateFilterDigest [sha256.Size]byte

func normalizeAggregateFilterNode(
	filter Filter, caseInsensitiveFields bool,
) (Filter, AggregateFilterDigest, AggregateFilterDigest, error) {
	result := filter
	if filter.Values != nil {
		result.Values = cloneTypedValues(filter.Values)
	}
	result.Expressions = nil
	if result.Kind == "predicate" {
		result.Field = canonicalIdentifier(result.Field, caseInsensitiveFields)
		shapeKey, valueKey, err := aggregatePredicateDigests(result)
		return result, shapeKey, valueKey, err
	}
	type normalizedExpression struct {
		filter   Filter
		shapeKey AggregateFilterDigest
		valueKey AggregateFilterDigest
	}
	expressions := make([]normalizedExpression, len(filter.Expressions))
	for index := range filter.Expressions {
		normalized, shapeKey, valueKey, err := normalizeAggregateFilterNode(
			filter.Expressions[index], caseInsensitiveFields,
		)
		if err != nil {
			return Filter{}, AggregateFilterDigest{}, AggregateFilterDigest{}, err
		}
		expressions[index] = normalizedExpression{
			filter:   normalized,
			shapeKey: shapeKey,
			valueKey: valueKey,
		}
	}
	slices.SortFunc(expressions, func(a, b normalizedExpression) int {
		if comparison := bytes.Compare(a.shapeKey[:], b.shapeKey[:]); comparison != 0 {
			return comparison
		}
		return bytes.Compare(a.valueKey[:], b.valueKey[:])
	})
	normalizedFilters := make([]Filter, len(expressions))
	shapeChildren := make([]AggregateFilterDigest, len(expressions))
	valueChildren := make([]AggregateFilterDigest, len(expressions))
	var previous AggregateFilterDigest
	for index, expression := range expressions {
		if index != 0 && expression.valueKey == previous {
			return Filter{}, AggregateFilterDigest{}, AggregateFilterDigest{}, validationError(
				"query.filter", "contains duplicate normalized expressions",
			)
		}
		previous = expression.valueKey
		normalizedFilters[index] = expression.filter
		shapeChildren[index] = expression.shapeKey
		valueChildren[index] = expression.valueKey
	}
	result.Expressions = normalizedFilters
	return result,
		aggregateGroupDigest("quordon/aggregate-filter-shape/v1", result, shapeChildren),
		aggregateGroupDigest("quordon/aggregate-filter-value/v1", result, valueChildren),
		nil
}

func aggregatePredicateDigests(filter Filter) (AggregateFilterDigest, AggregateFilterDigest, error) {
	shapeKey := AggregateFilterShapeDigest(filter)

	valueHash := sha256.New()
	writeFilterDigestString(valueHash, "quordon/aggregate-filter-value/v1")
	writeFilterDigestBytes(valueHash, shapeKey[:])
	for _, item := range filter.Values {
		bound, err := item.BindValue()
		if err != nil {
			return AggregateFilterDigest{}, AggregateFilterDigest{}, validationError("query.filter", err.Error())
		}
		if err := writeAggregateBoundValueDigest(valueHash, bound); err != nil {
			return AggregateFilterDigest{}, AggregateFilterDigest{}, validationError("query.filter", err.Error())
		}
	}
	return shapeKey, finishFilterDigest(valueHash), nil
}

func AggregateFilterShapeDigest(filter Filter) AggregateFilterDigest {
	if filter.Kind != "predicate" {
		children := make([]AggregateFilterDigest, len(filter.Expressions))
		for index, child := range filter.Expressions {
			children[index] = AggregateFilterShapeDigest(child)
		}
		slices.SortFunc(children, func(a, b AggregateFilterDigest) int {
			return bytes.Compare(a[:], b[:])
		})
		return aggregateGroupDigest("quordon/aggregate-filter-shape/v1", filter, children)
	}
	shapeHash := sha256.New()
	writeFilterDigestString(shapeHash, "quordon/aggregate-filter-shape/v1")
	writeFilterDigestString(shapeHash, filter.Kind)
	writeFilterDigestString(shapeHash, filter.Field)
	writeFilterDigestString(shapeHash, string(filter.Representation))
	writeFilterDigestString(shapeHash, filter.Operator)
	writeFilterDigestUint64(shapeHash, uint64(len(filter.Values)))
	for _, item := range filter.Values {
		writeFilterDigestString(shapeHash, item.Type)
	}
	return finishFilterDigest(shapeHash)
}

func aggregateGroupDigest(
	domain string, filter Filter, children []AggregateFilterDigest,
) AggregateFilterDigest {
	digest := sha256.New()
	writeFilterDigestString(digest, domain)
	writeFilterDigestString(digest, filter.Kind)
	writeFilterDigestString(digest, filter.Operator)
	writeFilterDigestUint64(digest, uint64(len(children)))
	for _, child := range children {
		writeFilterDigestBytes(digest, child[:])
	}
	return finishFilterDigest(digest)
}

func writeAggregateBoundValueDigest(digest hash.Hash, value any) error {
	switch typed := value.(type) {
	case bool:
		writeFilterDigestString(digest, "boolean")
		if typed {
			writeFilterDigestBytes(digest, []byte{1})
		} else {
			writeFilterDigestBytes(digest, []byte{0})
		}
	case int64:
		writeFilterDigestString(digest, "integer")
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], uint64(typed))
		writeFilterDigestBytes(digest, encoded[:])
	case string:
		writeFilterDigestString(digest, "string")
		writeFilterDigestString(digest, typed)
	case []byte:
		writeFilterDigestString(digest, "bytes")
		writeFilterDigestBytes(digest, typed)
	default:
		return fmt.Errorf("contains unsupported normalized bind type %T", value)
	}
	return nil
}

func writeFilterDigestString(digest hash.Hash, value string) {
	writeFilterDigestUint64(digest, uint64(len(value)))
	_, _ = io.WriteString(digest, value)
}

func writeFilterDigestBytes(digest hash.Hash, value []byte) {
	writeFilterDigestUint64(digest, uint64(len(value)))
	_, _ = digest.Write(value)
}

func writeFilterDigestUint64(digest hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = digest.Write(encoded[:])
}

func finishFilterDigest(digest hash.Hash) AggregateFilterDigest {
	var result AggregateFilterDigest
	digest.Sum(result[:0])
	return result
}

func exactAggregateFilterDigest(filter Filter) (AggregateFilterDigest, error) {
	if filter.Kind == "predicate" {
		digest := sha256.New()
		writeFilterDigestString(digest, "quordon/aggregate-filter-exact/v1")
		writeFilterDigestString(digest, filter.Kind)
		writeFilterDigestString(digest, filter.Field)
		writeFilterDigestString(digest, filter.Operator)
		writeFilterDigestUint64(digest, uint64(len(filter.Values)))
		for _, item := range filter.Values {
			writeFilterDigestString(digest, item.Type)
			writeFilterDigestString(digest, canonicalJSONScalar(item.Value))
		}
		return finishFilterDigest(digest), nil
	}
	children := make([]AggregateFilterDigest, len(filter.Expressions))
	seen := make(map[AggregateFilterDigest]struct{}, len(filter.Expressions))
	for index, child := range filter.Expressions {
		childDigest, err := exactAggregateFilterDigest(child)
		if err != nil {
			return AggregateFilterDigest{}, err
		}
		if _, duplicate := seen[childDigest]; duplicate {
			return AggregateFilterDigest{}, fmt.Errorf("query.filter contains duplicate expressions")
		}
		seen[childDigest] = struct{}{}
		children[index] = childDigest
	}
	return aggregateGroupDigest("quordon/aggregate-filter-exact/v1", filter, children), nil
}

func canonicalJSONScalar(raw json.RawMessage) string {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return "invalid:"
	}
	switch text[0] {
	case '"':
		var value string
		if json.Unmarshal(raw, &value) == nil {
			encoded, _ := json.Marshal(value)
			return "string:" + string(encoded)
		}
	case 't', 'f':
		var value bool
		if json.Unmarshal(raw, &value) == nil {
			return "boolean:" + strconv.FormatBool(value)
		}
	case 'n':
		if text == "null" {
			return "null"
		}
	default:
		if number, ok := canonicalJSONNumber(text); ok {
			return "number:" + number
		}
	}
	return "invalid:" + text
}

func canonicalJSONNumber(text string) (string, bool) {
	negative := strings.HasPrefix(text, "-")
	if negative {
		text = text[1:]
	}
	mantissa, exponentText, hasExponent := strings.Cut(text, "e")
	if !hasExponent {
		mantissa, exponentText, hasExponent = strings.Cut(text, "E")
	}
	exponent := new(big.Int)
	if hasExponent {
		if _, ok := exponent.SetString(exponentText, 10); !ok {
			return "", false
		}
	}
	integer, fraction, hasFraction := strings.Cut(mantissa, ".")
	digits := integer
	if hasFraction {
		digits += fraction
	}
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return "0", true
	}
	power := new(big.Int).Sub(exponent, new(big.Int).SetUint64(uint64(len(fraction))))
	one := big.NewInt(1)
	for len(digits) > 1 && digits[len(digits)-1] == '0' {
		digits = digits[:len(digits)-1]
		power.Add(power, one)
	}
	if negative {
		digits = "-" + digits
	}
	return digits + "e" + power.String(), true
}

func canonicalIdentifier(value string, insensitive bool) string {
	if insensitive {
		return strings.ToLower(value)
	}
	return value
}

func AggregateShapeHash(spec NormalizedAggregateSpec) string {
	type shape struct {
		Mode       string            `json:"mode"`
		Source     ResourceRef       `json:"source"`
		Projection []AggregateOutput `json:"projection"`
		Filter     *filterShape      `json:"filter,omitempty"`
		OrderBy    []AggregateSort   `json:"order_by,omitempty"`
		Limit      int               `json:"limit,omitempty"`
	}
	encoded, err := json.Marshal(shape{
		Mode: spec.Mode, Source: spec.Source, Projection: spec.Projection,
		Filter: shapeFilter(spec.Filter), OrderBy: spec.OrderBy, Limit: spec.Limit,
	})
	if err != nil {
		panic("queryspec: marshal aggregate shape: " + err.Error())
	}
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:])
}

func AggregateReferencedFields(spec NormalizedAggregateSpec) []string {
	seen := make(map[string]struct{})
	for _, output := range spec.Projection {
		if output.Field != "" {
			seen[output.Field] = struct{}{}
		}
	}
	if spec.Filter != nil {
		collectAggregateFilterFields(*spec.Filter, func(field string) { seen[field] = struct{}{} })
	}
	fields := make([]string, 0, len(seen))
	for field := range seen {
		fields = append(fields, field)
	}
	slices.Sort(fields)
	return fields
}

func AggregateUsesTimeBucket(spec NormalizedAggregateSpec) bool {
	for _, output := range spec.Projection {
		if output.Kind == "time_bucket" {
			return true
		}
	}
	return false
}

func collectAggregateFilterFields(filter Filter, add func(string)) {
	if filter.Kind == "predicate" {
		add(filter.Field)
		return
	}
	for _, expression := range filter.Expressions {
		collectAggregateFilterFields(expression, add)
	}
}

func cloneNormalizedAggregate(spec NormalizedAggregateSpec) NormalizedAggregateSpec {
	return NormalizedAggregateSpec{
		Mode: spec.Mode, Source: spec.Source,
		Projection: append([]AggregateOutput(nil), spec.Projection...),
		Filter:     cloneFilter(spec.Filter), OrderBy: append([]AggregateSort(nil), spec.OrderBy...), Limit: spec.Limit,
	}
}

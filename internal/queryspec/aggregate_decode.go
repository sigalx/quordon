package queryspec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

type aggregateRequestWire struct {
	Profile    wireString         `json:"profile"`
	Datasource wireString         `json:"datasource"`
	Query      *aggregateSpecWire `json:"query"`
}

type aggregateSpecWire struct {
	Mode       wireString             `json:"mode"`
	Source     *resourceWire          `json:"source"`
	Projection *[]aggregateOutputWire `json:"projection"`
	Filter     *filterWire            `json:"filter,omitempty"`
	OrderBy    *[]aggregateSortWire   `json:"order_by,omitempty"`
	Limit      wireInt                `json:"limit,omitempty"`
}

type aggregateOutputWire struct {
	Representation wireString `json:"representation,omitempty"`
	Kind           wireString `json:"kind"`
	Field          wireString `json:"field,omitempty"`
	Function       wireString `json:"function,omitempty"`
	Alias          wireString `json:"alias,omitempty"`
	Unit           wireString `json:"unit,omitempty"`
	Timezone       wireString `json:"timezone,omitempty"`
}

type aggregateSortWire struct {
	Representation wireString `json:"representation,omitempty"`
	Kind           wireString `json:"kind"`
	Field          wireString `json:"field,omitempty"`
	Alias          wireString `json:"alias,omitempty"`
	Direction      wireString `json:"direction"`
}

func DecodeStrictAggregate(
	data []byte, maxFilterDepth, maxPredicates, maxParameters int,
) (AggregateRequest, error) {
	if !utf8.Valid(data) {
		return AggregateRequest{}, errors.New("request body must be valid UTF-8")
	}
	if err := scanAggregateRequestShape(data, maxFilterDepth, maxPredicates, maxParameters); err != nil {
		return AggregateRequest{}, err
	}
	var wire *aggregateRequestWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return AggregateRequest{}, err
	}
	if wire == nil {
		return AggregateRequest{}, errors.New("request body must contain a JSON object")
	}
	if !wire.Profile.Set {
		return AggregateRequest{}, errors.New("profile is required")
	}
	if wire.Profile.Value == "" {
		return AggregateRequest{}, errors.New("profile must not be empty")
	}
	if !wire.Datasource.Set || wire.Datasource.Value == "" {
		return AggregateRequest{}, errors.New("datasource is required and must not be empty")
	}
	if wire.Query == nil {
		return AggregateRequest{}, errors.New("query is required")
	}
	query, err := wire.Query.decode(maxFilterDepth)
	if err != nil {
		return AggregateRequest{}, err
	}
	if _, err := validateAggregate(
		query, ProtocolMaxProjectionFields, ProtocolMaxGroupByFields, ProtocolMaxOrderByFields,
		maxPredicates, maxFilterDepth, maxParameters, ProtocolMaxRows, false,
	); err != nil {
		return AggregateRequest{}, err
	}
	return AggregateRequest{Profile: wire.Profile.Value, Datasource: wire.Datasource.Value, Query: query}, nil
}

func (w aggregateSpecWire) decode(maxFilterDepth int) (AggregateSpec, error) {
	if !w.Mode.Set {
		return AggregateSpec{}, errors.New("query.mode is required")
	}
	if w.Source == nil {
		return AggregateSpec{}, errors.New("query.source is required")
	}
	source, err := w.Source.decode()
	if err != nil {
		return AggregateSpec{}, err
	}
	if w.Projection == nil {
		return AggregateSpec{}, errors.New("query.projection is required")
	}
	if len(*w.Projection) == 0 {
		return AggregateSpec{}, errors.New("query.projection must not be empty")
	}
	if len(*w.Projection) > ProtocolMaxProjectionFields {
		return AggregateSpec{}, errors.New("query.projection exceeds the protocol projection limit")
	}
	result := AggregateSpec{
		Mode: w.Mode.Value, Source: source,
		Projection: make([]AggregateOutput, len(*w.Projection)),
	}
	seenProjection := make(map[string]struct{}, len(*w.Projection))
	for index, output := range *w.Projection {
		decoded, err := output.decode()
		if err != nil {
			return AggregateSpec{}, fmt.Errorf("query.projection[%d]: %w", index, err)
		}
		key := aggregateOutputKey(decoded)
		if _, duplicate := seenProjection[key]; duplicate {
			return AggregateSpec{}, errors.New("query.projection contains duplicate outputs")
		}
		seenProjection[key] = struct{}{}
		result.Projection[index] = decoded
	}
	if w.Filter != nil {
		filter, err := w.Filter.decode(1, maxFilterDepth)
		if err != nil {
			return AggregateSpec{}, fmt.Errorf("query.filter: %w", err)
		}
		if err := rejectExactFilterDuplicates(filter); err != nil {
			return AggregateSpec{}, err
		}
		result.Filter = &filter
	}
	if w.OrderBy != nil {
		if len(*w.OrderBy) == 0 {
			return AggregateSpec{}, errors.New("query.order_by must not be empty when present")
		}
		if len(*w.OrderBy) > ProtocolMaxOrderByFields {
			return AggregateSpec{}, errors.New("query.order_by exceeds the protocol order-by limit")
		}
		result.OrderBy = make([]AggregateSort, len(*w.OrderBy))
		seenOrder := make(map[string]struct{}, len(*w.OrderBy))
		for index, order := range *w.OrderBy {
			decoded, err := order.decode()
			if err != nil {
				return AggregateSpec{}, fmt.Errorf("query.order_by[%d]: %w", index, err)
			}
			key := aggregateSortKey(decoded)
			if _, duplicate := seenOrder[key]; duplicate {
				return AggregateSpec{}, errors.New("query.order_by contains duplicate terms")
			}
			seenOrder[key] = struct{}{}
			result.OrderBy[index] = decoded
		}
	}
	if w.Limit.Set {
		if w.Limit.Value < 1 || w.Limit.Value > ProtocolMaxRows {
			return AggregateSpec{}, fmt.Errorf("query.limit must be between 1 and %d", ProtocolMaxRows)
		}
		result.Limit = &w.Limit.Value
	}
	switch result.Mode {
	case AggregateModeScalar:
		if w.OrderBy != nil {
			return AggregateSpec{}, errors.New("query.order_by is not allowed in scalar mode")
		}
		if w.Limit.Set {
			return AggregateSpec{}, errors.New("query.limit is not allowed in scalar mode")
		}
	case AggregateModeGrouped:
		if !w.Limit.Set {
			return AggregateSpec{}, errors.New("query.limit is required in grouped mode")
		}
	default:
		return AggregateSpec{}, fmt.Errorf("query.mode %q is not supported", result.Mode)
	}
	return result, nil
}

func (w aggregateOutputWire) decode() (AggregateOutput, error) {
	representation, err := decodeRepresentation(w.Representation, w.Kind.Value == "dimension")
	if err != nil {
		return AggregateOutput{}, err
	}
	if !w.Kind.Set {
		return AggregateOutput{}, errors.New("kind is required")
	}
	for name, value := range map[string]wireString{
		"field": w.Field, "function": w.Function, "alias": w.Alias,
		"unit": w.Unit, "timezone": w.Timezone,
	} {
		if value.Set && value.Value == "" {
			return AggregateOutput{}, fmt.Errorf("%s must not be empty when present", name)
		}
	}
	switch w.Kind.Value {
	case "dimension":
		if !w.Field.Set {
			return AggregateOutput{}, errors.New("dimension requires field")
		}
		if w.Function.Set || w.Alias.Set || w.Unit.Set || w.Timezone.Set {
			return AggregateOutput{}, errors.New("dimension accepts only kind and field")
		}
	case "numeric_bucket":
		if !w.Field.Set || !w.Alias.Set {
			return AggregateOutput{}, errors.New("numeric_bucket requires field and alias")
		}
		if w.Function.Set || w.Unit.Set || w.Timezone.Set {
			return AggregateOutput{}, errors.New("numeric_bucket accepts only kind, field, and alias")
		}
	case "time_bucket":
		if !w.Field.Set || !w.Unit.Set || !w.Timezone.Set || !w.Alias.Set {
			return AggregateOutput{}, errors.New("time_bucket requires field, unit, timezone, and alias")
		}
		if w.Function.Set {
			return AggregateOutput{}, errors.New("time_bucket must not contain function")
		}
	case "measure":
		if w.Unit.Set || w.Timezone.Set {
			return AggregateOutput{}, errors.New("measure must not contain unit or timezone")
		}
		if !w.Function.Set || !w.Alias.Set {
			return AggregateOutput{}, errors.New("measure requires function and alias")
		}
		if w.Function.Value == "count_all" {
			if w.Field.Set {
				return AggregateOutput{}, errors.New("count_all must not contain field")
			}
		} else if !w.Field.Set {
			return AggregateOutput{}, errors.New("field aggregate requires field")
		}
	default:
		return AggregateOutput{}, fmt.Errorf("kind %q is not supported", w.Kind.Value)
	}
	return AggregateOutput{
		Representation: representation, Kind: w.Kind.Value, Field: w.Field.Value, Function: w.Function.Value, Alias: w.Alias.Value,
		Unit: w.Unit.Value, Timezone: w.Timezone.Value,
	}, nil
}

func (w aggregateSortWire) decode() (AggregateSort, error) {
	representation, err := decodeRepresentation(w.Representation, w.Kind.Value == "dimension")
	if err != nil {
		return AggregateSort{}, err
	}
	if !w.Kind.Set || !w.Direction.Set {
		return AggregateSort{}, errors.New("kind and direction are required")
	}
	if w.Field.Set && w.Field.Value == "" {
		return AggregateSort{}, errors.New("field must not be empty when present")
	}
	if w.Alias.Set && w.Alias.Value == "" {
		return AggregateSort{}, errors.New("alias must not be empty when present")
	}
	switch w.Kind.Value {
	case "dimension":
		if !w.Field.Set || w.Alias.Set {
			return AggregateSort{}, errors.New("dimension order requires field and forbids alias")
		}
	case "measure":
		if !w.Alias.Set || w.Field.Set {
			return AggregateSort{}, errors.New("measure order requires alias and forbids field")
		}
	case "time_bucket", "numeric_bucket":
		if !w.Alias.Set || w.Field.Set {
			return AggregateSort{}, errors.New("bucket order requires alias and forbids field")
		}
	default:
		return AggregateSort{}, fmt.Errorf("kind %q is not supported", w.Kind.Value)
	}
	return AggregateSort{
		Representation: representation, Kind: w.Kind.Value, Field: w.Field.Value, Alias: w.Alias.Value, Direction: w.Direction.Value,
	}, nil
}

func rejectExactFilterDuplicates(filter Filter) error {
	_, err := exactAggregateFilterDigest(filter)
	return err
}

func aggregateOutputKey(output AggregateOutput) string {
	encoded, _ := json.Marshal(output)
	return string(encoded)
}

func aggregateSortKey(order AggregateSort) string {
	encoded, _ := json.Marshal(order)
	return string(encoded)
}

func scanAggregateRequestShape(
	data []byte, maxFilterDepth, maxPredicates, maxParameters int,
) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return nil
	}
	seen := make(map[string]struct{}, 3)
	for decoder.More() {
		key, err := nextUniqueObjectKey(decoder, seen)
		if err != nil {
			return err
		}
		switch key {
		case "profile", "datasource":
			err = skipJSONValue(decoder)
		case "query":
			err = scanAggregateQueryShape(
				decoder, maxFilterDepth, newFilterShapeScanBudget(maxPredicates, maxParameters),
			)
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

func scanAggregateQueryShape(
	decoder *json.Decoder, maxFilterDepth int, budget *filterShapeScanBudget,
) error {
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
	seen := make(map[string]struct{}, 6)
	mode := ""
	for decoder.More() {
		key, err := nextUniqueObjectKey(decoder, seen)
		if err != nil {
			return err
		}
		switch key {
		case "mode":
			token, tokenErr := decoder.Token()
			if tokenErr != nil {
				err = tokenErr
				break
			}
			mode, _ = token.(string)
			err = skipJSONToken(decoder, token)
		case "limit":
			err = skipJSONValue(decoder)
		case "source":
			err = scanResourceShape(decoder)
		case "projection":
			err = scanBoundedArray(decoder, ProtocolMaxProjectionFields, "query.projection", func() error {
				return scanAggregateOutputShape(decoder)
			})
		case "filter":
			err = scanFilterShape(decoder, 1, maxFilterDepth, budget)
		case "order_by":
			err = scanBoundedArray(decoder, ProtocolMaxOrderByFields, "query.order_by", func() error {
				return scanAggregateSortShape(decoder)
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
	if mode == AggregateModeGrouped {
		return budget.addServerParameter()
	}
	return nil
}

func scanAggregateOutputShape(decoder *json.Decoder) error {
	return scanObjectShape(decoder, "query.projection item", func(key string) error {
		switch key {
		case "kind", "field", "function", "alias", "unit", "timezone", "representation":
			return skipJSONValue(decoder)
		default:
			return unknownJSONField(key)
		}
	})
}

func scanAggregateSortShape(decoder *json.Decoder) error {
	return scanObjectShape(decoder, "query.order_by item", func(key string) error {
		switch key {
		case "kind", "field", "alias", "direction", "representation":
			return skipJSONValue(decoder)
		default:
			return unknownJSONField(key)
		}
	})
}

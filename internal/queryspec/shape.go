package queryspec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

type queryShape struct {
	Source     ResourceRef  `json:"source"`
	Projection []Selection  `json:"projection"`
	Filter     *filterShape `json:"filter,omitempty"`
	GroupBy    []string     `json:"group_by,omitempty"`
	OrderBy    []Sort       `json:"order_by,omitempty"`
}

type filterShape struct {
	Representation Representation `json:"representation,omitempty"`
	Kind           string         `json:"kind"`
	Field          string         `json:"field,omitempty"`
	Operator       string         `json:"operator"`
	ValueTypes     []string       `json:"value_types,omitempty"`
	Expressions    []filterShape  `json:"expressions,omitempty"`
}

// ShapeHash identifies a normalized query without retaining parameter values.
// Parameter types and counts remain part of the shape because they can affect
// database planning and are needed to correlate equivalent attempts.
func ShapeHash(spec NormalizedSpec) string {
	shape := queryShape{
		Source:     spec.Source,
		Projection: append([]Selection(nil), spec.Projection...),
		Filter:     shapeFilter(spec.Filter),
		GroupBy:    append([]string(nil), spec.GroupBy...),
		OrderBy:    append([]Sort(nil), spec.OrderBy...),
	}
	encoded, err := json.Marshal(shape)
	if err != nil {
		panic("queryspec: marshal query shape: " + err.Error())
	}
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:])
}

func shapeFilter(filter *Filter) *filterShape {
	if filter == nil {
		return nil
	}
	result := &filterShape{Representation: filter.Representation, Kind: filter.Kind, Field: filter.Field, Operator: filter.Operator}
	if filter.Kind == "predicate" {
		result.ValueTypes = make([]string, len(filter.Values))
		for index, value := range filter.Values {
			result.ValueTypes[index] = value.Type
		}
		return result
	}
	result.Expressions = make([]filterShape, len(filter.Expressions))
	for index := range filter.Expressions {
		result.Expressions[index] = *shapeFilter(&filter.Expressions[index])
	}
	return result
}

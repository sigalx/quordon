package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/queryspec"
)

func validateKeysetSelectShapes(profile string, policy QueryPolicy, limits domain.Limits) error {
	type identity struct {
		index int
		name  string
	}
	seenNames := make(map[string]struct{}, len(policy.KeysetSelectShapes))
	seenSignatures := make(map[[sha256.Size]byte]identity, len(policy.KeysetSelectShapes))
	for index, shape := range policy.KeysetSelectShapes {
		path := fmt.Sprintf("profiles.%s.query.keyset_select_shapes[%d]", profile, index)
		if !validPortableIdentifier(shape.Name) {
			return fmt.Errorf("%s.name must be a portable identifier", path)
		}
		if _, duplicate := seenNames[shape.Name]; duplicate {
			return fmt.Errorf("profiles.%s.query.keyset_select_shapes contains duplicate name %q", profile, shape.Name)
		}
		seenNames[shape.Name] = struct{}{}
		if shape.PublicDescription != nil && !validPublicDescription(*shape.PublicDescription) {
			return fmt.Errorf("%s.public_description must contain 1 to %d non-control Unicode code points", path, maxPublicDescriptionRunes)
		}
		if !validPortableIdentifier(shape.Source.Schema) || !validPortableIdentifier(shape.Source.Name) {
			return fmt.Errorf("%s.source must contain portable schema and object identifiers", path)
		}
		if len(shape.Projection) == 0 || len(shape.Projection) > limits.MaxProjectionFields ||
			len(shape.Projection) > queryspec.ProtocolMaxProjectionFields {
			return fmt.Errorf("%s.projection is outside the effective bounds", path)
		}
		projectionFields := make(map[string]int, len(shape.Projection))
		outputs := make(map[string]struct{}, len(shape.Projection))
		seenProjection := make(map[string]struct{}, len(shape.Projection))
		for projectionIndex, output := range shape.Projection {
			outputPath := fmt.Sprintf("%s.projection[%d]", path, projectionIndex)
			if output.Kind != "field" || !validPortableIdentifier(output.Field) ||
				(output.Alias != "" && !validPortableIdentifier(output.Alias)) {
				return fmt.Errorf("%s must be a field projection with an optional portable alias", outputPath)
			}
			term := strings.ToLower(output.Field) + "\x00" + strings.ToLower(output.Alias)
			if _, duplicate := seenProjection[term]; duplicate {
				return fmt.Errorf("%s.projection contains duplicate normalized terms", path)
			}
			seenProjection[term] = struct{}{}
			field := strings.ToLower(output.Field)
			projectionFields[field]++
			name := field
			if output.Alias != "" {
				name = strings.ToLower(output.Alias)
			}
			if _, duplicate := outputs[name]; duplicate {
				return fmt.Errorf("%s.projection contains colliding output names", path)
			}
			outputs[name] = struct{}{}
		}
		if len(shape.OrderBy) == 0 || len(shape.OrderBy) > queryspec.ProtocolMaxKeysetFields ||
			len(shape.OrderBy) > limits.MaxOrderByFields {
			return fmt.Errorf("%s.order_by is outside the effective bounds", path)
		}
		if !policy.AllowSorting {
			return fmt.Errorf("%s requires allow_sorting", path)
		}
		seenOrder := make(map[string]struct{}, len(shape.OrderBy))
		for orderIndex, order := range shape.OrderBy {
			orderPath := fmt.Sprintf("%s.order_by[%d]", path, orderIndex)
			if !validPortableIdentifier(order.Field) || (order.Direction != "asc" && order.Direction != "desc") {
				return fmt.Errorf("%s requires a portable field and asc or desc direction", orderPath)
			}
			field := strings.ToLower(order.Field)
			if _, duplicate := seenOrder[field]; duplicate {
				return fmt.Errorf("%s.order_by contains repeated normalized fields", path)
			}
			seenOrder[field] = struct{}{}
			for _, output := range shape.Projection {
				if strings.EqualFold(output.Field, order.Field) && output.Representation != order.Representation {
					return fmt.Errorf("%s representation must match projected key", orderPath)
				}
			}
			if projectionFields[field] != 1 {
				return fmt.Errorf("%s.field must be projected exactly once", orderPath)
			}
		}
		if shape.MaximumLimit < 1 || shape.MaximumLimit > limits.MaxRows || shape.MaximumLimit > queryspec.ProtocolMaxRows {
			return fmt.Errorf("%s.maximum_limit is outside the effective row bounds", path)
		}
		if shape.RequiredIndex != "" && !validPortableIdentifier(shape.RequiredIndex) {
			return fmt.Errorf("%s.required_index must be a portable identifier", path)
		}
		if shape.MaximumRowsExaminedPerScan == 0 {
			return fmt.Errorf("%s.maximum_rows_examined_per_scan must be positive", path)
		}
		stats := aggregateShapeStats{}
		if shape.Filter != nil {
			if !policy.AllowFiltering {
				return fmt.Errorf("%s.filter requires allow_filtering", path)
			}
			if err := validateAggregateShapeFilter(
				path+".filter", *shape.Filter, 1, limits, policy.AllowedFilterOperators, &stats,
			); err != nil {
				return err
			}
			if err := validateKeysetShapeFilterTypes(path+".filter", *shape.Filter); err != nil {
				return err
			}
		}
		cursorParameters := len(shape.OrderBy) * (len(shape.OrderBy) + 1) / 2
		if stats.parameters > limits.MaxParameters-1 || cursorParameters > limits.MaxParameters-1-stats.parameters {
			return fmt.Errorf("%s cannot fit after-page bindings within max_parameters", path)
		}
		signature := canonicalKeysetRequestSignature(shape)
		if previous, overlap := seenSignatures[signature]; overlap {
			return fmt.Errorf("%s overlaps keyset shape %q at index %d", path, previous.name, previous.index)
		}
		seenSignatures[signature] = identity{index: index, name: shape.Name}
	}
	return nil
}

// Query-shape discovery publishes a closed keyset filter union: LIKE accepts
// only textual/binary placeholders and set predicates use one homogeneous
// discriminator. Enforce that contract before a snapshot can be published.
func validateKeysetShapeFilterTypes(path string, filter AggregateShapeFilter) error {
	if filter.Kind == "group" {
		for index, child := range filter.Expressions {
			if err := validateKeysetShapeFilterTypes(fmt.Sprintf("%s.expressions[%d]", path, index), child); err != nil {
				return err
			}
		}
		return nil
	}
	if filter.ValueTypes == nil {
		return fmt.Errorf("%s.value_types is required", path)
	}
	valueTypes := *filter.ValueTypes
	if filter.Operator == "like" && (len(valueTypes) != 1 || valueTypes[0] != "string" && valueTypes[0] != "bytes") {
		return fmt.Errorf("%s.value_types for like must contain exactly string or bytes", path)
	}
	if filter.Operator == "in" || filter.Operator == "not_in" {
		for index := 1; index < len(valueTypes); index++ {
			if valueTypes[index] != valueTypes[0] {
				return fmt.Errorf("%s.value_types for %s must be homogeneous", path, filter.Operator)
			}
		}
	}
	return nil
}

func validateUniqueQueryShapeNames(profile string, policy QueryPolicy) error {
	seen := make(map[string]string, len(policy.AggregateShapes)+len(policy.KeysetSelectShapes))
	for _, shape := range policy.AggregateShapes {
		seen[shape.Name] = "aggregate"
	}
	for _, shape := range policy.KeysetSelectShapes {
		if operation, duplicate := seen[shape.Name]; duplicate {
			return fmt.Errorf("profiles.%s query shape name %q is shared by %s and select_keyset", profile, shape.Name, operation)
		}
		seen[shape.Name] = "select_keyset"
	}
	return nil
}

func canonicalKeysetRequestSignature(shape KeysetSelectShape) [sha256.Size]byte {
	type projection struct {
		Representation queryspec.Representation `json:"representation,omitempty"`
		Field          string                   `json:"field"`
		Alias          string                   `json:"alias,omitempty"`
	}
	type order struct {
		Representation queryspec.Representation `json:"representation,omitempty"`
		Field          string                   `json:"field"`
		Direction      string                   `json:"direction"`
	}
	type signature struct {
		Schema     string                      `json:"schema"`
		Object     string                      `json:"object"`
		Projection []projection                `json:"projection"`
		Filter     *aggregateShapeFilterDigest `json:"filter,omitempty"`
		OrderBy    []order                     `json:"order_by"`
	}
	value := signature{
		Schema: strings.ToLower(shape.Source.Schema), Object: strings.ToLower(shape.Source.Name),
		Projection: make([]projection, len(shape.Projection)), OrderBy: make([]order, len(shape.OrderBy)),
	}
	for index, output := range shape.Projection {
		value.Projection[index] = projection{Representation: output.Representation, Field: strings.ToLower(output.Field), Alias: strings.ToLower(output.Alias)}
	}
	if shape.Filter != nil {
		digest := canonicalAggregateShapeFilter(*shape.Filter)
		value.Filter = &digest
	}
	for index, item := range shape.OrderBy {
		value.OrderBy[index] = order{Representation: item.Representation, Field: strings.ToLower(item.Field), Direction: item.Direction}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		panic("config: marshal keyset request signature: " + err.Error())
	}
	return sha256.Sum256(encoded)
}

func keysetShapeFiltersEqual(left, right *AggregateShapeFilter) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	a := canonicalAggregateShapeFilter(*left)
	b := canonicalAggregateShapeFilter(*right)
	return bytes.Equal(a[:], b[:])
}

func cloneKeysetSelectShapes(shapes []KeysetSelectShape) []KeysetSelectShape {
	cloned := make([]KeysetSelectShape, len(shapes))
	for index, shape := range shapes {
		if shape.PublicDescription != nil {
			description := *shape.PublicDescription
			shape.PublicDescription = &description
		}
		shape.AllowTemporaryTable = cloneConfigBool(shape.AllowTemporaryTable)
		shape.AllowFilesort = cloneConfigBool(shape.AllowFilesort)
		shape.Projection = slices.Clone(shape.Projection)
		shape.Filter = cloneConfigShapeFilter(shape.Filter)
		shape.OrderBy = slices.Clone(shape.OrderBy)
		cloned[index] = shape
	}
	return cloned
}

func cloneConfigShapeFilter(filter *AggregateShapeFilter) *AggregateShapeFilter {
	if filter == nil {
		return nil
	}
	cloned := *filter
	if filter.ValueTypes != nil {
		values := slices.Clone(*filter.ValueTypes)
		cloned.ValueTypes = &values
	}
	cloned.Expressions = make([]AggregateShapeFilter, len(filter.Expressions))
	for index := range filter.Expressions {
		cloned.Expressions[index] = *cloneConfigShapeFilter(&filter.Expressions[index])
	}
	return &cloned
}

func cloneConfigBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

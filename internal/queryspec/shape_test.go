package queryspec

import "testing"

func TestShapeHashExcludesValuesButRetainsTheirTypesAndCount(t *testing.T) {
	first := NormalizedSpec{
		Source:     ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{{Kind: "field", Field: "id"}},
		Filter: &Filter{Kind: "predicate", Field: "status", Operator: "eq", Values: []TypedValue{{
			Type: "string", Value: []byte(`"active"`),
		}}},
		Limit: 10,
	}
	second := cloneNormalized(first)
	second.Filter.Values[0].Value = []byte(`"private"`)
	if ShapeHash(first) != ShapeHash(second) {
		t.Fatal("parameter values changed the query shape hash")
	}
	second.Filter.Values[0].Type = "uuid"
	if ShapeHash(first) == ShapeHash(second) {
		t.Fatal("parameter type did not change the query shape hash")
	}
}

func TestShapeHashChangesWithQueryStructure(t *testing.T) {
	first := NormalizedSpec{
		Source:     ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{{Kind: "field", Field: "id"}},
	}
	second := cloneNormalized(first)
	second.Projection[0].Field = "status"
	if ShapeHash(first) == ShapeHash(second) {
		t.Fatal("projection did not change the query shape hash")
	}
}

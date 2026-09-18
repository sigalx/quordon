package queryspec

// Representation chooses an explicit source-field representation. The empty
// value preserves the ordinary portable representation.
type Representation string

const RepresentationSourceText Representation = "source_text"

func (r Representation) Valid() bool { return r == "" || r == RepresentationSourceText }

func validateRepresentation(path string, r Representation) error {
	if !r.Valid() {
		return validationError(path+".representation", "must be source_text when present")
	}
	return nil
}

func decodeRepresentation(w wireString, allowed bool) (Representation, error) {
	if !w.Set {
		return "", nil
	}
	if !allowed || w.Value != string(RepresentationSourceText) {
		return "", validationError("representation", "source_text is permitted only on fields, predicates, and dimensions")
	}
	return RepresentationSourceText, nil
}

func FilterUsesSourceText(filter *Filter) bool {
	if filter == nil {
		return false
	}
	if filter.Representation == RepresentationSourceText {
		return true
	}
	for i := range filter.Expressions {
		if FilterUsesSourceText(&filter.Expressions[i]) {
			return true
		}
	}
	return false
}

func UsesSourceText(spec NormalizedSpec) bool {
	for _, field := range spec.Projection {
		if field.Representation == RepresentationSourceText {
			return true
		}
	}
	for _, field := range spec.OrderBy {
		if field.Representation == RepresentationSourceText {
			return true
		}
	}
	return FilterUsesSourceText(spec.Filter)
}

func AggregateUsesSourceText(spec NormalizedAggregateSpec) bool {
	for _, field := range spec.Projection {
		if field.Representation == RepresentationSourceText {
			return true
		}
	}
	for _, field := range spec.OrderBy {
		if field.Representation == RepresentationSourceText {
			return true
		}
	}
	return FilterUsesSourceText(spec.Filter)
}

func KeysetUsesSourceText(request NormalizedKeysetRequest) bool {
	return UsesSourceText(NormalizedSpec{Projection: request.Query.Projection, OrderBy: request.Query.OrderBy, Filter: request.Query.Filter})
}

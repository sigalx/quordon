package config

import (
	"fmt"

	"github.com/sigalx/quordon/internal/queryspec"
)

func validateSourceTextShapes(profile string, policy QueryPolicy) error {
	check := func(r queryspec.Representation, allowed bool) error {
		if !r.Valid() || r != "" && (!allowed || !policy.AllowSourceText) {
			return fmt.Errorf("profile %q source_text requires allow_source_text and a field, predicate, or dimension", profile)
		}
		return nil
	}
	var filterCheck func(*AggregateShapeFilter) error
	filterCheck = func(f *AggregateShapeFilter) error {
		if f == nil {
			return nil
		}
		if err := check(f.Representation, f.Kind == "predicate"); err != nil {
			return err
		}
		if f.Representation == queryspec.RepresentationSourceText && f.ValueTypes != nil {
			for _, t := range *f.ValueTypes {
				if t != "string" {
					return fmt.Errorf("profile %q source_text requires string value_types", profile)
				}
			}
		}
		for i := range f.Expressions {
			if err := filterCheck(&f.Expressions[i]); err != nil {
				return err
			}
		}
		return nil
	}
	for _, shape := range policy.AggregateShapes {
		for _, out := range shape.Projection {
			if err := check(out.Representation, out.Kind == "dimension"); err != nil {
				return err
			}
		}
		for _, out := range shape.OrderBy {
			if err := check(out.Representation, out.Kind == "dimension"); err != nil {
				return err
			}
		}
		if err := filterCheck(shape.Filter); err != nil {
			return err
		}
	}
	for _, shape := range policy.KeysetSelectShapes {
		for _, out := range shape.Projection {
			if err := check(out.Representation, out.Kind == "field"); err != nil {
				return err
			}
		}
		for _, out := range shape.OrderBy {
			if err := check(out.Representation, true); err != nil {
				return err
			}
		}
		if err := filterCheck(shape.Filter); err != nil {
			return err
		}
	}
	return nil
}

// QueryPolicyUsesSourceText checks configured shapes, without accessing a datasource.
func QueryPolicyUsesSourceText(policy QueryPolicy) bool {
	var filterUses func(*AggregateShapeFilter) bool
	filterUses = func(f *AggregateShapeFilter) bool {
		if f == nil {
			return false
		}
		if f.Representation == queryspec.RepresentationSourceText {
			return true
		}
		for i := range f.Expressions {
			if filterUses(&f.Expressions[i]) {
				return true
			}
		}
		return false
	}
	for _, shape := range policy.AggregateShapes {
		for _, out := range shape.Projection {
			if out.Representation == queryspec.RepresentationSourceText {
				return true
			}
		}
		for _, out := range shape.OrderBy {
			if out.Representation == queryspec.RepresentationSourceText {
				return true
			}
		}
		if filterUses(shape.Filter) {
			return true
		}
	}
	for _, shape := range policy.KeysetSelectShapes {
		for _, out := range shape.Projection {
			if out.Representation == queryspec.RepresentationSourceText {
				return true
			}
		}
		for _, out := range shape.OrderBy {
			if out.Representation == queryspec.RepresentationSourceText {
				return true
			}
		}
		if filterUses(shape.Filter) {
			return true
		}
	}
	return false
}

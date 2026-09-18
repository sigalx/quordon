package policy

import (
	"os"
	"testing"

	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/queryspec"
)

func TestDenylistUsesRequestedViewFieldsWithoutDependencyPropagation(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	profile := cfg.Profiles["data-reader"]
	profile.Resources.Objects = config.PatternPolicy{Allow: []string{"application.*"}}
	profile.Resources.Fields = config.PatternPolicy{Allow: []string{"application.*.*"}, Deny: []string{"application.base.hidden", "application.trusted_view.hidden"}}
	cfg.Profiles["data-reader"] = profile
	snapshot := NewSnapshot(cfg)
	for _, fixture := range []struct {
		object, field string
		allowed       bool
	}{
		{"base", "hidden", false}, {"trusted_view", "hidden", false},
		// The administrator maps base.hidden to this view alias. Policy sees
		// requested-object coordinates and intentionally does not trace it.
		{"trusted_view", "exposed_alias", true},
	} {
		validated, err := queryspec.Validate(queryspec.Spec{Source: queryspec.ResourceRef{Schema: "application", Name: fixture.object}, Projection: []queryspec.Selection{{Kind: "field", Field: fixture.field}}}, 10, 10, 10, 10, 4, 10, 10, 10)
		if err != nil {
			t.Fatal(err)
		}
		_, err = snapshot.AuthorizeSelect("readonly-client", "data-reader", validated, domain.IdentifierSemantics{CaseInsensitiveFields: true})
		if fixture.allowed && err != nil {
			t.Fatalf("alias denied: %v", err)
		}
		if !fixture.allowed {
			var reason string
			if !IsDenial(err, &reason) || reason != ReasonDeniedField {
				t.Fatalf("deny = %v %s", err, reason)
			}
		}
	}
}

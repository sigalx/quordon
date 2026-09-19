package policy

import (
	"testing"

	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/queryspec"
)

func bindingForTest(
	t testing.TB,
	snapshot *Snapshot,
	principal, profile, datasource string,
	operation domain.Operation,
) AuthorizedBinding {
	t.Helper()
	binding, err := snapshot.AuthorizeBinding(principal, profile, datasource, operation)
	if err != nil {
		t.Fatalf("AuthorizeBinding(%q, %q, %q, %q): %v", principal, profile, datasource, operation, err)
	}
	return binding
}

func TestAuthorizeBindingRequiresThreeWayIntersection(t *testing.T) {
	limits := domain.Limits{MaxConcurrency: 1}
	snapshot := NewSnapshot(config.Config{
		PolicyHash: "hash", HardLimits: limits,
		Principals: map[string]config.Principal{
			"client":        {Profiles: []string{"reader"}, Datasources: []string{"test"}},
			"wrong-profile": {Profiles: []string{"other"}, Datasources: []string{"test"}},
			"wrong-source":  {Profiles: []string{"reader"}, Datasources: []string{"rc"}},
		},
		Profiles: map[string]config.Profile{
			"reader": {Datasources: []string{"test", "rc"}, Operations: []domain.Operation{domain.OperationSelect}, Limits: limits},
			"other":  {Datasources: []string{"test"}, Operations: []domain.Operation{domain.OperationSelect}, Limits: limits},
		},
	})

	binding, err := snapshot.AuthorizeBinding("client", "reader", "test", domain.OperationSelect)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Principal() != "client" || binding.Profile() != "reader" ||
		binding.Datasource() != "test" || binding.Operation() != domain.OperationSelect ||
		binding.Key() != (BindingKey{Profile: "reader", Datasource: "test"}) {
		t.Fatalf("binding = %+v", binding)
	}
	for _, attempt := range []struct {
		principal, profile, datasource string
		operation                      domain.Operation
	}{
		{principal: "unknown", profile: "reader", datasource: "test", operation: domain.OperationSelect},
		{principal: "wrong-profile", profile: "reader", datasource: "test", operation: domain.OperationSelect},
		{principal: "wrong-source", profile: "reader", datasource: "test", operation: domain.OperationSelect},
		{principal: "client", profile: "reader", datasource: "rc", operation: domain.OperationSelect},
		{principal: "client", profile: "reader", datasource: "test", operation: domain.OperationExplainSelect},
	} {
		if _, err := snapshot.AuthorizeBinding(attempt.principal, attempt.profile, attempt.datasource, attempt.operation); err == nil {
			t.Fatalf("unauthorized binding accepted: %+v", attempt)
		} else {
			var reason string
			if !IsDenial(err, &reason) || reason != ReasonDeniedOperation {
				t.Fatalf("denial = %v, reason = %q", err, reason)
			}
		}
	}
}

func TestOperationAuthorizationRejectsInvalidBindings(t *testing.T) {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 1024, MaxProjectionFields: 1,
		MaxGroupByFields: 1, MaxOrderByFields: 1, MaxPredicates: 1,
		MaxExpressionDepth: 1, MaxParameters: 2, MaxRows: 1,
		MaxResultBytes: 1024, MaxOffset: 1, MaxConcurrency: 1,
	}
	snapshot := NewSnapshot(config.Config{
		PolicyHash: "hash", HardLimits: limits,
		Principals: map[string]config.Principal{"client": {
			Profiles: []string{"reader"}, Datasources: []string{"test"},
		}},
		Profiles: map[string]config.Profile{"reader": {
			Datasources: []string{"test", "rc"}, Operations: []domain.Operation{domain.OperationSelect}, Limits: limits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"app"}},
				Objects: config.PatternPolicy{Allow: []string{"app.orders"}},
				Fields:  config.PatternPolicy{Allow: []string{"app.orders.id"}},
			},
		}},
	})
	limit := 1
	validated, err := queryspec.Validate(queryspec.Spec{
		Source:     queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.Selection{{Kind: "field", Field: "id"}}, Limit: &limit,
	}, 1, 0, 1, 0, 1, 2, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	valid := bindingForTest(t, snapshot, "client", "reader", "test", domain.OperationSelect)
	invalid := []AuthorizedBinding{
		{},
		{owner: snapshot, principal: "client", key: BindingKey{Profile: "reader", Datasource: "test"}, operation: domain.OperationExplainSelect, policyHash: snapshot.hash},
		{owner: snapshot, principal: "client", key: BindingKey{Profile: "reader", Datasource: "rc"}, operation: domain.OperationSelect, policyHash: snapshot.hash},
		{owner: snapshot, principal: "other", key: BindingKey{Profile: "reader", Datasource: "test"}, operation: domain.OperationSelect, policyHash: snapshot.hash},
	}
	if _, err := snapshot.AuthorizeSelect(valid, validated, domain.IdentifierSemantics{}); err != nil {
		t.Fatalf("valid binding rejected: %v", err)
	}
	for index, binding := range invalid {
		if _, err := snapshot.AuthorizeSelect(binding, validated, domain.IdentifierSemantics{}); err == nil {
			t.Fatalf("invalid binding %d accepted", index)
		}
	}
}

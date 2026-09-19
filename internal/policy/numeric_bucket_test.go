package policy

import (
	"strings"
	"testing"

	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/queryspec"
)

func numericPolicyFixture(t *testing.T) (config.Config, queryspec.ValidatedAggregate) {
	t.Helper()
	original := aggregatePolicySnapshot(10)
	profile, _ := original.Profile("analytics")
	profile.Query.AllowSorting = true
	profile.Operations = append(profile.Operations, domain.OperationListQueryShapes)
	profile.Query.AggregateShapes = []config.AggregateShape{{
		Name: "numeric_shape", Mode: "grouped", Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
		Projection: []config.AggregateShapeOutput{{Kind: "numeric_bucket", Field: "status", Alias: "status_bucket", Boundaries: []string{"-1", "0", "9007199254740993"}}, {Kind: "measure", Function: "count_all", Alias: "total"}},
		OrderBy:    []config.AggregateShapeOrder{{Kind: "numeric_bucket", Alias: "status_bucket", Direction: "asc"}}, MaximumLimit: 10, MaximumRowsExaminedPerScan: 100,
		AllowTemporaryTable: policyBoolPointer(true), AllowFilesort: policyBoolPointer(true),
	}}
	cfg := config.Config{Version: 1, HardLimits: original.HardLimits(), Principals: map[string]config.Principal{"client": {Profiles: []string{"analytics"}, Datasources: []string{"mysql"}}}, Profiles: map[string]config.Profile{"analytics": profile}}
	limit := 5
	query := validateAggregateForPolicy(t, queryspec.AggregateSpec{Mode: "grouped", Source: queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.AggregateOutput{{Kind: "numeric_bucket", Field: "status", Alias: "STATUS_BUCKET"}, {Kind: "measure", Function: "count_all", Alias: "total"}},
		OrderBy:    []queryspec.AggregateSort{{Kind: "numeric_bucket", Alias: "STATUS_BUCKET", Direction: "asc"}}, Limit: &limit})
	return cfg, query
}

func TestNumericBucketAuthorizationSnapshotAndDiscovery(t *testing.T) {
	cfg, query := numericPolicyFixture(t)
	snapshot := NewSnapshot(cfg)
	cfg.Profiles["analytics"].Query.AggregateShapes[0].Projection[0].Boundaries[0] = "-99"
	token, err := snapshot.AuthorizeAggregate(bindingForTest(t, snapshot, "client", "analytics", "mysql", domain.OperationAggregate), query, domain.IdentifierSemantics{})
	if err != nil {
		t.Fatal(err)
	}
	if token.ParameterCount() != 10 || token.NumericBoundaries()["status_bucket"][0] != "-1" {
		t.Fatalf("token=%+v boundaries=%v", token, token.NumericBoundaries())
	}
	copy := token.NumericBoundaries()
	copy["status_bucket"][0] = "changed"
	delete(copy, "status_bucket")
	profile, _ := snapshot.Profile("analytics")
	profile.Query.AggregateShapes[0].Projection[0].Boundaries[0] = "changed"
	if token.NumericBoundaries()["status_bucket"][0] != "-1" {
		t.Fatal("token has mutable alias")
	}
	discovery, err := snapshot.BuildQueryShapeDiscovery("analytics", "mysql", "adapter", domain.IdentifierSemantics{})
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := snapshot.AuthorizeQueryShapeList(bindingForTest(t, snapshot, "client", "analytics", "mysql", domain.OperationListQueryShapes), "credential", &discovery)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := allowed.ResponsePayload()
	if err != nil || !strings.Contains(string(payload), `"boundaries":["-1","0","9007199254740993"]`) {
		t.Fatalf("payload=%s error=%v", payload, err)
	}
	changed := NewSnapshot(cfg)
	newDiscovery, err := changed.BuildQueryShapeDiscovery("analytics", "mysql", "adapter", domain.IdentifierSemantics{})
	if err != nil || newDiscovery.document.shapeSetHash == discovery.document.shapeSetHash {
		t.Fatalf("boundary hash did not change: %v", err)
	}
	if (AuthorizedAggregate{}).Operation() == domain.OperationAggregate {
		t.Fatal("zero token grants aggregate")
	}
}

func TestNumericBucketAuthorizationDenialsAndBudget(t *testing.T) {
	for _, kind := range []string{"deny", "grouping", "sorting", "controls", "parameters", "ambiguous"} {
		t.Run(kind, func(t *testing.T) {
			cfg, query := numericPolicyFixture(t)
			p := cfg.Profiles["analytics"]
			switch kind {
			case "deny":
				p.Resources.Fields.Deny = []string{"app.orders.status"}
			case "grouping":
				p.Query.AllowGroupBy = false
			case "sorting":
				p.Query.AllowSorting = false
			case "controls":
				p.Query.AggregateShapes[0].AllowFilesort = nil
			case "parameters":
				p.Limits.MaxParameters = 9
			case "ambiguous":
				p.Query.AggregateShapes = append(p.Query.AggregateShapes, p.Query.AggregateShapes[0])
			}
			cfg.Profiles["analytics"] = p
			candidate := NewSnapshot(cfg)
			if _, err := candidate.AuthorizeAggregate(bindingForTest(t, candidate, "client", "analytics", "mysql", domain.OperationAggregate), query, domain.IdentifierSemantics{}); err == nil {
				t.Fatal("accepted forbidden aggregate")
			}
		})
	}
}

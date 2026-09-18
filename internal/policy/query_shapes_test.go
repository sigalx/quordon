package policy

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/queryspec"
)

func TestQueryShapeDiscoveryBuildsBoundedImmutableAuthorization(t *testing.T) {
	cfg := queryShapePolicyConfig()
	snapshot := NewSnapshot(cfg)
	*cfg.Profiles["analytics"].Query.AggregateShapes[0].PublicDescription = "mutated after snapshot"
	_, operations, _, ok := snapshot.ProfileBinding("analytics")
	if !ok {
		t.Fatal("profile binding is missing")
	}
	operations[0] = domain.OperationSelect
	_, freshOperations, _, _ := snapshot.ProfileBinding("analytics")
	if freshOperations[0] == domain.OperationSelect {
		t.Fatal("profile binding exposed a mutable operations alias")
	}
	semantics := domain.IdentifierSemantics{CaseInsensitiveFields: true}
	discovery, err := snapshot.BuildQueryShapeDiscovery("analytics", domain.AdapterMySQL8, semantics)
	if err != nil {
		t.Fatal(err)
	}
	if !discovery.MatchesSemantics(semantics) || discovery.MatchesSemantics(domain.IdentifierSemantics{}) {
		t.Fatal("discovery did not retain its identifier semantics")
	}
	authorized, err := snapshot.AuthorizeQueryShapeList("client", "credential-a", "analytics", &discovery)
	if err != nil {
		t.Fatal(err)
	}
	if authorized.Operation() != domain.OperationListQueryShapes || authorized.Principal() != "client" ||
		authorized.CredentialIdentifier() != "credential-a" || authorized.Profile() != "analytics" ||
		authorized.ShapeCount() != 2 || authorized.ShapeSetHash() == "" || authorized.Generation() == "" {
		t.Fatalf("authorization token is incomplete: %+v", authorized)
	}
	if got, want := authorized.ShapeSetHash(), "b0a4cea9c627419704c39c51623777952f3e413b8f5ecca81cdec2fe78df8a1b"; got != want {
		t.Fatalf("public shape-set hash = %s, want %s", got, want)
	}
	payload, err := authorized.ResponsePayload()
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(payload) || len(payload) != authorized.ResultBytes() ||
		!strings.Contains(string(payload), `"description":"Count orders by status."`) ||
		strings.Contains(string(payload), "required_index") ||
		strings.Contains(string(payload), "maximum_rows_examined_per_scan") {
		t.Fatalf("unsafe or incomplete public payload: %s", payload)
	}
	payload[0] = '['
	secondPayload, err := authorized.ResponsePayload()
	if err != nil || secondPayload[0] != '{' {
		t.Fatal("response payload exposed a mutable alias")
	}
	resources := authorized.Resources()
	resources[0].Schema = "changed"
	if authorized.Resources()[0].Schema == "changed" {
		t.Fatal("resource list exposed a mutable alias")
	}
	fields := authorized.Fields()
	fields[0] = "changed"
	if authorized.Fields()[0] == "changed" {
		t.Fatal("field list exposed a mutable alias")
	}
}

func TestQueryShapeDiscoveryRejectsDeniedOrOversizedDisclosure(t *testing.T) {
	cfg := queryShapePolicyConfig()
	profile := cfg.Profiles["analytics"]
	profile.Resources.Fields = config.PatternPolicy{Allow: []string{"app.orders.created_at"}}
	cfg.Profiles["analytics"] = profile
	if _, err := NewSnapshot(cfg).BuildQueryShapeDiscovery(
		"analytics", domain.AdapterMySQL8, domain.IdentifierSemantics{CaseInsensitiveFields: true},
	); err == nil || !strings.Contains(err.Error(), "denied field") {
		t.Fatalf("denied field error = %v", err)
	}

	cfg = queryShapePolicyConfig()
	profile = cfg.Profiles["analytics"]
	profile.Limits.MaxResultBytes = 1
	cfg.Profiles["analytics"] = profile
	if _, err := NewSnapshot(cfg).BuildQueryShapeDiscovery(
		"analytics", domain.AdapterMySQL8, domain.IdentifierSemantics{CaseInsensitiveFields: true},
	); err == nil || !strings.Contains(err.Error(), "exceeds max_result_bytes") {
		t.Fatalf("oversized disclosure error = %v", err)
	}

	cfg = queryShapePolicyConfig()
	profile = cfg.Profiles["analytics"]
	profile.Query.AllowGroupBy = false
	cfg.Profiles["analytics"] = profile
	if _, err := NewSnapshot(cfg).BuildQueryShapeDiscovery(
		"analytics", domain.AdapterMySQL8, domain.IdentifierSemantics{CaseInsensitiveFields: true},
	); err == nil || !strings.Contains(err.Error(), "denied query feature") {
		t.Fatalf("denied feature error = %v", err)
	}
}

func TestQueryShapeDiscoveryAuthorizationFailsClosed(t *testing.T) {
	cfg := queryShapePolicyConfig()
	snapshot := NewSnapshot(cfg)
	discovery, err := snapshot.BuildQueryShapeDiscovery(
		"analytics", domain.AdapterMySQL8, domain.IdentifierSemantics{CaseInsensitiveFields: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.AuthorizeQueryShapeList("other", "credential", "analytics", &discovery); err == nil {
		t.Fatal("unassigned principal received a query-shape token")
	}
	if _, err := snapshot.AuthorizeQueryShapeList("client", "", "analytics", &discovery); err == nil {
		t.Fatal("empty credential identifier received a query-shape token")
	}
	mutated := discovery
	mutated.policyHash = "different"
	if _, err := snapshot.AuthorizeQueryShapeList("client", "credential", "analytics", &mutated); err == nil {
		t.Fatal("mismatched discovery snapshot received a token")
	}
	foreignSnapshot := NewSnapshot(cfg)
	foreignDiscovery, err := foreignSnapshot.BuildQueryShapeDiscovery(
		"analytics", domain.AdapterMySQL8, domain.IdentifierSemantics{CaseInsensitiveFields: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if foreignDiscovery.policyHash != discovery.policyHash || foreignDiscovery.generation != discovery.generation {
		t.Fatal("foreign snapshot fixture does not exercise equal public snapshot attributes")
	}
	if _, err := snapshot.AuthorizeQueryShapeList("client", "credential", "analytics", &foreignDiscovery); err == nil {
		t.Fatal("discovery owned by another policy snapshot received a token")
	}
	if _, err := (AuthorizedQueryShapeList{}).ResponsePayload(); err == nil {
		t.Fatal("zero authorization token returned a response")
	}
}

func TestQueryShapeDiscoveryIncludesTimeBuckets(t *testing.T) {
	cfg := queryShapePolicyConfig()
	profile := cfg.Profiles["analytics"]
	profile.Query.AggregateShapes = append(profile.Query.AggregateShapes, config.AggregateShape{
		Name: "orders_by_day", Mode: queryspec.AggregateModeGrouped,
		Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
		Projection: []config.AggregateShapeOutput{
			{Kind: "time_bucket", Field: "created_at", Unit: "day", Timezone: "UTC", Alias: "created_day"},
			{Kind: "measure", Function: "count_all", Alias: "daily_count"},
		},
		MaximumLimit: 10, RequiredIndex: "idx_created_at", MaximumRowsExaminedPerScan: 100,
		AllowTemporaryTable: policyBoolPointer(true), AllowFilesort: policyBoolPointer(true),
	})
	cfg.Profiles["analytics"] = profile
	snapshot := NewSnapshot(cfg)
	discovery, err := snapshot.BuildQueryShapeDiscovery(
		"analytics", domain.AdapterMySQL8, domain.IdentifierSemantics{CaseInsensitiveFields: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := snapshot.AuthorizeQueryShapeList("client", "credential", "analytics", &discovery)
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := authorized.ResponsePayload(); err != nil || !strings.Contains(string(payload), `"kind":"time_bucket"`) {
		t.Fatalf("missing time-bucket JSON disclosure: %v", err)
	}
	if payload, err := authorized.ResponsePayload(); err != nil || strings.Contains(string(payload), "allow_temporary_table") {
		t.Fatalf("invalid time-bucket disclosure: error=%v payload=%s", err, payload)
	}
}

func TestQueryShapeDiscoveryCanonicalizesAuditScope(t *testing.T) {
	cfg := queryShapePolicyConfig()
	profile := cfg.Profiles["analytics"]
	for index := range profile.Query.AggregateShapes {
		profile.Query.AggregateShapes[index].Source.Schema = "App"
		profile.Query.AggregateShapes[index].Source.Name = "Orders"
	}
	profile.Query.AggregateShapes[0].Projection[0].Field = "Status"
	profile.Query.AggregateShapes[1].Projection[0].Field = "Created_At"
	cfg.Profiles["analytics"] = profile

	snapshot := NewSnapshot(cfg)
	discovery, err := snapshot.BuildQueryShapeDiscovery(
		"analytics",
		domain.AdapterMySQL8,
		domain.IdentifierSemantics{
			CaseInsensitiveSchemas: true,
			CaseInsensitiveObjects: true,
			CaseInsensitiveFields:  true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := snapshot.AuthorizeQueryShapeList("client", "credential", "analytics", &discovery)
	if err != nil {
		t.Fatal(err)
	}
	resources := authorized.Resources()
	if len(resources) != 1 || resources[0] != (QueryShapeResource{Schema: "app", Object: "orders"}) {
		t.Fatalf("canonical audit resources = %+v", resources)
	}
	if fields := authorized.Fields(); !slices.Equal(fields, []string{"created_at", "status"}) {
		t.Fatalf("canonical audit fields = %v", fields)
	}
	payload, err := authorized.ResponsePayload()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"schema":"App","name":"Orders"`) ||
		!strings.Contains(string(payload), `"field":"Status"`) ||
		!strings.Contains(string(payload), `"field":"Created_At"`) {
		t.Fatalf("public response did not preserve configured spelling: %s", payload)
	}
}

func TestQueryShapeDiscoveryAuditsCompleteShapeSet(t *testing.T) {
	cfg := queryShapePolicyConfig()
	profile := cfg.Profiles["analytics"]
	profile.Operations = append(profile.Operations, domain.OperationSelectKeyset)
	profile.Query.KeysetSelectShapes = []config.KeysetSelectShape{{
		Name: "orders_page", Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
		Projection:   []config.KeysetShapeProjection{{Kind: "field", Field: "id"}},
		OrderBy:      []config.KeysetShapeOrder{{Field: "id", Direction: "asc"}},
		MaximumLimit: 10, RequiredIndex: "PRIMARY", MaximumRowsExaminedPerScan: 100,
	}}
	cfg.Profiles["analytics"] = profile
	snapshot := NewSnapshot(cfg)
	discovery, err := snapshot.BuildQueryShapeDiscovery(
		"analytics", domain.AdapterMySQL8, domain.IdentifierSemantics{CaseInsensitiveFields: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := snapshot.AuthorizeQueryShapeList("client", "credential", "analytics", &discovery)
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := authorized.ResponsePayload(); err != nil || !strings.Contains(string(payload), `"operation":"select_keyset"`) {
		t.Fatalf("missing keyset JSON disclosure: %v", err)
	}
	if authorized.ShapeCount() != len(profile.Query.AggregateShapes)+len(profile.Query.KeysetSelectShapes) || authorized.ShapeSetHash() == "" {
		t.Fatal("audit identity omitted configured shapes")
	}
}

func TestQueryShapeHashesBindTimeBucketAndKeysetPublicMembers(t *testing.T) {
	timeBucketA := publicAggregateQueryShape{
		Name: "orders_by_time", Operation: domain.OperationAggregate,
		Query: publicAggregateShapeSpec{
			Mode:   queryspec.AggregateModeGrouped,
			Source: queryspec.ResourceRef{Schema: "app", Name: "orders"},
			Projection: []publicAggregateOutput{{
				Kind: "time_bucket", Field: "created_at", Unit: "day", Timezone: "UTC", Alias: "bucket",
			}},
			MaximumLimit: 10,
		},
	}
	timeBucketB := timeBucketA
	timeBucketB.Query.Projection = slices.Clone(timeBucketA.Query.Projection)
	timeBucketB.Query.Projection[0].Unit = "month"
	hashA, err := publicQueryShapeSetHash([]publicQueryShape{{aggregate: &timeBucketA}})
	if err != nil {
		t.Fatal(err)
	}
	hashB, err := publicQueryShapeSetHash([]publicQueryShape{{aggregate: &timeBucketB}})
	if err != nil {
		t.Fatal(err)
	}
	if hashA == hashB {
		t.Fatal("aggregate shape hash omitted the time-bucket unit")
	}

	keysetA := publicQueryShape{keyset: &publicKeysetQueryShape{
		Name: "orders_page", Operation: domain.OperationSelectKeyset,
		Query: publicKeysetShapeSpec{
			Source:     queryspec.ResourceRef{Schema: "app", Name: "orders"},
			Projection: []queryspec.Selection{{Kind: "field", Field: "id"}},
			OrderBy:    []queryspec.Sort{{Field: "id", Direction: "asc"}}, MaximumLimit: 10,
		},
	}}
	keysetBValue := *keysetA.keyset
	keysetBValue.Query = keysetA.keyset.Query
	keysetBValue.Query.OrderBy = slices.Clone(keysetA.keyset.Query.OrderBy)
	keysetBValue.Query.OrderBy[0].Direction = "desc"
	keysetB := publicQueryShape{keyset: &keysetBValue}
	keysetHashA, err := publicQueryShapeSetHash([]publicQueryShape{keysetA})
	if err != nil {
		t.Fatal(err)
	}
	keysetHashB, err := publicQueryShapeSetHash([]publicQueryShape{keysetB})
	if err != nil {
		t.Fatal(err)
	}
	if keysetHashA == keysetHashB {
		t.Fatal("shape hash omitted the keyset order direction")
	}
}

func queryShapePolicyConfig() config.Config {
	description := "Count orders by status."
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 65536, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10, MaxPredicates: 10,
		MaxExpressionDepth: 4, MaxParameters: 20, MaxRows: 100,
		MaxResultBytes: 65536, MaxOffset: 0, MaxConcurrency: 1,
	}
	return config.Config{
		Version: 3, PolicyHash: "redacted-policy-hash", HardLimits: limits,
		Principals:  map[string]config.Principal{"client": {Profiles: []string{"analytics"}}},
		Datasources: map[string]config.Datasource{"mysql": {Adapter: domain.AdapterMySQL8}},
		Profiles: map[string]config.Profile{"analytics": {
			Datasource: "mysql", Limits: limits,
			Operations: []domain.Operation{domain.OperationAggregate, domain.OperationListQueryShapes},
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"app"}},
				Objects: config.PatternPolicy{Allow: []string{"app.orders"}},
				Fields:  config.PatternPolicy{Allow: []string{"app.orders.*"}},
			},
			Query: config.QueryPolicy{
				AllowFiltering: true, AllowGroupBy: true, AllowSorting: true,
				AllowedFilterOperators: []string{"eq"}, AllowedAggregates: []string{"count", "max"},
				AggregateShapes: []config.AggregateShape{
					{
						Name: "orders_by_status", PublicDescription: &description, Mode: queryspec.AggregateModeGrouped,
						Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
						Projection: []config.AggregateShapeOutput{
							{Kind: "dimension", Field: "status"},
							{Kind: "measure", Function: "count_all", Alias: "total"},
						},
						OrderBy:      []config.AggregateShapeOrder{{Kind: "measure", Alias: "total", Direction: "desc"}},
						MaximumLimit: 10, RequiredIndex: "idx_status", MaximumRowsExaminedPerScan: 100,
					},
					{
						Name: "latest_order", Mode: queryspec.AggregateModeScalar,
						Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
						Projection: []config.AggregateShapeOutput{
							{Kind: "measure", Function: "max", Field: "created_at", Alias: "latest"},
						},
						RequiredIndex: "PRIMARY", MaximumRowsExaminedPerScan: 100,
					},
				},
			},
		}},
	}
}

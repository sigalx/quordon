package policy

import (
	"reflect"
	"testing"

	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/queryspec"
)

func TestSnapshotOwnsIndependentPolicyData(t *testing.T) {
	valueTypes := []string{"string"}
	allowTemporaryTable := true
	allowFilesort := false
	cfg := config.Config{
		Version:    7,
		PolicyHash: "original-hash",
		Principals: map[string]config.Principal{
			"client": {Profiles: []string{"explain"}, Datasources: []string{"mysql"}},
		},
		Profiles: map[string]config.Profile{
			"explain": {
				Datasources: []string{"mysql"},
				Operations:  []domain.Operation{domain.OperationExplainSelect},
				Resources: config.ResourcePolicy{
					Schemas: config.PatternPolicy{Allow: []string{"app"}, Deny: []string{"private"}},
					Objects: config.PatternPolicy{Allow: []string{"app.*"}, Deny: []string{"app.secret"}},
					Fields:  config.PatternPolicy{Allow: []string{"app.*.*"}, Deny: []string{"app.*.secret"}},
				},
				Query: config.QueryPolicy{
					AllowedFilterOperators: []string{"eq"},
					AllowedAggregates:      []string{"count"},
					AggregateShapes: []config.AggregateShape{{
						Name: "shape", Projection: []config.AggregateShapeOutput{{Kind: "measure", Function: "count_all", Alias: "total"}},
						Filter:              &config.AggregateShapeFilter{Kind: "predicate", Field: "status", Operator: "eq", ValueTypes: &valueTypes},
						OrderBy:             []config.AggregateShapeOrder{{Kind: "measure", Alias: "total", Direction: "desc"}},
						AllowTemporaryTable: &allowTemporaryTable, AllowFilesort: &allowFilesort,
					}},
				},
			},
		},
	}
	snapshot := NewSnapshot(cfg)
	wantProfiles := snapshot.PrincipalProfiles("client")
	wantDatasources := snapshot.PrincipalDatasources("client")
	wantProfile, ok := snapshot.Profile("explain")
	if !ok {
		t.Fatal("snapshot profile is missing")
	}

	principal := cfg.Principals["client"]
	principal.Profiles[0] = "mutated"
	principal.Datasources[0] = "mutated"
	cfg.Principals["client"] = config.Principal{Profiles: []string{"replacement"}, Datasources: []string{"mysql"}}

	profile := cfg.Profiles["explain"]
	profile.Datasources[0] = "mutated"
	profile.Operations[0] = "mutated"
	profile.Resources.Schemas.Allow[0] = "mutated"
	profile.Resources.Schemas.Deny[0] = "mutated"
	profile.Resources.Objects.Allow[0] = "mutated"
	profile.Resources.Objects.Deny[0] = "mutated"
	profile.Resources.Fields.Allow[0] = "mutated"
	profile.Resources.Fields.Deny[0] = "mutated"
	profile.Query.AllowedFilterOperators[0] = "mutated"
	profile.Query.AllowedAggregates[0] = "mutated"
	profile.Query.AggregateShapes[0].Projection[0].Alias = "mutated"
	(*profile.Query.AggregateShapes[0].Filter.ValueTypes)[0] = "mutated"
	profile.Query.AggregateShapes[0].OrderBy[0].Alias = "mutated"
	*profile.Query.AggregateShapes[0].AllowTemporaryTable = false
	*profile.Query.AggregateShapes[0].AllowFilesort = true
	cfg.Profiles["explain"] = config.Profile{Datasources: []string{"replacement"}}

	if got := snapshot.PrincipalProfiles("client"); !reflect.DeepEqual(got, wantProfiles) {
		t.Fatalf("principal profiles = %#v, want %#v", got, wantProfiles)
	}
	if got := snapshot.PrincipalDatasources("client"); !reflect.DeepEqual(got, wantDatasources) {
		t.Fatalf("principal datasources = %#v, want %#v", got, wantDatasources)
	}
	gotProfile, ok := snapshot.Profile("explain")
	if !ok || !reflect.DeepEqual(gotProfile, wantProfile) {
		t.Fatalf("profile = %#v, want %#v", gotProfile, wantProfile)
	}

	returnedProfiles := snapshot.PrincipalProfiles("client")
	returnedProfiles[0] = "accessor-mutation"
	returnedDatasources := snapshot.PrincipalDatasources("client")
	returnedDatasources[0] = "accessor-mutation"
	gotProfile.Datasources[0] = "accessor-mutation"
	gotProfile.Operations[0] = "accessor-mutation"
	gotProfile.Resources.Fields.Deny[0] = "accessor-mutation"
	gotProfile.Query.AllowedAggregates[0] = "accessor-mutation"
	gotProfile.Query.AggregateShapes[0].Projection[0].Alias = "accessor-mutation"
	(*gotProfile.Query.AggregateShapes[0].Filter.ValueTypes)[0] = "accessor-mutation"
	*gotProfile.Query.AggregateShapes[0].AllowTemporaryTable = false
	*gotProfile.Query.AggregateShapes[0].AllowFilesort = true
	if got := snapshot.PrincipalProfiles("client"); !reflect.DeepEqual(got, wantProfiles) {
		t.Fatalf("principal accessor exposed shared data: %#v", got)
	}
	if got := snapshot.PrincipalDatasources("client"); !reflect.DeepEqual(got, wantDatasources) {
		t.Fatalf("principal datasource accessor exposed shared data: %#v", got)
	}
	gotProfile, _ = snapshot.Profile("explain")
	if !reflect.DeepEqual(gotProfile, wantProfile) {
		t.Fatalf("profile accessor exposed shared data: %#v", gotProfile)
	}
}

func TestAuthorizeExplainAppliesDenyBeforeAllow(t *testing.T) {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 1000, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10,
		MaxPredicates: 10, MaxExpressionDepth: 4, MaxParameters: 10, MaxRows: 10,
		MaxResultBytes: 1000, MaxOffset: 10, MaxConcurrency: 1,
	}
	cfg := config.Config{
		Version: 1, PolicyHash: "hash", HardLimits: limits,
		Principals:  map[string]config.Principal{"client": {Profiles: []string{"explain"}, Datasources: []string{"mysql"}}},
		Datasources: map[string]config.Datasource{"mysql": {Adapter: domain.AdapterMySQL8}},
		Profiles: map[string]config.Profile{"explain": {
			Datasources: []string{"mysql"}, Operations: []domain.Operation{domain.OperationExplainSelect}, Limits: limits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"application"}},
				Objects: config.PatternPolicy{Allow: []string{"application.*"}},
				Fields: config.PatternPolicy{
					Allow: []string{"application.orders.*"},
					Deny:  []string{"application.orders.password_hash"},
				},
			},
		}},
	}
	validated, err := queryspec.Validate(queryspec.Spec{
		Source:     queryspec.ResourceRef{Schema: "application", Name: "orders"},
		Projection: []queryspec.Selection{{Kind: "field", Field: "password_hash"}},
	}, 10, 10, 10, 10, 4, 10, 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := NewSnapshot(cfg)
	_, err = snapshot.AuthorizeExplain(bindingForTest(t, snapshot, "client", "explain", "mysql", domain.OperationExplainSelect), validated, domain.IdentifierSemantics{})
	var reason string
	if !IsDenial(err, &reason) || reason != ReasonDeniedField {
		t.Fatalf("error = %v, reason = %q, want %s", err, reason, ReasonDeniedField)
	}
}

func TestAuthorizeExplainAppliesMySQLFieldDenyCaseInsensitively(t *testing.T) {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 1000, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10,
		MaxPredicates: 10, MaxExpressionDepth: 4, MaxParameters: 10, MaxRows: 10,
		MaxResultBytes: 1000, MaxOffset: 10, MaxConcurrency: 1,
	}
	cfg := config.Config{
		Version: 1, PolicyHash: "hash", HardLimits: limits,
		Principals:  map[string]config.Principal{"client": {Profiles: []string{"explain"}, Datasources: []string{"mysql"}}},
		Datasources: map[string]config.Datasource{"mysql": {Adapter: domain.AdapterMySQL8}},
		Profiles: map[string]config.Profile{"explain": {
			Datasources: []string{"mysql"}, Operations: []domain.Operation{domain.OperationExplainSelect}, Limits: limits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"application"}},
				Objects: config.PatternPolicy{Allow: []string{"application.users"}},
				Fields: config.PatternPolicy{
					Allow: []string{"application.users.*"},
					Deny:  []string{"application.users.password_hash"},
				},
			},
		}},
	}
	validated, err := queryspec.Validate(queryspec.Spec{
		Source:     queryspec.ResourceRef{Schema: "application", Name: "users"},
		Projection: []queryspec.Selection{{Kind: "field", Field: "PASSWORD_HASH"}},
	}, 10, 10, 10, 10, 4, 10, 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := NewSnapshot(cfg)
	_, err = snapshot.AuthorizeExplain(
		bindingForTest(t, snapshot, "client", "explain", "mysql", domain.OperationExplainSelect),
		validated,
		domain.IdentifierSemantics{CaseInsensitiveFields: true},
	)
	var reason string
	if !IsDenial(err, &reason) || reason != ReasonDeniedField {
		t.Fatalf("error = %v, reason = %q, want %s", err, reason, ReasonDeniedField)
	}
}

func TestAuthorizeExplainAppliesObjectDenyUsingServerCaseSemantics(t *testing.T) {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 1000, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10,
		MaxPredicates: 10, MaxExpressionDepth: 4, MaxParameters: 10, MaxRows: 10,
		MaxResultBytes: 1000, MaxOffset: 10, MaxConcurrency: 1,
	}
	cfg := config.Config{
		Version: 1, PolicyHash: "hash", HardLimits: limits,
		Principals: map[string]config.Principal{"client": {Profiles: []string{"explain"}, Datasources: []string{"mysql"}}},
		Profiles: map[string]config.Profile{"explain": {
			Datasources: []string{"mysql"}, Operations: []domain.Operation{domain.OperationExplainSelect}, Limits: limits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"application"}},
				Objects: config.PatternPolicy{
					Allow: []string{"application.*"},
					Deny:  []string{"application.users"},
				},
			},
		}},
	}
	validated, err := queryspec.Validate(queryspec.Spec{
		Source:     queryspec.ResourceRef{Schema: "application", Name: "Users"},
		Projection: []queryspec.Selection{{Kind: "field", Field: "id"}},
	}, 10, 10, 10, 10, 4, 10, 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := NewSnapshot(cfg)
	_, err = snapshot.AuthorizeExplain(
		bindingForTest(t, snapshot, "client", "explain", "mysql", domain.OperationExplainSelect),
		validated,
		domain.IdentifierSemantics{
			CaseInsensitiveSchemas: true,
			CaseInsensitiveObjects: true,
			CaseInsensitiveFields:  true,
		},
	)
	var reason string
	if !IsDenial(err, &reason) || reason != ReasonDeniedResource {
		t.Fatalf("error = %v, reason = %q, want %s", err, reason, ReasonDeniedResource)
	}
}

func TestAuthorizeExplainRejectsUnassignedProfile(t *testing.T) {
	snapshot := NewSnapshot(config.Config{
		Version:    1,
		Principals: map[string]config.Principal{"client": {Profiles: []string{"assigned"}, Datasources: []string{"mysql"}}},
		Profiles:   map[string]config.Profile{"assigned": {}},
	})
	_, err := snapshot.AuthorizeBinding("client", "other", "mysql", domain.OperationExplainSelect)
	var reason string
	if !IsDenial(err, &reason) || reason != ReasonDeniedOperation {
		t.Fatalf("error = %v, reason = %q", err, reason)
	}
}

func TestAuthorizedQueriesAreOperationBoundAndSelectIsValidatedAtPolicyBoundary(t *testing.T) {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 1000, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10, MaxPredicates: 10,
		MaxExpressionDepth: 4, MaxParameters: 10, MaxRows: 10,
		MaxResultBytes: 1000, MaxOffset: 10, MaxConcurrency: 1,
	}
	snapshot := NewSnapshot(config.Config{
		Version: 1, HardLimits: limits,
		Principals: map[string]config.Principal{"client": {Profiles: []string{"both"}, Datasources: []string{"mysql"}}},
		Profiles: map[string]config.Profile{"both": {
			Datasources: []string{"mysql"},
			Operations:  []domain.Operation{domain.OperationExplainSelect, domain.OperationSelect},
			Limits:      limits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"app"}},
				Objects: config.PatternPolicy{Allow: []string{"app.orders"}},
				Fields:  config.PatternPolicy{Allow: []string{"app.orders.*"}},
			},
			Query: config.QueryPolicy{AllowedAggregates: []string{"count"}},
		}},
	})
	validate := func(spec queryspec.Spec) queryspec.Validated {
		t.Helper()
		validated, err := queryspec.Validate(spec, 10, 10, 10, 10, 4, 10, 10, 10)
		if err != nil {
			t.Fatal(err)
		}
		return validated
	}
	fieldQuery := validate(queryspec.Spec{
		Source:     queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.Selection{{Kind: "field", Field: "id"}},
	})
	explain, err := snapshot.AuthorizeExplain(bindingForTest(t, snapshot, "client", "both", "mysql", domain.OperationExplainSelect), fieldQuery, domain.IdentifierSemantics{})
	if err != nil {
		t.Fatal(err)
	}
	if explain.Operation() != domain.OperationExplainSelect {
		t.Fatalf("explain token operation = %q", explain.Operation())
	}
	selectQuery, err := snapshot.AuthorizeSelect(bindingForTest(t, snapshot, "client", "both", "mysql", domain.OperationSelect), fieldQuery, domain.IdentifierSemantics{})
	if err != nil {
		t.Fatal(err)
	}
	if selectQuery.Operation() != domain.OperationSelect {
		t.Fatalf("select token operation = %q", selectQuery.Operation())
	}

	aggregate := validate(queryspec.Spec{
		Source:     queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.Selection{{Kind: "aggregate", Function: "count"}},
	})
	if _, err := snapshot.AuthorizeSelect(bindingForTest(t, snapshot, "client", "both", "mysql", domain.OperationSelect), aggregate, domain.IdentifierSemantics{}); err == nil {
		t.Fatal("AuthorizeSelect() minted a token for an aggregate query")
	}
}

func TestAuthorizedQueriesAreRevalidatedUnderEffectiveLimits(t *testing.T) {
	hardLimits := domain.Limits{
		DeadlineMS: 5000, MaxRequestBytes: 10000, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10, MaxPredicates: 10,
		MaxExpressionDepth: 8, MaxParameters: 20, MaxRows: 100,
		MaxResultBytes: 10000, MaxOffset: 100, MaxConcurrency: 4,
	}
	profileLimits := hardLimits
	profileLimits.MaxProjectionFields = 1
	profileLimits.MaxRows = 10
	profileLimits.MaxOffset = 5
	snapshot := NewSnapshot(config.Config{
		Version: 1, HardLimits: hardLimits,
		Principals: map[string]config.Principal{"client": {Profiles: []string{"reader"}, Datasources: []string{"mysql"}}},
		Profiles: map[string]config.Profile{"reader": {
			Datasources: []string{"mysql"}, Operations: []domain.Operation{
				domain.OperationExplainSelect, domain.OperationSelect,
			},
			Limits: profileLimits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"app"}},
				Objects: config.PatternPolicy{Allow: []string{"app.orders"}},
				Fields:  config.PatternPolicy{Allow: []string{"app.orders.*"}},
			},
		}},
	})

	requestedLimit := 50
	validated, err := queryspec.Validate(queryspec.Spec{
		Source:     queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.Selection{{Kind: "field", Field: "id"}},
		Limit:      &requestedLimit,
	}, 10, 10, 10, 10, 8, 20, 100, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, authorize := range []struct {
		name string
		call func() (AuthorizedQuery, error)
	}{
		{name: "select", call: func() (AuthorizedQuery, error) {
			return snapshot.AuthorizeSelect(bindingForTest(t, snapshot, "client", "reader", "mysql", domain.OperationSelect), validated, domain.IdentifierSemantics{})
		}},
		{name: "explain", call: func() (AuthorizedQuery, error) {
			return snapshot.AuthorizeExplain(bindingForTest(t, snapshot, "client", "reader", "mysql", domain.OperationExplainSelect), validated, domain.IdentifierSemantics{})
		}},
	} {
		t.Run(authorize.name+" normalizes limit", func(t *testing.T) {
			token, err := authorize.call()
			if err != nil {
				t.Fatal(err)
			}
			if token.Query().Limit != profileLimits.MaxRows || token.Limits().MaxRows != profileLimits.MaxRows {
				t.Fatalf("token query limit = %d, token max rows = %d, want %d",
					token.Query().Limit, token.Limits().MaxRows, profileLimits.MaxRows)
			}
		})
	}

	tooManyFields, err := queryspec.Validate(queryspec.Spec{
		Source: queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.Selection{
			{Kind: "field", Field: "id"},
			{Kind: "field", Field: "status"},
		},
	}, 10, 10, 10, 10, 8, 20, 100, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.AuthorizeSelect(bindingForTest(t, snapshot, "client", "reader", "mysql", domain.OperationSelect), tooManyFields, domain.IdentifierSemantics{}); err == nil {
		t.Fatal("AuthorizeSelect() accepted a query validated above the profile projection limit")
	}

	requestedOffset := 6
	largeOffset, err := queryspec.Validate(queryspec.Spec{
		Source:     queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.Selection{{Kind: "field", Field: "id"}},
		Offset:     &requestedOffset,
	}, 10, 10, 10, 10, 8, 20, 100, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.AuthorizeSelect(bindingForTest(t, snapshot, "client", "reader", "mysql", domain.OperationSelect), largeOffset, domain.IdentifierSemantics{}); err == nil {
		t.Fatal("AuthorizeSelect() accepted a query validated above the profile offset limit")
	}
}

func TestAuthorizeSchemaOperationsAreBoundToAllowedResources(t *testing.T) {
	limits := domain.Limits{DeadlineMS: 1000, MaxRequestBytes: 1000, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10, MaxPredicates: 10,
		MaxExpressionDepth: 4, MaxParameters: 10, MaxRows: 10,
		MaxResultBytes: 1000, MaxOffset: 10, MaxConcurrency: 1}
	snapshot := NewSnapshot(config.Config{
		Version: 1, HardLimits: limits,
		Principals: map[string]config.Principal{"client": {Profiles: []string{"reader"}, Datasources: []string{"mysql"}}},
		Profiles: map[string]config.Profile{"reader": {
			Datasources: []string{"mysql"}, Operations: []domain.Operation{
				domain.OperationListObjects, domain.OperationDescribeObject,
			}, Limits: limits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"app"}},
				Objects: config.PatternPolicy{Allow: []string{"app.*"}, Deny: []string{"app.secret"}},
				Fields:  config.PatternPolicy{Allow: []string{"app.*.*"}, Deny: []string{"app.orders.password"}},
			},
		}},
	})
	list, err := snapshot.AuthorizeListObjects(bindingForTest(t, snapshot, "client", "reader", "mysql", domain.OperationListObjects), "app",
		domain.IdentifierSemantics{CaseInsensitiveFields: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if list.Operation() != domain.OperationListObjects || !list.AllowsObject("orders") || list.AllowsObject("secret") {
		t.Fatalf("unexpected object policy result")
	}
	authorized, err := snapshot.AuthorizeDescribeObject(bindingForTest(t, snapshot, "client", "reader", "mysql", domain.OperationDescribeObject), queryspec.ResourceRef{Schema: "app", Name: "orders"},
		domain.IdentifierSemantics{CaseInsensitiveFields: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if authorized.Operation() != domain.OperationDescribeObject || authorized.Object() != "orders" ||
		!authorized.AllowsField("id") || authorized.AllowsField("PASSWORD") {
		t.Fatalf("unexpected field policy result")
	}
	if _, err := snapshot.AuthorizeDescribeObject(bindingForTest(t, snapshot, "client", "reader", "mysql", domain.OperationDescribeObject), queryspec.ResourceRef{Schema: "app", Name: "secret"},
		domain.IdentifierSemantics{},
	); err == nil {
		t.Fatal("denied object received an authorization token")
	}
}

func TestAuthorizeSchemaOperationsRejectInvalidResourcesBeforeMintingToken(t *testing.T) {
	limits := domain.Limits{DeadlineMS: 1000, MaxRequestBytes: 1000, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10, MaxPredicates: 10,
		MaxExpressionDepth: 4, MaxParameters: 10, MaxRows: 10,
		MaxResultBytes: 1000, MaxOffset: 10, MaxConcurrency: 1}
	snapshot := NewSnapshot(config.Config{
		Version: 1, HardLimits: limits,
		Principals: map[string]config.Principal{"client": {Profiles: []string{"metadata"}, Datasources: []string{"mysql"}}},
		Profiles: map[string]config.Profile{"metadata": {
			Datasources: []string{"mysql"}, Operations: []domain.Operation{
				domain.OperationListObjects, domain.OperationDescribeObject,
			}, Limits: limits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"*"}},
				Objects: config.PatternPolicy{Allow: []string{"*.*"}},
				Fields:  config.PatternPolicy{Allow: []string{"*.*.*"}},
			},
		}},
	})

	for _, schema := range []string{"", "not-portable"} {
		if _, err := snapshot.AuthorizeListObjects(bindingForTest(t, snapshot, "client", "metadata", "mysql", domain.OperationListObjects), schema, domain.IdentifierSemantics{}); err == nil {
			t.Fatalf("list_objects minted a token for schema %q", schema)
		}
	}
	for _, resource := range []queryspec.ResourceRef{
		{Schema: "", Name: "orders"},
		{Schema: "app", Name: ""},
		{Schema: "not-portable", Name: "orders"},
		{Schema: "app", Name: "not-portable"},
	} {
		if _, err := snapshot.AuthorizeDescribeObject(bindingForTest(t, snapshot, "client", "metadata", "mysql", domain.OperationDescribeObject), resource, domain.IdentifierSemantics{}); err == nil {
			t.Fatalf("describe_object minted a token for resource %+v", resource)
		}
	}
}

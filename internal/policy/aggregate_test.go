package policy

import (
	"encoding/json"
	"testing"

	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/queryspec"
)

func TestAuthorizeAggregateMintsOperationBoundTokenForExactShape(t *testing.T) {
	snapshot := aggregatePolicySnapshot(10)
	limit := 5
	filter := queryspec.Filter{Kind: "group", Operator: "and", Expressions: []queryspec.Filter{
		{
			Kind: "predicate", Field: "STATUS", Operator: "eq",
			Values: []queryspec.TypedValue{{Type: "string", Value: json.RawMessage(`"active"`)}},
		},
		{
			Kind: "predicate", Field: "CREATED_AT", Operator: "gte",
			Values: []queryspec.TypedValue{{Type: "datetime", Value: json.RawMessage(`"2026-01-01T00:00:00Z"`)}},
		},
	}}
	validated := validateAggregateForPolicy(t, queryspec.AggregateSpec{
		Mode:   queryspec.AggregateModeGrouped,
		Source: queryspec.ResourceRef{Schema: "APP", Name: "ORDERS"},
		Projection: []queryspec.AggregateOutput{
			{Kind: "dimension", Field: "STATUS"},
			{Kind: "measure", Function: "count_all", Alias: "TOTAL"},
		},
		Filter:  &filter,
		OrderBy: []queryspec.AggregateSort{{Kind: "measure", Alias: "TOTAL", Direction: "desc"}},
		Limit:   &limit,
	})
	token, err := snapshot.AuthorizeAggregate(bindingForTest(t, snapshot, "client", "analytics", "mysql", domain.OperationAggregate), validated,
		domain.IdentifierSemantics{
			CaseInsensitiveSchemas: true,
			CaseInsensitiveObjects: true,
			CaseInsensitiveFields:  true,
		},
	)
	if err != nil {
		t.Fatalf("AuthorizeAggregate() error = %v", err)
	}
	if token.Operation() != domain.OperationAggregate || token.Datasource() != "mysql" ||
		token.RequiredIndex() != "idx_orders_status" || token.MaximumRowsExaminedPerScan() != 100 ||
		token.ShapeName() != "orders_by_status" {
		t.Fatalf("unexpected aggregate token: operation=%q datasource=%q index=%q maximum=%d shape=%q",
			token.Operation(), token.Datasource(), token.RequiredIndex(), token.MaximumRowsExaminedPerScan(), token.ShapeName())
	}
	if got := token.Query(); got.Source.Schema != "app" || got.Source.Name != "orders" ||
		got.Projection[0].Field != "status" || got.Projection[1].Alias != "total" {
		t.Fatalf("token query was not canonicalized: %+v", got)
	}
	fields := token.ReferencedFields()
	if len(fields) != 2 || fields[0] != "created_at" || fields[1] != "status" {
		t.Fatalf("referenced fields = %#v", fields)
	}
}

func TestAuthorizeAggregateBindsTimeBucketExecutionControls(t *testing.T) {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 65536, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10, MaxPredicates: 10,
		MaxExpressionDepth: 4, MaxParameters: 20, MaxRows: 100,
		MaxResultBytes: 65536, MaxConcurrency: 1,
	}
	snapshot := NewSnapshot(config.Config{
		Version: 1, HardLimits: limits,
		Principals: map[string]config.Principal{"client": {Profiles: []string{"analytics"}, Datasources: []string{"mysql"}}},
		Profiles: map[string]config.Profile{"analytics": {
			Datasources: []string{"mysql"}, Operations: []domain.Operation{domain.OperationAggregate}, Limits: limits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"app"}},
				Objects: config.PatternPolicy{Allow: []string{"app.orders"}},
				Fields:  config.PatternPolicy{Allow: []string{"app.orders.created_at"}},
			},
			Query: config.QueryPolicy{
				AllowGroupBy: true, AllowSorting: true, AllowedAggregates: []string{"count"},
				AggregateShapes: []config.AggregateShape{{
					Name: "orders_by_day", Mode: queryspec.AggregateModeGrouped,
					Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
					Projection: []config.AggregateShapeOutput{
						{Kind: "time_bucket", Field: "created_at", Unit: "day", Timezone: "UTC", Alias: "created_day"},
						{Kind: "measure", Function: "count_all", Alias: "total"},
					},
					OrderBy:      []config.AggregateShapeOrder{{Kind: "time_bucket", Alias: "created_day", Direction: "asc"}},
					MaximumLimit: 10, RequiredIndex: "idx_created_at", MaximumRowsExaminedPerScan: 100,
					AllowTemporaryTable: policyBoolPointer(true), AllowFilesort: policyBoolPointer(false),
				}},
			},
		}},
	})
	limit := 5
	validated := validateAggregateForPolicy(t, queryspec.AggregateSpec{
		Mode: queryspec.AggregateModeGrouped, Source: queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.AggregateOutput{
			{Kind: "time_bucket", Field: "created_at", Unit: "day", Timezone: "UTC", Alias: "created_day"},
			{Kind: "measure", Function: "count_all", Alias: "total"},
		},
		OrderBy: []queryspec.AggregateSort{{Kind: "time_bucket", Alias: "created_day", Direction: "asc"}}, Limit: &limit,
	})
	token, err := snapshot.AuthorizeAggregate(bindingForTest(t, snapshot, "client", "analytics", "mysql", domain.OperationAggregate), validated, domain.IdentifierSemantics{CaseInsensitiveFields: true})
	if err != nil {
		t.Fatal(err)
	}
	if !token.AllowTemporaryTable() || token.AllowFilesort() {
		t.Fatalf("time-bucket controls were not bound to the token: temporary=%t filesort=%t", token.AllowTemporaryTable(), token.AllowFilesort())
	}
}

func policyBoolPointer(value bool) *bool { return &value }

func TestAuthorizeAggregateRejectsMissingTimeBucketExecutionControls(t *testing.T) {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 65536, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10, MaxPredicates: 10,
		MaxExpressionDepth: 4, MaxParameters: 20, MaxRows: 100,
		MaxResultBytes: 65536, MaxOffset: 100, MaxConcurrency: 1,
	}
	shape := config.AggregateShape{
		Name: "orders_by_day", Mode: queryspec.AggregateModeGrouped,
		Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
		Projection: []config.AggregateShapeOutput{
			{Kind: "time_bucket", Field: "created_at", Unit: "day", Timezone: "UTC", Alias: "created_day"},
			{Kind: "measure", Function: "count_all", Alias: "total"},
		},
		MaximumLimit: 10, RequiredIndex: "idx_created_at", MaximumRowsExaminedPerScan: 100,
	}
	cfg := config.Config{
		HardLimits: limits,
		Principals: map[string]config.Principal{"client": {Profiles: []string{"analytics"}, Datasources: []string{"mysql"}}},
		Profiles: map[string]config.Profile{"analytics": {
			Datasources: []string{"mysql"}, Operations: []domain.Operation{domain.OperationAggregate}, Limits: limits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"app"}},
				Objects: config.PatternPolicy{Allow: []string{"app.orders"}},
				Fields:  config.PatternPolicy{Allow: []string{"app.orders.created_at"}},
			},
			Query: config.QueryPolicy{
				AllowGroupBy: true, AllowedAggregates: []string{"count"}, AggregateShapes: []config.AggregateShape{shape},
			},
		}},
	}
	limit := 10
	validated, err := queryspec.ValidateAggregate(queryspec.AggregateSpec{
		Mode: queryspec.AggregateModeGrouped, Source: queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.AggregateOutput{
			{Kind: "time_bucket", Field: "created_at", Unit: "day", Timezone: "UTC", Alias: "created_day"},
			{Kind: "measure", Function: "count_all", Alias: "total"},
		},
		Limit: &limit,
	}, 10, 10, 10, 10, 4, 20, 100)
	if err != nil {
		t.Fatal(err)
	}
	candidate := NewSnapshot(cfg)
	if _, err := candidate.AuthorizeAggregate(bindingForTest(t, candidate, "client", "analytics", "mysql", domain.OperationAggregate), validated, domain.IdentifierSemantics{}); err == nil {
		t.Fatal("authorization token was minted without explicit time-bucket execution controls")
	}
}

func TestAuthorizeAggregateUsesSharedCanonicalFilterOrder(t *testing.T) {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 65536, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10, MaxPredicates: 10,
		MaxExpressionDepth: 4, MaxParameters: 20, MaxRows: 100,
		MaxResultBytes: 65536, MaxConcurrency: 1,
	}
	stringType := []string{"string"}
	snapshot := NewSnapshot(config.Config{
		Version: 1, HardLimits: limits,
		Principals: map[string]config.Principal{"client": {Profiles: []string{"analytics"}, Datasources: []string{"mysql"}}},
		Profiles: map[string]config.Profile{"analytics": {
			Datasources: []string{"mysql"}, Operations: []domain.Operation{domain.OperationAggregate}, Limits: limits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"app"}},
				Objects: config.PatternPolicy{Allow: []string{"app.orders"}},
				Fields:  config.PatternPolicy{Allow: []string{"app.orders.a", "app.orders.c"}},
			},
			Query: config.QueryPolicy{
				AllowFiltering: true, AllowedFilterOperators: []string{"eq"}, AllowedAggregates: []string{"count"},
				AggregateShapes: []config.AggregateShape{{
					Name: "a_and_c", Mode: queryspec.AggregateModeScalar,
					Source:     config.AggregateShapeSource{Schema: "app", Name: "orders"},
					Projection: []config.AggregateShapeOutput{{Kind: "measure", Function: "count_all", Alias: "total"}},
					Filter: &config.AggregateShapeFilter{Kind: "group", Operator: "and", Expressions: []config.AggregateShapeFilter{
						{Kind: "predicate", Field: "a", Operator: "eq", ValueTypes: &stringType},
						{Kind: "predicate", Field: "c", Operator: "eq", ValueTypes: &stringType},
					}},
					RequiredIndex: "idx_a_c", MaximumRowsExaminedPerScan: 100,
				}},
			},
		}},
	})
	filter := queryspec.Filter{Kind: "group", Operator: "and", Expressions: []queryspec.Filter{
		{Kind: "predicate", Field: "a", Operator: "eq", Values: []queryspec.TypedValue{{Type: "string", Value: json.RawMessage(`"one"`)}}},
		{Kind: "predicate", Field: "c", Operator: "eq", Values: []queryspec.TypedValue{{Type: "string", Value: json.RawMessage(`"two"`)}}},
	}}
	validated := validateAggregateForPolicy(t, queryspec.AggregateSpec{
		Mode:       queryspec.AggregateModeScalar,
		Source:     queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.AggregateOutput{{Kind: "measure", Function: "count_all", Alias: "total"}},
		Filter:     &filter,
	})
	if _, err := snapshot.AuthorizeAggregate(bindingForTest(t, snapshot, "client", "analytics", "mysql", domain.OperationAggregate), validated, domain.IdentifierSemantics{CaseInsensitiveFields: true}); err != nil {
		t.Fatalf("AuthorizeAggregate() rejected an exact a/c shape: %v", err)
	}
}

func TestAuthorizedAggregateQueryDeepCopiesBindPayloads(t *testing.T) {
	snapshot := aggregatePolicySnapshot(10)
	validated := validateAggregateForPolicy(t, aggregateRequestForPolicy(5))
	token, err := snapshot.AuthorizeAggregate(bindingForTest(t, snapshot, "client", "analytics", "mysql", domain.OperationAggregate), validated, domain.IdentifierSemantics{})
	if err != nil {
		t.Fatal(err)
	}

	queryCopy := token.Query()
	statusValue := aggregateFilterValueForField(t, queryCopy.Filter, "status")
	statusValue[1] = 'X'

	fresh := token.Query()
	if got := string(aggregateFilterValueForField(t, fresh.Filter, "status")); got != `"active"` {
		t.Fatalf("authorized token bind value was mutated through Query(): %s", got)
	}
}

func aggregateFilterValueForField(t *testing.T, filter *queryspec.Filter, field string) json.RawMessage {
	t.Helper()
	if filter == nil {
		t.Fatal("aggregate filter is nil")
	}
	if filter.Kind == "predicate" {
		if filter.Field == field && len(filter.Values) != 0 {
			return filter.Values[0].Value
		}
		t.Fatalf("aggregate predicate field = %q, want %q", filter.Field, field)
	}
	for index := range filter.Expressions {
		child := &filter.Expressions[index]
		if child.Kind == "predicate" && child.Field == field && len(child.Values) != 0 {
			return child.Values[0].Value
		}
	}
	t.Fatalf("aggregate filter does not contain field %q", field)
	return nil
}

func TestAuthorizeAggregateRejectsPartialOrExcessiveShape(t *testing.T) {
	snapshot := aggregatePolicySnapshot(10)
	base := aggregateRequestForPolicy(5)

	differentDirection := base
	differentDirection.OrderBy = []queryspec.AggregateSort{{Kind: "measure", Alias: "total", Direction: "asc"}}
	tooLarge := aggregateRequestForPolicy(11)

	for name, spec := range map[string]queryspec.AggregateSpec{
		"different ordering":   differentDirection,
		"shape limit exceeded": tooLarge,
	} {
		t.Run(name, func(t *testing.T) {
			validated := validateAggregateForPolicy(t, spec)
			_, err := snapshot.AuthorizeAggregate(bindingForTest(t, snapshot, "client", "analytics", "mysql", domain.OperationAggregate), validated, domain.IdentifierSemantics{})
			var reason string
			if !IsDenial(err, &reason) || reason != ReasonDeniedQueryFeature {
				t.Fatalf("error = %v, reason = %q", err, reason)
			}
		})
	}
}

func aggregatePolicySnapshot(maximumLimit int) *Snapshot {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 65536, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10, MaxPredicates: 10,
		MaxExpressionDepth: 4, MaxParameters: 20, MaxRows: 100,
		MaxResultBytes: 65536, MaxOffset: 0, MaxConcurrency: 1,
	}
	valueTypesString := []string{"string"}
	valueTypesDatetime := []string{"datetime"}
	return NewSnapshot(config.Config{
		Version: 1, HardLimits: limits,
		Principals: map[string]config.Principal{"client": {Profiles: []string{"analytics"}, Datasources: []string{"mysql"}}},
		Profiles: map[string]config.Profile{"analytics": {
			Datasources: []string{"mysql"}, Operations: []domain.Operation{domain.OperationAggregate}, Limits: limits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"app"}},
				Objects: config.PatternPolicy{Allow: []string{"app.orders"}},
				Fields:  config.PatternPolicy{Allow: []string{"app.orders.status", "app.orders.created_at"}},
			},
			Query: config.QueryPolicy{
				AllowFiltering: true, AllowGroupBy: true, AllowSorting: true,
				AllowedFilterOperators: []string{"eq", "gte"}, AllowedAggregates: []string{"count"},
				AggregateShapes: []config.AggregateShape{{
					Name: "orders_by_status", Mode: queryspec.AggregateModeGrouped,
					Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
					Projection: []config.AggregateShapeOutput{
						{Kind: "dimension", Field: "status"},
						{Kind: "measure", Function: "count_all", Alias: "total"},
					},
					Filter: &config.AggregateShapeFilter{Kind: "group", Operator: "and", Expressions: []config.AggregateShapeFilter{
						{Kind: "predicate", Field: "created_at", Operator: "gte", ValueTypes: &valueTypesDatetime},
						{Kind: "predicate", Field: "status", Operator: "eq", ValueTypes: &valueTypesString},
					}},
					OrderBy:      []config.AggregateShapeOrder{{Kind: "measure", Alias: "total", Direction: "desc"}},
					MaximumLimit: maximumLimit, RequiredIndex: "idx_orders_status",
					MaximumRowsExaminedPerScan: 100,
				}},
			},
		}},
	})
}

func aggregateRequestForPolicy(limit int) queryspec.AggregateSpec {
	filter := queryspec.Filter{Kind: "group", Operator: "and", Expressions: []queryspec.Filter{
		{Kind: "predicate", Field: "status", Operator: "eq", Values: []queryspec.TypedValue{{Type: "string", Value: json.RawMessage(`"active"`)}}},
		{Kind: "predicate", Field: "created_at", Operator: "gte", Values: []queryspec.TypedValue{{Type: "datetime", Value: json.RawMessage(`"2026-01-01T00:00:00Z"`)}}},
	}}
	return queryspec.AggregateSpec{
		Mode:   queryspec.AggregateModeGrouped,
		Source: queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.AggregateOutput{
			{Kind: "dimension", Field: "status"},
			{Kind: "measure", Function: "count_all", Alias: "total"},
		},
		Filter:  &filter,
		OrderBy: []queryspec.AggregateSort{{Kind: "measure", Alias: "total", Direction: "desc"}},
		Limit:   &limit,
	}
}

func validateAggregateForPolicy(t *testing.T, spec queryspec.AggregateSpec) queryspec.ValidatedAggregate {
	t.Helper()
	validated, err := queryspec.ValidateAggregate(spec, 10, 10, 10, 10, 4, 20, 100)
	if err != nil {
		t.Fatal(err)
	}
	return validated
}

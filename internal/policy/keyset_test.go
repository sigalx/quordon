package policy

import (
	"encoding/json"
	"testing"

	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/queryspec"
)

func TestAuthorizeKeysetSelectMintsImmutableOperationBoundToken(t *testing.T) {
	snapshot := keysetPolicySnapshot()
	validated := validateKeysetForPolicy(t, 5)
	semantics := domain.IdentifierSemantics{
		CaseInsensitiveSchemas: true, CaseInsensitiveObjects: true, CaseInsensitiveFields: true,
	}
	token, err := snapshot.AuthorizeKeysetSelect(bindingForTest(t, snapshot, "client", "reader", "mysql", domain.OperationSelectKeyset), "basic-user", "mysql8", validated, semantics)
	if err != nil {
		t.Fatal(err)
	}
	if token.Operation() != domain.OperationSelectKeyset || token.Datasource() != "mysql" ||
		token.Adapter() != "mysql8" || token.ShapeName() != "orders_by_id" || token.RequiredIndex() != "PRIMARY" ||
		token.MaximumRowsExaminedPerScan() != 100 || token.CredentialIdentifier() != "basic-user" {
		t.Fatalf("unexpected keyset token: %+v", token)
	}
	request := token.Query()
	if request.Query.Source.Schema != "app" || request.Query.Source.Name != "orders" ||
		request.Query.Projection[0].Field != "id" || request.Query.Filter.Field != "status" || request.Query.Limit != 5 {
		t.Fatalf("token did not preserve the canonical authorized request: %+v", request)
	}
	request.Query.Projection[0].Field = "mutated"
	request.Query.Filter.Values[0].Value[1] = 'X'
	again := token.Query()
	if again.Query.Projection[0].Field != "id" || string(again.Query.Filter.Values[0].Value) != `"active"` {
		t.Fatalf("token exposed mutable request aliases: %+v", again)
	}
}

func TestKeysetWorkControlsAreImmutableAndBoundToAuthorization(t *testing.T) {
	snapshot := keysetPolicySnapshot()
	profile, _ := snapshot.Profile("reader")
	allowTemporary, allowFilesort := true, false
	profile.Query.KeysetSelectShapes[0].AllowTemporaryTable = &allowTemporary
	profile.Query.KeysetSelectShapes[0].AllowFilesort = &allowFilesort
	snapshot = NewSnapshot(config.Config{
		Version: 1, HardLimits: snapshot.HardLimits(),
		Principals: map[string]config.Principal{"client": {Profiles: []string{"reader"}, Datasources: []string{"mysql"}}},
		Profiles:   map[string]config.Profile{"reader": profile},
	})
	allowTemporary, allowFilesort = false, true
	returned, _ := snapshot.Profile("reader")
	*returned.Query.KeysetSelectShapes[0].AllowTemporaryTable = false
	*returned.Query.KeysetSelectShapes[0].AllowFilesort = true
	token, err := snapshot.AuthorizeKeysetSelect(bindingForTest(t, snapshot, "client", "reader", "mysql", domain.OperationSelectKeyset), "basic-user", "mysql8", validateKeysetForPolicy(t, 5), domain.IdentifierSemantics{CaseInsensitiveSchemas: true, CaseInsensitiveObjects: true, CaseInsensitiveFields: true})
	if err != nil {
		t.Fatal(err)
	}
	if !token.AllowTemporaryTable() || token.AllowFilesort() {
		t.Fatal("work controls changed through mutable aliases")
	}
	defaultSnapshot := keysetPolicySnapshot()
	defaultToken, err := defaultSnapshot.AuthorizeKeysetSelect(bindingForTest(t, defaultSnapshot, "client", "reader", "mysql", domain.OperationSelectKeyset), "basic-user", "mysql8", validateKeysetForPolicy(t, 5), domain.IdentifierSemantics{CaseInsensitiveSchemas: true, CaseInsensitiveObjects: true, CaseInsensitiveFields: true})
	if err != nil {
		t.Fatal(err)
	}
	if defaultToken.AllowTemporaryTable() || defaultToken.AllowFilesort() {
		t.Fatal("omitted controls must default to false")
	}
}

func TestAuthorizeKeysetSelectRejectsShapeMismatchBeforeMintingToken(t *testing.T) {
	snapshot := keysetPolicySnapshot()
	validated := validateKeysetForPolicy(t, 5)
	request := validated.Request()
	request.Shape = "unknown_shape"
	invalid, err := queryspec.ValidateKeyset(queryspec.KeysetRequest{
		Kind: "keyset", Profile: request.Profile, Datasource: request.Datasource, Shape: request.Shape, Query: request.Query, Page: request.Page,
	}, 10, 8, 10, 4, 20, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.PrecheckKeysetSelect(bindingForTest(t, snapshot, "client", "reader", "mysql", domain.OperationSelectKeyset), invalid); err == nil {
		t.Fatal("unknown keyset shape passed the semantics-independent policy check")
	}
	if _, err := snapshot.AuthorizeKeysetSelect(bindingForTest(t, snapshot, "client", "reader", "mysql", domain.OperationSelectKeyset), "basic-user", "mysql8", invalid, domain.IdentifierSemantics{}); err == nil {
		t.Fatal("unknown keyset shape minted an authorization token")
	}
}

func TestPrecheckKeysetSelectCanonicalizesCommutativeFilterOrder(t *testing.T) {
	valueTypes := []string{"integer"}
	shape := config.KeysetSelectShape{
		Name: "orders_by_id", Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
		Projection: []config.KeysetShapeProjection{{Kind: "field", Field: "id"}},
		Filter: &config.AggregateShapeFilter{Kind: "group", Operator: "and", Expressions: []config.AggregateShapeFilter{
			{Kind: "predicate", Field: "a", Operator: "eq", ValueTypes: &valueTypes},
			{Kind: "predicate", Field: "c", Operator: "eq", ValueTypes: &valueTypes},
		}},
		OrderBy: []config.KeysetShapeOrder{{Field: "id", Direction: "asc"}}, MaximumLimit: 10,
		RequiredIndex: "PRIMARY", MaximumRowsExaminedPerScan: 100,
	}
	request := queryspec.KeysetRequest{
		Kind: "keyset", Profile: "reader", Datasource: "mysql", Shape: shape.Name,
		Query: queryspec.KeysetSpec{
			Source:     queryspec.ResourceRef{Schema: "app", Name: "orders"},
			Projection: []queryspec.Selection{{Kind: "field", Field: "id"}},
			Filter: &queryspec.Filter{Kind: "group", Operator: "and", Expressions: []queryspec.Filter{
				{Kind: "predicate", Field: "c", Operator: "eq", Values: []queryspec.TypedValue{{Type: "integer", Value: json.RawMessage(`1`)}}},
				{Kind: "predicate", Field: "a", Operator: "eq", Values: []queryspec.TypedValue{{Type: "integer", Value: json.RawMessage(`2`)}}},
			}},
			OrderBy: []queryspec.Sort{{Field: "id", Direction: "asc"}}, Limit: 5,
		},
		Page: queryspec.KeysetPage{Kind: "first"},
	}
	validated, err := queryspec.ValidateKeyset(request, 10, 8, 10, 4, 20, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !potentialKeysetShapeMatch(shape, validated) {
		t.Fatal("commutative filter order caused a false precheck denial")
	}
}

func keysetPolicySnapshot() *Snapshot {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 65536, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 8, MaxPredicates: 10,
		MaxExpressionDepth: 4, MaxParameters: 20, MaxRows: 100,
		MaxResultBytes: 65536, MaxOffset: 100, MaxConcurrency: 1,
	}
	valueTypes := []string{"string"}
	return NewSnapshot(config.Config{
		Version: 2, PolicyHash: "redacted-policy-hash", HardLimits: limits,
		Principals: map[string]config.Principal{"client": {Profiles: []string{"reader"}, Datasources: []string{"mysql"}}},
		Profiles: map[string]config.Profile{"reader": {
			Datasources: []string{"mysql"}, Operations: []domain.Operation{domain.OperationSelectKeyset}, Limits: limits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"app"}},
				Objects: config.PatternPolicy{Allow: []string{"app.orders"}},
				Fields:  config.PatternPolicy{Allow: []string{"app.orders.id", "app.orders.status"}},
			},
			Query: config.QueryPolicy{
				AllowFiltering: true, AllowSorting: true, AllowedFilterOperators: []string{"eq"},
				KeysetSelectShapes: []config.KeysetSelectShape{{
					Name: "orders_by_id", Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
					Projection: []config.KeysetShapeProjection{
						{Kind: "field", Field: "id"}, {Kind: "field", Field: "status"},
					},
					Filter: &config.AggregateShapeFilter{
						Kind: "predicate", Field: "status", Operator: "eq", ValueTypes: &valueTypes,
					},
					OrderBy:      []config.KeysetShapeOrder{{Field: "id", Direction: "asc"}},
					MaximumLimit: 10, RequiredIndex: "PRIMARY", MaximumRowsExaminedPerScan: 100,
				}},
			},
		}},
	})
}

func validateKeysetForPolicy(t *testing.T, limit int) queryspec.ValidatedKeyset {
	t.Helper()
	request := queryspec.KeysetRequest{
		Kind: "keyset", Profile: "reader", Datasource: "mysql", Shape: "orders_by_id",
		Query: queryspec.KeysetSpec{
			Source: queryspec.ResourceRef{Schema: "APP", Name: "ORDERS"},
			Projection: []queryspec.Selection{
				{Kind: "field", Field: "ID"}, {Kind: "field", Field: "STATUS"},
			},
			Filter: &queryspec.Filter{
				Kind: "predicate", Field: "STATUS", Operator: "eq",
				Values: []queryspec.TypedValue{{Type: "string", Value: json.RawMessage(`"active"`)}},
			},
			OrderBy: []queryspec.Sort{{Field: "ID", Direction: "asc"}}, Limit: limit,
		},
		Page: queryspec.KeysetPage{Kind: "first"},
	}
	validated, err := queryspec.ValidateKeyset(request, 10, 8, 10, 4, 20, 100)
	if err != nil {
		t.Fatal(err)
	}
	return validated
}

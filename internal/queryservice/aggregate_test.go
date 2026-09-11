package queryservice

import (
	"context"
	"database/sql"
	"testing"

	"github.com/sigalx/quordon/internal/audit"
	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryspec"
	"github.com/sigalx/quordon/internal/secrets"
)

type successfulAggregateAdapter struct {
	calls          int
	nameCalls      int
	semanticsCalls int
}

func (a *successfulAggregateAdapter) Name() string {
	a.nameCalls++
	return "aggregate-successful"
}
func (*successfulAggregateAdapter) Capabilities() []domain.Operation {
	return []domain.Operation{domain.OperationAggregate}
}
func (*successfulAggregateAdapter) Validate(context.Context, *sql.DB) error { return nil }

func (a *successfulAggregateAdapter) IdentifierSemantics(context.Context, *sql.DB) (domain.IdentifierSemantics, error) {
	a.semanticsCalls++
	return domain.IdentifierSemantics{CaseInsensitiveFields: true}, nil
}
func (*successfulAggregateAdapter) Open(string, config.Datasource) (*sql.DB, error) {
	return sql.OpenDB(inertConnector{}), nil
}
func (*successfulAggregateAdapter) Explain(context.Context, *sql.DB, policy.AuthorizedQuery) (database.ExplainResult, error) {
	panic("Explain must not be called")
}
func (a *successfulAggregateAdapter) Aggregate(
	_ context.Context, _ *sql.DB, token policy.AuthorizedAggregate, envelopeBaseBytes int,
) (database.AggregateResult, error) {
	a.calls++
	if token.Operation() != domain.OperationAggregate || token.ShapeName() != "orders_total" ||
		token.RequiredIndex() != "PRIMARY" || envelopeBaseBytes <= 0 {
		panic("aggregate adapter received an invalid authorization boundary")
	}
	value := "2"
	return database.AggregateResult{
		Mode: queryspec.AggregateModeScalar,
		Columns: []database.ResultColumn{{
			Name: "total", Type: "integer", Encoding: "string", Nullable: false,
		}},
		Rows: [][]*string{{&value}}, RowCount: 1, ResultBytes: envelopeBaseBytes + 32,
	}, nil
}

func TestAggregateSuccessIsAuthorizedBoundedAndAudited(t *testing.T) {
	cfg := aggregateServiceConfig("aggregate-successful")
	adapter := &successfulAggregateAdapter{}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatalf("database problems = %v", problems)
	}
	defer manager.Close()
	sink := &audit.MemorySink{}
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")

	result, err := service.Aggregate(
		context.Background(), "request", "query", "client", "credential", 1,
		queryspec.AggregateRequest{Profile: "analytics", Query: aggregateScalarSpec()},
	)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.calls != 1 || result.Mode != queryspec.AggregateModeScalar || result.RowCount != 1 ||
		len(result.Rows) != 1 || result.Rows[0][0] == nil || *result.Rows[0][0] != "2" {
		t.Fatalf("result = %+v, adapter calls = %d", result, adapter.calls)
	}
	if len(sink.Events) != 2 || sink.Events[0].Decision != "allow" || sink.Events[1].Outcome != "success" {
		t.Fatalf("audit events = %+v", sink.Events)
	}
	completion := sink.Events[1]
	if completion.Operation != string(domain.OperationAggregate) || completion.Metadata["mode"] != "scalar" ||
		completion.Metadata["aggregate_shape"] != "orders_total" || completion.Metadata["row_count"] != 1 ||
		completion.QueryShapeHash == "" || len(completion.Resources) != 1 {
		t.Fatalf("aggregate completion audit = %+v", completion)
	}
}

func TestAggregateShapeDenialHappensBeforeAdapterAction(t *testing.T) {
	cfg := aggregateServiceConfig("aggregate-successful")
	adapter := &successfulAggregateAdapter{}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	defer manager.Close()
	sink := &audit.MemorySink{}
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")

	spec := aggregateScalarSpec()
	spec.Projection[0].Alias = "Different"
	_, err := service.Aggregate(
		context.Background(), "request", "query", "client", "credential", 1,
		queryspec.AggregateRequest{Profile: "analytics", Query: spec},
	)
	assertServiceErrorKind(t, err, ErrorDenied)
	validated, validateErr := queryspec.ValidateAggregate(spec, 10, 10, 10, 10, 4, 20, 100)
	if validateErr != nil {
		t.Fatal(validateErr)
	}
	normalized, normalizeErr := queryspec.NormalizeAggregateIdentifiers(
		validated, domain.IdentifierSemantics{CaseInsensitiveFields: true},
	)
	if normalizeErr != nil {
		t.Fatal(normalizeErr)
	}
	wantHash := queryspec.AggregateShapeHash(normalized.Spec())
	if adapter.calls != 0 || len(sink.Events) != 1 || sink.Events[0].Decision != "deny" ||
		sink.Events[0].ReasonCode != policy.ReasonDeniedQueryFeature ||
		sink.Events[0].QueryShapeHash != wantHash {
		t.Fatalf("adapter calls = %d, audit events = %+v", adapter.calls, sink.Events)
	}
}

func TestAggregateOutputCollisionFailsBeforeIdentifierSemantics(t *testing.T) {
	cfg := aggregateServiceConfig("aggregate-successful")
	adapter := &successfulAggregateAdapter{}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	defer manager.Close()
	service := New(policy.NewSnapshot(cfg), manager, &audit.MemorySink{}, cfg, "test")

	spec := aggregateScalarSpec()
	spec.Projection = append(spec.Projection, queryspec.AggregateOutput{
		Kind: "measure", Function: "count_all", Alias: "TOTAL",
	})
	_, err := service.Aggregate(
		context.Background(), "request", "query", "client", "credential", 1,
		queryspec.AggregateRequest{Profile: "analytics", Query: spec},
	)
	assertServiceErrorKind(t, err, ErrorInvalid)
	if adapter.semanticsCalls != 0 || adapter.calls != 0 {
		t.Fatalf("identifier semantics calls = %d, aggregate calls = %d", adapter.semanticsCalls, adapter.calls)
	}
}

func TestTimeBucketFeatureMismatchReturnsNotImplementedWithoutDatasourceCall(t *testing.T) {
	cfg := aggregateServiceConfig("aggregate-successful")
	profile := cfg.Profiles["analytics"]
	profile.Query.AllowGroupBy = true
	profile.Query.AggregateShapes = []config.AggregateShape{{
		Name: "orders_by_day", Mode: queryspec.AggregateModeGrouped,
		Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
		Projection: []config.AggregateShapeOutput{
			{Kind: "time_bucket", Field: "created_at", Unit: "day", Timezone: "UTC", Alias: "created_day"},
			{Kind: "measure", Function: "count_all", Alias: "total"},
		},
		MaximumLimit: 10, RequiredIndex: "idx_created_at", MaximumRowsExaminedPerScan: 100,
		AllowTemporaryTable: queryServiceBoolPointer(true), AllowFilesort: queryServiceBoolPointer(true),
	}}
	profile.Resources.Fields.Allow = append(profile.Resources.Fields.Allow, "app.orders.created_at")
	cfg.Profiles["analytics"] = profile
	adapter := &successfulAggregateAdapter{}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	defer manager.Close()
	service := New(policy.NewSnapshot(cfg), manager, &audit.MemorySink{}, cfg, "test")
	limit := 5
	_, err := service.Aggregate(
		context.Background(), "request", "query", "client", "credential", 1,
		queryspec.AggregateRequest{Profile: "analytics", Query: queryspec.AggregateSpec{
			Mode: queryspec.AggregateModeGrouped, Source: queryspec.ResourceRef{Schema: "app", Name: "orders"},
			Projection: []queryspec.AggregateOutput{
				{Kind: "time_bucket", Field: "created_at", Unit: "day", Timezone: "UTC", Alias: "created_day"},
				{Kind: "measure", Function: "count_all", Alias: "total"},
			}, Limit: &limit,
		}},
	)
	assertServiceErrorKind(t, err, ErrorNotImplemented)
	if adapter.semanticsCalls != 0 || adapter.calls != 0 {
		t.Fatalf("feature mismatch reached datasource: semantics=%d aggregate=%d", adapter.semanticsCalls, adapter.calls)
	}
}

func queryServiceBoolPointer(value bool) *bool { return &value }

func TestAggregateCapacityFailureWritesCompletionAudit(t *testing.T) {
	cfg := aggregateServiceConfig("aggregate-successful")
	adapter := &successfulAggregateAdapter{}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	defer manager.Close()
	sink := &audit.MemorySink{}
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")

	release, ok := service.acquireCapacity("analytics")
	if !ok {
		t.Fatal("failed to occupy aggregate execution capacity")
	}
	defer release()

	_, err := service.Aggregate(
		context.Background(), "request", "query", "client", "credential", 1,
		queryspec.AggregateRequest{Profile: "analytics", Query: aggregateScalarSpec()},
	)
	assertServiceErrorKind(t, err, ErrorCapacity)
	if adapter.calls != 0 {
		t.Fatalf("adapter calls = %d, want 0", adapter.calls)
	}
	if len(sink.Events) != 2 || sink.Events[0].Decision != "allow" {
		t.Fatalf("audit events = %+v", sink.Events)
	}
	completion := sink.Events[1]
	if completion.Type != "query_completion" || completion.Outcome != "error" ||
		completion.ErrorKind != string(ErrorCapacity) || completion.DurationMS == nil ||
		completion.QueryShapeHash == "" || len(completion.Resources) != 1 ||
		completion.Metadata["aggregate_shape"] != "orders_total" {
		t.Fatalf("capacity completion audit = %+v", completion)
	}
}

func aggregateServiceConfig(adapter string) config.Config {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 65536, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10, MaxPredicates: 10,
		MaxExpressionDepth: 4, MaxParameters: 20, MaxRows: 100,
		MaxResultBytes: 65536, MaxOffset: 0, MaxConcurrency: 1,
	}
	return config.Config{
		Version: 1, PolicyHash: "hash", HardLimits: limits,
		Principals:  map[string]config.Principal{"client": {Profiles: []string{"analytics"}}},
		Datasources: map[string]config.Datasource{"db": {Adapter: adapter, DSN: "opaque"}},
		Profiles: map[string]config.Profile{"analytics": {
			Datasource: "db", Operations: []domain.Operation{domain.OperationAggregate}, Limits: limits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"app"}},
				Objects: config.PatternPolicy{Allow: []string{"app.orders"}},
			},
			Query: config.QueryPolicy{
				AllowedAggregates: []string{"count"},
				AggregateShapes: []config.AggregateShape{{
					Name: "orders_total", Mode: queryspec.AggregateModeScalar,
					Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
					Projection: []config.AggregateShapeOutput{{
						Kind: "measure", Function: "count_all", Alias: "total",
					}},
					RequiredIndex: "PRIMARY", MaximumRowsExaminedPerScan: 10,
				}},
			},
		}},
	}
}

func aggregateScalarSpec() queryspec.AggregateSpec {
	return queryspec.AggregateSpec{
		Mode:   queryspec.AggregateModeScalar,
		Source: queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.AggregateOutput{{
			Kind: "measure", Function: "count_all", Alias: "total",
		}},
	}
}

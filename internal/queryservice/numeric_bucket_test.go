package queryservice

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/sigalx/quordon/internal/audit"
	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryspec"
	"github.com/sigalx/quordon/internal/secrets"
)

type numericServiceAdapter struct {
	successfulAggregateAdapter
	enabled bool
	failure database.ErrorKind
}

func (a *numericServiceAdapter) Features() []domain.AdapterFeature {
	if a.enabled {
		return []domain.AdapterFeature{domain.FeatureNumericBucketExact}
	}
	return nil
}
func (a *numericServiceAdapter) Aggregate(_ context.Context, _ *sql.DB, token policy.AuthorizedAggregate, base int) (database.AggregateResult, error) {
	a.calls++
	if token.Operation() != domain.OperationAggregate || token.NumericBoundaries()["id_bucket"][1] != "100" || token.ParameterCount() != 5 {
		panic("invalid numeric authorization")
	}
	if a.failure != "" {
		return database.AggregateResult{}, &database.Error{Kind: a.failure}
	}
	value, count := "1", "2"
	return database.AggregateResult{Mode: "grouped", Columns: []database.ResultColumn{{Name: "id_bucket", Type: "integer", Encoding: "string", Nullable: false}, {Name: "total", Type: "integer", Encoding: "string", Nullable: false}}, Rows: [][]*string{{&value, &count}}, RowCount: 1, ResultBytes: base + 64}, nil
}

func numericServiceFixture() (config.Config, queryspec.AggregateRequest) {
	cfg := aggregateServiceConfig("aggregate-successful")
	p := cfg.Profiles["analytics"]
	p.Operations = append(p.Operations, domain.OperationListQueryShapes)
	p.Query.AllowGroupBy = true
	p.Resources.Fields.Allow = []string{"app.orders.id"}
	p.Query.AggregateShapes = append(p.Query.AggregateShapes, config.AggregateShape{Name: "numeric_shape", Mode: "grouped", Source: config.AggregateShapeSource{Schema: "app", Name: "orders"}, Projection: []config.AggregateShapeOutput{{Kind: "numeric_bucket", Field: "id", Alias: "id_bucket", Boundaries: []string{"0", "100"}}, {Kind: "measure", Function: "count_all", Alias: "total"}}, MaximumLimit: 10, MaximumRowsExaminedPerScan: 100, AllowTemporaryTable: queryServiceBoolPointer(true), AllowFilesort: queryServiceBoolPointer(true)})
	cfg.Profiles["analytics"] = p
	cfg.Authentication.Basic.Users = map[string]config.BasicUser{"credential": {Principal: "client"}}
	limit := 5
	return cfg, queryspec.AggregateRequest{Profile: "analytics", Datasource: "db", Query: queryspec.AggregateSpec{Mode: "grouped", Source: queryspec.ResourceRef{Schema: "app", Name: "orders"}, Projection: []queryspec.AggregateOutput{{Kind: "numeric_bucket", Field: "id", Alias: "id_bucket"}, {Kind: "measure", Function: "count_all", Alias: "total"}}, Limit: &limit}}
}

func TestNumericCapabilityAbsenceBlocksExecutionAndFullDiscoveryWithoutCalls(t *testing.T) {
	cfg, request := numericServiceFixture()
	adapter := &numericServiceAdapter{}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	defer manager.Close()
	sink := &audit.MemorySink{}
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")
	if problems, err := service.InitializeQueryShapeDiscovery(context.Background()); err != nil || len(problems) != 0 {
		t.Fatalf("discovery initialization %v %v", problems, err)
	}
	_, err := service.Aggregate(context.Background(), "request", "query", "client", "credential", 1, request)
	assertServiceErrorKind(t, err, ErrorNotImplemented)
	payload, err := service.ListQueryShapes(context.Background(), "request", "client", "credential", "analytics", "db")
	assertServiceErrorKind(t, err, ErrorNotImplemented)
	if len(payload) != 0 || adapter.calls != 0 || adapter.semanticsCalls != 0 || len(service.queryShapes) != 0 {
		t.Fatalf("partial disclosure or datasource calls: %s calls=%d semantics=%d", payload, adapter.calls, adapter.semanticsCalls)
	}
	auditJSON, _ := json.Marshal(sink.Events)
	if len(sink.Events) != 2 {
		t.Fatalf("audit=%s", auditJSON)
	}
}

func TestNumericBucketEarlySemanticFailureAndPolicyDeny(t *testing.T) {
	for _, kind := range []string{"alias collision", "wrong order", "field deny", "grouping deny", "parameters"} {
		t.Run(kind, func(t *testing.T) {
			cfg, request := numericServiceFixture()
			p := cfg.Profiles["analytics"]
			switch kind {
			case "alias collision":
				request.Query.Projection[1].Alias = "ID_BUCKET"
			case "wrong order":
				request.Query.OrderBy = []queryspec.AggregateSort{{Kind: "numeric_bucket", Alias: "missing", Direction: "asc"}}
				p.Query.AllowSorting = true
			case "field deny":
				p.Resources.Fields.Deny = []string{"app.orders.id"}
			case "grouping deny":
				p.Query.AllowGroupBy = false
			case "parameters":
				p.Limits.MaxParameters = 4
			}
			cfg.Profiles["analytics"] = p
			adapter := &numericServiceAdapter{enabled: true}
			manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
			if len(problems) != 0 {
				t.Fatal(problems)
			}
			defer manager.Close()
			service := New(policy.NewSnapshot(cfg), manager, &audit.MemorySink{}, cfg, "test")
			_, err := service.Aggregate(context.Background(), "request", "query", "client", "credential", 1, request)
			if err == nil || adapter.calls != 0 {
				t.Fatalf("failure=%v datasource calls=%d", err, adapter.calls)
			}
			if (kind == "alias collision" || kind == "wrong order") && adapter.semanticsCalls != 0 {
				t.Fatal("collision reached identifier semantics")
			}
		})
	}
}

func TestNumericBucketExecutionKeepsErrorMappingAndAudit(t *testing.T) {
	for _, kind := range []database.ErrorKind{"", database.ErrorInvalid, database.ErrorTimeout, database.ErrorUnavailable, database.ErrorResultTooLarge, database.ErrorUpstream} {
		t.Run(string(kind), func(t *testing.T) {
			cfg, request := numericServiceFixture()
			adapter := &numericServiceAdapter{enabled: true, failure: kind}
			manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
			if len(problems) != 0 {
				t.Fatal(problems)
			}
			defer manager.Close()
			sink := &audit.MemorySink{}
			service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")
			result, err := service.Aggregate(context.Background(), "request", "query", "client", "credential", 1, request)
			if kind == "" {
				if err != nil || result.RowCount != 1 {
					t.Fatalf("result=%+v error=%v", result, err)
				}
			} else {
				expected := map[database.ErrorKind]ErrorKind{database.ErrorInvalid: ErrorInvalid, database.ErrorTimeout: ErrorTimeout, database.ErrorUnavailable: ErrorUnavailable, database.ErrorResultTooLarge: ErrorResultTooLarge, database.ErrorUpstream: ErrorUpstream}[kind]
				assertServiceErrorKind(t, err, expected)
			}
			if adapter.calls != 1 || len(sink.Events) != 2 || sink.Events[0].Decision != "allow" || sink.Events[1].DurationMS == nil || sink.Events[1].QueryShapeHash == "" || sink.Events[1].Metadata["aggregate_shape"] != "numeric_shape" {
				t.Fatalf("calls=%d audit=%+v", adapter.calls, sink.Events)
			}
		})
	}
}

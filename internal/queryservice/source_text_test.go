package queryservice

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sigalx/quordon/internal/audit"
	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryspec"
	"github.com/sigalx/quordon/internal/secrets"
)

func TestSourceTextDenialAndMissingFeatureBeforeDatasourceCalls(t *testing.T) {
	for _, allow := range []bool{false, true} {
		for _, operation := range []domain.Operation{domain.OperationSelect, domain.OperationExplainSelect, domain.OperationAggregate, domain.OperationSelectKeyset} {
			adapter := &dataAdapter{}
			limits := domain.Limits{DeadlineMS: 1000, MaxRequestBytes: 65536, MaxProjectionFields: 10, MaxGroupByFields: 10, MaxOrderByFields: 8, MaxPredicates: 20, MaxExpressionDepth: 8, MaxParameters: 30, MaxRows: 10, MaxResultBytes: 65536, MaxConcurrency: 1}
			cfg := metadataTestConfig(limits, adapter.Name())
			profile := cfg.Profiles["metadata"]
			profile.Operations = []domain.Operation{operation}
			profile.Query.AllowSourceText = allow
			cfg.Profiles["metadata"] = profile
			manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
			if len(problems) != 0 {
				t.Fatal(problems)
			}
			sink := &audit.MemorySink{}
			service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")
			request := queryspec.Request{Profile: "metadata", Datasource: "db", Query: queryspec.Spec{Source: queryspec.ResourceRef{Schema: "app", Name: "orders"}, Projection: []queryspec.Selection{{Kind: "field", Field: "id", Representation: queryspec.RepresentationSourceText}}}}
			run := func() error {
				var err error
				switch operation {
				case domain.OperationSelect:
					_, err = service.Select(context.Background(), "request", "query", "client", "credential", 1, request)
				case domain.OperationExplainSelect:
					_, err = service.Explain(context.Background(), "request", "query", "client", "credential", 1, request)
				case domain.OperationAggregate:
					aggregate := queryspec.AggregateRequest{Profile: request.Profile, Datasource: request.Datasource, Query: queryspec.AggregateSpec{
						Mode: "scalar", Source: request.Query.Source,
						Projection: []queryspec.AggregateOutput{{Kind: "measure", Function: "count_all", Alias: "total"}},
						Filter:     &queryspec.Filter{Kind: "predicate", Field: "id", Operator: "eq", Representation: queryspec.RepresentationSourceText, Values: []queryspec.TypedValue{{Type: "string", Value: json.RawMessage(`"0000-00-00"`)}}},
					}}
					_, err = service.Aggregate(context.Background(), "request", "query", "client", "credential", 1, aggregate)
				case domain.OperationSelectKeyset:
					keyset := queryspec.KeysetRequest{Kind: "keyset", Profile: request.Profile, Datasource: request.Datasource, Shape: "events_page", Query: queryspec.KeysetSpec{
						Source: request.Query.Source, Projection: request.Query.Projection,
						OrderBy: []queryspec.Sort{{Field: "id", Direction: "asc", Representation: queryspec.RepresentationSourceText}}, Limit: 2,
					}, Page: queryspec.KeysetPage{Kind: "first"}}
					_, err = service.SelectKeyset(context.Background(), "request", "query", "client", "credential", 1, keyset)
				}
				return err
			}
			err := run()
			want := ErrorDenied
			if allow {
				want = ErrorNotImplemented
			}
			assertServiceErrorKind(t, err, want)
			if adapter.semanticsCalls != 0 {
				t.Fatal("diagnostic precheck accessed datasource")
			}
			if len(sink.Events) != 1 || sink.Events[0].QueryShapeHash == "" {
				t.Fatal("diagnostic precheck missing bounded audit")
			}
			if allow && sink.Events[0].DurationMS == nil {
				t.Fatal("unsupported diagnostic completion omitted duration")
			}
			sink.Err = audit.ErrUnavailable
			assertServiceErrorKind(t, run(), ErrorServiceUnavailable)
			if adapter.semanticsCalls != 0 {
				t.Fatal("failed diagnostic audit accessed datasource")
			}
			manager.Close()
		}
	}
}

type sourceTextStartupAdapter struct {
	dataAdapter
	openCalls int
}

func (a *sourceTextStartupAdapter) Open(dsn string, datasource config.Datasource) (*sql.DB, error) {
	a.openCalls++
	return a.dataAdapter.Open(dsn, datasource)
}

func TestSourceTextShapeFeatureMismatchRejectsStartup(t *testing.T) {
	adapter := &sourceTextStartupAdapter{}
	cfg := metadataTestConfig(domain.Limits{}, adapter.Name())
	profile := cfg.Profiles["metadata"]
	profile.Query = config.QueryPolicy{AllowSourceText: true, KeysetSelectShapes: []config.KeysetSelectShape{{Projection: []config.KeysetShapeProjection{{Kind: "field", Field: "id", Representation: queryspec.RepresentationSourceText}}}}}
	cfg.Profiles["metadata"] = profile
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	defer manager.Close()
	if len(problems) != 1 || !database.IsConfigurationError(problems[0]) || !strings.Contains(problems[0].Error(), "source_text") {
		t.Fatalf("incompatible diagnostic startup accepted: %v", problems)
	}
	if adapter.semanticsCalls != 0 || adapter.openCalls != 0 {
		t.Fatal("incompatible feature opened or probed datasource")
	}
}

func TestSourceTextAggregateRepresentationMismatchBeforeDatasourceCalls(t *testing.T) {
	for _, field := range []string{"event_date", "EVENT_DATE"} {
		adapter := &dataAdapter{}
		limits := domain.Limits{DeadlineMS: 1000, MaxRequestBytes: 65536, MaxProjectionFields: 10, MaxGroupByFields: 10, MaxOrderByFields: 8, MaxPredicates: 20, MaxExpressionDepth: 8, MaxParameters: 30, MaxRows: 10, MaxResultBytes: 65536, MaxConcurrency: 1}
		cfg := metadataTestConfig(limits, adapter.Name())
		profile := cfg.Profiles["metadata"]
		profile.Operations = []domain.Operation{domain.OperationAggregate}
		profile.Query.AllowSourceText = true
		cfg.Profiles["metadata"] = profile
		manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
		if len(problems) != 0 {
			t.Fatal(problems)
		}
		limit := 2
		request := queryspec.AggregateRequest{Profile: "metadata", Datasource: "db", Query: queryspec.AggregateSpec{
			Mode: "grouped", Source: queryspec.ResourceRef{Schema: "app", Name: "orders"}, Limit: &limit,
			Projection: []queryspec.AggregateOutput{{Kind: "dimension", Field: "event_date", Representation: queryspec.RepresentationSourceText}, {Kind: "measure", Function: "count_all", Alias: "total"}},
			OrderBy:    []queryspec.AggregateSort{{Kind: "dimension", Field: field, Direction: "asc"}},
		}}
		service := New(policy.NewSnapshot(cfg), manager, &audit.MemorySink{}, cfg, "test")
		_, err := service.Aggregate(context.Background(), "request", "query", "client", "credential", 1, request)
		assertServiceErrorKind(t, err, ErrorInvalid)
		if adapter.semanticsCalls != 0 {
			t.Fatal("known diagnostic representation mismatch accessed datasource")
		}
		manager.Close()
	}
}

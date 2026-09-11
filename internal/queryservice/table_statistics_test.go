package queryservice

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/sigalx/quordon/internal/audit"
	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryspec"
	"github.com/sigalx/quordon/internal/secrets"
)

type statisticsTestAdapter struct {
	capabilities    []domain.Operation
	semanticsCalls  int
	statisticsCalls int
	result          *database.ObjectStatisticsResult
}

func (*statisticsTestAdapter) Name() string { return "statistics-test" }
func (a *statisticsTestAdapter) Capabilities() []domain.Operation {
	return append([]domain.Operation(nil), a.capabilities...)
}
func (*statisticsTestAdapter) Validate(context.Context, *sql.DB) error { return nil }
func (a *statisticsTestAdapter) IdentifierSemantics(context.Context, *sql.DB) (domain.IdentifierSemantics, error) {
	a.semanticsCalls++
	return domain.IdentifierSemantics{}, nil
}
func (*statisticsTestAdapter) Open(string, config.Datasource) (*sql.DB, error) {
	return sql.OpenDB(inertConnector{}), nil
}
func (*statisticsTestAdapter) Explain(context.Context, *sql.DB, policy.AuthorizedQuery) (database.ExplainResult, error) {
	panic("unexpected explain")
}
func (a *statisticsTestAdapter) DescribeObjectStatistics(
	_ context.Context, _ *sql.DB, _ policy.AuthorizedObjectStatistics, envelopeBaseBytes int,
) (database.ObjectStatisticsResult, error) {
	a.statisticsCalls++
	if a.result != nil {
		return *a.result, nil
	}
	return database.ObjectStatisticsResult{
		ObservedAt: "2026-09-02T12:00:00Z", Engine: "InnoDB",
		Table: database.TableStatistics{}, Partitioning: database.PartitioningResult{Kind: "none"},
		ResultBytes: envelopeBaseBytes,
	}, nil
}

func TestObjectStatisticsRejectsAdapterResponseOutsideOpenAPI(t *testing.T) {
	adapter := &statisticsTestAdapter{
		capabilities: []domain.Operation{domain.OperationDescribeObjectStatistics},
		result: &database.ObjectStatisticsResult{
			ObservedAt: "2026-09-02T12:00:00Z", Engine: "MyISAM",
			Partitioning: database.PartitioningResult{Kind: "none"},
		},
	}
	service, sink, closeManager := newStatisticsTestService(t, adapter, 4096)
	defer closeManager()
	_, err := service.DescribeObjectStatistics(
		context.Background(), "request", "client", "credential", "statistics",
		queryspec.ResourceRef{Schema: "app", Name: "orders"},
	)
	assertServiceErrorKind(t, err, ErrorInternal)
	if adapter.statisticsCalls != 1 || len(sink.Events) != 2 || sink.Events[0].Decision != "allow" ||
		sink.Events[1].Outcome != "error" || sink.Events[1].ErrorKind != "internal" {
		t.Fatalf("invalid adapter result calls=%d events=%+v", adapter.statisticsCalls, sink.Events)
	}
}

func TestObjectStatisticsResultValidationIsClosed(t *testing.T) {
	valid := database.ObjectStatisticsResult{
		ObservedAt: "2026-09-02T12:00:00Z", Engine: "InnoDB",
		Table: database.TableStatistics{
			EstimatedRows: &database.UnsignedMetric{Value: "0", Estimated: true},
			AutoIncrement: &database.UnsignedMetric{Value: "18446744073709551615", Estimated: false},
		},
		Partitioning: database.PartitioningResult{Kind: "none"},
	}
	if err := validateObjectStatisticsResult(valid); err != nil {
		t.Fatalf("valid result rejected: %v", err)
	}
	fixtures := []struct {
		name   string
		mutate func(*database.ObjectStatisticsResult)
	}{
		{name: "oversized timestamp", mutate: func(result *database.ObjectStatisticsResult) {
			result.ObservedAt = "2026-09-02T12:00:00.0000000000Z"
		}},
		{name: "wrong estimate flag", mutate: func(result *database.ObjectStatisticsResult) {
			result.Table.EstimatedRows.Estimated = false
		}},
		{name: "noncanonical integer", mutate: func(result *database.ObjectStatisticsResult) {
			result.Table.EstimatedRows.Value = "00"
		}},
		{name: "hidden branch member", mutate: func(result *database.ObjectStatisticsResult) {
			result.Partitioning.Method = "range"
		}},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			candidate := valid
			metric := *valid.Table.EstimatedRows
			candidate.Table.EstimatedRows = &metric
			fixture.mutate(&candidate)
			if err := validateObjectStatisticsResult(candidate); err == nil {
				t.Fatal("invalid result unexpectedly passed")
			}
		})
	}
}

func TestObjectStatisticsChecksCapabilityBeforeDatasource(t *testing.T) {
	adapter := &statisticsTestAdapter{}
	service, sink, closeManager := newStatisticsTestService(t, adapter, 4096)
	defer closeManager()
	_, err := service.DescribeObjectStatistics(
		context.Background(), "request", "client", "credential", "statistics",
		queryspec.ResourceRef{Schema: "app", Name: "orders"},
	)
	assertServiceErrorKind(t, err, ErrorNotImplemented)
	if adapter.semanticsCalls != 0 || adapter.statisticsCalls != 0 {
		t.Fatalf("adapter calls = semantics:%d statistics:%d", adapter.semanticsCalls, adapter.statisticsCalls)
	}
	if len(sink.Events) != 1 || sink.Events[0].Outcome != "not_implemented" || len(sink.Events[0].Resources) != 0 {
		t.Fatalf("unsupported completion = %+v", sink.Events)
	}
}

func TestObjectStatisticsRejectsInvalidCoordinatesBeforeDatasource(t *testing.T) {
	adapter := &statisticsTestAdapter{capabilities: []domain.Operation{domain.OperationDescribeObjectStatistics}}
	service, sink, closeManager := newStatisticsTestService(t, adapter, 4096)
	defer closeManager()
	_, err := service.DescribeObjectStatistics(
		context.Background(), "request", "client", "credential", "statistics",
		queryspec.ResourceRef{Schema: "bad-name", Name: "orders"},
	)
	assertServiceErrorKind(t, err, ErrorInvalid)
	if adapter.semanticsCalls != 0 || adapter.statisticsCalls != 0 || len(sink.Events) != 0 {
		t.Fatalf(
			"invalid coordinates reached operation path: semantics=%d statistics=%d events=%+v",
			adapter.semanticsCalls, adapter.statisticsCalls, sink.Events,
		)
	}
}

func TestObjectStatisticsDeniesUnassignedProfileBeforeDatasource(t *testing.T) {
	adapter := &statisticsTestAdapter{capabilities: []domain.Operation{domain.OperationDescribeObjectStatistics}}
	service, sink, closeManager := newStatisticsTestService(t, adapter, 4096)
	defer closeManager()
	_, err := service.DescribeObjectStatistics(
		context.Background(), "request", "client", "credential", "unassigned",
		queryspec.ResourceRef{Schema: "app", Name: "orders"},
	)
	assertServiceErrorKind(t, err, ErrorDenied)
	if adapter.semanticsCalls != 0 || adapter.statisticsCalls != 0 || len(sink.Events) != 1 ||
		sink.Events[0].ReasonCode != policy.ReasonDeniedOperation || sink.Events[0].PolicyProfile != "" {
		t.Fatalf(
			"profile denial crossed the pre-token boundary: semantics=%d statistics=%d events=%+v",
			adapter.semanticsCalls, adapter.statisticsCalls, sink.Events,
		)
	}
}

func TestObjectStatisticsDenialAndEnvelopeOverflowDoNotReadResource(t *testing.T) {
	adapter := &statisticsTestAdapter{capabilities: []domain.Operation{domain.OperationDescribeObjectStatistics}}
	service, sink, closeManager := newStatisticsTestService(t, adapter, 1)
	defer closeManager()
	_, err := service.DescribeObjectStatistics(
		context.Background(), "denied", "client", "credential", "statistics",
		queryspec.ResourceRef{Schema: "app", Name: "secret"},
	)
	assertServiceErrorKind(t, err, ErrorNotFound)
	if adapter.statisticsCalls != 0 || len(sink.Events) != 1 ||
		sink.Events[0].ReasonCode != policy.ReasonDeniedResource || len(sink.Events[0].Resources) != 0 {
		t.Fatalf("resource denial calls=%d events=%+v", adapter.statisticsCalls, sink.Events)
	}

	sink.Events = nil
	_, err = service.DescribeObjectStatistics(
		context.Background(), "oversized", "client", "credential", "statistics",
		queryspec.ResourceRef{Schema: "app", Name: "orders"},
	)
	assertServiceErrorKind(t, err, ErrorResultTooLarge)
	if adapter.statisticsCalls != 0 || len(sink.Events) != 2 || sink.Events[0].Decision != "allow" ||
		sink.Events[1].ErrorKind != string(ErrorResultTooLarge) {
		t.Fatalf("envelope overflow calls=%d events=%+v", adapter.statisticsCalls, sink.Events)
	}
}

func newStatisticsTestService(
	t *testing.T, adapter *statisticsTestAdapter, maxResultBytes int,
) (*Service, *audit.MemorySink, func()) {
	t.Helper()
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 1024, MaxProjectionFields: 1,
		MaxGroupByFields: 1, MaxOrderByFields: 1, MaxPredicates: 1,
		MaxExpressionDepth: 1, MaxParameters: 2, MaxRows: 1,
		MaxResultBytes: maxResultBytes, MaxOffset: 0, MaxConcurrency: 1,
	}
	cfg := config.Config{
		Version: 1, PolicyHash: "policy-hash", HardLimits: limits,
		Principals:  map[string]config.Principal{"client": {Profiles: []string{"statistics"}}},
		Datasources: map[string]config.Datasource{"db": {Adapter: adapter.Name(), DSN: "opaque"}},
		Profiles: map[string]config.Profile{"statistics": {
			Datasource: "db", Operations: []domain.Operation{domain.OperationDescribeObjectStatistics},
			Limits: limits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"app"}},
				Objects: config.PatternPolicy{Allow: []string{"app.orders"}},
			},
		}},
	}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatalf("database problems = %v", problems)
	}
	sink := &audit.MemorySink{}
	return New(policy.NewSnapshot(cfg), manager, sink, cfg, "test"), sink, func() {
		if err := manager.Close(); err != nil && !errors.Is(err, sql.ErrConnDone) {
			t.Fatalf("close manager: %v", err)
		}
	}
}

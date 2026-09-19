package database_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"slices"
	"testing"

	"github.com/sigalx/quordon/internal/adapters/mysql8"
	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryspec"
	"github.com/sigalx/quordon/internal/secrets"
)

func databaseBindingForTest(
	t testing.TB, snapshot *policy.Snapshot, principal, profile string, operation domain.Operation,
) policy.AuthorizedBinding {
	t.Helper()
	binding, err := snapshot.AuthorizeBinding(principal, profile, "mysql", operation)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

type incompleteCapabilityAdapter struct {
	name         string
	capabilities []domain.Operation
	openCalls    int
}

type inertDriver struct{}

func (inertDriver) Open(string) (driver.Conn, error) { return nil, errors.New("not used") }

type inertConnector struct{}

func (inertConnector) Connect(context.Context) (driver.Conn, error) {
	return nil, errors.New("not used")
}
func (inertConnector) Driver() driver.Driver { return inertDriver{} }

type capabilityOmittingAdapter struct {
	explainCalls    int
	listCalls       int
	describeCalls   int
	selectCalls     int
	aggregateCalls  int
	statisticsCalls int
}

type countingNameAdapter struct {
	capabilityOmittingAdapter
	nameCalls int
}

type featureAdvertisingAdapter struct {
	*incompleteCapabilityAdapter
	features []domain.AdapterFeature
}

func (a *featureAdvertisingAdapter) Features() []domain.AdapterFeature {
	return append([]domain.AdapterFeature(nil), a.features...)
}

func (a *countingNameAdapter) Name() string {
	a.nameCalls++
	return "counting-name"
}

func (*capabilityOmittingAdapter) Name() string                     { return "capability-omitting" }
func (*capabilityOmittingAdapter) Capabilities() []domain.Operation { return nil }
func (*capabilityOmittingAdapter) Validate(context.Context, *sql.DB) error {
	return nil
}
func (*capabilityOmittingAdapter) IdentifierSemantics(context.Context, *sql.DB) (domain.IdentifierSemantics, error) {
	return domain.IdentifierSemantics{}, nil
}
func (*capabilityOmittingAdapter) Open(string, config.Datasource) (*sql.DB, error) {
	return sql.OpenDB(inertConnector{}), nil
}
func (a *capabilityOmittingAdapter) Explain(context.Context, *sql.DB, policy.AuthorizedQuery) (database.ExplainResult, error) {
	a.explainCalls++
	return database.ExplainResult{}, nil
}
func (a *capabilityOmittingAdapter) ListObjects(context.Context, *sql.DB, string) ([]database.SchemaObject, error) {
	a.listCalls++
	return nil, nil
}
func (a *capabilityOmittingAdapter) DescribeObject(context.Context, *sql.DB, queryspec.ResourceRef) (database.ObjectDescription, error) {
	a.describeCalls++
	return database.ObjectDescription{}, nil
}
func (a *capabilityOmittingAdapter) Select(context.Context, *sql.DB, policy.AuthorizedQuery) (database.SelectResult, error) {
	a.selectCalls++
	return database.SelectResult{}, nil
}
func (a *capabilityOmittingAdapter) Aggregate(context.Context, *sql.DB, policy.AuthorizedAggregate, int) (database.AggregateResult, error) {
	a.aggregateCalls++
	return database.AggregateResult{}, nil
}
func (a *capabilityOmittingAdapter) DescribeObjectStatistics(
	context.Context, *sql.DB, policy.AuthorizedObjectStatistics, int,
) (database.ObjectStatisticsResult, error) {
	a.statisticsCalls++
	return database.ObjectStatisticsResult{}, nil
}

func (a *incompleteCapabilityAdapter) Name() string { return a.name }
func (a *incompleteCapabilityAdapter) Capabilities() []domain.Operation {
	return append([]domain.Operation(nil), a.capabilities...)
}
func (*incompleteCapabilityAdapter) Validate(context.Context, *sql.DB) error { return nil }
func (*incompleteCapabilityAdapter) IdentifierSemantics(context.Context, *sql.DB) (domain.IdentifierSemantics, error) {
	return domain.IdentifierSemantics{}, nil
}
func (a *incompleteCapabilityAdapter) Open(string, config.Datasource) (*sql.DB, error) {
	a.openCalls++
	return nil, nil
}
func (*incompleteCapabilityAdapter) Explain(context.Context, *sql.DB, policy.AuthorizedQuery) (database.ExplainResult, error) {
	return database.ExplainResult{}, nil
}

func TestManagerAcceptsInlineDSNWithoutSecretResolver(t *testing.T) {
	cfg := config.Config{Datasources: map[string]config.Datasource{
		"mysql": {
			Adapter:     "mysql8",
			DSN:         "user:password@tcp(127.0.0.1:3306)/",
			TLSRequired: boolPointer(false),
			Pool: config.PoolConfig{
				MaxOpenConnections: 1, MaxIdleConnections: 0, MaxConnectionLifetimeSeconds: 60,
			},
		},
	}}
	manager, problems := database.NewManager(cfg, secrets.Map{}, mysql8.New())
	defer manager.Close()
	if len(problems) != 0 {
		t.Fatalf("NewManager() problems = %v", problems)
	}
}

func boolPointer(value bool) *bool { return &value }

func TestManagerCachesAdapterNameDuringInitialization(t *testing.T) {
	adapter := &countingNameAdapter{}
	manager, problems := database.NewManager(config.Config{
		Datasources: map[string]config.Datasource{
			"mysql": {Adapter: "counting-name", DSN: "opaque"},
		},
	}, secrets.Map{}, adapter)
	defer manager.Close()
	if len(problems) != 0 {
		t.Fatalf("NewManager() problems = %v", problems)
	}
	if adapter.nameCalls != 1 {
		t.Fatalf("Name calls during initialization = %d, want 1", adapter.nameCalls)
	}
	for range 3 {
		if name := manager.AdapterName("mysql"); name != "counting-name" {
			t.Fatalf("AdapterName() = %q", name)
		}
	}
	if adapter.nameCalls != 1 {
		t.Fatalf("cached AdapterName() invoked adapter Name %d times", adapter.nameCalls-1)
	}
}

func TestManagerClassifiesUnknownAdapterAsConfigurationError(t *testing.T) {
	cfg := config.Config{Datasources: map[string]config.Datasource{
		"unknown": {
			Adapter: "typo", DSN: "opaque", RequiredForReadiness: false,
		},
	}}
	manager, problems := database.NewManager(cfg, secrets.Map{}, mysql8.New())
	defer manager.Close()
	if len(problems) != 1 || !database.IsConfigurationError(problems[0]) {
		t.Fatalf("problems = %v, want one configuration error", problems)
	}
}

func TestManagerRejectsAdvertisedCapabilitiesWithoutRequiredInterfaces(t *testing.T) {
	for _, capability := range []domain.Operation{
		domain.OperationListObjects,
		domain.OperationDescribeObject,
		domain.OperationSelect,
		domain.OperationSelectKeyset,
		domain.OperationAggregate,
		domain.OperationDescribeObjectStatistics,
	} {
		t.Run(string(capability), func(t *testing.T) {
			adapter := &incompleteCapabilityAdapter{
				name: "incomplete-" + string(capability), capabilities: []domain.Operation{capability},
			}
			cfg := config.Config{Datasources: map[string]config.Datasource{
				"invalid": {Adapter: adapter.name, DSN: "opaque"},
			}}
			manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
			defer manager.Close()
			if len(problems) != 1 || !database.IsConfigurationError(problems[0]) {
				t.Fatalf("problems = %v, want one configuration error", problems)
			}
			if adapter.openCalls != 0 {
				t.Fatalf("Open calls = %d, want contract rejection before datasource initialization", adapter.openCalls)
			}
		})
	}
}

func TestManagerRejectsUnknownAndDuplicateAdvertisedCapabilities(t *testing.T) {
	for _, capabilities := range [][]domain.Operation{
		{"unknown"},
		{domain.OperationExplainSelect, domain.OperationExplainSelect},
		{domain.OperationListQueryShapes},
	} {
		adapter := &incompleteCapabilityAdapter{name: "invalid", capabilities: capabilities}
		cfg := config.Config{Datasources: map[string]config.Datasource{
			"invalid": {Adapter: adapter.name, DSN: "opaque"},
		}}
		manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
		manager.Close()
		if len(problems) != 1 || !database.IsConfigurationError(problems[0]) || adapter.openCalls != 0 {
			t.Fatalf("capabilities %v produced problems=%v openCalls=%d", capabilities, problems, adapter.openCalls)
		}
	}
}

func TestManagerCachesOnlyKnownUniqueAdapterFeatures(t *testing.T) {
	for _, features := range [][]domain.AdapterFeature{
		{"unknown"},
		{domain.FeatureTimeBucketUTC, domain.FeatureTimeBucketUTC},
	} {
		base := &incompleteCapabilityAdapter{name: "invalid-feature"}
		adapter := &featureAdvertisingAdapter{incompleteCapabilityAdapter: base, features: features}
		cfg := config.Config{Datasources: map[string]config.Datasource{
			"mysql": {Adapter: base.name, DSN: "opaque"},
		}}
		manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
		manager.Close()
		if len(problems) != 1 || !database.IsConfigurationError(problems[0]) || base.openCalls != 0 {
			t.Fatalf("features %v produced problems=%v openCalls=%d", features, problems, base.openCalls)
		}
	}
	base := &incompleteCapabilityAdapter{name: "valid-feature"}
	adapter := &featureAdvertisingAdapter{
		incompleteCapabilityAdapter: base, features: []domain.AdapterFeature{domain.FeatureTimeBucketUTC},
	}
	manager, problems := database.NewManager(config.Config{Datasources: map[string]config.Datasource{
		"mysql": {Adapter: base.name, DSN: "opaque"},
	}}, secrets.Map{}, adapter)
	defer manager.Close()
	if len(problems) != 0 || !slices.Equal(manager.Features("mysql"), []domain.AdapterFeature{domain.FeatureTimeBucketUTC}) {
		t.Fatalf("valid features were not cached: problems=%v features=%v", problems, manager.Features("mysql"))
	}
}

func TestManagerRequiresAdvertisedCapabilityBeforeAdapterAction(t *testing.T) {
	adapter := &capabilityOmittingAdapter{}
	manager, problems := database.NewManager(config.Config{
		Datasources: map[string]config.Datasource{
			"mysql": {Adapter: adapter.Name(), DSN: "opaque"},
		},
	}, secrets.Map{}, adapter)
	defer manager.Close()
	if len(problems) != 0 {
		t.Fatalf("NewManager() problems = %v", problems)
	}

	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 65536, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10, MaxPredicates: 10,
		MaxExpressionDepth: 4, MaxParameters: 10, MaxRows: 10,
		MaxResultBytes: 65536, MaxOffset: 10, MaxConcurrency: 1,
	}
	snapshot := policy.NewSnapshot(config.Config{
		HardLimits: limits,
		Principals: map[string]config.Principal{"client": {Profiles: []string{"all"}, Datasources: []string{"mysql"}}},
		Profiles: map[string]config.Profile{"all": {
			Datasources: []string{"mysql"}, Limits: limits,
			Operations: []domain.Operation{
				domain.OperationListObjects, domain.OperationDescribeObject,
				domain.OperationDescribeObjectStatistics, domain.OperationExplainSelect,
				domain.OperationSelect, domain.OperationAggregate,
			},
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"app"}},
				Objects: config.PatternPolicy{Allow: []string{"app.orders"}},
				Fields:  config.PatternPolicy{Allow: []string{"app.orders.id"}},
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
	})
	semantics := domain.IdentifierSemantics{}
	listToken, err := snapshot.AuthorizeListObjects(databaseBindingForTest(t, snapshot, "client", "all", domain.OperationListObjects), "app", semantics)
	if err != nil {
		t.Fatal(err)
	}
	describeToken, err := snapshot.AuthorizeDescribeObject(databaseBindingForTest(t, snapshot, "client", "all", domain.OperationDescribeObject), queryspec.ResourceRef{Schema: "app", Name: "orders"}, semantics)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := queryspec.Validate(queryspec.Spec{
		Source:     queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.Selection{{Kind: "field", Field: "id"}},
	}, 10, 10, 10, 10, 4, 10, 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	explainToken, err := snapshot.AuthorizeExplain(databaseBindingForTest(t, snapshot, "client", "all", domain.OperationExplainSelect), validated, semantics)
	if err != nil {
		t.Fatal(err)
	}
	selectToken, err := snapshot.AuthorizeSelect(databaseBindingForTest(t, snapshot, "client", "all", domain.OperationSelect), validated, semantics)
	if err != nil {
		t.Fatal(err)
	}
	aggregateValidated, err := queryspec.ValidateAggregate(queryspec.AggregateSpec{
		Mode:   queryspec.AggregateModeScalar,
		Source: queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.AggregateOutput{{
			Kind: "measure", Function: "count_all", Alias: "total",
		}},
	}, 10, 10, 10, 10, 4, 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	aggregateToken, err := snapshot.AuthorizeAggregate(databaseBindingForTest(t, snapshot, "client", "all", domain.OperationAggregate), aggregateValidated, semantics)
	if err != nil {
		t.Fatal(err)
	}
	statisticsToken, err := snapshot.AuthorizeObjectStatistics(databaseBindingForTest(t, snapshot, "client", "all", domain.OperationDescribeObjectStatistics), "credential", adapter.Name(),
		queryspec.ResourceRef{Schema: "app", Name: "orders"}, semantics,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := manager.ListObjects(context.Background(), listToken); !database.IsKind(err, database.ErrorNotImplemented) {
		t.Fatalf("ListObjects() error = %v, want not implemented", err)
	}
	if _, _, err := manager.DescribeObject(context.Background(), describeToken); !database.IsKind(err, database.ErrorNotImplemented) {
		t.Fatalf("DescribeObject() error = %v, want not implemented", err)
	}
	if _, _, err := manager.Explain(context.Background(), explainToken); !database.IsKind(err, database.ErrorNotImplemented) {
		t.Fatalf("Explain() error = %v, want not implemented", err)
	}
	if _, _, err := manager.Select(context.Background(), selectToken); !database.IsKind(err, database.ErrorNotImplemented) {
		t.Fatalf("Select() error = %v, want not implemented", err)
	}
	if _, _, err := manager.Aggregate(context.Background(), aggregateToken, 0); !database.IsKind(err, database.ErrorNotImplemented) {
		t.Fatalf("Aggregate() error = %v, want not implemented", err)
	}
	if _, _, err := manager.DescribeObjectStatistics(context.Background(), statisticsToken, 0); !database.IsKind(err, database.ErrorNotImplemented) {
		t.Fatalf("DescribeObjectStatistics() error = %v, want not implemented", err)
	}
	if adapter.explainCalls != 0 || adapter.listCalls != 0 || adapter.describeCalls != 0 ||
		adapter.selectCalls != 0 || adapter.aggregateCalls != 0 || adapter.statisticsCalls != 0 {
		t.Fatalf(
			"adapter calls = explain:%d list:%d describe:%d select:%d aggregate:%d statistics:%d, want all zero",
			adapter.explainCalls, adapter.listCalls, adapter.describeCalls, adapter.selectCalls,
			adapter.aggregateCalls, adapter.statisticsCalls,
		)
	}
}

func TestManagerRejectsMissingOrWrongMetadataAuthorization(t *testing.T) {
	manager, problems := database.NewManager(config.Config{}, secrets.Map{})
	if len(problems) != 0 {
		t.Fatalf("NewManager() problems = %v", problems)
	}
	defer manager.Close()

	if _, _, err := manager.ListObjects(context.Background(), policy.AuthorizedSchema{}); !database.IsKind(err, database.ErrorUpstream) {
		t.Fatalf("zero list token error = %v, want upstream programming error", err)
	}
	if _, _, err := manager.DescribeObjectStatistics(
		context.Background(), policy.AuthorizedObjectStatistics{}, 0,
	); !database.IsKind(err, database.ErrorUpstream) {
		t.Fatalf("zero statistics token error = %v, want upstream programming error", err)
	}

	snapshot := policy.NewSnapshot(config.Config{
		Principals: map[string]config.Principal{"client": {Profiles: []string{"metadata"}, Datasources: []string{"mysql"}}},
		Profiles: map[string]config.Profile{"metadata": {
			Datasources: []string{"mysql"}, Operations: []domain.Operation{domain.OperationListObjects},
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"app"}},
				Objects: config.PatternPolicy{Allow: []string{"app.*"}},
			},
		}},
	})
	list, err := snapshot.AuthorizeListObjects(databaseBindingForTest(t, snapshot, "client", "metadata", domain.OperationListObjects), "app", domain.IdentifierSemantics{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.DescribeObject(context.Background(), list); !database.IsKind(err, database.ErrorUpstream) {
		t.Fatalf("list token used for describe error = %v, want upstream programming error", err)
	}
}

func TestManagerRejectsMissingOrWrongQueryAuthorization(t *testing.T) {
	manager, problems := database.NewManager(config.Config{}, secrets.Map{})
	if len(problems) != 0 {
		t.Fatalf("NewManager() problems = %v", problems)
	}
	defer manager.Close()

	if _, _, err := manager.Explain(context.Background(), policy.AuthorizedQuery{}); !database.IsKind(err, database.ErrorUpstream) {
		t.Fatalf("zero explain token error = %v, want upstream programming error", err)
	}
	if _, _, err := manager.Select(context.Background(), policy.AuthorizedQuery{}); !database.IsKind(err, database.ErrorUpstream) {
		t.Fatalf("zero select token error = %v, want upstream programming error", err)
	}
	if _, _, err := manager.SelectKeyset(
		context.Background(), policy.AuthorizedKeysetSelect{}, database.KeysetEnvelopeBudget{},
	); !database.IsKind(err, database.ErrorUpstream) {
		t.Fatalf("zero keyset token error = %v, want upstream programming error", err)
	}
	if _, _, err := manager.Aggregate(context.Background(), policy.AuthorizedAggregate{}, 0); !database.IsKind(err, database.ErrorUpstream) {
		t.Fatalf("zero aggregate token error = %v, want upstream programming error", err)
	}

	limits := domain.Limits{DeadlineMS: 1000, MaxProjectionFields: 10, MaxGroupByFields: 10,
		MaxOrderByFields: 10, MaxPredicates: 10, MaxExpressionDepth: 4, MaxParameters: 10,
		MaxRows: 10, MaxResultBytes: 1000, MaxOffset: 10, MaxConcurrency: 1}
	snapshot := policy.NewSnapshot(config.Config{
		HardLimits: limits,
		Principals: map[string]config.Principal{"client": {Profiles: []string{"both"}, Datasources: []string{"mysql"}}},
		Profiles: map[string]config.Profile{"both": {
			Datasources: []string{"mysql"}, Limits: limits,
			Operations: []domain.Operation{domain.OperationExplainSelect, domain.OperationSelect},
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"app"}},
				Objects: config.PatternPolicy{Allow: []string{"app.orders"}},
				Fields:  config.PatternPolicy{Allow: []string{"app.orders.id"}},
			},
		}},
	})
	validated, err := queryspec.Validate(queryspec.Spec{
		Source:     queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.Selection{{Kind: "field", Field: "id"}},
	}, 10, 10, 10, 10, 4, 10, 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	explainToken, err := snapshot.AuthorizeExplain(databaseBindingForTest(t, snapshot, "client", "both", domain.OperationExplainSelect), validated, domain.IdentifierSemantics{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Select(context.Background(), explainToken); !database.IsKind(err, database.ErrorUpstream) {
		t.Fatalf("explain token used for select error = %v, want upstream programming error", err)
	}
	selectToken, err := snapshot.AuthorizeSelect(databaseBindingForTest(t, snapshot, "client", "both", domain.OperationSelect), validated, domain.IdentifierSemantics{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Explain(context.Background(), selectToken); !database.IsKind(err, database.ErrorUpstream) {
		t.Fatalf("select token used for explain error = %v, want upstream programming error", err)
	}
}

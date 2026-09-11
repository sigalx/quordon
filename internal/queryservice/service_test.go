package queryservice

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"slices"
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

type unsupportedAdapter struct {
	semanticsCalls int
}

type inertDriver struct{}

func (inertDriver) Open(string) (driver.Conn, error) { return nil, errors.New("not used") }

type inertConnector struct{}

func (inertConnector) Connect(context.Context) (driver.Conn, error) {
	return nil, errors.New("not used")
}
func (inertConnector) Driver() driver.Driver { return inertDriver{} }

type failingAdapter struct{}

type semanticsFailingAdapter struct{}

type successfulAdapter struct {
	plan []byte
}

type dataAdapter struct {
	successfulAdapter
	objects        []database.SchemaObject
	description    *database.ObjectDescription
	semanticsCalls int
}

type cancellationAwareSink struct {
	events []audit.Event
}

func (s *cancellationAwareSink) Write(ctx context.Context, event audit.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.events = append(s.events, event)
	return nil
}

func (*cancellationAwareSink) Ready() bool { return true }

func (*successfulAdapter) Name() string { return "successful" }
func (*successfulAdapter) Capabilities() []domain.Operation {
	return []domain.Operation{domain.OperationExplainSelect}
}
func (*successfulAdapter) Validate(context.Context, *sql.DB) error { return nil }
func (*successfulAdapter) IdentifierSemantics(context.Context, *sql.DB) (domain.IdentifierSemantics, error) {
	return domain.IdentifierSemantics{}, nil
}
func (*successfulAdapter) Open(string, config.Datasource) (*sql.DB, error) {
	return sql.OpenDB(inertConnector{}), nil
}
func (a *successfulAdapter) Explain(context.Context, *sql.DB, policy.AuthorizedQuery) (database.ExplainResult, error) {
	return database.ExplainResult{Format: "test_json", Plan: append([]byte(nil), a.plan...)}, nil
}

func (*dataAdapter) Capabilities() []domain.Operation {
	return []domain.Operation{
		domain.OperationListObjects, domain.OperationDescribeObject,
		domain.OperationExplainSelect, domain.OperationSelect,
	}
}

func (a *dataAdapter) IdentifierSemantics(context.Context, *sql.DB) (domain.IdentifierSemantics, error) {
	a.semanticsCalls++
	return domain.IdentifierSemantics{}, nil
}

func (a *dataAdapter) ListObjects(context.Context, *sql.DB, string) ([]database.SchemaObject, error) {
	if a.objects != nil {
		return append([]database.SchemaObject(nil), a.objects...), nil
	}
	return []database.SchemaObject{{Name: "orders"}, {Name: "secret"}}, nil
}
func (a *dataAdapter) DescribeObject(context.Context, *sql.DB, queryspec.ResourceRef) (database.ObjectDescription, error) {
	if a.description != nil {
		result := *a.description
		result.Columns = append([]database.ColumnDescription(nil), a.description.Columns...)
		return result, nil
	}
	return database.ObjectDescription{Schema: "app", Name: "orders", Columns: []database.ColumnDescription{
		{Name: "id", Type: "integer"}, {Name: "password", Type: "string"},
	}}, nil
}
func (*dataAdapter) Select(context.Context, *sql.DB, policy.AuthorizedQuery) (database.SelectResult, error) {
	return database.SelectResult{
		Columns: []database.ResultColumn{{Name: "id", Type: "integer", Encoding: "string"}},
		Rows:    [][]*string{{stringCell("1")}}, RowCount: 1, ResultBytes: 42,
	}, nil
}

func stringCell(value string) *string { return &value }

func (*failingAdapter) Name() string { return "failing" }
func (*failingAdapter) Capabilities() []domain.Operation {
	return []domain.Operation{domain.OperationExplainSelect}
}
func (*failingAdapter) Validate(context.Context, *sql.DB) error { return nil }
func (*failingAdapter) IdentifierSemantics(context.Context, *sql.DB) (domain.IdentifierSemantics, error) {
	return domain.IdentifierSemantics{}, nil
}
func (*failingAdapter) Open(string, config.Datasource) (*sql.DB, error) {
	return sql.OpenDB(inertConnector{}), nil
}
func (*failingAdapter) Explain(context.Context, *sql.DB, policy.AuthorizedQuery) (database.ExplainResult, error) {
	return database.ExplainResult{}, &database.Error{Kind: database.ErrorUnavailable}
}

func (*semanticsFailingAdapter) Name() string { return "semantics-failing" }
func (*semanticsFailingAdapter) Capabilities() []domain.Operation {
	return []domain.Operation{
		domain.OperationListObjects, domain.OperationDescribeObject, domain.OperationExplainSelect,
	}
}
func (*semanticsFailingAdapter) Validate(context.Context, *sql.DB) error { return nil }
func (*semanticsFailingAdapter) IdentifierSemantics(context.Context, *sql.DB) (domain.IdentifierSemantics, error) {
	return domain.IdentifierSemantics{}, &database.Error{Kind: database.ErrorUnavailable}
}
func (*semanticsFailingAdapter) Open(string, config.Datasource) (*sql.DB, error) {
	return sql.OpenDB(inertConnector{}), nil
}
func (*semanticsFailingAdapter) Explain(context.Context, *sql.DB, policy.AuthorizedQuery) (database.ExplainResult, error) {
	panic("Explain must not be called when identifier semantics are unavailable")
}
func (*semanticsFailingAdapter) ListObjects(context.Context, *sql.DB, string) ([]database.SchemaObject, error) {
	panic("ListObjects must not be called when identifier semantics are unavailable")
}
func (*semanticsFailingAdapter) DescribeObject(context.Context, *sql.DB, queryspec.ResourceRef) (database.ObjectDescription, error) {
	panic("DescribeObject must not be called when identifier semantics are unavailable")
}

func (*unsupportedAdapter) Name() string                     { return "unsupported" }
func (*unsupportedAdapter) Capabilities() []domain.Operation { return nil }
func (*unsupportedAdapter) Validate(context.Context, *sql.DB) error {
	return errors.New("must not be called")
}
func (a *unsupportedAdapter) IdentifierSemantics(context.Context, *sql.DB) (domain.IdentifierSemantics, error) {
	a.semanticsCalls++
	return domain.IdentifierSemantics{}, errors.New("must not be called")
}
func (*unsupportedAdapter) Open(string, config.Datasource) (*sql.DB, error) { return nil, nil }
func (*unsupportedAdapter) Explain(context.Context, *sql.DB, policy.AuthorizedQuery) (database.ExplainResult, error) {
	panic("Explain must not be called")
}

func TestGlobalCapacityAppliesAcrossProfiles(t *testing.T) {
	service := &Service{
		globalCapacity: make(chan struct{}, 1),
		profileCapacity: map[string]chan struct{}{
			"first":  make(chan struct{}, 1),
			"second": make(chan struct{}, 1),
		},
	}
	releaseFirst, ok := service.acquireCapacity("first")
	if !ok {
		t.Fatal("first profile did not acquire capacity")
	}
	if _, ok := service.acquireCapacity("second"); ok {
		t.Fatal("second profile exceeded global capacity")
	}
	releaseFirst()
	releaseSecond, ok := service.acquireCapacity("second")
	if !ok {
		t.Fatal("second profile did not acquire released capacity")
	}
	releaseSecond()
}

func TestPolicyDenialsAreDecidedAndAuditedBeforeCapacityAdmission(t *testing.T) {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 1000, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10, MaxPredicates: 10,
		MaxExpressionDepth: 4, MaxParameters: 10, MaxRows: 10,
		MaxResultBytes: 1000, MaxOffset: 10, MaxConcurrency: 1,
	}
	cfg := config.Config{
		Version: 1, PolicyHash: "policy-hash", HardLimits: limits,
		Principals:  map[string]config.Principal{"client": {Profiles: []string{"reader"}}},
		Datasources: map[string]config.Datasource{"db": {Adapter: "successful", DSN: "opaque"}},
		Profiles: map[string]config.Profile{"reader": {
			Datasource: "db",
			Operations: []domain.Operation{
				domain.OperationListObjects, domain.OperationDescribeObject,
				domain.OperationExplainSelect, domain.OperationSelect,
			},
			Limits: limits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"app"}},
				Objects: config.PatternPolicy{Allow: []string{"app.orders"}},
				Fields:  config.PatternPolicy{Allow: []string{"app.orders.id"}},
			},
		}},
	}
	adapter := &dataAdapter{}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatalf("database problems = %v", problems)
	}
	defer manager.Close()
	sink := &audit.MemorySink{}
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")
	releaseCapacity, ok := service.acquireCapacity("reader")
	if !ok {
		t.Fatal("failed to occupy execution capacity")
	}
	defer releaseCapacity()

	_, err := service.ListObjects(
		context.Background(), "list-request", "client", "credential", "reader", "closed",
	)
	assertServiceErrorKind(t, err, ErrorNotFound)
	_, err = service.DescribeObject(
		context.Background(), "describe-request", "client", "credential", "reader",
		queryspec.ResourceRef{Schema: "app", Name: "secret"},
	)
	assertServiceErrorKind(t, err, ErrorNotFound)
	deniedQuery := queryspec.Request{Profile: "reader", Query: queryspec.Spec{
		Source:     queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.Selection{{Kind: "field", Field: "secret"}},
	}}
	_, err = service.Select(
		context.Background(), "select-request", "select-query", "client", "credential", 1, deniedQuery,
	)
	assertServiceErrorKind(t, err, ErrorDenied)
	_, err = service.Explain(
		context.Background(), "explain-request", "explain-query", "client", "credential", 1, deniedQuery,
	)
	assertServiceErrorKind(t, err, ErrorDenied)

	if len(sink.Events) != 4 {
		t.Fatalf("audit events = %d, want one denial per operation", len(sink.Events))
	}
	wantReasons := []string{
		policy.ReasonDeniedResource, policy.ReasonDeniedResource,
		policy.ReasonDeniedField, policy.ReasonDeniedField,
	}
	for index, event := range sink.Events {
		if event.Decision != "deny" || event.ReasonCode != wantReasons[index] {
			t.Fatalf("audit event %d = %+v", index, event)
		}
	}
	if adapter.semanticsCalls != 4 {
		t.Fatalf("IdentifierSemantics calls = %d, want 4 authorization checks", adapter.semanticsCalls)
	}
}

func assertServiceErrorKind(t *testing.T, err error, want ErrorKind) {
	t.Helper()
	var serviceError *Error
	if !errors.As(err, &serviceError) || serviceError.Kind != want {
		t.Fatalf("error = %v, want %s", err, want)
	}
}

func TestSchemaDiscoveryAndSelectArePolicyFilteredAndAudited(t *testing.T) {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 1000, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10, MaxPredicates: 10,
		MaxExpressionDepth: 4, MaxParameters: 10, MaxRows: 10,
		MaxResultBytes: 1000, MaxOffset: 10, MaxConcurrency: 1,
	}
	cfg := config.Config{
		Version: 1, PolicyHash: "policy-hash", HardLimits: limits,
		Principals:  map[string]config.Principal{"client": {Profiles: []string{"reader"}}},
		Datasources: map[string]config.Datasource{"db": {Adapter: "successful", DSN: "opaque"}},
		Profiles: map[string]config.Profile{"reader": {
			Datasource: "db",
			Operations: []domain.Operation{
				domain.OperationListObjects, domain.OperationDescribeObject, domain.OperationSelect,
			},
			Limits: limits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"app"}},
				Objects: config.PatternPolicy{Allow: []string{"app.orders"}},
				Fields:  config.PatternPolicy{Allow: []string{"app.orders.*"}, Deny: []string{"app.orders.password"}},
			},
		}},
	}
	adapter := &dataAdapter{description: &database.ObjectDescription{
		Schema: "app", Name: "orders", Columns: []database.ColumnDescription{
			{Name: "status", Type: "string"},
			{Name: "id", Type: "integer"},
			{Name: "password", Type: "string"},
		},
	}}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatalf("database problems = %v", problems)
	}
	defer manager.Close()
	sink := &audit.MemorySink{}
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")

	objects, err := service.ListObjects(context.Background(), "request-list", "client", "credential", "reader", "app")
	if err != nil {
		t.Fatal(err)
	}
	if len(objects.Objects) != 1 || objects.Objects[0].Name != "orders" {
		t.Fatalf("objects = %#v", objects.Objects)
	}
	description, err := service.DescribeObject(
		context.Background(), "request-describe", "client", "credential", "reader",
		queryspec.ResourceRef{Schema: "app", Name: "orders"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(description.Columns) != 2 || description.Columns[0].Name != "status" || description.Columns[1].Name != "id" {
		t.Fatalf("columns = %#v", description.Columns)
	}
	describeCompletion := sink.Events[len(sink.Events)-1]
	if !slices.Equal(describeCompletion.Fields, []string{"id", "status"}) {
		t.Fatalf("described audit fields = %v, want sorted authorized fields", describeCompletion.Fields)
	}
	result, err := service.Select(
		context.Background(), "request-select", "query", "client", "credential", 1,
		queryspec.Request{Profile: "reader", Query: queryspec.Spec{
			Source:     queryspec.ResourceRef{Schema: "app", Name: "orders"},
			Projection: []queryspec.Selection{{Kind: "field", Field: "id"}},
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.RowCount != 1 || result.Rows[0][0] == nil || *result.Rows[0][0] != "1" {
		t.Fatalf("select result = %#v", result)
	}
	last := sink.Events[len(sink.Events)-1]
	if last.Operation != string(domain.OperationSelect) || last.Metadata["row_count"] != 1 {
		t.Fatalf("completion audit = %#v", last)
	}
}

func TestSchemaCoordinatesAreValidatedBeforeCapabilityAndDatasourceWork(t *testing.T) {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 1000, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10, MaxPredicates: 10,
		MaxExpressionDepth: 4, MaxParameters: 10, MaxRows: 10,
		MaxResultBytes: 1000, MaxOffset: 10, MaxConcurrency: 1,
	}
	cfg := config.Config{
		HardLimits: limits,
		Principals: map[string]config.Principal{"client": {Profiles: []string{"metadata"}}},
		Datasources: map[string]config.Datasource{"db": {
			Adapter: "unsupported", DSN: "opaque",
		}},
		Profiles: map[string]config.Profile{"metadata": {
			Datasource: "db", Operations: []domain.Operation{
				domain.OperationListObjects, domain.OperationDescribeObject,
			},
			Limits: limits,
		}},
	}
	adapter := &unsupportedAdapter{}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatalf("database problems = %v", problems)
	}
	defer manager.Close()
	sink := &audit.MemorySink{}
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")

	_, err := service.ListObjects(
		context.Background(), "request-list", "client", "credential", "metadata", "invalid-name",
	)
	var serviceError *Error
	if !errors.As(err, &serviceError) || serviceError.Kind != ErrorInvalid {
		t.Fatalf("invalid schema error = %v, want invalid", err)
	}
	_, err = service.DescribeObject(
		context.Background(), "request-describe", "client", "credential", "metadata",
		queryspec.ResourceRef{Schema: "app"},
	)
	if !errors.As(err, &serviceError) || serviceError.Kind != ErrorInvalid {
		t.Fatalf("empty object error = %v, want invalid", err)
	}
	if adapter.semanticsCalls != 0 {
		t.Fatalf("IdentifierSemantics calls = %d, want 0", adapter.semanticsCalls)
	}
	if len(sink.Events) != 0 {
		t.Fatalf("invalid coordinates produced audit events: %+v", sink.Events)
	}
}

func TestSchemaPreAuthorizationFailuresDoNotClaimAuthorizedResources(t *testing.T) {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 1000, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10, MaxPredicates: 10,
		MaxExpressionDepth: 4, MaxParameters: 10, MaxRows: 10,
		MaxResultBytes: 1000, MaxOffset: 10, MaxConcurrency: 1,
	}

	t.Run("unsupported capability", func(t *testing.T) {
		cfg := metadataTestConfig(limits, "unsupported")
		adapter := &unsupportedAdapter{}
		manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
		if len(problems) != 0 {
			t.Fatalf("database problems = %v", problems)
		}
		defer manager.Close()
		sink := &audit.MemorySink{}
		service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")

		_, err := service.ListObjects(
			context.Background(), "request", "client", "credential", "metadata", "app",
		)
		var serviceError *Error
		if !errors.As(err, &serviceError) || serviceError.Kind != ErrorNotImplemented {
			t.Fatalf("error = %v, want not implemented", err)
		}
		if len(sink.Events) != 1 || len(sink.Events[0].Resources) != 0 {
			t.Fatalf("pre-authorization audit resources = %+v, want empty", sink.Events)
		}
		if adapter.semanticsCalls != 0 {
			t.Fatalf("IdentifierSemantics calls = %d, want 0", adapter.semanticsCalls)
		}
	})

	t.Run("identifier semantics failure", func(t *testing.T) {
		cfg := metadataTestConfig(limits, "semantics-failing")
		manager, problems := database.NewManager(cfg, secrets.Map{}, &semanticsFailingAdapter{})
		if len(problems) != 0 {
			t.Fatalf("database problems = %v", problems)
		}
		defer manager.Close()
		sink := &audit.MemorySink{}
		service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")

		_, err := service.DescribeObject(
			context.Background(), "request", "client", "credential", "metadata",
			queryspec.ResourceRef{Schema: "app", Name: "orders"},
		)
		var serviceError *Error
		if !errors.As(err, &serviceError) || serviceError.Kind != ErrorUnavailable {
			t.Fatalf("error = %v, want unavailable", err)
		}
		if len(sink.Events) != 1 || len(sink.Events[0].Resources) != 0 {
			t.Fatalf("pre-authorization audit resources = %+v, want empty", sink.Events)
		}
	})
}

func metadataTestConfig(limits domain.Limits, adapter string) config.Config {
	return config.Config{
		Version: 1, PolicyHash: "policy-hash", HardLimits: limits,
		Principals:  map[string]config.Principal{"client": {Profiles: []string{"metadata"}}},
		Datasources: map[string]config.Datasource{"db": {Adapter: adapter, DSN: "opaque"}},
		Profiles: map[string]config.Profile{"metadata": {
			Datasource: "db", Operations: []domain.Operation{
				domain.OperationListObjects, domain.OperationDescribeObject,
			},
			Limits: limits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"app"}},
				Objects: config.PatternPolicy{Allow: []string{"app.orders"}},
				Fields:  config.PatternPolicy{Allow: []string{"app.orders.*"}},
			},
		}},
	}
}

func TestMetadataSizingMatchesJSONWithoutMaterialization(t *testing.T) {
	emptyObjectPayloadBytes := len(`{"objects":[]}`)
	emptyObjectBytes, err := boundedObjectListResult(nil, emptyObjectPayloadBytes)
	if err != nil || emptyObjectBytes != emptyObjectPayloadBytes {
		t.Fatalf("empty object size = (%d, %v), want %d", emptyObjectBytes, err, emptyObjectPayloadBytes)
	}
	if _, err := boundedObjectListResult(nil, emptyObjectPayloadBytes-1); !database.IsKind(err, database.ErrorResultTooLarge) {
		t.Fatalf("undersized empty object budget error = %v", err)
	}

	objects := []database.SchemaObject{{Name: "orders"}, {Name: `quoted\"<object>`}}
	objectPayload := struct {
		Objects []database.SchemaObject `json:"objects"`
	}{Objects: objects}
	encodedObjects, err := json.Marshal(objectPayload)
	if err != nil {
		t.Fatal(err)
	}
	objectBytes, err := boundedObjectListResult(objects, len(encodedObjects))
	if err != nil || objectBytes != len(encodedObjects) {
		t.Fatalf("object size = (%d, %v), want %d", objectBytes, err, len(encodedObjects))
	}
	if _, err := boundedObjectListResult(objects, len(encodedObjects)-1); !database.IsKind(err, database.ErrorResultTooLarge) {
		t.Fatalf("undersized object budget error = %v", err)
	}

	description := database.ObjectDescription{
		Schema: "app", Name: "orders",
		Columns: []database.ColumnDescription{{
			Name: "payload", Type: "string", NativeType: "varchar(255)<&>\u2028",
			Nullable: true, PrimaryKey: false, Indexed: true,
		}},
	}
	encodedDescription, err := json.Marshal(description)
	if err != nil {
		t.Fatal(err)
	}
	descriptionBytes, err := boundedObjectDescriptionResult(description, len(encodedDescription))
	if err != nil || descriptionBytes != len(encodedDescription) {
		t.Fatalf("description size = (%d, %v), want %d", descriptionBytes, err, len(encodedDescription))
	}
	if _, err := boundedObjectDescriptionResult(description, len(encodedDescription)-1); !database.IsKind(err, database.ErrorResultTooLarge) {
		t.Fatalf("undersized description budget error = %v", err)
	}
}

func TestMetadataSizingDoesNotAllocateEncodedPayload(t *testing.T) {
	description := database.ObjectDescription{
		Schema: "app", Name: "orders",
		Columns: []database.ColumnDescription{{
			Name: "payload", Type: "string", NativeType: strings.Repeat("<&", 1<<20),
		}},
	}
	if allocations := testing.AllocsPerRun(10, func() {
		_, _ = boundedObjectDescriptionResult(description, domain.MaxSupportedResultBytes)
	}); allocations != 0 {
		t.Fatalf("metadata sizing allocations = %v, want 0", allocations)
	}
}

func TestSelectRowsEncodeAsClosedStringOrNullValues(t *testing.T) {
	encoded, err := json.Marshal(SelectResult{
		Rows: [][]*string{{stringCell("1"), nil}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"rows":[["1",null]]`) {
		t.Fatalf("encoded SELECT rows = %s", encoded)
	}
}

func TestSchemaMetadataBudgetAppliesAfterPolicyFiltering(t *testing.T) {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 1000, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10, MaxPredicates: 10,
		MaxExpressionDepth: 4, MaxParameters: 10, MaxRows: 10,
		MaxResultBytes: 256, MaxOffset: 10, MaxConcurrency: 1,
	}
	tinyLimits := limits
	tinyLimits.MaxResultBytes = 16
	resources := config.ResourcePolicy{
		Schemas: config.PatternPolicy{Allow: []string{"app"}},
		Objects: config.PatternPolicy{Allow: []string{"app.orders"}},
		Fields:  config.PatternPolicy{Allow: []string{"app.orders.id"}},
	}
	cfg := config.Config{
		Version: 1, PolicyHash: "policy-hash", HardLimits: limits,
		Principals:  map[string]config.Principal{"client": {Profiles: []string{"metadata", "tiny"}}},
		Datasources: map[string]config.Datasource{"db": {Adapter: "successful", DSN: "opaque"}},
		Profiles: map[string]config.Profile{
			"metadata": {
				Datasource: "db", Operations: []domain.Operation{
					domain.OperationListObjects, domain.OperationDescribeObject,
				},
				Limits: limits, Resources: resources,
			},
			"tiny": {
				Datasource: "db", Operations: []domain.Operation{domain.OperationListObjects},
				Limits: tinyLimits, Resources: resources,
			},
		},
	}
	adapter := &dataAdapter{
		objects: []database.SchemaObject{
			{Name: "orders"},
			{Name: "hidden_metadata_padding_000000000000000000000000000001"},
			{Name: "hidden_metadata_padding_000000000000000000000000000002"},
			{Name: "hidden_metadata_padding_000000000000000000000000000003"},
			{Name: "hidden_metadata_padding_000000000000000000000000000004"},
		},
		description: &database.ObjectDescription{
			Schema: "app", Name: "orders",
			Columns: []database.ColumnDescription{
				{Name: "id", Type: "integer", NativeType: "bigint unsigned", PrimaryKey: true, Indexed: true},
				{Name: "secret_payload", Type: "string", NativeType: strings.Repeat("x", 512)},
			},
		},
	}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatalf("database problems = %v", problems)
	}
	defer manager.Close()
	sink := &audit.MemorySink{}
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")

	objects, err := service.ListObjects(
		context.Background(), "request-list", "client", "credential", "metadata", "app",
	)
	if err != nil {
		t.Fatalf("filtered list error = %v", err)
	}
	if len(objects.Objects) != 1 || objects.Objects[0].Name != "orders" {
		t.Fatalf("filtered objects = %#v", objects.Objects)
	}
	description, err := service.DescribeObject(
		context.Background(), "request-describe", "client", "credential", "metadata",
		queryspec.ResourceRef{Schema: "app", Name: "orders"},
	)
	if err != nil {
		t.Fatalf("filtered description error = %v", err)
	}
	if len(description.Columns) != 1 || description.Columns[0].Name != "id" {
		t.Fatalf("filtered columns = %#v", description.Columns)
	}
	if completion := sink.Events[len(sink.Events)-1]; completion.ResultBytes == 0 || completion.ResultBytes > limits.MaxResultBytes {
		t.Fatalf("description completion result_bytes = %d", completion.ResultBytes)
	}

	_, err = service.ListObjects(
		context.Background(), "request-tiny", "client", "credential", "tiny", "app",
	)
	var serviceError *Error
	if !errors.As(err, &serviceError) || serviceError.Kind != ErrorResultTooLarge {
		t.Fatalf("tiny filtered list error = %v, want result too large", err)
	}
	completion := sink.Events[len(sink.Events)-1]
	if completion.Outcome != "error" || completion.ErrorKind != string(ErrorResultTooLarge) {
		t.Fatalf("tiny completion = %#v", completion)
	}
}

func TestExplainFailsClosedWhenDenialAuditFails(t *testing.T) {
	manager, problems := database.NewManager(config.Config{}, secrets.Map{})
	if len(problems) != 0 {
		t.Fatalf("database problems = %v", problems)
	}
	defer manager.Close()
	sink := &audit.MemorySink{Err: errors.New("audit unavailable")}
	service := New(policy.NewSnapshot(config.Config{}), manager, sink, config.Config{}, "test")

	_, err := service.Explain(
		context.Background(),
		"request",
		"query",
		"principal",
		"credential",
		0,
		queryspec.Request{Profile: "unassigned"},
	)
	var serviceError *Error
	if !errors.As(err, &serviceError) || serviceError.Kind != ErrorServiceUnavailable {
		t.Fatalf("error = %v, want service unavailable", err)
	}
}

func TestDenialAuditSurvivesRequestCancellation(t *testing.T) {
	manager, problems := database.NewManager(config.Config{}, secrets.Map{})
	if len(problems) != 0 {
		t.Fatalf("database problems = %v", problems)
	}
	defer manager.Close()
	sink := &cancellationAwareSink{}
	service := New(policy.NewSnapshot(config.Config{}), manager, sink, config.Config{}, "test")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := service.Explain(
		ctx,
		"request",
		"query",
		"principal",
		"credential",
		0,
		queryspec.Request{Profile: "unassigned"},
	)
	var serviceError *Error
	if !errors.As(err, &serviceError) || serviceError.Kind != ErrorDenied {
		t.Fatalf("error = %v, want policy denial", err)
	}
	if len(sink.events) != 1 || sink.events[0].Decision != "deny" {
		t.Fatalf("audit events = %+v, want one denial", sink.events)
	}
	if sink.events[0].QueryShapeHash != "" {
		t.Fatalf("unassigned-profile denial hash = %q, want empty", sink.events[0].QueryShapeHash)
	}
}

func TestPostValidationDenialAuditIncludesQueryShapeHash(t *testing.T) {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 1000, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10,
		MaxPredicates: 10, MaxExpressionDepth: 4, MaxParameters: 10, MaxRows: 10,
		MaxResultBytes: 1000, MaxOffset: 10, MaxConcurrency: 1,
	}
	cfg := config.Config{
		Version: 1, PolicyHash: "policy-hash", HardLimits: limits,
		Principals:  map[string]config.Principal{"client": {Profiles: []string{"explain"}}},
		Datasources: map[string]config.Datasource{"db": {Adapter: "successful", DSN: "opaque"}},
		Profiles: map[string]config.Profile{"explain": {
			Datasource: "db", Operations: []domain.Operation{domain.OperationExplainSelect}, Limits: limits,
			Resources: config.ResourcePolicy{Objects: config.PatternPolicy{Deny: []string{"app.secret"}}},
		}},
	}
	manager, problems := database.NewManager(cfg, secrets.Map{}, &successfulAdapter{})
	if len(problems) != 0 {
		t.Fatalf("database problems = %v", problems)
	}
	defer manager.Close()
	sink := &audit.MemorySink{}
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")

	_, err := service.Explain(
		context.Background(), "request", "query", "client", "credential", 1,
		queryspec.Request{Profile: "explain", Query: queryspec.Spec{
			Source:     queryspec.ResourceRef{Schema: "app", Name: "secret"},
			Projection: []queryspec.Selection{{Kind: "field", Field: "id"}},
		}},
	)
	var serviceError *Error
	if !errors.As(err, &serviceError) || serviceError.Kind != ErrorDenied || serviceError.ReasonCode != policy.ReasonDeniedResource {
		t.Fatalf("error = %v, want resource denial", err)
	}
	if len(sink.Events) != 1 || sink.Events[0].Decision != "deny" {
		t.Fatalf("audit events = %+v, want one denial", sink.Events)
	}
	if sink.Events[0].QueryShapeHash == "" {
		t.Fatal("post-validation denial audit is missing query shape hash")
	}
}

func TestUnsupportedCapabilityDoesNotTouchDatasource(t *testing.T) {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 1000, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10,
		MaxPredicates: 10, MaxExpressionDepth: 4, MaxParameters: 10, MaxRows: 10,
		MaxResultBytes: 1000, MaxOffset: 10, MaxConcurrency: 1,
	}
	cfg := config.Config{
		HardLimits: limits,
		Principals: map[string]config.Principal{"client": {Profiles: []string{"explain"}}},
		Datasources: map[string]config.Datasource{"db": {
			Adapter: "unsupported", DSN: "opaque",
		}},
		Profiles: map[string]config.Profile{"explain": {
			Datasource: "db", Operations: []domain.Operation{domain.OperationExplainSelect}, Limits: limits,
		}},
	}
	adapter := &unsupportedAdapter{}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatalf("database problems = %v", problems)
	}
	defer manager.Close()
	sink := &audit.MemorySink{}
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")

	_, err := service.Explain(
		context.Background(), "request", "query", "client", "credential", 1,
		queryspec.Request{
			Profile: "explain",
			Query: queryspec.Spec{
				Source:     queryspec.ResourceRef{Schema: "app", Name: "orders"},
				Projection: []queryspec.Selection{{Kind: "field", Field: "id"}},
			},
		},
	)
	var serviceError *Error
	if !errors.As(err, &serviceError) || serviceError.Kind != ErrorNotImplemented {
		t.Fatalf("error = %v, want not implemented", err)
	}
	if len(sink.Events) != 1 || sink.Events[0].Type != "query_completion" ||
		sink.Events[0].Outcome != "not_implemented" || sink.Events[0].QueryShapeHash == "" {
		t.Fatalf("unsupported-capability audit = %+v, want completion with query shape hash", sink.Events)
	}
	if adapter.semanticsCalls != 0 {
		t.Fatalf("IdentifierSemantics calls = %d, want 0", adapter.semanticsCalls)
	}

	sink.Err = errors.New("audit unavailable")
	_, err = service.Explain(
		context.Background(), "request-2", "query-2", "client", "credential", 1,
		queryspec.Request{
			Profile: "explain",
			Query: queryspec.Spec{
				Source:     queryspec.ResourceRef{Schema: "app", Name: "orders"},
				Projection: []queryspec.Selection{{Kind: "field", Field: "id"}},
			},
		},
	)
	if !errors.As(err, &serviceError) || serviceError.Kind != ErrorServiceUnavailable {
		t.Fatalf("error = %v, want service unavailable when unsupported-capability audit fails", err)
	}
	if adapter.semanticsCalls != 0 {
		t.Fatalf("IdentifierSemantics calls = %d after audit failure, want 0", adapter.semanticsCalls)
	}
}

func TestExecutionFailureAuditRetainsQueryShapeHash(t *testing.T) {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 1000, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10,
		MaxPredicates: 10, MaxExpressionDepth: 4, MaxParameters: 10, MaxRows: 10,
		MaxResultBytes: 1000, MaxOffset: 10, MaxConcurrency: 1,
	}
	cfg := config.Config{
		Version: 1, PolicyHash: "policy-hash", HardLimits: limits,
		Principals:  map[string]config.Principal{"client": {Profiles: []string{"explain"}}},
		Datasources: map[string]config.Datasource{"db": {Adapter: "failing", DSN: "opaque"}},
		Profiles: map[string]config.Profile{"explain": {
			Datasource: "db", Operations: []domain.Operation{domain.OperationExplainSelect}, Limits: limits,
		}},
	}
	manager, problems := database.NewManager(cfg, secrets.Map{}, &failingAdapter{})
	if len(problems) != 0 {
		t.Fatalf("database problems = %v", problems)
	}
	defer manager.Close()
	sink := &audit.MemorySink{}
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")

	_, err := service.Explain(
		context.Background(), "request", "query", "client", "credential", 1,
		queryspec.Request{Profile: "explain", Query: queryspec.Spec{
			Source:     queryspec.ResourceRef{Schema: "app", Name: "orders"},
			Projection: []queryspec.Selection{{Kind: "field", Field: "id"}},
		}},
	)
	var serviceError *Error
	if !errors.As(err, &serviceError) || serviceError.Kind != ErrorUnavailable {
		t.Fatalf("error = %v, want unavailable", err)
	}
	if len(sink.Events) != 2 {
		t.Fatalf("audit events = %d, want decision and completion", len(sink.Events))
	}
	if sink.Events[0].QueryShapeHash == "" || sink.Events[1].QueryShapeHash == "" {
		t.Fatalf("query shape hash missing from audit events: %+v", sink.Events)
	}
	if sink.Events[0].QueryShapeHash != sink.Events[1].QueryShapeHash {
		t.Fatal("decision and completion query shape hashes differ")
	}
	if sink.Events[1].Outcome != "error" || sink.Events[1].ErrorKind != string(ErrorUnavailable) {
		t.Fatalf("completion classification = outcome %q, error_kind %q", sink.Events[1].Outcome, sink.Events[1].ErrorKind)
	}
}

func TestIdentifierSemanticsFailureIsAuditedAndFailsClosed(t *testing.T) {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 1000, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10,
		MaxPredicates: 10, MaxExpressionDepth: 4, MaxParameters: 10, MaxRows: 10,
		MaxResultBytes: 1000, MaxOffset: 10, MaxConcurrency: 1,
	}
	cfg := config.Config{
		Version: 1, PolicyHash: "policy-hash", HardLimits: limits,
		Principals: map[string]config.Principal{"client": {Profiles: []string{"explain"}}},
		Datasources: map[string]config.Datasource{"db": {
			Adapter: "semantics-failing", DSN: "opaque",
		}},
		Profiles: map[string]config.Profile{"explain": {
			Datasource: "db", Operations: []domain.Operation{domain.OperationExplainSelect}, Limits: limits,
		}},
	}
	manager, problems := database.NewManager(cfg, secrets.Map{}, &semanticsFailingAdapter{})
	if len(problems) != 0 {
		t.Fatalf("database problems = %v", problems)
	}
	defer manager.Close()
	sink := &audit.MemorySink{}
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")
	request := queryspec.Request{Profile: "explain", Query: queryspec.Spec{
		Source:     queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.Selection{{Kind: "field", Field: "id"}},
	}}

	_, err := service.Explain(context.Background(), "request", "query", "client", "credential", 1, request)
	var serviceError *Error
	if !errors.As(err, &serviceError) || serviceError.Kind != ErrorUnavailable {
		t.Fatalf("error = %v, want unavailable", err)
	}
	if len(sink.Events) != 1 {
		t.Fatalf("audit events = %d, want failed completion", len(sink.Events))
	}
	event := sink.Events[0]
	if event.Type != "query_completion" || event.Outcome != "error" || event.ErrorKind != string(ErrorUnavailable) {
		t.Fatalf("completion event = %+v", event)
	}
	if event.QueryShapeHash == "" {
		t.Fatal("query shape hash missing from identifier-semantics failure audit")
	}
	if event.DurationMS == nil {
		t.Fatal("duration missing from identifier-semantics failure audit")
	}
	if len(event.Resources) != 0 || len(event.Fields) != 0 {
		t.Fatalf("unauthorized identifiers leaked as authorized metadata: resources=%v fields=%v", event.Resources, event.Fields)
	}

	sink.Err = errors.New("audit unavailable")
	_, err = service.Explain(context.Background(), "request-2", "query-2", "client", "credential", 1, request)
	if !errors.As(err, &serviceError) || serviceError.Kind != ErrorServiceUnavailable {
		t.Fatalf("error = %v, want service unavailable when failure audit cannot be written", err)
	}
}

func TestAllowedAuditIncludesClientResourceFieldsAndResultSize(t *testing.T) {
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 1000, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10,
		MaxPredicates: 10, MaxExpressionDepth: 4, MaxParameters: 10, MaxRows: 10,
		MaxResultBytes: 1000, MaxOffset: 10, MaxConcurrency: 1,
	}
	cfg := config.Config{
		Version: 1, PolicyHash: "policy-hash", HardLimits: limits,
		Principals:  map[string]config.Principal{"client": {Profiles: []string{"explain"}}},
		Datasources: map[string]config.Datasource{"db": {Adapter: "successful", DSN: "opaque"}},
		Profiles: map[string]config.Profile{"explain": {
			Datasource: "db", Operations: []domain.Operation{domain.OperationExplainSelect}, Limits: limits,
			Query: config.QueryPolicy{
				AllowFiltering: true, AllowSorting: true, AllowedFilterOperators: []string{"eq"},
			},
		}},
	}
	plan := []byte(`{"query_block":{"select_id":1}}`)
	manager, problems := database.NewManager(cfg, secrets.Map{}, &successfulAdapter{plan: plan})
	if len(problems) != 0 {
		t.Fatalf("database problems = %v", problems)
	}
	defer manager.Close()
	sink := &audit.MemorySink{}
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")

	_, err := service.Explain(
		context.Background(), "request", "query", "client", "basic-user", 1,
		queryspec.Request{Profile: "explain", Query: queryspec.Spec{
			Source: queryspec.ResourceRef{Schema: "app", Name: "orders"},
			Projection: []queryspec.Selection{
				{Kind: "field", Field: "status"},
				{Kind: "field", Field: "id"},
			},
			Filter: &queryspec.Filter{
				Kind: "predicate", Field: "tenant_id", Operator: "eq",
				Values: []queryspec.TypedValue{{Type: "integer", Value: []byte("7")}},
			},
			OrderBy: []queryspec.Sort{{Field: "created_at", Direction: "asc"}},
		}},
	)
	if err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	if len(sink.Events) != 2 {
		t.Fatalf("audit events = %d, want decision and completion", len(sink.Events))
	}
	wantFields := []string{"created_at", "id", "status", "tenant_id"}
	for index, event := range sink.Events {
		if event.Principal != "client" || event.ClientIdentifier != "basic-user" {
			t.Fatalf("event %d identity = principal %q, client %q", index, event.Principal, event.ClientIdentifier)
		}
		if len(event.Resources) != 1 || event.Resources[0] != (audit.Resource{Schema: "app", Object: "orders"}) {
			t.Fatalf("event %d resources = %#v", index, event.Resources)
		}
		if !slices.Equal(event.Fields, wantFields) {
			t.Fatalf("event %d fields = %v, want %v", index, event.Fields, wantFields)
		}
	}
	if sink.Events[1].ResultBytes != len(plan) {
		t.Fatalf("completion result_bytes = %d, want %d", sink.Events[1].ResultBytes, len(plan))
	}
	if sink.Events[0].DurationMS != nil || sink.Events[1].DurationMS == nil {
		t.Fatalf("duration presence = decision %v, completion %v", sink.Events[0].DurationMS, sink.Events[1].DurationMS)
	}
}

func TestClassifyDatabaseError(t *testing.T) {
	tests := []struct {
		databaseKind database.ErrorKind
		want         ErrorKind
	}{
		{databaseKind: database.ErrorInvalid, want: ErrorInvalid},
		{databaseKind: database.ErrorNotImplemented, want: ErrorNotImplemented},
		{databaseKind: database.ErrorUnavailable, want: ErrorUnavailable},
		{databaseKind: database.ErrorTimeout, want: ErrorTimeout},
		{databaseKind: database.ErrorRequestTooLarge, want: ErrorTooLarge},
		{databaseKind: database.ErrorResultTooLarge, want: ErrorResultTooLarge},
		{databaseKind: database.ErrorUpstream, want: ErrorUpstream},
	}
	for _, test := range tests {
		err := &database.Error{Kind: test.databaseKind}
		if got := classifyDatabaseError(err); got != test.want {
			t.Fatalf("classifyDatabaseError(%q) = %q, want %q", test.databaseKind, got, test.want)
		}
	}
	requestTooLarge := &database.Error{Kind: database.ErrorRequestTooLarge}
	if got := classifyDatabaseAuditError(requestTooLarge); got != ErrorInvalid {
		t.Fatalf("request-too-large audit classification = %q, want %q", got, ErrorInvalid)
	}
}

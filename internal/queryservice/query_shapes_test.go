package queryservice

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sigalx/quordon/internal/audit"
	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryspec"
	"github.com/sigalx/quordon/internal/secrets"
)

type blockingQueryShapeAllowSink struct {
	started     chan struct{}
	release     chan struct{}
	startedOnce sync.Once
	releaseOnce sync.Once
}

func newBlockingQueryShapeAllowSink() *blockingQueryShapeAllowSink {
	return &blockingQueryShapeAllowSink{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (s *blockingQueryShapeAllowSink) Write(ctx context.Context, event audit.Event) error {
	if event.Type != "operation_decision" || event.Decision != "allow" {
		return nil
	}
	s.startedOnce.Do(func() { close(s.started) })
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (*blockingQueryShapeAllowSink) Ready() bool { return true }

func (s *blockingQueryShapeAllowSink) Release() {
	s.releaseOnce.Do(func() { close(s.release) })
}

type unavailableDiscoveryAdapter struct {
	semanticsCalls int
}

func (*unavailableDiscoveryAdapter) Name() string { return "aggregate-unavailable" }
func (*unavailableDiscoveryAdapter) Capabilities() []domain.Operation {
	return []domain.Operation{domain.OperationAggregate}
}
func (*unavailableDiscoveryAdapter) Validate(context.Context, *sql.DB) error { return nil }
func (a *unavailableDiscoveryAdapter) IdentifierSemantics(context.Context, *sql.DB) (domain.IdentifierSemantics, error) {
	a.semanticsCalls++
	return domain.IdentifierSemantics{}, &database.Error{Kind: database.ErrorUnavailable}
}
func (*unavailableDiscoveryAdapter) Open(string, config.Datasource) (*sql.DB, error) {
	return sql.OpenDB(inertConnector{}), nil
}
func (*unavailableDiscoveryAdapter) Explain(context.Context, *sql.DB, policy.AuthorizedQuery) (database.ExplainResult, error) {
	panic("Explain must not be called")
}
func (*unavailableDiscoveryAdapter) Aggregate(context.Context, *sql.DB, policy.AuthorizedAggregate, int) (database.AggregateResult, error) {
	panic("Aggregate must not be called")
}

func TestListQueryShapesUsesOnlyStartupSnapshotAndAuditsResult(t *testing.T) {
	cfg := aggregateServiceConfig("aggregate-successful")
	profile := cfg.Profiles["analytics"]
	profile.Operations = append(profile.Operations, domain.OperationListQueryShapes)
	cfg.Profiles["analytics"] = profile
	cfg.Authentication.Basic.Users = map[string]config.BasicUser{
		"credential": {Principal: "client"},
	}
	adapter := &successfulAggregateAdapter{}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	if adapter.nameCalls != 1 {
		t.Fatalf("adapter Name calls during manager initialization = %d, want 1", adapter.nameCalls)
	}
	defer manager.Close()
	sink := &audit.MemorySink{}
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")
	var supported bool
	allocations := testing.AllocsPerRun(100, func() {
		supported = service.supportsConfiguredQueryShapes("analytics", cfg.Profiles["analytics"].Datasource)
	})
	if !supported || allocations != 0 {
		t.Fatalf("precomputed query-shape support: supported=%t allocations=%f", supported, allocations)
	}
	initializationProblems, err := service.InitializeQueryShapeDiscovery(context.Background())
	if err != nil || len(initializationProblems) != 0 {
		t.Fatalf("initialization problems=%v error=%v", initializationProblems, err)
	}
	if adapter.semanticsCalls != 1 {
		t.Fatalf("startup semantics calls = %d, want 1", adapter.semanticsCalls)
	}
	if err := service.validateQueryShapeAuditBound(
		"analytics", service.queryShapes["analytics"], 1,
	); err == nil || !strings.Contains(err.Error(), "audit event exceeds") {
		t.Fatalf("undersized audit bound error = %v", err)
	}
	payload, err := service.ListQueryShapes(
		context.Background(), "request", "client", "credential", "analytics",
	)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.nameCalls != 1 || adapter.semanticsCalls != 1 || adapter.calls != 0 {
		t.Fatalf(
			"request touched adapter: name=%d semantics=%d aggregate=%d",
			adapter.nameCalls, adapter.semanticsCalls, adapter.calls,
		)
	}
	if !strings.Contains(string(payload), `"name":"orders_total"`) || strings.Contains(string(payload), "PRIMARY") {
		t.Fatalf("unexpected response payload: %s", payload)
	}
	if len(sink.Events) != 2 || sink.Events[0].Decision != "allow" || sink.Events[1].Outcome != "success" {
		t.Fatalf("audit events = %+v", sink.Events)
	}
	completion := sink.Events[1]
	if completion.Operation != string(domain.OperationListQueryShapes) || completion.PublicShapeSetHash == "" ||
		completion.ShapeCount != 1 || completion.ResultBytes != len(payload) || len(completion.Resources) != 1 {
		t.Fatalf("completion audit = %+v", completion)
	}
	capabilities := service.Capabilities("client")
	if len(capabilities.Profiles) != 1 ||
		!slices.Contains(capabilities.Profiles[0].Operations, domain.OperationListQueryShapes) {
		t.Fatalf("capabilities = %+v", capabilities)
	}
}

func TestQueryShapeAuditSizePreflightMatchesJSONEncoding(t *testing.T) {
	duration := int64(-9223372036854775807 - 1)
	event := audit.Event{
		Timestamp: time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC),
		Type:      "operation_<decision>", RequestID: "request\n\\\"", QueryID: "query",
		Principal: "principal&", ClientIdentifier: "credential\u2028", PolicyProfile: "profile",
		PolicyVersion: "version", PolicyHash: "hash", Datasource: "datasource", Adapter: "adapter",
		Operation: "list_query_shapes", Decision: "allow", ReasonCode: "reason", Outcome: "error",
		ErrorKind: "internal", DurationMS: &duration, ResultBytes: 123,
		QueryShapeHash: "query-hash", PublicShapeSetHash: "shape-hash", ShapeCount: 2,
		RequestedProfileHash: "requested-hash", RequestedProfileBytes: 17,
		Resources: []audit.Resource{{Schema: "app", Object: "orders"}, {Schema: "archive"}},
		Fields:    []string{"active", "created_at"},
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	size, within, err := queryShapeAuditEventJSONSizeWithin(event, len(payload))
	if err != nil || !within || size != len(payload) {
		t.Fatalf("preflight size=%d within=%t error=%v, want exact size %d", size, within, err, len(payload))
	}
	if _, within, err := queryShapeAuditEventJSONSizeWithin(event, len(payload)-1); err != nil || within {
		t.Fatalf("undersized preflight within=%t error=%v, want bounded rejection", within, err)
	}
}

func TestQueryShapeAuditSizePreflightStopsBeforeOversizedStringEncoding(t *testing.T) {
	event := audit.Event{
		Timestamp: time.Now().UTC(), Type: "operation_decision", RequestID: "request",
		PolicyVersion: "1", PolicyHash: "hash", Principal: strings.Repeat("<", 1<<20),
	}
	if _, within, err := queryShapeAuditEventJSONSizeWithin(event, 1024); err != nil || within {
		t.Fatalf("oversized escaped identity within=%t error=%v", within, err)
	}
	event.Principal = "principal"
	event.Metadata = map[string]any{"flag": true, "label": "shape", "count": 1}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	size, within, err := queryShapeAuditEventJSONSizeWithin(event, len(payload))
	if err != nil || !within || size != len(payload) {
		t.Fatalf("closed metadata size=%d within=%t error=%v, want %d", size, within, err, len(payload))
	}
	event.Metadata = map[string]any{"unexpected": 1.5}
	if _, _, err := queryShapeAuditEventJSONSizeWithin(event, 1024); err == nil {
		t.Fatal("unsupported metadata must fail closed")
	}
}

func TestQueryShapeAuditBoundIgnoresUnreachablePrincipal(t *testing.T) {
	cfg := aggregateServiceConfig("aggregate-successful")
	profile := cfg.Profiles["analytics"]
	profile.Operations = append(profile.Operations, domain.OperationListQueryShapes)
	cfg.Profiles["analytics"] = profile
	adapter := &successfulAggregateAdapter{}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	defer manager.Close()
	service := New(policy.NewSnapshot(cfg), manager, &audit.MemorySink{}, cfg, "test")
	if _, err := service.InitializeQueryShapeDiscovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := service.validateQueryShapeAuditBound(
		"analytics", service.queryShapes["analytics"], 1,
	); err != nil {
		t.Fatalf("unreachable audit identity produced a size failure: %v", err)
	}
}

func TestQueryShapePreTokenAuditBoundRejectsDenialWithoutPublishedProfile(t *testing.T) {
	cfg := aggregateServiceConfig("aggregate-successful")
	largePrincipal := strings.Repeat("p", maxQueryShapeAuditEventBytes)
	cfg.Authentication.Basic.Users = map[string]config.BasicUser{
		"credential": {Principal: largePrincipal},
	}
	cfg.Principals = map[string]config.Principal{
		largePrincipal: {Profiles: []string{"analytics"}},
	}
	adapter := &successfulAggregateAdapter{}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	defer manager.Close()
	service := New(policy.NewSnapshot(cfg), manager, &audit.MemorySink{}, cfg, "test")
	if _, err := service.InitializeQueryShapeDiscovery(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "denial audit event exceeds") {
		t.Fatalf("denial audit preflight error = %v", err)
	}
	if adapter.semanticsCalls != 0 {
		t.Fatalf("denial audit preflight made %d datasource probes", adapter.semanticsCalls)
	}
}

func TestQueryShapePreTokenAuditBoundCoversUnpublishedCompletion(t *testing.T) {
	cfg := aggregateServiceConfig("unsupported")
	longProfileName := strings.Repeat("profile", 300)
	profile := cfg.Profiles["analytics"]
	profile.Operations = append(profile.Operations, domain.OperationListQueryShapes)
	delete(cfg.Profiles, "analytics")
	cfg.Profiles[longProfileName] = profile
	cfg.Principals["client"] = config.Principal{Profiles: []string{longProfileName}}
	cfg.Authentication.Basic.Users = map[string]config.BasicUser{
		"credential": {Principal: "client"},
	}
	adapter := &unsupportedAdapter{}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	defer manager.Close()
	service := New(policy.NewSnapshot(cfg), manager, &audit.MemorySink{}, cfg, "test")
	if err := service.validateQueryShapePreTokenAuditBounds([]string{longProfileName}, 1024); err == nil ||
		!strings.Contains(err.Error(), "pre-token audit event exceeds") {
		t.Fatalf("unpublished completion audit preflight error = %v", err)
	}
	if adapter.semanticsCalls != 0 {
		t.Fatalf("completion audit preflight made %d datasource probes", adapter.semanticsCalls)
	}
}

func TestListQueryShapesDenialDoesNotDiscloseRawProfile(t *testing.T) {
	cfg := aggregateServiceConfig("aggregate-successful")
	profile := cfg.Profiles["analytics"]
	profile.Operations = append(profile.Operations, domain.OperationListQueryShapes)
	cfg.Profiles["analytics"] = profile
	adapter := &successfulAggregateAdapter{}
	manager, _ := database.NewManager(cfg, secrets.Map{}, adapter)
	defer manager.Close()
	sink := &audit.MemorySink{}
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")
	if _, err := service.InitializeQueryShapeDiscovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err := service.ListQueryShapes(
		context.Background(), "request", "client", "credential", "unknown-secret-profile",
	)
	assertServiceErrorKind(t, err, ErrorDenied)
	if adapter.semanticsCalls != 1 || len(sink.Events) != 1 {
		t.Fatalf("adapter calls=%d audit=%+v", adapter.semanticsCalls, sink.Events)
	}
	event := sink.Events[0]
	if event.PolicyProfile != "" || event.Datasource != "" || event.Adapter != "" ||
		event.RequestedProfileHash != "2ba451294d1635a3840c864b8ff4e7eed6027f1115e0e5862166d22c2fa593c1" ||
		event.RequestedProfileBytes != len("unknown-secret-profile") {
		t.Fatalf("denial audit disclosed or omitted attribution: %+v", event)
	}
}

func TestListQueryShapesUnsupportedCapabilityDoesNotProbeDatasource(t *testing.T) {
	cfg := aggregateServiceConfig("unsupported")
	profile := cfg.Profiles["analytics"]
	profile.Operations = append(profile.Operations, domain.OperationListQueryShapes)
	cfg.Profiles["analytics"] = profile
	adapter := &unsupportedAdapter{}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	defer manager.Close()
	sink := &audit.MemorySink{}
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")
	initializationProblems, err := service.InitializeQueryShapeDiscovery(context.Background())
	if err != nil || len(initializationProblems) != 0 {
		t.Fatalf("initialization problems=%v error=%v", initializationProblems, err)
	}
	_, err = service.ListQueryShapes(context.Background(), "request", "client", "credential", "analytics")
	assertServiceErrorKind(t, err, ErrorNotImplemented)
	if adapter.semanticsCalls != 0 || len(sink.Events) != 1 || sink.Events[0].Outcome != "not_implemented" {
		t.Fatalf("adapter calls=%d audit=%+v", adapter.semanticsCalls, sink.Events)
	}
}

func TestRequiredQueryShapeSnapshotFailureMakesServiceUnready(t *testing.T) {
	cfg := aggregateServiceConfig("aggregate-unavailable")
	profile := cfg.Profiles["analytics"]
	profile.Operations = append(profile.Operations, domain.OperationListQueryShapes)
	cfg.Profiles["analytics"] = profile
	datasource := cfg.Datasources["db"]
	datasource.RequiredForReadiness = true
	cfg.Datasources["db"] = datasource
	adapter := &unavailableDiscoveryAdapter{}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	defer manager.Close()
	sink := &audit.MemorySink{}
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")
	initializationProblems, err := service.InitializeQueryShapeDiscovery(context.Background())
	if err != nil || len(initializationProblems) != 1 {
		t.Fatalf("initialization problems=%v error=%v", initializationProblems, err)
	}
	if readyErr := service.Ready(context.Background()); readyErr == nil {
		t.Fatal("service reported ready without a required discovery snapshot")
	}
	_, err = service.ListQueryShapes(context.Background(), "request", "client", "credential", "analytics")
	assertServiceErrorKind(t, err, ErrorServiceUnavailable)
	if len(sink.Events) != 1 || sink.Events[0].ErrorKind != "unavailable" {
		t.Fatalf("unavailable completion audit = %+v", sink.Events)
	}
}

func TestQueryShapeStaticPreflightRejectsBeforeDatasourceProbe(t *testing.T) {
	cfg := aggregateServiceConfig("aggregate-successful")
	profile := cfg.Profiles["analytics"]
	profile.Operations = append(profile.Operations, domain.OperationListQueryShapes)
	profile.Limits.MaxResultBytes = 1
	cfg.Profiles["analytics"] = profile
	adapter := &successfulAggregateAdapter{}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	defer manager.Close()
	service := New(policy.NewSnapshot(cfg), manager, &audit.MemorySink{}, cfg, "test")
	if _, err := service.InitializeQueryShapeDiscovery(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "exceeds max_result_bytes") {
		t.Fatalf("static preflight error = %v", err)
	}
	if adapter.semanticsCalls != 0 {
		t.Fatalf("static preflight made %d datasource probes", adapter.semanticsCalls)
	}
}

func TestUnsupportedTimeBucketFeatureSkipsDiscoveryAndReturnsNotImplemented(t *testing.T) {
	cfg := aggregateServiceConfig("aggregate-successful")
	datasource := cfg.Datasources["db"]
	datasource.RequiredForReadiness = true
	cfg.Datasources["db"] = datasource
	profile := cfg.Profiles["analytics"]
	profile.Operations = append(profile.Operations, domain.OperationListQueryShapes)
	profile.Query.AllowGroupBy = true
	profile.Resources.Fields.Allow = []string{"app.orders.created_at"}
	profile.Query.AggregateShapes = []config.AggregateShape{{
		Name: "orders_by_day", Mode: queryspec.AggregateModeGrouped,
		Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
		Projection: []config.AggregateShapeOutput{
			{Kind: "time_bucket", Field: "created_at", Unit: "day", Timezone: "UTC", Alias: "created_day"},
			{Kind: "measure", Function: "count_all", Alias: "total"},
		},
		MaximumLimit: 10, RequiredIndex: "idx_created_at", MaximumRowsExaminedPerScan: 100,
		AllowTemporaryTable: queryServiceBoolPointer(true), AllowFilesort: queryServiceBoolPointer(false),
	}}
	cfg.Profiles["analytics"] = profile
	adapter := &successfulAggregateAdapter{}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	defer manager.Close()
	sink := &audit.MemorySink{}
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")
	initializationProblems, err := service.InitializeQueryShapeDiscovery(context.Background())
	if err != nil || len(initializationProblems) != 0 {
		t.Fatalf("initialization problems=%v error=%v", initializationProblems, err)
	}
	if err := service.Ready(context.Background()); err != nil {
		t.Fatalf("optional unsupported feature made service unready: %v", err)
	}
	_, err = service.ListQueryShapes(
		context.Background(), "request", "client", "credential", "analytics",
	)
	assertServiceErrorKind(t, err, ErrorNotImplemented)
	if adapter.semanticsCalls != 0 || adapter.calls != 0 {
		t.Fatalf("unsupported feature reached datasource: semantics=%d aggregate=%d", adapter.semanticsCalls, adapter.calls)
	}
	if len(sink.Events) != 1 || sink.Events[0].Outcome != "not_implemented" {
		t.Fatalf("unsupported feature audit = %+v", sink.Events)
	}
}

func TestIdentifierSemanticsMismatchInvalidatesQueryShapeSnapshot(t *testing.T) {
	cfg := aggregateServiceConfig("aggregate-successful")
	profile := cfg.Profiles["analytics"]
	profile.Operations = append(profile.Operations, domain.OperationListQueryShapes)
	cfg.Profiles["analytics"] = profile
	adapter := &successfulAggregateAdapter{}
	manager, _ := database.NewManager(cfg, secrets.Map{}, adapter)
	defer manager.Close()
	service := New(policy.NewSnapshot(cfg), manager, &audit.MemorySink{}, cfg, "test")
	if _, err := service.InitializeQueryShapeDiscovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	service.observeIdentifierSemantics("analytics", domain.IdentifierSemantics{})
	if slices.Contains(service.Capabilities("client").Profiles[0].Operations, domain.OperationListQueryShapes) {
		t.Fatal("invalidated discovery remained advertised")
	}
	_, err := service.ListQueryShapes(context.Background(), "request", "client", "credential", "analytics")
	var serviceError *Error
	if !errors.As(err, &serviceError) || serviceError.Kind != ErrorServiceUnavailable {
		t.Fatalf("error = %v, want service unavailable", err)
	}
}

func TestListQueryShapesDoesNotHoldDiscoveryLockDuringAudit(t *testing.T) {
	cfg := aggregateServiceConfig("aggregate-successful")
	profile := cfg.Profiles["analytics"]
	profile.Operations = append(profile.Operations, domain.OperationListQueryShapes)
	cfg.Profiles["analytics"] = profile
	adapter := &successfulAggregateAdapter{}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	defer manager.Close()
	sink := newBlockingQueryShapeAllowSink()
	defer sink.Release()
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")
	if _, err := service.InitializeQueryShapeDiscovery(context.Background()); err != nil {
		t.Fatal(err)
	}

	requestDone := make(chan error, 1)
	go func() {
		_, err := service.ListQueryShapes(
			context.Background(), "request", "client", "credential", "analytics",
		)
		requestDone <- err
	}()
	select {
	case <-sink.started:
	case <-time.After(time.Second):
		t.Fatal("list_query_shapes did not reach the allow audit")
	}

	invalidated := make(chan struct{})
	go func() {
		service.observeIdentifierSemantics("analytics", domain.IdentifierSemantics{})
		close(invalidated)
	}()
	select {
	case <-invalidated:
	case <-time.After(time.Second):
		sink.Release()
		<-invalidated
		<-requestDone
		t.Fatal("identifier-semantics invalidation waited for a blocked audit write")
	}

	sink.Release()
	if err := <-requestDone; err != nil {
		t.Fatalf("minted discovery token did not survive invalidation: %v", err)
	}
	if slices.Contains(service.Capabilities("client").Profiles[0].Operations, domain.OperationListQueryShapes) {
		t.Fatal("invalidated discovery remained advertised")
	}
}

func TestListQueryShapesCapacityFailureCompletesAllowAudit(t *testing.T) {
	cfg := aggregateServiceConfig("aggregate-successful")
	profile := cfg.Profiles["analytics"]
	profile.Operations = append(profile.Operations, domain.OperationListQueryShapes)
	cfg.Profiles["analytics"] = profile
	adapter := &successfulAggregateAdapter{}
	manager, _ := database.NewManager(cfg, secrets.Map{}, adapter)
	defer manager.Close()
	sink := &audit.MemorySink{}
	service := New(policy.NewSnapshot(cfg), manager, sink, cfg, "test")
	if _, err := service.InitializeQueryShapeDiscovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	release, ok := service.acquireCapacity("analytics")
	if !ok {
		t.Fatal("failed to occupy capacity")
	}
	defer release()
	_, err := service.ListQueryShapes(context.Background(), "request", "client", "credential", "analytics")
	assertServiceErrorKind(t, err, ErrorCapacity)
	if len(sink.Events) != 2 || sink.Events[0].Decision != "allow" ||
		sink.Events[1].Outcome != "error" || sink.Events[1].ErrorKind != "capacity" ||
		sink.Events[1].PublicShapeSetHash == "" || sink.Events[1].ShapeCount != 1 {
		t.Fatalf("capacity audit events = %+v", sink.Events)
	}
}

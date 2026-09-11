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

type keysetServiceAdapter struct {
	capabilities   []domain.Operation
	semanticsCalls int
	selectCalls    int
	invalidResult  bool
	invalidCursor  bool
	nilRows        bool
	selectErr      error
}

func (*keysetServiceAdapter) Name() string { return domain.AdapterMySQL8 }
func (a *keysetServiceAdapter) Capabilities() []domain.Operation {
	return append([]domain.Operation(nil), a.capabilities...)
}
func (*keysetServiceAdapter) Validate(context.Context, *sql.DB) error { return nil }
func (a *keysetServiceAdapter) IdentifierSemantics(context.Context, *sql.DB) (domain.IdentifierSemantics, error) {
	a.semanticsCalls++
	return domain.IdentifierSemantics{CaseInsensitiveFields: true}, nil
}
func (*keysetServiceAdapter) Open(string, config.Datasource) (*sql.DB, error) {
	return sql.OpenDB(inertConnector{}), nil
}
func (*keysetServiceAdapter) Explain(context.Context, *sql.DB, policy.AuthorizedQuery) (database.ExplainResult, error) {
	panic("unexpected explain")
}
func (a *keysetServiceAdapter) SelectKeyset(
	_ context.Context, _ *sql.DB, token policy.AuthorizedKeysetSelect, budget database.KeysetEnvelopeBudget,
) (database.KeysetSelectResult, error) {
	a.selectCalls++
	if token.Operation() != domain.OperationSelectKeyset || token.ShapeName() != "orders_page" ||
		token.Query().Query.Limit != 2 || token.RequiredIndex() != "PRIMARY" {
		panic("adapter received an invalid keyset authorization")
	}
	if a.selectErr != nil {
		return database.KeysetSelectResult{}, a.selectErr
	}
	value := "1"
	result := database.KeysetSelectResult{
		Columns: []database.ResultColumn{{Name: "id", Type: "integer", Encoding: "string", Nullable: false}},
		Rows:    [][]*string{{&value}}, RowCount: 1,
	}
	if a.nilRows {
		result.Rows = nil
		result.RowCount = 0
	}
	if a.invalidResult {
		result.Columns[0].Type = "float"
	}
	columns, _ := json.Marshal(result.Columns)
	rows, _ := json.Marshal(result.Rows)
	if a.invalidCursor {
		result.HasMore = true
		result.NextCursor = []queryspec.KeysetCursorValue{{Type: "integer", Value: "2"}}
		cursor, _ := json.Marshal(result.NextCursor)
		result.ResultBytes = budget.MoreBaseBytes + len(columns) - len(`[]`) + len(rows) - len(`[]`) + len(cursor) - len(`[]`)
	} else {
		result.ResultBytes = budget.FinalBaseBytes + len(columns) - len(`[]`) + len(rows) - len(`[]`)
	}
	return result, nil
}

func TestKeysetSelectSuccessIsAuthorizedBoundedAndAudited(t *testing.T) {
	adapter := &keysetServiceAdapter{capabilities: []domain.Operation{domain.OperationSelectKeyset}}
	service, sink, closeManager := newKeysetService(t, adapter)
	defer closeManager()
	result, err := service.SelectKeyset(
		context.Background(), "request", "query", "client", "credential", 256, keysetServiceRequest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.semanticsCalls != 1 || adapter.selectCalls != 1 || result.Kind != "keyset" ||
		result.RowCount != 1 || result.Page.HasMore || result.Page.NextCursor != nil {
		t.Fatalf("result=%+v semantics=%d selects=%d", result, adapter.semanticsCalls, adapter.selectCalls)
	}
	if !json.Valid(result.EncodedJSON()) {
		t.Fatal("service did not retain its validated keyset response payload")
	}
	if len(sink.Events) != 2 || sink.Events[0].Decision != "allow" ||
		sink.Events[0].Metadata["keyset_shape"] != "orders_page" || sink.Events[1].Outcome != "success" ||
		sink.Events[1].Operation != string(domain.OperationSelectKeyset) || sink.Events[1].ResultBytes == 0 ||
		len(sink.Events[1].Resources) != 1 || len(sink.Events[1].Fields) != 1 || sink.Events[1].Fields[0] != "id" ||
		sink.Events[1].Metadata["keyset_shape"] != "orders_page" ||
		sink.Events[1].Metadata["has_more"] != false || sink.Events[1].Metadata["truncated"] != false {
		t.Fatalf("keyset audit=%+v", sink.Events)
	}
}

func TestKeysetSelectHashesUnassignedProfileInDenialAudit(t *testing.T) {
	adapter := &keysetServiceAdapter{capabilities: []domain.Operation{domain.OperationSelectKeyset}}
	service, sink, closeManager := newKeysetService(t, adapter)
	defer closeManager()
	request := keysetServiceRequest()
	request.Profile = strings.Repeat("x", 4096)
	_, err := service.SelectKeyset(
		context.Background(), "request", "query", "client", "credential", 8192, request,
	)
	assertServiceErrorKind(t, err, ErrorDenied)
	if len(sink.Events) != 1 || sink.Events[0].PolicyProfile != "" ||
		sink.Events[0].RequestedProfileBytes != len(request.Profile) ||
		len(sink.Events[0].RequestedProfileHash) != 64 || sink.Events[0].ReasonCode != policy.ReasonDeniedOperation {
		t.Fatalf("unassigned-profile audit=%+v", sink.Events)
	}
}

func TestKeysetAuditPreflightBoundsConfiguredIdentitiesWithoutDatasourceCall(t *testing.T) {
	adapter := &keysetServiceAdapter{capabilities: []domain.Operation{domain.OperationSelectKeyset}}
	service, _, closeManager := newKeysetService(t, adapter)
	defer closeManager()
	identity := queryShapeAuditIdentity{principal: "client", clientIdentifier: strings.Repeat("u", 1024)}
	service.queryShapeAuditIdentities = []queryShapeAuditIdentity{identity}
	service.keysetAuditIdentities = map[string][]queryShapeAuditIdentity{"reader": {identity}}
	if err := service.validateKeysetAuditBounds(512); err == nil {
		t.Fatal("oversized keyset audit identity passed startup preflight")
	}
	if adapter.semanticsCalls != 0 || adapter.selectCalls != 0 {
		t.Fatalf("audit preflight made adapter calls=%d/%d", adapter.semanticsCalls, adapter.selectCalls)
	}
}

func TestKeysetSelectRejectsShapeMismatchBeforeDatasource(t *testing.T) {
	adapter := &keysetServiceAdapter{capabilities: []domain.Operation{domain.OperationSelectKeyset}}
	service, sink, closeManager := newKeysetService(t, adapter)
	defer closeManager()
	request := keysetServiceRequest()
	request.Query.Projection[0].Alias = "different"
	_, err := service.SelectKeyset(context.Background(), "request", "query", "client", "credential", 256, request)
	assertServiceErrorKind(t, err, ErrorDenied)
	if adapter.semanticsCalls != 0 || adapter.selectCalls != 0 || len(sink.Events) != 1 ||
		sink.Events[0].ReasonCode != policy.ReasonDeniedQueryFeature || sink.Events[0].QueryShapeHash == "" {
		t.Fatalf("adapter calls=%d/%d events=%+v", adapter.semanticsCalls, adapter.selectCalls, sink.Events)
	}
}

func TestKeysetPretokenDenialHashUsesConservativeNormalization(t *testing.T) {
	adapter := &keysetServiceAdapter{capabilities: []domain.Operation{domain.OperationSelectKeyset}}
	service, sink, closeManager := newKeysetService(t, adapter)
	defer closeManager()

	upper := keysetServiceRequest()
	upper.Query.Projection[0].Alias = "Different"
	lower := keysetServiceRequest()
	lower.Query.Projection[0].Alias = "different"
	for index, request := range []queryspec.KeysetRequest{upper, lower} {
		_, err := service.SelectKeyset(
			context.Background(), "request", "query", "client", "credential", 256, request,
		)
		assertServiceErrorKind(t, err, ErrorDenied)
		if len(sink.Events) != index+1 || sink.Events[index].QueryShapeHash == "" {
			t.Fatalf("denial %d audit=%+v", index, sink.Events)
		}
	}
	if sink.Events[0].QueryShapeHash != sink.Events[1].QueryShapeHash {
		t.Fatalf("equivalent pretoken shapes have different hashes: %q != %q", sink.Events[0].QueryShapeHash, sink.Events[1].QueryShapeHash)
	}
	if adapter.semanticsCalls != 0 || adapter.selectCalls != 0 {
		t.Fatalf("pretoken normalization made adapter calls=%d/%d", adapter.semanticsCalls, adapter.selectCalls)
	}
}

func TestKeysetSelectRejectsRepeatedOrderFieldBeforeDatasource(t *testing.T) {
	adapter := &keysetServiceAdapter{capabilities: []domain.Operation{domain.OperationSelectKeyset}}
	service, sink, closeManager := newKeysetService(t, adapter)
	defer closeManager()
	request := keysetServiceRequest()
	request.Query.OrderBy = append(request.Query.OrderBy, queryspec.Sort{Field: "id", Direction: "desc"})
	_, err := service.SelectKeyset(context.Background(), "request", "query", "client", "credential", 256, request)
	assertServiceErrorKind(t, err, ErrorInvalid)
	if adapter.semanticsCalls != 0 || adapter.selectCalls != 0 || len(sink.Events) != 0 {
		t.Fatalf("adapter calls=%d/%d events=%+v", adapter.semanticsCalls, adapter.selectCalls, sink.Events)
	}
}

func TestKeysetSelectChecksCapabilityBeforeDatasource(t *testing.T) {
	adapter := &keysetServiceAdapter{}
	service, sink, closeManager := newKeysetService(t, adapter)
	defer closeManager()
	_, err := service.SelectKeyset(
		context.Background(), "request", "query", "client", "credential", 256, keysetServiceRequest(),
	)
	assertServiceErrorKind(t, err, ErrorNotImplemented)
	if adapter.semanticsCalls != 0 || adapter.selectCalls != 0 || len(sink.Events) != 1 ||
		sink.Events[0].Outcome != "not_implemented" || sink.Events[0].DurationMS == nil {
		t.Fatalf("adapter calls=%d/%d events=%+v", adapter.semanticsCalls, adapter.selectCalls, sink.Events)
	}
}

func TestKeysetSelectRejectsCursorThatDoesNotMatchLastRow(t *testing.T) {
	adapter := &keysetServiceAdapter{
		capabilities: []domain.Operation{domain.OperationSelectKeyset}, invalidCursor: true,
	}
	service, sink, closeManager := newKeysetService(t, adapter)
	defer closeManager()
	_, err := service.SelectKeyset(
		context.Background(), "request", "query", "client", "credential", 256, keysetServiceRequest(),
	)
	assertServiceErrorKind(t, err, ErrorInternal)
	if len(sink.Events) != 2 || sink.Events[1].Outcome != "error" || sink.Events[1].ErrorKind != string(ErrorInternal) {
		t.Fatalf("mismatched-cursor audit=%+v", sink.Events)
	}
}

func TestKeysetSelectRejectsInvalidBodyByteCountBeforeAdapterCalls(t *testing.T) {
	adapter := &keysetServiceAdapter{capabilities: []domain.Operation{domain.OperationSelectKeyset}}
	service, sink, closeManager := newKeysetService(t, adapter)
	defer closeManager()
	_, err := service.SelectKeyset(
		context.Background(), "request", "query", "client", "credential", -1, keysetServiceRequest(),
	)
	assertServiceErrorKind(t, err, ErrorInvalid)
	if adapter.semanticsCalls != 0 || adapter.selectCalls != 0 || len(sink.Events) != 0 {
		t.Fatalf("adapter calls=%d/%d events=%+v", adapter.semanticsCalls, adapter.selectCalls, sink.Events)
	}
}

func TestValidateKeysetResponseRejectsOversizedContinuationCursor(t *testing.T) {
	value := strings.Repeat("x", queryspec.ProtocolMaxCursorStringRunes+1)
	cursor := []queryspec.KeysetCursorValue{{Type: "string", Value: value}}
	request := queryspec.NormalizedKeysetRequest{
		Profile: "reader", Shape: "orders_page",
		Query: queryspec.KeysetSpec{
			Projection: []queryspec.Selection{{Kind: "field", Field: "id"}},
			OrderBy:    []queryspec.Sort{{Field: "id", Direction: "asc"}}, Limit: 1,
		},
	}
	result := KeysetSelectResult{
		Kind: "keyset", QueryID: "query", PolicyProfile: request.Profile, PolicyVersion: "1",
		Shape: request.Shape, Datasource: "mysql", Adapter: domain.AdapterMySQL8,
		Columns: []database.ResultColumn{{Name: "id", Type: "string", Encoding: "string"}},
		Rows:    [][]*string{{&value}}, RowCount: 1, Truncated: true,
		Page: KeysetPageResult{HasMore: true, NextCursor: &cursor}, Warnings: []string{},
	}
	if err := validateKeysetResponse(result, request); err == nil {
		t.Fatal("oversized server-issued cursor passed the response boundary")
	}
}

func TestKeysetCursorMatchesPortableTemporalCells(t *testing.T) {
	fixtures := []struct {
		name   string
		cursor queryspec.KeysetCursorValue
		column database.ResultColumn
		cell   string
		want   bool
	}{
		{
			name: "date", cursor: queryspec.KeysetCursorValue{Type: "date", Value: "0001-01-01"},
			column: database.ResultColumn{Type: "date", Encoding: "string"}, cell: "0001-01-01", want: true,
		},
		{
			name: "datetime", cursor: queryspec.KeysetCursorValue{Type: "datetime", Value: "9999-12-31 23:59:59.123456789"},
			column: database.ResultColumn{Type: "datetime", Encoding: "string"}, cell: "9999-12-31 23:59:59.123456789", want: true,
		},
		{
			name:   "timestamp normalized to projected datetime",
			cursor: queryspec.KeysetCursorValue{Type: "timestamp", Value: "2026-09-15T12:34:56.123456Z"},
			column: database.ResultColumn{Type: "datetime", Encoding: "string"}, cell: "2026-09-15 12:34:56.123456", want: true,
		},
		{
			name:   "timestamp offset forbidden",
			cursor: queryspec.KeysetCursorValue{Type: "timestamp", Value: "2026-09-15T12:34:56+00:00"},
			column: database.ResultColumn{Type: "datetime", Encoding: "string"}, cell: "2026-09-15 12:34:56", want: false,
		},
		{
			name:   "timestamp requires datetime result cell",
			cursor: queryspec.KeysetCursorValue{Type: "timestamp", Value: "2026-09-15T12:34:56Z"},
			column: database.ResultColumn{Type: "timestamp", Encoding: "string"}, cell: "2026-09-15 12:34:56", want: false,
		},
		{
			name:   "timestamp value mismatch",
			cursor: queryspec.KeysetCursorValue{Type: "timestamp", Value: "2026-09-15T12:34:57Z"},
			column: database.ResultColumn{Type: "datetime", Encoding: "string"}, cell: "2026-09-15 12:34:56", want: false,
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			if got := keysetCursorMatchesCell(fixture.cursor, fixture.column, fixture.cell); got != fixture.want {
				t.Fatalf("match=%t, want %t", got, fixture.want)
			}
		})
	}
}

func TestValidateKeysetResponseDoesNotHardcodeConcreteAdapter(t *testing.T) {
	request := queryspec.NormalizedKeysetRequest{
		Profile: "reader", Shape: "events_by_date",
		Query: queryspec.KeysetSpec{
			Projection: []queryspec.Selection{{Kind: "field", Field: "event_date"}},
			OrderBy:    []queryspec.Sort{{Field: "event_date", Direction: "asc"}}, Limit: 1,
		},
	}
	value := "2026-09-15"
	result := KeysetSelectResult{
		Kind: "keyset", QueryID: "query", PolicyProfile: request.Profile, PolicyVersion: "1",
		Shape: request.Shape, Datasource: "main", Adapter: "future-adapter",
		Columns: []database.ResultColumn{{Name: "event_date", Type: "date", Encoding: "string"}},
		Rows:    [][]*string{{&value}}, RowCount: 1, Page: KeysetPageResult{HasMore: false}, Warnings: []string{},
	}
	if err := validateKeysetResponse(result, request); err != nil {
		t.Fatalf("portable keyset response rejected a non-MySQL adapter identity: %v", err)
	}
}

func TestKeysetResponseRejectsNonCanonicalDecimals(t *testing.T) {
	for _, value := range []string{"00", "01.25", "-0", "-0.00"} {
		if validKeysetResponseCell(value, database.ResultColumn{Type: "decimal", Encoding: "string"}) {
			t.Fatalf("non-canonical decimal %q passed the response boundary", value)
		}
	}
	for _, value := range []string{"0", "0.00", "1.25", "-1.25"} {
		if !validKeysetResponseCell(value, database.ResultColumn{Type: "decimal", Encoding: "string"}) {
			t.Fatalf("canonical decimal %q was rejected", value)
		}
	}
}

func TestKeysetResponseRejectsPlusPrefixedTime(t *testing.T) {
	column := database.ResultColumn{Type: "time", Encoding: "string"}
	for _, value := range []string{"00:00:00", "100:00:00", "-01:02:03.4", "838:59:59.999999"} {
		if !validKeysetResponseCell(value, column) {
			t.Fatalf("canonical TIME %q was rejected", value)
		}
	}
	for _, value := range []string{"+01:00:00", "-+01:00:00", "--01:00:00", "001:00:00"} {
		if validKeysetResponseCell(value, column) {
			t.Fatalf("non-canonical TIME %q passed the response boundary", value)
		}
	}
}

func TestKeysetSelectRejectsImpossibleEnvelopeBeforeDatasource(t *testing.T) {
	adapter := &keysetServiceAdapter{capabilities: []domain.Operation{domain.OperationSelectKeyset}}
	service, sink, closeManager := newKeysetServiceWithMaxResult(t, adapter, 1)
	defer closeManager()
	_, err := service.SelectKeyset(
		context.Background(), "request", "query", "client", "credential", 1, keysetServiceRequest(),
	)
	assertServiceErrorKind(t, err, ErrorResultTooLarge)
	if adapter.semanticsCalls != 0 || adapter.selectCalls != 0 || len(sink.Events) != 1 ||
		sink.Events[0].ErrorKind != string(ErrorResultTooLarge) || len(sink.Events[0].Resources) != 0 {
		t.Fatalf("adapter calls=%d/%d events=%+v", adapter.semanticsCalls, adapter.selectCalls, sink.Events)
	}
}

func TestKeysetContinuationBudgetErrorKeepsHTTPAndAuditClassificationsSeparate(t *testing.T) {
	adapter := &keysetServiceAdapter{
		capabilities: []domain.Operation{domain.OperationSelectKeyset},
		selectErr:    &database.Error{Kind: database.ErrorRequestTooLarge},
	}
	service, sink, closeManager := newKeysetService(t, adapter)
	defer closeManager()
	_, err := service.SelectKeyset(
		context.Background(), "request", "query", "client", "credential", 256, keysetServiceRequest(),
	)
	assertServiceErrorKind(t, err, ErrorTooLarge)
	if adapter.selectCalls != 1 || len(sink.Events) != 2 || sink.Events[1].Outcome != "error" ||
		sink.Events[1].ErrorKind != string(ErrorInvalid) {
		t.Fatalf("select calls=%d audit=%+v", adapter.selectCalls, sink.Events)
	}
}

func TestKeysetSelectRejectsInvalidAdapterResponseBeforeSuccessAudit(t *testing.T) {
	adapter := &keysetServiceAdapter{capabilities: []domain.Operation{domain.OperationSelectKeyset}, invalidResult: true}
	service, sink, closeManager := newKeysetService(t, adapter)
	defer closeManager()
	_, err := service.SelectKeyset(
		context.Background(), "request", "query", "client", "credential", 256, keysetServiceRequest(),
	)
	assertServiceErrorKind(t, err, ErrorInternal)
	if len(sink.Events) != 2 || sink.Events[1].Outcome != "error" || sink.Events[1].ErrorKind != string(ErrorInternal) {
		t.Fatalf("invalid-result audit=%+v", sink.Events)
	}
}

func TestKeysetSelectRejectsNilRowsBeforeEncoding(t *testing.T) {
	adapter := &keysetServiceAdapter{
		capabilities: []domain.Operation{domain.OperationSelectKeyset}, nilRows: true,
	}
	service, sink, closeManager := newKeysetService(t, adapter)
	defer closeManager()
	_, err := service.SelectKeyset(
		context.Background(), "request", "query", "client", "credential", 256, keysetServiceRequest(),
	)
	assertServiceErrorKind(t, err, ErrorInternal)
	if adapter.selectCalls != 1 || len(sink.Events) != 2 || sink.Events[1].Outcome != "error" ||
		sink.Events[1].ErrorKind != string(ErrorInternal) {
		t.Fatalf("select calls=%d audit=%+v", adapter.selectCalls, sink.Events)
	}
}

func TestKeysetResponseUsesPortableTemporalRange(t *testing.T) {
	for _, value := range []string{"0000-01-01", "10000-01-01"} {
		if validKeysetResponseCell(value, database.ResultColumn{Type: "date", Encoding: "string"}) {
			t.Fatalf("non-portable date %q passed the service boundary", value)
		}
	}
	for _, value := range []string{"0000-01-01 00:00:00", "10000-01-01 00:00:00"} {
		if validKeysetResponseCell(value, database.ResultColumn{Type: "datetime", Encoding: "string"}) {
			t.Fatalf("non-portable datetime %q passed the service boundary", value)
		}
	}
	for _, value := range []string{"0001-01-01", "0999-12-31", "9999-12-31"} {
		if !validKeysetResponseCell(value, database.ResultColumn{Type: "date", Encoding: "string"}) {
			t.Fatalf("portable date %q was rejected at the service boundary", value)
		}
	}
}

func newKeysetService(t *testing.T, adapter *keysetServiceAdapter) (*Service, *audit.MemorySink, func()) {
	return newKeysetServiceWithMaxResult(t, adapter, 65536)
}

func newKeysetServiceWithMaxResult(
	t *testing.T, adapter *keysetServiceAdapter, maxResultBytes int,
) (*Service, *audit.MemorySink, func()) {
	t.Helper()
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 65536, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 8, MaxPredicates: 10,
		MaxExpressionDepth: 4, MaxParameters: 20, MaxRows: 100,
		MaxResultBytes: maxResultBytes, MaxOffset: 100, MaxConcurrency: 1,
	}
	cfg := config.Config{
		Version: 1, PolicyHash: "policy-hash", HardLimits: limits,
		Principals:  map[string]config.Principal{"client": {Profiles: []string{"reader"}}},
		Datasources: map[string]config.Datasource{"mysql": {Adapter: adapter.Name(), DSN: "opaque"}},
		Profiles: map[string]config.Profile{"reader": {
			Datasource: "mysql", Operations: []domain.Operation{domain.OperationSelectKeyset}, Limits: limits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"app"}},
				Objects: config.PatternPolicy{Allow: []string{"app.orders"}},
				Fields:  config.PatternPolicy{Allow: []string{"app.orders.id"}},
			},
			Query: config.QueryPolicy{AllowSorting: true, KeysetSelectShapes: []config.KeysetSelectShape{{
				Name: "orders_page", Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
				Projection:   []config.KeysetShapeProjection{{Kind: "field", Field: "id"}},
				OrderBy:      []config.KeysetShapeOrder{{Field: "id", Direction: "asc"}},
				MaximumLimit: 10, RequiredIndex: "PRIMARY", MaximumRowsExaminedPerScan: 100,
			}}},
		}},
	}
	manager, problems := database.NewManager(cfg, secrets.Map{}, adapter)
	if len(problems) != 0 {
		t.Fatalf("database problems=%v", problems)
	}
	sink := &audit.MemorySink{}
	return New(policy.NewSnapshot(cfg), manager, sink, cfg, "test"), sink, func() { _ = manager.Close() }
}

func keysetServiceRequest() queryspec.KeysetRequest {
	return queryspec.KeysetRequest{
		Kind: "keyset", Profile: "reader", Shape: "orders_page",
		Query: queryspec.KeysetSpec{
			Source:     queryspec.ResourceRef{Schema: "app", Name: "orders"},
			Projection: []queryspec.Selection{{Kind: "field", Field: "id"}},
			OrderBy:    []queryspec.Sort{{Field: "id", Direction: "asc"}}, Limit: 2,
		},
		Page: queryspec.KeysetPage{Kind: "first"},
	}
}

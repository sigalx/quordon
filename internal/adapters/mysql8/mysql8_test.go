package mysql8

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryspec"
)

func TestClassifyExecutionError(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		err  error
		kind database.ErrorKind
	}{
		{name: "server-side timeout", ctx: context.Background(), err: &mysql.MySQLError{Number: 3024}, kind: database.ErrorTimeout},
		{name: "connection lost", ctx: context.Background(), err: &mysql.MySQLError{Number: 2013}, kind: database.ErrorUnavailable},
		{name: "database access denied", ctx: context.Background(), err: &mysql.MySQLError{Number: 1044}, kind: database.ErrorUnavailable},
		{name: "authentication failed", ctx: context.Background(), err: &mysql.MySQLError{Number: 1045}, kind: database.ErrorUnavailable},
		{name: "DDL guard privilege missing", ctx: context.Background(), err: &mysql.MySQLError{Number: 1227}, kind: database.ErrorUnavailable},
		{name: "bad connection", ctx: context.Background(), err: driver.ErrBadConn, kind: database.ErrorUnavailable},
		{name: "operation socket deadline", ctx: context.Background(), err: context.DeadlineExceeded, kind: database.ErrorTimeout},
		{name: "oversized result packet", ctx: context.Background(), err: mysql.ErrReadPktTooLarge, kind: database.ErrorResultTooLarge},
		{name: "SQL error", ctx: context.Background(), err: &mysql.MySQLError{Number: 1146}, kind: database.ErrorUpstream},
	}
	deadlineContext, cancel := context.WithCancel(context.Background())
	cancel()
	tests = append(tests, struct {
		name string
		ctx  context.Context
		err  error
		kind database.ErrorKind
	}{name: "canceled context", ctx: deadlineContext, err: errors.New("query interrupted"), kind: database.ErrorTimeout})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			classified := classifyExecutionError(test.ctx, test.err)
			if classified.Kind != test.kind {
				t.Fatalf("kind = %s, want %s", classified.Kind, test.kind)
			}
		})
	}
}

func TestClassifyExplainErrorTreatsInvalidQueryObjectsAsUnsupported(t *testing.T) {
	for _, number := range []uint16{1054, 1146, 1345, 1356} {
		err := classifyExplainError(context.Background(), &mysql.MySQLError{Number: number})
		if err.Kind != database.ErrorInvalid {
			t.Fatalf("MySQL error %d kind = %s, want %s", number, err.Kind, database.ErrorInvalid)
		}
	}
	err := classifyExplainError(context.Background(), &mysql.MySQLError{Number: 1064})
	if err.Kind != database.ErrorUpstream {
		t.Fatalf("MySQL syntax error kind = %s, want %s", err.Kind, database.ErrorUpstream)
	}
}

func TestBoundedPacketSizeIncludesFramingWithoutOverflow(t *testing.T) {
	if got := boundedPacketSize(4096); got != 4096+resultPacketOverhead {
		t.Fatalf("boundedPacketSize(4096) = %d", got)
	}
	maxInt := int(^uint(0) >> 1)
	if got := boundedPacketSize(maxInt); got != maxInt {
		t.Fatalf("boundedPacketSize(maxInt) = %d, want %d", got, maxInt)
	}
}

func TestAbsoluteResultPacketSizeUsesImplementationBound(t *testing.T) {
	want := domain.MaxSupportedResultBytes + resultPacketOverhead
	if got := absoluteResultPacketSize(); got != want {
		t.Fatalf("absoluteResultPacketSize() = %d, want %d", got, want)
	}
	if absoluteResultPacketSize() <= boundedPacketSize(1024) {
		t.Fatal("absolute packet bound still follows a small effective result budget")
	}
}

func TestEncodedRowSizeMatchesJSONEncodingWithoutMaterialization(t *testing.T) {
	tests := []struct {
		name    string
		raw     []sql.RawBytes
		columns []database.ResultColumn
		row     []any
	}{
		{
			name: "plain and null",
			raw:  []sql.RawBytes{[]byte("plain"), nil, []byte{}},
			columns: []database.ResultColumn{
				{Encoding: "string"}, {Encoding: "string"}, {Encoding: "string"},
			},
			row: []any{"plain", nil, ""},
		},
		{
			name:    "JSON escapes",
			raw:     []sql.RawBytes{{0, '"', '\\', '\n', '<', '>', '&'}},
			columns: []database.ResultColumn{{Encoding: "string"}},
			row:     []any{string([]byte{0, '"', '\\', '\n', '<', '>', '&'})},
		},
		{
			name:    "unicode and invalid UTF-8",
			raw:     []sql.RawBytes{[]byte("café\u2028"), {0xff, 'x'}},
			columns: []database.ResultColumn{{Encoding: "string"}, {Encoding: "string"}},
			row:     []any{"café\u2028", string([]byte{0xff, 'x'})},
		},
		{
			name:    "base64",
			raw:     []sql.RawBytes{{0, 1, 2, 0xff}},
			columns: []database.ResultColumn{{Encoding: "base64"}},
			row:     []any{base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 0xff})},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(test.row)
			if err != nil {
				t.Fatal(err)
			}
			got, ok := encodedRowSize(test.raw, test.columns, len(encoded))
			if !ok || got != len(encoded) {
				t.Fatalf("encodedRowSize() = (%d, %t), want (%d, true)", got, ok, len(encoded))
			}
			if _, ok := encodedRowSize(test.raw, test.columns, len(encoded)-1); ok {
				t.Fatal("encodedRowSize() accepted a budget one byte too small")
			}
		})
	}
}

func TestEncodedRowSizeStopsAtBudgetBeforeEscapedValueExpansion(t *testing.T) {
	raw := []sql.RawBytes{make([]byte, domain.MaxSupportedResultBytes)}
	columns := []database.ResultColumn{{Encoding: "string"}}
	if _, ok := encodedRowSize(raw, columns, 1024); ok {
		t.Fatal("encodedRowSize() accepted an expanded value above the effective budget")
	}
	if allocations := testing.AllocsPerRun(10, func() {
		_, _ = encodedRowSize(raw, columns, 1024)
	}); allocations != 0 {
		t.Fatalf("encodedRowSize() allocations = %v, want 0", allocations)
	}
}

func TestMetadataEncodedSizesMatchJSONWithoutMaterialization(t *testing.T) {
	object := database.SchemaObject{Name: "quoted\"<&>\u2028object"}
	encodedObject, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	objectSize, ok := encodedSchemaObjectSize(object, len(encodedObject))
	if !ok || objectSize != len(encodedObject) {
		t.Fatalf("object size = (%d, %t), want (%d, true)", objectSize, ok, len(encodedObject))
	}
	if _, ok := encodedSchemaObjectSize(object, len(encodedObject)-1); ok {
		t.Fatal("object sizing accepted a budget one byte too small")
	}

	column := database.ColumnDescription{
		Name: "payload", Type: "string", NativeType: "enum('\\n','<&>','\u2029')",
		Nullable: true, PrimaryKey: false, Indexed: true,
	}
	encodedColumn, err := json.Marshal(column)
	if err != nil {
		t.Fatal(err)
	}
	columnSize, ok := encodedColumnDescriptionSize(column, len(encodedColumn))
	if !ok || columnSize != len(encodedColumn) {
		t.Fatalf("column size = (%d, %t), want (%d, true)", columnSize, ok, len(encodedColumn))
	}
	if _, ok := encodedColumnDescriptionSize(column, len(encodedColumn)-1); ok {
		t.Fatal("column sizing accepted a budget one byte too small")
	}

	description := database.ObjectDescription{
		Schema: "app<&>", Name: "orders\u2028", Columns: []database.ColumnDescription{column},
	}
	encodedDescription, err := json.Marshal(description)
	if err != nil {
		t.Fatal(err)
	}
	baseSize, ok := encodedObjectDescriptionBaseSize(
		description.Schema, description.Name, len(encodedDescription),
	)
	if !ok || baseSize+columnSize != len(encodedDescription) {
		t.Fatalf(
			"description size = (%d + %d, %t), want %d",
			baseSize, columnSize, ok, len(encodedDescription),
		)
	}
}

func TestMetadataEncodedSizingStopsBeforeEscapedPayloadAllocation(t *testing.T) {
	column := database.ColumnDescription{
		Name: "payload", Type: "string", NativeType: strings.Repeat("<&", 1<<20),
	}
	if _, ok := encodedColumnDescriptionSize(column, 1024); ok {
		t.Fatal("metadata sizing accepted an escaped value above the absolute budget")
	}
	if allocations := testing.AllocsPerRun(10, func() {
		_, _ = encodedColumnDescriptionSize(column, 1024)
	}); allocations != 0 {
		t.Fatalf("metadata sizing allocations = %v, want 0", allocations)
	}
}

func TestSemanticsForLowerCaseTableNames(t *testing.T) {
	for _, value := range []int{1, 2} {
		semantics, err := semanticsForLowerCaseTableNames(value)
		if err != nil {
			t.Fatalf("value %d: %v", value, err)
		}
		if !semantics.CaseInsensitiveSchemas || !semantics.CaseInsensitiveObjects || !semantics.CaseInsensitiveFields {
			t.Fatalf("value %d semantics = %+v, want all identifiers case-insensitive", value, semantics)
		}
	}
	semantics, err := semanticsForLowerCaseTableNames(0)
	if err != nil {
		t.Fatal(err)
	}
	if semantics.CaseInsensitiveSchemas || semantics.CaseInsensitiveObjects || !semantics.CaseInsensitiveFields {
		t.Fatalf("value 0 semantics = %+v", semantics)
	}
	_, err = semanticsForLowerCaseTableNames(3)
	if !database.IsKind(err, database.ErrorUpstream) {
		t.Fatalf("value 3 error = %v, want upstream error", err)
	}
}

func TestValidateServerVersionAcceptsOnlyMySQL8(t *testing.T) {
	tests := []struct {
		name           string
		version        string
		versionComment string
		wantError      bool
	}{
		{name: "MySQL 8.0.11", version: "8.0.11", versionComment: "MySQL Community Server - GPL"},
		{name: "MySQL 8.0.12", version: "8.0.12", versionComment: "MySQL Community Server - GPL"},
		{name: "MySQL 8.0", version: "8.0.44", versionComment: "MySQL Community Server - GPL"},
		{name: "MySQL 8.4", version: "8.4.7", versionComment: "MySQL Community Server - GPL"},
		{name: "Aurora MySQL 8", version: "8.0.mysql_aurora.3.08.2", versionComment: "Source distribution"},
		{name: "MySQL 5.7", version: "5.7.44", versionComment: "MySQL Community Server - GPL", wantError: true},
		{name: "MySQL 9", version: "9.0.1", versionComment: "MySQL Community Server - GPL", wantError: true},
		{name: "MariaDB", version: "10.11.9-MariaDB", versionComment: "MariaDB Server", wantError: true},
		{name: "spoofed MariaDB major", version: "8.0.36-MariaDB", versionComment: "MariaDB Server", wantError: true},
		{name: "malformed", version: "eight", versionComment: "unknown", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateServerVersion(test.version, test.versionComment)
			if (err != nil) != test.wantError {
				t.Fatalf("validateServerVersion(%q, %q) error = %v, wantError = %v", test.version, test.versionComment, err, test.wantError)
			}
		})
	}
}

func TestBaseTableLookupFollowsServerCaseSemantics(t *testing.T) {
	caseSensitive := baseTableLookupStatement(0)
	if !strings.Contains(caseSensitive, "BINARY table_schema = BINARY ?") ||
		!strings.Contains(caseSensitive, "BINARY table_name = BINARY ?") {
		t.Fatalf("case-sensitive lookup = %q, want binary identifier comparison", caseSensitive)
	}
	for _, value := range []int{1, 2} {
		statement := baseTableLookupStatement(value)
		if strings.Contains(statement, "BINARY") {
			t.Fatalf("lower_case_table_names=%d lookup = %q, want case-insensitive comparison", value, statement)
		}
		if strings.Count(statement, "COLLATE "+caseInsensitiveIdentifierCollation) != 4 {
			t.Fatalf(
				"lower_case_table_names=%d lookup = %q, want accent-sensitive case-insensitive comparisons",
				value, statement,
			)
		}
	}
}

func TestMetadataIdentifierComparisonIsCaseOnly(t *testing.T) {
	caseSensitive := metadataIdentifierComparison("table_schema", "?", false)
	if caseSensitive != "BINARY table_schema = BINARY ?" {
		t.Fatalf("case-sensitive comparison = %q", caseSensitive)
	}
	caseInsensitive := metadataIdentifierComparison("table_schema", "?", true)
	if !strings.Contains(caseInsensitive, "COLLATE "+caseInsensitiveIdentifierCollation) ||
		strings.Contains(caseInsensitive, "general_ci") {
		t.Fatalf("case-insensitive comparison = %q, want explicit accent-sensitive collation", caseInsensitive)
	}

	tests := []struct {
		name            string
		actual          string
		requested       string
		caseInsensitive bool
		want            bool
	}{
		{name: "exact", actual: "resume", requested: "resume", want: true},
		{name: "case-sensitive mismatch", actual: "Resume", requested: "resume"},
		{name: "ASCII case-only match", actual: "Resume", requested: "resume", caseInsensitive: true, want: true},
		{name: "accent mismatch", actual: "résumé", requested: "resume", caseInsensitive: true},
		{name: "unicode fold mismatch", actual: "Key", requested: "Key", caseInsensitive: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := tokenIdentifierMatches(test.actual, test.requested, test.caseInsensitive); got != test.want {
				t.Fatalf("tokenIdentifierMatches() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestConfigureDSNEnforcesMVPTLSModes(t *testing.T) {
	tests := []struct {
		name      string
		dsn       string
		required  bool
		wantError bool
		wantTLS   bool
	}{
		{name: "local plaintext", dsn: "user:password@tcp(mysql:3306)/", required: false},
		{name: "explicit plaintext", dsn: "user:password@tcp(mysql:3306)/?tls=false", required: false},
		{name: "verified TLS", dsn: "user:password@tcp(mysql.example)/?tls=true", required: true, wantTLS: true},
		{name: "required but missing", dsn: "user:password@tcp(mysql:3306)/", required: true, wantError: true},
		{name: "required but disabled", dsn: "user:password@tcp(mysql:3306)/?tls=false", required: true, wantError: true},
		{name: "certificate verification disabled", dsn: "user:password@tcp(mysql:3306)/?tls=skip-verify", required: true, wantError: true},
		{name: "plaintext fallback", dsn: "user:password@tcp(mysql:3306)/?tls=preferred", required: true, wantError: true},
		{name: "TLS without policy requirement", dsn: "user:password@tcp(mysql:3306)/?tls=true", required: false, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := configureDSN(test.dsn, datasourceWithTLS(test.required))
			if (err != nil) != test.wantError {
				t.Fatalf("configureDSN() error = %v, wantError = %v", err, test.wantError)
			}
			if err != nil {
				return
			}
			if (parsed.TLS != nil) != test.wantTLS {
				t.Fatalf("TLS configured = %v, want %v", parsed.TLS != nil, test.wantTLS)
			}
			if parsed.TLS != nil && parsed.TLS.InsecureSkipVerify {
				t.Fatal("accepted TLS configuration disables certificate verification")
			}
			if _, ok := parsed.Logger.(*mysql.NopLogger); !ok {
				t.Fatalf("logger type = %T, want *mysql.NopLogger", parsed.Logger)
			}
		})
	}
}

func TestConfigureDSNRequiresExplicitTLSMode(t *testing.T) {
	if _, err := configureDSN("user:password@tcp(mysql:3306)/", config.Datasource{}); err == nil {
		t.Fatal("expected missing tls_required to be rejected")
	}
}

func TestConfigureDSNForcesServerSideParameterBinding(t *testing.T) {
	parsed, err := configureDSN(
		"user:password@tcp(mysql:3306)/?interpolateParams=true",
		datasourceWithTLS(false),
	)
	if err != nil {
		t.Fatalf("configureDSN() error = %v", err)
	}
	if parsed.InterpolateParams {
		t.Fatal("interpolateParams remained enabled")
	}
}

func TestConfigureDSNForcesNativeTemporalText(t *testing.T) {
	parsed, err := configureDSN(
		"user:password@tcp(mysql:3306)/?parseTime=true",
		datasourceWithTLS(false),
	)
	if err != nil {
		t.Fatalf("configureDSN() error = %v", err)
	}
	if parsed.ParseTime {
		t.Fatal("parseTime remained enabled")
	}
}

func TestConfigureDSNCanonicalizesResultMetadataAndEncoding(t *testing.T) {
	parsed, err := configureDSN(
		"user:password@tcp(mysql:3306)/?columnsWithAlias=true&collation=latin1_swedish_ci",
		datasourceWithTLS(false),
	)
	if err != nil {
		t.Fatalf("configureDSN() error = %v", err)
	}
	if parsed.ColumnsWithAlias {
		t.Fatal("columnsWithAlias remained enabled")
	}
	if parsed.Collation != "utf8mb4_general_ci" {
		t.Fatalf("collation = %q, want utf8mb4_general_ci", parsed.Collation)
	}
}

func TestConfigureDSNRejectsCharsetOverride(t *testing.T) {
	if _, err := configureDSN(
		"user:password@tcp(mysql:3306)/?charset=latin1",
		datasourceWithTLS(false),
	); err == nil {
		t.Fatal("configureDSN() accepted a charset override")
	}
}

func TestConfigureDSNDisablesLocalFileUploads(t *testing.T) {
	parsed, err := configureDSN(
		"user:password@tcp(mysql:3306)/?allowAllFiles=true",
		datasourceWithTLS(false),
	)
	if err != nil {
		t.Fatalf("configureDSN() error = %v", err)
	}
	if parsed.AllowAllFiles {
		t.Fatal("allowAllFiles remained enabled")
	}
}

func TestConfigureDSNOwnsReadOnlySessionSettings(t *testing.T) {
	parsed, err := configureDSN("user:password@tcp(mysql:3306)/", datasourceWithTLS(false))
	if err != nil {
		t.Fatalf("configureDSN() error = %v", err)
	}
	if len(parsed.Params) != 1 || parsed.Params["transaction_read_only"] != "ON" {
		t.Fatalf("session parameters = %#v, want canonical read-only setting", parsed.Params)
	}

	for _, dsn := range []string{
		"user:password@tcp(mysql:3306)/?TRANSACTION_READ_ONLY=OFF",
		"user:password@tcp(mysql:3306)/?@@session.transaction_read_only=OFF",
		"user:password@tcp(mysql:3306)/?@@LOCAL.Tx_Read_Only=OFF",
		"user:password@tcp(mysql:3306)/?time_zone=%27UTC%27",
	} {
		if _, err := configureDSN(dsn, datasourceWithTLS(false)); err == nil {
			t.Fatalf("configureDSN(%q) accepted a generic session parameter", dsn)
		}
	}
}

func datasourceWithTLS(required bool) config.Datasource {
	return config.Datasource{TLSRequired: &required}
}

type recordingRows struct {
	calls     []string
	remaining int
	err       error
}

type selectRowsStub struct {
	remaining int
	nextCalls int
	scanCalls int
	value     sql.RawBytes
	err       error
}

func (r *selectRowsStub) Next() bool {
	r.nextCalls++
	if r.remaining == 0 {
		return false
	}
	r.remaining--
	return true
}

func (r *selectRowsStub) Scan(destinations ...any) error {
	r.scanCalls++
	for _, destination := range destinations {
		*(destination.(*sql.RawBytes)) = r.value
	}
	return r.err
}

func (r *selectRowsStub) Err() error   { return nil }
func (r *selectRowsStub) Close() error { return nil }

func (r *recordingRows) Next() bool {
	r.calls = append(r.calls, "next")
	if r.remaining == 0 {
		return false
	}
	r.remaining--
	return true
}

func (r *recordingRows) Err() error {
	r.calls = append(r.calls, "err")
	return r.err
}

func (r *recordingRows) Close() error {
	r.calls = append(r.calls, "close")
	return nil
}

func TestDrainAndCloseRowsConsumesTerminatorBeforeClose(t *testing.T) {
	rows := &recordingRows{remaining: 1}
	if err := drainAndCloseRows(rows); err != nil {
		t.Fatalf("drainAndCloseRows() error = %v", err)
	}
	want := []string{"next", "next", "err", "close"}
	if strings.Join(rows.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("calls = %#v, want %#v", rows.calls, want)
	}
}

func TestCollectSelectRowsStopsScanningAfterByteTruncation(t *testing.T) {
	rows := &selectRowsStub{remaining: 1000, value: sql.RawBytes("value")}
	result := database.SelectResult{Rows: make([][]*string, 0), ResultBytes: 20}
	err := collectSelectRows(
		context.Background(),
		rows,
		[]database.ResultColumn{{Encoding: "string"}},
		1000,
		22,
		&result,
	)
	if err != nil {
		t.Fatalf("collectSelectRows() error = %v", err)
	}
	if !result.Truncated || len(result.Rows) != 0 {
		t.Fatalf("result = %+v, want an empty truncated prefix", result)
	}
	if rows.scanCalls != 1 {
		t.Fatalf("Scan calls = %d, want 1", rows.scanCalls)
	}
	if rows.nextCalls != 1001 {
		t.Fatalf("Next calls = %d, want full result drain", rows.nextCalls)
	}
}

func TestCompileUsesQuotedIdentifiersAndBoundValues(t *testing.T) {
	spec := queryspec.NormalizedSpec{
		Source: queryspec.ResourceRef{Schema: "application", Name: "orders"},
		Projection: []queryspec.Selection{
			{Kind: "field", Field: "id"},
			{Kind: "aggregate", Function: "count", Alias: "total"},
		},
		Filter: &queryspec.Filter{
			Kind: "predicate", Field: "status", Operator: "eq",
			Values: []queryspec.TypedValue{{Type: "string", Value: []byte(`"private-value"`)}},
		},
		OrderBy: []queryspec.Sort{{Field: "id", Direction: "desc"}},
		Limit:   25, Offset: 5,
	}
	statement, args, err := compile(spec, 3000)
	if err != nil {
		t.Fatalf("compile() error = %v", err)
	}
	if strings.Contains(statement, "private-value") {
		t.Fatal("compiled SQL contains a predicate value")
	}
	want := "EXPLAIN FORMAT=JSON SELECT /*+ MAX_EXECUTION_TIME(3000) */ `id`, COUNT(*) AS `total` FROM `application`.`orders` WHERE `status` = ? ORDER BY `application`.`orders`.`id` DESC LIMIT ? OFFSET ?"
	if statement != want {
		t.Fatalf("statement = %q, want %q", statement, want)
	}
	if len(args) != 3 || args[0] != "private-value" || args[1] != 25 || args[2] != 5 {
		t.Fatalf("args = %#v", args)
	}
}

func TestCompileQualifiesSourceFieldsWhenProjectionAliasCollides(t *testing.T) {
	spec := queryspec.NormalizedSpec{
		Source: queryspec.ResourceRef{Schema: "application", Name: "orders"},
		Projection: []queryspec.Selection{
			{Kind: "aggregate", Function: "count", Alias: "id"},
		},
		GroupBy: []string{"id"},
		OrderBy: []queryspec.Sort{{Field: "id", Direction: "asc"}},
		Limit:   10,
	}
	statement, _, err := compile(spec, 3000)
	if err != nil {
		t.Fatalf("compile() error = %v", err)
	}
	want := "EXPLAIN FORMAT=JSON SELECT /*+ MAX_EXECUTION_TIME(3000) */ COUNT(*) AS `id` FROM `application`.`orders` GROUP BY `application`.`orders`.`id` ORDER BY `application`.`orders`.`id` ASC LIMIT ? OFFSET ?"
	if statement != want {
		t.Fatalf("statement = %q, want %q", statement, want)
	}
}

func TestCompileSelectUsesOnlyBoundedFieldQuery(t *testing.T) {
	spec := queryspec.NormalizedSpec{
		Source: queryspec.ResourceRef{Schema: "application", Name: "orders"},
		Projection: []queryspec.Selection{
			{Kind: "field", Field: "id"},
			{Kind: "field", Field: "status", Alias: "state"},
		},
		Filter: &queryspec.Filter{Kind: "predicate", Field: "status", Operator: "eq", Values: []queryspec.TypedValue{
			{Type: "string", Value: []byte(`"active"`)},
		}},
		OrderBy: []queryspec.Sort{{Field: "id", Direction: "desc"}},
		Limit:   10, Offset: 2,
	}
	statement, args, err := compileSelect(spec, 1500, 11)
	if err != nil {
		t.Fatal(err)
	}
	want := "SELECT /*+ MAX_EXECUTION_TIME(1500) */ `application`.`orders`.`id`, `application`.`orders`.`status` AS `state` FROM `application`.`orders` WHERE `status` = ? ORDER BY `application`.`orders`.`id` DESC LIMIT ? OFFSET ?"
	if statement != want {
		t.Fatalf("statement = %q, want %q", statement, want)
	}
	if len(args) != 3 || args[0] != "active" || args[1] != 11 || args[2] != 2 {
		t.Fatalf("args = %#v", args)
	}
}

func TestAdapterRejectsZeroQueryAuthorizationBeforeDatabaseAccess(t *testing.T) {
	adapter := New()
	if _, err := adapter.Explain(context.Background(), nil, policy.AuthorizedQuery{}); !database.IsKind(err, database.ErrorUpstream) {
		t.Fatalf("zero explain authorization error = %v", err)
	}
	if _, err := adapter.Select(context.Background(), nil, policy.AuthorizedQuery{}); !database.IsKind(err, database.ErrorUpstream) {
		t.Fatalf("zero select authorization error = %v", err)
	}
}

func TestInstanceDDLGuardStatementsDoNotNameTheRequestedResource(t *testing.T) {
	for _, statement := range []string{instanceDDLGuardLockSQL, instanceDDLGuardUnlockSQL} {
		lower := strings.ToLower(statement)
		if strings.Contains(lower, "application") || strings.Contains(lower, "orders") ||
			strings.Contains(lower, "view") || strings.Contains(lower, "table") {
			t.Fatalf("DDL guard statement %q resolves a user resource", statement)
		}
	}
}

func TestPinAndValidateBaseTableAcquiresGuardBeforeLookup(t *testing.T) {
	calls := make([]string, 0, 3)
	release, err := pinAndValidateBaseTable(
		func() (func() error, error) {
			calls = append(calls, "guard")
			return func() error {
				calls = append(calls, "release")
				return nil
			}, nil
		},
		func() (bool, error) {
			calls = append(calls, "check")
			return true, nil
		},
	)
	if err != nil {
		t.Fatalf("pinAndValidateBaseTable() error = %v", err)
	}
	if got := strings.Join(calls, ","); got != "guard,check" {
		t.Fatalf("calls before release = %q, want guard,check", got)
	}
	if err := release(); err != nil {
		t.Fatalf("release() error = %v", err)
	}
	if got := strings.Join(calls, ","); got != "guard,check,release" {
		t.Fatalf("calls = %q, want guard,check,release", got)
	}
}

func TestPinAndValidateBaseTableRejectsViewUnderGuard(t *testing.T) {
	calls := make([]string, 0, 3)
	release, err := pinAndValidateBaseTable(
		func() (func() error, error) {
			calls = append(calls, "guard")
			return func() error {
				calls = append(calls, "release")
				return nil
			}, nil
		},
		func() (bool, error) {
			calls = append(calls, "check")
			return false, nil
		},
	)
	if release != nil || !database.IsKind(err, database.ErrorInvalid) {
		t.Fatalf("release present = %t, error = %v; want rejected view", release != nil, err)
	}
	if got := strings.Join(calls, ","); got != "guard,check,release" {
		t.Fatalf("calls = %q, want guard,check,release", got)
	}
}

func TestPortableColumnTypeAndResultEncoding(t *testing.T) {
	tests := map[string]string{
		"BIGINT": "integer", "UNSIGNED BIGINT": "integer", "UNSIGNED TINYINT": "integer",
		"DECIMAL": "decimal", "VARCHAR": "string",
		"DATE": "date", "DATETIME": "datetime", "TIME": "time",
		"BLOB": "bytes", "GEOMETRY": "bytes", "POINT": "bytes", "MULTIPOLYGON": "bytes",
		"JSON": "json",
	}
	for databaseType, want := range tests {
		if got := portableColumnType(databaseType); got != want {
			t.Fatalf("portableColumnType(%q) = %q, want %q", databaseType, got, want)
		}
	}
	if got := resultEncoding("VARBINARY"); got != "base64" {
		t.Fatalf("binary encoding = %q", got)
	}
	if got := resultEncoding("GEOMETRY"); got != "base64" {
		t.Fatalf("spatial encoding = %q", got)
	}
	if got := resultEncoding("DECIMAL"); got != "string" {
		t.Fatalf("decimal encoding = %q", got)
	}
}

func TestCompileFilterPreservesGrouping(t *testing.T) {
	filter := queryspec.Filter{Kind: "group", Operator: "or", Expressions: []queryspec.Filter{
		{Kind: "predicate", Field: "status", Operator: "is_null", Values: []queryspec.TypedValue{}},
		{Kind: "predicate", Field: "id", Operator: "in", Values: []queryspec.TypedValue{
			{Type: "integer", Value: []byte(`1`)}, {Type: "integer", Value: []byte(`2`)},
		}},
	}}
	statement, args, err := compileFilter(filter)
	if err != nil {
		t.Fatalf("compileFilter() error = %v", err)
	}
	if statement != "(`status` IS NULL OR `id` IN (?, ?))" {
		t.Fatalf("statement = %q", statement)
	}
	if len(args) != 2 {
		t.Fatalf("args = %#v", args)
	}
}

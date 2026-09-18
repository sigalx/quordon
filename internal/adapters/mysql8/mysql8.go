package mysql8

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryspec"
)

type Adapter struct{}

// A result row has a small amount of MySQL protocol framing around the JSON
// value. Keeping a fixed allowance also lets the driver read result metadata;
// the exact JSON size is still checked after Scan.
const (
	resultPacketOverhead  = 1024
	sessionCleanupTimeout = time.Second
)

func New() *Adapter { return &Adapter{} }

func (*Adapter) Name() string { return domain.AdapterMySQL8 }

func (*Adapter) Features() []domain.AdapterFeature {
	return []domain.AdapterFeature{domain.FeatureNumericBucketExact, domain.FeatureTimeBucketUTC, domain.FeatureSourceText}
}

func (*Adapter) Capabilities() []domain.Operation {
	return []domain.Operation{
		domain.OperationListObjects,
		domain.OperationDescribeObject,
		domain.OperationExplainSelect,
		domain.OperationSelect,
		domain.OperationSelectKeyset,
		domain.OperationAggregate,
		domain.OperationDescribeObjectStatistics,
	}
}

func (a *Adapter) Validate(ctx context.Context, db *sql.DB) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return classifyExecutionError(ctx, err)
	}
	defer conn.Close()
	if _, err := readServerInfo(ctx, conn); err != nil {
		return err
	}
	return nil
}

func (*Adapter) IdentifierSemantics(ctx context.Context, db *sql.DB) (domain.IdentifierSemantics, error) {
	info, err := readServerInfo(ctx, db)
	if err != nil {
		return domain.IdentifierSemantics{}, err
	}
	return semanticsForLowerCaseTableNames(info.lowerCaseTableNames)
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type serverInfo struct {
	version             string
	versionComment      string
	lowerCaseTableNames int
}

func readServerInfo(ctx context.Context, queryer queryRower) (serverInfo, error) {
	var info serverInfo
	if err := queryer.QueryRowContext(
		ctx,
		"SELECT @@version, @@version_comment, @@lower_case_table_names",
	).Scan(&info.version, &info.versionComment, &info.lowerCaseTableNames); err != nil {
		return serverInfo{}, classifyExecutionError(ctx, err)
	}
	if err := validateServerVersion(info.version, info.versionComment); err != nil {
		return serverInfo{}, &database.Error{Kind: database.ErrorUnavailable, Err: err}
	}
	if _, err := semanticsForLowerCaseTableNames(info.lowerCaseTableNames); err != nil {
		return serverInfo{}, err
	}
	return info, nil
}

func validateServerVersion(version, versionComment string) error {
	identity := strings.ToLower(version + " " + versionComment)
	if strings.Contains(identity, "mariadb") {
		return errors.New("MariaDB is not supported by the mysql8 adapter")
	}
	components := strings.SplitN(version, ".", 3)
	if len(components) < 2 {
		return fmt.Errorf("invalid MySQL server version %q", version)
	}
	major, err := strconv.Atoi(components[0])
	if err != nil {
		return fmt.Errorf("invalid MySQL server version %q", version)
	}
	if _, err := strconv.Atoi(components[1]); err != nil {
		return fmt.Errorf("invalid MySQL server version %q", version)
	}
	if major != 8 {
		return fmt.Errorf("unsupported MySQL server major version %d", major)
	}
	return nil
}

func semanticsForLowerCaseTableNames(value int) (domain.IdentifierSemantics, error) {
	switch value {
	case 0:
		return domain.IdentifierSemantics{CaseInsensitiveFields: true}, nil
	case 1, 2:
		return domain.IdentifierSemantics{
			CaseInsensitiveSchemas: true,
			CaseInsensitiveObjects: true,
			CaseInsensitiveFields:  true,
		}, nil
	default:
		return domain.IdentifierSemantics{}, &database.Error{
			Kind: database.ErrorUpstream,
			Err:  fmt.Errorf("unsupported lower_case_table_names value %d", value),
		}
	}
}

func (*Adapter) Open(dsn string, datasource config.Datasource) (*sql.DB, error) {
	parsed, err := configureDSN(dsn, datasource)
	if err != nil {
		return nil, err
	}
	connector, err := mysql.NewConnector(parsed)
	if err != nil {
		return nil, errors.New("configure MySQL connector")
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(datasource.Pool.MaxOpenConnections)
	db.SetMaxIdleConns(datasource.Pool.MaxIdleConnections)
	db.SetConnMaxLifetime(time.Duration(datasource.Pool.MaxConnectionLifetimeSeconds) * time.Second)
	return db, nil
}

func configureDSN(dsn string, datasource config.Datasource) (*mysql.Config, error) {
	parsed, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, errors.New("invalid MySQL DSN")
	}
	if datasource.TLSRequired == nil {
		return nil, errors.New("tls_required must be set explicitly")
	}
	if err := validateTLSMode(parsed, *datasource.TLSRequired); err != nil {
		return nil, err
	}
	// The driver's default logger writes raw internal errors to stderr. All
	// externally visible failures are classified and sanitized by the adapter.
	parsed.Logger = &mysql.NopLogger{}
	parsed.MultiStatements = false
	// EXPLAIN never needs LOAD DATA LOCAL INFILE. Leaving allowAllFiles enabled
	// would let a compromised server request any file readable by this process.
	parsed.AllowAllFiles = false
	// Quordon's security boundary requires server-side prepared statements;
	// never allow a datasource DSN to replace placeholders with SQL literals.
	parsed.InterpolateParams = false
	// SELECT results use MySQL's native textual DATE/DATETIME/TIMESTAMP
	// representation. Letting parseTime vary by DSN would change the public API
	// values by converting them to RFC3339 time.Time strings.
	parsed.ParseTime = false
	// Result column names and text encoding are part of the public API. The
	// driver otherwise lets datasource DSNs qualify names with table aliases or
	// negotiate a legacy single-byte connection collation.
	parsed.ColumnsWithAlias = false
	parsed.Collation = "utf8mb4_general_ci"
	// The driver's charset option is stored in unexported configuration state,
	// so it cannot be safely canonicalized after ParseDSN. Reject it instead of
	// allowing it to override the UTF8MB4 connection collation above.
	if dsnHasParameter(dsn, "charset") {
		return nil, errors.New("MySQL DSN charset parameter is not supported")
	}
	// The compressed protocol buffers compressed frames before the logical
	// packet header is available, so it cannot provide the pre-allocation bound
	// required for EXPLAIN results.
	if err := parsed.Apply(mysql.EnableCompression(false)); err != nil {
		return nil, errors.New("disable MySQL protocol compression")
	}
	// Generic DSN parameters are emitted as raw session-variable assignments.
	// They are unnecessary for the EXPLAIN MVP and could override the adapter's
	// read-only setting through qualified aliases or compound SQL expressions.
	if len(parsed.Params) != 0 {
		return nil, errors.New("MySQL DSN session-variable parameters are not supported")
	}
	parsed.Params = map[string]string{"transaction_read_only": "ON"}
	return parsed, nil
}

func validateTLSMode(parsed *mysql.Config, required bool) error {
	if required {
		if parsed.TLSConfig != "true" || parsed.TLS == nil || parsed.TLS.InsecureSkipVerify || parsed.AllowFallbackToPlaintext {
			return errors.New("tls_required requires DSN parameter tls=true with server certificate verification")
		}
		return nil
	}
	if parsed.TLSConfig != "" && parsed.TLSConfig != "false" {
		return errors.New("TLS DSN modes require tls_required: true; the MVP supports only tls=true")
	}
	return nil
}

func dsnHasParameter(dsn, name string) bool {
	slash := strings.LastIndexByte(dsn, '/')
	if slash < 0 {
		return false
	}
	query := dsn[slash+1:]
	question := strings.IndexByte(query, '?')
	if question < 0 {
		return false
	}
	for parameter := range strings.SplitSeq(query[question+1:], "&") {
		key, _, found := strings.Cut(parameter, "=")
		if found && key == name {
			return true
		}
	}
	return false
}

func bindConnectionDeadline(ctx context.Context, conn *sql.Conn, deadlineMS int) (func() error, error) {
	if deadlineMS <= 0 {
		return nil, errors.New("invalid query deadline")
	}
	deadline := time.Now().Add(time.Duration(deadlineMS) * time.Millisecond)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := setConnectionDeadline(conn, deadline); err != nil {
		return nil, err
	}
	return func() error { return setConnectionDeadline(conn, time.Time{}) }, nil
}

func setConnectionDeadline(conn *sql.Conn, deadline time.Time) error {
	return conn.Raw(func(driverConn any) error {
		return mysql.SetConnectionDeadline(driverConn, deadline)
	})
}

func discardSQLConnection(conn *sql.Conn) {
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
}

func (a *Adapter) Explain(ctx context.Context, db *sql.DB, query policy.AuthorizedQuery) (result database.ExplainResult, resultErr error) {
	if query.Operation() != domain.OperationExplainSelect {
		return database.ExplainResult{}, invalidAuthorizationError("explain_select")
	}
	statement, args, err := compile(query.Query(), query.Limits().DeadlineMS)
	if err != nil {
		return database.ExplainResult{}, &database.Error{Kind: database.ErrorUpstream, Err: err}
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return database.ExplainResult{}, classifyExecutionError(ctx, err)
	}
	defer conn.Close()
	clearDeadline, err := bindConnectionDeadline(ctx, conn, query.Limits().DeadlineMS)
	if err != nil {
		return database.ExplainResult{}, classifyExecutionError(ctx, err)
	}
	defer func() {
		if clearDeadline != nil {
			_ = clearDeadline()
		}
	}()
	info, err := readServerInfo(ctx, conn)
	if err != nil {
		return database.ExplainResult{}, err
	}
	cleanup, err := prepareLegacySourceText(ctx, conn, query.Query(), info.lowerCaseTableNames)
	if err != nil {
		return database.ExplainResult{}, err
	}
	defer func() {
		if cleanup == nil {
			return
		}
		if resultErr != nil && queryspec.UsesSourceText(query.Query()) {
			discardSQLConnection(conn)
			return
		}
		if err := cleanup(); err != nil {
			result = database.ExplainResult{}
			resultErr = err
		}
	}()
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return database.ExplainResult{}, classifyExecutionError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	ctx = mysql.WithMaxReadPacketSize(ctx, boundedPacketSize(query.Limits().MaxResultBytes))
	rows, err := tx.QueryContext(ctx, statement, args...)
	if err != nil {
		return database.ExplainResult{}, classifyExplainError(ctx, err)
	}
	// An explicit Rows.Close stops go-sql-driver's context watcher before it
	// drains unread packets. Drain through Next first so cancellation or the
	// query deadline can still close a stalled connection on every early return.
	defer func() { _ = drainAndCloseRows(rows) }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return database.ExplainResult{}, classifyExecutionError(ctx, err)
		}
		return database.ExplainResult{}, &database.Error{Kind: database.ErrorUpstream, Err: errors.New("MySQL returned no JSON plan")}
	}
	// RawBytes avoids database/sql's additional full-size copy. The patched
	// driver has already bounded the underlying packet from its header.
	var raw sql.RawBytes
	if err := rows.Scan(&raw); err != nil {
		return database.ExplainResult{}, classifyExecutionError(ctx, err)
	}
	if len(raw) > query.Limits().MaxResultBytes {
		return database.ExplainResult{}, &database.Error{Kind: database.ErrorResultTooLarge}
	}
	if !json.Valid(raw) {
		return database.ExplainResult{}, &database.Error{Kind: database.ErrorUpstream, Err: errors.New("MySQL returned an invalid JSON plan")}
	}
	plan := append(json.RawMessage(nil), raw...)
	if rows.Next() {
		return database.ExplainResult{}, &database.Error{Kind: database.ErrorUpstream, Err: errors.New("MySQL returned multiple JSON plans")}
	}
	if err := rows.Err(); err != nil {
		return database.ExplainResult{}, classifyExecutionError(ctx, err)
	}
	if err := rows.Close(); err != nil {
		return database.ExplainResult{}, classifyExecutionError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return database.ExplainResult{}, classifyExecutionError(ctx, err)
	}
	if err := cleanup(); err != nil {
		return database.ExplainResult{}, err
	}
	cleanup = nil
	if err := clearDeadline(); err != nil {
		return database.ExplainResult{}, classifyExecutionError(ctx, err)
	}
	clearDeadline = nil
	return database.ExplainResult{Format: "mysql_json", Plan: plan}, nil
}

func invalidSourceError() *database.Error {
	return &database.Error{
		Kind: database.ErrorInvalid,
		Err:  errors.New("query source does not exist"),
	}
}

func classifyExplainError(ctx context.Context, err error) *database.Error {
	return classifyQueryError(ctx, err)
}

func classifyQueryError(ctx context.Context, err error) *database.Error {
	var mysqlError *mysql.MySQLError
	if errors.As(err, &mysqlError) &&
		(mysqlError.Number == 1054 || mysqlError.Number == 1146 || mysqlError.Number == 1356) {
		return &database.Error{Kind: database.ErrorInvalid, Err: err}
	}
	return classifyExecutionError(ctx, err)
}

const caseInsensitiveIdentifierCollation = "utf8mb4_0900_as_ci"

func metadataIdentifierComparison(left, right string, caseInsensitive bool) string {
	if !caseInsensitive {
		return "BINARY " + left + " = BINARY " + right
	}
	return "CONVERT(" + left + " USING utf8mb4) COLLATE " + caseInsensitiveIdentifierCollation +
		" = CONVERT(" + right + " USING utf8mb4) COLLATE " + caseInsensitiveIdentifierCollation
}

func tokenIdentifierMatches(actual, requested string, caseInsensitive bool) bool {
	if !caseInsensitive {
		return actual == requested
	}
	if len(actual) != len(requested) {
		return false
	}
	for index := range actual {
		actualByte := actual[index]
		requestedByte := requested[index]
		if actualByte >= 'A' && actualByte <= 'Z' {
			actualByte += 'a' - 'A'
		}
		if requestedByte >= 'A' && requestedByte <= 'Z' {
			requestedByte += 'a' - 'A'
		}
		if actualByte != requestedByte {
			return false
		}
	}
	return true
}

func metadataResourceMismatchError() *database.Error {
	return &database.Error{
		Kind: database.ErrorUpstream,
		Err:  errors.New("database metadata returned a resource outside the authorized coordinates"),
	}
}

func (*Adapter) ListObjects(
	ctx context.Context,
	db *sql.DB,
	schema string,
) ([]database.SchemaObject, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, classifyExecutionError(ctx, err)
	}
	defer conn.Close()
	info, err := readServerInfo(ctx, conn)
	if err != nil {
		return nil, err
	}
	caseInsensitive := info.lowerCaseTableNames != 0
	comparison := metadataIdentifierComparison("table_schema", "?", caseInsensitive)
	statement := `SELECT table_schema, table_name
FROM information_schema.tables
WHERE ` + comparison + `
ORDER BY table_name`
	ctx = mysql.WithMaxReadPacketSize(ctx, absoluteResultPacketSize())
	rows, err := conn.QueryContext(ctx, statement, schema)
	if err != nil {
		return nil, classifyQueryError(ctx, err)
	}
	defer func() { _ = drainAndCloseRows(rows) }()
	objects := make([]database.SchemaObject, 0)
	encodedBytes := len(`{"objects":[]}`)
	for rows.Next() {
		var actualSchema string
		var object database.SchemaObject
		if err := rows.Scan(&actualSchema, &object.Name); err != nil {
			return nil, classifyExecutionError(ctx, err)
		}
		if !tokenIdentifierMatches(actualSchema, schema, caseInsensitive) {
			return nil, metadataResourceMismatchError()
		}
		objectBytes, ok := encodedSchemaObjectSize(object, domain.MaxSupportedResultBytes)
		if !ok {
			return nil, &database.Error{Kind: database.ErrorResultTooLarge}
		}
		increment := objectBytes
		if len(objects) != 0 {
			increment++
		}
		encodedBytes, ok = addEncodedSize(encodedBytes, increment, domain.MaxSupportedResultBytes)
		if !ok {
			return nil, &database.Error{Kind: database.ErrorResultTooLarge}
		}
		objects = append(objects, object)
	}
	if err := rows.Err(); err != nil {
		return nil, classifyExecutionError(ctx, err)
	}
	if err := rows.Close(); err != nil {
		return nil, classifyExecutionError(ctx, err)
	}
	return objects, nil
}

func (*Adapter) DescribeObject(
	ctx context.Context,
	db *sql.DB,
	object queryspec.ResourceRef,
) (database.ObjectDescription, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return database.ObjectDescription{}, classifyExecutionError(ctx, err)
	}
	defer conn.Close()
	info, err := readServerInfo(ctx, conn)
	if err != nil {
		return database.ObjectDescription{}, err
	}
	caseInsensitive := info.lowerCaseTableNames != 0
	schemaComparison := metadataIdentifierComparison("t.table_schema", "?", caseInsensitive)
	objectComparison := metadataIdentifierComparison("t.table_name", "?", caseInsensitive)
	columnJoin := metadataIdentifierComparison("c.table_schema", "t.table_schema", caseInsensitive) +
		" AND " + metadataIdentifierComparison("c.table_name", "t.table_name", caseInsensitive)
	statisticsJoin := metadataIdentifierComparison("s.table_schema", "c.table_schema", caseInsensitive) +
		" AND " + metadataIdentifierComparison("s.table_name", "c.table_name", caseInsensitive)
	columnComparison := metadataIdentifierComparison("s.column_name", "c.column_name", true)
	statement := `SELECT t.table_schema, t.table_name, c.column_name, c.data_type, c.column_type, c.is_nullable,
       c.column_key = 'PRI', EXISTS (
	           SELECT 1 FROM information_schema.statistics s
	           WHERE ` + statisticsJoin + `
	             AND ` + columnComparison + `
       )
FROM information_schema.tables t
JOIN information_schema.columns c
  ON ` + columnJoin + `
WHERE ` + schemaComparison + ` AND ` + objectComparison + `
ORDER BY c.ordinal_position`
	ctx = mysql.WithMaxReadPacketSize(ctx, absoluteResultPacketSize())
	rows, err := conn.QueryContext(ctx, statement, object.Schema, object.Name)
	if err != nil {
		return database.ObjectDescription{}, classifyQueryError(ctx, err)
	}
	defer func() { _ = drainAndCloseRows(rows) }()
	description := database.ObjectDescription{
		Schema: object.Schema, Name: object.Name, Columns: []database.ColumnDescription{},
	}
	columnsBytes := 0
	if _, ok := encodedObjectDescriptionBaseSize(
		description.Schema, description.Name, domain.MaxSupportedResultBytes,
	); !ok {
		return database.ObjectDescription{}, &database.Error{Kind: database.ErrorResultTooLarge}
	}
	for rows.Next() {
		var column database.ColumnDescription
		var actualSchema, actualName, dataType, nullable string
		if err := rows.Scan(
			&actualSchema, &actualName, &column.Name, &dataType, &column.NativeType, &nullable,
			&column.PrimaryKey, &column.Indexed,
		); err != nil {
			return database.ObjectDescription{}, classifyExecutionError(ctx, err)
		}
		if !tokenIdentifierMatches(actualSchema, object.Schema, caseInsensitive) ||
			!tokenIdentifierMatches(actualName, object.Name, caseInsensitive) {
			return database.ObjectDescription{}, metadataResourceMismatchError()
		}
		column.Type = portableColumnType(dataType)
		column.Nullable = nullable == "YES"
		baseBytes, ok := encodedObjectDescriptionBaseSize(
			actualSchema, actualName, domain.MaxSupportedResultBytes,
		)
		if !ok {
			return database.ObjectDescription{}, &database.Error{Kind: database.ErrorResultTooLarge}
		}
		columnBytes, ok := encodedColumnDescriptionSize(column, domain.MaxSupportedResultBytes)
		if !ok {
			return database.ObjectDescription{}, &database.Error{Kind: database.ErrorResultTooLarge}
		}
		increment := columnBytes
		if len(description.Columns) != 0 {
			increment++
		}
		nextColumnsBytes, ok := addEncodedSize(columnsBytes, increment, domain.MaxSupportedResultBytes)
		if !ok {
			return database.ObjectDescription{}, &database.Error{Kind: database.ErrorResultTooLarge}
		}
		if _, ok := addEncodedSize(baseBytes, nextColumnsBytes, domain.MaxSupportedResultBytes); !ok {
			return database.ObjectDescription{}, &database.Error{Kind: database.ErrorResultTooLarge}
		}
		description.Schema = actualSchema
		description.Name = actualName
		columnsBytes = nextColumnsBytes
		description.Columns = append(description.Columns, column)
	}
	if err := rows.Err(); err != nil {
		return database.ObjectDescription{}, classifyExecutionError(ctx, err)
	}
	if err := rows.Close(); err != nil {
		return database.ObjectDescription{}, classifyExecutionError(ctx, err)
	}
	if len(description.Columns) == 0 {
		return database.ObjectDescription{}, &database.Error{Kind: database.ErrorInvalid, Err: sql.ErrNoRows}
	}
	return description, nil
}

func (a *Adapter) Select(
	ctx context.Context,
	db *sql.DB,
	query policy.AuthorizedQuery,
) (result database.SelectResult, resultErr error) {
	if query.Operation() != domain.OperationSelect {
		return database.SelectResult{}, invalidAuthorizationError("select")
	}
	spec := query.Query()
	statement, args, err := compileSelect(spec, query.Limits().DeadlineMS, spec.Limit+1)
	if err != nil {
		return database.SelectResult{}, &database.Error{Kind: database.ErrorUpstream, Err: err}
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return database.SelectResult{}, classifyExecutionError(ctx, err)
	}
	defer conn.Close()
	clearDeadline, err := bindConnectionDeadline(ctx, conn, query.Limits().DeadlineMS)
	if err != nil {
		return database.SelectResult{}, classifyExecutionError(ctx, err)
	}
	defer func() {
		if clearDeadline != nil {
			_ = clearDeadline()
		}
	}()
	info, err := readServerInfo(ctx, conn)
	if err != nil {
		return database.SelectResult{}, err
	}
	cleanup, err := prepareLegacySourceText(ctx, conn, spec, info.lowerCaseTableNames)
	if err != nil {
		return database.SelectResult{}, err
	}
	defer func() {
		if cleanup == nil {
			return
		}
		if resultErr != nil && queryspec.UsesSourceText(spec) {
			discardSQLConnection(conn)
			return
		}
		if err := cleanup(); err != nil {
			result = database.SelectResult{}
			resultErr = err
		}
	}()
	ctx = mysql.WithMaxReadPacketSize(ctx, absoluteResultPacketSize())
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return database.SelectResult{}, classifyExecutionError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	// The effective result budget is enforced while serializing rows below. A
	// separate absolute packet bound allows a later row to be consumed and
	// reported as truncated without permitting an unbounded driver allocation.
	rows, err := tx.QueryContext(ctx, statement, args...)
	if err != nil {
		return database.SelectResult{}, classifyQueryError(ctx, err)
	}
	defer func() { _ = drainAndCloseRows(rows) }()
	columnTypes, err := rows.ColumnTypes()
	if err != nil {
		return database.SelectResult{}, classifyExecutionError(ctx, err)
	}
	columns := make([]database.ResultColumn, len(columnTypes))
	for index, columnType := range columnTypes {
		nullable, known := columnType.Nullable()
		columns[index] = database.ResultColumn{
			Name: columnType.Name(), Type: portableColumnType(columnType.DatabaseTypeName()),
			Encoding: resultEncoding(columnType.DatabaseTypeName()), Nullable: !known || nullable,
		}
	}
	for index, selection := range spec.Projection {
		if selection.Representation == queryspec.RepresentationSourceText {
			columns[index].Type = "string"
			columns[index].Encoding = "string"
		}
	}
	columnsJSON, err := json.Marshal(columns)
	if err != nil {
		return database.SelectResult{}, &database.Error{Kind: database.ErrorUpstream, Err: err}
	}
	resultBytes := len(`{"columns":`) + len(columnsJSON) + len(`,"rows":[]}`)
	if resultBytes > query.Limits().MaxResultBytes {
		return database.SelectResult{}, &database.Error{Kind: database.ErrorResultTooLarge}
	}
	result = database.SelectResult{Columns: columns, Rows: make([][]*string, 0), ResultBytes: resultBytes}
	if err := collectSelectRows(ctx, rows, columns, spec.Limit, query.Limits().MaxResultBytes, &result); err != nil {
		return database.SelectResult{}, err
	}
	if err := rows.Close(); err != nil {
		return database.SelectResult{}, classifyExecutionError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return database.SelectResult{}, classifyExecutionError(ctx, err)
	}
	if err := cleanup(); err != nil {
		return database.SelectResult{}, err
	}
	cleanup = nil
	if err := clearDeadline(); err != nil {
		return database.SelectResult{}, classifyExecutionError(ctx, err)
	}
	clearDeadline = nil
	result.RowCount = len(result.Rows)
	return result, nil
}

type selectRowSet interface {
	rowSet
	Scan(...any) error
}

func collectSelectRows(
	ctx context.Context,
	rows selectRowSet,
	columns []database.ResultColumn,
	limit int,
	maxResultBytes int,
	result *database.SelectResult,
) error {
	rawValues := make([]sql.RawBytes, len(columns))
	destinations := make([]any, len(columns))
	for index := range rawValues {
		destinations[index] = &rawValues[index]
	}
	for rows.Next() {
		// Once a safe prefix is complete, advancing without Scan lets the driver
		// consume the result terminator while avoiding per-row destination and
		// conversion allocations for data that will be discarded.
		if result.Truncated {
			continue
		}
		if len(result.Rows) == limit {
			result.Truncated = true
			continue
		}
		if err := rows.Scan(destinations...); err != nil {
			return classifyExecutionError(ctx, err)
		}
		separatorBytes := 0
		if len(result.Rows) != 0 {
			separatorBytes = 1
		}
		remainingBytes := maxResultBytes - result.ResultBytes
		if separatorBytes > remainingBytes {
			result.Truncated = true
			continue
		}
		rowBytes, fits := encodedRowSize(rawValues, columns, remainingBytes-separatorBytes)
		if !fits {
			result.Truncated = true
			continue
		}
		row := make([]*string, len(columns))
		for index, raw := range rawValues {
			if raw != nil {
				value := string(raw)
				if columns[index].Encoding == "base64" {
					value = base64.StdEncoding.EncodeToString(raw)
				}
				row[index] = &value
			}
		}
		result.ResultBytes += separatorBytes + rowBytes
		result.Rows = append(result.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return classifyExecutionError(ctx, err)
	}
	return nil
}

func invalidAuthorizationError(operation string) *database.Error {
	return &database.Error{
		Kind: database.ErrorUpstream,
		Err:  fmt.Errorf("invalid %s authorization", operation),
	}
}

func encodedSchemaObjectSize(object database.SchemaObject, maxBytes int) (int, bool) {
	return encodedMetadataObjectSize(
		len(`{"name":}`), maxBytes,
		object.Name,
	)
}

func encodedObjectDescriptionBaseSize(schema, name string, maxBytes int) (int, bool) {
	return encodedMetadataObjectSize(
		len(`{"schema":,"name":,"columns":[]}`), maxBytes,
		schema, name,
	)
}

func encodedColumnDescriptionSize(column database.ColumnDescription, maxBytes int) (int, bool) {
	size, ok := encodedMetadataObjectSize(
		len(`{"name":,"type":,"native_type":,"nullable":,"primary_key":,"indexed":}`),
		maxBytes,
		column.Name, column.Type, column.NativeType,
	)
	if !ok {
		return 0, false
	}
	for _, value := range []bool{column.Nullable, column.PrimaryKey, column.Indexed} {
		booleanBytes := len("false")
		if value {
			booleanBytes = len("true")
		}
		size, ok = addEncodedSize(size, booleanBytes, maxBytes)
		if !ok {
			return 0, false
		}
	}
	return size, true
}

func encodedMetadataObjectSize(baseSize, maxBytes int, values ...string) (int, bool) {
	size, ok := addEncodedSize(0, baseSize, maxBytes)
	if !ok {
		return 0, false
	}
	for _, value := range values {
		valueBytes, ok := encodedMetadataJSONStringSize(value, maxBytes-size)
		if !ok {
			return 0, false
		}
		size, ok = addEncodedSize(size, valueBytes, maxBytes)
		if !ok {
			return 0, false
		}
	}
	return size, true
}

// encodedMetadataJSONStringSize mirrors encoding/json's default string
// escaping while reading the already-materialized database string in place.
func encodedMetadataJSONStringSize(value string, maxBytes int) (int, bool) {
	size := 2 // JSON string quotes.
	if size > maxBytes {
		return 0, false
	}
	for index := 0; index < len(value); {
		width := 1
		encodedBytes := 1
		character := value[index]
		if character < utf8.RuneSelf {
			switch character {
			case '\\', '"', '\b', '\f', '\n', '\r', '\t':
				encodedBytes = 2
			case '<', '>', '&':
				encodedBytes = 6
			default:
				if character < 0x20 {
					encodedBytes = 6
				}
			}
		} else {
			runeValue, runeWidth := utf8.DecodeRuneInString(value[index:])
			width = runeWidth
			switch {
			case runeValue == utf8.RuneError && runeWidth == 1:
				encodedBytes = 6
			case runeValue == '\u2028' || runeValue == '\u2029':
				encodedBytes = 6
			default:
				encodedBytes = runeWidth
			}
		}
		var ok bool
		size, ok = addEncodedSize(size, encodedBytes, maxBytes)
		if !ok {
			return 0, false
		}
		index += width
	}
	return size, true
}

func encodedRowSize(rawValues []sql.RawBytes, columns []database.ResultColumn, maxBytes int) (int, bool) {
	if len(rawValues) != len(columns) || maxBytes < 2 {
		return 0, false
	}
	size := 2 // JSON array brackets.
	for index, raw := range rawValues {
		if index != 0 {
			var ok bool
			size, ok = addEncodedSize(size, 1, maxBytes)
			if !ok {
				return 0, false
			}
		}
		valueBytes := 4 // null
		if raw != nil {
			if columns[index].Encoding == "base64" {
				valueBytes = 2 + base64.StdEncoding.EncodedLen(len(raw))
			} else {
				var ok bool
				valueBytes, ok = encodedJSONStringSize(raw, maxBytes-size)
				if !ok {
					return 0, false
				}
			}
		}
		var ok bool
		size, ok = addEncodedSize(size, valueBytes, maxBytes)
		if !ok {
			return 0, false
		}
	}
	return size, true
}

func encodedJSONStringSize(value []byte, maxBytes int) (int, bool) {
	size := 2 // JSON string quotes.
	if size > maxBytes {
		return 0, false
	}
	for index := 0; index < len(value); {
		width := 1
		encodedBytes := 1
		character := value[index]
		if character < utf8.RuneSelf {
			switch character {
			case '\\', '"', '\b', '\f', '\n', '\r', '\t':
				encodedBytes = 2
			case '<', '>', '&':
				encodedBytes = 6 // encoding/json uses EscapeHTML by default.
			default:
				if character < 0x20 {
					encodedBytes = 6
				}
			}
		} else {
			runeValue, runeWidth := utf8.DecodeRune(value[index:])
			width = runeWidth
			switch {
			case runeValue == utf8.RuneError && runeWidth == 1:
				encodedBytes = 6 // encoding/json replaces invalid UTF-8 with \ufffd.
			case runeValue == '\u2028' || runeValue == '\u2029':
				encodedBytes = 6
			default:
				encodedBytes = runeWidth
			}
		}
		var ok bool
		size, ok = addEncodedSize(size, encodedBytes, maxBytes)
		if !ok {
			return 0, false
		}
		index += width
	}
	return size, true
}

func addEncodedSize(current, increment, maxBytes int) (int, bool) {
	if current < 0 || increment < 0 || current > maxBytes || increment > maxBytes-current {
		return 0, false
	}
	return current + increment, true
}

func portableColumnType(databaseType string) string {
	normalized := strings.TrimSpace(strings.ToUpper(databaseType))
	normalized = strings.TrimPrefix(normalized, "UNSIGNED ")
	switch normalized {
	case "TINYINT", "SMALLINT", "MEDIUMINT", "INT", "INTEGER", "BIGINT", "YEAR":
		return "integer"
	case "DECIMAL", "NUMERIC", "FLOAT", "DOUBLE", "REAL":
		return "decimal"
	case "DATE":
		return "date"
	case "DATETIME", "TIMESTAMP":
		return "datetime"
	case "TIME":
		return "time"
	case "BINARY", "VARBINARY", "TINYBLOB", "BLOB", "MEDIUMBLOB", "LONGBLOB", "BIT",
		"GEOMETRY", "POINT", "LINESTRING", "POLYGON", "MULTIPOINT", "MULTILINESTRING",
		"MULTIPOLYGON", "GEOMETRYCOLLECTION", "GEOMCOLLECTION":
		return "bytes"
	case "JSON":
		return "json"
	default:
		return "string"
	}
}

func resultEncoding(databaseType string) string {
	if portableColumnType(databaseType) == "bytes" {
		return "base64"
	}
	return "string"
}

type rowSet interface {
	Next() bool
	Err() error
	Close() error
}

func drainAndCloseRows(rows rowSet) error {
	for rows.Next() {
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	return rows.Close()
}

func classifyExecutionError(ctx context.Context, err error) *database.Error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return &database.Error{Kind: database.ErrorTimeout, Err: err}
	}
	if errors.Is(err, mysql.ErrReadPktTooLarge) {
		return &database.Error{Kind: database.ErrorResultTooLarge, Err: err}
	}
	var mysqlError *mysql.MySQLError
	if errors.As(err, &mysqlError) {
		if mysqlError.Number == 3024 { // ER_QUERY_TIMEOUT from MAX_EXECUTION_TIME.
			return &database.Error{Kind: database.ErrorTimeout, Err: err}
		}
		switch mysqlError.Number {
		case 1040, // ER_CON_COUNT_ERROR
			1044, 1045, // Database/user access denied; datasource credentials are unavailable.
			1053,                   // ER_SERVER_SHUTDOWN
			1158, 1159, 1160, 1161, // Network read/write errors.
			1227,       // Required datasource privilege is unavailable.
			1345,       // EXPLAIN lacks SHOW VIEW or underlying-object privileges.
			2002, 2003, // Connection failures.
			2006, 2013: // Server gone or connection lost.
			return &database.Error{Kind: database.ErrorUnavailable, Err: err}
		}
	}
	var networkError net.Error
	if errors.As(err, &networkError) || errors.Is(err, driver.ErrBadConn) ||
		errors.Is(err, mysql.ErrInvalidConn) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return &database.Error{Kind: database.ErrorUnavailable, Err: err}
	}
	return &database.Error{Kind: database.ErrorUpstream, Err: err}
}

func boundedPacketSize(maxResultBytes int) int {
	maxInt := int(^uint(0) >> 1)
	if maxResultBytes > maxInt-resultPacketOverhead {
		return maxInt
	}
	return maxResultBytes + resultPacketOverhead
}

func absoluteResultPacketSize() int {
	return boundedPacketSize(domain.MaxSupportedResultBytes)
}

func compile(spec queryspec.NormalizedSpec, deadlineMS int) (string, []any, error) {
	projection := make([]string, 0, len(spec.Projection))
	for _, selection := range spec.Projection {
		var expression string
		if selection.Kind == "field" {
			expression = representedField(quote(selection.Field), selection.Representation, false)
		} else {
			argument := "*"
			if selection.Field != "" {
				argument = quote(selection.Field)
			}
			expression = strings.ToUpper(selection.Function) + "(" + argument + ")"
		}
		if selection.Alias != "" {
			expression += " AS " + quote(selection.Alias)
		} else if selection.Representation == queryspec.RepresentationSourceText {
			expression += " AS " + quote(selection.Field)
		}
		projection = append(projection, expression)
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "EXPLAIN FORMAT=JSON SELECT /*+ MAX_EXECUTION_TIME(%d) */ ", deadlineMS)
	builder.WriteString(strings.Join(projection, ", "))
	builder.WriteString(" FROM ")
	builder.WriteString(quote(spec.Source.Schema))
	builder.WriteByte('.')
	builder.WriteString(quote(spec.Source.Name))
	args := make([]any, 0)
	if spec.Filter != nil {
		where, filterArgs, err := compileFilter(*spec.Filter)
		if err != nil {
			return "", nil, err
		}
		builder.WriteString(" WHERE ")
		builder.WriteString(where)
		args = append(args, filterArgs...)
	}
	if len(spec.GroupBy) > 0 {
		fields := make([]string, len(spec.GroupBy))
		for index, field := range spec.GroupBy {
			fields[index] = qualifySourceField(spec.Source, field)
		}
		builder.WriteString(" GROUP BY ")
		builder.WriteString(strings.Join(fields, ", "))
	}
	if len(spec.OrderBy) > 0 {
		fields := make([]string, len(spec.OrderBy))
		for index, sort := range spec.OrderBy {
			fields[index] = representedField(qualifySourceField(spec.Source, sort.Field), sort.Representation, true) + " " + strings.ToUpper(sort.Direction)
		}
		builder.WriteString(" ORDER BY ")
		builder.WriteString(strings.Join(fields, ", "))
	}
	builder.WriteString(" LIMIT ? OFFSET ?")
	args = append(args, spec.Limit, spec.Offset)
	return builder.String(), args, nil
}

func compileSelect(spec queryspec.NormalizedSpec, deadlineMS, rowLimit int) (string, []any, error) {
	projection := make([]string, 0, len(spec.Projection))
	for _, selection := range spec.Projection {
		expression := representedField(qualifySourceField(spec.Source, selection.Field), selection.Representation, false)
		if selection.Alias != "" {
			expression += " AS " + quote(selection.Alias)
		} else if selection.Representation == queryspec.RepresentationSourceText {
			expression += " AS " + quote(selection.Field)
		}
		projection = append(projection, expression)
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "SELECT /*+ MAX_EXECUTION_TIME(%d) */ ", deadlineMS)
	builder.WriteString(strings.Join(projection, ", "))
	builder.WriteString(" FROM ")
	builder.WriteString(quote(spec.Source.Schema))
	builder.WriteByte('.')
	builder.WriteString(quote(spec.Source.Name))
	args := make([]any, 0)
	if spec.Filter != nil {
		where, filterArgs, err := compileFilter(*spec.Filter)
		if err != nil {
			return "", nil, err
		}
		builder.WriteString(" WHERE ")
		builder.WriteString(where)
		args = append(args, filterArgs...)
	}
	if len(spec.OrderBy) > 0 {
		fields := make([]string, len(spec.OrderBy))
		for index, sort := range spec.OrderBy {
			fields[index] = representedField(qualifySourceField(spec.Source, sort.Field), sort.Representation, true) + " " + strings.ToUpper(sort.Direction)
		}
		builder.WriteString(" ORDER BY ")
		builder.WriteString(strings.Join(fields, ", "))
	}
	builder.WriteString(" LIMIT ? OFFSET ?")
	args = append(args, rowLimit, spec.Offset)
	return builder.String(), args, nil
}

func compileFilter(filter queryspec.Filter) (string, []any, error) {
	if filter.Representation == queryspec.RepresentationSourceText {
		return compileSourceTextFilter(filter, quote(filter.Field))
	}
	if filter.Kind == "group" {
		parts := make([]string, len(filter.Expressions))
		var args []any
		for index, expression := range filter.Expressions {
			part, childArgs, err := compileFilter(expression)
			if err != nil {
				return "", nil, err
			}
			parts[index] = part
			args = append(args, childArgs...)
		}
		return "(" + strings.Join(parts, " "+strings.ToUpper(filter.Operator)+" ") + ")", args, nil
	}
	operators := map[string]string{
		"eq": "=", "ne": "<>", "lt": "<", "lte": "<=", "gt": ">", "gte": ">=", "like": "LIKE",
		"in": "IN", "not_in": "NOT IN", "is_null": "IS NULL", "is_not_null": "IS NOT NULL",
	}
	operator, ok := operators[filter.Operator]
	if !ok {
		return "", nil, errors.New("unsupported filter operator")
	}
	if filter.Operator == "is_null" || filter.Operator == "is_not_null" {
		return quote(filter.Field) + " " + operator, nil, nil
	}
	args := make([]any, len(filter.Values))
	placeholders := make([]string, len(filter.Values))
	for index, value := range filter.Values {
		bound, err := value.BindValue()
		if err != nil {
			return "", nil, err
		}
		args[index] = bound
		placeholders[index] = "?"
	}
	if filter.Operator == "in" || filter.Operator == "not_in" {
		return quote(filter.Field) + " " + operator + " (" + strings.Join(placeholders, ", ") + ")", args, nil
	}
	return quote(filter.Field) + " " + operator + " ?", args, nil
}

func quote(identifier string) string { return "`" + strings.ReplaceAll(identifier, "`", "``") + "`" }

func qualifySourceField(source queryspec.ResourceRef, field string) string {
	return quote(source.Schema) + "." + quote(source.Name) + "." + quote(field)
}

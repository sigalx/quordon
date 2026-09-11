package mysql8

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryspec"
)

const (
	aggregateSourceAlias             = "__quordon_source"
	aggregateTimeBucketValidityAlias = "__quordon$time_bucket_invalid"
)

type aggregateSourceColumn struct {
	name       string
	dataType   string
	nativeType string
	nullable   bool
}

func (*Adapter) Aggregate(
	ctx context.Context,
	db *sql.DB,
	query policy.AuthorizedAggregate,
	envelopeBaseBytes int,
) (result database.AggregateResult, resultErr error) {
	if query.Operation() != domain.OperationAggregate {
		return database.AggregateResult{}, invalidAuthorizationError("aggregate")
	}
	spec := query.Query()
	conn, err := db.Conn(ctx)
	if err != nil {
		return database.AggregateResult{}, classifyExecutionError(ctx, err)
	}
	defer conn.Close()
	clearDeadline, err := bindConnectionDeadline(ctx, conn, query.Limits().DeadlineMS)
	if err != nil {
		return database.AggregateResult{}, classifyExecutionError(ctx, err)
	}
	defer func() {
		if clearDeadline != nil {
			_ = clearDeadline()
		}
	}()
	info, err := readServerInfo(ctx, conn)
	if err != nil {
		return database.AggregateResult{}, err
	}
	ctx = mysql.WithMaxReadPacketSize(ctx, absoluteResultPacketSize())
	releaseDDLGuard, err := acquireInstanceDDLGuard(ctx, conn)
	if err != nil {
		return database.AggregateResult{}, err
	}
	defer func() {
		if releaseDDLGuard != nil {
			_ = releaseDDLGuard()
		}
	}()
	columnsByName, err := validateAggregateSource(
		ctx, conn, spec, query.RequiredIndex(), info.lowerCaseTableNames,
	)
	if err != nil {
		return database.AggregateResult{}, err
	}
	resultColumns, err := aggregateResultColumns(spec, columnsByName)
	if err != nil {
		return database.AggregateResult{}, err
	}
	statement, args, err := compileAggregate(spec, query.RequiredIndex(), query.Limits().DeadlineMS)
	if err != nil {
		return database.AggregateResult{}, &database.Error{Kind: database.ErrorUpstream, Err: err}
	}
	resultBytes, err := addAggregateColumnsSize(
		envelopeBaseBytes, resultColumns, query.Limits().MaxResultBytes,
	)
	if err != nil {
		return database.AggregateResult{}, err
	}
	originalTimezone := ""
	sessionMutated := false
	if queryspec.AggregateUsesTimeBucket(spec) {
		originalTimezone, err = setAggregateUTCSession(ctx, conn)
		if err != nil {
			return database.AggregateResult{}, err
		}
		sessionMutated = true
	}
	defer func() {
		if !sessionMutated {
			return
		}
		if resultErr != nil {
			discardSQLConnection(conn)
			return
		}
		if restoreErr := restoreAggregateSessionTimezone(ctx, conn, originalTimezone); restoreErr != nil {
			result = database.AggregateResult{}
			resultErr = restoreErr
		}
	}()
	if err := startAggregateTransaction(ctx, conn); err != nil {
		return database.AggregateResult{}, err
	}
	transactionActive := true
	defer func() {
		if transactionActive {
			_ = finalizeAggregateTransaction(ctx, conn, "ROLLBACK")
		}
	}()
	plan, err := readAggregatePlan(ctx, conn, "EXPLAIN FORMAT=JSON "+statement, args)
	if err != nil {
		return database.AggregateResult{}, err
	}
	if err := validateAggregatePlan(
		plan, query.RequiredIndex(), query.MaximumRowsExaminedPerScan(),
		query.AllowTemporaryTable(), query.AllowFilesort(),
	); err != nil {
		return database.AggregateResult{}, err
	}
	rows, err := conn.QueryContext(ctx, statement, args...)
	if err != nil {
		return database.AggregateResult{}, classifyQueryError(ctx, err)
	}
	defer func() { _ = drainAndCloseRows(rows) }()
	result = database.AggregateResult{
		Mode: spec.Mode, Columns: resultColumns, Rows: make([][]*string, 0), ResultBytes: resultBytes,
	}
	if err := collectAggregateRowsWithSpec(
		ctx, rows, spec, resultColumns, query.Limits().MaxResultBytes, &result,
	); err != nil {
		return database.AggregateResult{}, err
	}
	if err := rows.Close(); err != nil {
		return database.AggregateResult{}, classifyExecutionError(ctx, err)
	}
	baseTable, err := isBaseTable(ctx, conn, spec.Source, info.lowerCaseTableNames)
	if err != nil {
		return database.AggregateResult{}, err
	}
	if !baseTable {
		return database.AggregateResult{}, invalidSourceError()
	}
	if err := finalizeAggregateTransaction(ctx, conn, "COMMIT"); err != nil {
		return database.AggregateResult{}, err
	}
	transactionActive = false
	if sessionMutated {
		if err := restoreAggregateSessionTimezone(ctx, conn, originalTimezone); err != nil {
			return database.AggregateResult{}, err
		}
		sessionMutated = false
	}
	if err := releaseDDLGuard(); err != nil {
		return database.AggregateResult{}, err
	}
	releaseDDLGuard = nil
	if err := clearDeadline(); err != nil {
		return database.AggregateResult{}, classifyExecutionError(ctx, err)
	}
	clearDeadline = nil
	result.RowCount = len(result.Rows)
	return result, nil
}

func validateAggregateSource(
	ctx context.Context,
	conn *sql.Conn,
	spec queryspec.NormalizedAggregateSpec,
	requiredIndex string,
	lowerCaseTableNames int,
) (map[string]aggregateSourceColumn, error) {
	caseInsensitiveObjects := lowerCaseTableNames != 0
	schemaComparison := metadataIdentifierComparison("t.table_schema", "?", caseInsensitiveObjects)
	objectComparison := metadataIdentifierComparison("t.table_name", "?", caseInsensitiveObjects)
	indexSchemaComparison := metadataIdentifierComparison("s.table_schema", "t.table_schema", caseInsensitiveObjects)
	indexObjectComparison := metadataIdentifierComparison("s.table_name", "t.table_name", caseInsensitiveObjects)
	indexNameComparison := metadataIdentifierComparison("s.index_name", "?", true)
	statement := `SELECT t.table_schema, t.table_name, t.engine, EXISTS (
	    SELECT 1 FROM information_schema.statistics s
	    WHERE ` + indexSchemaComparison + `
	      AND ` + indexObjectComparison + `
	      AND ` + indexNameComparison + `
	      AND s.is_visible = 'YES'
	)
FROM information_schema.tables t
WHERE ` + schemaComparison + `
  AND ` + objectComparison + `
  AND t.table_type = 'BASE TABLE'
LIMIT 1`
	var actualSchema, actualObject, engine string
	var hasIndex bool
	if err := conn.QueryRowContext(
		ctx, statement, requiredIndex, spec.Source.Schema, spec.Source.Name,
	).Scan(&actualSchema, &actualObject, &engine, &hasIndex); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, invalidSourceError()
		}
		return nil, classifyQueryError(ctx, err)
	}
	if !tokenIdentifierMatches(actualSchema, spec.Source.Schema, caseInsensitiveObjects) ||
		!tokenIdentifierMatches(actualObject, spec.Source.Name, caseInsensitiveObjects) {
		return nil, metadataResourceMismatchError()
	}
	if !strings.EqualFold(engine, "InnoDB") || !hasIndex {
		return nil, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("aggregate source or required index is unsupported")}
	}
	referenced := queryspec.AggregateReferencedFields(spec)
	if len(referenced) == 0 {
		return map[string]aggregateSourceColumn{}, nil
	}
	comparisons := make([]string, len(referenced))
	args := make([]any, 0, 2+len(referenced))
	args = append(args, actualSchema, actualObject)
	for index, field := range referenced {
		comparisons[index] = metadataIdentifierComparison("c.column_name", "?", true)
		args = append(args, field)
	}
	columnStatement := `SELECT c.table_schema, c.table_name, c.column_name, c.data_type, c.column_type, c.is_nullable
FROM information_schema.columns c
WHERE ` + metadataIdentifierComparison("c.table_schema", "?", caseInsensitiveObjects) + `
  AND ` + metadataIdentifierComparison("c.table_name", "?", caseInsensitiveObjects) + `
  AND (` + strings.Join(comparisons, " OR ") + `)
ORDER BY c.ordinal_position`
	rows, err := conn.QueryContext(ctx, columnStatement, args...)
	if err != nil {
		return nil, classifyQueryError(ctx, err)
	}
	defer func() { _ = drainAndCloseRows(rows) }()
	result := make(map[string]aggregateSourceColumn, len(referenced))
	requested := make(map[string]struct{}, len(referenced))
	for _, field := range referenced {
		requested[strings.ToLower(field)] = struct{}{}
	}
	for rows.Next() {
		var rowSchema, rowObject, nullable string
		var column aggregateSourceColumn
		if err := rows.Scan(
			&rowSchema, &rowObject, &column.name, &column.dataType, &column.nativeType, &nullable,
		); err != nil {
			return nil, classifyExecutionError(ctx, err)
		}
		if !tokenIdentifierMatches(rowSchema, spec.Source.Schema, caseInsensitiveObjects) ||
			!tokenIdentifierMatches(rowObject, spec.Source.Name, caseInsensitiveObjects) {
			return nil, metadataResourceMismatchError()
		}
		key := strings.ToLower(column.name)
		if _, ok := requested[key]; !ok {
			return nil, metadataResourceMismatchError()
		}
		if _, duplicate := result[key]; duplicate {
			return nil, metadataResourceMismatchError()
		}
		column.nullable = nullable == "YES"
		result[key] = column
	}
	if err := rows.Err(); err != nil {
		return nil, classifyExecutionError(ctx, err)
	}
	if len(result) != len(referenced) {
		return nil, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("aggregate references an unknown field")}
	}
	return result, nil
}

func aggregateResultColumns(
	spec queryspec.NormalizedAggregateSpec,
	source map[string]aggregateSourceColumn,
) ([]database.ResultColumn, error) {
	result := make([]database.ResultColumn, len(spec.Projection))
	for index, output := range spec.Projection {
		if output.Kind == "dimension" || output.Kind == "time_bucket" {
			column, ok := source[strings.ToLower(output.Field)]
			if !ok {
				return nil, &database.Error{Kind: database.ErrorInvalid}
			}
			if output.Kind == "time_bucket" {
				if dataType := strings.ToUpper(strings.TrimSpace(column.dataType)); dataType != "TIMESTAMP" && dataType != "DATETIME" {
					return nil, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("time bucket requires a temporal field")}
				}
				result[index] = database.ResultColumn{
					Name: output.Alias, Type: "datetime", Encoding: "string", Nullable: column.nullable,
				}
				continue
			}
			result[index] = database.ResultColumn{
				Name: output.Field, Type: portableColumnType(column.dataType),
				Encoding: resultEncoding(column.dataType), Nullable: column.nullable,
			}
			continue
		}
		column := aggregateSourceColumn{}
		if output.Field != "" {
			var ok bool
			column, ok = source[strings.ToLower(output.Field)]
			if !ok {
				return nil, &database.Error{Kind: database.ErrorInvalid}
			}
		}
		switch output.Function {
		case "count_all", "count", "count_distinct":
			result[index] = database.ResultColumn{Name: output.Alias, Type: "integer", Encoding: "string", Nullable: false}
		case "sum", "avg":
			if !aggregateNumericType(column.dataType) {
				return nil, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("aggregate requires a numeric field")}
			}
			result[index] = database.ResultColumn{
				Name: output.Alias, Type: "decimal", Encoding: "string",
				Nullable: spec.Mode == queryspec.AggregateModeScalar || column.nullable,
			}
		case "min", "max":
			portableType := portableColumnType(column.dataType)
			if portableType == "bytes" || portableType == "json" {
				return nil, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("aggregate requires an ordered scalar field")}
			}
			result[index] = database.ResultColumn{
				Name: output.Alias, Type: portableType, Encoding: resultEncoding(column.dataType),
				Nullable: spec.Mode == queryspec.AggregateModeScalar || column.nullable,
			}
		default:
			return nil, &database.Error{Kind: database.ErrorInvalid}
		}
	}
	return result, nil
}

func aggregateNumericType(dataType string) bool {
	switch strings.ToUpper(strings.TrimSpace(dataType)) {
	case "TINYINT", "SMALLINT", "MEDIUMINT", "INT", "INTEGER", "BIGINT", "DECIMAL", "NUMERIC", "FLOAT", "DOUBLE", "REAL":
		return true
	default:
		return false
	}
}

func addAggregateColumnsSize(
	base int, columns []database.ResultColumn, maximum int,
) (int, error) {
	current := base
	for index, column := range columns {
		columnSize, ok := encodedAggregateResultColumnSize(column, maximum-current)
		if !ok {
			return 0, &database.Error{Kind: database.ErrorResultTooLarge}
		}
		if index != 0 {
			columnSize++
		}
		current, ok = addEncodedSize(current, columnSize, maximum)
		if !ok {
			return 0, &database.Error{Kind: database.ErrorResultTooLarge}
		}
	}
	return current, nil
}

func encodedAggregateResultColumnSize(column database.ResultColumn, maximum int) (int, bool) {
	size, ok := encodedMetadataObjectSize(
		len(`{"name":,"type":,"encoding":,"nullable":}`), maximum,
		column.Name, column.Type, column.Encoding,
	)
	if !ok {
		return 0, false
	}
	booleanBytes := len("false")
	if column.Nullable {
		booleanBytes = len("true")
	}
	return addEncodedSize(size, booleanBytes, maximum)
}

func setAggregateUTCSession(ctx context.Context, conn *sql.Conn) (string, error) {
	var original string
	if err := conn.QueryRowContext(ctx, "SELECT @@session.time_zone").Scan(&original); err != nil {
		return "", classifyExecutionError(ctx, err)
	}
	if original == "" || len(original) > 64 || !utf8.ValidString(original) || strings.ContainsAny(original, "\x00\r\n") {
		discardSQLConnection(conn)
		return "", &database.Error{Kind: database.ErrorUpstream, Err: errors.New("invalid MySQL session timezone")}
	}
	if _, err := conn.ExecContext(ctx, "SET SESSION time_zone = ?", "+00:00"); err != nil {
		discardSQLConnection(conn)
		return "", classifyExecutionError(ctx, err)
	}
	var verified string
	if err := conn.QueryRowContext(ctx, "SELECT @@session.time_zone").Scan(&verified); err != nil {
		discardSQLConnection(conn)
		return "", classifyExecutionError(ctx, err)
	}
	if verified != "+00:00" {
		discardSQLConnection(conn)
		return "", &database.Error{Kind: database.ErrorUpstream, Err: errors.New("MySQL UTC session verification failed")}
	}
	return original, nil
}

func restoreAggregateSessionTimezone(ctx context.Context, conn *sql.Conn, original string) error {
	cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), ddlGuardCleanupTimeout)
	defer cancel()
	if err := setConnectionDeadline(conn, time.Now().Add(ddlGuardCleanupTimeout)); err != nil {
		discardSQLConnection(conn)
		return classifyExecutionError(cleanupContext, err)
	}
	if _, err := conn.ExecContext(cleanupContext, "SET SESSION time_zone = ?", original); err != nil {
		discardSQLConnection(conn)
		return classifyExecutionError(cleanupContext, err)
	}
	var verified string
	if err := conn.QueryRowContext(cleanupContext, "SELECT @@session.time_zone").Scan(&verified); err != nil {
		discardSQLConnection(conn)
		return classifyExecutionError(cleanupContext, err)
	}
	if verified != original {
		discardSQLConnection(conn)
		return &database.Error{Kind: database.ErrorUpstream, Err: errors.New("MySQL session timezone restoration failed")}
	}
	return nil
}

func startAggregateTransaction(ctx context.Context, conn *sql.Conn) error {
	if _, err := conn.ExecContext(ctx, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"); err != nil {
		return classifyExecutionError(ctx, err)
	}
	if _, err := conn.ExecContext(ctx, "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY"); err != nil {
		discardSQLConnection(conn)
		return classifyExecutionError(ctx, err)
	}
	return nil
}

func finalizeAggregateTransaction(ctx context.Context, conn *sql.Conn, statement string) error {
	cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), ddlGuardCleanupTimeout)
	defer cancel()
	if err := setConnectionDeadline(conn, time.Now().Add(ddlGuardCleanupTimeout)); err != nil {
		discardSQLConnection(conn)
		return classifyExecutionError(cleanupContext, err)
	}
	if _, err := conn.ExecContext(cleanupContext, statement); err != nil {
		discardSQLConnection(conn)
		return classifyExecutionError(cleanupContext, err)
	}
	return nil
}

func readAggregatePlan(ctx context.Context, conn *sql.Conn, statement string, args []any) (json.RawMessage, error) {
	rows, err := conn.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, classifyQueryError(ctx, err)
	}
	defer func() { _ = drainAndCloseRows(rows) }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, classifyExecutionError(ctx, err)
		}
		return nil, &database.Error{Kind: database.ErrorUpstream, Err: errors.New("MySQL returned no aggregate plan")}
	}
	var raw sql.RawBytes
	if err := rows.Scan(&raw); err != nil {
		return nil, classifyExecutionError(ctx, err)
	}
	if len(raw) > domain.MaxSupportedResultBytes {
		return nil, &database.Error{Kind: database.ErrorResultTooLarge}
	}
	if !json.Valid(raw) {
		return nil, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("aggregate plan is malformed")}
	}
	plan := append(json.RawMessage(nil), raw...)
	if rows.Next() {
		return nil, &database.Error{Kind: database.ErrorUpstream, Err: errors.New("MySQL returned multiple aggregate plans")}
	}
	if err := rows.Err(); err != nil {
		return nil, classifyExecutionError(ctx, err)
	}
	return plan, nil
}

func validateAggregatePlan(
	plan json.RawMessage,
	requiredIndex string,
	maximumRows uint64,
	workControls ...bool,
) error {
	allowTemporaryTable := len(workControls) > 0 && workControls[0]
	allowFilesort := len(workControls) > 1 && workControls[1]
	if len(workControls) > 2 {
		return &database.Error{Kind: database.ErrorInvalid, Err: errors.New("invalid aggregate plan controls")}
	}
	decoder := json.NewDecoder(bytes.NewReader(plan))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return &database.Error{Kind: database.ErrorInvalid, Err: errors.New("aggregate plan is malformed")}
	}
	tables := make([]map[string]any, 0, 1)
	invalidNode := false
	var visit func(any)
	visit = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				if key == "materialized_from_subquery" {
					invalidNode = true
				}
				if key == "using_temporary_table" {
					if enabled, ok := child.(bool); !ok || enabled && !allowTemporaryTable {
						invalidNode = true
					}
				}
				if key == "using_filesort" {
					if enabled, ok := child.(bool); !ok || enabled && !allowFilesort {
						invalidNode = true
					}
				}
				if key == "table" {
					if table, ok := child.(map[string]any); ok {
						tables = append(tables, table)
					} else {
						invalidNode = true
					}
				}
				visit(child)
			}
		case []any:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(document)
	if invalidNode {
		return &database.Error{Kind: database.ErrorInvalid, Err: errors.New("aggregate plan violates the authorized shape")}
	}
	if len(tables) == 0 && isSafelyEmptyAggregatePlan(document) {
		return nil
	}
	if len(tables) != 1 {
		return &database.Error{Kind: database.ErrorInvalid, Err: errors.New("aggregate plan violates the authorized shape")}
	}
	table := tables[0]
	name, nameOK := table["table_name"].(string)
	key, keyOK := table["key"].(string)
	accessType, accessOK := table["access_type"].(string)
	rowsNumber, rowsOK := table["rows_examined_per_scan"].(json.Number)
	if !nameOK || name != aggregateSourceAlias || !keyOK ||
		!strings.EqualFold(key, requiredIndex) || !accessOK || strings.EqualFold(accessType, "ALL") || !rowsOK {
		return &database.Error{Kind: database.ErrorInvalid, Err: errors.New("aggregate plan does not use the required index")}
	}
	rowsText := rowsNumber.String()
	if rowsText == "" || strings.HasPrefix(rowsText, "-") || strings.ContainsAny(rowsText, ".eE+") ||
		(len(rowsText) > 1 && rowsText[0] == '0') {
		return &database.Error{Kind: database.ErrorInvalid, Err: errors.New("aggregate plan row estimate is invalid")}
	}
	rowsExamined, err := strconv.ParseUint(rowsText, 10, 64)
	if err != nil || rowsExamined > maximumRows {
		return &database.Error{Kind: database.ErrorInvalid, Err: errors.New("aggregate plan exceeds the authorized estimate")}
	}
	return nil
}

func isSafelyEmptyAggregatePlan(document any) bool {
	root, ok := document.(map[string]any)
	if !ok || len(root) != 1 {
		return false
	}
	queryBlock, ok := root["query_block"].(map[string]any)
	if !ok || len(queryBlock) != 2 {
		return false
	}
	selectID, ok := queryBlock["select_id"].(json.Number)
	if !ok || selectID.String() != "1" {
		return false
	}
	message, ok := queryBlock["message"].(string)
	if !ok {
		return false
	}
	return message == "Impossible WHERE" || message == "no matching row in const table"
}

func collectAggregateRows(
	ctx context.Context,
	rows selectRowSet,
	mode string,
	limit int,
	columns []database.ResultColumn,
	maxResultBytes int,
	result *database.AggregateResult,
) error {
	return collectAggregateRowsWithSpec(
		ctx, rows, queryspec.NormalizedAggregateSpec{Mode: mode, Limit: limit},
		columns, maxResultBytes, result,
	)
}

func collectAggregateRowsWithSpec(
	ctx context.Context,
	rows selectRowSet,
	spec queryspec.NormalizedAggregateSpec,
	columns []database.ResultColumn,
	maxResultBytes int,
	result *database.AggregateResult,
) error {
	bucketUnits := make([]string, len(columns))
	hasTimeBucket := false
	for index, output := range spec.Projection {
		if output.Kind == "time_bucket" {
			bucketUnits[index] = output.Unit
			hasTimeBucket = true
		}
	}
	hiddenColumns := 0
	if hasTimeBucket {
		hiddenColumns = 1
	}
	rawValues := make([]sql.RawBytes, len(columns)+hiddenColumns)
	destinations := make([]any, len(rawValues))
	for index := range rawValues {
		destinations[index] = &rawValues[index]
	}
	provisionalTruncatedRow := false
	provisionalPreviousBytes := 0
	for rows.Next() {
		if provisionalTruncatedRow {
			if hasTimeBucket {
				if err := rows.Scan(destinations...); err != nil {
					return classifyExecutionError(ctx, err)
				}
				if err := validateTimeBucketRow(rawValues, bucketUnits); err != nil {
					return err
				}
			}
			// The current row proves that the provisionally included previous row is
			// a complete member of the largest truncated prefix.
			provisionalTruncatedRow = false
			continue
		}
		if result.Truncated {
			if hasTimeBucket {
				if err := rows.Scan(destinations...); err != nil {
					return classifyExecutionError(ctx, err)
				}
				if err := validateTimeBucketRow(rawValues, bucketUnits); err != nil {
					return err
				}
			}
			continue
		}
		if spec.Mode == queryspec.AggregateModeGrouped && len(result.Rows) == spec.Limit {
			if hasTimeBucket {
				if err := rows.Scan(destinations...); err != nil {
					return classifyExecutionError(ctx, err)
				}
				if err := validateTimeBucketRow(rawValues, bucketUnits); err != nil {
					return err
				}
			}
			result.Truncated = true
			if result.ResultBytes > 0 {
				result.ResultBytes-- // JSON true is one byte shorter than false.
			}
			continue
		}
		if err := rows.Scan(destinations...); err != nil {
			return classifyExecutionError(ctx, err)
		}
		if hasTimeBucket {
			if err := validateTimeBucketRow(rawValues, bucketUnits); err != nil {
				return err
			}
		}
		visibleValues := rawValues[:len(columns)]
		separatorBytes := 0
		if len(result.Rows) != 0 {
			separatorBytes = 1
		}
		rowCountGrowth := decimalDigits(len(result.Rows)+1) - decimalDigits(len(result.Rows))
		remaining := maxResultBytes - result.ResultBytes - separatorBytes - rowCountGrowth
		rowBytes, fits := encodedRowSize(visibleValues, columns, remaining)
		if !fits {
			if spec.Mode == queryspec.AggregateModeScalar {
				return &database.Error{Kind: database.ErrorResultTooLarge}
			}
			if rowBytesWithTruncation, fitsWithTruncation := encodedRowSize(visibleValues, columns, remaining+1); fitsWithTruncation {
				provisionalPreviousBytes = result.ResultBytes
				result.Truncated = true
				result.ResultBytes-- // JSON true is one byte shorter than false.
				result.ResultBytes += separatorBytes + rowCountGrowth + rowBytesWithTruncation
				result.Rows = append(result.Rows, materializeAggregateRow(visibleValues, columns))
				provisionalTruncatedRow = true
				continue
			}
			result.Truncated = true
			if result.ResultBytes > 0 {
				result.ResultBytes--
			}
			continue
		}
		row := materializeAggregateRow(visibleValues, columns)
		result.ResultBytes += separatorBytes + rowCountGrowth + rowBytes
		result.Rows = append(result.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return classifyExecutionError(ctx, err)
	}
	if provisionalTruncatedRow {
		// There was no later row to omit. The provisional row cannot be returned
		// with truncated=false, so omit it and retain the largest fitting prefix.
		result.Rows = result.Rows[:len(result.Rows)-1]
		result.ResultBytes = provisionalPreviousBytes - 1
	}
	if spec.Mode == queryspec.AggregateModeScalar {
		if len(result.Rows) != 1 {
			return &database.Error{Kind: database.ErrorUpstream, Err: errors.New("scalar aggregate did not return exactly one row")}
		}
		result.Truncated = false
	}
	return nil
}

func validateTimeBucketRow(rawValues []sql.RawBytes, bucketUnits []string) error {
	if len(rawValues) != len(bucketUnits)+1 {
		return &database.Error{Kind: database.ErrorUpstream, Err: errors.New("time-bucket row width invariant failed")}
	}
	if !bytes.Equal(rawValues[len(bucketUnits)], []byte("0")) {
		return &database.Error{Kind: database.ErrorUpstream, Err: errors.New("MySQL returned an invalid temporal source value")}
	}
	for index, unit := range bucketUnits {
		if unit == "" || rawValues[index] == nil {
			continue
		}
		if !validCanonicalTimeBucket(rawValues[index], unit) {
			return &database.Error{Kind: database.ErrorUpstream, Err: errors.New("MySQL returned a non-canonical time bucket")}
		}
	}
	return nil
}

func validCanonicalTimeBucket(raw []byte, unit string) bool {
	if len(raw) != len("2006-01-02T15:04:05Z") || raw[10] != 'T' || raw[19] != 'Z' {
		return false
	}
	parsed, err := time.Parse("2006-01-02T15:04:05Z", string(raw))
	if err != nil || parsed.Minute() != 0 || parsed.Second() != 0 || parsed.Nanosecond() != 0 {
		return false
	}
	switch unit {
	case "hour":
		return true
	case "day":
		return parsed.Hour() == 0
	case "week":
		return parsed.Hour() == 0 && parsed.Weekday() == time.Monday
	case "month":
		return parsed.Hour() == 0 && parsed.Day() == 1
	default:
		return false
	}
}

func materializeAggregateRow(rawValues []sql.RawBytes, columns []database.ResultColumn) []*string {
	row := make([]*string, len(columns))
	for index, raw := range rawValues {
		if raw == nil {
			continue
		}
		value := string(raw)
		if columns[index].Encoding == "base64" {
			value = base64.StdEncoding.EncodeToString(raw)
		}
		row[index] = &value
	}
	return row
}

func decimalDigits(value int) int {
	if value == 0 {
		return 1
	}
	digits := 0
	for value > 0 {
		digits++
		value /= 10
	}
	return digits
}

func compileAggregate(
	spec queryspec.NormalizedAggregateSpec, requiredIndex string, deadlineMS int,
) (string, []any, error) {
	projection := make([]string, len(spec.Projection))
	dimensions := make([]string, 0)
	bucketExpressions := make(map[string]string)
	bucketNullnessChecks := make([]string, 0)
	for index, output := range spec.Projection {
		if output.Kind == "dimension" || output.Kind == "time_bucket" {
			expression := qualifyAggregateField(output.Field)
			outputName := output.Field
			if output.Kind == "time_bucket" {
				var err error
				expression, err = compileTimeBucketExpression(output.Field, output.Unit, output.Timezone)
				if err != nil {
					return "", nil, err
				}
				outputName = output.Alias
				bucketExpressions[output.Alias] = expression
				source := qualifyAggregateField(output.Field)
				bucketNullnessChecks = append(
					bucketNullnessChecks,
					"NOT (("+source+" IS NULL) <=> ("+expression+" IS NULL))",
				)
			}
			projection[index] = expression + " AS " + quote(outputName)
			dimensions = append(dimensions, expression)
			continue
		}
		argument := "*"
		if output.Field != "" {
			argument = qualifyAggregateField(output.Field)
		}
		function := strings.ToUpper(output.Function)
		if output.Function == "count_all" {
			function = "COUNT"
		} else if output.Function == "count_distinct" {
			function = "COUNT"
			argument = "DISTINCT " + argument
		}
		projection[index] = function + "(" + argument + ") AS " + quote(output.Alias)
	}
	if len(bucketNullnessChecks) != 0 {
		projection = append(
			projection,
			"MAX(CASE WHEN "+strings.Join(bucketNullnessChecks, " OR ")+" THEN 1 ELSE 0 END) AS "+
				quote(aggregateTimeBucketValidityAlias),
		)
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "SELECT /*+ MAX_EXECUTION_TIME(%d) */ ", deadlineMS)
	builder.WriteString(strings.Join(projection, ", "))
	builder.WriteString(" FROM ")
	builder.WriteString(quote(spec.Source.Schema))
	builder.WriteByte('.')
	builder.WriteString(quote(spec.Source.Name))
	builder.WriteString(" AS ")
	builder.WriteString(quote(aggregateSourceAlias))
	builder.WriteString(" FORCE INDEX (")
	builder.WriteString(quote(requiredIndex))
	builder.WriteByte(')')
	args := make([]any, 0)
	if spec.Filter != nil {
		where, filterArgs, err := compileAggregateFilter(*spec.Filter)
		if err != nil {
			return "", nil, err
		}
		builder.WriteString(" WHERE ")
		builder.WriteString(where)
		args = append(args, filterArgs...)
	}
	if len(dimensions) != 0 {
		builder.WriteString(" GROUP BY ")
		builder.WriteString(strings.Join(dimensions, ", "))
	}
	if len(spec.OrderBy) != 0 {
		terms := make([]string, len(spec.OrderBy))
		for index, order := range spec.OrderBy {
			target := quote(order.Alias)
			if order.Kind == "dimension" {
				target = qualifyAggregateField(order.Field)
			} else if order.Kind == "time_bucket" {
				var ok bool
				target, ok = bucketExpressions[order.Alias]
				if !ok {
					return "", nil, errors.New("time-bucket order target is not projected")
				}
			}
			terms[index] = target + " " + strings.ToUpper(order.Direction)
		}
		builder.WriteString(" ORDER BY ")
		builder.WriteString(strings.Join(terms, ", "))
	}
	if spec.Mode == queryspec.AggregateModeGrouped {
		builder.WriteString(" LIMIT ?")
		args = append(args, spec.Limit+1)
	}
	return builder.String(), args, nil
}

func compileTimeBucketExpression(field, unit, timezone string) (string, error) {
	if timezone != "UTC" {
		return "", errors.New("unsupported time-bucket timezone")
	}
	source := qualifyAggregateField(field)
	switch unit {
	case "hour":
		return "DATE_FORMAT(" + source + ", '%Y-%m-%dT%H:00:00Z')", nil
	case "day":
		return "DATE_FORMAT(" + source + ", '%Y-%m-%dT00:00:00Z')", nil
	case "week":
		return "DATE_FORMAT(DATE_SUB(DATE(" + source + "), INTERVAL WEEKDAY(" + source + ") DAY), '%Y-%m-%dT00:00:00Z')", nil
	case "month":
		return "DATE_FORMAT(" + source + ", '%Y-%m-01T00:00:00Z')", nil
	default:
		return "", errors.New("unsupported time-bucket unit")
	}
}

func compileAggregateFilter(filter queryspec.Filter) (string, []any, error) {
	if filter.Kind == "group" {
		parts := make([]string, len(filter.Expressions))
		args := make([]any, 0)
		for index, expression := range filter.Expressions {
			part, childArgs, err := compileAggregateFilter(expression)
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
	field := qualifyAggregateField(filter.Field)
	if filter.Operator == "is_null" || filter.Operator == "is_not_null" {
		return field + " " + operator, nil, nil
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
		return field + " " + operator + " (" + strings.Join(placeholders, ", ") + ")", args, nil
	}
	return field + " " + operator + " ?", args, nil
}

func qualifyAggregateField(field string) string {
	return quote(aggregateSourceAlias) + "." + quote(field)
}

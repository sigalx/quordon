package mysql8

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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

type keysetSourceColumn struct {
	name                   string
	dataType               string
	nativeType             string
	nullable               bool
	characterSet           string
	collation              string
	characterMaximumLength sql.NullInt64
	characterOctetLength   sql.NullInt64
	numericPrecision       sql.NullInt64
	numericScale           sql.NullInt64
	datetimePrecision      sql.NullInt64
}

type keysetSource struct {
	columns           map[string]keysetSourceColumn
	projectionColumns []keysetSourceColumn
	keyColumns        []keysetSourceColumn
	keyKinds          []string
	keyIndexes        []int
}

func (a *Adapter) SelectKeyset(
	ctx context.Context,
	db *sql.DB,
	query policy.AuthorizedKeysetSelect,
	budget database.KeysetEnvelopeBudget,
) (result database.KeysetSelectResult, resultErr error) {
	if query.Operation() != domain.OperationSelectKeyset || query.Adapter() != domain.AdapterMySQL8 {
		return database.KeysetSelectResult{}, invalidAuthorizationError("select_keyset")
	}
	if budget.FinalBaseBytes < 0 || budget.MoreBaseBytes < 0 ||
		budget.FinalBaseBytes > query.Limits().MaxResultBytes || budget.MoreBaseBytes > query.Limits().MaxResultBytes {
		return database.KeysetSelectResult{}, &database.Error{Kind: database.ErrorResultTooLarge}
	}
	request := query.Query()
	conn, err := db.Conn(ctx)
	if err != nil {
		return database.KeysetSelectResult{}, classifyExecutionError(ctx, err)
	}
	defer conn.Close()
	clearDeadline, err := bindConnectionDeadline(ctx, conn, query.Limits().DeadlineMS)
	if err != nil {
		return database.KeysetSelectResult{}, classifyExecutionError(ctx, err)
	}
	defer func() {
		if clearDeadline != nil {
			_ = clearDeadline()
		}
	}()
	info, err := readServerInfo(ctx, conn)
	if err != nil {
		return database.KeysetSelectResult{}, err
	}
	semantics, err := semanticsForLowerCaseTableNames(info.lowerCaseTableNames)
	if err != nil {
		return database.KeysetSelectResult{}, err
	}
	if semantics != query.IdentifierSemantics() {
		return database.KeysetSelectResult{}, &database.Error{
			Kind: database.ErrorUnavailable, Err: errors.New("identifier semantics changed after authorization"),
		}
	}
	ctx = mysql.WithMaxReadPacketSize(ctx, absoluteResultPacketSize())
	source, err := validateKeysetSource(
		ctx, conn, request, info.lowerCaseTableNames,
	)
	if err != nil {
		return database.KeysetSelectResult{}, err
	}
	columns, err := keysetResultColumns(request, source)
	if err != nil {
		return database.KeysetSelectResult{}, err
	}
	finalBase, err := addKeysetColumnsSize(budget.FinalBaseBytes, columns, query.Limits().MaxResultBytes)
	if err != nil {
		return database.KeysetSelectResult{}, err
	}
	moreBase, err := addKeysetColumnsSize(budget.MoreBaseBytes, columns, query.Limits().MaxResultBytes)
	if err != nil {
		return database.KeysetSelectResult{}, err
	}
	if !keysetContinuationRequestFits(request, source, query.Limits().MaxRequestBytes) {
		return database.KeysetSelectResult{}, &database.Error{Kind: database.ErrorRequestTooLarge, Err: errors.New("continuation request cannot fit")}
	}
	statement, args, err := compileKeyset(request, source, query.Limits().DeadlineMS)
	if err != nil {
		return database.KeysetSelectResult{}, classifyKeysetCompileError(err)
	}
	if err := validateKeysetCharacterBindings(ctx, conn, request, source); err != nil {
		return database.KeysetSelectResult{}, err
	}
	originalTimezone, err := setAggregateUTCSession(ctx, conn)
	if err != nil {
		return database.KeysetSelectResult{}, err
	}
	sessionMutated := true
	defer func() {
		if !sessionMutated {
			return
		}
		if resultErr != nil {
			discardSQLConnection(conn)
			return
		}
		if restoreErr := restoreAggregateSessionTimezone(ctx, conn, originalTimezone); restoreErr != nil {
			result = database.KeysetSelectResult{}
			resultErr = restoreErr
		}
	}()
	if err := startAggregateTransaction(ctx, conn); err != nil {
		return database.KeysetSelectResult{}, err
	}
	transactionActive := true
	defer func() {
		if transactionActive {
			_ = finalizeAggregateTransaction(ctx, conn, "ROLLBACK")
		}
	}()
	plan, err := readAggregatePlan(ctx, conn, "EXPLAIN FORMAT=JSON "+statement, args)
	if err != nil {
		return database.KeysetSelectResult{}, err
	}
	if err := validateAggregatePlan(plan, query.RequiredIndex(), query.MaximumRowsExaminedPerScan(), query.AllowTemporaryTable(), query.AllowFilesort()); err != nil {
		return database.KeysetSelectResult{}, err
	}
	rows, err := conn.QueryContext(ctx, statement, args...)
	if err != nil {
		return database.KeysetSelectResult{}, classifyKeysetCharacterError(ctx, err)
	}
	result = database.KeysetSelectResult{Columns: columns, Rows: make([][]*string, 0)}
	stoppedEarly, err := collectKeysetRows(
		ctx, rows, request.Query.Limit, columns, source, finalBase, moreBase,
		query.Limits().MaxResultBytes, &result,
	)
	if err != nil {
		if abortErr := abortKeysetRows(conn, rows); abortErr != nil {
			return database.KeysetSelectResult{}, classifyExecutionError(ctx, abortErr)
		}
		transactionActive = false
		sessionMutated = false
		clearDeadline = nil
		return database.KeysetSelectResult{}, err
	}
	if stoppedEarly {
		// Closing the physical connection rolls back the read-only transaction,
		// restores session state without draining the intentionally unread result.
		if err := abortKeysetRows(conn, rows); err != nil {
			return database.KeysetSelectResult{}, classifyExecutionError(ctx, err)
		}
		transactionActive = false
		sessionMutated = false
		clearDeadline = nil
		return result, nil
	}
	if err := rows.Close(); err != nil {
		return database.KeysetSelectResult{}, classifyExecutionError(ctx, err)
	}
	if err := finalizeAggregateTransaction(ctx, conn, "COMMIT"); err != nil {
		return database.KeysetSelectResult{}, err
	}
	transactionActive = false
	if err := restoreAggregateSessionTimezone(ctx, conn, originalTimezone); err != nil {
		return database.KeysetSelectResult{}, err
	}
	sessionMutated = false
	if err := clearDeadline(); err != nil {
		return database.KeysetSelectResult{}, classifyExecutionError(ctx, err)
	}
	clearDeadline = nil
	result.RowCount = len(result.Rows)
	return result, nil
}

func abortKeysetRows(conn *sql.Conn, rows *sql.Rows) error {
	if err := conn.Raw(func(driverConn any) error {
		return mysql.AbortConnection(driverConn)
	}); err != nil {
		return err
	}
	// AbortConnection has already closed the socket, so this releases the
	// database/sql row lock without invoking the driver's unread-row drain.
	_ = rows.Close()
	return nil
}

func validateKeysetSource(
	ctx context.Context,
	conn *sql.Conn,
	request queryspec.NormalizedKeysetRequest,
	lowerCaseTableNames int,
) (keysetSource, error) {
	caseInsensitiveObjects := lowerCaseTableNames != 0
	var actualSchema, actualObject string
	if err := conn.QueryRowContext(
		ctx,
		`SELECT table_schema, table_name FROM information_schema.tables WHERE `+
			metadataIdentifierComparison("table_schema", "?", caseInsensitiveObjects)+` AND `+
			metadataIdentifierComparison("table_name", "?", caseInsensitiveObjects)+
			` LIMIT 1`,
		request.Query.Source.Schema, request.Query.Source.Name,
	).Scan(&actualSchema, &actualObject); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return keysetSource{}, invalidSourceError()
		}
		return keysetSource{}, classifyQueryError(ctx, err)
	}
	if !tokenIdentifierMatches(actualSchema, request.Query.Source.Schema, caseInsensitiveObjects) ||
		!tokenIdentifierMatches(actualObject, request.Query.Source.Name, caseInsensitiveObjects) {
		return keysetSource{}, metadataResourceMismatchError()
	}

	referenced := queryspec.KeysetReferencedFields(request)
	comparisons := make([]string, len(referenced))
	args := make([]any, 0, 2+len(referenced))
	args = append(args, actualSchema, actualObject)
	for index, field := range referenced {
		comparisons[index] = metadataIdentifierComparison("column_name", "?", true)
		args = append(args, field)
	}
	statement := `SELECT table_schema, table_name, column_name, data_type, column_type, is_nullable,
       COALESCE(character_set_name, ''), COALESCE(collation_name, ''),
       character_maximum_length, character_octet_length, numeric_precision, numeric_scale,
       datetime_precision
FROM information_schema.columns
WHERE ` + metadataIdentifierComparison("table_schema", "?", caseInsensitiveObjects) + `
  AND ` + metadataIdentifierComparison("table_name", "?", caseInsensitiveObjects) + `
  AND (` + strings.Join(comparisons, " OR ") + `)
ORDER BY ordinal_position`
	rows, err := conn.QueryContext(ctx, statement, args...)
	if err != nil {
		return keysetSource{}, classifyQueryError(ctx, err)
	}
	defer func() { _ = drainAndCloseRows(rows) }()
	columns := make(map[string]keysetSourceColumn, len(referenced))
	wanted := make(map[string]struct{}, len(referenced))
	for _, field := range referenced {
		wanted[strings.ToLower(field)] = struct{}{}
	}
	for rows.Next() {
		var rowSchema, rowObject, nullable string
		var column keysetSourceColumn
		if err := rows.Scan(
			&rowSchema, &rowObject, &column.name, &column.dataType, &column.nativeType, &nullable,
			&column.characterSet, &column.collation, &column.characterMaximumLength,
			&column.characterOctetLength, &column.numericPrecision, &column.numericScale,
			&column.datetimePrecision,
		); err != nil {
			return keysetSource{}, classifyExecutionError(ctx, err)
		}
		if !tokenIdentifierMatches(rowSchema, request.Query.Source.Schema, caseInsensitiveObjects) ||
			!tokenIdentifierMatches(rowObject, request.Query.Source.Name, caseInsensitiveObjects) {
			return keysetSource{}, metadataResourceMismatchError()
		}
		key := strings.ToLower(column.name)
		if _, ok := wanted[key]; !ok {
			return keysetSource{}, metadataResourceMismatchError()
		}
		if _, duplicate := columns[key]; duplicate {
			return keysetSource{}, metadataResourceMismatchError()
		}
		column.nullable = nullable == "YES"
		columns[key] = column
	}
	if err := rows.Err(); err != nil {
		return keysetSource{}, classifyExecutionError(ctx, err)
	}
	if len(columns) != len(referenced) {
		return keysetSource{}, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("keyset query references an unknown field")}
	}
	if err := validateKeysetFilterTypes(request.Query.Filter, columns); err != nil {
		return keysetSource{}, err
	}
	projectionColumns := make([]keysetSourceColumn, len(request.Query.Projection))
	for index, projection := range request.Query.Projection {
		column, ok := columns[strings.ToLower(projection.Field)]
		if !ok {
			return keysetSource{}, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("keyset projection references an unknown field")}
		}
		projectionColumns[index] = column
	}

	keyColumns := make([]keysetSourceColumn, 0, len(request.Query.OrderBy))
	keyKinds := make([]string, 0, len(request.Query.OrderBy))
	for _, order := range request.Query.OrderBy {
		column, ok := columns[strings.ToLower(order.Field)]
		if !ok || column.nullable {
			return keysetSource{}, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("keyset columns must be non-null")}
		}
		kind, err := validateKeysetColumnType(column)
		if err != nil {
			return keysetSource{}, err
		}
		keyColumns = append(keyColumns, column)
		keyKinds = append(keyKinds, kind)
	}
	keyIndexes := make([]int, len(keyColumns))
	for keyIndex, keyColumn := range keyColumns {
		projectionIndex := -1
		for index, projection := range request.Query.Projection {
			if strings.EqualFold(projection.Field, keyColumn.name) {
				if projectionIndex != -1 {
					return keysetSource{}, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("key field is projected more than once")}
				}
				projectionIndex = index
			}
		}
		if projectionIndex == -1 {
			return keysetSource{}, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("key field is not projected")}
		}
		keyIndexes[keyIndex] = projectionIndex
	}
	if request.Page.Kind == "after" {
		for index, value := range request.Page.Cursor {
			if value.Type != keyKinds[index] {
				return keysetSource{}, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("cursor type does not match key column")}
			}
			if _, err := bindKeysetCursor(value, keyColumns[index]); err != nil {
				return keysetSource{}, err
			}
		}
	}
	return keysetSource{
		columns: columns, projectionColumns: projectionColumns,
		keyColumns: keyColumns, keyKinds: keyKinds, keyIndexes: keyIndexes,
	}, nil
}

func validateKeysetColumnType(column keysetSourceColumn) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(column.dataType)) {
	case "TINYINT", "SMALLINT", "MEDIUMINT", "INT", "INTEGER", "BIGINT":
		return "integer", nil
	case "CHAR", "VARCHAR":
		if !validKeysetCharacterMetadata(column) || !column.characterMaximumLength.Valid ||
			column.characterMaximumLength.Int64 < 0 || column.characterMaximumLength.Int64 > queryspec.ProtocolMaxCursorStringRunes {
			return "", &database.Error{Kind: database.ErrorInvalid, Err: errors.New("character key cannot round-trip through the cursor contract")}
		}
		return "string", nil
	case "BINARY", "VARBINARY":
		if !column.characterOctetLength.Valid || column.characterOctetLength.Int64 < 0 ||
			column.characterOctetLength.Int64 > queryspec.ProtocolMaxCursorBytes {
			return "", &database.Error{Kind: database.ErrorInvalid, Err: errors.New("binary key exceeds the cursor contract")}
		}
		return "bytes", nil
	case "DATE":
		return "date", nil
	case "DATETIME":
		if _, err := mysqlKeysetTemporalPrecision(column); err != nil {
			return "", err
		}
		return "datetime", nil
	case "TIMESTAMP":
		if _, err := mysqlKeysetTemporalPrecision(column); err != nil {
			return "", err
		}
		return "timestamp", nil
	default:
		return "", &database.Error{Kind: database.ErrorInvalid, Err: errors.New("column type is not supported for a keyset cursor")}
	}
}

func validateKeysetFilterTypes(filter *queryspec.Filter, columns map[string]keysetSourceColumn) error {
	if filter == nil {
		return nil
	}
	if filter.Kind == "group" {
		for index := range filter.Expressions {
			if err := validateKeysetFilterTypes(&filter.Expressions[index], columns); err != nil {
				return err
			}
		}
		return nil
	}
	column, ok := columns[strings.ToLower(filter.Field)]
	if !ok {
		return &database.Error{Kind: database.ErrorInvalid, Err: errors.New("filter field is unknown")}
	}
	for _, value := range filter.Values {
		if !keysetFilterTypeCompatible(value.Type, filter.Operator, column) {
			return &database.Error{Kind: database.ErrorInvalid, Err: errors.New("filter value type is incompatible with source field")}
		}
	}
	return nil
}

func keysetFilterTypeCompatible(valueType, operator string, column keysetSourceColumn) bool {
	dataType := strings.ToUpper(strings.TrimSpace(column.dataType))
	if operator == "is_null" || operator == "is_not_null" {
		return true
	}
	switch valueType {
	case "boolean":
		return dataType == "TINYINT" && isMySQLBooleanColumn(column.nativeType)
	case "integer":
		return slices.Contains([]string{"TINYINT", "SMALLINT", "MEDIUMINT", "INT", "INTEGER", "BIGINT"}, dataType)
	case "decimal":
		_, _, err := keysetDecimalDefinition(column)
		return err == nil
	case "string":
		// Concrete values are checked by a bounded server-side round trip before
		// EXPLAIN; the metadata charset is not an application allowlist.
		if !validKeysetCharacterMetadata(column) {
			return false
		}
		return slices.Contains([]string{"CHAR", "VARCHAR", "TINYTEXT", "TEXT", "MEDIUMTEXT", "LONGTEXT", "ENUM", "SET"}, dataType) && operator != "like" ||
			operator == "like" && slices.Contains([]string{"CHAR", "VARCHAR", "TINYTEXT", "TEXT", "MEDIUMTEXT", "LONGTEXT"}, dataType)
	case "uuid":
		// Canonical UUID values are 36 ASCII characters. Requiring a physical
		// character column with sufficient declared width makes the advertised
		// round trip explicit instead of relying on MySQL truncation/coercion.
		return validKeysetCharacterMetadata(column) &&
			slices.Contains([]string{"CHAR", "VARCHAR", "TINYTEXT", "TEXT", "MEDIUMTEXT", "LONGTEXT"}, dataType) &&
			column.characterMaximumLength.Valid && column.characterMaximumLength.Int64 >= 36
	case "date":
		return dataType == "DATE"
	case "datetime":
		return dataType == "DATETIME" || dataType == "TIMESTAMP"
	case "bytes":
		return slices.Contains([]string{"BINARY", "VARBINARY", "TINYBLOB", "BLOB", "MEDIUMBLOB", "LONGBLOB"}, dataType)
	default:
		return false
	}
}

func keysetResultColumns(
	request queryspec.NormalizedKeysetRequest, source keysetSource,
) ([]database.ResultColumn, error) {
	result := make([]database.ResultColumn, len(request.Query.Projection))
	for index, projection := range request.Query.Projection {
		column, ok := source.columns[strings.ToLower(projection.Field)]
		if !ok {
			return nil, &database.Error{Kind: database.ErrorInvalid}
		}
		dataType := strings.ToUpper(strings.TrimSpace(column.dataType))
		if keysetNumericColumnHasZerofill(column, dataType) {
			return nil, &database.Error{
				Kind: database.ErrorInvalid,
				Err:  errors.New("ZEROFILL numeric projections are not supported"),
			}
		}
		if dataType == "FLOAT" || dataType == "DOUBLE" || dataType == "REAL" {
			return nil, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("floating-point projections are not supported")}
		}
		name := projection.Field
		if projection.Alias != "" {
			name = projection.Alias
		}
		result[index] = database.ResultColumn{
			Name: name, Type: portableColumnType(column.dataType),
			Encoding: resultEncoding(column.dataType), Nullable: column.nullable,
		}
	}
	return result, nil
}

func keysetNumericColumnHasZerofill(column keysetSourceColumn, normalizedDataType string) bool {
	if !slices.Contains([]string{
		"TINYINT", "SMALLINT", "MEDIUMINT", "INT", "INTEGER", "BIGINT", "DECIMAL", "NUMERIC",
	}, normalizedDataType) {
		return false
	}
	for _, modifier := range strings.Fields(column.nativeType) {
		if strings.EqualFold(modifier, "ZEROFILL") {
			return true
		}
	}
	return false
}

func addKeysetColumnsSize(base int, columns []database.ResultColumn, maximum int) (int, error) {
	return addAggregateColumnsSize(base, columns, maximum)
}

func compileKeyset(
	request queryspec.NormalizedKeysetRequest,
	source keysetSource,
	deadlineMS int,
) (string, []any, error) {
	if len(source.keyColumns) != len(source.keyKinds) {
		return "", nil, &database.Error{Kind: database.ErrorUpstream, Err: errors.New("keyset source type invariant failed")}
	}
	projection := make([]string, len(request.Query.Projection))
	for index, selection := range request.Query.Projection {
		expression := qualifyAggregateField(selection.Field)
		if selection.Alias != "" {
			expression += " AS " + quote(selection.Alias)
		}
		projection[index] = expression
	}
	for index, column := range source.keyColumns {
		if source.keyKinds[index] != "string" {
			continue
		}
		if !validKeysetCharacterMetadata(column) {
			return "", nil, invalidKeysetCharacterError()
		}
		// Hidden fixed-width markers validate only already-authorized key fields
		// in this bounded page. They never enter the public projection or cursor.
		field := qualifyAggregateField(column.name)
		projection = append(projection, keysetCharacterRoundTrip(field, field, "utf8mb4", column.characterSet))
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "SELECT /*+ MAX_EXECUTION_TIME(%d) */ ", deadlineMS)
	builder.WriteString(strings.Join(projection, ", "))
	builder.WriteString(" FROM ")
	builder.WriteString(quote(request.Query.Source.Schema))
	builder.WriteByte('.')
	builder.WriteString(quote(request.Query.Source.Name))
	builder.WriteString(" AS ")
	builder.WriteString(quote(aggregateSourceAlias))
	where := make([]string, 0, 2)
	args := make([]any, 0)
	if request.Query.Filter != nil {
		filterSQL, filterArgs, err := compileKeysetFilter(*request.Query.Filter, source.columns)
		if err != nil {
			return "", nil, err
		}
		where = append(where, filterSQL)
		args = append(args, filterArgs...)
	}
	if request.Page.Kind == "after" {
		cursorSQL, cursorArgs, err := compileKeysetCursor(request, source)
		if err != nil {
			return "", nil, err
		}
		where = append(where, cursorSQL)
		args = append(args, cursorArgs...)
	}
	if len(where) != 0 {
		builder.WriteString(" WHERE ")
		builder.WriteString(strings.Join(where, " AND "))
	}
	terms := make([]string, len(request.Query.OrderBy))
	for index, order := range request.Query.OrderBy {
		terms[index] = qualifyAggregateField(order.Field) + " " + strings.ToUpper(order.Direction)
	}
	builder.WriteString(" ORDER BY ")
	builder.WriteString(strings.Join(terms, ", "))
	builder.WriteString(" LIMIT ?")
	args = append(args, request.Query.Limit+1)
	return builder.String(), args, nil
}

func compileKeysetFilter(
	filter queryspec.Filter, columns map[string]keysetSourceColumn,
) (string, []any, error) {
	if filter.Kind == "group" {
		parts := make([]string, len(filter.Expressions))
		args := make([]any, 0)
		for index, child := range filter.Expressions {
			part, childArgs, err := compileKeysetFilter(child, columns)
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
		return "", nil, errors.New("unsupported keyset filter operator")
	}
	field := qualifyAggregateField(filter.Field)
	if filter.Operator == "is_null" || filter.Operator == "is_not_null" {
		return field + " " + operator, nil, nil
	}
	column, ok := columns[strings.ToLower(filter.Field)]
	if !ok {
		return "", nil, errors.New("unknown keyset filter field")
	}
	args := make([]any, len(filter.Values))
	placeholders := make([]string, len(filter.Values))
	for index, value := range filter.Values {
		bound, err := bindKeysetFilterValue(value, column)
		if err != nil {
			return "", nil, err
		}
		args[index] = bound
		placeholders[index], err = keysetFilterPlaceholder(value, column)
		if err != nil {
			return "", nil, err
		}
	}
	if filter.Operator == "in" || filter.Operator == "not_in" {
		return field + " " + operator + " (" + strings.Join(placeholders, ", ") + ")", args, nil
	}
	return field + " " + operator + " " + placeholders[0], args, nil
}

func bindKeysetFilterValue(value queryspec.TypedValue, column keysetSourceColumn) (any, error) {
	bound, err := value.BindValue()
	if err != nil {
		return nil, err
	}
	if value.Type == "integer" {
		integer, ok := bound.(int64)
		if !ok {
			return nil, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("invalid integer binding")}
		}
		// Use the exact source-width conversion shared with keyset cursors. In
		// particular, a negative signed parameter must never reach comparison
		// with an UNSIGNED MySQL column, where it could be reinterpreted as a
		// large unsigned value.
		return bindKeysetInteger(strconv.FormatInt(integer, 10), column)
	}
	if value.Type == "decimal" {
		text, ok := bound.(string)
		if !ok {
			return nil, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("invalid decimal binding")}
		}
		precision, scale, err := keysetDecimalDefinition(column)
		if err != nil {
			return nil, err
		}
		normalized, err := normalizeExactKeysetDecimal(
			text, precision, scale, strings.Contains(strings.ToLower(column.nativeType), "unsigned"),
		)
		if err != nil {
			return nil, &database.Error{Kind: database.ErrorInvalid, Err: err}
		}
		return normalized, nil
	}
	if value.Type == "date" {
		text, ok := bound.(string)
		if !ok {
			return nil, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("invalid date binding")}
		}
		parsed, err := time.Parse(time.DateOnly, text)
		if err != nil || parsed.Before(mysqlDateMinimum) || parsed.After(mysqlDateMaximum) {
			return nil, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("date value is outside the MySQL DATE range")}
		}
		return parsed.Format(time.DateOnly), nil
	}
	if value.Type != "datetime" {
		return bound, nil
	}
	text, ok := bound.(string)
	if !ok {
		return nil, errors.New("invalid datetime binding")
	}
	normalized := []byte(text)
	if len(normalized) > 10 && normalized[10] == 't' {
		normalized[10] = 'T'
	}
	if len(normalized) != 0 && normalized[len(normalized)-1] == 'z' {
		normalized[len(normalized)-1] = 'Z'
	}
	parsed, err := time.Parse(time.RFC3339Nano, string(normalized))
	if err != nil {
		return nil, err
	}
	if !column.datetimePrecision.Valid || column.datetimePrecision.Int64 < 0 || column.datetimePrecision.Int64 > 6 {
		return nil, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("source datetime precision is unsupported")}
	}
	precisionFactor := int64(1)
	for digits := column.datetimePrecision.Int64; digits < 9; digits++ {
		precisionFactor *= 10
	}
	if int64(parsed.Nanosecond())%precisionFactor != 0 {
		return nil, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("datetime value exceeds the source precision")}
	}
	// TIMESTAMP represents an instant and the adapter pins the session to UTC.
	// DATETIME is timezone-naive, so preserve the RFC 3339 wall-clock fields
	// instead of silently shifting them by the supplied offset.
	boundTime := time.Date(
		parsed.Year(), parsed.Month(), parsed.Day(),
		parsed.Hour(), parsed.Minute(), parsed.Second(), parsed.Nanosecond(), time.UTC,
	)
	dataType := strings.ToUpper(strings.TrimSpace(column.dataType))
	if dataType == "TIMESTAMP" {
		boundTime = parsed.UTC()
	}
	minimum, maximum := mysqlDatetimeMinimum, mysqlDatetimeMaximum
	if dataType == "TIMESTAMP" {
		minimum, maximum = mysqlTimestampMinimum, mysqlTimestampMaximum
	}
	if boundTime.Before(minimum) || boundTime.After(maximum) {
		return nil, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("datetime value is outside the MySQL source range")}
	}
	return boundTime.Format("2006-01-02 15:04:05.999999"), nil
}

func keysetFilterPlaceholder(value queryspec.TypedValue, column keysetSourceColumn) (string, error) {
	switch value.Type {
	case "string", "uuid":
		return keysetCharacterOperand(column)
	case "date":
		return "CAST(? AS DATE)", nil
	case "datetime":
		if !column.datetimePrecision.Valid || column.datetimePrecision.Int64 < 0 || column.datetimePrecision.Int64 > 6 {
			return "", &database.Error{Kind: database.ErrorInvalid, Err: errors.New("source datetime precision is unsupported")}
		}
		// MySQL has no CAST(... AS TIMESTAMP). The session is pinned to UTC,
		// therefore an explicitly typed DATETIME operand preserves the exact
		// TIMESTAMP instant as well as timezone-naive DATETIME wall-clock fields.
		return fmt.Sprintf("CAST(? AS DATETIME(%d))", column.datetimePrecision.Int64), nil
	case "decimal":
	default:
		return "?", nil
	}
	precision, scale, err := keysetDecimalDefinition(column)
	if err != nil {
		return "", err
	}
	// go-sql-driver has no exact decimal driver.Value. The argument therefore
	// remains a bounded canonical decimal string, while the server-owned cast
	// gives MySQL an explicit exact numeric operand. normalizeExactKeysetDecimal
	// has already proved that the cast cannot round or overflow.
	return fmt.Sprintf("CAST(? AS DECIMAL(%d,%d))", precision, scale), nil
}

var (
	mysqlDateMinimum      = time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
	mysqlDateMaximum      = time.Date(9999, time.December, 31, 0, 0, 0, 0, time.UTC)
	mysqlDatetimeMinimum  = time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
	mysqlDatetimeMaximum  = time.Date(9999, time.December, 31, 23, 59, 59, 499999000, time.UTC)
	mysqlTimestampMinimum = time.Date(1970, time.January, 1, 0, 0, 1, 0, time.UTC)
	mysqlTimestampMaximum = time.Date(2038, time.January, 19, 3, 14, 7, 499999000, time.UTC)
)

func keysetDecimalDefinition(column keysetSourceColumn) (int, int, error) {
	dataType := strings.ToUpper(strings.TrimSpace(column.dataType))
	if dataType != "DECIMAL" && dataType != "NUMERIC" ||
		!column.numericPrecision.Valid || !column.numericScale.Valid ||
		column.numericPrecision.Int64 < 1 || column.numericPrecision.Int64 > 65 ||
		column.numericScale.Int64 < 0 || column.numericScale.Int64 > 30 ||
		column.numericScale.Int64 > column.numericPrecision.Int64 {
		return 0, 0, &database.Error{
			Kind: database.ErrorInvalid, Err: errors.New("source decimal definition is unsupported"),
		}
	}
	return int(column.numericPrecision.Int64), int(column.numericScale.Int64), nil
}

func normalizeExactKeysetDecimal(text string, precision, scale int, unsigned bool) (string, error) {
	if text == "" {
		return "", errors.New("decimal value is empty")
	}
	position := 0
	negative := false
	if text[position] == '-' {
		negative = true
		position++
		if position == len(text) {
			return "", errors.New("decimal value has no digits")
		}
	} else if text[position] == '+' {
		return "", errors.New("decimal value has a leading plus sign")
	}

	exponentOffset := strings.IndexAny(text[position:], "eE")
	mantissaEnd := len(text)
	exponent := 0
	if exponentOffset >= 0 {
		mantissaEnd = position + exponentOffset
		parsed, ok := parseBoundedKeysetDecimalExponent(
			text[mantissaEnd+1:], len(text)+precision+scale+1,
		)
		if !ok {
			return "", errors.New("decimal exponent is invalid")
		}
		exponent = parsed
	}

	coefficient := make([]byte, 0, precision)
	pendingZeros := 0
	fractionalDigits := 0
	digitsBeforePoint := 0
	digitsAfterPoint := 0
	decimalPoint := false
	nonzero := false
	for index := position; index < mantissaEnd; index++ {
		character := text[index]
		if character == '.' {
			if decimalPoint || digitsBeforePoint == 0 {
				return "", errors.New("decimal mantissa is invalid")
			}
			decimalPoint = true
			continue
		}
		if character < '0' || character > '9' {
			return "", errors.New("decimal mantissa is invalid")
		}
		if decimalPoint {
			digitsAfterPoint++
			fractionalDigits++
		} else {
			digitsBeforePoint++
		}
		if character == '0' {
			if nonzero {
				pendingZeros++
			}
			continue
		}
		if len(coefficient)+pendingZeros+1 > precision {
			return "", errors.New("decimal value exceeds the source precision")
		}
		coefficient = append(coefficient, strings.Repeat("0", pendingZeros)...)
		pendingZeros = 0
		coefficient = append(coefficient, character)
		nonzero = true
	}
	if digitsBeforePoint == 0 || decimalPoint && digitsAfterPoint == 0 {
		return "", errors.New("decimal mantissa is invalid")
	}
	if !nonzero {
		return "0", nil
	}
	if negative && unsigned {
		return "", errors.New("negative decimal is not representable by the unsigned source")
	}

	// Removing pending trailing zeroes changes the coefficient by a power of
	// ten. Track that power arithmetically so even a request-sized run of zeroes
	// never becomes an expanded intermediate string.
	scalePower := fractionalDigits - exponent - pendingZeros
	requiredScale := scalePower
	integerDigits := 0
	if requiredScale < len(coefficient) {
		integerDigits = len(coefficient) - requiredScale
	}
	if requiredScale < 0 {
		integerDigits = len(coefficient) - requiredScale
		requiredScale = 0
	}
	if requiredScale > scale || integerDigits > precision-scale {
		return "", errors.New("decimal value is not exactly representable by the source precision and scale")
	}

	var builder strings.Builder
	if negative {
		builder.WriteByte('-')
	}
	switch {
	case requiredScale == 0:
		builder.Grow(len(coefficient) - scalePower)
		builder.Write(coefficient)
		for zeros := scalePower; zeros < 0; zeros++ {
			builder.WriteByte('0')
		}
	case requiredScale >= len(coefficient):
		builder.Grow(2 + requiredScale)
		builder.WriteString("0.")
		for zeros := len(coefficient); zeros < requiredScale; zeros++ {
			builder.WriteByte('0')
		}
		builder.Write(coefficient)
	default:
		split := len(coefficient) - requiredScale
		builder.Grow(len(coefficient) + 1)
		builder.Write(coefficient[:split])
		builder.WriteByte('.')
		builder.Write(coefficient[split:])
	}
	return builder.String(), nil
}

func parseBoundedKeysetDecimalExponent(text string, maximum int) (int, bool) {
	if text == "" {
		return 0, false
	}
	negative := false
	position := 0
	if text[0] == '-' || text[0] == '+' {
		negative = text[0] == '-'
		position++
		if position == len(text) {
			return 0, false
		}
	}
	value := 0
	for ; position < len(text); position++ {
		digit := text[position]
		if digit < '0' || digit > '9' {
			return 0, false
		}
		numeric := int(digit - '0')
		if value > (maximum-numeric)/10 {
			value = maximum
			continue
		}
		value = value*10 + numeric
	}
	if negative {
		return -value, true
	}
	return value, true
}

func classifyKeysetCompileError(err error) error {
	var classified *database.Error
	if errors.As(err, &classified) {
		return err
	}
	return &database.Error{Kind: database.ErrorUpstream, Err: err}
}

func compileKeysetCursor(
	request queryspec.NormalizedKeysetRequest, source keysetSource,
) (string, []any, error) {
	parts := make([]string, len(request.Query.OrderBy))
	args := make([]any, 0, len(parts)*(len(parts)+1)/2)
	for index, order := range request.Query.OrderBy {
		terms := make([]string, index+1)
		for prefix := 0; prefix < index; prefix++ {
			placeholder, err := keysetCursorPlaceholder(request.Page.Cursor[prefix], source.keyColumns[prefix])
			if err != nil {
				return "", nil, err
			}
			terms[prefix] = qualifyAggregateField(request.Query.OrderBy[prefix].Field) + " = " + placeholder
			bound, err := bindKeysetCursor(request.Page.Cursor[prefix], source.keyColumns[prefix])
			if err != nil {
				return "", nil, err
			}
			args = append(args, bound)
		}
		operator := ">"
		if order.Direction == "desc" {
			operator = "<"
		}
		placeholder, err := keysetCursorPlaceholder(request.Page.Cursor[index], source.keyColumns[index])
		if err != nil {
			return "", nil, err
		}
		terms[index] = qualifyAggregateField(order.Field) + " " + operator + " " + placeholder
		bound, err := bindKeysetCursor(request.Page.Cursor[index], source.keyColumns[index])
		if err != nil {
			return "", nil, err
		}
		args = append(args, bound)
		parts[index] = "(" + strings.Join(terms, " AND ") + ")"
	}
	return "(" + strings.Join(parts, " OR ") + ")", args, nil
}

func bindKeysetCursor(value queryspec.KeysetCursorValue, column keysetSourceColumn) (any, error) {
	switch value.Type {
	case "integer":
		return bindKeysetInteger(value.Value, column)
	case "string":
		if !validKeysetCharacterMetadata(column) || !column.characterMaximumLength.Valid ||
			!utf8.ValidString(value.Value) || utf8.RuneCountInString(value.Value) > int(column.characterMaximumLength.Int64) {
			return nil, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("string cursor exceeds the source column")}
		}
		return value.Value, nil
	case "bytes":
		decoded, err := base64.StdEncoding.Strict().DecodeString(value.Value)
		if err != nil || base64.StdEncoding.EncodeToString(decoded) != value.Value ||
			len(decoded) > int(column.characterOctetLength.Int64) {
			return nil, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("binary cursor exceeds the source column")}
		}
		return decoded, nil
	case "date", "datetime", "timestamp":
		return bindMySQLKeysetTemporalCursor(value, column)
	default:
		return nil, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("unsupported cursor type")}
	}
}

func keysetCursorPlaceholder(value queryspec.KeysetCursorValue, column keysetSourceColumn) (string, error) {
	switch value.Type {
	case "string":
		return keysetCharacterOperand(column)
	case "date":
		return "CAST(? AS DATE)", nil
	case "datetime", "timestamp":
		precision, err := mysqlKeysetTemporalPrecision(column)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("CAST(? AS DATETIME(%d))", precision), nil
	default:
		return "?", nil
	}
}

func bindMySQLKeysetTemporalCursor(value queryspec.KeysetCursorValue, column keysetSourceColumn) (string, error) {
	dataType := strings.ToUpper(strings.TrimSpace(column.dataType))
	switch value.Type {
	case "date":
		parsed, ok := queryspec.ParsePortableDate(value.Value)
		if dataType != "DATE" || !ok || parsed.Before(mysqlDateMinimum) || parsed.After(mysqlDateMaximum) {
			return "", &database.Error{Kind: database.ErrorInvalid, Err: errors.New("date cursor is incompatible with the MySQL source column")}
		}
		return value.Value, nil
	case "datetime":
		parsed, digits, ok := queryspec.ParsePortableDateTime(value.Value)
		precision, precisionErr := mysqlKeysetTemporalPrecision(column)
		if dataType != "DATETIME" || !ok || precisionErr != nil || digits != precision ||
			parsed.Before(mysqlDatetimeMinimum) || parsed.After(mysqlDatetimeMaximum) {
			return "", &database.Error{Kind: database.ErrorInvalid, Err: errors.New("datetime cursor is incompatible with the MySQL source column")}
		}
		return value.Value, nil
	case "timestamp":
		parsed, digits, ok := queryspec.ParsePortableTimestamp(value.Value)
		precision, precisionErr := mysqlKeysetTemporalPrecision(column)
		if dataType != "TIMESTAMP" || !ok || precisionErr != nil || digits != precision ||
			parsed.Before(mysqlTimestampMinimum) || parsed.After(mysqlTimestampMaximum) {
			return "", &database.Error{Kind: database.ErrorInvalid, Err: errors.New("timestamp cursor is incompatible with the MySQL source column")}
		}
		return value.Value[:10] + " " + value.Value[11:len(value.Value)-1], nil
	default:
		return "", &database.Error{Kind: database.ErrorInvalid, Err: errors.New("unsupported temporal cursor type")}
	}
}

func mysqlKeysetTemporalPrecision(column keysetSourceColumn) (int, error) {
	if !column.datetimePrecision.Valid || column.datetimePrecision.Int64 < 0 || column.datetimePrecision.Int64 > 6 {
		return 0, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("source temporal precision is unsupported")}
	}
	return int(column.datetimePrecision.Int64), nil
}

func bindKeysetInteger(value string, column keysetSourceColumn) (any, error) {
	dataType := strings.ToUpper(strings.TrimSpace(column.dataType))
	bits := map[string]int{"TINYINT": 8, "SMALLINT": 16, "MEDIUMINT": 24, "INT": 32, "INTEGER": 32, "BIGINT": 64}[dataType]
	if bits == 0 {
		return nil, &database.Error{Kind: database.ErrorInvalid}
	}
	if strings.Contains(strings.ToLower(column.nativeType), "unsigned") {
		parsed, err := strconv.ParseUint(value, 10, bits)
		if err != nil {
			return nil, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("integer cursor exceeds the unsigned source column")}
		}
		return parsed, nil
	}
	parsed, err := strconv.ParseInt(value, 10, bits)
	if err != nil {
		return nil, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("integer cursor exceeds the signed source column")}
	}
	return parsed, nil
}

func collectKeysetRows(
	ctx context.Context,
	rows selectRowSet,
	limit int,
	columns []database.ResultColumn,
	source keysetSource,
	finalBase, moreBase, maximum int,
	result *database.KeysetSelectResult,
) (bool, error) {
	rawValues := make([]sql.RawBytes, len(columns)+keysetCharacterGuardCount(source))
	destinations := make([]any, len(rawValues))
	for index := range rawValues {
		destinations[index] = &rawValues[index]
	}
	finalSize := finalBase
	lastSafeMoreSize := 0
	lastSafeCursor := []queryspec.KeysetCursorValue(nil)
	provisional := false
	provisionalPreviousSize := 0
	moreObserved := false
	for rows.Next() {
		if provisional || len(result.Rows) == limit {
			moreObserved = true
			break
		}
		if err := rows.Scan(destinations...); err != nil {
			return false, classifyKeysetCharacterError(ctx, err)
		}
		if err := validateKeysetCharacterGuards(rawValues[len(columns):]); err != nil {
			return false, err
		}
		rowValues := rawValues[:len(columns)]
		if err := validateKeysetRow(rowValues, columns, source); err != nil {
			return false, err
		}
		separator := 0
		if len(result.Rows) != 0 {
			separator = 1
		}
		rowCountGrowth := decimalDigits(len(result.Rows)+1) - decimalDigits(len(result.Rows))
		remaining := maximum - finalSize - separator - rowCountGrowth
		rowSize, finalFits := encodedRowSize(rowValues, columns, remaining)
		if !finalFits {
			moreObserved = true
			break
		}
		nextFinalSize := finalSize + separator + rowCountGrowth + rowSize
		rowsSize := nextFinalSize - finalBase
		cursorSize, cursorFits := encodedKeysetCursorSize(rowValues, source, maximum-moreBase-rowsSize)
		moreSize := moreBase + rowsSize
		if cursorFits {
			moreSize += cursorSize
			cursorFits = moreSize <= maximum
		}
		row := materializeAggregateRow(rowValues, columns)
		result.Rows = append(result.Rows, row)
		provisionalPreviousSize = finalSize
		finalSize = nextFinalSize
		if cursorFits {
			cursor, cursorErr := materializeKeysetCursor(rowValues, source)
			if cursorErr != nil {
				return false, cursorErr
			}
			lastSafeMoreSize = moreSize
			lastSafeCursor = cursor
		} else {
			provisional = true
		}
	}
	if err := rows.Err(); err != nil {
		return false, classifyKeysetCharacterError(ctx, err)
	}
	if moreObserved {
		if provisional {
			result.Rows = result.Rows[:len(result.Rows)-1]
			finalSize = provisionalPreviousSize
		}
		if len(result.Rows) == 0 || lastSafeMoreSize == 0 || len(lastSafeCursor) == 0 {
			return true, &database.Error{Kind: database.ErrorResultTooLarge, Err: errors.New("no keyset row and continuation cursor fit")}
		}
		result.HasMore = true
		result.NextCursor = lastSafeCursor
		result.ResultBytes = lastSafeMoreSize
	} else {
		result.HasMore = false
		result.NextCursor = nil
		result.ResultBytes = finalSize
	}
	result.RowCount = len(result.Rows)
	return moreObserved, nil
}

func validateKeysetRow(raw []sql.RawBytes, columns []database.ResultColumn, source keysetSource) error {
	if len(raw) != len(columns) || len(source.projectionColumns) != len(columns) {
		return &database.Error{Kind: database.ErrorUpstream, Err: errors.New("keyset row width invariant failed")}
	}
	for index, value := range raw {
		if value == nil {
			if !columns[index].Nullable {
				return &database.Error{Kind: database.ErrorUpstream, Err: errors.New("non-null keyset column returned NULL")}
			}
			continue
		}
		if !validKeysetCell(value, columns[index].Type) ||
			!validKeysetSourceTemporalCell(value, source.projectionColumns[index]) {
			return &database.Error{Kind: database.ErrorUpstream, Err: errors.New("keyset row contains a non-canonical value")}
		}
	}
	for _, projectionIndex := range source.keyIndexes {
		if raw[projectionIndex] == nil {
			return &database.Error{Kind: database.ErrorUpstream, Err: errors.New("keyset column returned NULL")}
		}
	}
	return nil
}

func validKeysetCell(value []byte, portableType string) bool {
	switch portableType {
	case "integer":
		text := string(value)
		if text == "" || text[0] == '+' || text == "-0" || len(text) > 20 || len(text) > 1 && text[0] == '0' {
			return false
		}
		if text[0] == '-' && (len(text) == 1 || text[1] == '0') {
			return false
		}
		for index, character := range text {
			if character == '-' && index == 0 {
				continue
			}
			if character < '0' || character > '9' {
				return false
			}
		}
		return true
	case "decimal":
		text := string(value)
		if text == "" || strings.ContainsAny(text, "eE+") {
			return false
		}
		negative := text[0] == '-'
		if text[0] == '-' {
			text = text[1:]
		}
		parts := strings.Split(text, ".")
		if len(parts) > 2 || parts[0] == "" || len(parts) > 1 && parts[1] == "" ||
			len(parts[0]) > 1 && parts[0][0] == '0' {
			return false
		}
		nonzero := false
		for _, part := range parts {
			for _, character := range part {
				if character < '0' || character > '9' {
					return false
				}
				if character != '0' {
					nonzero = true
				}
			}
		}
		return !negative || nonzero
	case "string":
		return utf8.Valid(value)
	case "date":
		_, ok := queryspec.ParsePortableDate(string(value))
		return ok
	case "datetime":
		_, _, ok := queryspec.ParsePortableDateTime(string(value))
		return ok
	case "time":
		return queryspec.ValidPortableTime(string(value))
	case "json":
		return utf8.Valid(value) && json.Valid(value)
	case "bytes":
		return true
	default:
		return false
	}
}

func isMySQLBooleanColumn(nativeType string) bool {
	parts := strings.Fields(strings.ToLower(strings.TrimSpace(nativeType)))
	if len(parts) == 0 || parts[0] != "tinyint(1)" {
		return false
	}
	return len(parts) == 1 || len(parts) == 2 && parts[1] == "unsigned"
}

func validKeysetSourceTemporalCell(value []byte, column keysetSourceColumn) bool {
	switch strings.ToUpper(strings.TrimSpace(column.dataType)) {
	case "DATE":
		parsed, ok := queryspec.ParsePortableDate(string(value))
		return ok && !parsed.Before(mysqlDateMinimum) && !parsed.After(mysqlDateMaximum)
	case "DATETIME":
		parsed, digits, ok := queryspec.ParsePortableDateTime(string(value))
		precision, err := mysqlKeysetTemporalPrecision(column)
		return ok && err == nil && digits == precision &&
			!parsed.Before(mysqlDatetimeMinimum) && !parsed.After(mysqlDatetimeMaximum)
	case "TIMESTAMP":
		parsed, digits, ok := queryspec.ParsePortableDateTime(string(value))
		precision, err := mysqlKeysetTemporalPrecision(column)
		return ok && err == nil && digits == precision &&
			!parsed.Before(mysqlTimestampMinimum) && !parsed.After(mysqlTimestampMaximum)
	case "TIME":
		text := string(value)
		if !queryspec.ValidPortableTime(text) {
			return false
		}
		dot := strings.IndexByte(text, '.')
		return dot < 0 || len(text)-dot-1 <= 6
	default:
		return true
	}
}

func encodedKeysetCursorSize(raw []sql.RawBytes, source keysetSource, maximum int) (int, bool) {
	if maximum < 0 {
		return 0, false
	}
	size := 0 // The base response already contains the empty array brackets.
	for index, projectionIndex := range source.keyIndexes {
		value := raw[projectionIndex]
		valueSize := 0
		kind := source.keyKinds[index]
		switch kind {
		case "bytes":
			valueSize = 2 + base64.StdEncoding.EncodedLen(len(value))
		default:
			cursorValue, cursorOK := mysqlKeysetCursorText(value, kind)
			if !cursorOK {
				return 0, false
			}
			var sizeOK bool
			valueSize, sizeOK = encodedJSONStringSize([]byte(cursorValue), maximum-size)
			if !sizeOK {
				return 0, false
			}
		}
		itemSize := len(`{"type":,"value":}`) + encodedJSONStringLiteralSize(kind) + valueSize
		if index != 0 {
			itemSize++
		}
		var ok bool
		size, ok = addEncodedSize(size, itemSize, maximum)
		if !ok {
			return 0, false
		}
	}
	return size, true
}

func encodedJSONStringLiteralSize(value string) int {
	size, _ := encodedMetadataJSONStringSize(value, int(^uint(0)>>1))
	return size
}

func materializeKeysetCursor(raw []sql.RawBytes, source keysetSource) ([]queryspec.KeysetCursorValue, error) {
	result := make([]queryspec.KeysetCursorValue, len(source.keyIndexes))
	for index, projectionIndex := range source.keyIndexes {
		kind := source.keyKinds[index]
		value := ""
		if kind == "bytes" {
			value = base64.StdEncoding.EncodeToString(raw[projectionIndex])
		} else {
			var ok bool
			value, ok = mysqlKeysetCursorText(raw[projectionIndex], kind)
			if !ok {
				return nil, &database.Error{Kind: database.ErrorUpstream, Err: errors.New("keyset cursor cannot be represented by the portable contract")}
			}
		}
		result[index] = queryspec.KeysetCursorValue{Type: kind, Value: value}
	}
	return result, nil
}

func mysqlKeysetCursorText(value []byte, kind string) (string, bool) {
	text := string(value)
	switch kind {
	case "date":
		_, ok := queryspec.ParsePortableDate(text)
		return text, ok
	case "datetime":
		_, _, ok := queryspec.ParsePortableDateTime(text)
		return text, ok
	case "timestamp":
		if _, _, ok := queryspec.ParsePortableDateTime(text); !ok {
			return "", false
		}
		result := text[:10] + "T" + text[11:] + "Z"
		if _, _, ok := queryspec.ParsePortableTimestamp(result); !ok {
			return "", false
		}
		return result, true
	default:
		return text, true
	}
}

func keysetContinuationRequestFits(
	request queryspec.NormalizedKeysetRequest, source keysetSource, maximum int,
) bool {
	// Compute a conservative canonical after-request size without materializing
	// the request or any maximum-width cursor value.
	size := 0
	add := func(value int) bool {
		var ok bool
		size, ok = addEncodedSize(size, value, maximum)
		return ok
	}
	addString := func(value string) bool {
		encoded, ok := encodedMetadataJSONStringSize(value, maximum-size)
		return ok && add(encoded)
	}
	if !add(len(`{"kind":"keyset","profile":`)) || !addString(request.Profile) ||
		!add(len(`,"shape":`)) || !addString(request.Shape) ||
		!add(len(`,"query":{"source":{"schema":`)) || !addString(request.Query.Source.Schema) ||
		!add(len(`,"name":`)) || !addString(request.Query.Source.Name) ||
		!add(len(`},"projection":[`)) {
		return false
	}
	for index, projection := range request.Query.Projection {
		if index != 0 && !add(1) {
			return false
		}
		if !add(len(`{"kind":"field","field":`)) || !addString(projection.Field) {
			return false
		}
		if projection.Alias != "" && (!add(len(`,"alias":`)) || !addString(projection.Alias)) {
			return false
		}
		if !add(1) {
			return false
		}
	}
	if !add(1) {
		return false
	}
	if request.Query.Filter != nil {
		if !add(len(`,"filter":`)) || !addKeysetFilterRequestBound(request.Query.Filter, maximum, &size) {
			return false
		}
	}
	if !add(len(`,"order_by":[`)) {
		return false
	}
	for index, order := range request.Query.OrderBy {
		if index != 0 && !add(1) {
			return false
		}
		if !add(len(`{"field":`)) || !addString(order.Field) ||
			!add(len(`,"direction":`)) || !addString(order.Direction) || !add(1) {
			return false
		}
	}
	if !add(len(`],"limit":`)) || !add(len(strconv.Itoa(request.Query.Limit))) ||
		!add(len(`},"page":{"kind":"after","cursor":[`)) {
		return false
	}
	for index, column := range source.keyColumns {
		if index != 0 && !add(1) {
			return false
		}
		valueBytes := 20
		switch source.keyKinds[index] {
		case "string":
			if !column.characterMaximumLength.Valid || column.characterMaximumLength.Int64 < 0 ||
				column.characterMaximumLength.Int64 > int64((maximum-size)/6) {
				return false
			}
			valueBytes = 2 + int(column.characterMaximumLength.Int64)*6
		case "bytes":
			if !column.characterOctetLength.Valid || column.characterOctetLength.Int64 < 0 ||
				column.characterOctetLength.Int64 > int64(maximum-size) {
				return false
			}
			valueBytes = 2 + base64.StdEncoding.EncodedLen(int(column.characterOctetLength.Int64))
		case "date":
			valueBytes = 2 + len("0001-01-01")
		case "datetime", "timestamp":
			precision, err := mysqlKeysetTemporalPrecision(column)
			if err != nil {
				return false
			}
			valueLength := len("0001-01-01 00:00:00")
			if source.keyKinds[index] == "timestamp" {
				valueLength++ // Required trailing Z; the space becomes T.
			}
			if precision != 0 {
				valueLength += 1 + precision
			}
			valueBytes = 2 + valueLength
		default:
			valueBytes += 2
		}
		if !add(len(`{"type":`)) || !addString(source.keyKinds[index]) ||
			!add(len(`,"value":`)) || !add(valueBytes) || !add(1) {
			return false
		}
	}
	return add(len(`]}}`)) && size <= maximum
}

func addKeysetFilterRequestBound(filter *queryspec.Filter, maximum int, size *int) bool {
	if filter == nil {
		return true
	}
	add := func(value int) bool {
		var ok bool
		*size, ok = addEncodedSize(*size, value, maximum)
		return ok
	}
	addString := func(value string) bool {
		encoded, ok := encodedMetadataJSONStringSize(value, maximum-*size)
		return ok && add(encoded)
	}
	if !add(len(`{"kind":`)) || !addString(filter.Kind) {
		return false
	}
	if filter.Kind == "predicate" {
		if !add(len(`,"field":`)) || !addString(filter.Field) ||
			!add(len(`,"operator":`)) || !addString(filter.Operator) || !add(len(`,"values":[`)) {
			return false
		}
		for index, value := range filter.Values {
			if index != 0 && !add(1) {
				return false
			}
			if !add(len(`{"type":`)) || !addString(value.Type) || !add(len(`,"value":`)) {
				return false
			}
			// Raw bind JSON is already strictly decoded. Six bytes per source
			// byte conservatively covers JSON string escaping without decoding
			// or rematerializing the value.
			if len(value.Value) > (maximum-*size)/6 || !add(6*len(value.Value)) || !add(1) {
				return false
			}
		}
		return add(len(`]}`))
	}
	if !add(len(`,"operator":`)) || !addString(filter.Operator) || !add(len(`,"expressions":[`)) {
		return false
	}
	for index := range filter.Expressions {
		if index != 0 && !add(1) {
			return false
		}
		if !addKeysetFilterRequestBound(&filter.Expressions[index], maximum, size) {
			return false
		}
	}
	return add(len(`]}`))
}

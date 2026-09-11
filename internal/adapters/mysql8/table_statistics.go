package mysql8

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
)

const maxPhysicalPartitionLeaves = 8192

type tableIdentity struct {
	schema string
	name   string
	engine string
}

type partitionRow struct {
	partitionName       sql.RawBytes
	partitionOrdinal    sql.RawBytes
	partitionMethod     sql.RawBytes
	subpartitionName    sql.RawBytes
	subpartitionOrdinal sql.RawBytes
	subpartitionMethod  sql.RawBytes
	estimatedRows       sql.RawBytes
	dataBytes           sql.RawBytes
	indexBytes          sql.RawBytes
}

func (a *Adapter) DescribeObjectStatistics(
	ctx context.Context,
	db *sql.DB,
	authorized policy.AuthorizedObjectStatistics,
	envelopeBaseBytes int,
) (database.ObjectStatisticsResult, error) {
	if authorized.Operation() != domain.OperationDescribeObjectStatistics ||
		authorized.Adapter() != domain.AdapterMySQL8 ||
		authorized.IdentifierSemanticsGeneration() == "" ||
		envelopeBaseBytes < 0 || envelopeBaseBytes > authorized.Limits().MaxResultBytes {
		return database.ObjectStatisticsResult{}, invalidAuthorizationError("describe_object_statistics")
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return database.ObjectStatisticsResult{}, classifyExecutionError(ctx, err)
	}
	defer conn.Close()
	clearDeadline, err := bindConnectionDeadline(ctx, conn, authorized.Limits().DeadlineMS)
	if err != nil {
		return database.ObjectStatisticsResult{}, classifyExecutionError(ctx, err)
	}
	defer func() {
		if clearDeadline != nil {
			_ = clearDeadline()
		}
	}()
	info, err := readServerInfo(ctx, conn)
	if err != nil {
		return database.ObjectStatisticsResult{}, err
	}
	semantics, err := semanticsForLowerCaseTableNames(info.lowerCaseTableNames)
	if err != nil {
		return database.ObjectStatisticsResult{}, err
	}
	if semantics != authorized.IdentifierSemantics() {
		return database.ObjectStatisticsResult{}, metadataResourceMismatchError()
	}

	boundedContext := mysql.WithMaxReadPacketSize(ctx, absoluteResultPacketSize())
	identity, rawBytes, err := readInnoDBBaseTableIdentity(boundedContext, conn, authorized, info.lowerCaseTableNames)
	if err != nil {
		return database.ObjectStatisticsResult{}, err
	}
	table, rawBytes, err := readTableStatistics(
		boundedContext, conn, authorized, identity, info.lowerCaseTableNames, rawBytes,
	)
	if err != nil {
		return database.ObjectStatisticsResult{}, err
	}
	resultBytes, err := addTableStatisticsSize(envelopeBaseBytes, table, authorized.Limits().MaxResultBytes)
	if err != nil {
		return database.ObjectStatisticsResult{}, err
	}
	partitioning, resultBytes, partitionCount, subpartitionCount, err := readPartitionStatistics(
		boundedContext, conn, authorized, identity, info.lowerCaseTableNames,
		rawBytes, resultBytes, authorized.Limits().MaxResultBytes,
	)
	if err != nil {
		return database.ObjectStatisticsResult{}, err
	}
	observedAt := time.Now().UTC().Format(time.RFC3339Nano)
	// envelopeBaseBytes reserves the shortest canonical UTC timestamp.
	resultBytes, ok := addEncodedSize(
		resultBytes, len(observedAt)-len("0000-00-00T00:00:00Z"), authorized.Limits().MaxResultBytes,
	)
	if !ok {
		return database.ObjectStatisticsResult{}, &database.Error{Kind: database.ErrorResultTooLarge}
	}
	if err := clearDeadline(); err != nil {
		discardSQLConnection(conn)
		return database.ObjectStatisticsResult{}, classifyExecutionError(ctx, err)
	}
	clearDeadline = nil
	return database.ObjectStatisticsResult{
		ObservedAt: observedAt, Engine: "InnoDB", Table: table, Partitioning: partitioning,
		ResultBytes: resultBytes, PartitionCount: partitionCount, SubpartitionCount: subpartitionCount,
	}, nil
}

func readInnoDBBaseTableIdentity(
	ctx context.Context, conn *sql.Conn, authorized policy.AuthorizedObjectStatistics, lowerCaseTableNames int,
) (tableIdentity, int, error) {
	caseInsensitive := lowerCaseTableNames != 0
	statement := `SELECT table_schema, table_name, table_type, engine
FROM information_schema.tables
WHERE ` + metadataIdentifierComparison("table_schema", "?", caseInsensitive) + `
  AND ` + metadataIdentifierComparison("table_name", "?", caseInsensitive) + `
LIMIT 2`
	rows, err := conn.QueryContext(ctx, statement, authorized.Schema(), authorized.Object())
	if err != nil {
		return tableIdentity{}, 0, classifyQueryError(ctx, err)
	}
	defer func() { _ = drainAndCloseRows(rows) }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return tableIdentity{}, 0, classifyExecutionError(ctx, err)
		}
		return tableIdentity{}, 0, statisticsNotFoundError()
	}
	// []byte makes database/sql copy each value. Unlike sql.RawBytes, these
	// values remain valid while we advance once more to detect an ambiguous
	// second metadata row and while Rows.Close finalizes the result.
	var actualSchema, actualName, tableType, engine []byte
	if err := rows.Scan(&actualSchema, &actualName, &tableType, &engine); err != nil {
		return tableIdentity{}, 0, classifyExecutionError(ctx, err)
	}
	if rows.Next() {
		return tableIdentity{}, 0, metadataResourceMismatchError()
	}
	if err := rows.Err(); err != nil {
		return tableIdentity{}, 0, classifyExecutionError(ctx, err)
	}
	if err := rows.Close(); err != nil {
		return tableIdentity{}, 0, classifyExecutionError(ctx, err)
	}
	if !tokenIdentifierMatches(string(actualSchema), authorized.Schema(), caseInsensitive) ||
		!tokenIdentifierMatches(string(actualName), authorized.Object(), caseInsensitive) {
		return tableIdentity{}, 0, metadataResourceMismatchError()
	}
	if string(tableType) == "VIEW" {
		return tableIdentity{}, 0, &database.Error{Kind: database.ErrorInvalid, Err: errors.New("view statistics are unsupported")}
	}
	if string(tableType) != "BASE TABLE" || !strings.EqualFold(string(engine), "InnoDB") {
		return tableIdentity{}, 0, statisticsNotFoundError()
	}
	rawTotal, ok := boundedRawTotal(0, actualSchema, actualName, tableType, engine)
	if !ok {
		return tableIdentity{}, 0, &database.Error{Kind: database.ErrorResultTooLarge}
	}
	return tableIdentity{schema: string(actualSchema), name: string(actualName), engine: "InnoDB"}, rawTotal, nil
}

func readTableStatistics(
	ctx context.Context, conn *sql.Conn, authorized policy.AuthorizedObjectStatistics,
	identity tableIdentity, lowerCaseTableNames, rawTotal int,
) (database.TableStatistics, int, error) {
	caseInsensitive := lowerCaseTableNames != 0
	statement := `SELECT table_schema, table_name, table_type, engine,
       table_rows, data_length, index_length, auto_increment
FROM information_schema.tables
WHERE ` + metadataIdentifierComparison("table_schema", "?", caseInsensitive) + `
  AND ` + metadataIdentifierComparison("table_name", "?", caseInsensitive) + `
LIMIT 2`
	rows, err := conn.QueryContext(ctx, statement, authorized.Schema(), authorized.Object())
	if err != nil {
		return database.TableStatistics{}, 0, classifyQueryError(ctx, err)
	}
	defer func() { _ = drainAndCloseRows(rows) }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return database.TableStatistics{}, 0, classifyExecutionError(ctx, err)
		}
		return database.TableStatistics{}, 0, statisticsNotFoundError()
	}
	var actualSchema, actualName, tableType, engine []byte
	var rowEstimate, dataBytes, indexBytes, autoIncrement []byte
	if err := rows.Scan(
		&actualSchema, &actualName, &tableType, &engine,
		&rowEstimate, &dataBytes, &indexBytes, &autoIncrement,
	); err != nil {
		return database.TableStatistics{}, 0, classifyExecutionError(ctx, err)
	}
	if rows.Next() {
		return database.TableStatistics{}, 0, metadataResourceMismatchError()
	}
	if err := rows.Err(); err != nil {
		return database.TableStatistics{}, 0, classifyExecutionError(ctx, err)
	}
	if err := rows.Close(); err != nil {
		return database.TableStatistics{}, 0, classifyExecutionError(ctx, err)
	}
	if !tokenIdentifierMatches(string(actualSchema), identity.schema, caseInsensitive) ||
		!tokenIdentifierMatches(string(actualName), identity.name, caseInsensitive) ||
		string(tableType) != "BASE TABLE" || !strings.EqualFold(string(engine), "InnoDB") {
		return database.TableStatistics{}, 0, statisticsNotFoundError()
	}
	rawTotal, ok := boundedRawTotal(rawTotal, actualSchema, actualName, tableType, engine, rowEstimate, dataBytes, indexBytes, autoIncrement)
	if !ok {
		return database.TableStatistics{}, 0, &database.Error{Kind: database.ErrorResultTooLarge}
	}
	estimatedRows, err := parseUnsignedMetric(rowEstimate, true)
	if err != nil {
		return database.TableStatistics{}, 0, err
	}
	dataMetric, err := parseUnsignedMetric(dataBytes, true)
	if err != nil {
		return database.TableStatistics{}, 0, err
	}
	indexMetric, err := parseUnsignedMetric(indexBytes, true)
	if err != nil {
		return database.TableStatistics{}, 0, err
	}
	autoMetric, err := parseUnsignedMetric(autoIncrement, false)
	if err != nil {
		return database.TableStatistics{}, 0, err
	}
	return database.TableStatistics{
		EstimatedRows: estimatedRows, DataBytes: dataMetric,
		IndexBytes: indexMetric, AutoIncrement: autoMetric,
	}, rawTotal, nil
}

func readPartitionStatistics(
	ctx context.Context, conn *sql.Conn, authorized policy.AuthorizedObjectStatistics,
	identity tableIdentity, lowerCaseTableNames, rawTotal, resultBytes, maxResultBytes int,
) (database.PartitioningResult, int, int, int, error) {
	caseInsensitive := lowerCaseTableNames != 0
	statement := `SELECT table_schema, table_name,
       partition_name, partition_ordinal_position, partition_method,
       subpartition_name, subpartition_ordinal_position, subpartition_method,
       table_rows, data_length, index_length
FROM information_schema.partitions
WHERE ` + metadataIdentifierComparison("table_schema", "?", caseInsensitive) + `
  AND ` + metadataIdentifierComparison("table_name", "?", caseInsensitive) + `
ORDER BY partition_ordinal_position, subpartition_ordinal_position`
	rows, err := conn.QueryContext(ctx, statement, authorized.Schema(), authorized.Object())
	if err != nil {
		return database.PartitioningResult{}, 0, 0, 0, classifyQueryError(ctx, err)
	}
	defer func() { _ = drainAndCloseRows(rows) }()
	partitioning := database.PartitioningResult{}
	const nonePartitioningBytes = len(`{"kind":"none"}`)
	if resultBytes < nonePartitioningBytes {
		return database.PartitioningResult{}, 0, 0, 0, invalidStatisticsMetadata()
	}
	envelopeWithoutPartitioning := resultBytes - nonePartitioningBytes
	partitioningBytes := nonePartitioningBytes
	partitionNames := make(map[string]struct{})
	subpartitionNames := make(map[string]struct{})
	leafCount := 0
	for rows.Next() {
		var actualSchema, actualName sql.RawBytes
		var row partitionRow
		if err := rows.Scan(
			&actualSchema, &actualName,
			&row.partitionName, &row.partitionOrdinal, &row.partitionMethod,
			&row.subpartitionName, &row.subpartitionOrdinal, &row.subpartitionMethod,
			&row.estimatedRows, &row.dataBytes, &row.indexBytes,
		); err != nil {
			return database.PartitioningResult{}, 0, 0, 0, classifyExecutionError(ctx, err)
		}
		var ok bool
		rawTotal, ok = boundedRawTotal(
			rawTotal, actualSchema, actualName,
			row.partitionName, row.partitionOrdinal, row.partitionMethod,
			row.subpartitionName, row.subpartitionOrdinal, row.subpartitionMethod,
			row.estimatedRows, row.dataBytes, row.indexBytes,
		)
		if !ok {
			return database.PartitioningResult{}, 0, 0, 0, &database.Error{Kind: database.ErrorResultTooLarge}
		}
		if !tokenIdentifierMatches(string(actualSchema), identity.schema, caseInsensitive) ||
			!tokenIdentifierMatches(string(actualName), identity.name, caseInsensitive) {
			return database.PartitioningResult{}, 0, 0, 0, metadataResourceMismatchError()
		}
		leafCount++
		if leafCount > maxPhysicalPartitionLeaves {
			return database.PartitioningResult{}, 0, 0, 0, &database.Error{Kind: database.ErrorResultTooLarge}
		}
		if leafCount == 1 {
			switch {
			case row.partitionName == nil:
				partitioning.Kind = "none"
			case row.subpartitionName == nil:
				partitioning.Kind = "partitioned"
			default:
				partitioning.Kind = "subpartitioned"
			}
		}
		switch partitioning.Kind {
		case "none":
			if leafCount != 1 || row.partitionName != nil || row.partitionOrdinal != nil || row.partitionMethod != nil ||
				row.subpartitionName != nil || row.subpartitionOrdinal != nil || row.subpartitionMethod != nil {
				return database.PartitioningResult{}, 0, 0, 0, invalidStatisticsMetadata()
			}
		case "partitioned":
			if row.partitionName == nil || row.partitionOrdinal == nil || row.partitionMethod == nil ||
				row.subpartitionName != nil || row.subpartitionOrdinal != nil || row.subpartitionMethod != nil {
				return database.PartitioningResult{}, 0, 0, 0, invalidStatisticsMetadata()
			}
			entry, method, err := makePartitionEntry(row)
			if err != nil {
				return database.PartitioningResult{}, 0, 0, 0, err
			}
			partitionNameKey, uniquePartitionName := availableMetadataName(partitionNames, entry.Name)
			if !validTopPartitionMethod(method) ||
				(partitioning.Method != "" && partitioning.Method != method) ||
				entry.Ordinal != len(partitioning.Partitions)+1 || !uniquePartitionName {
				return database.PartitioningResult{}, 0, 0, 0, invalidStatisticsMetadata()
			}
			partitioning.Method = method
			if len(partitioning.Partitions) == 0 {
				partitioningBytes, ok = encodedPartitioningSize(partitioning, maxResultBytes-envelopeWithoutPartitioning)
				if !ok {
					return database.PartitioningResult{}, 0, 0, 0, &database.Error{Kind: database.ErrorResultTooLarge}
				}
			}
			entryBytes, ok := encodedPartitionEntrySize(entry, maxResultBytes-envelopeWithoutPartitioning-partitioningBytes)
			if !ok {
				return database.PartitioningResult{}, 0, 0, 0, &database.Error{Kind: database.ErrorResultTooLarge}
			}
			if len(partitioning.Partitions) != 0 {
				entryBytes++
			}
			partitioningBytes, ok = addEncodedSize(partitioningBytes, entryBytes, maxResultBytes-envelopeWithoutPartitioning)
			if !ok {
				return database.PartitioningResult{}, 0, 0, 0, &database.Error{Kind: database.ErrorResultTooLarge}
			}
			resultBytes = envelopeWithoutPartitioning + partitioningBytes
			partitionNames[partitionNameKey] = struct{}{}
			partitioning.Partitions = append(partitioning.Partitions, entry)
		case "subpartitioned":
			if row.partitionName == nil || row.partitionOrdinal == nil || row.partitionMethod == nil ||
				row.subpartitionName == nil || row.subpartitionOrdinal == nil || row.subpartitionMethod == nil {
				return database.PartitioningResult{}, 0, 0, 0, invalidStatisticsMetadata()
			}
			partitionName, err := validatedMetadataName(row.partitionName)
			if err != nil {
				return database.PartitioningResult{}, 0, 0, 0, err
			}
			partitionOrdinal, err := parseOrdinal(row.partitionOrdinal)
			if err != nil {
				return database.PartitioningResult{}, 0, 0, 0, err
			}
			method, ok := mapPartitionMethod(row.partitionMethod)
			if !ok || !validSubpartitionParentMethod(method) {
				return database.PartitioningResult{}, 0, 0, 0, invalidStatisticsMetadata()
			}
			subMethod, ok := mapPartitionMethod(row.subpartitionMethod)
			if !ok || !validSubpartitionMethod(subMethod) {
				return database.PartitioningResult{}, 0, 0, 0, invalidStatisticsMetadata()
			}
			if (partitioning.Method != "" && partitioning.Method != method) ||
				(partitioning.SubpartitionMethod != "" && partitioning.SubpartitionMethod != subMethod) {
				return database.PartitioningResult{}, 0, 0, 0, invalidStatisticsMetadata()
			}
			partitioning.Method, partitioning.SubpartitionMethod = method, subMethod
			newGroup := len(partitioning.PartitionGroups) == 0 ||
				partitioning.PartitionGroups[len(partitioning.PartitionGroups)-1].Ordinal != partitionOrdinal
			partitionNameKey := ""
			if newGroup {
				var uniquePartitionName bool
				partitionNameKey, uniquePartitionName = availableMetadataName(partitionNames, partitionName)
				if partitionOrdinal != len(partitioning.PartitionGroups)+1 || !uniquePartitionName {
					return database.PartitioningResult{}, 0, 0, 0, invalidStatisticsMetadata()
				}
			}
			if !newGroup {
				group := partitioning.PartitionGroups[len(partitioning.PartitionGroups)-1]
				if group.Name != partitionName || group.Ordinal != partitionOrdinal {
					return database.PartitioningResult{}, 0, 0, 0, invalidStatisticsMetadata()
				}
			}
			groupSubpartitionCount := 0
			if !newGroup {
				groupSubpartitionCount = len(partitioning.PartitionGroups[len(partitioning.PartitionGroups)-1].Subpartitions)
			}
			subName, err := validatedMetadataName(row.subpartitionName)
			if err != nil {
				return database.PartitioningResult{}, 0, 0, 0, err
			}
			subpartitionNameKey, uniqueSubpartitionName := availableMetadataName(subpartitionNames, subName)
			if !uniqueSubpartitionName {
				return database.PartitioningResult{}, 0, 0, 0, invalidStatisticsMetadata()
			}
			subOrdinal, err := parseOrdinal(row.subpartitionOrdinal)
			if err != nil || subOrdinal != groupSubpartitionCount+1 {
				return database.PartitioningResult{}, 0, 0, 0, invalidStatisticsMetadata()
			}
			statistics, err := makePartitionStatistics(row)
			if err != nil {
				return database.PartitioningResult{}, 0, 0, 0, err
			}
			entry := database.SubpartitionEntry{
				Name: subName, Ordinal: subOrdinal, Statistics: statistics,
			}
			if len(partitioning.PartitionGroups) == 0 {
				partitioningBytes, ok = encodedPartitioningSize(partitioning, maxResultBytes-envelopeWithoutPartitioning)
				if !ok {
					return database.PartitioningResult{}, 0, 0, 0, &database.Error{Kind: database.ErrorResultTooLarge}
				}
			}
			increment := 0
			if newGroup {
				group := database.PartitionGroup{Name: partitionName, Ordinal: partitionOrdinal, Subpartitions: []database.SubpartitionEntry{}}
				increment, ok = encodedPartitionGroupSize(group, maxResultBytes-envelopeWithoutPartitioning-partitioningBytes)
				if !ok {
					return database.PartitioningResult{}, 0, 0, 0, &database.Error{Kind: database.ErrorResultTooLarge}
				}
				if len(partitioning.PartitionGroups) != 0 {
					increment++
				}
			}
			entryBytes, entryOK := encodedSubpartitionEntrySize(
				entry, maxResultBytes-envelopeWithoutPartitioning-partitioningBytes-increment,
			)
			if !entryOK {
				return database.PartitioningResult{}, 0, 0, 0, &database.Error{Kind: database.ErrorResultTooLarge}
			}
			if groupSubpartitionCount != 0 {
				entryBytes++
			}
			increment += entryBytes
			partitioningBytes, ok = addEncodedSize(partitioningBytes, increment, maxResultBytes-envelopeWithoutPartitioning)
			if !ok {
				return database.PartitioningResult{}, 0, 0, 0, &database.Error{Kind: database.ErrorResultTooLarge}
			}
			resultBytes = envelopeWithoutPartitioning + partitioningBytes
			if newGroup {
				partitionNames[partitionNameKey] = struct{}{}
				partitioning.PartitionGroups = append(partitioning.PartitionGroups, database.PartitionGroup{
					Name: partitionName, Ordinal: partitionOrdinal, Subpartitions: []database.SubpartitionEntry{},
				})
			}
			subpartitionNames[subpartitionNameKey] = struct{}{}
			group := &partitioning.PartitionGroups[len(partitioning.PartitionGroups)-1]
			group.Subpartitions = append(group.Subpartitions, entry)
		default:
			return database.PartitioningResult{}, 0, 0, 0, invalidStatisticsMetadata()
		}
	}
	if err := rows.Err(); err != nil {
		return database.PartitioningResult{}, 0, 0, 0, classifyExecutionError(ctx, err)
	}
	if err := rows.Close(); err != nil {
		return database.PartitioningResult{}, 0, 0, 0, classifyExecutionError(ctx, err)
	}
	if leafCount == 0 || (partitioning.Kind == "none" && leafCount != 1) {
		return database.PartitioningResult{}, 0, 0, 0, invalidStatisticsMetadata()
	}
	if partitioning.Kind == "none" {
		return partitioning, resultBytes, 0, 0, nil
	}
	return partitioning, resultBytes, len(partitioning.Partitions) + len(partitioning.PartitionGroups),
		leafCount - len(partitioning.Partitions), nil
}

func makePartitionEntry(row partitionRow) (database.PartitionEntry, string, error) {
	name, err := validatedMetadataName(row.partitionName)
	if err != nil {
		return database.PartitionEntry{}, "", err
	}
	ordinal, err := parseOrdinal(row.partitionOrdinal)
	if err != nil {
		return database.PartitionEntry{}, "", err
	}
	method, ok := mapPartitionMethod(row.partitionMethod)
	if !ok {
		return database.PartitionEntry{}, "", invalidStatisticsMetadata()
	}
	statistics, err := makePartitionStatistics(row)
	if err != nil {
		return database.PartitionEntry{}, "", err
	}
	return database.PartitionEntry{Name: name, Ordinal: ordinal, Statistics: statistics}, method, nil
}

func makePartitionStatistics(row partitionRow) (database.PartitionStatistics, error) {
	estimatedRows, err := parseUnsignedMetric(row.estimatedRows, true)
	if err != nil {
		return database.PartitionStatistics{}, err
	}
	dataBytes, err := parseUnsignedMetric(row.dataBytes, true)
	if err != nil {
		return database.PartitionStatistics{}, err
	}
	indexBytes, err := parseUnsignedMetric(row.indexBytes, true)
	if err != nil {
		return database.PartitionStatistics{}, err
	}
	return database.PartitionStatistics{EstimatedRows: estimatedRows, DataBytes: dataBytes, IndexBytes: indexBytes}, nil
}

func parseUnsignedMetric(raw []byte, estimated bool) (*database.UnsignedMetric, error) {
	if raw == nil {
		return nil, nil
	}
	if len(raw) == 0 || len(raw) > 20 || (len(raw) > 1 && raw[0] == '0') {
		return nil, invalidStatisticsMetadata()
	}
	for _, character := range raw {
		if character < '0' || character > '9' {
			return nil, invalidStatisticsMetadata()
		}
	}
	if _, err := strconv.ParseUint(string(raw), 10, 64); err != nil {
		return nil, invalidStatisticsMetadata()
	}
	return &database.UnsignedMetric{Value: string(append([]byte(nil), raw...)), Estimated: estimated}, nil
}

func parseOrdinal(raw []byte) (int, error) {
	metric, err := parseUnsignedMetric(raw, false)
	if err != nil || metric == nil {
		return 0, invalidStatisticsMetadata()
	}
	value, err := strconv.ParseUint(metric.Value, 10, 14)
	if err != nil || value == 0 || value > maxPhysicalPartitionLeaves {
		return 0, invalidStatisticsMetadata()
	}
	return int(value), nil
}

func validatedMetadataName(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > 256 || !utf8.Valid(raw) || utf8.RuneCount(raw) > 64 {
		return "", invalidStatisticsMetadata()
	}
	value := string(append([]byte(nil), raw...))
	for len(raw) > 0 {
		r, size := utf8.DecodeRune(raw)
		if unicode.IsControl(r) || isBidiFormattingRune(r) {
			return "", invalidStatisticsMetadata()
		}
		raw = raw[size:]
	}
	return value, nil
}

func isBidiFormattingRune(r rune) bool {
	return r == '\u061c' || r == '\u200e' || r == '\u200f' ||
		(r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069')
}

func availableMetadataName(names map[string]struct{}, name string) (string, bool) {
	key := canonicalMetadataName(name)
	if _, exists := names[key]; exists {
		return "", false
	}
	return key, true
}

func canonicalMetadataName(name string) string {
	var builder strings.Builder
	builder.Grow(len(name))
	for _, value := range name {
		canonical := value
		for folded := unicode.SimpleFold(value); folded != value; folded = unicode.SimpleFold(folded) {
			if folded < canonical {
				canonical = folded
			}
		}
		builder.WriteRune(canonical)
	}
	return builder.String()
}

func mapPartitionMethod(raw []byte) (string, bool) {
	switch string(raw) {
	case "HASH":
		return "hash", true
	case "LINEAR HASH":
		return "linear_hash", true
	case "KEY":
		return "key", true
	case "LINEAR KEY":
		return "linear_key", true
	case "RANGE":
		return "range", true
	case "RANGE COLUMNS":
		return "range_columns", true
	case "LIST":
		return "list", true
	case "LIST COLUMNS":
		return "list_columns", true
	default:
		return "", false
	}
}

func validTopPartitionMethod(method string) bool {
	return method == "hash" || method == "linear_hash" || method == "key" || method == "linear_key" ||
		method == "range" || method == "range_columns" || method == "list" || method == "list_columns"
}

func validSubpartitionParentMethod(method string) bool {
	return method == "range" || method == "range_columns" || method == "list" || method == "list_columns"
}

func validSubpartitionMethod(method string) bool {
	return method == "hash" || method == "linear_hash" || method == "key" || method == "linear_key"
}

func boundedRawTotal(current int, values ...[]byte) (int, bool) {
	for _, value := range values {
		var ok bool
		current, ok = addEncodedSize(current, len(value), domain.MaxSupportedResultBytes)
		if !ok {
			return 0, false
		}
	}
	return current, true
}

func invalidStatisticsMetadata() *database.Error {
	return &database.Error{Kind: database.ErrorUpstream, Err: errors.New("invalid table statistics metadata")}
}

func addTableStatisticsSize(current int, table database.TableStatistics, maximum int) (int, error) {
	for _, metric := range []*database.UnsignedMetric{
		table.EstimatedRows, table.DataBytes, table.IndexBytes, table.AutoIncrement,
	} {
		if metric == nil {
			continue
		}
		metricSize := len(`{"value":,"estimated":}`) + len(strconv.Quote(metric.Value))
		if metric.Estimated {
			metricSize += len("true")
		} else {
			metricSize += len("false")
		}
		var ok bool
		current, ok = addEncodedSize(current, metricSize-len("null"), maximum)
		if !ok {
			return 0, &database.Error{Kind: database.ErrorResultTooLarge}
		}
	}
	return current, nil
}

func encodedPartitioningSize(partitioning database.PartitioningResult, maximum int) (int, bool) {
	size := 0
	var ok bool
	switch partitioning.Kind {
	case "none":
		return addEncodedSize(0, len(`{"kind":"none"}`), maximum)
	case "partitioned":
		size = len(`{"kind":"partitioned","method":,"partitions":[]}`) + len(strconv.Quote(partitioning.Method))
		if size > maximum {
			return 0, false
		}
		for index, entry := range partitioning.Partitions {
			increment, valid := encodedPartitionEntrySize(entry, maximum-size)
			if !valid {
				return 0, false
			}
			if index != 0 {
				increment++
			}
			size, ok = addEncodedSize(size, increment, maximum)
			if !ok {
				return 0, false
			}
		}
		return size, true
	case "subpartitioned":
		size = len(`{"kind":"subpartitioned","method":,"subpartition_method":,"partitions":[]}`) +
			len(strconv.Quote(partitioning.Method)) + len(strconv.Quote(partitioning.SubpartitionMethod))
		if size > maximum {
			return 0, false
		}
		for index, group := range partitioning.PartitionGroups {
			increment, valid := encodedPartitionGroupSize(group, maximum-size)
			if !valid {
				return 0, false
			}
			if index != 0 {
				increment++
			}
			size, ok = addEncodedSize(size, increment, maximum)
			if !ok {
				return 0, false
			}
		}
		return size, true
	default:
		return 0, false
	}
}

func encodedPartitionEntrySize(entry database.PartitionEntry, maximum int) (int, bool) {
	size := len(`{"name":,"ordinal":,"statistics":}`) + len(strconv.Itoa(entry.Ordinal))
	nameBytes, ok := encodedMetadataJSONStringSize(entry.Name, maximum-size)
	if !ok {
		return 0, false
	}
	size += nameBytes
	statisticsBytes, ok := encodedPartitionStatisticsSize(entry.Statistics, maximum-size)
	if !ok {
		return 0, false
	}
	return addEncodedSize(size, statisticsBytes, maximum)
}

func encodedPartitionGroupSize(group database.PartitionGroup, maximum int) (int, bool) {
	size := len(`{"name":,"ordinal":,"subpartitions":[]}`) + len(strconv.Itoa(group.Ordinal))
	nameBytes, ok := encodedMetadataJSONStringSize(group.Name, maximum-size)
	if !ok {
		return 0, false
	}
	size += nameBytes
	for index, entry := range group.Subpartitions {
		increment, valid := encodedSubpartitionEntrySize(entry, maximum-size)
		if !valid {
			return 0, false
		}
		if index != 0 {
			increment++
		}
		size, ok = addEncodedSize(size, increment, maximum)
		if !ok {
			return 0, false
		}
	}
	return size, true
}

func encodedSubpartitionEntrySize(entry database.SubpartitionEntry, maximum int) (int, bool) {
	return encodedPartitionEntrySize(database.PartitionEntry{
		Name: entry.Name, Ordinal: entry.Ordinal, Statistics: entry.Statistics,
	}, maximum)
}

func encodedPartitionStatisticsSize(statistics database.PartitionStatistics, maximum int) (int, bool) {
	size := len(`{"estimated_rows":,"data_bytes":,"index_bytes":}`)
	if size > maximum {
		return 0, false
	}
	for _, metric := range []*database.UnsignedMetric{statistics.EstimatedRows, statistics.DataBytes, statistics.IndexBytes} {
		metricSize := len("null")
		if metric != nil {
			metricSize = len(`{"value":,"estimated":true}`) + len(strconv.Quote(metric.Value))
		}
		var ok bool
		size, ok = addEncodedSize(size, metricSize, maximum)
		if !ok {
			return 0, false
		}
	}
	return size, true
}

func statisticsNotFoundError() *database.Error {
	return &database.Error{Kind: database.ErrorNotFound}
}

package mysql8

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryspec"
)

func TestCompileKeysetBindsFilterCursorAndLimit(t *testing.T) {
	request := queryspec.NormalizedKeysetRequest{
		Query: queryspec.KeysetSpec{
			Source: queryspec.ResourceRef{Schema: "application", Name: "orders"},
			Projection: []queryspec.Selection{
				{Kind: "field", Field: "tenant_id"},
				{Kind: "field", Field: "id"},
			},
			Filter:  &queryspec.Filter{Kind: "predicate", Field: "status", Operator: "eq", Values: []queryspec.TypedValue{{Type: "string", Value: json.RawMessage(`"active"`)}}},
			OrderBy: []queryspec.Sort{{Field: "tenant_id", Direction: "asc"}, {Field: "id", Direction: "desc"}},
			Limit:   10,
		},
		Page: queryspec.KeysetPage{Kind: "after", Cursor: []queryspec.KeysetCursorValue{
			{Type: "integer", Value: "7"}, {Type: "integer", Value: "42"},
		}},
	}
	source := keysetSource{
		columns: map[string]keysetSourceColumn{
			"tenant_id": {name: "tenant_id", dataType: "bigint", nativeType: "bigint unsigned"},
			"id":        {name: "id", dataType: "bigint", nativeType: "bigint"},
			"status":    {name: "status", dataType: "varchar", nativeType: "varchar(20)"},
		},
		keyColumns: []keysetSourceColumn{
			{name: "tenant_id", dataType: "bigint", nativeType: "bigint unsigned"},
			{name: "id", dataType: "bigint", nativeType: "bigint"},
		},
		keyKinds: []string{"integer", "integer"},
	}
	statement, args, err := compileKeyset(request, source, "idx_tenant_id", 1500)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"MAX_EXECUTION_TIME(1500)", "FORCE INDEX (`idx_tenant_id`)",
		"`__quordon_source`.`status` = ?", "`__quordon_source`.`tenant_id` > ?",
		"`__quordon_source`.`tenant_id` = ? AND `__quordon_source`.`id` < ?",
		"ORDER BY `__quordon_source`.`tenant_id` ASC, `__quordon_source`.`id` DESC LIMIT ?",
	} {
		if !strings.Contains(statement, fragment) {
			t.Fatalf("statement %q does not contain %q", statement, fragment)
		}
	}
	wantArgs := []any{"active", uint64(7), uint64(7), int64(42), 11}
	if len(args) != len(wantArgs) {
		t.Fatalf("args=%#v", args)
	}
	for index := range args {
		if args[index] != wantArgs[index] {
			t.Fatalf("arg[%d]=%#v, want %#v", index, args[index], wantArgs[index])
		}
	}
}

func TestValidateKeysetColumnTypeUsesClosedCursorTypes(t *testing.T) {
	valid := []struct {
		column keysetSourceColumn
		kind   string
	}{
		{column: keysetSourceColumn{dataType: "bigint"}, kind: "integer"},
		{column: keysetSourceColumn{dataType: "varchar", characterSet: "utf8mb4", characterMaximumLength: sql.NullInt64{Int64: 3072, Valid: true}}, kind: "string"},
		{column: keysetSourceColumn{dataType: "varbinary", characterOctetLength: sql.NullInt64{Int64: 3072, Valid: true}}, kind: "bytes"},
	}
	for _, fixture := range valid {
		kind, err := validateKeysetColumnType(fixture.column)
		if err != nil || kind != fixture.kind {
			t.Fatalf("column %+v => (%q, %v), want %q", fixture.column, kind, err, fixture.kind)
		}
	}
	for _, column := range []keysetSourceColumn{
		{dataType: "enum", characterSet: "utf8mb4", characterMaximumLength: sql.NullInt64{Int64: 10, Valid: true}},
		{dataType: "varchar", characterSet: "latin1", characterMaximumLength: sql.NullInt64{Int64: 10, Valid: true}},
		{dataType: "varchar", characterSet: "utf8mb4", characterMaximumLength: sql.NullInt64{Int64: 3073, Valid: true}},
		{dataType: "blob", characterOctetLength: sql.NullInt64{Int64: 10, Valid: true}},
	} {
		if _, err := validateKeysetColumnType(column); !database.IsKind(err, database.ErrorInvalid) {
			t.Fatalf("unsupported column %+v error=%v", column, err)
		}
	}
}

func TestKeysetDatetimeBindingRejectsLossBeyondSourcePrecision(t *testing.T) {
	column := keysetSourceColumn{
		dataType: "datetime", datetimePrecision: sql.NullInt64{Int64: 3, Valid: true},
	}
	valid := queryspec.TypedValue{Type: "datetime", Value: json.RawMessage(`"2026-01-02t03:04:05.123z"`)}
	bound, err := bindKeysetFilterValue(valid, column)
	if err != nil || bound != "2026-01-02 03:04:05.123" {
		t.Fatalf("valid datetime => (%#v, %v)", bound, err)
	}
	invalid := queryspec.TypedValue{Type: "datetime", Value: json.RawMessage(`"2026-01-02T03:04:05.1234Z"`)}
	if _, err := bindKeysetFilterValue(invalid, column); !database.IsKind(err, database.ErrorInvalid) {
		t.Fatalf("over-precise datetime error=%v", err)
	}

	withOffset := queryspec.TypedValue{Type: "datetime", Value: json.RawMessage(`"2026-01-02T03:04:05.123+03:00"`)}
	bound, err = bindKeysetFilterValue(withOffset, column)
	if err != nil || bound != "2026-01-02 03:04:05.123" {
		t.Fatalf("DATETIME wall clock => (%#v, %v)", bound, err)
	}
	timestamp := column
	timestamp.dataType = "timestamp"
	bound, err = bindKeysetFilterValue(withOffset, timestamp)
	if err != nil || bound != "2026-01-02 00:04:05.123" {
		t.Fatalf("TIMESTAMP UTC instant => (%#v, %v)", bound, err)
	}
	placeholder, err := keysetFilterPlaceholder(valid, column)
	if err != nil || placeholder != "CAST(? AS DATETIME(3))" {
		t.Fatalf("DATETIME placeholder => (%q, %v)", placeholder, err)
	}
}

func TestKeysetTemporalBindingHonorsMySQLPhysicalRanges(t *testing.T) {
	dateColumn := keysetSourceColumn{dataType: "date"}
	for raw, wantValid := range map[string]bool{
		`"0999-12-31"`: false,
		`"1000-01-01"`: true,
		`"9999-12-31"`: true,
	} {
		bound, err := bindKeysetFilterValue(
			queryspec.TypedValue{Type: "date", Value: json.RawMessage(raw)}, dateColumn,
		)
		if wantValid && (err != nil || bound == nil) {
			t.Fatalf("valid DATE %s => (%#v, %v)", raw, bound, err)
		}
		if !wantValid && !database.IsKind(err, database.ErrorInvalid) {
			t.Fatalf("out-of-range DATE %s error=%v", raw, err)
		}
	}
	placeholder, err := keysetFilterPlaceholder(
		queryspec.TypedValue{Type: "date", Value: json.RawMessage(`"1000-01-01"`)}, dateColumn,
	)
	if err != nil || placeholder != "CAST(? AS DATE)" {
		t.Fatalf("DATE placeholder => (%q, %v)", placeholder, err)
	}

	datetimeColumn := keysetSourceColumn{
		dataType: "datetime", datetimePrecision: sql.NullInt64{Int64: 6, Valid: true},
	}
	for raw, wantValid := range map[string]bool{
		`"0999-12-31T23:59:59Z"`:        false,
		`"1000-01-01T00:00:00+14:00"`:   true,
		`"9999-12-31T23:59:59.499999Z"`: true,
		`"9999-12-31T23:59:59.500000Z"`: false,
	} {
		_, err := bindKeysetFilterValue(
			queryspec.TypedValue{Type: "datetime", Value: json.RawMessage(raw)}, datetimeColumn,
		)
		if wantValid && err != nil {
			t.Fatalf("valid DATETIME %s error=%v", raw, err)
		}
		if !wantValid && !database.IsKind(err, database.ErrorInvalid) {
			t.Fatalf("out-of-range DATETIME %s error=%v", raw, err)
		}
	}

	timestampColumn := datetimeColumn
	timestampColumn.dataType = "timestamp"
	for raw, wantValid := range map[string]bool{
		`"1970-01-01T00:00:00Z"`:        false,
		`"1970-01-01T00:00:01Z"`:        true,
		`"1970-01-01T00:00:01+01:00"`:   false,
		`"2038-01-19T03:14:07.499999Z"`: true,
		`"2038-01-19T03:14:07.500000Z"`: false,
	} {
		_, err := bindKeysetFilterValue(
			queryspec.TypedValue{Type: "datetime", Value: json.RawMessage(raw)}, timestampColumn,
		)
		if wantValid && err != nil {
			t.Fatalf("valid TIMESTAMP %s error=%v", raw, err)
		}
		if !wantValid && !database.IsKind(err, database.ErrorInvalid) {
			t.Fatalf("out-of-range TIMESTAMP %s error=%v", raw, err)
		}
	}
}

func TestCompileKeysetUsesExplicitTemporalOperands(t *testing.T) {
	request := queryspec.NormalizedKeysetRequest{
		Query: queryspec.KeysetSpec{
			Source:     queryspec.ResourceRef{Schema: "application", Name: "events"},
			Projection: []queryspec.Selection{{Kind: "field", Field: "id"}},
			Filter: &queryspec.Filter{
				Kind: "group", Operator: "and", Expressions: []queryspec.Filter{
					{Kind: "predicate", Field: "event_date", Operator: "gte", Values: []queryspec.TypedValue{{Type: "date", Value: json.RawMessage(`"2026-01-01"`)}}},
					{Kind: "predicate", Field: "created_at", Operator: "lt", Values: []queryspec.TypedValue{{Type: "datetime", Value: json.RawMessage(`"2026-02-01T00:00:00Z"`)}}},
				},
			},
			OrderBy: []queryspec.Sort{{Field: "id", Direction: "asc"}}, Limit: 10,
		},
		Page: queryspec.KeysetPage{Kind: "first"},
	}
	source := keysetSource{columns: map[string]keysetSourceColumn{
		"event_date": {dataType: "date"},
		"created_at": {dataType: "timestamp", datetimePrecision: sql.NullInt64{Int64: 6, Valid: true}},
	}}
	statement, args, err := compileKeyset(request, source, "PRIMARY", 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"`__quordon_source`.`event_date` >= CAST(? AS DATE)",
		"`__quordon_source`.`created_at` < CAST(? AS DATETIME(6))",
	} {
		if !strings.Contains(statement, fragment) {
			t.Fatalf("statement %q does not contain %q", statement, fragment)
		}
	}
	if len(args) != 3 || args[0] != "2026-01-01" || args[1] != "2026-02-01 00:00:00" || args[2] != 11 {
		t.Fatalf("temporal args=%#v", args)
	}
}

func TestKeysetDecimalBindingIsExactAndSourceAware(t *testing.T) {
	column := keysetSourceColumn{
		name: "amount", dataType: "decimal", nativeType: "decimal(5,2)",
		numericPrecision: sql.NullInt64{Int64: 5, Valid: true},
		numericScale:     sql.NullInt64{Int64: 2, Valid: true},
	}
	for raw, want := range map[string]string{
		`1.23`: "1.23", `1.2300`: "1.23", `123e-2`: "1.23",
		`100e-2`: "1", `0.0100`: "0.01", `-0e400`: "0",
	} {
		bound, err := bindKeysetFilterValue(
			queryspec.TypedValue{Type: "decimal", Value: json.RawMessage(raw)}, column,
		)
		if err != nil || bound != want {
			t.Fatalf("decimal %s => (%#v, %v), want %q", raw, bound, err, want)
		}
	}
	for _, raw := range []string{`1.234`, `1000`, `1e400`, `0.001`} {
		_, err := bindKeysetFilterValue(
			queryspec.TypedValue{Type: "decimal", Value: json.RawMessage(raw)}, column,
		)
		if !database.IsKind(err, database.ErrorInvalid) {
			t.Fatalf("unrepresentable decimal %s error=%v", raw, err)
		}
	}
	unsigned := column
	unsigned.nativeType = "decimal(5,2) unsigned"
	if _, err := bindKeysetFilterValue(
		queryspec.TypedValue{Type: "decimal", Value: json.RawMessage(`-1.25`)}, unsigned,
	); !database.IsKind(err, database.ErrorInvalid) {
		t.Fatalf("negative unsigned decimal error=%v", err)
	}

	request := queryspec.NormalizedKeysetRequest{
		Query: queryspec.KeysetSpec{
			Source:     queryspec.ResourceRef{Schema: "application", Name: "orders"},
			Projection: []queryspec.Selection{{Kind: "field", Field: "amount"}},
			Filter: &queryspec.Filter{
				Kind: "predicate", Field: "amount", Operator: "gte",
				Values: []queryspec.TypedValue{{Type: "decimal", Value: json.RawMessage(`123e-2`)}},
			},
			OrderBy: []queryspec.Sort{{Field: "id", Direction: "asc"}}, Limit: 10,
		},
		Page: queryspec.KeysetPage{Kind: "first"},
	}
	statement, args, err := compileKeyset(
		request, keysetSource{columns: map[string]keysetSourceColumn{"amount": column}}, "PRIMARY", 1000,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(statement, "`__quordon_source`.`amount` >= CAST(? AS DECIMAL(5,2))") {
		t.Fatalf("decimal predicate is not explicitly typed: %s", statement)
	}
	if len(args) != 2 || args[0] != "1.23" || args[1] != 11 {
		t.Fatalf("decimal args=%#v", args)
	}
}

func TestKeysetDecimalCompatibilityRequiresCompleteMetadata(t *testing.T) {
	complete := keysetSourceColumn{
		dataType: "decimal", nativeType: "decimal(12,2)",
		numericPrecision: sql.NullInt64{Int64: 12, Valid: true},
		numericScale:     sql.NullInt64{Int64: 2, Valid: true},
	}
	if !keysetFilterTypeCompatible("decimal", "eq", complete) {
		t.Fatal("complete DECIMAL metadata was rejected")
	}
	for _, column := range []keysetSourceColumn{
		{dataType: "decimal", numericScale: sql.NullInt64{Int64: 2, Valid: true}},
		{dataType: "decimal", numericPrecision: sql.NullInt64{Int64: 12, Valid: true}},
		{dataType: "decimal", numericPrecision: sql.NullInt64{Int64: 66, Valid: true}, numericScale: sql.NullInt64{Int64: 2, Valid: true}},
		{dataType: "decimal", numericPrecision: sql.NullInt64{Int64: 2, Valid: true}, numericScale: sql.NullInt64{Int64: 3, Valid: true}},
	} {
		if keysetFilterTypeCompatible("decimal", "eq", column) {
			t.Fatalf("incomplete DECIMAL metadata was accepted: %+v", column)
		}
	}
}

func TestKeysetResultColumnsRejectZerofillNumericTypesBeforeExecution(t *testing.T) {
	request := queryspec.NormalizedKeysetRequest{Query: queryspec.KeysetSpec{
		Projection: []queryspec.Selection{{Kind: "field", Field: "value"}},
	}}
	for name, column := range map[string]keysetSourceColumn{
		"integer": {
			name: "value", dataType: "int", nativeType: "int(10) unsigned ZEROFILL",
		},
		"decimal": {
			name: "value", dataType: "decimal", nativeType: "decimal(12,2) unsigned zerofill",
			numericPrecision: sql.NullInt64{Int64: 12, Valid: true},
			numericScale:     sql.NullInt64{Int64: 2, Valid: true},
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := keysetResultColumns(
				request, keysetSource{columns: map[string]keysetSourceColumn{"value": column}},
			)
			if !database.IsKind(err, database.ErrorInvalid) {
				t.Fatalf("ZEROFILL projection error=%v", err)
			}
		})
	}

	columns, err := keysetResultColumns(request, keysetSource{columns: map[string]keysetSourceColumn{
		"value": {name: "value", dataType: "int", nativeType: "int unsigned"},
	}})
	if err != nil || len(columns) != 1 || columns[0].Type != "integer" {
		t.Fatalf("ordinary unsigned projection => (%+v, %v)", columns, err)
	}
}

func TestKeysetGeneratedColumnDetectionDoesNotRejectGeneratedDefaults(t *testing.T) {
	for _, extra := range []string{"", "DEFAULT_GENERATED", "DEFAULT_GENERATED on update CURRENT_TIMESTAMP"} {
		if isGeneratedKeysetColumn(extra) {
			t.Fatalf("ordinary physical column extra %q was classified as generated", extra)
		}
	}
	for _, extra := range []string{"VIRTUAL GENERATED", "STORED GENERATED"} {
		if !isGeneratedKeysetColumn(extra) {
			t.Fatalf("generated column extra %q was accepted", extra)
		}
	}
}

func TestKeysetCompileErrorPreservesInvalidClassification(t *testing.T) {
	invalid := &database.Error{Kind: database.ErrorInvalid, Err: context.DeadlineExceeded}
	if err := classifyKeysetCompileError(invalid); !database.IsKind(err, database.ErrorInvalid) {
		t.Fatalf("invalid compile error was reclassified: %v", err)
	}
	if err := classifyKeysetCompileError(context.Canceled); !database.IsKind(err, database.ErrorUpstream) {
		t.Fatalf("unclassified compile error was not contained: %v", err)
	}
}

func TestKeysetFilterTypeCompatibilityRequiresLosslessCharacterSources(t *testing.T) {
	utf8Column := keysetSourceColumn{
		dataType: "varchar", characterSet: "utf8mb4",
		characterMaximumLength: sql.NullInt64{Int64: 64, Valid: true},
	}
	if !keysetFilterTypeCompatible("string", "eq", utf8Column) ||
		!keysetFilterTypeCompatible("uuid", "eq", utf8Column) {
		t.Fatal("lossless UTF-8 character source was rejected")
	}
	latin1Column := utf8Column
	latin1Column.characterSet = "latin1"
	if keysetFilterTypeCompatible("string", "eq", latin1Column) {
		t.Fatal("arbitrary UTF-8 string was accepted for a lossy latin1 source")
	}
	shortUUIDColumn := utf8Column
	shortUUIDColumn.characterMaximumLength.Int64 = 35
	if keysetFilterTypeCompatible("uuid", "eq", shortUUIDColumn) {
		t.Fatal("UUID was accepted for a source that cannot hold its canonical representation")
	}
}

func TestKeysetBytesFilterRejectsBitSource(t *testing.T) {
	for _, dataType := range []string{"binary", "varbinary", "tinyblob", "blob", "mediumblob", "longblob"} {
		if !keysetFilterTypeCompatible("bytes", "eq", keysetSourceColumn{dataType: dataType}) {
			t.Fatalf("bytes-compatible source %q was rejected", dataType)
		}
	}
	if keysetFilterTypeCompatible("bytes", "eq", keysetSourceColumn{dataType: "bit"}) {
		t.Fatal("BIT source was accepted for a bytes predicate")
	}
}

func TestKeysetBooleanFilterRequiresExactTinyintOne(t *testing.T) {
	for _, nativeType := range []string{"tinyint(1)", "TINYINT(1) UNSIGNED"} {
		column := keysetSourceColumn{dataType: "tinyint", nativeType: nativeType}
		if !keysetFilterTypeCompatible("boolean", "eq", column) {
			t.Fatalf("boolean-compatible source %q was rejected", nativeType)
		}
	}
	for _, nativeType := range []string{"tinyint", "tinyint(10)", "tinyint(1) zerofill", "tinyint(11) unsigned"} {
		column := keysetSourceColumn{dataType: "tinyint", nativeType: nativeType}
		if keysetFilterTypeCompatible("boolean", "eq", column) {
			t.Fatalf("non-boolean source %q was accepted", nativeType)
		}
	}
}

func TestKeysetIntegerFilterBindingHonorsSourceSignednessAndWidth(t *testing.T) {
	unsigned := keysetSourceColumn{dataType: "tinyint", nativeType: "tinyint unsigned"}
	bound, err := bindKeysetFilterValue(
		queryspec.TypedValue{Type: "integer", Value: json.RawMessage(`255`)}, unsigned,
	)
	if err != nil || bound != uint64(255) {
		t.Fatalf("unsigned integer => (%#v, %v), want uint64(255)", bound, err)
	}
	for _, raw := range []string{`-1`, `256`} {
		if _, err := bindKeysetFilterValue(
			queryspec.TypedValue{Type: "integer", Value: json.RawMessage(raw)}, unsigned,
		); !database.IsKind(err, database.ErrorInvalid) {
			t.Fatalf("unsigned integer %s error=%v", raw, err)
		}
	}

	signed := keysetSourceColumn{dataType: "tinyint", nativeType: "tinyint"}
	bound, err = bindKeysetFilterValue(
		queryspec.TypedValue{Type: "integer", Value: json.RawMessage(`-128`)}, signed,
	)
	if err != nil || bound != int64(-128) {
		t.Fatalf("signed integer => (%#v, %v), want int64(-128)", bound, err)
	}
	if _, err := bindKeysetFilterValue(
		queryspec.TypedValue{Type: "integer", Value: json.RawMessage(`128`)}, signed,
	); !database.IsKind(err, database.ErrorInvalid) {
		t.Fatalf("out-of-range signed integer error=%v", err)
	}
}

func TestKeysetIndexMetadataDoesNotRequirePost8011Columns(t *testing.T) {
	statement := strings.ToLower(keysetIndexMetadataStatement(false))
	if strings.Contains(statement, "expression") {
		t.Fatalf("keyset metadata depends on MySQL 8.0.13 EXPRESSION: %s", statement)
	}
	for _, required := range []string{"column_name", "sub_part", "collation", "is_visible"} {
		if !strings.Contains(statement, required) {
			t.Fatalf("keyset metadata is missing %q: %s", required, statement)
		}
	}
}

func TestKeysetCellRejectsNonCanonicalDecimals(t *testing.T) {
	for _, value := range []string{"00", "01.25", "-0", "-0.00"} {
		if validKeysetCell([]byte(value), "decimal") {
			t.Fatalf("non-canonical decimal %q passed the adapter boundary", value)
		}
	}
	for _, value := range []string{"0", "0.00", "1.25", "-1.25"} {
		if !validKeysetCell([]byte(value), "decimal") {
			t.Fatalf("canonical decimal %q was rejected", value)
		}
	}
}

func TestKeysetCellRejectsPlusPrefixedTime(t *testing.T) {
	for _, value := range []string{"00:00:00", "100:00:00", "-01:02:03.4", "838:59:59.999999"} {
		if !validKeysetCell([]byte(value), "time") {
			t.Fatalf("canonical TIME %q was rejected", value)
		}
	}
	for _, value := range []string{"+01:00:00", "-+01:00:00", "--01:00:00", "001:00:00"} {
		if validKeysetCell([]byte(value), "time") {
			t.Fatalf("non-canonical TIME %q passed the adapter boundary", value)
		}
	}
}

func TestKeysetCellRejectsTemporalValuesOutsidePhysicalRange(t *testing.T) {
	for _, value := range []string{"0000-01-01", "0999-12-31"} {
		if validKeysetCell([]byte(value), "date") {
			t.Fatalf("out-of-range DATE %q passed the adapter boundary", value)
		}
	}
	for _, value := range []string{"0000-01-01 00:00:00", "0999-12-31 23:59:59"} {
		if validKeysetCell([]byte(value), "datetime") {
			t.Fatalf("out-of-range DATETIME %q passed the adapter boundary", value)
		}
	}
	if validKeysetSourceTemporalCell(
		[]byte("1969-12-31 23:59:59"), keysetSourceColumn{dataType: "timestamp"},
	) {
		t.Fatal("out-of-range TIMESTAMP passed source-aware adapter validation")
	}
	if !validKeysetSourceTemporalCell(
		[]byte("1970-01-01 00:00:01"), keysetSourceColumn{dataType: "timestamp"},
	) {
		t.Fatal("minimum supported TIMESTAMP was rejected")
	}
}

func TestKeysetContinuationRequestBudgetHasNoArbitraryFloor(t *testing.T) {
	request := queryspec.NormalizedKeysetRequest{
		Profile: "reader", Shape: "orders_page",
		Query: queryspec.KeysetSpec{
			Source:     queryspec.ResourceRef{Schema: "app", Name: "orders"},
			Projection: []queryspec.Selection{{Kind: "field", Field: "id"}},
			OrderBy:    []queryspec.Sort{{Field: "id", Direction: "asc"}}, Limit: 10,
		},
		Page: queryspec.KeysetPage{Kind: "first"},
	}
	source := keysetSource{
		keyColumns: []keysetSourceColumn{{dataType: "bigint", nativeType: "bigint unsigned"}},
		keyKinds:   []string{"integer"},
	}
	continuation := queryspec.KeysetRequest{
		Kind: "keyset", Profile: request.Profile, Shape: request.Shape, Query: request.Query,
		Page: queryspec.KeysetPage{Kind: "after", Cursor: []queryspec.KeysetCursorValue{{Type: "integer", Value: "18446744073709551615"}}},
	}
	payload, err := json.Marshal(continuation)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) >= 1024 {
		t.Fatalf("test continuation unexpectedly large: %d", len(payload))
	}
	if !keysetContinuationRequestFits(request, source, len(payload)) {
		t.Fatalf("exact %d-byte integer continuation was rejected", len(payload))
	}
	if keysetContinuationRequestFits(request, source, len(payload)-1) {
		t.Fatal("continuation budget one byte below the canonical maximum was accepted")
	}
}

func TestCollectKeysetRowsReturnsExactBoundedContinuation(t *testing.T) {
	columns := []database.ResultColumn{{Name: "id", Type: "integer", Encoding: "string", Nullable: false}}
	source := keysetSource{
		projectionColumns: []keysetSourceColumn{{name: "id", dataType: "bigint", nativeType: "bigint"}},
		keyKinds:          []string{"integer"}, keyIndexes: []int{0},
		keyColumns: []keysetSourceColumn{{name: "id", dataType: "bigint", nativeType: "bigint"}},
	}
	type page struct {
		HasMore    bool                           `json:"has_more"`
		NextCursor *[]queryspec.KeysetCursorValue `json:"next_cursor,omitempty"`
	}
	type variablePayload struct {
		Columns   []database.ResultColumn `json:"columns"`
		Rows      [][]*string             `json:"rows"`
		RowCount  int                     `json:"row_count"`
		Truncated bool                    `json:"truncated"`
		Page      page                    `json:"page"`
	}
	finalEmpty, _ := json.Marshal(variablePayload{Columns: []database.ResultColumn{}, Rows: [][]*string{}, Page: page{HasMore: false}})
	emptyCursor := []queryspec.KeysetCursorValue{}
	moreEmpty, _ := json.Marshal(variablePayload{Columns: []database.ResultColumn{}, Rows: [][]*string{}, Truncated: true, Page: page{HasMore: true, NextCursor: &emptyCursor}})
	const outside = 500
	finalBase, err := addKeysetColumnsSize(outside+len(finalEmpty), columns, 4096)
	if err != nil {
		t.Fatal(err)
	}
	moreBase, err := addKeysetColumnsSize(outside+len(moreEmpty), columns, 4096)
	if err != nil {
		t.Fatal(err)
	}
	rows := &keysetRowsStub{rows: [][]sql.RawBytes{{sql.RawBytes("1")}, {sql.RawBytes("2")}}}
	result := database.KeysetSelectResult{Columns: columns, Rows: make([][]*string, 0)}
	stoppedEarly, err := collectKeysetRows(
		context.Background(), rows, 1, columns, source, finalBase, moreBase, 4096, &result,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !stoppedEarly || rows.scanCalls != 1 {
		t.Fatalf("early stop=%v, scan calls=%d, want true and one", stoppedEarly, rows.scanCalls)
	}
	if !result.HasMore || result.RowCount != 1 || len(result.NextCursor) != 1 || result.NextCursor[0].Value != "1" {
		t.Fatalf("result=%+v", result)
	}
	nextCursor := result.NextCursor
	actual, _ := json.Marshal(variablePayload{
		Columns: columns, Rows: result.Rows, RowCount: result.RowCount, Truncated: true,
		Page: page{HasMore: true, NextCursor: &nextCursor},
	})
	if result.ResultBytes != outside+len(actual) {
		t.Fatalf("result bytes=%d, want %d", result.ResultBytes, outside+len(actual))
	}
}

func TestKeysetRejectsZeroAuthorizationBeforeDatabaseAccess(t *testing.T) {
	if _, err := New().SelectKeyset(
		context.Background(), nil, policy.AuthorizedKeysetSelect{}, database.KeysetEnvelopeBudget{},
	); !database.IsKind(err, database.ErrorUpstream) {
		t.Fatalf("zero keyset authorization error=%v", err)
	}
}

type keysetRowsStub struct {
	rows      [][]sql.RawBytes
	position  int
	scanCalls int
}

func (r *keysetRowsStub) Next() bool { return r.position < len(r.rows) }

func (r *keysetRowsStub) Scan(destinations ...any) error {
	row := r.rows[r.position]
	r.position++
	r.scanCalls++
	for index := range destinations {
		*(destinations[index].(*sql.RawBytes)) = row[index]
	}
	return nil
}

func (*keysetRowsStub) Err() error   { return nil }
func (*keysetRowsStub) Close() error { return nil }

package mysql8

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryspec"
)

func numericAdapterSpec() queryspec.NormalizedAggregateSpec {
	return queryspec.NormalizedAggregateSpec{Mode: "grouped", Source: queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.AggregateOutput{{Kind: "numeric_bucket", Field: "amount", Alias: "range"}, {Kind: "numeric_bucket", Field: "id", Alias: "id_range"}, {Kind: "dimension", Field: "status"}, {Kind: "time_bucket", Field: "created_at", Alias: "day", Unit: "day", Timezone: "UTC"}, {Kind: "measure", Function: "sum", Field: "amount", Alias: "total"}},
		Filter:     &queryspec.Filter{Kind: "predicate", Field: "status", Operator: "eq", Values: []queryspec.TypedValue{{Type: "string", Value: json.RawMessage(`"active"`)}}},
		OrderBy:    []queryspec.AggregateSort{{Kind: "numeric_bucket", Alias: "range", Direction: "asc"}, {Kind: "numeric_bucket", Alias: "id_range", Direction: "desc"}}, Limit: 10}
}

func TestNumericBucketCompilationIsExactAndComposes(t *testing.T) {
	spec := numericAdapterSpec()
	boundaries := map[string][]string{"range": {"-1.5", "0", "9007199254740993.01"}, "id_range": {"18446744073709551616"}}
	statement, args, err := compileAggregate(spec, 1000, boundaries)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(statement, "CAST(? AS DECIMAL(18,2))") != 3 || strings.Count(statement, "CAST(? AS DECIMAL(20,0))") != 3 || strings.Contains(statement, "ORDER BY `range`") || !strings.Contains(statement, "IS NULL THEN NULL") || strings.Count(statement, "MIN(CASE WHEN ") != 4 {
		t.Fatalf("SQL=%s", statement)
	}
	want := []any{"-1.5", "0", "9007199254740993.01", "18446744073709551616", "active", "-1.5", "0", "9007199254740993.01", "18446744073709551616", "-1.5", "0", "9007199254740993.01", "18446744073709551616", 11}
	if !slices.Equal(args, want) || strings.Count(statement, "?") != len(args) {
		t.Fatalf("binds=%v", args)
	}
	for _, boundary := range []string{strings.Repeat("9", 66), "0." + strings.Repeat("0", 30) + "1", "NaN", "1e2", "0.00"} {
		if _, err := numericBoundaryCast(boundary); err == nil {
			t.Fatalf("accepted boundary %q", boundary)
		}
	}
	for _, boundary := range []string{"-9223372036854775809", "18446744073709551616", strings.Repeat("9", 65), "0." + strings.Repeat("0", 29) + "1"} {
		if _, err := numericBoundaryCast(boundary); err != nil {
			t.Fatalf("rejected boundary %q: %v", boundary, err)
		}
	}
}

func TestNumericBucketSourceAndResultBoundary(t *testing.T) {
	spec := queryspec.NormalizedAggregateSpec{Mode: "grouped", Projection: []queryspec.AggregateOutput{{Kind: "numeric_bucket", Field: "value", Alias: "bucket"}}, Limit: 1}
	boundaries := map[string][]string{"bucket": {"-1.5", "0", "9007199254740993"}}
	for _, physical := range []string{"tinyint", "smallint", "mediumint", "int", "bigint", "decimal", "float", "double", "varchar", "bit"} {
		source := map[string]aggregateSourceColumn{"value": {dataType: physical, nullable: true}}
		err := validateNumericBucketSource(spec, source, boundaries)
		good := numericBucketSourceType(physical)
		if (err == nil) != good {
			t.Fatalf("source %s: %v", physical, err)
		}
		columns, err := aggregateResultColumns(spec, source)
		if good && (err != nil || columns[0].Type != "integer" || columns[0].Encoding != "string" || !columns[0].Nullable) {
			t.Fatalf("columns=%v error=%v", columns, err)
		}
	}
	columns := []database.ResultColumn{{Name: "bucket", Type: "integer", Encoding: "string", Nullable: true}}
	for _, value := range []string{"0", "1", "2", "3", "-1", "4", "01", "1.0", "1e0", "+1", "", "99"} {
		err := validateNumericBucketRow([]sql.RawBytes{[]byte(value)}, spec, columns, boundaries)
		valid := value == "0" || value == "1" || value == "2" || value == "3"
		if (err == nil) != valid {
			t.Fatalf("value %q error=%v", value, err)
		}
	}
	if err := validateNumericBucketRow([]sql.RawBytes{nil}, spec, columns, boundaries); err != nil {
		t.Fatal(err)
	}
	columns[0].Nullable = false
	if err := validateNumericBucketRow([]sql.RawBytes{nil}, spec, columns, boundaries); err == nil {
		t.Fatal("accepted unexpected NULL")
	}
	for _, budget := range []int{21, 100} {
		rows := &selectRowsStub{remaining: 3, value: sql.RawBytes("1")}
		result := database.AggregateResult{Mode: "grouped", Rows: [][]*string{}, ResultBytes: 20}
		if err := collectAggregateRowsWithSpec(context.Background(), rows, spec, columns, budget, &result, boundaries); err != nil {
			t.Fatal(err)
		}
		if !result.Truncated || rows.scanCalls != 3 {
			t.Fatalf("result=%+v scan=%d", result, rows.scanCalls)
		}
	}
	if _, err := (&Adapter{}).Aggregate(context.Background(), nil, policy.AuthorizedAggregate{}, 0); !database.IsKind(err, database.ErrorUpstream) {
		t.Fatalf("zero token error=%v", err)
	}
}

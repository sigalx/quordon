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

func TestCompileAggregateUsesOptimizerIndexesAndBoundValues(t *testing.T) {
	limit := 10
	spec := queryspec.NormalizedAggregateSpec{
		Mode:   queryspec.AggregateModeGrouped,
		Source: queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.AggregateOutput{
			{Kind: "dimension", Field: "status"},
			{Kind: "measure", Function: "count_distinct", Field: "customer_id", Alias: "customers"},
		},
		Filter: &queryspec.Filter{
			Kind: "predicate", Field: "status", Operator: "eq",
			Values: []queryspec.TypedValue{{Type: "string", Value: json.RawMessage(`"private-value"`)}},
		},
		OrderBy: []queryspec.AggregateSort{{Kind: "measure", Alias: "customers", Direction: "desc"}},
		Limit:   limit,
	}
	statement, args, err := compileAggregate(spec, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(statement, "private-value") {
		t.Fatal("compiled aggregate SQL contains a bound value")
	}
	want := "SELECT /*+ MAX_EXECUTION_TIME(1500) */ `__quordon_source`.`status` AS `status`, COUNT(DISTINCT `__quordon_source`.`customer_id`) AS `customers` FROM `app`.`orders` AS `__quordon_source` WHERE `__quordon_source`.`status` = ? GROUP BY `__quordon_source`.`status` ORDER BY `customers` DESC LIMIT ?"
	if statement != want {
		t.Fatalf("statement = %q, want %q", statement, want)
	}
	if len(args) != 2 || args[0] != "private-value" || args[1] != 11 {
		t.Fatalf("args = %#v", args)
	}
}

func TestCompileAggregateUsesOneServerOwnedTimeBucketExpression(t *testing.T) {
	spec := queryspec.NormalizedAggregateSpec{
		Mode:   queryspec.AggregateModeGrouped,
		Source: queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.AggregateOutput{
			{Kind: "time_bucket", Field: "created_at", Unit: "week", Timezone: "UTC", Alias: "created_week"},
			{Kind: "measure", Function: "count_all", Alias: "total"},
		},
		OrderBy: []queryspec.AggregateSort{{Kind: "time_bucket", Alias: "created_week", Direction: "asc"}},
		Limit:   10,
	}
	statement, args, err := compileAggregate(spec, 1500)
	if err != nil {
		t.Fatal(err)
	}
	expression := "DATE_FORMAT(DATE_SUB(DATE(`__quordon_source`.`created_at`), INTERVAL WEEKDAY(`__quordon_source`.`created_at`) DAY), '%Y-%m-%dT00:00:00Z')"
	if strings.Count(statement, expression) != 4 {
		t.Fatalf("bucket expression count = %d in %q", strings.Count(statement, expression), statement)
	}
	if strings.Contains(statement, "ORDER BY `created_week`") || !strings.Contains(statement, aggregateTimeBucketValidityAlias) {
		t.Fatalf("compiled time-bucket statement violates expression invariants: %q", statement)
	}
	if len(args) != 1 || args[0] != 11 {
		t.Fatalf("args = %#v", args)
	}
}

func TestCompileAggregateKeepsHiddenTimeBucketAliasOutsidePortableNamespace(t *testing.T) {
	spec := queryspec.NormalizedAggregateSpec{
		Mode:   queryspec.AggregateModeGrouped,
		Source: queryspec.ResourceRef{Schema: "app", Name: "orders"},
		Projection: []queryspec.AggregateOutput{
			{
				Kind: "time_bucket", Field: "created_at", Unit: "day", Timezone: "UTC",
				Alias: "__quordon_time_bucket_invalid",
			},
			{Kind: "measure", Function: "count_all", Alias: "total"},
		},
		Limit: 10,
	}
	statement, _, err := compileAggregate(spec, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(statement, "AS `__quordon_time_bucket_invalid`") != 1 ||
		!strings.Contains(statement, "AS `"+aggregateTimeBucketValidityAlias+"`") {
		t.Fatalf("hidden and public aliases are not disjoint: %q", statement)
	}
}

func TestValidateAggregatePlanChecksOptionalIndexAndEveryRead(t *testing.T) {
	valid := json.RawMessage(`{"query_block":{"table":{"table_name":"__quordon_source","access_type":"ref","key":"idx_orders_status","rows_examined_per_scan":42}}}`)
	if err := validateAggregatePlan(valid, "idx_orders_status", 42); err != nil {
		t.Fatalf("valid aggregate plan rejected: %v", err)
	}
	for name, plan := range map[string]json.RawMessage{
		"estimate too large":      json.RawMessage(`{"table":{"table_name":"__quordon_source","access_type":"ref","key":"idx_orders_status","rows_examined_per_scan":43}}`),
		"full scan":               json.RawMessage(`{"table":{"table_name":"__quordon_source","access_type":"ALL","key":"idx_orders_status","rows_examined_per_scan":1}}`),
		"wrong index":             json.RawMessage(`{"table":{"table_name":"__quordon_source","access_type":"ref","key":"other","rows_examined_per_scan":1}}`),
		"string estimate":         json.RawMessage(`{"table":{"table_name":"__quordon_source","access_type":"ref","key":"idx_orders_status","rows_examined_per_scan":"1"}}`),
		"filesort":                json.RawMessage(`{"ordering_operation":{"using_filesort":true,"table":{"table_name":"__quordon_source","access_type":"ref","key":"idx_orders_status","rows_examined_per_scan":1}}}`),
		"second table over bound": json.RawMessage(`{"nested_loop":[{"table":{"table_name":"__quordon_source","access_type":"ref","key":"idx_orders_status","rows_examined_per_scan":1}},{"table":{"table_name":"other","access_type":"eq_ref","key":"PRIMARY","rows_examined_per_scan":43}}]}`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateAggregatePlan(plan, "idx_orders_status", 42); !database.IsKind(err, database.ErrorInvalid) {
				t.Fatalf("error = %v, want invalid", err)
			}
		})
	}
}

func TestValidateAggregatePlanRequiresExplicitTemporaryAndFilesortControls(t *testing.T) {
	plan := json.RawMessage(`{"ordering_operation":{"using_temporary_table":true,"using_filesort":true,"table":{"table_name":"__quordon_source","access_type":"index","key":"idx_created_at","rows_examined_per_scan":2}}}`)
	if err := validateAggregatePlan(plan, "idx_created_at", 10); !database.IsKind(err, database.ErrorInvalid) {
		t.Fatalf("plan without opt-ins error = %v", err)
	}
	if err := validateAggregatePlan(plan, "idx_created_at", 10, true, false); !database.IsKind(err, database.ErrorInvalid) {
		t.Fatalf("plan with partial opt-in error = %v", err)
	}
	if err := validateAggregatePlan(plan, "idx_created_at", 10, true, true); err != nil {
		t.Fatalf("plan with both opt-ins rejected: %v", err)
	}
	malformed := json.RawMessage(`{"ordering_operation":{"using_filesort":"true","table":{"table_name":"__quordon_source","access_type":"index","key":"idx_created_at","rows_examined_per_scan":2}}}`)
	if err := validateAggregatePlan(malformed, "idx_created_at", 10, true, true); !database.IsKind(err, database.ErrorInvalid) {
		t.Fatalf("non-boolean plan flag error = %v", err)
	}
}

func TestValidateAggregatePlanAcceptsOnlyExactEmptyResultPlans(t *testing.T) {
	for name, plan := range map[string]json.RawMessage{
		"impossible predicate": json.RawMessage(`{"query_block":{"select_id":1,"message":"Impossible WHERE"}}`),
		"missing const row":    json.RawMessage(`{"query_block":{"select_id":1,"message":"no matching row in const table"}}`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateAggregatePlan(plan, "PRIMARY", 1); err != nil {
				t.Fatalf("safe empty aggregate plan rejected: %v", err)
			}
		})
	}
	for name, plan := range map[string]json.RawMessage{
		"unknown message": json.RawMessage(`{"query_block":{"select_id":1,"message":"Select tables optimized away"}}`),
		"wrong select id": json.RawMessage(`{"query_block":{"select_id":2,"message":"Impossible WHERE"}}`),
		"extra member":    json.RawMessage(`{"query_block":{"select_id":1,"message":"Impossible WHERE","cost_info":{}}}`),
		"extra root":      json.RawMessage(`{"query_block":{"select_id":1,"message":"Impossible WHERE"},"other":true}`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateAggregatePlan(plan, "PRIMARY", 1); !database.IsKind(err, database.ErrorInvalid) {
				t.Fatalf("error = %v, want invalid", err)
			}
		})
	}
}

func TestCollectAggregateRowsReturnsBoundedGroupedPrefix(t *testing.T) {
	rows := &selectRowsStub{remaining: 1000, value: sql.RawBytes("value")}
	result := database.AggregateResult{
		Mode: queryspec.AggregateModeGrouped, Rows: make([][]*string, 0), ResultBytes: 20,
	}
	err := collectAggregateRows(
		context.Background(), rows, queryspec.AggregateModeGrouped, 1000,
		[]database.ResultColumn{{Encoding: "string"}}, 22, &result,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Truncated || len(result.Rows) != 0 || rows.scanCalls != 1 || rows.nextCalls != 1001 {
		t.Fatalf("result=%+v scanCalls=%d nextCalls=%d", result, rows.scanCalls, rows.nextCalls)
	}
}

func TestCollectAggregateRowsRejectsPartialScalar(t *testing.T) {
	rows := &selectRowsStub{remaining: 1, value: sql.RawBytes("oversized")}
	result := database.AggregateResult{
		Mode: queryspec.AggregateModeScalar, Rows: make([][]*string, 0), ResultBytes: 20,
	}
	err := collectAggregateRows(
		context.Background(), rows, queryspec.AggregateModeScalar, 0,
		[]database.ResultColumn{{Encoding: "string"}}, 21, &result,
	)
	if !database.IsKind(err, database.ErrorResultTooLarge) {
		t.Fatalf("error = %v, want result too large", err)
	}
}

func TestAggregateResultColumnsUseClosedPortableTypes(t *testing.T) {
	spec := queryspec.NormalizedAggregateSpec{
		Mode: queryspec.AggregateModeScalar,
		Projection: []queryspec.AggregateOutput{
			{Kind: "measure", Function: "count_all", Alias: "total"},
			{Kind: "measure", Function: "sum", Field: "amount", Alias: "amount_sum"},
			{Kind: "measure", Function: "max", Field: "created_at", Alias: "latest"},
		},
	}
	columns, err := aggregateResultColumns(spec, map[string]aggregateSourceColumn{
		"amount":     {dataType: "decimal", nullable: false},
		"created_at": {dataType: "datetime", nullable: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if columns[0].Type != "integer" || columns[0].Nullable ||
		columns[1].Type != "decimal" || !columns[1].Nullable ||
		columns[2].Type != "datetime" || !columns[2].Nullable {
		t.Fatalf("columns = %+v", columns)
	}
}

func TestGroupedAggregateResultColumnsDeriveNullabilityFromSource(t *testing.T) {
	spec := queryspec.NormalizedAggregateSpec{
		Mode: queryspec.AggregateModeGrouped,
		Projection: []queryspec.AggregateOutput{
			{Kind: "dimension", Field: "status"},
			{Kind: "measure", Function: "sum", Field: "amount", Alias: "amount_sum"},
			{Kind: "measure", Function: "max", Field: "created_at", Alias: "latest"},
			{Kind: "measure", Function: "min", Field: "optional_score", Alias: "minimum_score"},
		},
	}
	columns, err := aggregateResultColumns(spec, map[string]aggregateSourceColumn{
		"status":         {dataType: "varchar", nullable: false},
		"amount":         {dataType: "decimal", nullable: false},
		"created_at":     {dataType: "datetime", nullable: false},
		"optional_score": {dataType: "integer", nullable: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if columns[0].Nullable || columns[1].Nullable || columns[2].Nullable || !columns[3].Nullable {
		t.Fatalf("grouped aggregate columns have incorrect nullability: %+v", columns)
	}
}

func TestTimeBucketResultColumnsRequireTemporalSource(t *testing.T) {
	spec := queryspec.NormalizedAggregateSpec{
		Mode: queryspec.AggregateModeGrouped,
		Projection: []queryspec.AggregateOutput{
			{Kind: "time_bucket", Field: "created_at", Unit: "day", Timezone: "UTC", Alias: "created_day"},
			{Kind: "measure", Function: "count_all", Alias: "total"},
		},
	}
	columns, err := aggregateResultColumns(spec, map[string]aggregateSourceColumn{
		"created_at": {dataType: "datetime", nullable: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if columns[0] != (database.ResultColumn{Name: "created_day", Type: "datetime", Encoding: "string", Nullable: true}) {
		t.Fatalf("time-bucket column = %+v", columns[0])
	}
	if _, err := aggregateResultColumns(spec, map[string]aggregateSourceColumn{
		"created_at": {dataType: "varchar"},
	}); !database.IsKind(err, database.ErrorInvalid) {
		t.Fatalf("non-temporal source error = %v", err)
	}
}

func TestValidateTimeBucketRowRejectsInvalidPhysicalAndNonCanonicalValues(t *testing.T) {
	for name, row := range map[string][]sql.RawBytes{
		"valid":          {sql.RawBytes("2026-08-10T00:00:00Z"), sql.RawBytes("0")},
		"invalid flag":   {sql.RawBytes("2026-08-10T00:00:00Z"), sql.RawBytes("1")},
		"invalid token":  {sql.RawBytes("0000-00-00T00:00:00Z"), sql.RawBytes("0")},
		"wrong boundary": {sql.RawBytes("2026-08-11T00:00:00Z"), sql.RawBytes("0")},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateTimeBucketRow(row, []string{"week"})
			if name == "valid" && err != nil {
				t.Fatalf("valid row rejected: %v", err)
			}
			if name != "valid" && !database.IsKind(err, database.ErrorUpstream) {
				t.Fatalf("invalid row error = %v", err)
			}
		})
	}
}

func TestCollectAggregateRowsUsesTruncatedFlagByteForLargestPrefix(t *testing.T) {
	columns := []database.ResultColumn{{Encoding: "string"}}

	t.Run("later row exists", func(t *testing.T) {
		rows := &selectRowsStub{remaining: 2, value: sql.RawBytes("x")}
		result := database.AggregateResult{
			Mode: queryspec.AggregateModeGrouped, Rows: make([][]*string, 0), ResultBytes: 20,
		}
		if err := collectAggregateRows(
			context.Background(), rows, queryspec.AggregateModeGrouped, 10, columns, 24, &result,
		); err != nil {
			t.Fatal(err)
		}
		if !result.Truncated || len(result.Rows) != 1 || result.ResultBytes != 24 || rows.scanCalls != 1 {
			t.Fatalf("result=%+v scanCalls=%d", result, rows.scanCalls)
		}
	})

	t.Run("candidate is final row", func(t *testing.T) {
		rows := &selectRowsStub{remaining: 1, value: sql.RawBytes("x")}
		result := database.AggregateResult{
			Mode: queryspec.AggregateModeGrouped, Rows: make([][]*string, 0), ResultBytes: 20,
		}
		if err := collectAggregateRows(
			context.Background(), rows, queryspec.AggregateModeGrouped, 10, columns, 24, &result,
		); err != nil {
			t.Fatal(err)
		}
		if !result.Truncated || len(result.Rows) != 0 || result.ResultBytes != 19 || rows.scanCalls != 1 {
			t.Fatalf("result=%+v scanCalls=%d", result, rows.scanCalls)
		}
	})
}

func TestAggregateByteAccountingMatchesJSONEncoding(t *testing.T) {
	columns := []database.ResultColumn{{
		Name: "status", Type: "string", Encoding: "string", Nullable: false,
	}}
	type variablePayload struct {
		Columns   []database.ResultColumn `json:"columns"`
		Rows      [][]*string             `json:"rows"`
		RowCount  int                     `json:"row_count"`
		Truncated bool                    `json:"truncated"`
	}
	baseline, err := json.Marshal(variablePayload{
		Columns: []database.ResultColumn{}, Rows: [][]*string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	const envelopeBaseBytes = 500
	resultBytes, err := addAggregateColumnsSize(envelopeBaseBytes, columns, 4096)
	if err != nil {
		t.Fatal(err)
	}
	rows := &selectRowsStub{remaining: 1, value: sql.RawBytes("<&\n")}
	result := database.AggregateResult{
		Mode: queryspec.AggregateModeGrouped, Columns: columns,
		Rows: make([][]*string, 0), ResultBytes: resultBytes,
	}
	if err := collectAggregateRows(
		context.Background(), rows, queryspec.AggregateModeGrouped, 10, columns, 4096, &result,
	); err != nil {
		t.Fatal(err)
	}
	result.RowCount = len(result.Rows)
	encoded, err := json.Marshal(variablePayload{
		Columns: result.Columns, Rows: result.Rows,
		RowCount: result.RowCount, Truncated: result.Truncated,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := envelopeBaseBytes + len(encoded) - len(baseline)
	if result.ResultBytes != want {
		t.Fatalf("result bytes = %d, want exact JSON size %d", result.ResultBytes, want)
	}
}

func TestAggregateRejectsZeroAuthorizationBeforeDatabaseAccess(t *testing.T) {
	if _, err := New().Aggregate(context.Background(), nil, policy.AuthorizedAggregate{}, 0); !database.IsKind(err, database.ErrorUpstream) {
		t.Fatalf("zero aggregate authorization error = %v", err)
	}
}

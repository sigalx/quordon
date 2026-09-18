package mysql8

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/queryspec"
)

func TestSourceTextTemporalKeysUseBinaryComparisons(t *testing.T) {
	for _, dataType := range []string{"date", "datetime", "timestamp"} {
		column := keysetSourceColumn{name: "event_date", dataType: dataType, representation: queryspec.RepresentationSourceText, datetimePrecision: sql.NullInt64{Valid: true, Int64: 6}}
		kind, err := validateKeysetColumnType(column)
		if err != nil || kind != "string" {
			t.Fatalf("diagnostic key: %s %v", kind, err)
		}
		request := queryspec.NormalizedKeysetRequest{Profile: "reader", Shape: "events_page", Query: queryspec.KeysetSpec{
			Source:     queryspec.ResourceRef{Schema: "app", Name: "events"},
			Projection: []queryspec.Selection{{Kind: "field", Field: "event_date", Representation: queryspec.RepresentationSourceText}},
			OrderBy:    []queryspec.Sort{{Field: "event_date", Direction: "desc", Representation: queryspec.RepresentationSourceText}}, Limit: 1,
		}, Page: queryspec.KeysetPage{Kind: "after", Cursor: []queryspec.KeysetCursorValue{{Type: "string", Value: "2026-02-31"}}}}
		source := keysetSource{columns: map[string]keysetSourceColumn{"event_date": column}, projectionColumns: []keysetSourceColumn{column}, keyColumns: []keysetSourceColumn{column}, keyKinds: []string{kind}, keyIndexes: []int{0}}
		statement, args, err := compileKeyset(request, source, 1000)
		if err != nil || len(args) != 2 || args[0] != "2026-02-31" || !strings.Contains(statement, "AS BINARY) < CAST(? AS BINARY)") || !strings.Contains(statement, "AS BINARY) DESC") || strings.Contains(statement, "AS DATE") || strings.Contains(statement, "CONVERT(") {
			t.Fatalf("incorrect diagnostic cursor SQL: %s %#v %v", statement, args, err)
		}
		checks, _, err := compileKeysetCharacterValidation(request, source)
		if err != nil || checks != "" || keysetCharacterGuardCount(source) != 0 {
			t.Fatal("temporal text entered character round-trip guards")
		}
		columns, err := keysetResultColumns(request, source)
		if err != nil || columns[0].Type != "string" || columns[0].Encoding != "string" {
			t.Fatal("diagnostic result type lost")
		}
		for _, raw := range []string{"0000-00-00", "2026-00-01", "2026-02-31", "0001-01-01"} {
			if err := validateKeysetRow([]sql.RawBytes{[]byte(raw)}, columns, source); err != nil {
				t.Fatalf("diagnostic value rejected: %v", err)
			}
		}
		if !keysetContinuationRequestFits(request, source, 65536) {
			t.Fatal("temporal string used physical character width for continuation budget")
		}
		request.Query.Filter = &queryspec.Filter{Kind: "predicate", Field: "event_date", Operator: "eq", Representation: queryspec.RepresentationSourceText, Values: []queryspec.TypedValue{{Type: "string", Value: json.RawMessage(`"2026-02-31"`)}}}
		if err := validateKeysetFilterTypes(request.Query.Filter, source.columns); err != nil {
			t.Fatal(err)
		}
		if _, err := bindKeysetCursor(queryspec.KeysetCursorValue{Type: "date", Value: "2026-01-01"}, column); !database.IsKind(err, database.ErrorInvalid) {
			t.Fatal("wrong native diagnostic cursor accepted")
		}
	}
	if err := validateSourceTextType("varchar"); !database.IsKind(err, database.ErrorInvalid) {
		t.Fatal("non-temporal source_text accepted")
	}
}

func TestSourceTextProjectionFilterAndAggregateCompilation(t *testing.T) {
	r := queryspec.RepresentationSourceText
	filter := queryspec.Filter{Kind: "predicate", Field: "event_date", Representation: r, Operator: "in", Values: []queryspec.TypedValue{{Type: "string", Value: json.RawMessage(`"0000-00-00"`)}, {Type: "string", Value: json.RawMessage(`"2026-02-31"`)}}}
	spec := queryspec.NormalizedSpec{Source: queryspec.ResourceRef{Schema: "app", Name: "events"}, Projection: []queryspec.Selection{{Kind: "field", Field: "event_date", Representation: r}}, Filter: &filter, OrderBy: []queryspec.Sort{{Field: "event_date", Direction: "asc", Representation: r}}, Limit: 2}
	statement, args, err := compileSelect(spec, 1000, 3)
	if err != nil || !strings.Contains(statement, "AS CHAR CHARACTER SET utf8mb4) AS `event_date`") || !strings.Contains(statement, "IN (CAST(? AS BINARY), CAST(? AS BINARY))") || len(args) != 4 {
		t.Fatalf("diagnostic SELECT: %s %v", statement, err)
	}
	aggregate := queryspec.NormalizedAggregateSpec{Mode: "grouped", Source: spec.Source, Projection: []queryspec.AggregateOutput{{Kind: "dimension", Field: "event_date", Representation: r}, {Kind: "measure", Function: "count_all", Alias: "total"}}, Filter: &filter, OrderBy: []queryspec.AggregateSort{{Kind: "dimension", Field: "event_date", Direction: "asc", Representation: r}}, Limit: 2}
	statement, _, err = compileAggregate(aggregate, 1000)
	group := sourceTextExpression(qualifyAggregateField("event_date"), true)
	if err != nil || !strings.Contains(statement, group+" AS `event_date`") || !strings.Contains(statement, "GROUP BY "+group) || !strings.Contains(statement, "ORDER BY "+group+" ASC") {
		t.Fatalf("inconsistent diagnostic grouping: %s %v", statement, err)
	}
	columns, err := aggregateResultColumns(aggregate, map[string]aggregateSourceColumn{"event_date": {name: "event_date", dataType: "date", nullable: true}})
	if err != nil || columns[0].Type != "string" || columns[0].Encoding != "string" || !columns[0].Nullable {
		t.Fatal("incorrect grouped diagnostic metadata")
	}
}

func TestSourceTextContinuationIncludesRepresentationInRequestBudget(t *testing.T) {
	r := queryspec.RepresentationSourceText
	request := queryspec.NormalizedKeysetRequest{Profile: "reader", Shape: "events_page", Query: queryspec.KeysetSpec{
		Source:     queryspec.ResourceRef{Schema: "app", Name: "events"},
		Projection: []queryspec.Selection{{Kind: "field", Field: "wall_time", Representation: r}},
		OrderBy:    []queryspec.Sort{{Field: "wall_time", Direction: "asc", Representation: r}}, Limit: 2,
	}, Page: queryspec.KeysetPage{Kind: "first"}}
	source := keysetSource{keyKinds: []string{"string"}, keyColumns: []keysetSourceColumn{{dataType: "datetime", representation: r}}}
	continuation := queryspec.KeysetRequest{Kind: "keyset", Profile: request.Profile, Shape: request.Shape, Query: request.Query,
		Page: queryspec.KeysetPage{Kind: "after", Cursor: []queryspec.KeysetCursorValue{{Type: "string", Value: "9999-12-31 23:59:59.499999"}}}}
	payload, err := json.Marshal(continuation)
	if err != nil {
		t.Fatal(err)
	}
	if !keysetContinuationRequestFits(request, source, len(payload)) {
		t.Fatal("exact diagnostic continuation request budget rejected")
	}
	if keysetContinuationRequestFits(request, source, len(payload)-1) {
		t.Fatal("diagnostic continuation omitted representation from its request budget")
	}
}

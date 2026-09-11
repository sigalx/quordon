package mysql8

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/queryspec"
)

func characterKeysetFixture() (queryspec.NormalizedKeysetRequest, keysetSource) {
	column := keysetSourceColumn{
		name: "label", dataType: "varchar", characterSet: "utf8mb3", collation: "utf8mb3_unicode_ci",
		characterMaximumLength: sql.NullInt64{Int64: 64, Valid: true},
	}
	id := keysetSourceColumn{name: "id", dataType: "int"}
	return queryspec.NormalizedKeysetRequest{
			Query: queryspec.KeysetSpec{
				Source:     queryspec.ResourceRef{Schema: "application", Name: "character_keys"},
				Projection: []queryspec.Selection{{Kind: "field", Field: "label", Alias: "title"}, {Kind: "field", Field: "id"}},
				OrderBy:    []queryspec.Sort{{Field: "label", Direction: "asc"}, {Field: "id", Direction: "desc"}}, Limit: 1,
			},
			Page: queryspec.KeysetPage{Kind: "after", Cursor: []queryspec.KeysetCursorValue{{Type: "string", Value: "Роль"}, {Type: "integer", Value: "2"}}},
		}, keysetSource{
			columns: map[string]keysetSourceColumn{"label": column, "id": id}, projectionColumns: []keysetSourceColumn{column, id},
			keyColumns: []keysetSourceColumn{column, id}, keyKinds: []string{"string", "integer"}, keyIndexes: []int{0, 1},
		}
}

func TestKeysetCharacterCompilationUsesMetadataWithoutCharsetAllowlist(t *testing.T) {
	request, source := characterKeysetFixture()
	// Synthetic names demonstrate that compilation does not contain an encoding
	// registry. The actual server must support the metadata conversion at runtime.
	source.keyColumns[0].characterSet = "future_charset"
	source.keyColumns[0].collation = "future_charset_custom_ci"
	statement, args, err := compileKeyset(request, source, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"`__quordon_source`.`label` AS `title`",
		"CAST(CONVERT(CONVERT(`__quordon_source`.`label` USING utf8mb4) USING future_charset) AS BINARY) = CAST(`__quordon_source`.`label` AS BINARY)",
		"`__quordon_source`.`label` > CONVERT(CAST(? AS CHAR CHARACTER SET utf8mb4) USING future_charset) COLLATE future_charset_custom_ci",
		"ORDER BY `__quordon_source`.`label` ASC, `__quordon_source`.`id` DESC LIMIT ?",
	} {
		if !strings.Contains(statement, fragment) {
			t.Fatalf("missing fragment %q", fragment)
		}
	}
	if strings.Contains(statement, "Роль") || len(args) != 4 || args[0] != "Роль" || args[1] != "Роль" {
		t.Fatalf("cursor was not bound separately: %q %#v", statement, args)
	}
}

func TestKeysetCharacterValidationBatchesNestedFilterAndCursorValues(t *testing.T) {
	request, source := characterKeysetFixture()
	request.Query.Filter = &queryspec.Filter{Kind: "group", Operator: "and", Expressions: []queryspec.Filter{
		{Kind: "predicate", Field: "label", Operator: "in", Values: []queryspec.TypedValue{
			{Type: "string", Value: json.RawMessage(`"café"`)}, {Type: "string", Value: json.RawMessage(`""`)},
		}},
		{Kind: "group", Operator: "or", Expressions: []queryspec.Filter{
			{Kind: "predicate", Field: "label", Operator: "eq", Values: []queryspec.TypedValue{{Type: "uuid", Value: json.RawMessage(`"550e8400-e29b-41d4-a716-446655440000"`)}}},
		}},
	}}
	statement, args, err := compileKeysetCharacterValidation(request, source)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(statement, " FROM ") || strings.Contains(statement, "café") || len(args) != 8 || strings.Count(statement, "?") != 8 {
		t.Fatalf("validation is not a single bound constant query: %q %#v", statement, args)
	}
	if args[0] != "café" || args[2] != "" || args[6] != "Роль" || args[7] != "Роль" {
		t.Fatalf("bind order=%#v", args)
	}
	if strings.Count(statement, "AS BINARY") != 8 {
		t.Fatal("round-trip validation used linguistic instead of byte equality")
	}
	if !strings.Contains(statement, "AS BINARY) = CAST(? AS BINARY)") {
		t.Fatal("validation did not compare with the unmodified original bind bytes")
	}
}

func TestKeysetCharacterMetadataRejectsSQLFragmentsBeforeDatabaseCall(t *testing.T) {
	request, source := characterKeysetFixture()
	for _, name := range []string{"", "utf8mb3); SELECT 1", "utf8mb3`", "utf8mb3--", "utf8mb3\x00", "кириллица", "123", strings.Repeat("a", 65)} {
		for _, member := range []string{"charset", "collation"} {
			column := source.keyColumns[0]
			if member == "charset" {
				column.characterSet = name
			} else {
				column.collation = name
			}
			invalidSource := source
			invalidSource.keyColumns = []keysetSourceColumn{column, source.keyColumns[1]}
			if _, err := keysetCharacterOperand(column); !database.IsKind(err, database.ErrorInvalid) {
				t.Fatalf("unsafe %s name %q accepted", member, name)
			}
			if _, err := validateKeysetColumnType(column); !database.IsKind(err, database.ErrorInvalid) {
				t.Fatalf("unsafe %s metadata accepted", member)
			}
			if err := validateKeysetCharacterBindings(context.Background(), nil, request, invalidSource); !database.IsKind(err, database.ErrorInvalid) {
				t.Fatalf("unsafe %s reached database: %v", member, err)
			}
		}
	}
	request.Page.Cursor[0].Value = string([]byte{0xff})
	if err := validateKeysetCharacterBindings(context.Background(), nil, request, source); !database.IsKind(err, database.ErrorInvalid) {
		t.Fatalf("invalid UTF-8 reached database: %v", err)
	}
}

func TestKeysetCharacterValidationExecutesOnlyOneConstantQuery(t *testing.T) {
	request, source := characterKeysetFixture()
	for _, fixture := range []struct {
		name string
		rows [][]driver.Value
		kind database.ErrorKind
	}{
		{name: "lossless", rows: [][]driver.Value{{int64(1)}}},
		{name: "lossy", rows: [][]driver.Value{{int64(0)}}, kind: database.ErrorInvalid},
		{name: "null", rows: [][]driver.Value{{nil}}, kind: database.ErrorInvalid},
		{name: "invalid marker", rows: [][]driver.Value{{"true"}}, kind: database.ErrorUpstream},
		{name: "missing row", kind: database.ErrorUpstream},
		{name: "extra row", rows: [][]driver.Value{{int64(1)}, {int64(1)}}, kind: database.ErrorUpstream},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			connector := &characterValidationConnector{rows: fixture.rows}
			db := sql.OpenDB(connector)
			defer db.Close()
			conn, err := db.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			err = validateKeysetCharacterBindings(context.Background(), conn, request, source)
			if fixture.kind == "" && err != nil || fixture.kind != "" && !database.IsKind(err, fixture.kind) {
				t.Fatalf("error=%v, want %s", err, fixture.kind)
			}
			if connector.calls != 1 || strings.Contains(connector.statement, " FROM ") || len(connector.args) != 2 {
				t.Fatalf("unexpected query calls=%d, statement=%q", connector.calls, connector.statement)
			}
		})
	}
	request.Page.Kind = "first"
	if err := validateKeysetCharacterBindings(context.Background(), nil, request, source); err != nil {
		t.Fatalf("no textual binds unexpectedly reached database: %v", err)
	}
}

func TestKeysetCharacterRowGuardsAreHiddenAndFailClosedBeforeMaterialization(t *testing.T) {
	_, source := characterKeysetFixture()
	columns := []database.ResultColumn{{Name: "title", Type: "string", Encoding: "string"}, {Name: "id", Type: "integer", Encoding: "string"}}
	for _, marker := range []sql.RawBytes{sql.RawBytes("1"), sql.RawBytes("0"), nil, sql.RawBytes("true")} {
		rows := &keysetRowsStub{rows: [][]sql.RawBytes{{sql.RawBytes("Роль"), sql.RawBytes("2"), marker}, {sql.RawBytes("Другая"), sql.RawBytes("1"), sql.RawBytes("1")}}}
		result := database.KeysetSelectResult{Columns: columns, Rows: make([][]*string, 0)}
		_, err := collectKeysetRows(context.Background(), rows, 1, columns, source, 100, 200, 4096, &result)
		if string(marker) == "1" {
			if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 2 || !result.HasMore || result.NextCursor[0].Value != "Роль" {
				t.Fatalf("hidden marker entered public result: %+v, %v", result, err)
			}
		} else {
			want := database.ErrorInvalid
			if string(marker) == "true" {
				want = database.ErrorUpstream
			}
			if !database.IsKind(err, want) || len(result.Rows) != 0 || result.NextCursor != nil {
				t.Fatalf("unsafe key was materialized: %+v, %v", result, err)
			}
		}
	}
	rows := &keysetRowsStub{rows: [][]sql.RawBytes{{sql.RawBytes("Роль"), sql.RawBytes("2"), sql.RawBytes("1")}, {sql.RawBytes("Другая"), sql.RawBytes("1"), sql.RawBytes("0")}}}
	result := database.KeysetSelectResult{Columns: columns, Rows: make([][]*string, 0)}
	if _, err := collectKeysetRows(context.Background(), rows, 2, columns, source, 100, 200, 4096, &result); !database.IsKind(err, database.ErrorInvalid) {
		t.Fatalf("later lossy key was accepted: %v", err)
	}
}

func TestKeysetCharacterErrorMappingPreservesTimeoutAndUnavailable(t *testing.T) {
	for _, number := range []uint16{1300, 1366, 3854, 3988} {
		if err := classifyKeysetCharacterError(context.Background(), &mysql.MySQLError{Number: number, Message: "sensitive driver detail"}); !database.IsKind(err, database.ErrorInvalid) || strings.Contains(err.Error(), "sensitive") {
			t.Fatalf("conversion error was not sanitized: %v", err)
		}
	}
	if err := classifyKeysetCharacterError(context.Background(), &mysql.MySQLError{Number: 2013}); !database.IsKind(err, database.ErrorUnavailable) {
		t.Fatalf("unavailable was reclassified: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := classifyKeysetCharacterError(ctx, &mysql.MySQLError{Number: 3854}); !database.IsKind(err, database.ErrorTimeout) {
		t.Fatalf("cancelled conversion was reclassified: %v", err)
	}
}

type characterValidationConnector struct {
	rows      [][]driver.Value
	calls     int
	statement string
	args      []driver.NamedValue
}

func (c *characterValidationConnector) Connect(context.Context) (driver.Conn, error) {
	return &characterValidationConn{connector: c}, nil
}
func (c *characterValidationConnector) Driver() driver.Driver { return characterValidationDriver{} }

type characterValidationDriver struct{}

func (characterValidationDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("use connector")
}

type characterValidationConn struct{ connector *characterValidationConnector }

func (*characterValidationConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (*characterValidationConn) Close() error { return nil }
func (*characterValidationConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected transaction")
}
func (c *characterValidationConn) QueryContext(_ context.Context, statement string, args []driver.NamedValue) (driver.Rows, error) {
	c.connector.calls++
	c.connector.statement = statement
	c.connector.args = append([]driver.NamedValue(nil), args...)
	return &characterValidationRows{rows: c.connector.rows}, nil
}

type characterValidationRows struct {
	rows     [][]driver.Value
	position int
}

func (*characterValidationRows) Columns() []string { return []string{"round_trip"} }
func (*characterValidationRows) Close() error      { return nil }
func (r *characterValidationRows) Next(destinations []driver.Value) error {
	if r.position == len(r.rows) {
		return io.EOF
	}
	copy(destinations, r.rows[r.position])
	r.position++
	return nil
}

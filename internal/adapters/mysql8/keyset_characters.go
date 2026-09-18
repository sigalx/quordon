package mysql8

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"unicode/utf8"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/queryspec"
)

// Charset and collation names are server-owned metadata, never API input. The
// SQL grammar cannot bind these names, so validate their lexical form before
// compiling them. MySQL itself supplies the conversion tables; there is no
// application-maintained list of supported encodings.
func validKeysetCharacterMetadata(column keysetSourceColumn) bool {
	return validMySQLCharacterName(column.characterSet) && validMySQLCharacterName(column.collation)
}

func validMySQLCharacterName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	if name[0] != '_' && (name[0] < 'a' || name[0] > 'z') && (name[0] < 'A' || name[0] > 'Z') {
		return false
	}
	for _, character := range name {
		if character != '_' && (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func keysetCharacterOperand(column keysetSourceColumn) (string, error) {
	if !validKeysetCharacterMetadata(column) {
		return "", invalidKeysetCharacterError()
	}
	// Convert only the bound operand, not the indexed source column. Pin both
	// its input encoding and its comparison collation explicitly.
	return "CONVERT(CAST(? AS CHAR CHARACTER SET utf8mb4) USING " + column.characterSet +
		") COLLATE " + column.collation, nil
}

func invalidKeysetCharacterError() *database.Error {
	return &database.Error{Kind: database.ErrorInvalid, Err: errors.New("character value cannot round-trip through the cursor contract")}
}

// Both directions use byte equality, not linguistic equality: case, accents,
// trailing spaces and replacement characters must not conceal conversion loss.
func keysetCharacterRoundTrip(expression, originalExpression, intermediate, original string) string {
	return "CAST(CONVERT(CONVERT(" + expression + " USING " + intermediate + ") USING " +
		original + ") AS BINARY) = CAST(" + originalExpression + " AS BINARY)"
}

func compileKeysetCharacterValidation(request queryspec.NormalizedKeysetRequest, source keysetSource) (string, []any, error) {
	checks := make([]string, 0)
	args := make([]any, 0)
	add := func(value string, column keysetSourceColumn) error {
		if !validKeysetCharacterMetadata(column) || !utf8.ValidString(value) {
			return invalidKeysetCharacterError()
		}
		checks = append(checks, keysetCharacterRoundTrip("CAST(? AS CHAR CHARACTER SET utf8mb4)", "?", column.characterSet, "utf8mb4"))
		args = append(args, value, value)
		return nil
	}
	var visit func(*queryspec.Filter) error
	visit = func(filter *queryspec.Filter) error {
		if filter == nil {
			return nil
		}
		if filter.Kind == "group" {
			for index := range filter.Expressions {
				if err := visit(&filter.Expressions[index]); err != nil {
					return err
				}
			}
			return nil
		}
		if filter.Representation == queryspec.RepresentationSourceText {
			return nil
		}
		for _, value := range filter.Values {
			if value.Type != "string" && value.Type != "uuid" {
				continue
			}
			column, ok := source.columns[strings.ToLower(filter.Field)]
			if !ok {
				return invalidKeysetCharacterError()
			}
			bound, err := value.BindValue()
			if err != nil {
				return invalidKeysetCharacterError()
			}
			text, ok := bound.(string)
			if !ok {
				return invalidKeysetCharacterError()
			}
			if err := add(text, column); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(request.Query.Filter); err != nil {
		return "", nil, err
	}
	if request.Page.Kind == "after" {
		if len(request.Page.Cursor) != len(source.keyColumns) {
			return "", nil, invalidKeysetCharacterError()
		}
		for index, value := range request.Page.Cursor {
			if value.Type == "string" && source.keyColumns[index].representation != queryspec.RepresentationSourceText {
				if err := add(value.Value, source.keyColumns[index]); err != nil {
					return "", nil, err
				}
			}
		}
	}
	if len(checks) == 0 {
		return "", nil, nil
	}
	// A single bounded constant SELECT, without a source-table read, validates
	// every textual bind before EXPLAIN or execution of the authorized query.
	return "SELECT " + strings.Join(checks, ", "), args, nil
}

func validateKeysetCharacterBindings(ctx context.Context, conn *sql.Conn, request queryspec.NormalizedKeysetRequest, source keysetSource) error {
	statement, args, err := compileKeysetCharacterValidation(request, source)
	if err != nil || statement == "" {
		return err
	}
	values := make([]sql.RawBytes, len(args)/2)
	destinations := make([]any, len(values))
	for index := range values {
		destinations[index] = &values[index]
	}
	rows, err := conn.QueryContext(ctx, statement, args...)
	if err != nil {
		return classifyKeysetCharacterError(ctx, err)
	}
	defer func() { _ = drainAndCloseRows(rows) }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return classifyKeysetCharacterError(ctx, err)
		}
		return &database.Error{Kind: database.ErrorUpstream, Err: errors.New("character validation returned no row")}
	}
	if err := rows.Scan(destinations...); err != nil {
		return classifyKeysetCharacterError(ctx, err)
	}
	if err := validateKeysetCharacterGuards(values); err != nil {
		return err
	}
	if rows.Next() {
		return &database.Error{Kind: database.ErrorUpstream, Err: errors.New("character validation returned multiple rows")}
	}
	if err := rows.Err(); err != nil {
		return classifyKeysetCharacterError(ctx, err)
	}
	return nil
}

func keysetCharacterGuardCount(source keysetSource) int {
	count := 0
	for index, kind := range source.keyKinds {
		if kind == "string" && (index >= len(source.keyColumns) || source.keyColumns[index].representation != queryspec.RepresentationSourceText) {
			count++
		}
	}
	return count
}

func validateKeysetCharacterGuards(values []sql.RawBytes) error {
	for _, value := range values {
		if value == nil || string(value) == "0" {
			return invalidKeysetCharacterError()
		}
		if string(value) != "1" {
			return &database.Error{Kind: database.ErrorUpstream, Err: errors.New("invalid character round-trip marker")}
		}
	}
	return nil
}

func classifyKeysetCharacterError(ctx context.Context, err error) *database.Error {
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return classifyExecutionError(ctx, err)
	}
	var native *mysql.MySQLError
	if errors.As(err, &native) {
		switch native.Number {
		case 1300, 1366, 3854, 3988: // Invalid character data / impossible conversion.
			return invalidKeysetCharacterError()
		}
	}
	return classifyQueryError(ctx, err)
}

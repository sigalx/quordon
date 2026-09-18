package mysql8

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/queryspec"
)

func sourceTextExpression(field string, binary bool) string {
	expression := "CAST(" + field + " AS CHAR CHARACTER SET utf8mb4)"
	if binary {
		expression = "CAST(" + expression + " AS BINARY)"
	}
	return expression
}

func representedField(field string, r queryspec.Representation, binary bool) string {
	if r == queryspec.RepresentationSourceText {
		return sourceTextExpression(field, binary)
	}
	return field
}

func validateSourceTextType(dataType string) error {
	if !slices.Contains([]string{"DATE", "DATETIME", "TIMESTAMP"}, strings.ToUpper(strings.TrimSpace(dataType))) {
		return &database.Error{Kind: database.ErrorInvalid, Err: errors.New("source_text requires a temporal source field")}
	}
	return nil
}

func compileSourceTextFilter(filter queryspec.Filter, field string) (string, []any, error) {
	operators := map[string]string{"eq": "=", "ne": "<>", "lt": "<", "lte": "<=", "gt": ">", "gte": ">=", "like": "LIKE", "in": "IN", "not_in": "NOT IN", "is_null": "IS NULL", "is_not_null": "IS NOT NULL"}
	op, ok := operators[filter.Operator]
	if !ok {
		return "", nil, errors.New("unsupported source_text operator")
	}
	field = sourceTextExpression(field, true)
	if filter.Operator == "is_null" || filter.Operator == "is_not_null" {
		return field + " " + op, nil, nil
	}
	args := make([]any, len(filter.Values))
	placeholders := make([]string, len(args))
	for i, value := range filter.Values {
		if value.Type != "string" {
			return "", nil, errors.New("source_text requires string operands")
		}
		bound, err := value.BindValue()
		if err != nil {
			return "", nil, err
		}
		args[i] = bound
		placeholders[i] = "CAST(? AS BINARY)"
	}
	if filter.Operator == "in" || filter.Operator == "not_in" {
		return field + " " + op + " (" + strings.Join(placeholders, ", ") + ")", args, nil
	}
	if len(args) != 1 {
		return "", nil, errors.New("invalid source_text operand arity")
	}
	return field + " " + op + " " + placeholders[0], args, nil
}

func sourceTextFields(spec queryspec.NormalizedSpec) []string {
	var fields []string
	for _, p := range spec.Projection {
		if p.Representation == queryspec.RepresentationSourceText {
			fields = append(fields, p.Field)
		}
	}
	for _, p := range spec.OrderBy {
		if p.Representation == queryspec.RepresentationSourceText {
			fields = append(fields, p.Field)
		}
	}
	var visit func(*queryspec.Filter)
	visit = func(f *queryspec.Filter) {
		if f == nil {
			return
		}
		if f.Representation == queryspec.RepresentationSourceText {
			fields = append(fields, f.Field)
		}
		for i := range f.Expressions {
			visit(&f.Expressions[i])
		}
	}
	visit(spec.Filter)
	slices.Sort(fields)
	return slices.Compact(fields)
}

func aggregateSourceTextFields(spec queryspec.NormalizedAggregateSpec) []string {
	legacy := queryspec.NormalizedSpec{Filter: spec.Filter}
	for _, p := range spec.Projection {
		legacy.Projection = append(legacy.Projection, queryspec.Selection{Field: p.Field, Representation: p.Representation})
	}
	for _, p := range spec.OrderBy {
		legacy.OrderBy = append(legacy.OrderBy, queryspec.Sort{Field: p.Field, Representation: p.Representation})
	}
	return sourceTextFields(legacy)
}

func validateLegacySourceText(ctx context.Context, conn *sql.Conn, spec queryspec.NormalizedSpec, lowerCaseTableNames int) error {
	fields := sourceTextFields(spec)
	if len(fields) == 0 {
		return nil
	}
	aggregate := queryspec.NormalizedAggregateSpec{Source: spec.Source}
	for _, field := range fields {
		aggregate.Projection = append(aggregate.Projection, queryspec.AggregateOutput{Kind: "dimension", Field: field, Representation: queryspec.RepresentationSourceText})
	}
	_, err := validateAggregateSource(ctx, conn, aggregate, lowerCaseTableNames)
	return err
}

// prepareLegacySourceText pins the diagnostic timezone before executing SQL.
// Cleanup always has its own deadline and discards an unrestorable connection.
func prepareLegacySourceText(ctx context.Context, conn *sql.Conn, spec queryspec.NormalizedSpec, lowerCaseTableNames int) (func() error, error) {
	ctx = mysql.WithMaxReadPacketSize(ctx, absoluteResultPacketSize())
	if err := validateLegacySourceText(ctx, conn, spec, lowerCaseTableNames); err != nil {
		return nil, err
	}
	if !queryspec.UsesSourceText(spec) {
		return func() error { return nil }, nil
	}
	original, err := setAggregateUTCSession(ctx, conn)
	if err != nil {
		return nil, err
	}
	return func() error { return restoreAggregateSessionTimezone(ctx, conn, original) }, nil
}

package mysql8

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/queryspec"
)

func numericBucketSourceType(dataType string) bool {
	switch strings.ToUpper(strings.TrimSpace(dataType)) {
	case "TINYINT", "SMALLINT", "MEDIUMINT", "INT", "INTEGER", "BIGINT", "DECIMAL", "NUMERIC":
		return true
	default:
		return false
	}
}

// Each bound has its own exact DECIMAL type, independent of the source range.
// MySQL compares DECIMAL against INTEGER/DECIMAL using exact decimal arithmetic.
func numericBoundaryCast(boundary string) (string, error) {
	canonical, err := queryspec.NormalizeNumericBoundaries([]string{boundary})
	if err != nil || canonical[0] != boundary {
		return "", &database.Error{Kind: database.ErrorInvalid, Err: errors.New("invalid numeric bucket boundary")}
	}
	text := strings.TrimPrefix(boundary, "-")
	integer, fraction, _ := strings.Cut(text, ".")
	scale := len(fraction)
	precision := max(1, len(strings.TrimLeft(integer, "0"))+scale)
	if precision > 65 || scale > 30 {
		return "", &database.Error{Kind: database.ErrorInvalid, Err: errors.New("numeric bucket boundary exceeds adapter precision or scale")}
	}
	return fmt.Sprintf("CAST(? AS DECIMAL(%d,%d))", precision, scale), nil
}

func validateNumericBucketSource(spec queryspec.NormalizedAggregateSpec, source map[string]aggregateSourceColumn, boundaries map[string][]string) error {
	for _, output := range spec.Projection {
		if output.Kind != "numeric_bucket" {
			continue
		}
		column, ok := source[strings.ToLower(output.Field)]
		if !ok || !numericBucketSourceType(column.dataType) {
			return &database.Error{Kind: database.ErrorInvalid, Err: errors.New("numeric bucket requires an exact numeric field")}
		}
		values := boundaries[output.Alias]
		canonical, err := queryspec.NormalizeNumericBoundaries(values)
		if err != nil {
			return &database.Error{Kind: database.ErrorInvalid, Err: errors.New("invalid numeric bucket boundaries")}
		}
		for i, boundary := range canonical {
			if boundary != values[i] {
				return &database.Error{Kind: database.ErrorInvalid}
			}
			if _, err := numericBoundaryCast(boundary); err != nil {
				return err
			}
		}
	}
	return nil
}

func compileNumericBucketExpression(field string, boundaries []string) (string, []any, error) {
	if len(boundaries) < 1 || len(boundaries) > queryspec.NumericBucketMaxBoundaries {
		return "", nil, errors.New("numeric bucket boundaries are missing")
	}
	var builder strings.Builder
	source := qualifyAggregateField(field)
	builder.WriteString("CASE WHEN " + source + " IS NULL THEN NULL")
	args := make([]any, 0, len(boundaries))
	for i, boundary := range boundaries {
		cast, err := numericBoundaryCast(boundary)
		if err != nil {
			return "", nil, err
		}
		fmt.Fprintf(&builder, " WHEN %s < %s THEN %d", source, cast, i)
		args = append(args, boundary)
	}
	fmt.Fprintf(&builder, " ELSE %d END", len(boundaries))
	return builder.String(), args, nil
}

func validateNumericBucketRow(raw []sql.RawBytes, spec queryspec.NormalizedAggregateSpec, columns []database.ResultColumn, boundaries map[string][]string) error {
	for i, output := range spec.Projection {
		if output.Kind != "numeric_bucket" {
			continue
		}
		if i >= len(raw) || i >= len(columns) {
			return &database.Error{Kind: database.ErrorUpstream}
		}
		if raw[i] == nil {
			if columns[i].Nullable {
				continue
			}
			return &database.Error{Kind: database.ErrorUpstream, Err: errors.New("unexpected numeric bucket null")}
		}
		// Bucket indexes have at most two ASCII digits; reject before allocating text.
		if len(raw[i]) < 1 || len(raw[i]) > 2 {
			return &database.Error{Kind: database.ErrorUpstream}
		}
		value, err := strconv.Atoi(string(raw[i]))
		if err != nil || value < 0 || value > len(boundaries[output.Alias]) || strconv.Itoa(value) != string(raw[i]) {
			return &database.Error{Kind: database.ErrorUpstream, Err: errors.New("invalid numeric bucket index")}
		}
	}
	return nil
}

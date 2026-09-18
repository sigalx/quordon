package queryspec

import (
	"errors"
	"math/big"
	"strings"
)

const (
	NumericBucketMaxBoundaries    = 64
	NumericBucketMaxBoundaryBytes = 128
)

// NormalizeNumericBoundaries validates bounded fixed-point decimal policy data.
// It compares exact rationals and returns independent canonical strings.
func NormalizeNumericBoundaries(boundaries []string) ([]string, error) {
	if len(boundaries) < 1 || len(boundaries) > NumericBucketMaxBoundaries {
		return nil, errors.New("numeric bucket requires 1 to 64 boundaries")
	}
	result := make([]string, len(boundaries))
	var previous *big.Rat
	for i, text := range boundaries {
		if len(text) > NumericBucketMaxBoundaryBytes || !decimalPattern.MatchString(text) {
			return nil, errors.New("numeric bucket boundary requires bounded fixed-point decimal text")
		}
		value, ok := new(big.Rat).SetString(text)
		if !ok || previous != nil && previous.Cmp(value) >= 0 {
			return nil, errors.New("numeric bucket boundaries must be strictly increasing")
		}
		previous = value
		if strings.Contains(text, ".") {
			text = strings.TrimRight(strings.TrimRight(text, "0"), ".")
		}
		if value.Sign() == 0 {
			text = "0"
		}
		result[i] = text
	}
	return result, nil
}

func AggregateUsesNumericBucket(spec NormalizedAggregateSpec) bool {
	for _, output := range spec.Projection {
		if output.Kind == "numeric_bucket" {
			return true
		}
	}
	return false
}

// NumericBucketParameters counts each occurrence in projection, grouping, and
// ordering before bind slices or SQL are materialized. Other binds count in base.
func NumericBucketParameters(spec NormalizedAggregateSpec, counts map[string]int, base, maximum int) (int, error) {
	total := base
	if total > maximum {
		return 0, errors.New("aggregate exceeds the effective parameter limit")
	}
	for _, output := range spec.Projection {
		if output.Kind != "numeric_bucket" {
			continue
		}
		count := counts[strings.ToLower(output.Alias)]
		if count < 1 || count > NumericBucketMaxBoundaries {
			return 0, errors.New("numeric bucket boundaries are missing")
		}
		repeats := 2
		for _, order := range spec.OrderBy {
			if order.Kind == "numeric_bucket" && strings.EqualFold(order.Alias, output.Alias) {
				repeats++
			}
		}
		if count > (maximum-total)/repeats {
			return 0, errors.New("aggregate exceeds the effective parameter limit")
		}
		total += count * repeats
	}
	return total, nil
}

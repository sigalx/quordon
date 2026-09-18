package queryspec

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestNumericBoundariesExactCanonicalization(t *testing.T) {
	input := []string{"-123.4500", "-0.000", "0.000000000000000000000000000001", "9007199254740993.000", "18446744073709551616"}
	got, err := NormalizeNumericBoundaries(input)
	want := []string{"-123.45", "0", "0.000000000000000000000000000001", "9007199254740993", "18446744073709551616"}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("boundaries=%v error=%v", got, err)
	}
	got[0] = "changed"
	if input[0] != "-123.4500" {
		t.Fatal("mutable alias")
	}
	for _, invalid := range [][]string{
		nil, {}, {"0", "-0.00"}, {"1.000", "1"}, {"9007199254740993", "9007199254740992"}, {"1e3"}, {"+1"}, {" 1"}, {"1 "}, {"01"}, {".5"}, {"1."}, {"NaN"}, {"∞"}, {strings.Repeat("1", 129)}, make([]string, 65),
	} {
		if _, err := NormalizeNumericBoundaries(invalid); err == nil {
			t.Fatalf("accepted invalid boundaries: %v", invalid)
		}
	}
}

func TestNumericBoundaryPolicyMaximaArePortable(t *testing.T) {
	values := make([]string, NumericBucketMaxBoundaries)
	for i := range values {
		values[i] = strconv.Itoa(i)
	}
	canonical, err := NormalizeNumericBoundaries(values)
	if err != nil || len(canonical) != 64 {
		t.Fatalf("64 boundaries: %v", err)
	}
	if _, err := NormalizeNumericBoundaries([]string{strings.Repeat("9", 128)}); err != nil {
		t.Fatalf("128-byte portable boundary: %v", err)
	}
}

func TestNumericBucketParametersIncludeAllOccurrences(t *testing.T) {
	spec := NormalizedAggregateSpec{
		Projection: []AggregateOutput{{Kind: "numeric_bucket", Alias: "a"}, {Kind: "numeric_bucket", Alias: "b"}},
		OrderBy:    []AggregateSort{{Kind: "numeric_bucket", Alias: "a", Direction: "asc"}},
	}
	counts := map[string]int{"a": 4, "b": 2}
	if total, err := NumericBucketParameters(spec, counts, 3, 19); err != nil || total != 19 {
		t.Fatalf("parameters=%d error=%v", total, err)
	}
	if _, err := NumericBucketParameters(spec, counts, 3, 18); err == nil {
		t.Fatal("accepted parameter overflow")
	}
}

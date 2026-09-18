package mysql8

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/sigalx/quordon/internal/database"
)

func indexMergePlan(key string, lengths ...string) json.RawMessage {
	keyLengths := "4,4"
	if len(lengths) > 0 {
		keyLengths = lengths[0]
	}
	return json.RawMessage(fmt.Sprintf(`{"query_block":{"table":{"table_name":"merge_rows","access_type":"index_merge","possible_keys":["idx_a","idx_b","idx_c","idx_d","PRIMARY"],"key":%q,"key_length":%q,"rows_examined_per_scan":42}}}`, key, keyLengths))
}

func TestValidateAggregatePlanIndexMergeKeys(t *testing.T) {
	for _, fixture := range []struct {
		name, key string
		indexes   []string
	}{
		{"union", "union(idx_a,idx_b)", []string{"idx_a", "idx_b"}},
		{"intersection", "intersect(idx_a,idx_b)", []string{"idx_a", "idx_b"}},
		{"sort union", "sort_union(idx_a,idx_b)", []string{"idx_a", "idx_b"}},
		{"nested", "union(intersect(idx_a,idx_b),idx_c)", []string{"idx_a", "idx_b", "idx_c"}},
		{"primary key", "intersect(idx_a,PRIMARY)", []string{"idx_a", "PRIMARY"}},
		{"comma list", "idx_a,idx_b", []string{"idx_a", "idx_b"}},
		{"single index", "idx_a", []string{"idx_a"}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			plan := indexMergePlan(fixture.key, "4"+strings.Repeat(",4", len(fixture.indexes)-1))
			for _, required := range append(fixture.indexes, "") {
				if err := validateAggregatePlan(plan, strings.ToUpper(required), 42); err != nil {
					t.Fatalf("required index %q rejected: %v", required, err)
				}
			}
			for _, required := range []string{"missing", "idx", "idx_a_suffix", "union", "intersect", "sort_union"} {
				if err := validateAggregatePlan(plan, required, 42); !database.IsKind(err, database.ErrorInvalid) {
					t.Fatalf("unread index %q admitted: %v", required, err)
				}
			}
		})
	}
}

func TestValidateAggregatePlanRejectsMalformedIndexMerge(t *testing.T) {
	for _, key := range []string{
		"", "union()", "intersect()", "sort_union()", "union(,idx_a)",
		"union(idx_a,)", "union(idx_a,,idx_b)", "union(idx_a,idx_b",
		"union(idx_a,idx_b))", "union(idx_a,idx_b)tail", "unknown(idx_a,idx_b)",
		"union(idx_a,unknown(idx_b,idx_c))", "union(idx_a,intersect())",
		"union(idx_a,intersect(idx_b,))", "(idx_a,idx_b)",
		"idx_a,", ",idx_a", "idx_a,,idx_b", "idx_a)",
		"union(idx_a,idx_b),idx_c", "idx_a,union(idx_b,idx_c)",
	} {
		t.Run(key, func(t *testing.T) {
			// Syntax is checked even when no index was required or an earlier
			// leaf already matched. A matching prefix must not admit a bad plan.
			for _, required := range []string{"", "idx_a"} {
				if err := validateAggregatePlan(indexMergePlan(key), required, 42); !database.IsKind(err, database.ErrorInvalid) {
					t.Fatalf("key %q, requirement %q admitted: %v", key, required, err)
				}
			}
		})
	}
	missingKey := json.RawMessage(`{"table":{"table_name":"merge_rows","access_type":"index_merge","rows_examined_per_scan":42}}`)
	if err := validateAggregatePlan(missingKey, "", 42); !database.IsKind(err, database.ErrorInvalid) {
		t.Fatalf("index merge without key admitted: %v", err)
	}
}

func TestValidateAggregatePlanIndexMergePreservesBounds(t *testing.T) {
	plan := indexMergePlan("union(idx_a,idx_b)")
	for name, denied := range map[string]json.RawMessage{
		"estimate":             json.RawMessage(strings.Replace(string(plan), `:42`, `:43`, 1)),
		"temporary":            json.RawMessage(`{"using_temporary_table":true,"child":` + string(plan) + `}`),
		"filesort":             json.RawMessage(`{"using_filesort":true,"child":` + string(plan) + `}`),
		"materialized index":   json.RawMessage(strings.Replace(string(plan), `"table_name":"merge_rows"`, `"table_name":"result","materialized_from_subquery":{"query_block":{"message":"No tables used"}}`, 1)),
		"malformed later read": json.RawMessage(`{"nested_loop":[` + string(plan) + `,` + string(indexMergePlan("union(idx_a,)")) + `]}`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateAggregatePlan(denied, "idx_a", 42); !database.IsKind(err, database.ErrorInvalid) {
				t.Fatalf("invalid index merge admitted: %v", err)
			}
		})
	}
	allowed := json.RawMessage(`{"using_temporary_table":true,"using_filesort":true,"child":` + string(plan) + `}`)
	if err := validateAggregatePlan(allowed, "idx_a", 42, true, true); err != nil {
		t.Fatalf("index merge with permitted work rejected: %v", err)
	}
}

func TestValidateAggregatePlanDeepIndexMerge(t *testing.T) {
	key := strings.Repeat("union(idx_b,", 4096) + "idx_a" + strings.Repeat(")", 4096)
	if err := validateAggregatePlan(indexMergePlan(key, "4"+strings.Repeat(",4", 4096)), "idx_a", 42); err != nil {
		t.Fatalf("deep valid index merge rejected: %v", err)
	}
}

func TestValidateAggregatePlanAmbiguousIndexMergeIdentities(t *testing.T) {
	for _, fixture := range []struct{ key, lengths string }{
		// Two native indexes: the first is named "idx_a,idx_b". MySQL
		// does not escape the comma, but emits just two key lengths.
		{"union(idx_a,idx_b,idx_c)", "4,4"},
		{"intersect(idx_a,idx_b,idx_c)", "4,4"},
		{"sort_union(idx_a,idx_b,idx_c)", "4,4"},
		{"union(intersect(idx_a,idx_b,idx_c),idx_d)", "4,4,4"},
		// A native name can also look like a unary merge expression.
		// A length-count check alone would accept the spurious idx_a.
		{"union(intersect(idx_a),idx_c)", "4,4"},
	} {
		t.Run(fixture.key, func(t *testing.T) {
			for _, required := range []string{"", "idx_a", "idx_b", "idx_c", "idx_a,idx_b"} {
				if err := validateAggregatePlan(indexMergePlan(fixture.key, fixture.lengths), required, 42); !database.IsKind(err, database.ErrorInvalid) {
					t.Fatalf("ambiguous key %q, requirement %q admitted: %v", fixture.key, required, err)
				}
			}
		})
	}
}

func TestValidateAggregatePlanIndexMergeLengths(t *testing.T) {
	for _, lengths := range []string{"", "4", "4,4,4", "0,4", "04,4", "-4,4", "+4,4", "4.0,4", "4e0,4", "4,", ",4", "4,,4", "4, 4", "4,18446744073709551616"} {
		t.Run(lengths, func(t *testing.T) {
			if err := validateAggregatePlan(indexMergePlan("union(idx_a,idx_b)", lengths), "idx_a", 42); !database.IsKind(err, database.ErrorInvalid) {
				t.Fatalf("malformed or mismatched lengths %q admitted: %v", lengths, err)
			}
		})
	}
	for _, replacement := range []string{"", `,"key_length":null`, `,"key_length":4`, `,"key_length":true`, `,"key_length":[]`} {
		plan := strings.Replace(string(indexMergePlan("union(idx_a,idx_b)")), `,"key_length":"4,4"`, replacement, 1)
		if err := validateAggregatePlan(json.RawMessage(plan), "", 42); !database.IsKind(err, database.ErrorInvalid) {
			t.Fatalf("missing or non-string key_length admitted: %v", err)
		}
	}
}

func TestValidateAggregatePlanIndexMergeNativeIdentities(t *testing.T) {
	for _, fixture := range []struct{ key, lengths, possible string }{
		{"union(idx_a,idx_b,idx_c)", "4,4", `["idx_a,idx_b","idx_c"]`},
		// Parentheses spread across two native names can preserve the leaf
		// count and produce valid binary syntax. Only native identities expose
		// that idx_a and idx_b are fragments rather than participating indexes.
		{"union(union(idx_a,idx_b),idx_c)", "4,4,4", `["union(idx_a","idx_b)","idx_c"]`},
		{"union(idx_a,idx_b)", "4,4", `["idx_a","idx_a,idx_b","idx_b"]`},
		{"union(idx_a,idx_b)", "4,4", `["idx_a","different"]`},
		{"union(idx_a,idx_b)", "4,4", `[]`},
		{"union(idx_a,idx_b)", "4,4", `null`},
		{"union(idx_a,idx_b)", "4,4", `"idx_a,idx_b"`},
		{"union(idx_a,idx_b)", "4,4", `["idx_a",null]`},
		{"union(idx_a,idx_b)", "4,4", `["idx_a",4]`},
		{"union(idx_a,idx_b)", "4,4", `["idx_a",""]`},
	} {
		t.Run(fixture.possible, func(t *testing.T) {
			plan := strings.Replace(string(indexMergePlan(fixture.key, fixture.lengths)), `["idx_a","idx_b","idx_c","idx_d","PRIMARY"]`, fixture.possible, 1)
			for _, required := range []string{"", "idx_a", "idx_c"} {
				if err := validateAggregatePlan(json.RawMessage(plan), required, 42); !database.IsKind(err, database.ErrorInvalid) {
					t.Fatalf("ambiguous or malformed native identities admitted for %q: %v", required, err)
				}
			}
		})
	}
	plan := strings.Replace(string(indexMergePlan("union(idx_a,idx_b)")), `"possible_keys":["idx_a","idx_b","idx_c","idx_d","PRIMARY"],`, "", 1)
	if err := validateAggregatePlan(json.RawMessage(plan), "", 42); !database.IsKind(err, database.ErrorInvalid) {
		t.Fatalf("merge without native identities admitted: %v", err)
	}
}

func TestValidateAggregatePlanPhysicalAlias(t *testing.T) {
	for _, alias := range []string{"<orders>", "<derived2>", "<union2,3>", "ordinary"} {
		t.Run(alias, func(t *testing.T) {
			plan := json.RawMessage(fmt.Sprintf(`{"table":{"table_name":%q,"access_type":"ref","key":"idx_c","rows_examined_per_scan":100}}`, alias))
			if err := validateAggregatePlan(plan, "idx_c", 100); err != nil {
				t.Fatalf("physical read with alias %q rejected: %v", alias, err)
			}
			merge := strings.Replace(string(indexMergePlan("union(idx_a,idx_b)")), `"merge_rows"`, fmt.Sprintf("%q", alias), 1)
			if err := validateAggregatePlan(json.RawMessage(merge), "idx_a", 42); err != nil {
				t.Fatalf("physical index merge with alias %q rejected: %v", alias, err)
			}
		})
	}
}

func TestValidateAggregatePlanNonMergeWholeIndexName(t *testing.T) {
	for _, accessType := range []string{"ref", "range", "index"} {
		t.Run(accessType, func(t *testing.T) {
			for _, fixture := range []struct {
				name, key, required string
				valid               bool
			}{
				{"matching identifier", "idx_a", "IDX_A", true},
				{"different identifier", "idx_a", "idx_b", false},
				{"comma prefix", "idx_a,idx_b", "idx_a", false},
				{"comma suffix", "idx_a,idx_b", "idx_b", false},
				{"unconstrained comma name", "idx_a,idx_b", "", true},
				{"expression is a single name", "union(idx_a,idx_b)", "idx_a", false},
			} {
				t.Run(fixture.name, func(t *testing.T) {
					plan := json.RawMessage(fmt.Sprintf(`{"table":{"table_name":"rows","access_type":%q,"key":%q,"rows_examined_per_scan":10}}`, accessType, fixture.key))
					err := validateAggregatePlan(plan, fixture.required, 10)
					if fixture.valid && err != nil || !fixture.valid && !database.IsKind(err, database.ErrorInvalid) {
						t.Fatalf("key %q, requirement %q: admission = %v, want valid %t", fixture.key, fixture.required, err, fixture.valid)
					}
				})
			}
		})
	}
}

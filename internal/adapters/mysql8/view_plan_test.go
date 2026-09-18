package mysql8

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sigalx/quordon/internal/database"
)

func TestTrustedViewPlanAdmission(t *testing.T) {
	join := `{"query_block":{"nested_loop":[{"table":{"table_name":"orders","access_type":"ALL","rows_examined_per_scan":2}},{"table":{"table_name":"events","access_type":"ref","key":"PRIMARY","rows_examined_per_scan":3}}]}}`
	materialized := `{"query_block":{"table":{"table_name":"<derived2>","access_type":"ref","key":"<auto_key0>","rows_examined_per_scan":4,"materialized_from_subquery":{"using_temporary_table":true,"query_block":{"table":{"table_name":"orders","access_type":"index","key":"idx_status","rows_examined_per_scan":2}}}}}}`
	ordinaryMaterialized := strings.Replace(materialized, `"<derived2>"`, `"ordinary_alias"`, 1)
	shared := `{"table":{"table_name":"ordinary_alias","access_type":"ref","key":"<auto_key0>","rows_examined_per_scan":4,"materialized_from_subquery":{"sharing_temporary_table_with":{"select_id":2}}}}`
	for _, fixture := range []struct {
		name, plan, index          string
		bound                      uint64
		temporary, filesort, valid bool
	}{
		{"bounded full scan", `{"table":{"table_name":"orders","access_type":"ALL","rows_examined_per_scan":2}}`, "", 2, false, false, true},
		{"join without index constraint", join, "", 3, false, false, true},
		{"join with index on second source", join, "primary", 3, false, false, true},
		{"join index mismatch", join, "missing", 3, false, false, false},
		{"later source exceeds estimate", join, "", 2, false, false, false},
		{"materialized permitted", materialized, "idx_status", 4, true, false, true},
		{"materialization needs temporary control", materialized, "", 4, false, false, false},
		{"materialized result exceeds estimate", materialized, "idx_status", 3, true, false, false},
		{"materialized source exceeds estimate", strings.Replace(materialized, `"rows_examined_per_scan":2`, `"rows_examined_per_scan":5`, 1), "", 4, true, false, false},
		{"derived index cannot satisfy physical constraint", materialized, "<auto_key0>", 4, true, false, false},
		{"ordinary materialized alias physical source", ordinaryMaterialized, "idx_status", 4, true, false, true},
		{"ordinary materialized alias index excluded", ordinaryMaterialized, "<auto_key0>", 4, true, false, false},
		{"shared materialization permitted", shared, "", 4, true, false, true},
		{"shared materialization index excluded", shared, "<auto_key0>", 4, true, false, false},
		{"shared materialization requires temporary control", shared, "", 4, false, false, false},
		{"shared materialization estimate bound", shared, "", 3, true, false, false},
		{"malformed shared reference", strings.Replace(shared, `{"select_id":2}`, `[]`, 1), "", 4, true, false, false},
		{"missing shared select id", strings.Replace(shared, `{"select_id":2}`, `{}`, 1), "", 4, true, false, false},
		{"noninteger shared select id", strings.Replace(shared, `"select_id":2`, `"select_id":2.5`, 1), "", 4, true, false, false},
		{"nonnumber shared select id", strings.Replace(shared, `"select_id":2`, `"select_id":"2"`, 1), "", 4, true, false, false},
		{"zero shared select id", strings.Replace(shared, `"select_id":2`, `"select_id":0`, 1), "", 4, true, false, false},
		{"filesort allowed for ordinary shape", `{"ordering_operation":{"using_filesort":true,"table":{"table_name":"view_source","access_type":"ALL","rows_examined_per_scan":1}}}`, "", 1, false, true, true},
		{"filesort default denied", `{"ordering_operation":{"using_filesort":true,"table":{"table_name":"view_source","access_type":"ALL","rows_examined_per_scan":1}}}`, "", 1, false, false, false},
		{"trailing document", join + `{}`, "", 3, false, false, false},
		{"non-object plan", `[]`, "", 3, false, false, false},
		{"non-object table", `{"table":[]}`, "", 3, false, false, false},
		{"missing estimate", `{"table":{"table_name":"orders","access_type":"ALL"}}`, "", 3, false, false, false},
		{"null estimate", `{"table":{"table_name":"orders","access_type":"ALL","rows_examined_per_scan":null}}`, "", 3, false, false, false},
		{"fraction estimate", `{"table":{"table_name":"orders","access_type":"ALL","rows_examined_per_scan":1.5}}`, "", 3, false, false, false},
		{"overflow estimate", `{"table":{"table_name":"orders","access_type":"ALL","rows_examined_per_scan":18446744073709551616}}`, "", 3, false, false, false},
		{"unknown access", `{"table":{"table_name":"orders","access_type":"unknown","rows_examined_per_scan":1}}`, "", 3, false, false, false},
		{"nonstring index", `{"table":{"table_name":"orders","access_type":"ref","key":1,"rows_examined_per_scan":1}}`, "", 3, false, false, false},
		{"zero bound", join, "", 0, false, false, false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			err := validateAggregatePlan(json.RawMessage(fixture.plan), fixture.index, fixture.bound, fixture.temporary, fixture.filesort)
			if fixture.valid && err != nil || !fixture.valid && !database.IsKind(err, database.ErrorInvalid) {
				t.Fatalf("admission = %v, want valid %t", err, fixture.valid)
			}
		})
	}
}

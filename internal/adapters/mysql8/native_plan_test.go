package mysql8

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sigalx/quordon/internal/database"
)

// The integration runner captures these native plans in its isolated MySQL
// fixture. A privileged fixture connection observes view EXPLAIN; the service
// connection retains SELECT-only grants and its permission-denial regressions.
func TestNativeIndexPlanAdmission(t *testing.T) {
	directory := os.Getenv("QUORDON_NATIVE_PLAN_DIRECTORY")
	if directory == "" {
		t.Skip("native JSON fixtures are supplied by make integration")
	}
	for _, operation := range []string{"aggregate", "keyset"} {
		for _, fixture := range []struct {
			name    string
			indexes []string
			valid   bool
		}{
			{"ambiguous", []string{"", "idx_a", "idx_b", "idx_c"}, false},
			{"alias", []string{"", "idx_c"}, true},
			{"alias", []string{"idx_a", "missing"}, false},
		} {
			plan, err := os.ReadFile(filepath.Join(directory, fixture.name+"_"+operation+".json"))
			if err != nil {
				t.Fatal(err)
			}
			for _, required := range fixture.indexes {
				t.Run(fixture.name+"/"+operation+"/"+required, func(t *testing.T) {
					err := validateAggregatePlan(plan, required, 1000, false, operation == "keyset")
					if fixture.valid && err != nil || !fixture.valid && !database.IsKind(err, database.ErrorInvalid) {
						t.Fatalf("native admission = %v, want valid %t", err, fixture.valid)
					}
				})
			}
		}
	}
}

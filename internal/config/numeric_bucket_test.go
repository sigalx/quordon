package config

import (
	"os"
	"strings"
	"testing"
)

const numericPolicyShape = `        - name: orders_by_numeric_bucket
          mode: grouped
          source: {schema: application, name: orders}
          projection:
            - kind: numeric_bucket
              field: id
              alias: id_bucket
              boundaries: ["-0.00", "100.5000", "9007199254740993"]
            - kind: measure
              function: count_all
              alias: bucket_count
          order_by:
            - kind: numeric_bucket
              alias: id_bucket
              direction: asc
          maximum_limit: 10
          maximum_rows_examined_per_scan: 100
          allow_temporary_table: true
          allow_filesort: true
`

func numericPolicyText(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Replace(string(data), "      aggregate_shapes:\n", "      aggregate_shapes:\n"+numericPolicyShape, 1)
}

func TestNumericBucketPolicyStrictLoadingAndFingerprint(t *testing.T) {
	valid := numericPolicyText(t)
	cfg, err := Load([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	out := cfg.Profiles["analytics"].Query.AggregateShapes[0].Projection[0]
	if strings.Join(out.Boundaries, ",") != "0,100.5,9007199254740993" {
		t.Fatalf("canonical boundaries=%v", out.Boundaries)
	}
	same, err := Load([]byte(strings.Replace(valid, `["-0.00", "100.5000", "9007199254740993"]`, `["0", "100.5", "9007199254740993.000"]`, 1)))
	if err != nil || same.PolicyHash != cfg.PolicyHash {
		t.Fatalf("equivalent fingerprint differs: %v", err)
	}
	changed, err := Load([]byte(strings.Replace(valid, `"100.5000"`, `"101"`, 1)))
	if err != nil || changed.PolicyHash == cfg.PolicyHash {
		t.Fatalf("boundary change did not change fingerprint: %v", err)
	}
	for name, body := range map[string]string{
		"missing":           strings.Replace(valid, `              boundaries: ["-0.00", "100.5000", "9007199254740993"]`+"\n", "", 1),
		"null":              strings.Replace(valid, `["-0.00", "100.5000", "9007199254740993"]`, `null`, 1),
		"number":            strings.Replace(valid, `["-0.00", "100.5000", "9007199254740993"]`, `[0, 100]`, 1),
		"empty":             strings.Replace(valid, `["-0.00", "100.5000", "9007199254740993"]`, `[]`, 1),
		"duplicate":         strings.Replace(valid, `["-0.00", "100.5000", "9007199254740993"]`, `["1", "1.00"]`, 1),
		"reverse":           strings.Replace(valid, `["-0.00", "100.5000", "9007199254740993"]`, `["2", "1"]`, 1),
		"exponent":          strings.Replace(valid, `"100.5000"`, `"1e2"`, 1),
		"oversized":         strings.Replace(valid, `"100.5000"`, `"`+strings.Repeat("1", 129)+`"`, 1),
		"too many":          strings.Replace(valid, `["-0.00", "100.5000", "9007199254740993"]`, `[`+strings.Repeat(`"1",`, 64)+`"2"]`, 1),
		"temporary control": strings.Replace(valid, "          allow_temporary_table: true\n", "", 1),
		"sort control":      strings.Replace(valid, "          allow_filesort: true\n", "", 1),
		"string control":    strings.Replace(valid, "allow_filesort: true", `allow_filesort: "true"`, 1),
		"null control":      strings.Replace(valid, "allow_filesort: true", "allow_filesort: null", 1),
		"function":          strings.Replace(valid, "              alias: id_bucket", "              alias: id_bucket\n              function: min", 1),
		"unit":              strings.Replace(valid, "              alias: id_bucket", "              alias: id_bucket\n              unit: day", 1),
		"timezone":          strings.Replace(valid, "              alias: id_bucket", "              alias: id_bucket\n              timezone: UTC", 1),
		"representation":    strings.Replace(valid, "              alias: id_bucket", "              alias: id_bucket\n              representation: source_text", 1),
		"colliding alias":   strings.Replace(valid, "alias: bucket_count", "alias: id_bucket", 1),
		"wrong branch":      strings.Replace(valid, "              function: count_all", "              function: count_all\n              boundaries: [\"1\"]", 1),
		"overlap":           strings.Replace(valid, numericPolicyShape, numericPolicyShape+strings.Replace(strings.Replace(numericPolicyShape, "orders_by_numeric_bucket", "other_numeric_shape", 1), `"100.5000"`, `"101"`, 1), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load([]byte(body)); err == nil {
				t.Fatal("accepted invalid numeric policy")
			}
		})
	}
	profile := cfg.Profiles["analytics"]
	profile.Limits.MaxParameters = 9
	cfg.Profiles["analytics"] = profile
	if err := cfg.Validate(); err == nil {
		t.Fatal("accepted parameter overflow")
	}
}

package mysql8

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sigalx/quordon/internal/database"
)

func TestStatisticsUnsignedMetricParsingIsCanonical(t *testing.T) {
	for _, valid := range []string{"0", "1", "18446744073709551615"} {
		metric, err := parseUnsignedMetric(sql.RawBytes(valid), true)
		if err != nil || metric == nil || metric.Value != valid || !metric.Estimated {
			t.Fatalf("parse %q = (%#v, %v)", valid, metric, err)
		}
	}
	if metric, err := parseUnsignedMetric(nil, true); err != nil || metric != nil {
		t.Fatalf("parse NULL = (%#v, %v)", metric, err)
	}
	for _, invalid := range []string{"", "00", "+1", "-1", "1.0", "1e0", "18446744073709551616"} {
		if _, err := parseUnsignedMetric(sql.RawBytes(invalid), true); err == nil {
			t.Fatalf("parse %q unexpectedly succeeded", invalid)
		}
	}
}

func TestStatisticsMetadataNameValidation(t *testing.T) {
	for _, valid := range []string{"p0", "résumé", strings.Repeat("я", 64)} {
		if got, err := validatedMetadataName(sql.RawBytes(valid)); err != nil || got != valid {
			t.Fatalf("validate %q = (%q, %v)", valid, got, err)
		}
	}
	for _, invalid := range [][]byte{
		{}, []byte("bad\nname"), []byte("bad\u202ename"), {0xff}, []byte(strings.Repeat("я", 65)),
	} {
		if _, err := validatedMetadataName(sql.RawBytes(invalid)); err == nil {
			t.Fatalf("validate %q unexpectedly succeeded", invalid)
		}
	}
}

func TestStatisticsMetadataNamesUseUnicodeSimpleCaseFolding(t *testing.T) {
	names := map[string]struct{}{}
	key, available := availableMetadataName(names, "Σ")
	if !available {
		t.Fatal("first folded name was unavailable")
	}
	names[key] = struct{}{}
	if _, available := availableMetadataName(names, "ς"); available {
		t.Fatal("Unicode simple-fold collision was not rejected")
	}
}

func TestPartitioningEncoderEmitsClosedBranches(t *testing.T) {
	fixtures := []struct {
		value database.PartitioningResult
		want  string
	}{
		{value: database.PartitioningResult{Kind: "none"}, want: `{"kind":"none"}`},
		{value: database.PartitioningResult{
			Kind: "partitioned", Method: "range", Partitions: []database.PartitionEntry{{
				Name: "p0", Ordinal: 1, Statistics: database.PartitionStatistics{},
			}},
		}, want: `{"kind":"partitioned","method":"range","partitions":[{"name":"p0","ordinal":1,"statistics":{"estimated_rows":null,"data_bytes":null,"index_bytes":null}}]}`},
		{value: database.PartitioningResult{
			Kind: "subpartitioned", Method: "range", SubpartitionMethod: "hash",
			PartitionGroups: []database.PartitionGroup{{
				Name: "p0", Ordinal: 1, Subpartitions: []database.SubpartitionEntry{{
					Name: "p0s0", Ordinal: 1, Statistics: database.PartitionStatistics{},
				}},
			}},
		}, want: `{"kind":"subpartitioned","method":"range","subpartition_method":"hash","partitions":[{"name":"p0","ordinal":1,"subpartitions":[{"name":"p0s0","ordinal":1,"statistics":{"estimated_rows":null,"data_bytes":null,"index_bytes":null}}]}]}`},
	}
	for _, fixture := range fixtures {
		encoded, err := json.Marshal(fixture.value)
		if err != nil || string(encoded) != fixture.want {
			t.Fatalf("encoded partitioning = %s, %v; want %s", encoded, err, fixture.want)
		}
		if size, ok := encodedPartitioningSize(fixture.value, len(encoded)); !ok || size != len(encoded) {
			t.Fatalf("sized partitioning = (%d, %t), want %d", size, ok, len(encoded))
		}
	}
}

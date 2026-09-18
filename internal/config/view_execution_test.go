package config

import (
	"os"
	"strings"
	"testing"
)

func TestRemovedDDLGuardIsUnknownConfiguration(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"required", "disabled", "optional", "null", "false", `""`} {
		t.Run(value, func(t *testing.T) {
			fixture := strings.Replace(string(data), "    adapter: mysql8\n", "    adapter: mysql8\n    ddl_guard_mode: "+value+"\n", 1)
			if _, err := Load([]byte(fixture)); err == nil {
				t.Fatal("removed setting accepted")
			}
		})
	}
}

func TestQueryExecutionControlsAreOptionalStrictAndPrivate(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []string{"idx_orders_status", "PRIMARY"} {
		anchor := "          required_index: " + index + "\n"
		omitted := strings.Replace(string(data), anchor, "", 1)
		cfg, err := Load([]byte(omitted))
		if err != nil {
			t.Fatalf("optional index omitted: %v", err)
		}
		profile := cfg.Profiles["analytics"]
		if index == "PRIMARY" && profile.Query.KeysetSelectShapes[0].RequiredIndex != "" || index != "PRIMARY" && profile.Query.AggregateShapes[0].RequiredIndex != "" {
			t.Fatal("omission acquired an index constraint")
		}
		for _, value := range []string{"null", `""`, "true", "1", "[]", "{}"} {
			fixture := strings.Replace(string(data), anchor, "          required_index: "+value+"\n", 1)
			if _, err := Load([]byte(fixture)); err == nil {
				t.Fatalf("index %s accepted", value)
			}
		}
		for _, controls := range []string{"", "          allow_temporary_table: true\n          allow_filesort: true\n", "          allow_temporary_table: false\n          allow_filesort: false\n"} {
			if _, err := Load([]byte(strings.Replace(string(data), anchor, controls, 1))); err != nil {
				t.Fatal(err)
			}
		}
		for _, key := range []string{"allow_temporary_table", "allow_filesort"} {
			for _, value := range []string{"null", `"false"`, "0", "[]", "{}"} {
				fixture := strings.Replace(string(data), anchor, anchor+"          "+key+": "+value+"\n", 1)
				if _, err := Load([]byte(fixture)); err == nil {
					t.Fatalf("%s: %s accepted", key, value)
				}
			}
		}
	}
}

package config

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/queryspec"
)

func TestExamplePolicyLoads(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	cfg, err := Load(data)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.PolicyHash == "" {
		t.Fatal("policy hash is empty")
	}
	if cfg.Server.Listen != "127.0.0.1:8080" {
		t.Fatalf("example listen address = %q", cfg.Server.Listen)
	}
	if !slices.Equal(cfg.Profiles["query-explainer"].Datasources, []string{"primary-mysql"}) {
		t.Fatal("example profile was not decoded")
	}
	analytics := cfg.Profiles["analytics"]
	if !slices.Contains(analytics.Operations, domain.OperationAggregate) ||
		!slices.Contains(analytics.Operations, domain.OperationSelectKeyset) ||
		!slices.Contains(analytics.Operations, domain.OperationListQueryShapes) ||
		len(analytics.Query.AggregateShapes) != 2 || len(analytics.Query.KeysetSelectShapes) != 1 {
		t.Fatalf("example aggregate profile = %+v", analytics)
	}
}

func TestDatasourceAssignmentsAreRequiredStrictLists(t *testing.T) {
	templateBytes, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	template := string(templateBytes)
	principalField := "    datasources: [primary-mysql]\n"
	profileField := "  query-explainer:\n    datasources: [primary-mysql]\n"
	fixtures := []struct {
		name, old, replacement string
	}{
		{name: "missing principal datasources", old: principalField, replacement: ""},
		{name: "null principal datasources", old: principalField, replacement: "    datasources: null\n"},
		{name: "scalar principal datasource", old: principalField, replacement: "    datasources: primary-mysql\n"},
		{name: "empty principal datasources", old: principalField, replacement: "    datasources: []\n"},
		{name: "missing profile datasources", old: profileField, replacement: "  query-explainer:\n"},
		{name: "null profile datasources", old: profileField, replacement: "  query-explainer:\n    datasources: null\n"},
		{name: "scalar profile datasources", old: profileField, replacement: "  query-explainer:\n    datasources: primary-mysql\n"},
		{name: "empty profile datasources", old: profileField, replacement: "  query-explainer:\n    datasources: []\n"},
		{name: "legacy profile datasource", old: profileField, replacement: "  query-explainer:\n    datasource: primary-mysql\n"},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			candidate := strings.Replace(template, fixture.old, fixture.replacement, 1)
			if candidate == template {
				t.Fatalf("fixture insertion point %q was not found", fixture.old)
			}
			if _, err := Load([]byte(candidate)); err == nil {
				t.Fatal("invalid datasource assignment was accepted")
			}
		})
	}
}

func TestDatasourceAssignmentValidationAndFingerprint(t *testing.T) {
	loadExample := func(t *testing.T) Config {
		t.Helper()
		data, err := os.ReadFile("../../config/policy.example.yaml")
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(data)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	for _, fixture := range []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "duplicate principal datasource", mutate: func(cfg *Config) {
			principal := cfg.Principals["readonly-client"]
			principal.Datasources = []string{"primary-mysql", "primary-mysql"}
			cfg.Principals["readonly-client"] = principal
		}},
		{name: "unknown principal datasource", mutate: func(cfg *Config) {
			principal := cfg.Principals["readonly-client"]
			principal.Datasources = []string{"unknown"}
			cfg.Principals["readonly-client"] = principal
		}},
		{name: "duplicate profile datasource", mutate: func(cfg *Config) {
			profile := cfg.Profiles["query-explainer"]
			profile.Datasources = []string{"primary-mysql", "primary-mysql"}
			cfg.Profiles["query-explainer"] = profile
		}},
		{name: "unknown profile datasource", mutate: func(cfg *Config) {
			profile := cfg.Profiles["query-explainer"]
			profile.Datasources = []string{"unknown"}
			cfg.Profiles["query-explainer"] = profile
		}},
		{name: "no principal profile intersection", mutate: func(cfg *Config) {
			secondary := cfg.Datasources["primary-mysql"]
			cfg.Datasources["secondary-mysql"] = secondary
			profile := cfg.Profiles["query-explainer"]
			profile.Datasources = []string{"secondary-mysql"}
			cfg.Profiles["query-explainer"] = profile
		}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			cfg := loadExample(t)
			fixture.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid datasource assignment was accepted")
			}
		})
	}

	cfg := loadExample(t)
	secondary := cfg.Datasources["primary-mysql"]
	cfg.Datasources["secondary-mysql"] = secondary
	principal := cfg.Principals["readonly-client"]
	principal.Datasources = append(principal.Datasources, "secondary-mysql")
	cfg.Principals["readonly-client"] = principal
	profile := cfg.Profiles["query-explainer"]
	profile.Datasources = append(profile.Datasources, "secondary-mysql")
	cfg.Profiles["query-explainer"] = profile
	changed, err := policyFingerprint(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if changed == cfg.PolicyHash {
		t.Fatal("datasource assignment did not change the policy fingerprint")
	}
}

func TestProfileDatasourceBindingLimit(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(data)
	if err != nil {
		t.Fatal(err)
	}
	profile := cfg.Profiles["query-explainer"]
	profile.Datasources = make([]string, maxSupportedBindings+1)
	principal := cfg.Principals["readonly-client"]
	principal.Datasources = []string{"primary-mysql"}
	base := cfg.Datasources["primary-mysql"]
	for index := range profile.Datasources {
		name := fmt.Sprintf("source-%d", index)
		profile.Datasources[index] = name
		principal.Datasources = append(principal.Datasources, name)
		cfg.Datasources[name] = base
	}
	cfg.Profiles["query-explainer"] = profile
	cfg.Principals["readonly-client"] = principal
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "profile-datasource bindings") {
		t.Fatalf("binding limit error = %v", err)
	}
}

func TestKeysetPolicyRequiresStrictBoundedUnambiguousShapes(t *testing.T) {
	loadExample := func(t *testing.T) Config {
		t.Helper()
		data, err := os.ReadFile("../../config/policy.example.yaml")
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(data)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	t.Run("operation requires shape", func(t *testing.T) {
		cfg := loadExample(t)
		profile := cfg.Profiles["analytics"]
		profile.Query.KeysetSelectShapes = nil
		cfg.Profiles["analytics"] = profile
		if err := cfg.Validate(); err == nil {
			t.Fatal("select_keyset operation without a shape was accepted")
		}
	})

	t.Run("request signatures do not overlap", func(t *testing.T) {
		cfg := loadExample(t)
		profile := cfg.Profiles["analytics"]
		duplicate := profile.Query.KeysetSelectShapes[0]
		duplicate.Name = "orders_by_id_copy"
		duplicate.MaximumLimit--
		duplicate.MaximumRowsExaminedPerScan--
		profile.Query.KeysetSelectShapes = append(profile.Query.KeysetSelectShapes, duplicate)
		cfg.Profiles["analytics"] = profile
		if err := cfg.Validate(); err == nil || !policyLoadErrorMatches(err, "overlaps keyset shape") {
			t.Fatalf("overlapping keyset shape error=%v", err)
		}
	})

	t.Run("after cursor bindings fit parameter limit", func(t *testing.T) {
		cfg := loadExample(t)
		profile := cfg.Profiles["analytics"]
		profile.Query.KeysetSelectShapes[0].OrderBy = append(
			profile.Query.KeysetSelectShapes[0].OrderBy,
			KeysetShapeOrder{Field: "status", Direction: "asc"},
		)
		profile.Limits.MaxParameters = 3
		cfg.Profiles["analytics"] = profile
		if err := cfg.Validate(); err == nil || !policyLoadErrorMatches(err, "after-page bindings") {
			t.Fatalf("unallocatable cursor bindings error=%v", err)
		}
	})

	t.Run("order key is projected exactly once", func(t *testing.T) {
		cfg := loadExample(t)
		profile := cfg.Profiles["analytics"]
		profile.Query.KeysetSelectShapes[0].OrderBy[0].Field = "created_at"
		cfg.Profiles["analytics"] = profile
		if err := cfg.Validate(); err == nil {
			t.Fatal("unprojected keyset order field was accepted")
		}
	})

	t.Run("like placeholders use a compatible discriminator", func(t *testing.T) {
		cfg := loadExample(t)
		profile := cfg.Profiles["analytics"]
		valueTypes := []string{"integer"}
		profile.Query.KeysetSelectShapes[0].Filter = &AggregateShapeFilter{
			Kind: "predicate", Field: "id", Operator: "like", ValueTypes: &valueTypes,
		}
		profile.Query.AllowedFilterOperators = append(profile.Query.AllowedFilterOperators, "like")
		cfg.Profiles["analytics"] = profile
		if err := cfg.Validate(); err == nil || !policyLoadErrorMatches(err, "for like must contain") {
			t.Fatalf("numeric LIKE keyset shape error=%v", err)
		}
	})

	t.Run("set placeholders are homogeneous", func(t *testing.T) {
		cfg := loadExample(t)
		profile := cfg.Profiles["analytics"]
		valueTypes := []string{"integer", "string"}
		profile.Query.KeysetSelectShapes[0].Filter = &AggregateShapeFilter{
			Kind: "predicate", Field: "id", Operator: "in", ValueTypes: &valueTypes,
		}
		profile.Query.AllowedFilterOperators = append(profile.Query.AllowedFilterOperators, "in")
		cfg.Profiles["analytics"] = profile
		if err := cfg.Validate(); err == nil || !policyLoadErrorMatches(err, "for in must be homogeneous") {
			t.Fatalf("heterogeneous IN keyset shape error=%v", err)
		}
	})
}

func TestLoadStrictlyValidatesKeysetShapeYAML(t *testing.T) {
	template, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		name, old, replacement, want string
	}{
		{
			name: "null order", old: "          order_by:\n            - field: id\n              direction: asc\n          maximum_limit: 100\n",
			replacement: "          order_by: null\n          maximum_limit: 100\n",
			want:        "keyset_select_shapes[0].order_by must not be null",
		},
		{
			name: "fractional limit", old: "          maximum_limit: 100\n          required_index: PRIMARY\n",
			replacement: "          maximum_limit: 10.5\n          required_index: PRIMARY\n",
			want:        "maximum_limit must be a canonical decimal integer",
		},
		{
			name: "boolean field", old: "            - kind: field\n              field: id\n            - kind: field\n              field: status\n",
			replacement: "            - kind: field\n              field: true\n            - kind: field\n              field: status\n",
			want:        "keyset_select_shapes[0].projection[0].field must be a YAML string",
		},
		{
			name: "empty alias", old: "            - kind: field\n              field: id\n            - kind: field\n              field: status\n",
			replacement: "            - kind: field\n              field: id\n              alias: \"\"\n            - kind: field\n              field: status\n",
			want:        "keyset_select_shapes[0].projection[0].alias must not be empty when present",
		},
		{
			name: "merge key", old: "        - name: orders_by_id\n",
			replacement: "        - name: orders_by_id\n          <<: {maximum_limit: 10}\n",
			want:        "keyset_select_shapes[0].<< must not use YAML merge keys",
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			policy := strings.Replace(string(template), fixture.old, fixture.replacement, 1)
			if policy == string(template) {
				t.Fatalf("fixture insertion point %q was not found", fixture.old)
			}
			if _, err := Load([]byte(policy)); err == nil || !policyLoadErrorMatches(err, fixture.want) {
				t.Fatalf("Load() error=%v, want %q", err, fixture.want)
			}
		})
	}
}

func TestAggregatePolicyRequiresValidUnambiguousShapes(t *testing.T) {
	loadExample := func(t *testing.T) Config {
		t.Helper()
		data, err := os.ReadFile("../../config/policy.example.yaml")
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(data)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	t.Run("operation requires shape", func(t *testing.T) {
		cfg := loadExample(t)
		profile := cfg.Profiles["analytics"]
		profile.Query.AggregateShapes = nil
		cfg.Profiles["analytics"] = profile
		if err := cfg.Validate(); err == nil {
			t.Fatal("aggregate operation without shapes was accepted")
		}
	})

	t.Run("output names collide case-insensitively", func(t *testing.T) {
		cfg := loadExample(t)
		profile := cfg.Profiles["analytics"]
		profile.Query.AggregateShapes[0].Projection[1].Alias = "STATUS"
		cfg.Profiles["analytics"] = profile
		if err := cfg.Validate(); err == nil {
			t.Fatal("colliding aggregate outputs were accepted")
		}
	})

	for name, shapeIndex := range map[string]int{"grouped": 0, "scalar": 1} {
		t.Run(name+" request signatures must not overlap", func(t *testing.T) {
			cfg := loadExample(t)
			profile := cfg.Profiles["analytics"]
			duplicate := profile.Query.AggregateShapes[shapeIndex]
			duplicate.Name += "_duplicate"
			duplicate.RequiredIndex = "PRIMARY"
			duplicate.MaximumRowsExaminedPerScan++
			if duplicate.Mode == queryspec.AggregateModeGrouped {
				duplicate.MaximumLimit--
			}
			profile.Query.AggregateShapes = append(profile.Query.AggregateShapes, duplicate)
			cfg.Profiles["analytics"] = profile
			if err := cfg.Validate(); err == nil || !policyLoadErrorMatches(err, "overlaps aggregate shape") {
				t.Fatalf("overlapping aggregate shapes error = %v", err)
			}
		})
	}

	t.Run("order target must be projected", func(t *testing.T) {
		cfg := loadExample(t)
		profile := cfg.Profiles["analytics"]
		profile.Query.AllowSorting = true
		profile.Query.AggregateShapes[0].OrderBy = []AggregateShapeOrder{{
			Kind: "measure", Alias: "missing", Direction: "desc",
		}}
		cfg.Profiles["analytics"] = profile
		if err := cfg.Validate(); err == nil {
			t.Fatal("unprojected aggregate order target was accepted")
		}
	})

	t.Run("ordinary aggregate permits work controls", func(t *testing.T) {
		cfg := loadExample(t)
		profile := cfg.Profiles["analytics"]
		profile.Query.AggregateShapes[0].AllowFilesort = configBoolPointer(true)
		cfg.Profiles["analytics"] = profile
		if err := cfg.Validate(); err != nil {
			t.Fatalf("ordinary aggregate controls rejected: %v", err)
		}
	})

	t.Run("programmatic time-bucket configuration preserves control presence", func(t *testing.T) {
		cfg := loadExample(t)
		profile := cfg.Profiles["analytics"]
		profile.Query.AggregateShapes[0].Projection[0] = AggregateShapeOutput{
			Kind: "time_bucket", Field: "status", Unit: "day", Timezone: "UTC", Alias: "status_day",
		}
		profile.Query.AggregateShapes[0].AllowTemporaryTable = nil
		profile.Query.AggregateShapes[0].AllowFilesort = nil
		cfg.Profiles["analytics"] = profile
		if err := cfg.Validate(); err == nil || !policyLoadErrorMatches(err, "requires allow_temporary_table and allow_filesort") {
			t.Fatalf("missing programmatic time-bucket controls error = %v", err)
		}
	})

	t.Run("normalized filter shapes must be unique", func(t *testing.T) {
		cfg := loadExample(t)
		profile := cfg.Profiles["analytics"]
		valueTypes := []string{"string"}
		profile.Query.AggregateShapes[1].Filter = &AggregateShapeFilter{
			Kind: "group", Operator: "or", Expressions: []AggregateShapeFilter{
				{Kind: "predicate", Field: "status", Operator: "eq", ValueTypes: &valueTypes},
				{Kind: "predicate", Field: "STATUS", Operator: "eq", ValueTypes: &valueTypes},
			},
		}
		cfg.Profiles["analytics"] = profile
		if err := cfg.Validate(); err == nil {
			t.Fatal("duplicate normalized aggregate filter shapes were accepted")
		}
	})

	t.Run("dimensions respect group-by limit", func(t *testing.T) {
		cfg := loadExample(t)
		profile := cfg.Profiles["analytics"]
		profile.Limits.MaxGroupByFields = 1
		profile.Query.AggregateShapes[0].Projection = append(
			profile.Query.AggregateShapes[0].Projection,
			AggregateShapeOutput{Kind: "dimension", Field: "created_at"},
		)
		cfg.Profiles["analytics"] = profile
		if err := cfg.Validate(); err == nil {
			t.Fatal("aggregate shape exceeding max_group_by_fields was accepted")
		}
	})

	t.Run("predicate arrays respect protocol limit", func(t *testing.T) {
		cfg := loadExample(t)
		cfg.HardLimits.MaxParameters = 1000
		profile := cfg.Profiles["analytics"]
		profile.Limits.MaxParameters = 1000
		profile.Query.AllowedFilterOperators = append(profile.Query.AllowedFilterOperators, "in")
		valueTypes := make([]string, queryspec.ProtocolMaxFilterItems+1)
		for index := range valueTypes {
			valueTypes[index] = "string"
		}
		profile.Query.AggregateShapes[1].Filter.Operator = "in"
		profile.Query.AggregateShapes[1].Filter.ValueTypes = &valueTypes
		cfg.Profiles["analytics"] = profile
		if err := cfg.Validate(); err == nil {
			t.Fatal("aggregate shape exceeding the protocol predicate-array limit was accepted")
		}
	})

	t.Run("identifiers respect request length", func(t *testing.T) {
		invalid := strings.Repeat("a", queryspec.ProtocolMaxIdentifierBytes+1)
		tests := map[string]func(*Profile){
			"source": func(profile *Profile) {
				profile.Query.AggregateShapes[0].Source.Name = invalid
			},
			"projection": func(profile *Profile) {
				profile.Query.AggregateShapes[0].Projection[0].Field = invalid
			},
			"filter": func(profile *Profile) {
				profile.Query.AggregateShapes[1].Filter.Field = invalid
			},
			"order": func(profile *Profile) {
				profile.Query.AllowSorting = true
				profile.Query.AggregateShapes[0].OrderBy = []AggregateShapeOrder{{
					Kind: "measure", Alias: invalid, Direction: "asc",
				}}
			},
		}
		for name, mutate := range tests {
			t.Run(name, func(t *testing.T) {
				cfg := loadExample(t)
				profile := cfg.Profiles["analytics"]
				mutate(&profile)
				cfg.Profiles["analytics"] = profile
				if err := cfg.Validate(); err == nil {
					t.Fatal("aggregate policy accepted an identifier exceeding the request limit")
				}
			})
		}
	})
}

func configBoolPointer(value bool) *bool { return &value }

func TestLoadRejectsUnknownYAMLField(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	data = append(data, []byte("\nunknown_top_level: true\n")...)
	if _, err := Load(data); err == nil {
		t.Fatal("expected an unknown-field error")
	}
}

func TestListQueryShapesConfigurationRequiresShapeOperationAndBoundsShapeCount(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(data)
	if err != nil {
		t.Fatal(err)
	}
	profile := cfg.Profiles["analytics"]
	profile.Operations = []domain.Operation{domain.OperationListQueryShapes}
	profile.Query.AggregateShapes = nil
	profile.Query.KeysetSelectShapes = nil
	cfg.Profiles["analytics"] = profile
	if err := cfg.Validate(); err == nil || !policyLoadErrorMatches(err, "requires aggregate or select_keyset") {
		t.Fatalf("list_query_shapes without query operation error = %v", err)
	}

	profile.Operations = []domain.Operation{domain.OperationAggregate, domain.OperationListQueryShapes}
	profile.Query.AggregateShapes = make([]AggregateShape, maxSupportedQueryShapes+1)
	cfg.Profiles["analytics"] = profile
	if err := cfg.Validate(); err == nil || !policyLoadErrorMatches(err, "must not exceed 1000") {
		t.Fatalf("excessive query-shape count error = %v", err)
	}

	profile.Operations = []domain.Operation{domain.OperationSelectKeyset}
	profile.Query.AggregateShapes = nil
	profile.Query.KeysetSelectShapes = make([]KeysetSelectShape, maxSupportedQueryShapes+1)
	cfg.Profiles["analytics"] = profile
	if err := cfg.Validate(); err == nil || !policyLoadErrorMatches(err, "must not exceed 1000") {
		t.Fatalf("excessive undiscovered keyset-shape count error = %v", err)
	}
}

func TestPublicDescriptionIsStrictAndBounded(t *testing.T) {
	template, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		name, value, want string
	}{
		{name: "null", value: "null", want: "must not be null"},
		{name: "boolean", value: "true", want: "must be a YAML string"},
		{name: "numeric", value: "123", want: "must be a YAML string"},
		{name: "empty", value: `""`, want: "must not be empty when present"},
		{name: "control", value: `"\u0085"`, want: "must contain 1 to 512 non-control Unicode code points"},
		{name: "overlong", value: `"` + strings.Repeat("a", maxPublicDescriptionRunes+1) + `"`, want: "must contain 1 to 512 non-control Unicode code points"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			policy := strings.Replace(
				string(template),
				"          public_description: Count orders grouped by their current status.\n",
				"          public_description: "+fixture.value+"\n",
				1,
			)
			_, err := Load([]byte(policy))
			if err == nil || !policyLoadErrorMatches(err, fixture.want) {
				t.Fatalf("Load() error = %v, want %q", err, fixture.want)
			}
		})
	}

	t.Run("alias to non-string", func(t *testing.T) {
		policy := strings.Replace(string(template), "version: 1", "version: &description 1", 1)
		policy = strings.Replace(
			policy,
			"          public_description: Count orders grouped by their current status.\n",
			"          public_description: *description\n",
			1,
		)
		_, err := Load([]byte(policy))
		if err == nil || !policyLoadErrorMatches(err, "public_description must be a YAML string") {
			t.Fatalf("non-string alias error = %v", err)
		}
	})

	t.Run("valid alias", func(t *testing.T) {
		policy := strings.Replace(string(template), "realm: quordon", "realm: &description Query shape", 1)
		policy = strings.Replace(
			policy,
			"          public_description: Count orders grouped by their current status.\n",
			"          public_description: *description\n",
			1,
		)
		if _, err := Load([]byte(policy)); err != nil {
			t.Fatalf("valid string alias rejected: %v", err)
		}
	})
}

func TestLoadRejectsExplicitNullAggregateShapeMembers(t *testing.T) {
	template, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		old         string
		replacement string
		wantPath    string
	}{
		{
			name:        "optional filter",
			old:         "          maximum_limit: 100\n",
			replacement: "          filter: null\n          maximum_limit: 100\n",
			wantPath:    "policy.profiles.analytics.query.aggregate_shapes[0].filter",
		},
		{
			name:        "scalar maximum limit",
			old:         "            value_types: [string]\n          required_index: idx_orders_status\n",
			replacement: "            value_types: [string]\n          maximum_limit: null\n          required_index: idx_orders_status\n",
			wantPath:    "policy.profiles.analytics.query.aggregate_shapes[1].maximum_limit",
		},
		{
			name:        "optional order by",
			old:         "          maximum_limit: 100\n",
			replacement: "          order_by: null\n          maximum_limit: 100\n",
			wantPath:    "policy.profiles.analytics.query.aggregate_shapes[0].order_by",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := strings.Replace(string(template), test.old, test.replacement, 1)
			if policy == string(template) {
				t.Fatalf("fixture insertion point %q was not found", test.old)
			}
			_, err := Load([]byte(policy))
			if err == nil || !policyLoadErrorMatches(err, test.wantPath+" must not be null") {
				t.Fatalf("Load() error = %v, want explicit-null error at %s", err, test.wantPath)
			}
		})
	}

	t.Run("aliased scalar mode preserves maximum-limit presence", func(t *testing.T) {
		policy := strings.Replace(string(template), "realm: quordon", "realm: &scalar_mode scalar", 1)
		policy = strings.Replace(policy, "          mode: scalar\n", "          mode: *scalar_mode\n", 1)
		policy = strings.Replace(
			policy,
			"            value_types: [string]\n          required_index: idx_orders_status\n",
			"            value_types: [string]\n          maximum_limit: 0\n          required_index: idx_orders_status\n",
			1,
		)
		_, err := Load([]byte(policy))
		want := "maximum_limit must be omitted in scalar mode"
		if err == nil || !policyLoadErrorMatches(err, want) {
			t.Fatalf("Load() error = %v, want %q", err, want)
		}
	})
}

func TestLoadRejectsYAMLMergeKeys(t *testing.T) {
	template, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		old         string
		replacement string
		wantPath    string
	}{
		{
			name:        "policy mapping",
			old:         "server:\n  listen: 127.0.0.1:8080\n",
			replacement: "server:\n  <<: {listen: 127.0.0.1:8080}\n",
			wantPath:    "policy.server.<<",
		},
		{
			name:        "scalar maximum limit",
			old:         "          mode: scalar\n",
			replacement: "          mode: scalar\n          <<: {maximum_limit: 0}\n",
			wantPath:    "policy.profiles.analytics.query.aggregate_shapes[1].<<",
		},
		{
			name:        "non-canonical rows bound",
			old:         "          maximum_rows_examined_per_scan: 100000\n",
			replacement: "          <<: {maximum_rows_examined_per_scan: 0x186A0}\n",
			wantPath:    "policy.profiles.analytics.query.aggregate_shapes[0].<<",
		},
		{
			name: "nested projection member",
			old: "            - kind: measure\n              function: count_all\n" +
				"              alias: orders_count\n",
			replacement: "            - <<: {kind: measure, function: count_all, alias: orders_count}\n",
			wantPath:    "policy.profiles.analytics.query.aggregate_shapes[0].projection[1].<<",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := strings.Replace(string(template), test.old, test.replacement, 1)
			if policy == string(template) {
				t.Fatalf("fixture insertion point %q was not found", test.old)
			}
			_, err := Load([]byte(policy))
			if err == nil || !policyLoadErrorMatches(err, test.wantPath+" must not use YAML merge keys") {
				t.Fatalf("Load() error = %v, want YAML-merge error at %s", err, test.wantPath)
			}
		})
	}
}

func TestLoadRejectsCoercedAggregateBounds(t *testing.T) {
	template, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		old         string
		replacement string
		want        string
	}{
		{
			name: "fractional maximum limit", old: "maximum_limit: 100",
			replacement: "maximum_limit: 10.5", want: "maximum_limit must be a canonical decimal integer",
		},
		{
			name: "fractional rows estimate", old: "maximum_rows_examined_per_scan: 100000",
			replacement: "maximum_rows_examined_per_scan: 1.5", want: "maximum_rows_examined_per_scan must be a canonical decimal integer",
		},
		{
			name: "quoted rows estimate", old: "maximum_rows_examined_per_scan: 100000",
			replacement: "maximum_rows_examined_per_scan: \"100\"", want: "maximum_rows_examined_per_scan must be a canonical decimal integer",
		},
		{
			name: "overflowing rows estimate", old: "maximum_rows_examined_per_scan: 100000",
			replacement: "maximum_rows_examined_per_scan: 18446744073709551616", want: "maximum_rows_examined_per_scan is outside the supported integer range",
		},
		{
			name: "explicit scalar zero limit", old: "            value_types: [string]\n          required_index: idx_orders_status\n",
			replacement: "            value_types: [string]\n          maximum_limit: 0\n          required_index: idx_orders_status\n", want: "maximum_limit must be omitted in scalar mode",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := strings.Replace(string(template), test.old, test.replacement, 1)
			if policy == string(template) {
				t.Fatalf("fixture insertion point %q was not found", test.old)
			}
			_, err := Load([]byte(policy))
			if err == nil || !policyLoadErrorMatches(err, test.want) {
				t.Fatalf("Load() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestLoadAcceptsCanonicalIntegerAliasesForAggregateBounds(t *testing.T) {
	template, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	policy := strings.Replace(string(template), "  max_group_by_fields: 100\n", "  max_group_by_fields: &group_limit 100\n", 1)
	policy = strings.Replace(policy, "  max_offset: 100000\n", "  max_offset: &rows_bound 100000\n", 1)
	policy = strings.Replace(policy, "          maximum_limit: 100\n", "          maximum_limit: *group_limit\n", 1)
	policy = strings.Replace(
		policy,
		"          maximum_rows_examined_per_scan: 100000\n",
		"          maximum_rows_examined_per_scan: *rows_bound\n",
		1,
	)
	cfg, err := Load([]byte(policy))
	if err != nil {
		t.Fatalf("Load() rejected canonical integer aliases: %v", err)
	}
	shape := cfg.Profiles["analytics"].Query.AggregateShapes[0]
	if shape.MaximumLimit != 100 || shape.MaximumRowsExaminedPerScan != 100000 {
		t.Fatalf("aliased bounds = %d/%d", shape.MaximumLimit, shape.MaximumRowsExaminedPerScan)
	}
}

func TestLoadRejectsExplicitEmptyAggregateBranchMembers(t *testing.T) {
	template, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		old         string
		replacement string
		wantPath    string
	}{
		{
			name: "count-all field",
			old:  "              function: count_all\n              alias: orders_count\n",
			replacement: "              function: count_all\n              field: \"\"\n" +
				"              alias: orders_count\n",
			wantPath: "policy.profiles.analytics.query.aggregate_shapes[0].projection[1].field",
		},
		{
			name: "dimension alias",
			old:  "              field: status\n            - kind: measure\n",
			replacement: "              field: status\n              alias: \"\"\n" +
				"            - kind: measure\n",
			wantPath: "policy.profiles.analytics.query.aggregate_shapes[0].projection[0].alias",
		},
		{
			name: "group filter field",
			old: "          filter:\n            kind: predicate\n            field: status\n" +
				"            operator: eq\n            value_types: [string]\n",
			replacement: "          filter:\n            kind: group\n            field: \"\"\n" +
				"            operator: and\n            expressions: []\n",
			wantPath: "policy.profiles.analytics.query.aggregate_shapes[1].filter.field",
		},
		{
			name: "dimension order alias",
			old:  "          maximum_limit: 100\n",
			replacement: "          order_by:\n            - kind: dimension\n              field: status\n" +
				"              alias: \"\"\n              direction: asc\n          maximum_limit: 100\n",
			wantPath: "policy.profiles.analytics.query.aggregate_shapes[0].order_by[0].alias",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := strings.Replace(string(template), test.old, test.replacement, 1)
			if policy == string(template) {
				t.Fatalf("fixture insertion point %q was not found", test.old)
			}
			_, err := Load([]byte(policy))
			if err == nil || !policyLoadErrorMatches(err, test.wantPath+" must not be empty when present") {
				t.Fatalf("Load() error = %v, want explicit-empty error at %s", err, test.wantPath)
			}
		})
	}

	t.Run("aliased empty count-all field", func(t *testing.T) {
		policy := strings.Replace(string(template), "realm: quordon", "realm: &empty_identifier \"\"", 1)
		policy = strings.Replace(
			policy,
			"              function: count_all\n              alias: orders_count\n",
			"              function: count_all\n              field: *empty_identifier\n              alias: orders_count\n",
			1,
		)
		_, err := Load([]byte(policy))
		wantPath := "policy.profiles.analytics.query.aggregate_shapes[0].projection[1].field"
		if err == nil || !policyLoadErrorMatches(err, wantPath+" must not be empty when present") {
			t.Fatalf("Load() error = %v, want aliased explicit-empty error at %s", err, wantPath)
		}
	})
}

func TestLoadRejectsNonStringAggregateShapeMembers(t *testing.T) {
	template, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		old         string
		replacement string
		wantPath    string
	}{
		{
			name: "shape name", old: "        - name: orders_by_status\n",
			replacement: "        - name: true\n",
			wantPath:    "policy.profiles.analytics.query.aggregate_shapes[0].name",
		},
		{
			name: "mode", old: "          mode: grouped\n",
			replacement: "          mode: true\n",
			wantPath:    "policy.profiles.analytics.query.aggregate_shapes[0].mode",
		},
		{
			name: "source schema", old: "            schema: application\n",
			replacement: "            schema: true\n",
			wantPath:    "policy.profiles.analytics.query.aggregate_shapes[0].source.schema",
		},
		{
			name: "projection field", old: "            - kind: dimension\n              field: status\n",
			replacement: "            - kind: dimension\n              field: true\n",
			wantPath:    "policy.profiles.analytics.query.aggregate_shapes[0].projection[0].field",
		},
		{
			name: "measure alias", old: "              alias: orders_count\n",
			replacement: "              alias: true\n",
			wantPath:    "policy.profiles.analytics.query.aggregate_shapes[0].projection[1].alias",
		},
		{
			name: "filter value type", old: "            value_types: [string]\n",
			replacement: "            value_types: [true]\n",
			wantPath:    "policy.profiles.analytics.query.aggregate_shapes[1].filter.value_types[0]",
		},
		{
			name: "required index", old: "          required_index: idx_orders_status\n",
			replacement: "          required_index: true\n",
			wantPath:    "policy.profiles.analytics.query.aggregate_shapes[0].required_index",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := strings.Replace(string(template), test.old, test.replacement, 1)
			if policy == string(template) {
				t.Fatalf("fixture insertion point %q was not found", test.old)
			}
			_, err := Load([]byte(policy))
			if err == nil || !policyLoadErrorMatches(err, test.wantPath+" must be a YAML string") {
				t.Fatalf("Load() error = %v, want YAML-string error at %s", err, test.wantPath)
			}
		})
	}
}

func TestLoadStrictlyValidatesTimeBucketShapeControls(t *testing.T) {
	template, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	shape := `        - name: orders_by_created_day
          mode: grouped
          source:
            schema: application
            name: orders
          projection:
            - kind: time_bucket
              field: created_at
              unit: day
              timezone: UTC
              alias: created_day
            - kind: measure
              function: count_all
              alias: daily_count
          maximum_limit: 100
          required_index: idx_orders_created_at
          maximum_rows_examined_per_scan: 100000
          allow_temporary_table: true
          allow_filesort: false
`
	valid := strings.Replace(string(template), "      aggregate_shapes:\n", "      aggregate_shapes:\n"+shape, 1)
	loaded, err := Load([]byte(valid))
	if err != nil {
		t.Fatalf("valid time-bucket shape rejected: %v", err)
	}
	changedControls, err := Load([]byte(strings.Replace(
		valid, "          allow_filesort: false\n", "          allow_filesort: true\n", 1,
	)))
	if err != nil {
		t.Fatalf("valid changed time-bucket controls rejected: %v", err)
	}
	if loaded.PolicyHash == changedControls.PolicyHash {
		t.Fatal("time-bucket execution controls are absent from the policy fingerprint")
	}
	tests := map[string]string{
		"missing temporary control": strings.Replace(valid, "          allow_temporary_table: true\n", "", 1),
		"missing filesort control":  strings.Replace(valid, "          allow_filesort: false\n", "", 1),
		"null control":              strings.Replace(valid, "          allow_filesort: false\n", "          allow_filesort: null\n", 1),
		"string control":            strings.Replace(valid, "          allow_filesort: false\n", "          allow_filesort: \"false\"\n", 1),
		"non-string unit":           strings.Replace(valid, "              unit: day\n", "              unit: true\n", 1),
		"empty timezone":            strings.Replace(valid, "              timezone: UTC\n", "              timezone: \"\"\n", 1),
	}
	for name, policy := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load([]byte(policy)); err == nil {
				t.Fatal("malformed time-bucket policy was accepted")
			}
		})
	}
	t.Run("boolean aliases are dereferenced", func(t *testing.T) {
		policy := strings.Replace(valid, "      allow_filtering: true\n", "      allow_filtering: &allow_sort true\n", 1)
		policy = strings.Replace(policy, "          allow_temporary_table: true\n", "          allow_temporary_table: *allow_sort\n", 1)
		if _, err := Load([]byte(policy)); err != nil {
			t.Fatalf("valid boolean alias rejected: %v", err)
		}
	})
}

func TestPolicyFingerprintRedactsInlineSecretsAndCanonicalizesYAML(t *testing.T) {
	template, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	inlinePolicy := func(passwordHash, dsn string, suffix string) []byte {
		policy := strings.Replace(
			string(template),
			"password_hash_secret_ref: env:QUORDON_EXPLAIN_PASSWORD_HASH",
			`password_hash: "`+passwordHash+`"`,
			1,
		)
		policy = strings.Replace(
			policy,
			"dsn_secret_ref: file:/run/credentials/primary-mysql-dsn",
			`dsn: "`+dsn+`"`,
			1,
		)
		return []byte(policy + suffix)
	}
	first, err := Load(inlinePolicy("first-hash", "first:first@tcp(db:3306)/?tls=true", ""))
	if err != nil {
		t.Fatalf("load first inline policy: %v", err)
	}
	second, err := Load(inlinePolicy("second-hash", "second:second@tcp(db:3306)/?tls=true", "\n# formatting-only comment\n"))
	if err != nil {
		t.Fatalf("load second inline policy: %v", err)
	}
	if first.PolicyHash != second.PolicyHash {
		t.Fatalf("secret-only and formatting changes altered policy fingerprint: %q != %q", first.PolicyHash, second.PolicyHash)
	}

	changedPolicy := strings.Replace(
		string(inlinePolicy("third-hash", "third:third@tcp(db:3306)/?tls=true", "")),
		"max_rows: 1000",
		"max_rows: 999",
		1,
	)
	changed, err := Load([]byte(changedPolicy))
	if err != nil {
		t.Fatalf("load changed policy: %v", err)
	}
	if first.PolicyHash == changed.PolicyHash {
		t.Fatal("authorization limit change did not alter policy fingerprint")
	}
}

func TestBasicUserRequiresExactlyOneHashSource(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	cfg, err := Load(data)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	user := cfg.Authentication.Basic.Users["explain-client"]
	user.PasswordHash = "$2a$10$inline"
	cfg.Authentication.Basic.Users["explain-client"] = user
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected both hash sources to be rejected")
	}
	user.PasswordHashSecretRef = ""
	cfg.Authentication.Basic.Users["explain-client"] = user
	if err := cfg.Validate(); err != nil {
		t.Fatalf("inline hash source was rejected: %v", err)
	}
	user.PasswordHash = ""
	cfg.Authentication.Basic.Users["explain-client"] = user
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected a missing hash source to be rejected")
	}
}

func TestDatasourceRequiresExactlyOneDSNSource(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	cfg, err := Load(data)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	datasource := cfg.Datasources["primary-mysql"]
	datasource.DSN = "user:password@tcp(127.0.0.1:3306)/"
	cfg.Datasources["primary-mysql"] = datasource
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected both DSN sources to be rejected")
	}
	datasource.DSNSecretRef = ""
	cfg.Datasources["primary-mysql"] = datasource
	if err := cfg.Validate(); err != nil {
		t.Fatalf("inline DSN source was rejected: %v", err)
	}
	datasource.DSN = ""
	cfg.Datasources["primary-mysql"] = datasource
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected a missing DSN source to be rejected")
	}
}

func TestDatasourceRequiresExplicitTLSMode(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	data = []byte(strings.Replace(string(data), "    tls_required: true\n", "", 1))
	if _, err := Load(data); err == nil || !policyLoadErrorMatches(err, "tls_required must be set explicitly") {
		t.Fatalf("Load() error = %v, want explicit tls_required error", err)
	}
}

func TestLimitsRequireSlotsForLimitAndOffset(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	cfg, err := Load(data)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	cfg.HardLimits.MaxParameters = 1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected hard max_parameters below 2 to be rejected")
	}
	cfg.HardLimits.MaxParameters = 200
	profile := cfg.Profiles["query-explainer"]
	profile.Limits.MaxParameters = 1
	cfg.Profiles["query-explainer"] = profile
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected profile max_parameters below 2 to be rejected")
	}
}

func TestHardProjectionLimitCannotExceedProtocolMaximum(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	cfg, err := Load(data)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	cfg.HardLimits.MaxProjectionFields = 101
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected hard projection limit above the OpenAPI maximum to be rejected")
	}
}

func TestAggregatePredicateAndParameterLimitsMayExceedArrayMaximum(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	cfg, err := Load(data)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	cfg.HardLimits.MaxPredicates = 500
	cfg.HardLimits.MaxParameters = 500
	profile := cfg.Profiles["query-explainer"]
	profile.Limits.MaxPredicates = 500
	profile.Limits.MaxParameters = 500
	cfg.Profiles["query-explainer"] = profile
	if err := cfg.Validate(); err != nil {
		t.Fatalf("aggregate limits above a single array maximum were rejected: %v", err)
	}
}

func TestConcurrencyLimitCannotExceedImplementationMaximum(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	cfg, err := Load(data)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	cfg.HardLimits.MaxConcurrency = maxSupportedConcurrency + 1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected excessive hard max_concurrency to be rejected")
	}

	cfg.HardLimits.MaxConcurrency = maxSupportedConcurrency
	profile := cfg.Profiles["query-explainer"]
	profile.Limits.MaxConcurrency = maxSupportedConcurrency + 1
	cfg.Profiles["query-explainer"] = profile
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected excessive profile max_concurrency to be rejected")
	}
}

func TestNumericLimitsCannotExceedImplementationMaximums(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	cfg, err := Load(data)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*domain.Limits)
	}{
		{name: "deadline", mutate: func(l *domain.Limits) { l.DeadlineMS = maxSupportedDeadlineMS + 1 }},
		{name: "request bytes", mutate: func(l *domain.Limits) { l.MaxRequestBytes = maxSupportedRequestBytes + 1 }},
		{name: "projection", mutate: func(l *domain.Limits) { l.MaxProjectionFields = queryspec.ProtocolMaxProjectionFields + 1 }},
		{name: "group by", mutate: func(l *domain.Limits) { l.MaxGroupByFields = queryspec.ProtocolMaxGroupByFields + 1 }},
		{name: "order by", mutate: func(l *domain.Limits) { l.MaxOrderByFields = queryspec.ProtocolMaxOrderByFields + 1 }},
		{name: "predicates", mutate: func(l *domain.Limits) { l.MaxPredicates = maxSupportedPredicates + 1 }},
		{name: "expression depth", mutate: func(l *domain.Limits) { l.MaxExpressionDepth = maxSupportedExpressionDepth + 1 }},
		{name: "parameters", mutate: func(l *domain.Limits) { l.MaxParameters = maxSupportedParameters + 1 }},
		{name: "rows", mutate: func(l *domain.Limits) { l.MaxRows = queryspec.ProtocolMaxRows + 1 }},
		{name: "result bytes", mutate: func(l *domain.Limits) { l.MaxResultBytes = domain.MaxSupportedResultBytes + 1 }},
		{name: "offset", mutate: func(l *domain.Limits) { l.MaxOffset = queryspec.ProtocolMaxOffset + 1 }},
		{name: "concurrency", mutate: func(l *domain.Limits) { l.MaxConcurrency = maxSupportedConcurrency + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := cfg.HardLimits
			test.mutate(&limits)
			if err := validateLimits("hard_limits", limits); err == nil {
				t.Fatal("expected excessive limit to be rejected")
			}
		})
	}
}

func TestPoolLimitsCannotOverflowOrExceedServiceCapacity(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	cfg, err := Load(data)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	datasource := cfg.Datasources["primary-mysql"]
	datasource.Pool.MaxOpenConnections = maxSupportedPoolConnections + 1
	cfg.Datasources["primary-mysql"] = datasource
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected excessive max_open_connections to be rejected")
	}

	datasource.Pool.MaxOpenConnections = 4
	datasource.Pool.MaxConnectionLifetimeSeconds = maxSupportedConnLifetimeSec + 1
	cfg.Datasources["primary-mysql"] = datasource
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected excessive connection lifetime to be rejected")
	}
}

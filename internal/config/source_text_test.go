package config

import (
	"os"
	"strings"
	"testing"

	"github.com/sigalx/quordon/internal/queryspec"
)

func TestSourceTextPolicyStrictDecodeAndPermission(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.integration.yaml")
	if err != nil {
		t.Fatal(err)
	}
	baseline := string(data)
	cfg, err := Load(data)
	if err != nil || !QueryPolicyUsesSourceText(cfg.Profiles["diagnostic-reader"].Query) {
		t.Fatalf("diagnostic policy rejected: %v", err)
	}
	for _, token := range []string{"null", "\"true\"", "1", "[]", "{}", "false"} {
		t.Run("permission/"+token, func(t *testing.T) {
			policy := strings.Replace(baseline, "allow_source_text: true", "allow_source_text: "+token, 1)
			if _, err := Load([]byte(policy)); err == nil {
				t.Fatal("invalid permission or unpermitted diagnostic shapes accepted")
			}
		})
	}
	for _, token := range []string{"null", "\"\"", "native", "false", "1", "[]", "{}"} {
		t.Run("representation/"+token, func(t *testing.T) {
			policy := strings.Replace(baseline, "representation: source_text", "representation: "+token, 1)
			if _, err := Load([]byte(policy)); err == nil {
				t.Fatal("invalid representation accepted")
			}
		})
	}
	omitted := strings.Replace(baseline, "      allow_source_text: true\n", "", 1)
	if _, err := Load([]byte(omitted)); err == nil {
		t.Fatal("diagnostic shapes accepted with default permission")
	}
	for _, modify := range []func(*QueryPolicy){
		func(p *QueryPolicy) { (*p.AggregateShapes[3].Filter.ValueTypes)[0] = "date" },
		func(p *QueryPolicy) {
			p.AggregateShapes[0].Projection[1].Representation = queryspec.RepresentationSourceText
		},
		func(p *QueryPolicy) { p.AggregateShapes[0].OrderBy[0].Representation = "" },
		func(p *QueryPolicy) { p.KeysetSelectShapes[0].OrderBy[0].Representation = "" },
	} {
		cfg, err := Load(data)
		if err != nil {
			t.Fatal(err)
		}
		profile := cfg.Profiles["diagnostic-reader"]
		modify(&profile.Query)
		cfg.Profiles["diagnostic-reader"] = profile
		if err := cfg.Validate(); err == nil {
			t.Fatal("inconsistent source_text policy accepted")
		}
	}
}

func TestSourceTextPermissionDefaultsToFalse(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range []string{string(data), strings.Replace(string(data), "      allow_source_text: false\n", "", 1)} {
		cfg, err := Load([]byte(policy))
		if err != nil {
			t.Fatal(err)
		}
		for _, profile := range cfg.Profiles {
			if profile.Query.AllowSourceText || QueryPolicyUsesSourceText(profile.Query) {
				t.Fatal("ordinary policy implicitly enabled source_text")
			}
		}
	}
}

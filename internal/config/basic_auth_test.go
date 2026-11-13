package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func basicAuthPolicyFixture(t *testing.T, mutate func(*yaml.Node)) []byte {
	t.Helper()
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	mutate(document.Content[0])
	data, err = yaml.Marshal(&document)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func basicAuthUsersNode(root *yaml.Node) *yaml.Node {
	return mappingValue(mappingValue(mappingValue(root, "authentication"), "basic"), "users")
}

func TestBasicUsernameContract(t *testing.T) {
	base, err := Load(basicAuthPolicyFixture(t, func(*yaml.Node) {}))
	if err != nil {
		t.Fatal(err)
	}
	user := base.Authentication.Basic.Users["explain-client"]
	for _, test := range []struct {
		username string
		valid    bool
	}{
		{"client", true}, {"client-01", true}, {"client_01", true},
		{"andrey.shcheglov", true}, {"Andrey.Shcheglov", true}, {"_client.01", true},
		{"", false}, {"1client", false}, {".client", false}, {"-client", false},
		{"client name", false}, {"client:name", false}, {"client/name", false},
		{"client@example", false}, {"client\nname", false}, {"клиент", false},
	} {
		t.Run(test.username, func(t *testing.T) {
			typed := base
			typed.Authentication.Basic.Users = map[string]BasicUser{test.username: user}
			if err := typed.Validate(); (err == nil) != test.valid {
				t.Fatalf("typed validation: valid=%v error=%v", test.valid, err)
			}
			data := basicAuthPolicyFixture(t, func(root *yaml.Node) {
				key := basicAuthUsersNode(root).Content[0]
				key.Value, key.Style = test.username, yaml.DoubleQuotedStyle
			})
			path := filepath.Join(t.TempDir(), "policy.yaml")
			if err := os.WriteFile(path, data, RequiredFileMode); err != nil {
				t.Fatal(err)
			}
			for _, load := range []struct {
				name string
				load func() (Config, error)
			}{
				{"inline", func() (Config, error) { return Load(data) }},
				{"file", func() (Config, error) { return LoadFile(path) }},
			} {
				t.Run(load.name, func(t *testing.T) {
					cfg, err := load.load()
					if !test.valid {
						loadErrorCode(t, err, "POLICY_IDENTIFIER")
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if _, ok := cfg.Authentication.Basic.Users[test.username]; !ok {
						t.Fatal("username was changed during decoding")
					}
					if err := cfg.Validate(); err != nil {
						t.Fatalf("typed validation disagrees with decoding: %v", err)
					}
				})
			}
		})
	}
}

func TestDottedBasicUsernamesAreDistinctAndPreservedThroughReferences(t *testing.T) {
	data := basicAuthPolicyFixture(t, func(root *yaml.Node) {
		users := basicAuthUsersNode(root)
		user := users.Content[1]
		users.Content = nil
		for _, name := range []string{"first.client", "first-client", "first_client", "First.Client"} {
			users.Content = append(users.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}, user)
		}
	})
	dir := t.TempDir()
	writePolicyFile(t, dir, "users.yaml", string(data))
	path := writePolicyFile(t, dir, "policy.yaml", "$ref: './users.yaml'\n")
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Authentication.Basic.Users) != 4 {
		t.Fatal("distinct usernames were normalized or merged")
	}
	inline, err := Load(data)
	if err != nil || inline.PolicyHash != cfg.PolicyHash {
		t.Fatal("reference changed the effective policy")
	}
}

func TestDottedBasicUsersKeepStrictCredentialValidation(t *testing.T) {
	for _, test := range []struct {
		name, code string
		mutate     func(*yaml.Node)
	}{
		{"duplicate username", "POLICY_YAML_DUPLICATE", func(users *yaml.Node) {
			key := *users.Content[0]
			users.Content = append(users.Content, &key, users.Content[1])
		}},
		{"null credential", "POLICY_NULL", func(users *yaml.Node) {
			users.Content[1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}
		}},
		{"missing principal", "POLICY_REQUIRED", func(users *yaml.Node) {
			users.Content[1].Content = users.Content[1].Content[2:]
		}},
		{"case-folded field", "POLICY_UNKNOWN_FIELD", func(users *yaml.Node) {
			users.Content[1].Content[0].Value = "Principal"
		}},
		{"unknown field", "POLICY_UNKNOWN_FIELD", func(users *yaml.Node) {
			users.Content[1].Content[0].Value = "unknown"
		}},
		{"numeric principal", "POLICY_TYPE", func(users *yaml.Node) {
			value := users.Content[1].Content[1]
			value.Tag, value.Value = "!!int", "1"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := basicAuthPolicyFixture(t, func(root *yaml.Node) {
				users := basicAuthUsersNode(root)
				users.Content[0].Value = "first.client"
				test.mutate(users)
			})
			_, err := Load(data)
			loadErrorCode(t, err, test.code)
		})
	}
}

func TestDotsRemainForbiddenInOtherPolicyNames(t *testing.T) {
	for _, section := range []string{"principals", "datasources", "profiles"} {
		t.Run(section, func(t *testing.T) {
			data := basicAuthPolicyFixture(t, func(root *yaml.Node) {
				mappingValue(root, section).Content[0].Value = "dotted.name"
			})
			_, err := Load(data)
			loadErrorCode(t, err, "POLICY_IDENTIFIER")
		})
	}
}

package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func loadErrorCode(t *testing.T, err error, code string) *LoadError {
	t.Helper()
	var problem *LoadError
	if !errors.As(err, &problem) || problem.Code != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
	if problem.Location.Document < 1 {
		t.Fatal("missing source document")
	}
	return problem
}

// Existing fixtures used paths containing operator-supplied mapping keys.
// Keep their validation checks while asserting the new safe diagnostic codes.
func policyLoadErrorMatches(err error, oldDiagnostic string) bool {
	var problem *LoadError
	if !errors.As(err, &problem) {
		return err != nil && strings.Contains(err.Error(), oldDiagnostic)
	}
	if problem.Location.Document < 1 || problem.Location.Line < 1 || problem.Location.Column < 1 {
		return false
	}
	var code string
	switch {
	case strings.Contains(oldDiagnostic, "must not be null"):
		code = "POLICY_NULL"
	case strings.Contains(oldDiagnostic, "YAML merge"):
		code = "POLICY_YAML_MERGE"
	case strings.Contains(oldDiagnostic, "must not be empty"):
		code = "POLICY_EMPTY"
	case strings.Contains(oldDiagnostic, "outside the supported integer range"):
		return problem.Code == "POLICY_INTEGER_RANGE" || problem.Code == "POLICY_TYPE"
	case strings.Contains(oldDiagnostic, "must be a YAML"), strings.Contains(oldDiagnostic, "canonical decimal integer"):
		code = "POLICY_TYPE"
	case strings.Contains(oldDiagnostic, "must be omitted in scalar mode"):
		code = "POLICY_SHAPE"
	case strings.Contains(oldDiagnostic, "tls_required must be set explicitly"):
		code = "POLICY_REQUIRED"
	case strings.Contains(oldDiagnostic, "non-control Unicode code points"):
		code = "POLICY_SEMANTIC"
	default:
		return strings.Contains(err.Error(), oldDiagnostic)
	}
	return problem.Code == code
}

func writePolicyFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), RequiredFileMode); err != nil {
		t.Fatal(err)
	}
	return path
}

func assembleTestPolicy(t *testing.T, dir, name string, budgets policyBudgets) (*policyLoader, resolvedPolicyNode, error) {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	l := newPolicyLoader(root, budgets)
	doc, err := l.document(name, nil)
	if err != nil {
		return l, resolvedPolicyNode{}, err
	}
	node, err := l.resolve(doc.node, doc, 1)
	return l, node, err
}

func TestPolicyReferencesAtEveryLevelAndFingerprint(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	inline, err := Load(data)
	if err != nil {
		t.Fatal(err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	root := document.Content[0]
	dir := t.TempDir()
	writePolicyFile(t, dir, "common.yaml", string(data))
	paths := [][]string{
		{}, {"profiles", "analytics"}, {"profiles", "query-explainer", "resources", "fields", "deny"},
		{"profiles", "analytics", "query", "aggregate_shapes"},
		{"profiles", "analytics", "query", "aggregate_shapes", "0"},
		{"profiles", "analytics", "query", "keyset_select_shapes", "0"},
		{"profiles", "analytics", "limits"}, {"profiles", "analytics", "datasources"},
		{"datasources", "primary-mysql", "tls_required"}, {"hard_limits", "max_rows"},
	}
	for _, path := range paths {
		t.Run(strings.Join(path, "/"), func(t *testing.T) {
			var copy yaml.Node
			if err := yaml.Unmarshal(data, &copy); err != nil {
				t.Fatal(err)
			}
			node := copy.Content[0]
			for _, key := range path {
				if node.Kind == yaml.SequenceNode {
					node = node.Content[0]
				} else {
					node = mappingValue(node, key)
				}
				if node == nil {
					t.Fatal("fixture path missing")
				}
			}
			ref := "./common.yaml"
			if len(path) != 0 {
				ref += "#/" + strings.Join(path, "/")
			}
			*node = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Tag: "!!str", Value: "$ref"}, {Kind: yaml.ScalarNode, Tag: "!!str", Value: ref},
			}}
			assembled, err := yaml.Marshal(&copy)
			if err != nil {
				t.Fatal(err)
			}
			path := writePolicyFile(t, dir, "policy.yaml", string(assembled))
			got, err := LoadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(inline, got) {
				t.Fatal("effective policy or fingerprint changed")
			}
		})
	}
	// An internal reference needs no filesystem root or template registry.
	profile := mappingValue(mappingValue(root, "profiles"), "query-explainer")
	profileBytes, err := yaml.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	internal := strings.Replace(string(data), "  query-explainer:\n"+indentYAML(string(profileBytes), 4), "  query-explainer:\n    $ref: '#/profiles/data-reader'\n", 1)
	if internal == string(data) { // Marshal formatting may differ from the example; use the AST instead.
		*profile = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "$ref"}, {Kind: yaml.ScalarNode, Tag: "!!str", Value: "#/profiles/data-reader"},
		}}
		b, err := yaml.Marshal(&document)
		if err != nil {
			t.Fatal(err)
		}
		internal = string(b)
	}
	if _, err := Load([]byte(internal)); err != nil {
		t.Fatal(err)
	}
}

func TestReferencedProfileOverrideAllowsMultipleDatasourcesAndPreservesFingerprint(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var original, inlineDocument yaml.Node
	if err := yaml.Unmarshal(data, &original); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &inlineDocument); err != nil {
		t.Fatal(err)
	}
	root := inlineDocument.Content[0]
	datasources := mappingValue(root, "datasources")
	primary := mappingValue(datasources, "primary-mysql")
	primaryBytes, err := yaml.Marshal(primary)
	if err != nil {
		t.Fatal(err)
	}
	var secondaryDocument yaml.Node
	if err := yaml.Unmarshal(primaryBytes, &secondaryDocument); err != nil {
		t.Fatal(err)
	}
	datasources.Content = append(datasources.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "secondary-mysql"},
		secondaryDocument.Content[0],
	)
	principalDatasources := mappingValue(
		mappingValue(mappingValue(root, "principals"), "readonly-client"), "datasources",
	)
	principalDatasources.Content = append(principalDatasources.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "secondary-mysql"},
	)
	profile := mappingValue(mappingValue(root, "profiles"), "query-explainer")
	profileDatasources := mappingValue(profile, "datasources")
	profileDatasources.Content = append(profileDatasources.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "secondary-mysql"},
	)
	inlineBytes, err := yaml.Marshal(&inlineDocument)
	if err != nil {
		t.Fatal(err)
	}
	inline, err := Load(inlineBytes)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	baseProfile := mappingValue(mappingValue(original.Content[0], "profiles"), "query-explainer")
	baseProfileBytes, err := yaml.Marshal(baseProfile)
	if err != nil {
		t.Fatal(err)
	}
	writePolicyFile(t, dir, "query-explainer.yaml", string(baseProfileBytes))
	var referencedDocument yaml.Node
	if err := yaml.Unmarshal(inlineBytes, &referencedDocument); err != nil {
		t.Fatal(err)
	}
	referencedProfile := mappingValue(mappingValue(referencedDocument.Content[0], "profiles"), "query-explainer")
	var reference yaml.Node
	if err := yaml.Unmarshal([]byte("$ref: './query-explainer.yaml'\n$override:\n  datasources: [primary-mysql, secondary-mysql]\n"), &reference); err != nil {
		t.Fatal(err)
	}
	*referencedProfile = *reference.Content[0]
	referencedBytes, err := yaml.Marshal(&referencedDocument)
	if err != nil {
		t.Fatal(err)
	}
	path := writePolicyFile(t, dir, "policy.yaml", string(referencedBytes))
	referenced, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := referenced.Profiles["query-explainer"].Datasources; !reflect.DeepEqual(got, []string{"primary-mysql", "secondary-mysql"}) {
		t.Fatalf("expanded profile datasources = %#v", got)
	}
	if inline.PolicyHash != referenced.PolicyHash || !reflect.DeepEqual(inline, referenced) {
		t.Fatalf("referenced override changed effective policy: inline=%q referenced=%q", inline.PolicyHash, referenced.PolicyHash)
	}
}

func indentYAML(s string, count int) string {
	return strings.Repeat(" ", count) + strings.ReplaceAll(strings.TrimSuffix(s, "\n"), "\n", "\n"+strings.Repeat(" ", count)) + "\n"
}

func TestNestedReferencesPointersAndShallowOverrides(t *testing.T) {
	dir := t.TempDir()
	writePolicyFile(t, dir, "library/base.yaml", `
limits: {rows: 10, bytes: 20}
list: [one, two]
"a/b": {"m~n": [zero, {"c%d": exact}]}
"~1": escaped-once
"": empty-key
"a?b": question
unicode: {"кириллица": correct}
alias: &shared [anchored]
ordinary: *shared
`)
	writePolicyFile(t, dir, "library/profile.yaml", `
datasources: [test]
limits: {$ref: './base.yaml#/limits'}
list: {$ref: './base.yaml#/list'}
`)
	writePolicyFile(t, dir, "local.yaml", "rows: 7\n")
	writePolicyFile(t, dir, "policy.yaml", `
original: {$ref: './library/profile.yaml'}
rc:
  $ref: './library/profile.yaml'
  $override:
    datasources: [rc]
    list: [replacement]
    limits:
      $ref: './library/base.yaml#/limits'
      $override:
        rows: {$ref: './local.yaml#/rows'}
shallow:
  $ref: './library/profile.yaml'
  $override:
    limits: {rows: 1}
pointer: {$ref: './library/base.yaml#/a~1b/m~0n/1/c%25d'}
once: {$ref: './library/base.yaml#/~01'}
empty: {$ref: './library/base.yaml#/'}
question: {$ref: './library/base.yaml#/a?b'}
unicode: {$ref: './library/base.yaml#/%75nicode/%D0%BA%D0%B8%D1%80%D0%B8%D0%BB%D0%BB%D0%B8%D1%86%D0%B0'}
alias: {$ref: './library/base.yaml#/ordinary/0'}
`)
	l, result, err := assembleTestPolicy(t, dir, "policy.yaml", defaultPolicyBudgets)
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	writeAssembledJSON(&buffer, result.node)
	if buffer.Len() != result.size {
		t.Fatalf("size=%d, measured=%d", buffer.Len(), result.size)
	}
	var got map[string]any
	if err := yaml.Unmarshal(buffer.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"pointer": "exact", "once": "escaped-once", "empty": "empty-key", "question": "question", "unicode": "correct", "alias": "anchored"} {
		if got[key] != want {
			t.Fatalf("pointer %s failed", key)
		}
	}
	original := got["original"].(map[string]any)
	rc := got["rc"].(map[string]any)
	if !reflect.DeepEqual(original["datasources"], []any{"test"}) || !reflect.DeepEqual(rc["datasources"], []any{"rc"}) || len(rc["list"].([]any)) != 1 || !reflect.DeepEqual(rc["limits"], map[string]any{"rows": 7, "bytes": 20}) {
		t.Fatal("override did not replace only direct fields")
	}
	if len(got["shallow"].(map[string]any)["limits"].(map[string]any)) != 1 {
		t.Fatal("unexpected deep merge")
	}
	if len(l.documents) != 4 {
		t.Fatalf("loaded documents=%d", len(l.documents))
	}
}

func TestReferencesRejectMalformedNodesAndTargets(t *testing.T) {
	for _, test := range []struct{ input, code string }{
		{"$override: {}", "POLICY_REF_REQUIRED"}, {"$ref: ''", "POLICY_REF_TYPE"},
		{"$ref: 1", "POLICY_REF_TYPE"}, {"$ref: null", "POLICY_REF_TYPE"},
		{"$ref: []", "POLICY_REF_TYPE"}, {"$ref: {}", "POLICY_REF_TYPE"},
		{"$ref: '#/value'\nextra: 1", "POLICY_REF_FIELDS"},
		{"$ref: '#/value'\n$override: null", "POLICY_OVERRIDE_TYPE"},
		{"$ref: '#/value'\n$override: []", "POLICY_OVERRIDE_TYPE"},
		{"value: 1\nref: {$ref: '#/value', $override: {}}", "POLICY_OVERRIDE_TARGET"},
		{"ref: {$ref: '#/missing'}", "POLICY_REF_TARGET"},
		{"value: [a]\nref: {$ref: '#/value/01'}", "POLICY_REF_POINTER"},
		{"value: [a]\nref: {$ref: '#/value/-'}", "POLICY_REF_POINTER"},
		{"value: [a]\nref: {$ref: '#/value/2'}", "POLICY_REF_TARGET"},
		{"value: [a]\nref: {$ref: '#/value/999999999999999999999999'}", "POLICY_REF_TARGET"},
		{"ref: {$ref: '#bad'}", "POLICY_REF_POINTER"},
		{"ref: {$ref: '#/a~2'}", "POLICY_REF_POINTER"},
		{"ref: {$ref: '#/a~'}", "POLICY_REF_POINTER"},
		{"ref: {$ref: '#/%ZZ'}", "POLICY_REF_URI"},
		{"$ref: '#/ref'\nref: 1", "POLICY_REF_FIELDS"},
		{"ref: {$ref: '#/ref'}", "POLICY_REF_CYCLE"},
		{"a: {$ref: '#/b'}\nb: {$ref: '#/a'}", "POLICY_REF_CYCLE"},
		{"a: &a {b: *a}", "POLICY_YAML_ALIAS_CYCLE"},
		{"a: 1\na: 2", "POLICY_YAML_DUPLICATE"},
		{"a: {b: 1, b: 2}", "POLICY_YAML_DUPLICATE"},
		{"1: value", "POLICY_YAML_KEY"}, {"? [a, b]\n: value", "POLICY_YAML_KEY"},
		{"a: {<<: {b: 1}}", "POLICY_YAML_MERGE"},
		{"a: 1\n---\nb: 2", "POLICY_DOCUMENT_COUNT"},
		{string([]byte{'a', ':', ' ', 0xff}), "POLICY_UTF8"},
	} {
		t.Run(test.code+test.input, func(t *testing.T) {
			l := newPolicyLoader(nil, defaultPolicyBudgets)
			doc, err := l.parse("", []byte(test.input))
			if err == nil {
				_, err = l.resolve(doc.node, doc, 1)
			}
			loadErrorCode(t, err, test.code)
		})
	}
}

func TestReferencePathValidationPrecedesOpeningTargets(t *testing.T) {
	for _, ref := range []string{"https://example.invalid/a", "file:policy.yaml", "//host/a", "/absolute", "%2fabsolute", "../outside", "a/../../outside", "./a?query", "./a?", `C:\file`, `a\file`, "./a#/bad~2", "./a#bad", "./a#/%ff"} {
		t.Run(ref, func(t *testing.T) {
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			l := newPolicyLoader(root, defaultPolicyBudgets)
			opens := 0
			l.open = func(string) (*os.File, error) { opens++; return nil, errors.New("unexpected open") }
			var node yaml.Node
			if err := node.Encode(map[string]string{"$ref": ref}); err != nil {
				t.Fatal(err)
			}
			data, err := yaml.Marshal(&node)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := l.parse("policy.yaml", data)
			if err == nil {
				_, err = l.resolve(doc.node, doc, 1)
			}
			if err == nil || opens != 0 {
				t.Fatalf("error=%v, opens=%d", err, opens)
			}
		})
	}
	_, err := Load([]byte("$ref: './never-open.yaml'"))
	loadErrorCode(t, err, "POLICY_REF_EXTERNAL_INLINE")
}

func TestSecureReferencedFilesAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	outside := writePolicyFile(t, t.TempDir(), "outside.yaml", "outside: secret\n")
	writePolicyFile(t, dir, "good.yaml", "value: accepted\n")
	if err := os.Symlink("good.yaml", filepath.Join(dir, "inside.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escape.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ target, code string }{
		{"inside.yaml", ""}, {"escape.yaml", "POLICY_FILE_OPEN"}, {"missing.yaml", "POLICY_FILE_OPEN"}, {"directory", "POLICY_FILE_REGULAR"},
	} {
		writePolicyFile(t, dir, "policy.yaml", "$ref: './"+test.target+"'\n")
		_, _, err := assembleTestPolicy(t, dir, "policy.yaml", defaultPolicyBudgets)
		if test.code == "" {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			loadErrorCode(t, err, test.code)
		}
	}
	for _, mode := range []os.FileMode{0o400, 0o640, 0o644, 0o660, os.ModeSetuid | 0o600} {
		writePolicyFile(t, dir, "policy.yaml", "$ref: './good.yaml'\n")
		if err := os.Chmod(filepath.Join(dir, "good.yaml"), mode); err != nil {
			t.Fatal(err)
		}
		_, _, err := assembleTestPolicy(t, dir, "policy.yaml", defaultPolicyBudgets)
		loadErrorCode(t, err, "POLICY_FILE_MODE")
	}
	if err := os.Chmod(filepath.Join(dir, "policy.yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFile(filepath.Join(dir, "policy.yaml"))
	loadErrorCode(t, err, "POLICY_FILE_MODE")
}

func TestReferenceDocumentsCachedAndErrorsSurviveOverrides(t *testing.T) {
	dir := t.TempDir()
	writePolicyFile(t, dir, "policy.yaml", "a: {$ref: './base.yaml'}\nb: {$ref: 'base.yaml', $override: {value: replacement}}\n")
	writePolicyFile(t, dir, "base.yaml", "value: original\n")
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	l := newPolicyLoader(root, defaultPolicyBudgets)
	counts := make(map[string]int)
	l.open = func(uri string) (*os.File, error) { counts[uri]++; return root.Open(uri) }
	doc, err := l.document("policy.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.resolve(doc.node, doc, 1); err != nil {
		t.Fatal(err)
	}
	if counts["base.yaml"] != 1 {
		t.Fatal("normalized URI was reread")
	}
	writePolicyFile(t, dir, "base.yaml", "value: {$ref: './missing.yaml'}\n")
	_, _, err = assembleTestPolicy(t, dir, "policy.yaml", defaultPolicyBudgets)
	problem := loadErrorCode(t, err, "POLICY_FILE_OPEN")
	if len(problem.Chain) != 2 || problem.Location.Document != 2 {
		t.Fatal("missing reference chain or origin")
	}
	writePolicyFile(t, dir, "base.yaml", "$ref: './policy.yaml'\n")
	_, _, err = assembleTestPolicy(t, dir, "policy.yaml", defaultPolicyBudgets)
	loadErrorCode(t, err, "POLICY_REF_CYCLE")
}

func TestEveryPolicyAssemblyBudget(t *testing.T) {
	for _, test := range []struct {
		name, main, other, code string
		adjust                  func(*policyBudgets)
	}{
		{"file", "value: long\n", "", "POLICY_FILE_LIMIT", func(b *policyBudgets) { b.fileBytes = 5 }},
		{"total", "$ref: './other.yaml'\n", "value: long\n", "POLICY_READ_LIMIT", func(b *policyBudgets) { b.readBytes = 25 }},
		{"documents", "$ref: './other.yaml'\n", "value: long\n", "POLICY_DOCUMENT_LIMIT", func(b *policyBudgets) { b.documents = 1 }},
		{"depth", "[[[a]]]", "", "POLICY_DEPTH_LIMIT", func(b *policyBudgets) { b.depth = 3 }},
		{"ref", "$ref: '#/value'\n", "", "POLICY_REF_LIMIT", func(b *policyBudgets) { b.refBytes = 2 }},
		{"source", "[a, b, c]", "", "POLICY_SOURCE_LIMIT", func(b *policyBudgets) { b.sourceNodes = 3 }},
		{"expanded aliases", "a: &a [x, y]\nb: *a\n", "", "POLICY_EXPANSION_LIMIT", func(b *policyBudgets) { b.expandedNodes = 8 }},
		{"expanded references", "a: [x, y]\nb: {$ref: '#/a'}\n", "", "POLICY_EXPANSION_LIMIT", func(b *policyBudgets) { b.expandedNodes = 8 }},
		{"intermediate override", "a: {x: [one, two]}\nb: {$ref: '#/a', $override: {x: []}}", "", "POLICY_EXPANSION_LIMIT", func(b *policyBudgets) { b.expandedNodes = 14 }},
		{"assembled", "'\\u0000\\u0001'", "", "POLICY_ASSEMBLED_LIMIT", func(b *policyBudgets) { b.assembledBytes = 10 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			writePolicyFile(t, dir, "policy.yaml", test.main)
			if test.other != "" {
				writePolicyFile(t, dir, "other.yaml", test.other)
			}
			budgets := defaultPolicyBudgets
			test.adjust(&budgets)
			_, _, err := assembleTestPolicy(t, dir, "policy.yaml", budgets)
			loadErrorCode(t, err, test.code)
		})
	}
	// Real fixed limits: bounded reads, source tree allocation, reference text,
	// and alias amplification are enforced without changing production limits.
	_, err := Load(make([]byte, maxPolicyFileBytes+1))
	loadErrorCode(t, err, "POLICY_FILE_LIMIT")
	_, err = Load([]byte("$ref: '" + strings.Repeat("a", maxPolicyRefBytes+1) + "'"))
	loadErrorCode(t, err, "POLICY_REF_LIMIT")
	_, err = Load([]byte("[" + strings.Repeat("a,", maxPolicySourceNodes) + "a]"))
	loadErrorCode(t, err, "POLICY_SOURCE_LIMIT")
	var bomb strings.Builder
	bomb.WriteString("a0: &a0 [x, x]\n")
	for i := 1; i < 19; i++ {
		fmt.Fprintf(&bomb, "a%d: &a%d [*a%d, *a%d]\n", i, i, i-1, i-1)
	}
	_, err = Load([]byte(bomb.String()))
	loadErrorCode(t, err, "POLICY_EXPANSION_LIMIT")
}

func TestStrictTypesPresenceAndOverridesBeforeStartup(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var original yaml.Node
	if err := yaml.Unmarshal(data, &original); err != nil {
		t.Fatal(err)
	}
	// Every required field, and every type-bearing field, is exercised by
	// walking the closed typed schema instead of duplicating its field list.
	var walk func(*yaml.Node, reflect.Type)
	walk = func(n *yaml.Node, typ reflect.Type) {
		if typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		switch typ.Kind() {
		case reflect.Struct:
			for _, key := range requiredPolicyFields(typ) {
				copy := *n
				copy.Content = append([]*yaml.Node(nil), n.Content...)
				for i := 0; i < len(copy.Content); i += 2 {
					if copy.Content[i].Value == key {
						copy.Content = append(copy.Content[:i], copy.Content[i+2:]...)
						break
					}
				}
				l := newPolicyLoader(nil, defaultPolicyBudgets)
				if err := l.strict(&copy, typ); err == nil {
					t.Fatalf("required field %s accepted", key)
				}
			}
			for i := 0; i < typ.NumField(); i++ {
				key := typ.Field(i).Tag.Get("yaml")
				child := mappingValue(n, key)
				if child != nil {
					walk(child, typ.Field(i).Type)
				}
			}
		case reflect.Map:
			for i := 1; i < len(n.Content); i += 2 {
				walk(n.Content[i], typ.Elem())
			}
		case reflect.Slice:
			for _, child := range n.Content {
				walk(child, typ.Elem())
			}
		case reflect.String, reflect.Bool, reflect.Int, reflect.Uint64:
			for _, invalid := range []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!null"}, {Kind: yaml.MappingNode, Tag: "!!map"}, {Kind: yaml.SequenceNode, Tag: "!!seq"}} {
				l := newPolicyLoader(nil, defaultPolicyBudgets)
				if err := l.strict(invalid, typ); err == nil {
					t.Fatalf("invalid scalar accepted as %v", typ)
				}
			}
			var invalid yaml.Node
			if typ.Kind() == reflect.String {
				invalid = yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "false"}
			} else {
				invalid = yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "1"}
			}
			if err := newPolicyLoader(nil, defaultPolicyBudgets).strict(&invalid, typ); err == nil {
				t.Fatalf("coercion accepted as %v", typ)
			}
		}
	}
	walk(original.Content[0], reflect.TypeFor[Config]())
	dir := t.TempDir()
	writePolicyFile(t, dir, "base.yaml", string(data))
	for _, override := range []string{"version: '2'", "profiles: {}", "extra: 1", "version: null", "version: 999999999999999999999", "hard_limits: {max_rows: 1}"} {
		path := writePolicyFile(t, dir, "policy.yaml", "$ref: './base.yaml'\n$override:\n"+indentYAML(override, 2))
		if _, err := LoadFile(path); err == nil {
			t.Fatal("invalid override accepted")
		}
	}
}

func TestOverriddenProfilesAndSnapshotsHaveNoMutableAliases(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	profiles := mappingValue(document.Content[0], "profiles")
	base := mappingValue(profiles, "analytics")
	bytes, err := yaml.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writePolicyFile(t, dir, "analytics.yaml", string(bytes))
	*base = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "$ref"}, {Kind: yaml.ScalarNode, Tag: "!!str", Value: "./analytics.yaml"}}}
	var rc yaml.Node
	if err := yaml.Unmarshal([]byte("$ref: './analytics.yaml'\n$override: {datasources: [primary-mysql]}"), &rc); err != nil {
		t.Fatal(err)
	}
	profiles.Content = append(profiles.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "rc"}, rc.Content[0])
	assembled, err := yaml.Marshal(&document)
	if err != nil {
		t.Fatal(err)
	}
	path := writePolicyFile(t, dir, "policy.yaml", string(assembled))
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	baseProfile := cfg.Profiles["analytics"]
	rcProfile := cfg.Profiles["rc"]
	baseProfile.Operations[0] = "changed"
	baseProfile.Resources.Fields.Allow[0] = "changed"
	baseProfile.Query.AggregateShapes[0].Projection[0].Field = "changed"
	baseProfile.Query.KeysetSelectShapes[0].Projection[0].Field = "changed"
	*baseProfile.Query.AggregateShapes[1].Filter.ValueTypes = []string{"changed"}
	if rcProfile.Operations[0] == "changed" || rcProfile.Resources.Fields.Allow[0] == "changed" || rcProfile.Query.AggregateShapes[0].Projection[0].Field == "changed" || rcProfile.Query.KeysetSelectShapes[0].Projection[0].Field == "changed" || (*rcProfile.Query.AggregateShapes[1].Filter.ValueTypes)[0] == "changed" {
		t.Fatal("profiles share mutable storage")
	}
	if _, err := LoadFile(path); err != nil {
		t.Fatal("another load was affected by mutation")
	}
}

func TestPolicyDiagnosticsContainOnlyCodesAndLocations(t *testing.T) {
	secret := "opaque-secret-NO-LOG"
	for _, input := range []string{"$ref: 'https://" + secret + "/file'", secret + ": {broken: [", "$ref: './" + secret + ".yaml'", "a: 1\na: " + secret} {
		_, err := Load([]byte(input))
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("unsafe diagnostic=%v", err)
		}
		var problem *LoadError
		if !errors.As(err, &problem) {
			t.Fatal("unclassified diagnostic")
		}
	}
	var out bytes.Buffer
	for _, value := range []string{"\u0085", "\u2028", "\u2029", "\x00", "quote\"\\", "кириллица<&>"} {
		out.Reset()
		writeJSONString(&out, value)
		if out.Len() != jsonStringSize(value) {
			t.Fatal("encoded size differs")
		}
		var decoded string
		if err := yaml.Unmarshal(out.Bytes(), &decoded); err != nil || decoded != value {
			t.Fatal("scalar changed during assembly")
		}
	}
}

func TestYAMLNativeSpellingsAndReservedAliasesRemainTyped(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := Load(data)
	if err != nil {
		t.Fatal(err)
	}
	spellings := strings.Replace(string(data), "version: 1", "version: 0x1", 1)
	spellings = strings.Replace(spellings, "tls_required: true", "tls_required: TRUE", 1)
	got, err := Load([]byte(spellings))
	if err != nil || !reflect.DeepEqual(got, baseline) {
		t.Fatalf("native YAML spellings changed types: %v", err)
	}
	dir := t.TempDir()
	writePolicyFile(t, dir, "value.yaml", "value: original\n")
	writePolicyFile(t, dir, "policy.yaml", "path: &path './value.yaml'\nchanges: &changes {value: replacement}\nref: {$ref: *path, $override: *changes}\n")
	_, node, err := assembleTestPolicy(t, dir, "policy.yaml", defaultPolicyBudgets)
	if err != nil {
		t.Fatal(err)
	}
	if mappingValue(mappingValue(node.node, "ref"), "value").Value != "replacement" {
		t.Fatal("reserved field aliases were not resolved")
	}
}

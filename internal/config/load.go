package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/sigalx/quordon/internal/domain"
	"gopkg.in/yaml.v3"
)

// These limits apply to inline policies too. They are independent of request
// limits: configuration must be bounded before a policy snapshot exists.
const (
	maxPolicyFileBytes      = 8 << 20
	maxPolicyReadBytes      = 16 << 20
	maxPolicyDocuments      = 64
	maxPolicyDepth          = 64
	maxPolicyRefBytes       = 4096
	maxPolicySourceNodes    = 250_000
	maxPolicyExpandedNodes  = 250_000
	maxPolicyAssembledBytes = 16 << 20
)

// PolicyLocation uses document ordinals, never filenames, keys or values. Even
// an invalid filename or mapping key may contain credential material.
type PolicyLocation struct {
	Document int
	Line     int
	Column   int
}

// LoadError deliberately has no wrapped parser, filesystem or semantic error.
// Code and numeric locations are safe to put in application logs.
type LoadError struct {
	Code     string
	Location PolicyLocation
	Chain    []PolicyLocation
}

func (e *LoadError) Error() string {
	var out strings.Builder
	fmt.Fprintf(&out, "%s at document %d:%d:%d", e.Code, e.Location.Document, e.Location.Line, e.Location.Column)
	for _, at := range e.Chain {
		fmt.Fprintf(&out, " <- document %d:%d:%d", at.Document, at.Line, at.Column)
	}
	return out.String()
}

type policyBudgets struct {
	fileBytes, readBytes, documents, depth, refBytes, sourceNodes, expandedNodes, assembledBytes int
}

var defaultPolicyBudgets = policyBudgets{
	maxPolicyFileBytes, maxPolicyReadBytes, maxPolicyDocuments, maxPolicyDepth,
	maxPolicyRefBytes, maxPolicySourceNodes, maxPolicyExpandedNodes, maxPolicyAssembledBytes,
}

type policyDocument struct {
	uri  string
	id   int
	node *yaml.Node
}

type resolvedPolicyNode struct {
	node   *yaml.Node
	nodes  int
	size   int // exact size of the assembled JSON (also valid YAML) representation
	height int
}

type policyLoader struct {
	root                                  *os.Root
	budgets                               policyBudgets
	documents                             map[string]*policyDocument
	locations                             map[*yaml.Node]PolicyLocation
	chains                                map[*yaml.Node][]PolicyLocation
	indexes                               map[*yaml.Node]map[string]*yaml.Node
	resolved                              map[*yaml.Node]resolvedPolicyNode // immutable, including shared ref targets
	active                                map[*yaml.Node]bool
	chain                                 []PolicyLocation
	readBytes, sourceNodes, expandedNodes int
	// A narrow seam verifies that rejected references never open their targets.
	open func(string) (*os.File, error)
}

func newPolicyLoader(root *os.Root, budgets policyBudgets) *policyLoader {
	l := &policyLoader{
		root: root, budgets: budgets,
		documents: make(map[string]*policyDocument), locations: make(map[*yaml.Node]PolicyLocation),
		resolved: make(map[*yaml.Node]resolvedPolicyNode), active: make(map[*yaml.Node]bool), chains: make(map[*yaml.Node][]PolicyLocation), indexes: make(map[*yaml.Node]map[string]*yaml.Node),
	}
	if root != nil {
		// O_NONBLOCK prevents a FIFO from hanging before descriptor Stat can
		// reject it. It does not change ordinary regular-file reads.
		l.open = func(path string) (*os.File, error) { return root.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) }
	}
	return l
}

// Load accepts inline configuration and document-local references. External
// references are rejected without any filesystem access.
func Load(data []byte) (Config, error) {
	l := newPolicyLoader(nil, defaultPolicyBudgets)
	doc, err := l.parse("", data)
	if err != nil {
		return Config{}, err
	}
	return l.load(doc)
}

// LoadFile confines all references, including symlinks, to the main policy's
// directory. Every opened descriptor must be a regular file with mode 0600.
func LoadFile(path string) (Config, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return Config{}, &LoadError{Code: "POLICY_FILE_OPEN", Location: PolicyLocation{Document: 1}}
	}
	defer root.Close()
	l := newPolicyLoader(root, defaultPolicyBudgets)
	doc, err := l.document(filepath.Base(path), nil)
	if err != nil {
		return Config{}, err
	}
	return l.load(doc)
}

func (l *policyLoader) fail(code string, node *yaml.Node) error {
	at := l.locations[node]
	if at.Document == 0 {
		at.Document = 1
	}
	chain := l.chain
	if len(chain) == 0 {
		chain = l.chains[node]
	}
	return &LoadError{Code: code, Location: at, Chain: append([]PolicyLocation(nil), chain...)}
}

func (l *policyLoader) document(uri string, from *yaml.Node) (*policyDocument, error) {
	if doc, ok := l.documents[uri]; ok {
		return doc, nil
	}
	if l.root == nil {
		return nil, l.fail("POLICY_REF_EXTERNAL_INLINE", from)
	}
	if len(l.documents) >= l.budgets.documents {
		return nil, l.fail("POLICY_DOCUMENT_LIMIT", from)
	}
	remaining := l.budgets.readBytes - l.readBytes
	if remaining <= 0 {
		return nil, l.fail("POLICY_READ_LIMIT", from)
	}
	file, err := l.open(uri)
	if err != nil {
		return nil, l.fail("POLICY_FILE_OPEN", from)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, l.fail("POLICY_FILE_STAT", from)
	}
	if !info.Mode().IsRegular() {
		return nil, l.fail("POLICY_FILE_REGULAR", from)
	}
	if info.Mode() != RequiredFileMode {
		return nil, l.fail("POLICY_FILE_MODE", from)
	}
	if info.Size() > int64(l.budgets.fileBytes) {
		return nil, l.fail("POLICY_FILE_LIMIT", from)
	}
	if info.Size() > int64(remaining) {
		return nil, l.fail("POLICY_READ_LIMIT", from)
	}
	// The descriptor may grow after Stat. Never read past either budget; an
	// additional Stat detects growth without consuming an out-of-budget byte.
	limit := min(l.budgets.fileBytes, remaining)
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)))
	if err != nil {
		return nil, l.fail("POLICY_FILE_READ", from)
	}
	if len(data) == limit {
		after, err := file.Stat()
		if err != nil {
			return nil, l.fail("POLICY_FILE_STAT", from)
		}
		if after.Size() > int64(limit) {
			code := "POLICY_FILE_LIMIT"
			if remaining < l.budgets.fileBytes {
				code = "POLICY_READ_LIMIT"
			}
			return nil, l.fail(code, from)
		}
	}
	return l.parse(uri, data)
}

func (l *policyLoader) parse(uri string, data []byte) (*policyDocument, error) {
	id := len(l.documents) + 1
	at := &yaml.Node{Line: 1, Column: 1}
	l.locations[at] = PolicyLocation{id, 1, 1}
	if len(l.documents) >= l.budgets.documents {
		return nil, l.fail("POLICY_DOCUMENT_LIMIT", at)
	}
	if len(data) > l.budgets.fileBytes {
		return nil, l.fail("POLICY_FILE_LIMIT", at)
	}
	if len(data) > l.budgets.readBytes-l.readBytes {
		return nil, l.fail("POLICY_READ_LIMIT", at)
	}
	l.readBytes += len(data)
	if !utf8.Valid(data) {
		return nil, l.fail("POLICY_UTF8", at)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if l.sourceNodes >= l.budgets.sourceNodes {
		return nil, l.fail("POLICY_SOURCE_LIMIT", at)
	}
	decoder.NodeLimits(l.budgets.sourceNodes-l.sourceNodes, l.budgets.depth)
	var node yaml.Node
	if err := decoder.Decode(&node); err != nil {
		var limit *yaml.NodeLimitError
		if errors.As(err, &limit) {
			l.locations[at] = PolicyLocation{id, limit.Line, limit.Column}
			code := "POLICY_SOURCE_LIMIT"
			if limit.Kind == "depth" {
				code = "POLICY_DEPTH_LIMIT"
			}
			return nil, l.fail(code, at)
		}
		return nil, l.fail("POLICY_YAML", at)
	}
	if len(node.Content) != 1 {
		return nil, l.fail("POLICY_YAML", at)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, l.fail("POLICY_DOCUMENT_COUNT", at)
	}
	doc := &policyDocument{uri: uri, id: id, node: node.Content[0]}
	if err := l.scan(doc.node, doc, 1); err != nil {
		return nil, err
	}
	if err := l.checkAliases(doc.node, make(map[*yaml.Node]bool), 1); err != nil {
		return nil, err
	}
	l.documents[uri] = doc
	return doc, nil
}

// scan visits source nodes once. Aliases are graph edges, not recursively
// traversed source nodes. Their full expansion is charged by resolve.
func (l *policyLoader) scan(n *yaml.Node, doc *policyDocument, depth int) error {
	l.locations[n] = PolicyLocation{doc.id, n.Line, n.Column}
	l.chains[n] = l.chain
	if depth > l.budgets.depth {
		return l.fail("POLICY_DEPTH_LIMIT", n)
	}
	if l.sourceNodes >= l.budgets.sourceNodes {
		return l.fail("POLICY_SOURCE_LIMIT", n)
	}
	l.sourceNodes++
	if n.Tag == "!!null" {
		return l.fail("POLICY_NULL", n)
	}
	switch n.Kind {
	case yaml.MappingNode:
		if n.Tag != "!!map" {
			return l.fail("POLICY_YAML_TAG", n)
		}
		seen := make(map[string]*yaml.Node, len(n.Content)/2)
		hasRef, hasOverride := false, false
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			l.locations[key] = PolicyLocation{doc.id, key.Line, key.Column}
			if key.Tag == "!!merge" || key.Value == "<<" {
				return l.fail("POLICY_YAML_MERGE", key)
			}
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return l.fail("POLICY_YAML_KEY", key)
			}
			if seen[key.Value] != nil {
				return l.fail("POLICY_YAML_DUPLICATE", key)
			}
			seen[key.Value] = n.Content[i+1]
			hasRef = hasRef || key.Value == "$ref"
			hasOverride = hasOverride || key.Value == "$override"
		}
		l.indexes[n] = seen
		if hasOverride && !hasRef {
			return l.fail("POLICY_REF_REQUIRED", n)
		}
		if hasRef {
			if len(n.Content)/2 != 1+boolInt(hasOverride) {
				return l.fail("POLICY_REF_FIELDS", n)
			}
			ref := mappingValue(n, "$ref")
			ref, err := resolveYAMLAlias(ref, "")
			if err != nil {
				return l.fail("POLICY_YAML_ALIAS_CYCLE", n)
			}
			if ref.Kind != yaml.ScalarNode || ref.Tag != "!!str" || ref.Value == "" {
				return l.fail("POLICY_REF_TYPE", n)
			}
			if len(ref.Value) > l.budgets.refBytes {
				return l.fail("POLICY_REF_LIMIT", n)
			}
			if hasOverride {
				override, err := resolveYAMLAlias(mappingValue(n, "$override"), "")
				if err != nil {
					return l.fail("POLICY_YAML_ALIAS_CYCLE", n)
				}
				if override.Kind != yaml.MappingNode {
					return l.fail("POLICY_OVERRIDE_TYPE", n)
				}
			}
		}
	case yaml.SequenceNode:
		if n.Tag != "!!seq" {
			return l.fail("POLICY_YAML_TAG", n)
		}
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str", "!!int", "!!float", "!!bool":
		default:
			return l.fail("POLICY_YAML_TAG", n)
		}
	case yaml.AliasNode:
		if n.Alias == nil {
			return l.fail("POLICY_YAML_ALIAS", n)
		}
	default:
		return l.fail("POLICY_YAML", n)
	}
	for _, child := range n.Content {
		if err := l.scan(child, doc, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func (l *policyLoader) lookup(n *yaml.Node, key string) *yaml.Node {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	index, ok := l.indexes[n]
	if !ok {
		index = make(map[string]*yaml.Node, len(n.Content)/2)
		for i := 0; i < len(n.Content); i += 2 {
			index[n.Content[i].Value] = n.Content[i+1]
		}
		l.indexes[n] = index
	}
	return index[key]
}

// Memoization avoids exponential alias traversal even in an unused library
// branch. The active set still rejects recursive aliases everywhere.
func (l *policyLoader) checkAliases(n *yaml.Node, active map[*yaml.Node]bool, depth int) error {
	heights := make(map[*yaml.Node]int)
	var visit func(*yaml.Node, int) (int, error)
	visit = func(node *yaml.Node, nesting int) (int, error) {
		if nesting > l.budgets.depth {
			return 0, l.fail("POLICY_DEPTH_LIMIT", node)
		}
		if active[node] {
			return 0, l.fail("POLICY_YAML_ALIAS_CYCLE", node)
		}
		if h, ok := heights[node]; ok {
			if h+nesting-1 > l.budgets.depth {
				return 0, l.fail("POLICY_DEPTH_LIMIT", node)
			}
			return h, nil
		}
		active[node] = true
		defer delete(active, node)
		h := 1
		children := node.Content
		if node.Kind == yaml.AliasNode {
			children = []*yaml.Node{node.Alias}
		}
		for _, child := range children {
			ch, err := visit(child, nesting+1)
			if err != nil {
				return 0, err
			}
			h = max(h, 1+ch)
			if h > l.budgets.depth {
				return 0, l.fail("POLICY_DEPTH_LIMIT", node)
			}
		}
		heights[node] = h
		return h, nil
	}
	_, err := visit(n, depth)
	return err
}

func (l *policyLoader) reference(doc *policyDocument, ref string, from *yaml.Node) (*policyDocument, []string, error) {
	// Validate the entire URI and pointer before attempting to open a target.
	u, err := url.Parse(ref)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || strings.HasPrefix(ref, "//") {
		return nil, nil, l.fail("POLICY_REF_URI", from)
	}
	if !utf8.ValidString(u.Fragment) || (u.Fragment != "" && !strings.HasPrefix(u.Fragment, "/")) {
		return nil, nil, l.fail("POLICY_REF_POINTER", from)
	}
	var tokens []string
	if u.Fragment != "" {
		for _, token := range strings.Split(u.Fragment[1:], "/") {
			for i := 0; i < len(token); i++ {
				if token[i] == '~' {
					if i+1 == len(token) || token[i+1] != '0' && token[i+1] != '1' {
						return nil, nil, l.fail("POLICY_REF_POINTER", from)
					}
					i++
				}
			}
			tokens = append(tokens, strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~"))
		}
	}
	if u.Path == "" {
		return doc, tokens, nil
	}
	if strings.ContainsAny(u.Path, "\\\x00") || filepath.IsAbs(u.Path) || !utf8.ValidString(u.Path) {
		return nil, nil, l.fail("POLICY_REF_PATH", from)
	}
	if !filepath.IsLocal(u.Path) { // Parent traversal is permitted only when the normalized result stays under root.
		if !strings.HasPrefix(u.Path, "../") {
			return nil, nil, l.fail("POLICY_REF_PATH", from)
		}
	}
	uri := filepath.Clean(filepath.Join(filepath.Dir(doc.uri), u.Path))
	if !filepath.IsLocal(uri) {
		return nil, nil, l.fail("POLICY_REF_PATH", from)
	}
	target, err := l.document(uri, from)
	return target, tokens, err
}

func (l *policyLoader) target(doc *policyDocument, tokens []string, from *yaml.Node) (*yaml.Node, error) {
	n := doc.node
	for _, token := range tokens {
		for n.Kind == yaml.AliasNode {
			n = n.Alias
		} // acyclicity was checked before document publication
		switch n.Kind {
		case yaml.MappingNode:
			n = l.lookup(n, token)
			if n == nil {
				return nil, l.fail("POLICY_REF_TARGET", from)
			}
		case yaml.SequenceNode:
			if !canonicalUnsignedDecimal(token) {
				return nil, l.fail("POLICY_REF_POINTER", from)
			}
			index, err := strconv.ParseUint(token, 10, 64)
			if err != nil || index >= uint64(len(n.Content)) {
				return nil, l.fail("POLICY_REF_TARGET", from)
			}
			n = n.Content[int(index)]
		default:
			return nil, l.fail("POLICY_REF_TARGET", from)
		}
	}
	return n, nil
}

func (l *policyLoader) charge(count int, n *yaml.Node) error {
	if count > l.budgets.expandedNodes-l.expandedNodes {
		return l.fail("POLICY_EXPANSION_LIMIT", n)
	}
	l.expandedNodes += count
	return nil
}

func (l *policyLoader) resolve(n *yaml.Node, doc *policyDocument, depth int) (resolvedPolicyNode, error) {
	if depth > l.budgets.depth {
		return resolvedPolicyNode{}, l.fail("POLICY_DEPTH_LIMIT", n)
	}
	if l.active[n] {
		return resolvedPolicyNode{}, l.fail("POLICY_REF_CYCLE", n)
	}
	if cached, ok := l.resolved[n]; ok {
		if cached.height+depth-1 > l.budgets.depth {
			return resolvedPolicyNode{}, l.fail("POLICY_DEPTH_LIMIT", n)
		}
		return cached, l.charge(cached.nodes, n)
	}
	l.active[n] = true
	defer delete(l.active, n)
	var result resolvedPolicyNode
	if n.Kind == yaml.AliasNode {
		var err error
		result, err = l.resolve(n.Alias, doc, depth+1)
		if err != nil {
			return result, err
		}
		result.height++
	} else if ref := l.lookup(n, "$ref"); ref != nil {
		ref, _ = resolveYAMLAlias(ref, "") // validated source graph
		previousChain := l.chain
		l.chain = append(append([]PolicyLocation(nil), previousChain...), l.locations[n])
		defer func() { l.chain = previousChain }()
		targetDoc, tokens, err := l.reference(doc, ref.Value, n)
		if err != nil {
			return result, err
		}
		target, err := l.target(targetDoc, tokens, n)
		if err != nil {
			return result, err
		}
		result, err = l.resolve(target, targetDoc, depth+1)
		if err != nil {
			return result, err
		}
		if override := mappingValue(n, "$override"); override != nil {
			override, _ = resolveYAMLAlias(override, "")
			if result.node.Kind != yaml.MappingNode {
				return result, l.fail("POLICY_OVERRIDE_TARGET", n)
			}
			// Resolve the complete base first, including overwritten branches.
			// Override values keep the referring document as their origin.
			fields := make(map[string]resolvedPolicyNode, len(override.Content)/2)
			keys := make(map[string]resolvedPolicyNode, len(override.Content)/2)
			for i := 0; i < len(override.Content); i += 2 {
				key := override.Content[i]
				value, err := l.resolve(override.Content[i+1], doc, depth+1)
				if err != nil {
					return result, err
				}
				keyResult, err := l.resolve(key, doc, depth+1)
				if err != nil {
					return result, err
				}
				fields[key.Value] = value
				keys[key.Value] = keyResult
			}
			// No mutation of cached nodes. A new mapping owns its Content;
			// retained children are immutable and typed decode copies them.
			childCount := len(result.node.Content)
			for i := 0; i < len(override.Content); i += 2 {
				if l.lookup(result.node, override.Content[i].Value) == nil {
					childCount += 2
				}
			}
			if childCount >= l.budgets.expandedNodes {
				return result, l.fail("POLICY_EXPANSION_LIMIT", n)
			}
			children := make([]resolvedPolicyNode, 0, childCount)
			for i := 0; i < len(result.node.Content); i += 2 {
				key := result.node.Content[i]
				if value, ok := fields[key.Value]; ok {
					children = append(children, keys[key.Value], value)
					delete(fields, key.Value)
				} else {
					children = append(children, l.resolved[key], l.resolved[result.node.Content[i+1]])
				}
			}
			for i := 0; i < len(override.Content); i += 2 {
				key := override.Content[i]
				if value, ok := fields[key.Value]; ok {
					children = append(children, keys[key.Value], value)
				}
			}
			result, err = l.container(n, yaml.MappingNode, children, depth)
			if err != nil {
				return result, err
			}
		}
		result.height++
	} else if n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode {
		children := make([]resolvedPolicyNode, 0, len(n.Content))
		for _, child := range n.Content {
			resolved, err := l.resolve(child, doc, depth+1)
			if err != nil {
				return result, err
			}
			children = append(children, resolved)
		}
		var err error
		result, err = l.container(n, n.Kind, children, depth)
		if err != nil {
			return result, err
		}
	} else {
		if err := l.charge(1, n); err != nil {
			return result, err
		}
		size := len(n.Value)
		if n.Tag == "!!str" {
			size = jsonStringSize(n.Value)
		} else if n.Tag == "!!int" || n.Tag == "!!bool" {
			text, err := yamlScalarText(n)
			if err != nil {
				return result, l.fail("POLICY_INTEGER_RANGE", n)
			}
			size = len(text)
		}
		if size > l.budgets.assembledBytes {
			return result, l.fail("POLICY_ASSEMBLED_LIMIT", n)
		}
		copy := *n
		copy.Anchor = ""
		copy.HeadComment = ""
		copy.LineComment = ""
		copy.FootComment = ""
		result = resolvedPolicyNode{&copy, 1, size, 1}
		l.locations[&copy] = l.locations[n]
		l.chains[&copy] = l.chain
	}
	if result.height+depth-1 > l.budgets.depth {
		return result, l.fail("POLICY_DEPTH_LIMIT", n)
	}
	l.resolved[n] = result
	// Also index new immutable nodes, used when rebuilding an override mapping.
	if _, ok := l.resolved[result.node]; !ok {
		l.resolved[result.node] = result
	}
	return result, nil
}

func (l *policyLoader) container(origin *yaml.Node, kind yaml.Kind, children []resolvedPolicyNode, depth int) (resolvedPolicyNode, error) {
	if err := l.charge(1, origin); err != nil {
		return resolvedPolicyNode{}, err
	}
	result := resolvedPolicyNode{nodes: 1, size: 2, height: 1}
	if len(children) > 0 {
		result.size += len(children) - 1
	}
	for _, child := range children {
		if child.nodes > l.budgets.expandedNodes-result.nodes {
			return result, l.fail("POLICY_EXPANSION_LIMIT", origin)
		}
		result.nodes += child.nodes
		if child.size > l.budgets.assembledBytes-result.size {
			return result, l.fail("POLICY_ASSEMBLED_LIMIT", origin)
		}
		result.size += child.size
		result.height = max(result.height, child.height+1)
	}
	if result.size > l.budgets.assembledBytes {
		return result, l.fail("POLICY_ASSEMBLED_LIMIT", origin)
	}
	if result.height+depth-1 > l.budgets.depth {
		return result, l.fail("POLICY_DEPTH_LIMIT", origin)
	}
	node := &yaml.Node{Kind: kind, Tag: "!!seq", Line: origin.Line, Column: origin.Column, Content: make([]*yaml.Node, len(children))}
	if kind == yaml.MappingNode {
		node.Tag = "!!map"
	}
	for i, child := range children {
		node.Content[i] = child.node
	}
	l.locations[node] = l.locations[origin]
	l.chains[node] = l.chain
	result.node = node
	return result, nil
}

// Exact JSON string size with HTML escaping disabled. Counting comes before
// either quoting or allocating a buffer for the assembled representation.
func jsonStringSize(s string) int {
	size := 2
	for _, r := range s {
		switch r {
		case '"', '\\', '\b', '\f', '\n', '\r', '\t':
			size += 2
		case '\u0085', '\u2028', '\u2029':
			size += 6
		default:
			if r < 0x20 {
				size += 6
			} else {
				size += utf8.RuneLen(r)
			}
		}
	}
	return size
}

func (l *policyLoader) load(doc *policyDocument) (Config, error) {
	assembled, err := l.resolve(doc.node, doc, 1)
	if err != nil {
		return Config{}, err
	}
	if err := l.strict(assembled.node, reflect.TypeFor[Config]()); err != nil {
		return Config{}, err
	}
	if err := validatePolicyYAMLNode(assembled.node, "policy", make(map[*yaml.Node]struct{})); err != nil {
		return Config{}, l.fail("POLICY_SHAPE", l.errorNode(assembled.node, err))
	}
	// The graph is fully bounded and contains no aliases or references now.
	// A strict KnownFields decode provides an independent closed-field check.
	var buffer bytes.Buffer
	buffer.Grow(assembled.size)
	writeAssembledJSON(&buffer, assembled.node)
	decoder := yaml.NewDecoder(&buffer)
	decoder.KnownFields(true)
	decoder.NodeLimits(assembled.nodes, l.budgets.depth)
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, l.fail("POLICY_DECODE", assembled.node)
	}
	finished, err := finishLoad(cfg)
	if err != nil {
		return Config{}, l.fail("POLICY_SEMANTIC", l.errorNode(assembled.node, err))
	}
	return finished, nil
}

func writeAssembledJSON(out *bytes.Buffer, n *yaml.Node) {
	switch n.Kind {
	case yaml.MappingNode:
		out.WriteByte('{')
		for i := 0; i < len(n.Content); i += 2 {
			if i > 0 {
				out.WriteByte(',')
			}
			writeAssembledJSON(out, n.Content[i])
			out.WriteByte(':')
			writeAssembledJSON(out, n.Content[i+1])
		}
		out.WriteByte('}')
	case yaml.SequenceNode:
		out.WriteByte('[')
		for i, child := range n.Content {
			if i > 0 {
				out.WriteByte(',')
			}
			writeAssembledJSON(out, child)
		}
		out.WriteByte(']')
	case yaml.ScalarNode:
		if n.Tag == "!!str" {
			// strconv.AppendQuote can emit Go-only escapes. A JSON encoder
			// handles control characters and Unicode without an intermediate tree.
			writeJSONString(out, n.Value)
		} else {
			text, _ := yamlScalarText(n) // strict validation has already succeeded
			out.WriteString(text)
		}
	}
}

// YAML-native integer and boolean spellings are preserved as those types,
// then rendered canonically as JSON. Shape-specific lexical validation still
// sees the original node spelling and style.
func yamlScalarText(n *yaml.Node) (string, error) {
	if n.Tag == "!!bool" {
		var value bool
		if err := n.Decode(&value); err != nil {
			return "", err
		}
		return strconv.FormatBool(value), nil
	}
	if n.Tag == "!!int" {
		var unsigned uint64
		if err := n.Decode(&unsigned); err == nil {
			return strconv.FormatUint(unsigned, 10), nil
		}
		var signed int64
		if err := n.Decode(&signed); err != nil {
			return "", err
		}
		return strconv.FormatInt(signed, 10), nil
	}
	return n.Value, nil
}

func writeJSONString(out *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteRune(r)
		case '\b':
			out.WriteString("\\b")
		case '\f':
			out.WriteString("\\f")
		case '\n':
			out.WriteString("\\n")
		case '\r':
			out.WriteString("\\r")
		case '\t':
			out.WriteString("\\t")
		default:
			if r < 0x20 || r == '\u0085' || r == '\u2028' || r == '\u2029' {
				out.WriteString("\\u")
				out.WriteByte(hex[(r>>12)&15])
				out.WriteByte(hex[(r>>8)&15])
				out.WriteByte(hex[(r>>4)&15])
				out.WriteByte(hex[r&15])
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}

// Map legacy validation paths to source locations; the raw error is discarded.
func (l *policyLoader) errorNode(root *yaml.Node, err error) *yaml.Node {
	path := strings.Fields(err.Error())[0]
	path = strings.TrimPrefix(path, "policy.")
	path = strings.TrimSuffix(path, ":")
	n := root
	for _, part := range strings.Split(path, ".") {
		field, indexText, hasIndex := strings.Cut(part, "[")
		child := mappingValue(n, field)
		if child == nil {
			break
		}
		n = child
		if hasIndex {
			index, err := strconv.Atoi(strings.TrimSuffix(indexText, "]"))
			if err != nil || n.Kind != yaml.SequenceNode || index < 0 || index >= len(n.Content) {
				break
			}
			n = n.Content[index]
		}
	}
	return n
}

func (l *policyLoader) strict(n *yaml.Node, t reflect.Type) error {
	if t.Kind() == reflect.Pointer {
		return l.strict(n, t.Elem())
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			return l.fail("POLICY_TYPE", n)
		}
		fields := make(map[string]reflect.Type, t.NumField())
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if name != "" && name != "-" {
				fields[name] = f.Type
			}
		}
		for i := 0; i < len(n.Content); i += 2 {
			field, ok := fields[n.Content[i].Value]
			if !ok {
				return l.fail("POLICY_UNKNOWN_FIELD", n.Content[i])
			}
			if err := l.strict(n.Content[i+1], field); err != nil {
				return err
			}
		}
		for _, key := range requiredPolicyFields(t) {
			if mappingValue(n, key) == nil {
				return l.fail("POLICY_REQUIRED", n)
			}
		}
	case reflect.Map:
		if n.Kind != yaml.MappingNode {
			return l.fail("POLICY_TYPE", n)
		}
		for i := 0; i < len(n.Content); i += 2 {
			if err := validateName("", n.Content[i].Value); err != nil {
				return l.fail("POLICY_IDENTIFIER", n.Content[i])
			}
			if err := l.strict(n.Content[i+1], t.Elem()); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if n.Kind != yaml.SequenceNode {
			return l.fail("POLICY_TYPE", n)
		}
		for _, child := range n.Content {
			if err := l.strict(child, t.Elem()); err != nil {
				return err
			}
		}
	case reflect.String:
		if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
			return l.fail("POLICY_TYPE", n)
		}
		if n.Value == "" {
			return l.fail("POLICY_EMPTY", n)
		}
	case reflect.Bool:
		if n.Kind != yaml.ScalarNode || n.Tag != "!!bool" {
			return l.fail("POLICY_TYPE", n)
		}
		var value bool
		if err := n.Decode(&value); err != nil {
			return l.fail("POLICY_TYPE", n)
		}
	case reflect.Int, reflect.Uint64:
		if n.Kind != yaml.ScalarNode || n.Tag != "!!int" {
			return l.fail("POLICY_TYPE", n)
		}
		if err := n.Decode(reflect.New(t).Interface()); err != nil {
			return l.fail("POLICY_INTEGER_RANGE", n)
		}
	default:
		return l.fail("POLICY_TYPE", n)
	}
	return nil
}

func requiredPolicyFields(t reflect.Type) []string {
	switch t {
	case reflect.TypeFor[Config]():
		return []string{"version", "hard_limits", "authentication", "principals", "datasources", "profiles"}
	case reflect.TypeFor[Authentication]():
		return []string{"basic"}
	case reflect.TypeFor[BasicAuth]():
		return []string{"users"}
	case reflect.TypeFor[BasicUser]():
		return []string{"principal"}
	case reflect.TypeFor[Principal]():
		return []string{"profiles"}
	case reflect.TypeFor[Datasource]():
		return []string{"adapter", "tls_required", "pool"}
	case reflect.TypeFor[PoolConfig]():
		return []string{"max_open_connections", "max_idle_connections", "max_connection_lifetime_seconds"}
	case reflect.TypeFor[Profile]():
		return []string{"datasource", "operations", "resources", "query", "limits"}
	case reflect.TypeFor[ResourcePolicy]():
		return []string{"schemas", "objects"}
	case reflect.TypeFor[domain.Limits]():
		return []string{"deadline_ms", "max_request_bytes", "max_projection_fields", "max_group_by_fields", "max_order_by_fields", "max_predicates", "max_expression_depth", "max_parameters", "max_rows", "max_result_bytes", "max_offset", "max_concurrency"}
	default:
		return nil
	}
}

package yaml

import (
	"errors"
	"strings"
	"testing"
)

func TestQuordonParserLimits(t *testing.T) {
	for _, test := range []struct {
		name, input, kind string
		nodes, depth      int
	}{
		{"nodes", "[a, b, c]", "nodes", 3, 64},
		{"flow depth", "[[[a]]]", "depth", 100, 3},
		{"block depth", "a:\n  b:\n    c: d\n", "depth", 100, 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			decoder := NewDecoder(strings.NewReader(test.input))
			decoder.NodeLimits(test.nodes, test.depth)
			var node Node
			err := decoder.Decode(&node)
			var limit *NodeLimitError
			if !errors.As(err, &limit) || limit.Kind != test.kind || limit.Line < 1 || limit.Column < 1 {
				t.Fatalf("error=%v", err)
			}
		})
	}
	decoder := NewDecoder(strings.NewReader("[a, b, c]"))
	decoder.NodeLimits(4, 2)
	var node Node
	if err := decoder.Decode(&node); err != nil {
		t.Fatal(err)
	}
}

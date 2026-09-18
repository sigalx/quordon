# Quordon YAML parser bounds

This source copy is `gopkg.in/yaml.v3` v3.0.1, under the original MIT and
Apache-2.0 terms in LICENSE and NOTICE.

Quordon adds `Decoder.NodeLimits` and `NodeLimitError`. Source node counts are
checked before node allocation, and nesting depth before recursive descent.
Document wrappers are excluded; alias nodes count once without expansion.
Zero limits retain upstream behavior. Policy assembly separately accounts for
aliases, references, intermediate overrides, bytes and document counts.

Implementation changes are confined to `yaml.go` and `decode.go`; upstream tests
are retained. The test-only check.v1 dependency is pinned to the version already
used by Quordon's module graph. `limits_test.go` covers boundary acceptance and
early parser rejection.

package mysql8

import (
	"errors"
	"strconv"
	"strings"
)

var errMalformedIndexMergePlan = errors.New("aggregate plan index merge is malformed")

// MySQL's JSON EXPLAIN replaces the comma-separated key list with a merge
// expression, without escaping native names. key_length still contains one
// numeric length per physical index, including flattened nested merges, while
// possible_keys preserves complete native identities. Reject punctuation in
// those identities rather than interpreting it as expression syntax.
// The explicit argument stack keeps parsing linear without recursion.
func indexMergeUsesIndex(key, keyLengths, requiredIndex string, possibleKeys []any) (bool, error) {
	if len(possibleKeys) == 0 {
		return false, errMalformedIndexMergePlan
	}
	nativeIndexes := make(map[string]struct{}, len(possibleKeys))
	for _, value := range possibleKeys {
		name, ok := value.(string)
		if !ok || name == "" || strings.ContainsAny(name, "(),") {
			return false, errMalformedIndexMergePlan
		}
		nativeIndexes[name] = struct{}{}
	}
	indexCount := 0
	for rest := keyLengths; ; {
		length, tail, more := strings.Cut(rest, ",")
		if length == "" || length[0] == '0' || strings.IndexFunc(length, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return false, errMalformedIndexMergePlan
		}
		if _, err := strconv.ParseUint(length, 10, 64); err != nil {
			return false, errMalformedIndexMergePlan
		}
		indexCount++
		if !more {
			break
		}
		rest = tail
	}
	arguments := []int{0}
	expectIndex := true
	rootExpression := false
	usesIndex := false
	leaves := 0
	for position := 0; position < len(key); {
		if expectIndex {
			end := position
			for end < len(key) && key[end] != '(' && key[end] != ')' && key[end] != ',' {
				end++
			}
			if end == position {
				return false, errMalformedIndexMergePlan
			}
			name := key[position:end]
			if end < len(key) && key[end] == '(' {
				switch name {
				case "union", "intersect", "sort_union":
				default:
					return false, errMalformedIndexMergePlan
				}
				if len(arguments) == 1 {
					if arguments[0] != 0 {
						return false, errMalformedIndexMergePlan
					}
					rootExpression = true
				}
				arguments = append(arguments, 0)
				position = end + 1
			} else {
				if _, ok := nativeIndexes[name]; !ok {
					return false, errMalformedIndexMergePlan
				}
				usesIndex = usesIndex || strings.EqualFold(name, requiredIndex)
				leaves++
				arguments[len(arguments)-1]++
				expectIndex = false
				position = end
			}
			continue
		}
		switch key[position] {
		case ',':
			if len(arguments) == 1 && rootExpression {
				return false, errMalformedIndexMergePlan
			}
			expectIndex = true
		case ')':
			// Native merge operators combine at least two children. A unary
			// wrapper could instead be part of a quoted physical index name.
			if len(arguments) == 1 || arguments[len(arguments)-1] < 2 {
				return false, errMalformedIndexMergePlan
			}
			arguments = arguments[:len(arguments)-1]
			arguments[len(arguments)-1]++
		default:
			return false, errMalformedIndexMergePlan
		}
		position++
	}
	if expectIndex || len(arguments) != 1 || leaves != indexCount {
		return false, errMalformedIndexMergePlan
	}
	return usesIndex, nil
}

package queryspec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

type keysetRequestWire struct {
	Kind       wireString      `json:"kind"`
	Profile    wireString      `json:"profile"`
	Datasource wireString      `json:"datasource"`
	Shape      wireString      `json:"shape"`
	Query      *keysetSpecWire `json:"query"`
	Page       *keysetPageWire `json:"page"`
}

type keysetSpecWire struct {
	Source     *resourceWire    `json:"source"`
	Projection *[]selectionWire `json:"projection"`
	Filter     *filterWire      `json:"filter,omitempty"`
	OrderBy    *[]sortWire      `json:"order_by"`
	Limit      wireInt          `json:"limit"`
}

type keysetPageWire struct {
	Kind   wireString          `json:"kind"`
	Cursor *[]keysetCursorWire `json:"cursor,omitempty"`
}

type keysetCursorWire struct {
	Type  wireString `json:"type"`
	Value wireString `json:"value"`
}

func DecodeStrictSelectVNext(
	data []byte, maxFilterDepth, maxPredicates, maxParameters int,
) (SelectRequestVNext, error) {
	if !utf8.Valid(data) {
		return SelectRequestVNext{}, errors.New("request body must be valid UTF-8")
	}
	if err := validateJSONSurrogateEscapes(data); err != nil {
		return SelectRequestVNext{}, err
	}
	keyset, err := detectKeysetSelectBranch(data, maxFilterDepth, maxPredicates, maxParameters)
	if err != nil {
		return SelectRequestVNext{}, err
	}
	if !keyset {
		request, err := DecodeStrictSelect(data, maxFilterDepth)
		if err != nil {
			return SelectRequestVNext{}, err
		}
		return NewLegacySelectRequest(request), nil
	}
	request, err := DecodeStrictKeyset(data, maxFilterDepth, maxPredicates, maxParameters)
	if err != nil {
		return SelectRequestVNext{}, err
	}
	return NewKeysetSelectRequest(request), nil
}

func DecodeStrictKeyset(
	data []byte, maxFilterDepth, maxPredicates, maxParameters int,
) (KeysetRequest, error) {
	if !utf8.Valid(data) {
		return KeysetRequest{}, errors.New("request body must be valid UTF-8")
	}
	if err := validateJSONSurrogateEscapes(data); err != nil {
		return KeysetRequest{}, err
	}
	if err := scanKeysetRequestShape(data, maxFilterDepth, maxPredicates, maxParameters); err != nil {
		return KeysetRequest{}, err
	}
	var wire *keysetRequestWire
	if err := decodeStrictJSON(data, &wire); err != nil {
		return KeysetRequest{}, err
	}
	if wire == nil {
		return KeysetRequest{}, errors.New("request body must contain a JSON object")
	}
	if !wire.Kind.Set || wire.Kind.Value != "keyset" {
		return KeysetRequest{}, errors.New("kind must be keyset")
	}
	if !wire.Profile.Set || wire.Profile.Value == "" {
		return KeysetRequest{}, errors.New("profile is required and must not be empty")
	}
	if !wire.Datasource.Set || wire.Datasource.Value == "" {
		return KeysetRequest{}, errors.New("datasource is required and must not be empty")
	}
	if !wire.Shape.Set || wire.Shape.Value == "" {
		return KeysetRequest{}, errors.New("shape is required and must not be empty")
	}
	if wire.Query == nil || wire.Page == nil {
		return KeysetRequest{}, errors.New("query and page are required")
	}
	query, err := wire.Query.decode(maxFilterDepth)
	if err != nil {
		return KeysetRequest{}, err
	}
	page, err := wire.Page.decode()
	if err != nil {
		return KeysetRequest{}, err
	}
	request := KeysetRequest{
		Kind: "keyset", Profile: wire.Profile.Value, Datasource: wire.Datasource.Value,
		Shape: wire.Shape.Value, Query: query, Page: page,
	}
	if _, err := ValidateKeyset(
		request, ProtocolMaxProjectionFields, ProtocolMaxKeysetFields,
		maxPredicates, maxFilterDepth, maxParameters, ProtocolMaxRows,
	); err != nil {
		return KeysetRequest{}, err
	}
	return request, nil
}

func (w keysetSpecWire) decode(maxFilterDepth int) (KeysetSpec, error) {
	if w.Source == nil || w.Projection == nil || w.OrderBy == nil || !w.Limit.Set {
		return KeysetSpec{}, errors.New("query source, projection, order_by, and limit are required")
	}
	source, err := w.Source.decode()
	if err != nil {
		return KeysetSpec{}, err
	}
	if len(*w.Projection) == 0 || len(*w.Projection) > ProtocolMaxProjectionFields {
		return KeysetSpec{}, errors.New("query.projection is outside the protocol bounds")
	}
	projection := make([]Selection, len(*w.Projection))
	for index, item := range *w.Projection {
		projection[index], err = item.decode()
		if err != nil {
			return KeysetSpec{}, fmt.Errorf("query.projection[%d]: %w", index, err)
		}
		if projection[index].Kind != "field" || projection[index].Function != "" {
			return KeysetSpec{}, fmt.Errorf("query.projection[%d] must be a field selection", index)
		}
	}
	if len(*w.OrderBy) == 0 || len(*w.OrderBy) > ProtocolMaxKeysetFields {
		return KeysetSpec{}, errors.New("query.order_by is outside the protocol bounds")
	}
	order := make([]Sort, len(*w.OrderBy))
	for index, item := range *w.OrderBy {
		order[index], err = item.decode()
		if err != nil {
			return KeysetSpec{}, fmt.Errorf("query.order_by[%d]: %w", index, err)
		}
	}
	result := KeysetSpec{Source: source, Projection: projection, OrderBy: order, Limit: w.Limit.Value}
	if w.Filter != nil {
		filter, err := w.Filter.decode(1, maxFilterDepth)
		if err != nil {
			return KeysetSpec{}, fmt.Errorf("query.filter: %w", err)
		}
		result.Filter = &filter
	}
	return result, nil
}

func (w keysetPageWire) decode() (KeysetPage, error) {
	if !w.Kind.Set {
		return KeysetPage{}, errors.New("page.kind is required")
	}
	result := KeysetPage{Kind: w.Kind.Value}
	switch w.Kind.Value {
	case "first":
		if w.Cursor != nil {
			return KeysetPage{}, errors.New("page.cursor is forbidden for the first page")
		}
	case "after":
		if w.Cursor == nil || len(*w.Cursor) == 0 || len(*w.Cursor) > ProtocolMaxKeysetFields {
			return KeysetPage{}, errors.New("page.cursor is required within protocol bounds")
		}
		result.Cursor = make([]KeysetCursorValue, len(*w.Cursor))
		for index, item := range *w.Cursor {
			if !item.Type.Set || !item.Value.Set {
				return KeysetPage{}, fmt.Errorf("page.cursor[%d] requires type and value", index)
			}
			result.Cursor[index] = KeysetCursorValue{Type: item.Type.Value, Value: item.Value.Value}
		}
	default:
		return KeysetPage{}, errors.New("page.kind must be first or after")
	}
	return result, nil
}

func detectKeysetSelectBranch(data []byte, maxDepth, maxPredicates, maxParameters int) (bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	// Branch detection is only a structural pass. Preserve arbitrary-precision
	// JSON number tokens so it cannot reject a value that the selected strict
	// decoder is responsible for validating without float64 conversion.
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return false, errors.New("request body must contain a JSON object")
	}
	seen := make(map[string]struct{}, 6)
	budget := newFilterShapeScanBudget(maxPredicates, maxParameters)
	kindSeen := false
	keyset := false
	for decoder.More() {
		key, err := nextUniqueObjectKey(decoder, seen)
		if err != nil {
			return false, err
		}
		switch key {
		case "kind":
			kindSeen = true
			value, err := decoder.Token()
			if err != nil {
				return false, err
			}
			kind, ok := value.(string)
			if !ok || kind != "keyset" {
				return false, errors.New("kind must be keyset when present")
			}
			keyset = true
		case "profile", "datasource", "shape":
			if err := skipJSONValue(decoder); err != nil {
				return false, err
			}
		case "query":
			if err := scanSelectVNextQueryShape(decoder, maxDepth, budget); err != nil {
				return false, err
			}
		case "page":
			if _, err := scanKeysetPageShape(decoder); err != nil {
				return false, err
			}
		default:
			return false, unknownJSONField(key)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return false, err
	}
	if kindSeen {
		return keyset, nil
	}
	return false, nil
}

// scanSelectVNextQueryShape bounds the union of the legacy and keyset query
// branches before branch selection. This prevents an earlier query member from
// hiding a deeply nested tree until a later kind discriminator is encountered.
func scanSelectVNextQueryShape(
	decoder *json.Decoder, maxDepth int, budget *filterShapeScanBudget,
) error {
	return scanObjectShape(decoder, "query", func(key string) error {
		switch key {
		case "source":
			return scanResourceShape(decoder)
		case "projection":
			return scanBoundedArray(decoder, ProtocolMaxProjectionFields, "query.projection", func() error {
				return scanSelectionShape(decoder, true)
			})
		case "filter":
			return scanFilterShape(decoder, 1, maxDepth, budget)
		case "group_by":
			return scanBoundedArray(decoder, ProtocolMaxGroupByFields, "query.group_by", func() error {
				return skipJSONValue(decoder)
			})
		case "order_by":
			return scanBoundedArray(decoder, ProtocolMaxOrderByFields, "query.order_by", func() error {
				return scanSortShape(decoder)
			})
		case "limit", "offset":
			return skipJSONValue(decoder)
		default:
			return unknownJSONField(key)
		}
	})
}

func scanKeysetRequestShape(data []byte, maxDepth, maxPredicates, maxParameters int) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return nil
	}
	seen := make(map[string]struct{}, 6)
	budget := newFilterShapeScanBudget(maxPredicates, maxParameters)
	cursorCount := 0
	for decoder.More() {
		key, err := nextUniqueObjectKey(decoder, seen)
		if err != nil {
			return err
		}
		switch key {
		case "kind", "profile", "datasource", "shape":
			err = skipJSONValue(decoder)
		case "query":
			err = scanKeysetQueryShape(decoder, maxDepth, budget)
		case "page":
			cursorCount, err = scanKeysetPageShape(decoder)
		default:
			return unknownJSONField(key)
		}
		if err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	for range keysetCursorParameterCount(cursorCount) + 1 {
		if err := budget.addServerParameter(); err != nil {
			return err
		}
	}
	return nil
}

func scanKeysetQueryShape(decoder *json.Decoder, maxDepth int, budget *filterShapeScanBudget) error {
	return scanObjectShape(decoder, "query", func(key string) error {
		switch key {
		case "source":
			return scanResourceShape(decoder)
		case "projection":
			return scanBoundedArray(decoder, ProtocolMaxProjectionFields, "query.projection", func() error {
				return scanSelectionShape(decoder, true)
			})
		case "filter":
			return scanFilterShape(decoder, 1, maxDepth, budget)
		case "order_by":
			return scanBoundedArray(decoder, ProtocolMaxKeysetFields, "query.order_by", func() error {
				return scanSortShape(decoder)
			})
		case "limit":
			return skipJSONValue(decoder)
		default:
			return unknownJSONField(key)
		}
	})
}

func scanKeysetPageShape(decoder *json.Decoder) (int, error) {
	count := 0
	err := scanObjectShape(decoder, "page", func(key string) error {
		switch key {
		case "kind":
			return skipJSONValue(decoder)
		case "cursor":
			return scanBoundedArray(decoder, ProtocolMaxKeysetFields, "page.cursor", func() error {
				count++
				return scanObjectShape(decoder, "page.cursor item", func(key string) error {
					switch key {
					case "type", "value":
						return skipJSONValue(decoder)
					default:
						return unknownJSONField(key)
					}
				})
			})
		default:
			return unknownJSONField(key)
		}
	})
	return count, err
}

// validateJSONSurrogateEscapes prevents encoding/json from silently replacing
// an unpaired escaped surrogate with U+FFFD. Raw UTF-8 is checked separately.
func validateJSONSurrogateEscapes(data []byte) error {
	inString := false
	escaped := false
	for index := 0; index < len(data); index++ {
		character := data[index]
		if !inString {
			if character == '"' {
				inString = true
			}
			continue
		}
		if escaped {
			escaped = false
			if character != 'u' || index+4 >= len(data) {
				continue
			}
			first, ok := parseJSONHex16(data[index+1 : index+5])
			if !ok {
				continue // The JSON decoder reports malformed hexadecimal escapes.
			}
			index += 4
			if first >= 0xD800 && first <= 0xDBFF {
				if index+6 >= len(data) || data[index+1] != '\\' || data[index+2] != 'u' {
					return errors.New("JSON string contains an unpaired high surrogate")
				}
				second, ok := parseJSONHex16(data[index+3 : index+7])
				if !ok || second < 0xDC00 || second > 0xDFFF || !utf16.IsSurrogate(rune(first)) {
					return errors.New("JSON string contains an unpaired high surrogate")
				}
				index += 6
			} else if first >= 0xDC00 && first <= 0xDFFF {
				return errors.New("JSON string contains an unpaired low surrogate")
			}
			continue
		}
		switch character {
		case '\\':
			escaped = true
		case '"':
			inString = false
		}
	}
	return nil
}

func parseJSONHex16(value []byte) (uint16, bool) {
	if len(value) != 4 {
		return 0, false
	}
	var result uint16
	for _, digit := range value {
		result <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			result += uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			result += uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			result += uint16(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
}

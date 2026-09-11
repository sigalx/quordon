package queryspec

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestDecodeStrictRejectsUnknownFields(t *testing.T) {
	_, err := DecodeStrict([]byte(`{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"sql":"select 1"}}`), 8)
	if err == nil {
		t.Fatal("expected an unknown-field error")
	}
}

func TestDecodeStrictRejectsCaseFoldedFields(t *testing.T) {
	tests := []struct {
		name string
		body string
		key  string
	}{
		{name: "request", key: "Query", body: `{"profile":"p","Query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}]}}`},
		{name: "query", key: "Projection", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"Projection":[{"kind":"field","field":"id"}]}}`},
		{name: "resource", key: "Schema", body: `{"profile":"p","query":{"source":{"Schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}]}}`},
		{name: "selection", key: "Kind", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"Kind":"field","field":"id"}]}}`},
		{name: "filter", key: "Filter", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"Filter":{"kind":"predicate","field":"id","operator":"is_null","values":[]}}}`},
		{name: "typed value", key: "Type", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"predicate","field":"id","operator":"eq","values":[{"Type":"integer","value":1}]}}}`},
		{name: "sort", key: "Direction", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"order_by":[{"field":"id","Direction":"asc"}]}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeStrict([]byte(test.body), 8)
			if err == nil || !strings.Contains(err.Error(), `unknown field "`+test.key+`"`) {
				t.Fatalf("DecodeStrict() error = %v, want exact-key rejection", err)
			}
		})
	}
}

func TestDecodeStrictRejectsCaseFoldedExpressionsBeforeDepthValidation(t *testing.T) {
	leaf := `{"kind":"predicate","field":"id","operator":"is_null","values":[]}`
	filter := leaf
	for range 8 {
		filter = `{"kind":"group","operator":"and","Expressions":[` + filter + `,` + leaf + `]}`
	}
	body := `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":` + filter + `}}`
	_, err := DecodeStrict([]byte(body), 4)
	if err == nil || !strings.Contains(err.Error(), `unknown field "Expressions"`) {
		t.Fatalf("DecodeStrict() error = %v, want case-folded key rejection before tree decoding", err)
	}
}

func TestDecodeStrictRejectsExactAndCaseFoldedDuplicateKeys(t *testing.T) {
	body := `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}]},"Query":{"source":{"schema":"app","name":"secret"},"projection":[{"kind":"field","field":"password"}]}}`
	_, err := DecodeStrict([]byte(body), 8)
	if err == nil || !strings.Contains(err.Error(), `unknown field "Query"`) {
		t.Fatalf("DecodeStrict() error = %v, want case-folded duplicate rejection", err)
	}
}

func TestDecodeStrictRejectsDuplicateFields(t *testing.T) {
	tests := []struct {
		name string
		body string
		key  string
	}{
		{
			name: "request objects are not merged",
			key:  "query",
			body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"}},"query":{"projection":[{"kind":"field","field":"id"}]}}`,
		},
		{
			name: "query",
			key:  "source",
			body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"source":{"schema":"app","name":"other"},"projection":[{"kind":"field","field":"id"}]}}`,
		},
		{
			name: "resource",
			key:  "schema",
			body: `{"profile":"p","query":{"source":{"schema":"app","schema":"other","name":"orders"},"projection":[{"kind":"field","field":"id"}]}}`,
		},
		{
			name: "selection",
			key:  "field",
			body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id","field":"password"}]}}`,
		},
		{
			name: "filter",
			key:  "operator",
			body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"predicate","field":"id","operator":"eq","operator":"ne","values":[{"type":"integer","value":1}]}}}`,
		},
		{
			name: "typed value",
			key:  "value",
			body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"predicate","field":"id","operator":"eq","values":[{"type":"integer","value":1,"value":2}]}}}`,
		},
		{
			name: "sort",
			key:  "direction",
			body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"order_by":[{"field":"id","direction":"asc","direction":"desc"}]}}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeStrict([]byte(test.body), 8)
			if err == nil || !strings.Contains(err.Error(), `duplicate JSON field "`+test.key+`"`) {
				t.Fatalf("DecodeStrict() error = %v, want duplicate-key rejection", err)
			}
		})
	}
}

func TestDecodeStrictRejectsNullEnvelope(t *testing.T) {
	if _, err := DecodeStrict([]byte("null"), 8); err == nil {
		t.Fatal("expected null request envelope to be rejected")
	}
}

func TestDecodeStrictRejectsInvalidUTF8(t *testing.T) {
	body := []byte(`{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"predicate","field":"status","operator":"eq","values":[{"type":"string","value":"active"}]}}}`)
	body[bytes.Index(body, []byte("active"))] = 0xff
	if _, err := DecodeStrict(body, 8); err == nil || !strings.Contains(err.Error(), "valid UTF-8") {
		t.Fatalf("DecodeStrict() error = %v, want invalid UTF-8 error", err)
	}
}

func TestDecodeStrictEnforcesRequiredAndDiscriminatorFields(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "missing profile", body: `{"query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}]}}`},
		{name: "empty profile", body: `{"profile":"","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}]}}`},
		{name: "missing query", body: `{"profile":"p"}`},
		{name: "missing source", body: `{"profile":"p","query":{"projection":[{"kind":"field","field":"id"}]}}`},
		{name: "missing projection", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"}}}`},
		{name: "field selection missing field", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field"}]}}`},
		{name: "field selection has empty alias", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id","alias":""}]}}`},
		{name: "field selection has empty aggregate property", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id","function":""}]}}`},
		{name: "aggregate missing function", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"aggregate"}]}}`},
		{name: "count aggregate has empty field", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"aggregate","function":"count","field":""}]}}`},
		{name: "aggregate has empty alias", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"aggregate","function":"count","alias":""}]}}`},
		{name: "predicate missing values", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"predicate","field":"id","operator":"eq"}}}`},
		{name: "predicate has empty expressions", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"predicate","field":"id","operator":"is_null","values":[],"expressions":[]}}}`},
		{name: "group has empty field", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"group","field":"","operator":"and","expressions":[]}}}`},
		{name: "sort missing direction", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"order_by":[{"field":"id"}]}}`},
		{name: "typed value missing value", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"predicate","field":"id","operator":"eq","values":[{"type":"integer"}]}}}`},
		{name: "null filter", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":null}}`},
		{name: "null group by", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"group_by":null}}`},
		{name: "null order by", body: `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"order_by":null}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeStrict([]byte(test.body), 8); err == nil {
				t.Fatal("expected request contract error")
			}
		})
	}
}

func TestDecodeStrictAcceptsDiscriminatorSpecificFields(t *testing.T) {
	body := `{
		"profile":"p",
		"query":{
			"source":{"schema":"app","name":"orders"},
			"projection":[{"kind":"aggregate","function":"count","alias":"total"}],
			"filter":{"kind":"predicate","field":"status","operator":"is_null","values":[]}
		}
	}`
	if _, err := DecodeStrict([]byte(body), 8); err != nil {
		t.Fatalf("DecodeStrict() error = %v", err)
	}
}

func TestDecodeStrictRejectsFilterDepthBeforeMaterializingTree(t *testing.T) {
	leaf := `{"kind":"predicate","field":"id","operator":"is_null","values":[]}`
	filter := leaf
	for range 8 {
		filter = `{"kind":"group","operator":"and","expressions":[` + filter + `,` + leaf + `]}`
	}
	body := `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":` + filter + `}}`
	if _, err := DecodeStrict([]byte(body), 4); err == nil || !strings.Contains(err.Error(), "expression depth") {
		t.Fatalf("DecodeStrict() error = %v, want expression depth error", err)
	}
}

func TestDecodeStrictEnforcesProtocolArrayBounds(t *testing.T) {
	projection := strings.Repeat(`{"kind":"field","field":"id"},`, ProtocolMaxProjectionFields) + `{"kind":"field","field":"id"}`
	body := `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[` + projection + `]}}`
	if _, err := DecodeStrict([]byte(body), 8); err == nil || !strings.Contains(err.Error(), "protocol limit") {
		t.Fatalf("projection DecodeStrict() error = %v, want protocol limit error", err)
	}

	value := `{"type":"integer","value":1}`
	values := strings.Repeat(value+`,`, ProtocolMaxFilterItems) + value
	body = `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"predicate","field":"id","operator":"in","values":[` + values + `]}}}`
	if _, err := DecodeStrict([]byte(body), 8); err == nil || !strings.Contains(err.Error(), "protocol limit") {
		t.Fatalf("values DecodeStrict() error = %v, want protocol limit error", err)
	}

	groupBy := strings.Repeat(`"id",`, ProtocolMaxGroupByFields) + `"id"`
	body = `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"group_by":[` + groupBy + `]}}`
	if _, err := DecodeStrict([]byte(body), 8); err == nil || !strings.Contains(err.Error(), "protocol limit") {
		t.Fatalf("group_by DecodeStrict() error = %v, want protocol limit error", err)
	}

	sort := `{"field":"id","direction":"asc"}`
	orderBy := strings.Repeat(sort+`,`, ProtocolMaxOrderByFields) + sort
	body = `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"order_by":[` + orderBy + `]}}`
	if _, err := DecodeStrict([]byte(body), 8); err == nil || !strings.Contains(err.Error(), "protocol limit") {
		t.Fatalf("order_by DecodeStrict() error = %v, want protocol limit error", err)
	}
}

func TestDecodeStrictEnforcesPublishedLimitAndOffsetBounds(t *testing.T) {
	base := `{"profile":"p","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}]%s}}`
	tests := []struct {
		name     string
		member   string
		accepted bool
	}{
		{name: "minimum limit", member: `,"limit":1`, accepted: true},
		{name: "maximum limit", member: fmt.Sprintf(`,"limit":%d`, ProtocolMaxRows), accepted: true},
		{name: "integral fraction limit", member: `,"limit":1.0`, accepted: true},
		{name: "integral exponent limit", member: `,"limit":1e2`, accepted: true},
		{name: "zero limit", member: `,"limit":0`},
		{name: "excessive limit", member: fmt.Sprintf(`,"limit":%d`, ProtocolMaxRows+1)},
		{name: "quoted limit", member: `,"limit":"1"`},
		{name: "fractional limit", member: `,"limit":1.5`},
		{name: "non-integral exponent limit", member: `,"limit":1e-2`},
		{name: "integer overflow", member: `,"limit":9223372036854775808`},
		{name: "minimum offset", member: `,"offset":0`, accepted: true},
		{name: "maximum offset", member: fmt.Sprintf(`,"offset":%d`, ProtocolMaxOffset), accepted: true},
		{name: "negative offset", member: `,"offset":-1`},
		{name: "excessive offset", member: fmt.Sprintf(`,"offset":%d`, ProtocolMaxOffset+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeStrictSelect([]byte(fmt.Sprintf(base, test.member)), 8)
			if test.accepted && err != nil {
				t.Fatalf("DecodeStrictSelect() error = %v", err)
			}
			if !test.accepted && err == nil {
				t.Fatal("DecodeStrictSelect() accepted an out-of-contract integer")
			}
		})
	}
}

func TestValidateEnforcesEffectiveGroupAndOrderLimits(t *testing.T) {
	_, err := Validate(Spec{
		Source:     ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{{Kind: "field", Field: "id"}},
		GroupBy:    []string{"id", "status"},
	}, 10, 1, 10, 10, 4, 10, 100, 1000)
	if err == nil || !strings.Contains(err.Error(), "effective group-by limit") {
		t.Fatalf("group_by Validate() error = %v, want effective limit", err)
	}

	_, err = Validate(Spec{
		Source:     ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{{Kind: "field", Field: "id"}},
		OrderBy: []Sort{
			{Field: "id", Direction: "asc"},
			{Field: "status", Direction: "asc"},
		},
	}, 10, 10, 1, 10, 4, 10, 100, 1000)
	if err == nil || !strings.Contains(err.Error(), "effective order-by limit") {
		t.Fatalf("order_by Validate() error = %v, want effective limit", err)
	}
}

func TestValidateNormalizesLimitsAndCountsParameters(t *testing.T) {
	requestedLimit := 500
	validated, err := Validate(Spec{
		Source:     ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{{Kind: "field", Field: "id"}},
		Filter: &Filter{Kind: "predicate", Field: "status", Operator: "eq", Values: []TypedValue{{
			Type: "string", Value: []byte(`"active"`),
		}}},
		Limit: &requestedLimit,
	}, 10, 10, 10, 10, 4, 10, 100, 1000)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if validated.Spec().Limit != 100 {
		t.Fatalf("normalized limit = %d, want 100", validated.Spec().Limit)
	}
	if validated.Stats().Parameters != 3 {
		t.Fatalf("parameter count = %d, want 3", validated.Stats().Parameters)
	}
}

func TestRevalidateUsesStoredStructureWithoutReparsingBindValues(t *testing.T) {
	requestedLimit := 100
	largeValue := make([]byte, (1<<20)+2)
	largeValue[0] = '"'
	largeValue[len(largeValue)-1] = '"'
	for index := 1; index < len(largeValue)-1; index++ {
		largeValue[index] = 'a'
	}
	validated, err := Validate(Spec{
		Source:     ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{{Kind: "field", Field: "id"}},
		Filter: &Filter{Kind: "predicate", Field: "payload", Operator: "eq", Values: []TypedValue{{
			Type: "string", Value: largeValue,
		}}},
		Limit: &requestedLimit,
	}, 10, 10, 10, 10, 4, 10, 100, 1000)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	var revalidated Validated
	var revalidateErr error
	allocations := testing.AllocsPerRun(10, func() {
		revalidated, revalidateErr = Revalidate(validated, 10, 10, 10, 10, 4, 10, 25, 1000)
	})
	if revalidateErr != nil {
		t.Fatalf("Revalidate() error = %v", revalidateErr)
	}
	if allocations != 0 {
		t.Fatalf("Revalidate() allocations = %v, want 0", allocations)
	}
	if revalidated.spec.Limit != 25 || revalidated.stats != validated.stats {
		t.Fatalf("revalidated query = %+v, stats = %+v", revalidated.spec, revalidated.stats)
	}
}

func TestRevalidateEnforcesStoredEffectiveLimits(t *testing.T) {
	filter := Filter{Kind: "group", Operator: "and", Expressions: []Filter{
		{Kind: "predicate", Field: "id", Operator: "eq", Values: []TypedValue{{Type: "integer", Value: []byte("1")}}},
		{Kind: "predicate", Field: "status", Operator: "is_not_null", Values: []TypedValue{}},
	}}
	validated, err := Validate(Spec{
		Source: ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{
			{Kind: "field", Field: "id"},
			{Kind: "field", Field: "status"},
		},
		Filter:  &filter,
		GroupBy: []string{"id", "status"},
		OrderBy: []Sort{{Field: "id", Direction: "asc"}, {Field: "status", Direction: "desc"}},
	}, 10, 10, 10, 10, 4, 10, 100, 1000)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	tests := []struct {
		name                                                    string
		projection, group, order, predicates, depth, parameters int
		message                                                 string
	}{
		{name: "projection", projection: 1, group: 10, order: 10, predicates: 10, depth: 4, parameters: 10, message: "projection limit"},
		{name: "group", projection: 10, group: 1, order: 10, predicates: 10, depth: 4, parameters: 10, message: "group-by limit"},
		{name: "order", projection: 10, group: 10, order: 1, predicates: 10, depth: 4, parameters: 10, message: "order-by limit"},
		{name: "predicates", projection: 10, group: 10, order: 10, predicates: 1, depth: 4, parameters: 10, message: "predicate limit"},
		{name: "depth", projection: 10, group: 10, order: 10, predicates: 10, depth: 1, parameters: 10, message: "expression depth limit"},
		{name: "parameters", projection: 10, group: 10, order: 10, predicates: 10, depth: 4, parameters: 2, message: "parameter limit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Revalidate(
				validated, test.projection, test.group, test.order, test.predicates, test.depth,
				test.parameters, 100, 1000,
			)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Revalidate() error = %v, want %q", err, test.message)
			}
		})
	}
	if _, err := Revalidate(Validated{}, 10, 10, 10, 10, 4, 10, 100, 1000); err == nil {
		t.Fatal("Revalidate() accepted a zero-value validation token")
	}
}

func TestTypedValueRejectsNull(t *testing.T) {
	for _, valueType := range []string{"null", "boolean", "integer", "decimal", "string", "uuid", "date", "datetime", "bytes"} {
		t.Run(valueType, func(t *testing.T) {
			if _, err := (TypedValue{Type: valueType, Value: []byte("null")}).BindValue(); err == nil {
				t.Fatalf("type %q accepted a JSON null value", valueType)
			}
		})
	}
}

func TestTypedValueIntegerRequiresJSONInteger(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  int64
		valid bool
	}{
		{name: "integer", value: "1", want: 1, valid: true},
		{name: "negative integer", value: "-1", want: -1, valid: true},
		{name: "integral fraction", value: "1.0", want: 1, valid: true},
		{name: "integral exponent", value: "1e2", want: 100, valid: true},
		{name: "negative exponent with trailing zeros", value: "100e-2", want: 1, valid: true},
		{name: "minimum int64", value: "-9223372036854775808.0", want: -1 << 63, valid: true},
		{name: "quoted integer", value: `"1"`},
		{name: "fraction", value: "1.5"},
		{name: "non-integral exponent", value: "1e-2"},
		{name: "overflow", value: "9223372036854775808"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := (TypedValue{Type: "integer", Value: []byte(test.value)}).BindValue()
			if (err == nil) != test.valid {
				t.Fatalf("BindValue(%s) error = %v, valid = %v", test.value, err, test.valid)
			}
			if test.valid && value != test.want {
				t.Fatalf("BindValue(%s) = %#v, want %d", test.value, value, test.want)
			}
		})
	}
}

func TestTypedValueDecimalMatchesOpenAPIForms(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
		valid bool
	}{
		{name: "JSON integer", value: "100", want: "100", valid: true},
		{name: "JSON fraction", value: "-12.50", want: "-12.50", valid: true},
		{name: "JSON positive exponent", value: "1e2", want: "1e2", valid: true},
		{name: "JSON signed exponent", value: "-2.5E-3", want: "-2.5E-3", valid: true},
		{name: "fixed-point string", value: `"12.50"`, want: "12.50", valid: true},
		{name: "exponent string", value: `"1e2"`},
		{name: "boolean", value: "true"},
		{name: "leading zero", value: "01"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := (TypedValue{Type: "decimal", Value: []byte(test.value)}).BindValue()
			if (err == nil) != test.valid {
				t.Fatalf("BindValue(%s) error = %v, valid = %v", test.value, err, test.valid)
			}
			if test.valid && got != test.want {
				t.Fatalf("BindValue(%s) = %#v, want %q", test.value, got, test.want)
			}
		})
	}
}

func TestTypedValueBytesRequiresCanonicalStandardBase64(t *testing.T) {
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{name: "empty", value: `""`, valid: true},
		{name: "canonical padded", value: `"YQ=="`, valid: true},
		{name: "canonical unpadded block", value: `"YWJj"`, valid: true},
		{name: "non-zero padding bits", value: `"YR=="`},
		{name: "embedded newline", value: `"YQ==\n"`},
		{name: "missing padding", value: `"YQ"`},
		{name: "URL alphabet", value: `"_w=="`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := (TypedValue{Type: "bytes", Value: []byte(test.value)}).BindValue()
			if (err == nil) != test.valid {
				t.Fatalf("BindValue(%s) error = %v, valid = %v", test.value, err, test.valid)
			}
		})
	}
}

func TestTypedValueDateTimeMatchesOpenAPIFormat(t *testing.T) {
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{name: "upper-case UTC", value: "2026-01-01T00:00:00Z", valid: true},
		{name: "lower-case separators", value: "2026-01-01t00:00:00z", valid: true},
		{name: "lower-case T with offset", value: "2026-01-01t00:00:00.123+03:00", valid: true},
		{name: "space separator", value: "2026-01-01 00:00:00Z"},
		{name: "missing timezone", value: "2026-01-01T00:00:00"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := (TypedValue{Type: "datetime", Value: []byte(`"` + test.value + `"`)}).BindValue()
			if (err == nil) != test.valid {
				t.Fatalf("BindValue(%q) error = %v, valid = %v", test.value, err, test.valid)
			}
			if test.valid && got != test.value {
				t.Fatalf("BindValue(%q) = %#v, want the original lexical value", test.value, got)
			}
		})
	}
}

func TestValidateRejectsTypedNullComparison(t *testing.T) {
	for _, operator := range []string{"eq", "ne", "in", "not_in"} {
		t.Run(operator, func(t *testing.T) {
			_, err := Validate(Spec{
				Source:     ResourceRef{Schema: "app", Name: "orders"},
				Projection: []Selection{{Kind: "field", Field: "id"}},
				Filter: &Filter{Kind: "predicate", Field: "deleted_at", Operator: operator, Values: []TypedValue{{
					Type: "null", Value: []byte("null"),
				}}},
			}, 10, 10, 10, 10, 4, 10, 100, 1000)
			if err == nil || !strings.Contains(err.Error(), "use is_null or is_not_null") {
				t.Fatalf("Validate() error = %v, want typed null rejection", err)
			}
		})
	}
}

func TestValidateRejectsNonPortableIdentifier(t *testing.T) {
	_, err := Validate(Spec{
		Source:     ResourceRef{Schema: "app", Name: "orders;drop_table"},
		Projection: []Selection{{Kind: "field", Field: "id"}},
	}, 10, 10, 10, 10, 4, 10, 100, 1000)
	var validationError *ValidationError
	if !errors.As(err, &validationError) {
		t.Fatalf("error = %v, want ValidationError", err)
	}
}

func TestValidateRejectsMixedAggregateWithoutGroupBy(t *testing.T) {
	_, err := Validate(Spec{
		Source: ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{
			{Kind: "field", Field: "status"},
			{Kind: "aggregate", Function: "count"},
		},
	}, 10, 10, 10, 10, 4, 10, 100, 1000)
	var validationError *ValidationError
	if !errors.As(err, &validationError) || validationError.Path != "query.projection" {
		t.Fatalf("error = %v, want query.projection ValidationError", err)
	}
}

func TestValidateAcceptsMixedAggregateWithCompleteGroupBy(t *testing.T) {
	validated, err := Validate(Spec{
		Source: ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{
			{Kind: "field", Field: "status"},
			{Kind: "aggregate", Function: "count"},
		},
		GroupBy: []string{"status"},
	}, 10, 10, 10, 10, 4, 10, 100, 1000)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if len(validated.Spec().GroupBy) != 1 {
		t.Fatalf("group_by = %v", validated.Spec().GroupBy)
	}
}

func TestValidateRejectsNonGroupedOrderField(t *testing.T) {
	_, err := Validate(Spec{
		Source:     ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{{Kind: "field", Field: "status"}},
		GroupBy:    []string{"status"},
		OrderBy:    []Sort{{Field: "id", Direction: "asc"}},
	}, 10, 10, 10, 10, 4, 10, 100, 1000)
	var validationError *ValidationError
	if !errors.As(err, &validationError) || validationError.Path != "query.order_by[0].field" {
		t.Fatalf("error = %v, want order_by ValidationError", err)
	}
}

func TestValidateRejectsSourceOrderFieldForImplicitAggregateGroup(t *testing.T) {
	_, err := Validate(Spec{
		Source:     ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{{Kind: "aggregate", Function: "count", Alias: "total"}},
		OrderBy:    []Sort{{Field: "id", Direction: "asc"}},
	}, 10, 10, 10, 10, 4, 10, 100, 1000)
	var validationError *ValidationError
	if !errors.As(err, &validationError) || validationError.Path != "query.order_by[0].field" {
		t.Fatalf("error = %v, want order_by ValidationError", err)
	}
}

func TestValidateAcceptsGroupedOrderField(t *testing.T) {
	_, err := Validate(Spec{
		Source: ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{
			{Kind: "field", Field: "status"},
			{Kind: "aggregate", Function: "count"},
		},
		GroupBy: []string{"status"},
		OrderBy: []Sort{{Field: "STATUS", Direction: "desc"}},
	}, 10, 10, 10, 10, 4, 10, 100, 1000)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateStopsAtExpressionDepthLimit(t *testing.T) {
	leaf := Filter{
		Kind: "predicate", Field: "id", Operator: "is_null", Values: []TypedValue{},
	}
	deep := leaf
	for range 1000 {
		deep = Filter{Kind: "group", Operator: "and", Expressions: []Filter{deep, leaf}}
	}
	_, err := Validate(Spec{
		Source:     ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{{Kind: "field", Field: "id"}},
		Filter:     &deep,
	}, 10, 10, 10, 10, 4, 20, 100, 1000)
	var validationError *ValidationError
	if !errors.As(err, &validationError) || validationError.Message != "exceeds the effective expression depth limit" {
		t.Fatalf("error = %v, want expression depth limit", err)
	}
}

func TestValidateStopsAtPredicateLimitBeforeInspectingMoreValues(t *testing.T) {
	filter := Filter{Kind: "group", Operator: "and", Expressions: []Filter{
		{Kind: "predicate", Field: "id", Operator: "is_null", Values: []TypedValue{}},
		{Kind: "predicate", Field: "status", Operator: "eq", Values: []TypedValue{{Type: "invalid"}}},
	}}
	_, err := Validate(Spec{
		Source:     ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{{Kind: "field", Field: "id"}},
		Filter:     &filter,
	}, 10, 10, 10, 1, 4, 20, 100, 1000)
	var validationError *ValidationError
	if !errors.As(err, &validationError) || validationError.Message != "exceeds the effective predicate limit" {
		t.Fatalf("error = %v, want predicate limit", err)
	}
}

func TestValidateEnforcesProtocolArrayBoundsForProgrammaticCallers(t *testing.T) {
	projection := make([]Selection, ProtocolMaxProjectionFields+1)
	for index := range projection {
		projection[index] = Selection{Kind: "field", Field: "id"}
	}
	_, err := Validate(Spec{
		Source: ResourceRef{Schema: "app", Name: "orders"}, Projection: projection,
	}, 1000, 1000, 1000, 1000, 8, 1000, 100, 1000)
	if err == nil || !strings.Contains(err.Error(), "protocol projection limit") {
		t.Fatalf("projection Validate() error = %v, want protocol projection limit", err)
	}

	groupBy := make([]string, ProtocolMaxGroupByFields+1)
	for index := range groupBy {
		groupBy[index] = "id"
	}
	_, err = Validate(Spec{
		Source:     ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{{Kind: "field", Field: "id"}},
		GroupBy:    groupBy,
	}, 1000, 1000, 1000, 1000, 8, 1000, 100, 1000)
	if err == nil || !strings.Contains(err.Error(), "protocol group-by limit") {
		t.Fatalf("group_by Validate() error = %v, want protocol limit", err)
	}

	orderBy := make([]Sort, ProtocolMaxOrderByFields+1)
	for index := range orderBy {
		orderBy[index] = Sort{Field: "id", Direction: "asc"}
	}
	_, err = Validate(Spec{
		Source:     ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{{Kind: "field", Field: "id"}},
		OrderBy:    orderBy,
	}, 1000, 1000, 1000, 1000, 8, 1000, 100, 1000)
	if err == nil || !strings.Contains(err.Error(), "protocol order-by limit") {
		t.Fatalf("order_by Validate() error = %v, want protocol limit", err)
	}

	values := make([]TypedValue, ProtocolMaxFilterItems+1)
	for index := range values {
		values[index] = TypedValue{Type: "integer", Value: []byte("1")}
	}
	_, err = Validate(Spec{
		Source:     ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{{Kind: "field", Field: "id"}},
		Filter:     &Filter{Kind: "predicate", Field: "id", Operator: "in", Values: values},
	}, 1000, 1000, 1000, 1000, 8, 1000, 100, 1000)
	if err == nil || !strings.Contains(err.Error(), "protocol array limit") {
		t.Fatalf("values Validate() error = %v, want protocol array limit", err)
	}

	expressions := make([]Filter, ProtocolMaxFilterItems+1)
	for index := range expressions {
		expressions[index] = Filter{Kind: "predicate", Field: "id", Operator: "is_null", Values: []TypedValue{}}
	}
	_, err = Validate(Spec{
		Source:     ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{{Kind: "field", Field: "id"}},
		Filter:     &Filter{Kind: "group", Operator: "and", Expressions: expressions},
	}, 1000, 1000, 1000, 1000, 8, 1000, 100, 1000)
	if err == nil || !strings.Contains(err.Error(), "protocol array limit") {
		t.Fatalf("expressions Validate() error = %v, want protocol array limit", err)
	}
}

func TestValidateEnforcesProtocolLimitAndOffsetBoundsForProgrammaticCallers(t *testing.T) {
	limit := ProtocolMaxRows + 1
	offset := ProtocolMaxOffset + 1
	base := Spec{
		Source:     ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{{Kind: "field", Field: "id"}},
	}
	withLimit := base
	withLimit.Limit = &limit
	if _, err := Validate(withLimit, 10, 10, 10, 10, 4, 10, ProtocolMaxRows, ProtocolMaxOffset); err == nil || !strings.Contains(err.Error(), "protocol row limit") {
		t.Fatalf("limit Validate() error = %v, want protocol row limit", err)
	}
	withOffset := base
	withOffset.Offset = &offset
	if _, err := Validate(withOffset, 10, 10, 10, 10, 4, 10, ProtocolMaxRows, ProtocolMaxOffset); err == nil || !strings.Contains(err.Error(), "protocol offset limit") {
		t.Fatalf("offset Validate() error = %v, want protocol offset limit", err)
	}
}

func TestValidateSimpleSelectAcceptsFieldsAndRejectsAggregatesAndGrouping(t *testing.T) {
	validate := func(spec Spec) Validated {
		t.Helper()
		validated, err := Validate(spec, 10, 10, 10, 10, 4, 20, 100, 100)
		if err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
		return validated
	}
	base := Spec{
		Source:     ResourceRef{Schema: "app", Name: "orders"},
		Projection: []Selection{{Kind: "field", Field: "id"}},
		OrderBy:    []Sort{{Field: "id", Direction: "asc"}},
	}
	if err := ValidateSimpleSelect(validate(base)); err != nil {
		t.Fatalf("field-only select error = %v", err)
	}
	aggregate := base
	aggregate.Projection = []Selection{{Kind: "aggregate", Function: "count"}}
	aggregate.OrderBy = nil
	if err := ValidateSimpleSelect(validate(aggregate)); err == nil {
		t.Fatal("aggregate select was accepted")
	}
	grouped := base
	grouped.GroupBy = []string{"id"}
	if err := ValidateSimpleSelect(validate(grouped)); err == nil {
		t.Fatal("grouped select was accepted")
	}
}

func TestDecodeStrictSelectMatchesSimpleSelectOpenAPIShape(t *testing.T) {
	valid := []string{
		`{"profile":"reader","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"order_by":[],"limit":10}}`,
		`{"profile":"reader","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id","alias":"order_id"}],"filter":{"kind":"predicate","field":"status","operator":"eq","values":[{"type":"string","value":"active"}]},"order_by":[{"field":"id","direction":"desc"}]}}`,
	}
	for index, body := range valid {
		if _, err := DecodeStrictSelect([]byte(body), 8); err != nil {
			t.Fatalf("DecodeStrictSelect(valid[%d]) error = %v", index, err)
		}
	}

	invalid := []struct {
		name string
		body string
	}{
		{
			name: "explicit empty group_by",
			body: `{"profile":"reader","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"group_by":[]}}`,
		},
		{
			name: "nonempty group_by",
			body: `{"profile":"reader","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"group_by":["id"]}}`,
		},
		{
			name: "aggregate branch",
			body: `{"profile":"reader","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"aggregate","function":"count"}]}}`,
		},
		{
			name: "function on field branch",
			body: `{"profile":"reader","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id","function":"count"}]}}`,
		},
		{
			name: "empty projection",
			body: `{"profile":"reader","query":{"source":{"schema":"app","name":"orders"},"projection":[]}}`,
		},
		{
			name: "invalid source schema",
			body: `{"profile":"reader","query":{"source":{"schema":"bad-name","name":"orders"},"projection":[{"kind":"field","field":"id"}]}}`,
		},
		{
			name: "invalid source object",
			body: `{"profile":"reader","query":{"source":{"schema":"app","name":"bad-name"},"projection":[{"kind":"field","field":"id"}]}}`,
		},
		{
			name: "invalid projection field",
			body: `{"profile":"reader","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"bad-name"}]}}`,
		},
		{
			name: "invalid projection alias",
			body: `{"profile":"reader","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id","alias":"bad-name"}]}}`,
		},
		{
			name: "invalid order field",
			body: `{"profile":"reader","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"order_by":[{"field":"bad-name","direction":"asc"}]}}`,
		},
		{
			name: "invalid order direction",
			body: `{"profile":"reader","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"order_by":[{"field":"id","direction":"sideways"}]}}`,
		},
		{
			name: "invalid predicate field",
			body: `{"profile":"reader","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"predicate","field":"bad-name","operator":"eq","values":[{"type":"integer","value":1}]}}}`,
		},
		{
			name: "invalid predicate operator",
			body: `{"profile":"reader","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"predicate","field":"id","operator":"sideways","values":[{"type":"integer","value":1}]}}}`,
		},
		{
			name: "invalid predicate cardinality",
			body: `{"profile":"reader","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"predicate","field":"id","operator":"eq","values":[]}}}`,
		},
		{
			name: "invalid null predicate cardinality",
			body: `{"profile":"reader","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"predicate","field":"id","operator":"is_null","values":[{"type":"integer","value":1}]}}}`,
		},
		{
			name: "undersized filter group",
			body: `{"profile":"reader","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"group","operator":"and","expressions":[{"kind":"predicate","field":"id","operator":"is_null","values":[]}]}}}`,
		},
		{
			name: "typed value token mismatch",
			body: `{"profile":"reader","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"predicate","field":"active","operator":"eq","values":[{"type":"boolean","value":"true"}]}}}`,
		},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeStrictSelect([]byte(test.body), 8); err == nil {
				t.Fatal("DecodeStrictSelect() accepted an OpenAPI-invalid SELECT request")
			}
		})
	}

	// The full QuerySpec used by EXPLAIN still permits grouping.
	explainGrouped := `{"profile":"explain","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"group_by":[]}}`
	if _, err := DecodeStrict([]byte(explainGrouped), 8); err != nil {
		t.Fatalf("DecodeStrict(explain grouped) error = %v", err)
	}
}

package queryspec

import (
	"bytes"
	"strings"
	"testing"
)

const validKeysetRequestJSON = `{
	"kind":"keyset","profile":"reader","shape":"orders_by_id",
	"query":{
		"source":{"schema":"application","name":"orders"},
		"projection":[{"kind":"field","field":"id"},{"kind":"field","field":"status"}],
		"filter":{"kind":"predicate","field":"status","operator":"eq","values":[{"type":"string","value":"active"}]},
		"order_by":[{"field":"id","direction":"asc"}],"limit":10
	},
	"page":{"kind":"first"}
}`

func TestDecodeStrictSelectVNextAcceptsKeysetAndLegacyBranches(t *testing.T) {
	request, err := DecodeStrictSelectVNext([]byte(validKeysetRequestJSON), 8, 50, 100)
	if err != nil {
		t.Fatal(err)
	}
	keyset, ok := request.Keyset()
	if !ok || keyset.Query.Limit != 10 || keyset.Shape != "orders_by_id" {
		t.Fatalf("unexpected keyset request: %+v", keyset)
	}
	if _, ok := request.Legacy(); ok {
		t.Fatal("keyset request also exposed the legacy branch")
	}

	legacy := `{"profile":"reader","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"id"}],"limit":10}}`
	decoded, err := DecodeStrictSelectVNext([]byte(legacy), 8, 50, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded.Legacy(); !ok {
		t.Fatal("legacy request did not select the legacy branch")
	}
}

func TestDecodeStrictSelectVNextPreservesLargeDecimalTokensDuringBranchDetection(t *testing.T) {
	keysetBody := strings.Replace(
		validKeysetRequestJSON,
		`{"type":"string","value":"active"}`,
		`{"type":"decimal","value":1e400}`,
		1,
	)
	keysetRequest, err := DecodeStrictSelectVNext([]byte(keysetBody), 8, 50, 100)
	if err != nil {
		t.Fatalf("keyset branch rejected exact large decimal: %v", err)
	}
	keyset, ok := keysetRequest.Keyset()
	if !ok || string(keyset.Query.Filter.Values[0].Value) != "1e400" {
		t.Fatalf("keyset branch did not preserve decimal token: %+v", keyset)
	}

	legacyBody := `{"profile":"reader","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"predicate","field":"amount","operator":"eq","values":[{"type":"decimal","value":1e400}]},"limit":10}}`
	legacyRequest, err := DecodeStrictSelectVNext([]byte(legacyBody), 8, 50, 100)
	if err != nil {
		t.Fatalf("legacy branch rejected exact large decimal: %v", err)
	}
	legacy, ok := legacyRequest.Legacy()
	if !ok || string(legacy.Query.Filter.Values[0].Value) != "1e400" {
		t.Fatalf("legacy branch did not preserve decimal token: %+v", legacy)
	}
}

func TestDecodeStrictKeysetAcceptsIntegralJSONNumberSpellings(t *testing.T) {
	for _, spelling := range []string{"10", "10.0", "1e1"} {
		body := strings.Replace(validKeysetRequestJSON, `"limit":10`, `"limit":`+spelling, 1)
		request, err := DecodeStrictKeyset([]byte(body), 8, 50, 100)
		if err != nil {
			t.Fatalf("limit %s: %v", spelling, err)
		}
		if request.Query.Limit != 10 {
			t.Fatalf("limit %s decoded as %d", spelling, request.Query.Limit)
		}
	}
}

func TestDecodeStrictKeysetRejectsClosedContractViolations(t *testing.T) {
	after := strings.Replace(
		validKeysetRequestJSON,
		`"page":{"kind":"first"}`,
		`"page":{"kind":"after","cursor":[{"type":"integer","value":"1"}]}`,
		1,
	)
	fixtures := map[string]string{
		"missing shape": strings.Replace(validKeysetRequestJSON, `"shape":"orders_by_id",`, "", 1),
		"null optional filter": strings.Replace(
			validKeysetRequestJSON,
			`"filter":{"kind":"predicate","field":"status","operator":"eq","values":[{"type":"string","value":"active"}]}`,
			`"filter":null`, 1,
		),
		"quoted limit":                strings.Replace(validKeysetRequestJSON, `"limit":10`, `"limit":"10"`, 1),
		"fractional limit":            strings.Replace(validKeysetRequestJSON, `"limit":10`, `"limit":10.5`, 1),
		"case folded member":          strings.Replace(validKeysetRequestJSON, `"projection"`, `"Projection"`, 1),
		"duplicate root member":       strings.Replace(validKeysetRequestJSON, `"kind":"keyset"`, `"kind":"keyset","kind":"keyset"`, 1),
		"unknown nested member":       strings.Replace(validKeysetRequestJSON, `"direction":"asc"`, `"direction":"asc","extra":true`, 1),
		"numeric cursor":              strings.Replace(after, `"value":"1"`, `"value":1`, 1),
		"cursor arity mismatch":       strings.Replace(after, `[{"type":"integer","value":"1"}]`, `[{"type":"integer","value":"1"},{"type":"integer","value":"2"}]`, 1),
		"noncanonical integer cursor": strings.Replace(after, `"value":"1"`, `"value":"01"`, 1),
		"unpaired surrogate":          strings.Replace(after, `"value":"1"`, `"value":"\\ud800"`, 1),
		"first page cursor":           strings.Replace(after, `"kind":"after"`, `"kind":"first"`, 1),
		"repeated order field": strings.Replace(
			validKeysetRequestJSON,
			`"order_by":[{"field":"id","direction":"asc"}]`,
			`"order_by":[{"field":"id","direction":"asc"},{"field":"id","direction":"desc"}]`, 1,
		),
	}
	for name, body := range fixtures {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeStrictKeyset([]byte(body), 8, 50, 100); err == nil {
				t.Fatal("invalid keyset request was accepted")
			}
		})
	}

	invalidUTF8 := append([]byte(validKeysetRequestJSON[:len(validKeysetRequestJSON)-1]), 0xff, '}')
	if _, err := DecodeStrictKeyset(invalidUTF8, 8, 50, 100); err == nil {
		t.Fatal("invalid UTF-8 was accepted")
	}
}

func TestDecodeStrictSelectVNextBoundsBeforeBranchSelection(t *testing.T) {
	deep := `{"profile":"reader","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":`
	for range 10 {
		deep += `{"kind":"group","operator":"and","expressions":[`
	}
	deep += `{"kind":"predicate","field":"id","operator":"eq","values":[{"type":"integer","value":1}]}`
	for range 10 {
		deep += `,` + `{"kind":"predicate","field":"id","operator":"eq","values":[{"type":"integer","value":2}]}` + `]}`
	}
	deep += `,"order_by":[{"field":"id","direction":"asc"}],"limit":10},"kind":"keyset","shape":"orders_by_id","page":{"kind":"first"}}`
	if _, err := DecodeStrictSelectVNext([]byte(deep), 4, 50, 100); err == nil || !bytes.Contains([]byte(err.Error()), []byte("depth")) {
		t.Fatalf("deep pre-discriminator filter was not rejected early: %v", err)
	}
}

func TestKeysetAuthorizationValueIsDeeplyImmutable(t *testing.T) {
	request, err := DecodeStrictKeyset([]byte(validKeysetRequestJSON), 8, 50, 100)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := ValidateKeyset(request, 50, 8, 50, 8, 100, 1000)
	if err != nil {
		t.Fatal(err)
	}
	first := validated.Request()
	first.Query.Filter.Values[0].Value[1] = 'X'
	second := validated.Request()
	if string(second.Query.Filter.Values[0].Value) != `"active"` {
		t.Fatalf("validated keyset leaked a mutable bind value: %s", second.Query.Filter.Values[0].Value)
	}
}

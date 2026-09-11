package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/pb33f/libopenapi"
	openapivalidator "github.com/pb33f/libopenapi-validator"
	"github.com/pb33f/libopenapi/datamodel"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/queryspec"
	"gopkg.in/yaml.v3"
)

func TestKeysetPaginationContractIsPromotedToRuntime(t *testing.T) {
	specification, err := os.ReadFile("../../openapi/keyset-pagination.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Status          string `yaml:"x-quordon-status"`
		RuntimeContract bool   `yaml:"x-quordon-runtime-contract"`
	}
	if err := yaml.Unmarshal(specification, &metadata); err != nil {
		t.Fatalf("decode keyset design metadata: %v", err)
	}
	if metadata.Status != "stable" || !metadata.RuntimeContract {
		t.Fatalf("keyset contract does not claim runtime support: %+v", metadata)
	}

	root, err := os.ReadFile("../../openapi/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(root), "select_keyset") || !strings.Contains(string(root), "keyset-pagination.yaml#/components/schemas/SelectRequestVNext") {
		t.Fatal("keyset contract is absent from the executable root contract")
	}
}

func TestKeysetPaginationDesignPromotionGuardsAreExplicit(t *testing.T) {
	specification, err := os.ReadFile("../../openapi/keyset-pagination.yaml")
	if err != nil {
		t.Fatal(err)
	}
	discoverySpecification, err := os.ReadFile("../../openapi/query-shapes.yaml")
	if err != nil {
		t.Fatal(err)
	}
	contractText := string(specification) + "\n" + string(discoverySpecification)
	for _, invariant := range []string{
		"register-queries-select-by-path-and-route-every-method-through-the-exact-post-guard",
		"integer-cursor-outside-portable-int64-through-uint64-envelope-is-400-before-datasource",
		"keep-portable-temporal-grammar-and-validation-outside-concrete-adapters",
		"concrete-source-range-precision-casts-and-bindings: adapter-owned-post-metadata-validation",
		"application-charset-allowlist: absent",
		"incoming-round-trip: utf8-to-source-charset-to-utf8-with-byte-equality",
		"returned-key-round-trip: source-key-to-utf8-to-source-charset-with-byte-equality",
		"indexed-column-and-order-by-conversion: forbidden",
		"timestamp: canonical-rfc3339-utc-with-uppercase-t-and-z-and-optional-fraction",
		"aggregate-and-keyset-shape-count-is-1-through-1000",
		"any-post-allow-pre-execution-failure: bounded-completion-required",
		"requested-profile: domain-separated-sha256-and-utf8-byte-length-only",
		"configured-keyset-events-validated-before-datasource-probes: true",
		"single-bottom-up-bounded-pass",
		"strict-zero-table-impossible-plan-produces-an-empty-final-page",
		"worst-case-after-page-bind-count-exceeding-effective-max-parameters-rejects-startup",
		"dbms-implicit-cross-family-coercion: forbidden",
		"JSON Schema cannot correlate an item at rows[r][c] with columns[c]",
		"reject-null-row-collections-and-out-of-range-temporal-cells-before-success-encoding",
		"bytes-column-with-malformed-or-noncanonical-base64-cell",
		"unpaired-high-or-low-unicode-surrogate-escape-in-any-json-string",
		"enum-set-bit-text-and-blob-cursor-key-types-are-422-before-select",
		"requested-page-limit-below-shape-maximum-is-bound-immutably-and-drives-limit-plus-one",
		"SelectRequestVNext",
		"SelectResultVNext",
		"worst-case-server-issued-cursor-fits-a-canonical-next-request-before-select",
		"float-double-or-real-projection-is-422-before-select",
		"zerofill-integer-or-decimal-projection-is-422-before-select",
		"every-emitted-next-cursor-can-be-resubmitted",
		"float-double-or-real-mapped-to-portable-decimal: forbidden",
		"time-bucket-profile-rejects-v1-and-accepts-v2-and-v3",
		"keyset-profile-rejects-v1-and-v2-and-accepts-v3",
		"operationId: listQueryShapes",
		"discovery-like-with-integer-value-type-is-schema-invalid",
		"discovery-in-with-heterogeneous-value-types-is-schema-invalid",
		"discovery-denial-allows-only-denied-operation",
		"discovery-unavailable-allows-only-capacity-or-service-unavailable",
		"legacy-and-keyset-success-responses-match-the-selected-request-branch",
		"cross-branch-success-response-is-500-before-http-200-write",
		"independently-selecting-a-success-union-branch: forbidden",
	} {
		if !strings.Contains(contractText, invariant) {
			t.Fatalf("keyset design is missing promotion invariant %q", invariant)
		}
	}
}

func TestKeysetPaginationDesignRequestBranches(t *testing.T) {
	contract := loadKeysetPaginationDesignValidator(t)
	defer contract.Release()

	firstPage := `{
		"kind":"keyset",
		"profile":"reader",
		"shape":"employees_by_id",
		"query":{
			"source":{"schema":"application","name":"employees"},
			"projection":[{"kind":"field","field":"id"}],
			"order_by":[{"field":"id","direction":"asc"}],
			"limit":100
		},
		"page":{"kind":"first"}
	}`
	afterPage := strings.Replace(firstPage, `"page":{"kind":"first"}`, `"page":{"kind":"after","cursor":[{"type":"integer","value":"1500"}]}`, 1)
	maxSignedCursor := strings.Replace(afterPage, `"value":"1500"`, `"value":"9223372036854775807"`, 1)
	maxUnsignedCursor := strings.Replace(afterPage, `"value":"1500"`, `"value":"18446744073709551615"`, 1)
	numericCursor := strings.Replace(afterPage, `"value":"1500"`, `"value":1500`, 1)
	overlongCursor := strings.Replace(afterPage, `"value":"1500"`, `"value":"100000000000000000000"`, 1)
	dateCursor := strings.Replace(afterPage, `"type":"integer","value":"1500"`, `"type":"date","value":"2026-09-15"`, 1)
	emptyStringCursor := strings.Replace(afterPage, `"type":"integer","value":"1500"`, `"type":"string","value":""`, 1)
	unicodeStringCursor := strings.Replace(afterPage, `"type":"integer","value":"1500"`, `"type":"string","value":"Роль Straße 😀 "`, 1)
	quotedStringNumber := strings.Replace(afterPage, `"type":"integer","value":"1500"`, `"type":"string","value":"1"`, 1)
	numericStringCursor := strings.Replace(afterPage, `"type":"integer","value":"1500"`, `"type":"string","value":1`, 1)
	datetimeCursor := strings.Replace(afterPage, `"type":"integer","value":"1500"`, `"type":"datetime","value":"2026-09-15 12:34:56.123456789"`, 1)
	timestampCursor := strings.Replace(afterPage, `"type":"integer","value":"1500"`, `"type":"timestamp","value":"2026-09-15T12:34:56.123456789Z"`, 1)
	timestampWithOffset := strings.Replace(timestampCursor, `Z"`, `+00:00"`, 1)
	lowercaseTimestamp := strings.Replace(timestampCursor, `T12:34:56.123456789Z`, `t12:34:56.123456789z`, 1)
	overpreciseTimestamp := strings.Replace(timestampCursor, `.123456789Z`, `.1234567890Z`, 1)
	infiniteTimestamp := strings.Replace(timestampCursor, `2026-09-15T12:34:56.123456789Z`, `infinity`, 1)
	firstWithCursor := strings.Replace(firstPage, `"page":{"kind":"first"}`, `"page":{"kind":"first","cursor":[{"type":"integer","value":"1500"}]}`, 1)
	lowerRequestedLimit := strings.Replace(firstPage, `"limit":100`, `"limit":10`, 1)

	for _, fixture := range []struct {
		name string
		body string
		want bool
	}{
		{name: "first", body: firstPage, want: true},
		{name: "after", body: afterPage, want: true},
		{name: "maximum signed cursor", body: maxSignedCursor, want: true},
		{name: "maximum unsigned cursor", body: maxUnsignedCursor, want: true},
		{name: "date cursor", body: dateCursor, want: true},
		{name: "empty string cursor", body: emptyStringCursor, want: true},
		{name: "unicode string cursor is adapter-neutral", body: unicodeStringCursor, want: true},
		{name: "string containing a number remains string", body: quotedStringNumber, want: true},
		{name: "numeric token is not a string cursor", body: numericStringCursor, want: false},
		{name: "datetime cursor", body: datetimeCursor, want: true},
		{name: "timestamp cursor", body: timestampCursor, want: true},
		{name: "requested limit below shape maximum", body: lowerRequestedLimit, want: true},
		{name: "cursor number", body: numericCursor, want: false},
		{name: "overlong integer cursor", body: overlongCursor, want: false},
		{name: "timestamp offset", body: timestampWithOffset, want: false},
		{name: "lowercase timestamp", body: lowercaseTimestamp, want: false},
		{name: "overprecise timestamp", body: overpreciseTimestamp, want: false},
		{name: "infinite timestamp", body: infiniteTimestamp, want: false},
		{name: "first with cursor", body: firstWithCursor, want: false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			request := keysetDesignRequest(fixture.body)
			valid, validationErrors := contract.ValidateHttpRequestSync(request)
			if valid != fixture.want {
				t.Fatalf("request validity = %t, want %t; errors=%v", valid, fixture.want, validationErrors)
			}
			_, runtimeErr := queryspec.DecodeStrictSelectVNext([]byte(fixture.body), 8, 200, 200)
			if (runtimeErr == nil) != fixture.want {
				t.Fatalf("runtime validity = %t, want %t; error=%v", runtimeErr == nil, fixture.want, runtimeErr)
			}
		})
	}
}

func TestKeysetPaginationTemporalCursorSemanticValidation(t *testing.T) {
	contract := loadKeysetPaginationDesignValidator(t)
	defer contract.Release()

	base := `{
		"kind":"keyset","profile":"reader","shape":"events_by_time",
		"query":{"source":{"schema":"application","name":"events"},"projection":[{"kind":"field","field":"occurred_at"}],"order_by":[{"field":"occurred_at","direction":"asc"}],"limit":100},
		"page":{"kind":"after","cursor":[{"type":"timestamp","value":"2026-09-15T12:34:56Z"}]}
	}`
	for _, fixture := range []struct {
		name  string
		value string
	}{
		{name: "invalid calendar", value: "2026-02-29T12:34:56Z"},
		{name: "zero year", value: "0000-01-01T00:00:00Z"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			body := strings.Replace(base, "2026-09-15T12:34:56Z", fixture.value, 1)
			valid, validationErrors := contract.ValidateHttpRequestSync(keysetDesignRequest(body))
			if !valid {
				t.Fatalf("semantic-only fixture must remain OpenAPI-valid: %v", validationErrors)
			}
			if _, err := queryspec.DecodeStrictSelectVNext([]byte(body), 8, 200, 200); err == nil {
				t.Fatal("runtime accepted an OpenAPI-valid but semantically invalid timestamp")
			}
		})
	}
}

func TestKeysetPaginationDesignPreservesLegacySelectBranch(t *testing.T) {
	contract := loadKeysetPaginationDesignValidator(t)
	defer contract.Release()

	legacyBody := `{
		"profile":"reader",
		"query":{
			"source":{"schema":"application","name":"employees"},
			"projection":[{"kind":"field","field":"id"}],
			"limit":10,
			"offset":0
		}
	}`
	request := keysetDesignRequest(legacyBody)
	valid, validationErrors := contract.ValidateHttpRequestSync(request)
	if !valid {
		t.Fatalf("legacy SELECT request violates additive design contract: %v", validationErrors)
	}

	responseRequest := keysetDesignRequest(legacyBody)
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":  []string{"application/json"},
			"X-Request-ID":  []string{"req-contract"},
			"Cache-Control": []string{"no-store"},
		},
		Body: io.NopCloser(strings.NewReader(`{
			"query_id":"q-contract","policy_profile":"reader","policy_version":"1",
			"datasource":"mysql","adapter":"mysql8",
			"columns":[{"name":"id","type":"integer","encoding":"string","nullable":false}],
			"rows":[["1"]],"row_count":1,"truncated":false,
			"limits":{"deadline_ms":3000,"max_request_bytes":65536,"max_projection_fields":50,"max_group_by_fields":50,"max_order_by_fields":8,"max_predicates":50,"max_expression_depth":8,"max_parameters":100,"max_rows":1000,"max_result_bytes":1048576,"max_offset":10000,"max_concurrency":2},
			"warnings":[]
		}`)),
	}
	valid, validationErrors = contract.ValidateHttpResponse(responseRequest, response)
	if !valid {
		t.Fatalf("legacy SELECT response violates additive design contract: %v", validationErrors)
	}
}

func TestKeysetPaginationDesignBindsSuccessToRequestBranch(t *testing.T) {
	contract := loadKeysetPaginationDesignValidator(t)
	defer contract.Release()

	legacyRequest := `{
		"profile":"reader",
		"query":{"source":{"schema":"application","name":"employees"},"projection":[{"kind":"field","field":"id"}],"limit":10}
	}`
	keysetRequest := `{
		"kind":"keyset","profile":"reader","shape":"employees_by_id",
		"query":{"source":{"schema":"application","name":"employees"},"projection":[{"kind":"field","field":"id"}],"order_by":[{"field":"id","direction":"asc"}],"limit":10},
		"page":{"kind":"first"}
	}`
	limits := `"limits":{"deadline_ms":3000,"max_request_bytes":65536,"max_projection_fields":50,"max_group_by_fields":50,"max_order_by_fields":8,"max_predicates":50,"max_expression_depth":8,"max_parameters":100,"max_rows":1000,"max_result_bytes":1048576,"max_offset":10000,"max_concurrency":2}`
	legacyResult := `{
		"query_id":"q-contract","policy_profile":"reader","policy_version":"1","datasource":"mysql","adapter":"mysql8",
		"columns":[{"name":"id","type":"integer","encoding":"string","nullable":false}],"rows":[["1"]],"row_count":1,"truncated":false,
		` + limits + `,"warnings":[]
	}`
	keysetResult := `{
		"kind":"keyset","query_id":"q-contract","policy_profile":"reader","policy_version":"1","shape":"employees_by_id","datasource":"mysql","adapter":"mysql8",
		"columns":[{"name":"id","type":"integer","encoding":"string","nullable":false}],"rows":[["1"]],"row_count":1,"truncated":false,"page":{"has_more":false},
		` + limits + `,"warnings":[]
	}`

	for _, fixture := range []struct {
		name         string
		requestBody  string
		responseBody string
		want         bool
	}{
		{name: "legacy to legacy", requestBody: legacyRequest, responseBody: legacyResult, want: true},
		{name: "keyset to keyset", requestBody: keysetRequest, responseBody: keysetResult, want: true},
		{name: "legacy to keyset", requestBody: legacyRequest, responseBody: keysetResult, want: false},
		{name: "keyset to legacy", requestBody: keysetRequest, responseBody: legacyResult, want: false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			request := keysetDesignRequest(fixture.requestBody)
			valid, validationErrors := contract.ValidateHttpRequestSync(request)
			if !valid {
				t.Fatalf("fixture request is not OpenAPI-valid: %v", validationErrors)
			}

			responseRequest := keysetDesignRequest(fixture.requestBody)
			response := &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Type":  []string{"application/json"},
					"X-Request-ID":  []string{"req-contract"},
					"Cache-Control": []string{"no-store"},
				},
				Body: io.NopCloser(strings.NewReader(fixture.responseBody)),
			}
			valid, validationErrors = contract.ValidateHttpResponse(responseRequest, response)
			if !valid {
				t.Fatalf("fixture response is not independently OpenAPI-valid: %v", validationErrors)
			}
			if got := keysetDesignResponseMatchesRequestBranch(fixture.requestBody, fixture.responseBody); got != fixture.want {
				t.Fatalf("semantic branch match=%t, want %t", got, fixture.want)
			}
		})
	}
}

func keysetDesignResponseMatchesRequestBranch(requestBody, responseBody string) bool {
	branch := func(body string) (bool, bool) {
		var object map[string]json.RawMessage
		if err := json.Unmarshal([]byte(body), &object); err != nil {
			return false, false
		}
		rawKind, hasKind := object["kind"]
		if !hasKind {
			return false, true
		}
		var kind string
		if err := json.Unmarshal(rawKind, &kind); err != nil || kind != "keyset" {
			return false, false
		}
		return true, true
	}
	requestKeyset, requestValid := branch(requestBody)
	responseKeyset, responseValid := branch(responseBody)
	return requestValid && responseValid && requestKeyset == responseKeyset
}

func TestKeysetPaginationDesignResponseBranches(t *testing.T) {
	contract := loadKeysetPaginationDesignValidator(t)
	defer contract.Release()
	request := keysetDesignRequest(`{
		"kind":"keyset","profile":"reader","shape":"employees_by_id",
		"query":{"source":{"schema":"application","name":"employees"},"projection":[{"kind":"field","field":"id"}],"order_by":[{"field":"id","direction":"asc"}],"limit":1},
		"page":{"kind":"first"}
	}`)

	limits := `"limits":{"deadline_ms":3000,"max_request_bytes":65536,"max_projection_fields":50,"max_group_by_fields":50,"max_order_by_fields":8,"max_predicates":50,"max_expression_depth":8,"max_parameters":100,"max_rows":1000,"max_result_bytes":1048576,"max_offset":10000,"max_concurrency":2}`
	more := `{"kind":"keyset","query_id":"q-contract","policy_profile":"reader","policy_version":"1","shape":"employees_by_id","datasource":"mysql","adapter":"mysql8","columns":[{"name":"id","type":"integer","encoding":"string","nullable":false}],"rows":[["1500"]],"row_count":1,"truncated":true,"page":{"has_more":true,"next_cursor":[{"type":"integer","value":"1500"}]},` + limits + `,"warnings":[]}`
	final := strings.Replace(more, `"truncated":true,"page":{"has_more":true,"next_cursor":[{"type":"integer","value":"1500"}]}`, `"truncated":false,"page":{"has_more":false}`, 1)
	missingCursor := strings.Replace(more, `,"next_cursor":[{"type":"integer","value":"1500"}]`, "", 1)
	inconsistent := strings.Replace(more, `"truncated":true`, `"truncated":false`, 1)
	invalidColumnEncoding := strings.Replace(more, `"encoding":"string"`, `"encoding":"base64"`, 1)
	nullRows := strings.Replace(more, `"rows":[["1500"]]`, `"rows":null`, 1)
	dateMore := strings.ReplaceAll(more, `"1500"`, `"2026-09-15"`)
	dateMore = strings.ReplaceAll(dateMore, `"type":"integer"`, `"type":"date"`)
	datetimeMore := strings.ReplaceAll(more, `"1500"`, `"2026-09-15 12:34:56.123456789"`)
	datetimeMore = strings.ReplaceAll(datetimeMore, `"type":"integer"`, `"type":"datetime"`)
	timestampMore := strings.Replace(more, `"type":"integer"`, `"type":"datetime"`, 1)
	timestampMore = strings.Replace(timestampMore, `"rows":[["1500"]]`, `"rows":[["2026-09-15 12:34:56.123456789"]]`, 1)
	timestampMore = strings.Replace(timestampMore, `{"type":"integer","value":"1500"}`, `{"type":"timestamp","value":"2026-09-15T12:34:56.123456789Z"}`, 1)
	invalidTimestampMore := strings.Replace(timestampMore, `Z"`, `+00:00"`, 1)

	for _, fixture := range []struct {
		name string
		body string
		want bool
	}{
		{name: "more", body: more, want: true},
		{name: "final", body: final, want: true},
		{name: "date cursor", body: dateMore, want: true},
		{name: "datetime cursor", body: datetimeMore, want: true},
		{name: "timestamp cursor", body: timestampMore, want: true},
		{name: "timestamp offset", body: invalidTimestampMore, want: false},
		{name: "more without cursor", body: missingCursor, want: false},
		{name: "inconsistent continuation", body: inconsistent, want: false},
		{name: "invalid column encoding", body: invalidColumnEncoding, want: false},
		{name: "null rows", body: nullRows, want: false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			response := &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Type":  []string{"application/json"},
					"X-Request-ID":  []string{"req-contract"},
					"Cache-Control": []string{"no-store"},
				},
				Body: io.NopCloser(strings.NewReader(fixture.body)),
			}
			valid, validationErrors := contract.ValidateHttpResponse(request, response)
			if valid != fixture.want {
				t.Fatalf("response validity = %t, want %t; errors=%v", valid, fixture.want, validationErrors)
			}
		})
	}
}

func TestKeysetPaginationDesignDiscoveryV3(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()

	request := httptest.NewRequest(http.MethodGet, "http://quordon.test/query-shapes?profile=reader", nil)
	request.Header.Set("Accept", "application/vnd.quordon.query-shapes.v3+json")
	request.SetBasicAuth("contract-client", "contract-password")
	body := `{
		"policy_profile":"reader","policy_version":"1","datasource":"mysql","adapter":"mysql8",
		"shapes":[{
			"name":"employees_by_id","operation":"select_keyset",
			"query":{
				"source":{"schema":"application","name":"employees"},
				"projection":[{"kind":"field","field":"id"}],
				"order_by":[{"field":"id","direction":"asc"}],
				"maximum_limit":100
			}
		}]
	}`
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":  []string{"application/vnd.quordon.query-shapes.v3+json"},
			"X-Request-ID":  []string{"req-contract"},
			"Cache-Control": []string{"no-store"},
			"Vary":          []string{"Accept"},
		},
		Body: io.NopCloser(strings.NewReader(body)),
	}
	valid, validationErrors := contract.ValidateHttpResponse(request, response)
	if !valid {
		t.Fatalf("v3 discovery response violates design contract: %v", validationErrors)
	}
	portableAdapterBody := strings.Replace(body, `"adapter":"mysql8"`, `"adapter":"future-adapter"`, 1)
	response.Body = io.NopCloser(strings.NewReader(portableAdapterBody))
	valid, validationErrors = contract.ValidateHttpResponse(request, response)
	if !valid {
		t.Fatalf("v3 discovery hardcodes a concrete adapter: %v", validationErrors)
	}

	invalidFilterArity := strings.Replace(
		body,
		`"order_by":[`,
		`"filter":{"kind":"predicate","field":"id","operator":"is_null","value_types":["integer"]},"order_by":[`,
		1,
	)
	response.Body = io.NopCloser(strings.NewReader(invalidFilterArity))
	valid, _ = contract.ValidateHttpResponse(request, response)
	if valid {
		t.Fatal("v3 discovery accepted an impossible NULL predicate arity")
	}

	invalidLikeType := strings.Replace(
		body,
		`"order_by":[`,
		`"filter":{"kind":"predicate","field":"id","operator":"like","value_types":["integer"]},"order_by":[`,
		1,
	)
	response.Body = io.NopCloser(strings.NewReader(invalidLikeType))
	valid, _ = contract.ValidateHttpResponse(request, response)
	if valid {
		t.Fatal("v3 discovery accepted LIKE with an integer placeholder type")
	}

	heterogeneousSet := strings.Replace(
		body,
		`"order_by":[`,
		`"filter":{"kind":"predicate","field":"id","operator":"in","value_types":["integer","string"]},"order_by":[`,
		1,
	)
	response.Body = io.NopCloser(strings.NewReader(heterogeneousSet))
	valid, _ = contract.ValidateHttpResponse(request, response)
	if valid {
		t.Fatal("v3 discovery accepted heterogeneous IN placeholder types")
	}

	for _, validFilter := range []string{
		`"filter":{"kind":"predicate","field":"id","operator":"like","value_types":["string"]},"order_by":[`,
		`"filter":{"kind":"predicate","field":"id","operator":"in","value_types":["integer","integer"]},"order_by":[`,
	} {
		filteredBody := strings.Replace(body, `"order_by":[`, validFilter, 1)
		response.Body = io.NopCloser(strings.NewReader(filteredBody))
		valid, validationErrors = contract.ValidateHttpResponse(request, response)
		if !valid {
			t.Fatalf("v3 discovery rejected a valid statically typed filter: %v", validationErrors)
		}
	}
}

func TestKeysetPaginationDesignDiscoveryErrorsAreClosed(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()
	request := httptest.NewRequest(http.MethodGet, "http://quordon.test/query-shapes?profile=reader", nil)
	request.Header.Set("Accept", "application/vnd.quordon.query-shapes.v3+json")
	request.SetBasicAuth("contract-client", "contract-password")

	for _, fixture := range []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{
			name:   "discovery policy denial",
			status: http.StatusForbidden,
			body:   `{"code":"DENIED_OPERATION","message":"The operation is not allowed by policy","request_id":"req-contract","policy_version":"1"}`,
			want:   true,
		},
		{
			name:   "resource denial is impossible",
			status: http.StatusForbidden,
			body:   `{"code":"DENIED_RESOURCE","message":"The operation is not allowed by policy","request_id":"req-contract","policy_version":"1"}`,
			want:   false,
		},
		{
			name:   "service unavailable",
			status: http.StatusServiceUnavailable,
			body:   `{"code":"SERVICE_UNAVAILABLE","message":"A required service dependency is unavailable","request_id":"req-contract"}`,
			want:   true,
		},
		{
			name:   "database unavailable is impossible",
			status: http.StatusServiceUnavailable,
			body:   `{"code":"DATABASE_UNAVAILABLE","message":"The database is unavailable","request_id":"req-contract"}`,
			want:   false,
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			response := &http.Response{
				StatusCode: fixture.status,
				Header: http.Header{
					"Content-Type":  []string{"application/json"},
					"X-Request-ID":  []string{"req-contract"},
					"Cache-Control": []string{"no-store"},
				},
				Body: io.NopCloser(strings.NewReader(fixture.body)),
			}
			valid, validationErrors := contract.ValidateHttpResponse(request, response)
			if valid != fixture.want {
				t.Fatalf("response validity=%t, want %t; errors=%v", valid, fixture.want, validationErrors)
			}
		})
	}
}

func TestKeysetPaginationDesignPreservesLegacyDiscoveryNegotiation(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()

	for _, accept := range []string{
		"",
		"*/*",
		"application/json",
		"application/vnd.quordon.query-shapes.v2+json",
		"application/vnd.quordon.query-shapes.v3+json",
	} {
		t.Run("accept "+accept, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://quordon.test/query-shapes?profile=reader", nil)
			if accept != "" {
				request.Header.Set("Accept", accept)
			}
			request.SetBasicAuth("contract-client", "contract-password")
			valid, validationErrors := contract.ValidateHttpRequestSync(request)
			if !valid {
				t.Fatalf("legacy-compatible Accept %q is invalid: %v", accept, validationErrors)
			}
		})
	}

	request := httptest.NewRequest(http.MethodGet, "http://quordon.test/query-shapes?profile=reader", nil)
	request.Header.Set("Accept", "text/plain")
	request.SetBasicAuth("contract-client", "contract-password")
	valid, _ := contract.ValidateHttpRequestSync(request)
	if valid {
		t.Fatal("unknown discovery Accept value is OpenAPI-valid")
	}

	legacyRequest := httptest.NewRequest(http.MethodGet, "http://quordon.test/query-shapes?profile=reader", nil)
	legacyRequest.Header.Set("Accept", "application/json")
	legacyRequest.SetBasicAuth("contract-client", "contract-password")
	legacyResponse := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":  []string{"application/json"},
			"X-Request-ID":  []string{"req-contract"},
			"Cache-Control": []string{"no-store"},
			"Vary":          []string{"Accept"},
		},
		Body: io.NopCloser(strings.NewReader(`{
			"policy_profile":"reader","policy_version":"1","datasource":"mysql","adapter":"mysql8",
			"shapes":[{"name":"employees_count","operation":"aggregate","query":{
				"mode":"scalar","source":{"schema":"application","name":"employees"},
				"projection":[{"kind":"measure","function":"count_all","alias":"total"}]
			}}]
		}`)),
	}
	valid, validationErrors := contract.ValidateHttpResponse(legacyRequest, legacyResponse)
	if !valid {
		t.Fatalf("legacy discovery response violates additive design contract: %v", validationErrors)
	}
}

func TestKeysetPaginationDesignLayersTimeBucketAndKeysetNegotiation(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()
	server, _, closeDatabases := successfulTimeBucketContractServer(t)
	defer closeDatabases()

	legacyRuntimeRequest := httptest.NewRequest(http.MethodGet, "/query-shapes?profile=reader", nil)
	legacyRuntimeRequest.SetBasicAuth("client", "secret")
	legacyRuntimeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(legacyRuntimeResponse, legacyRuntimeRequest)
	if legacyRuntimeResponse.Code != http.StatusNotAcceptable {
		t.Fatalf("time-bucket profile legacy status=%d, want 406; body=%s", legacyRuntimeResponse.Code, legacyRuntimeResponse.Body.String())
	}
	legacyContractRequest := httptest.NewRequest(http.MethodGet, "http://quordon.test/query-shapes?profile=reader", nil)
	legacyContractRequest.SetBasicAuth("client", "secret")
	valid, validationErrors := contract.ValidateHttpResponse(legacyContractRequest, legacyRuntimeResponse.Result())
	if !valid {
		t.Fatalf("existing time-bucket v1 gate violates additive design contract: %v", validationErrors)
	}

	v2RuntimeRequest := httptest.NewRequest(http.MethodGet, "/query-shapes?profile=reader", nil)
	v2RuntimeRequest.Header.Set("Accept", "application/vnd.quordon.query-shapes.v2+json")
	v2RuntimeRequest.SetBasicAuth("client", "secret")
	v2RuntimeResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(v2RuntimeResponse, v2RuntimeRequest)
	if v2RuntimeResponse.Code != http.StatusOK || !strings.Contains(v2RuntimeResponse.Body.String(), `"kind":"time_bucket"`) {
		t.Fatalf("time-bucket profile v2 status=%d; body=%s", v2RuntimeResponse.Code, v2RuntimeResponse.Body.String())
	}
	v2Body := v2RuntimeResponse.Body.String()
	v2ContractRequest := httptest.NewRequest(http.MethodGet, "http://quordon.test/query-shapes?profile=reader", nil)
	v2ContractRequest.Header.Set("Accept", "application/vnd.quordon.query-shapes.v2+json")
	v2ContractRequest.SetBasicAuth("client", "secret")
	valid, validationErrors = contract.ValidateHttpResponse(v2ContractRequest, v2RuntimeResponse.Result())
	if !valid {
		t.Fatalf("existing time-bucket v2 response violates additive design contract: %v", validationErrors)
	}

	v3ContractRequest := httptest.NewRequest(http.MethodGet, "http://quordon.test/query-shapes?profile=reader", nil)
	v3ContractRequest.Header.Set("Accept", "application/vnd.quordon.query-shapes.v3+json")
	v3ContractRequest.SetBasicAuth("client", "secret")
	v3Response := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":  []string{"application/vnd.quordon.query-shapes.v3+json"},
			"X-Request-ID":  []string{"req-contract"},
			"Cache-Control": []string{"no-store"},
			"Vary":          []string{"Accept"},
		},
		Body: io.NopCloser(strings.NewReader(v2Body)),
	}
	valid, validationErrors = contract.ValidateHttpResponse(v3ContractRequest, v3Response)
	if !valid {
		t.Fatalf("time-bucket-only v3 response violates layered design contract: %v", validationErrors)
	}
}

func TestSuccessfulKeysetHandlerMatchesExecutableOpenAPI31(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()
	server, sink, closeDatabases := successfulKeysetContractServer(t)
	defer closeDatabases()
	body := `{
		"kind":"keyset","profile":"reader","shape":"orders_page",
		"query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"order_by":[{"field":"id","direction":"asc"}],"limit":2},
		"page":{"kind":"first"}
	}`
	contractRequest := newContractRequest(http.MethodPost, "/queries/select", body)
	valid, validationErrors := contract.ValidateHttpRequestSync(contractRequest)
	if !valid {
		t.Fatalf("keyset request violates executable OpenAPI: %v", validationErrors)
	}
	runtimeRequest := newContractRequest(http.MethodPost, "/queries/select", body)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, runtimeRequest)
	if response.Code != http.StatusOK {
		t.Fatalf("keyset runtime status=%d body=%s", response.Code, response.Body.String())
	}
	responseRequest := newContractRequest(http.MethodPost, "/queries/select", body)
	valid, validationErrors = contract.ValidateHttpResponse(responseRequest, response.Result())
	if !valid {
		t.Fatalf("keyset runtime response violates executable OpenAPI: %v; body=%s", validationErrors, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"kind":"keyset"`) ||
		!strings.Contains(response.Body.String(), `"shape":"orders_page"`) ||
		!strings.Contains(response.Body.String(), `"page":{"has_more":false}`) {
		t.Fatalf("unexpected keyset response: %s", response.Body.String())
	}
	if len(sink.Events) < 2 {
		t.Fatalf("keyset audit events=%+v", sink.Events)
	}
	decision := sink.Events[len(sink.Events)-2]
	completion := sink.Events[len(sink.Events)-1]
	if decision.Operation != string(domain.OperationSelectKeyset) || completion.Operation != string(domain.OperationSelectKeyset) ||
		completion.Outcome != "success" || completion.ResultBytes != response.Body.Len() ||
		len(completion.Resources) != 1 || len(completion.Fields) != 1 || completion.Fields[0] != "id" {
		t.Fatalf("incomplete keyset audit: decision=%+v completion=%+v", decision, completion)
	}
}

func TestSuccessfulKeysetDiscoveryHandlerMatchesExecutableOpenAPI31(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()
	server, sink, closeDatabases := successfulKeysetContractServer(t)
	defer closeDatabases()

	runtimeRequest := newContractRequest(http.MethodGet, "/query-shapes?profile=reader", "")
	runtimeRequest.Header.Set("Accept", domain.QueryShapesMediaTypeV3)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, runtimeRequest)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != domain.QueryShapesMediaTypeV3 {
		t.Fatalf("keyset discovery status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	contractRequest := newContractRequest(http.MethodGet, "/query-shapes?profile=reader", "")
	contractRequest.Header.Set("Accept", domain.QueryShapesMediaTypeV3)
	valid, validationErrors := contract.ValidateHttpResponse(contractRequest, response.Result())
	if !valid {
		t.Fatalf("keyset discovery runtime response violates executable OpenAPI: %v; body=%s", validationErrors, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"operation":"select_keyset"`) ||
		!strings.Contains(response.Body.String(), `"name":"orders_page"`) ||
		!strings.Contains(response.Body.String(), `"name":"orders_page_aliased"`) ||
		!strings.Contains(response.Body.String(), `"alias":"order_id"`) ||
		strings.Contains(response.Body.String(), "required_index") || strings.Contains(response.Body.String(), "maximum_rows_examined_per_scan") {
		t.Fatalf("unsafe or incomplete keyset discovery response: %s", response.Body.String())
	}
	if len(sink.Events) < 2 || sink.Events[len(sink.Events)-1].PublicShapeSetHash == "" ||
		sink.Events[len(sink.Events)-1].ShapeCount != 4 {
		t.Fatalf("incomplete keyset discovery audit: %+v", sink.Events)
	}

	for _, mediaType := range []string{domain.QueryShapesMediaTypeV1, domain.QueryShapesMediaTypeV2} {
		request := newContractRequest(http.MethodGet, "/query-shapes?profile=reader", "")
		request.Header.Set("Accept", mediaType)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNotAcceptable || response.Header().Get("Vary") != "Accept" {
			t.Fatalf("legacy discovery media=%q status=%d headers=%v body=%s", mediaType, response.Code, response.Header(), response.Body.String())
		}
	}
}

func TestSelectRouteRejectsUnsupportedMethodsBeforeAuthentication(t *testing.T) {
	server, _, closeDatabases := successfulKeysetContractServer(t)
	defer closeDatabases()
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodOptions, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			request := httptest.NewRequest(method, "/queries/select", nil)
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodPost ||
				response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
			}
			if response.Header().Get("X-Quordon-Error-Code") != "METHOD_NOT_ALLOWED" {
				t.Fatalf("stable code header=%q", response.Header().Get("X-Quordon-Error-Code"))
			}
		})
	}
}

func keysetDesignRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "http://quordon.test/queries/select", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("contract-client", "contract-password")
	return request
}

func loadKeysetPaginationDesignValidator(t *testing.T) openapivalidator.Validator {
	t.Helper()
	specification, err := os.ReadFile("../../openapi/keyset-pagination.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configuration := datamodel.NewDocumentConfiguration()
	configuration.BasePath = "../../openapi"
	configuration.SpecFilePath = "keyset-pagination.yaml"
	configuration.FileFilter = []string{"keyset-pagination.yaml", "openapi.yaml", "query-shapes.yaml", "aggregate.yaml", "table-statistics.yaml"}
	configuration.AllowFileReferences = true
	document, err := libopenapi.NewDocumentWithConfiguration(specification, configuration)
	if err != nil {
		t.Fatalf("parse keyset pagination design: %v", err)
	}
	contract, problems := openapivalidator.NewValidator(document)
	if len(problems) != 0 {
		t.Fatalf("create keyset pagination design validator: %v", problems)
	}
	valid, validationErrors := contract.ValidateDocument()
	if !valid {
		contract.Release()
		t.Fatalf("keyset pagination design validation failed: %v", validationErrors)
	}
	return contract
}

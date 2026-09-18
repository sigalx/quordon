package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/pb33f/libopenapi"
	openapivalidator "github.com/pb33f/libopenapi-validator"
	"github.com/pb33f/libopenapi/datamodel"
	"gopkg.in/yaml.v3"
)

type queryShapesContractDocument struct {
	Paths map[string]struct {
		Get struct {
			Audit struct {
				CommonRecords []string `yaml:"common-records"`
				PolicyHash    struct {
					FieldName string `yaml:"field-name"`
					Source    string `yaml:"source"`
					Required  bool   `yaml:"required-on-every-decision-and-completion"`
				} `yaml:"redacted-policy-hash"`
				PreTokenDenial struct {
					RecordsRaw bool `yaml:"records-requested-profile-raw"`
					Hash       struct {
						Algorithm string `yaml:"algorithm"`
						Output    string `yaml:"output"`
						Payload   string `yaml:"payload"`
					} `yaml:"requested-profile-hash"`
					ByteLength struct {
						Representation string `yaml:"representation"`
					} `yaml:"requested-profile-byte-length"`
				} `yaml:"pre-token-denial"`
				InternalBefore queryShapesInternalAudit `yaml:"internal-failure-before-token"`
				InternalAfter  queryShapesInternalAudit `yaml:"internal-failure-after-token"`
			} `yaml:"x-quordon-audit"`
		} `yaml:"get"`
	} `yaml:"paths"`
}

type queryShapesInternalAudit struct {
	Event      string `yaml:"event"`
	Outcome    string `yaml:"outcome"`
	ErrorKind  string `yaml:"error-kind"`
	DurationMS string `yaml:"duration-ms"`
}

func TestQueryShapesContractCompilesWithContractValidator(t *testing.T) {
	contract := loadQueryShapesContractValidator(t)
	contract.Release()
}

func TestQueryShapesRuntimeResponseMatchesRootOpenAPI31(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()
	server, closeDatabases := successfulContractServer(t)
	defer closeDatabases()

	request := httptest.NewRequest(http.MethodGet, "/query-shapes?profile=reader", nil)
	request.SetBasicAuth("client", "secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
	if !strings.Contains(response.Body.String(), `"name":"orders_by_id"`) ||
		!strings.Contains(response.Body.String(), `"name":"active_order_summary"`) ||
		!strings.Contains(response.Body.String(), `"description":"Count matching orders and report their latest creation time."`) ||
		!strings.Contains(response.Body.String(), `"value_types":["boolean"]`) ||
		strings.Contains(response.Body.String(), "required_index") ||
		strings.Contains(response.Body.String(), "maximum_rows_examined_per_scan") {
		t.Fatalf("runtime disclosure payload is incomplete or unsafe: %s", response.Body.String())
	}

	contractRequest := httptest.NewRequest(
		http.MethodGet, "http://quordon.test/query-shapes?profile=reader", nil,
	)
	contractRequest.SetBasicAuth("client", "secret")
	valid, validationErrors := contract.ValidateHttpResponse(contractRequest, response.Result())
	if !valid {
		t.Fatalf("runtime response violates root OpenAPI: %v; body=%s", validationErrors, response.Body.String())
	}
}

func TestQueryShapesPublishesTimeBucketsInJSON(t *testing.T) {
	contract := loadQueryShapesContractValidator(t)
	defer contract.Release()
	server, sink, closeDatabases := successfulTimeBucketContractServer(t)
	defer closeDatabases()
	for _, accept := range []string{"", "*/*", "application/json"} {
		request := httptest.NewRequest(http.MethodGet, "http://quordon.test/query-shapes?profile=reader", nil)
		request.SetBasicAuth("client", "secret")
		if accept != "" {
			request.Header.Set("Accept", accept)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" || !strings.Contains(response.Body.String(), `"kind":"time_bucket"`) {
			t.Fatalf("JSON time buckets status=%d body=%s", response.Code, response.Body.String())
		}
		if valid, errs := contract.ValidateHttpResponse(request, response.Result()); !valid {
			t.Fatalf("JSON discovery violates OpenAPI: %v", errs)
		}
		if len(sink.Events) < 2 || sink.Events[len(sink.Events)-1].ResultBytes != response.Body.Len() {
			t.Fatal("discovery completion bytes are incorrect")
		}
	}
}

func TestQueryShapesRuntimeEnforcesStrictQueryAndNoStoreOnErrors(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()
	server, closeDatabases := successfulContractServer(t)
	defer closeDatabases()
	for _, fixture := range []struct {
		name, path  string
		credentials bool
		status      int
	}{
		{name: "missing credentials", path: "/query-shapes?profile=reader", status: http.StatusUnauthorized},
		{name: "missing profile", path: "/query-shapes", credentials: true, status: http.StatusBadRequest},
		{name: "repeated profile", path: "/query-shapes?profile=reader&profile=reader", credentials: true, status: http.StatusBadRequest},
		{name: "additional parameter", path: "/query-shapes?profile=reader&other=x", credentials: true, status: http.StatusBadRequest},
		{name: "invalid utf8", path: "/query-shapes?profile=%FF", credentials: true, status: http.StatusBadRequest},
		{name: "unassigned", path: "/query-shapes?profile=unknown", credentials: true, status: http.StatusForbidden},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, fixture.path, nil)
			if fixture.credentials {
				request.SetBasicAuth("client", "secret")
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != fixture.status {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, fixture.status, response.Body.String())
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
			}
			contractRequest := httptest.NewRequest(http.MethodGet, "http://quordon.test"+fixture.path, nil)
			if fixture.credentials {
				contractRequest.SetBasicAuth("client", "secret")
			}
			valid, validationErrors := contract.ValidateHttpResponse(contractRequest, response.Result())
			if !valid {
				t.Fatalf("runtime error response violates root OpenAPI: %v; body=%s", validationErrors, response.Body.String())
			}
		})
	}
}

func TestQueryShapesRejectsUnsupportedMethodsBeforeAuthenticationAndAudit(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()
	server, sink, closeDatabases := successfulContractServerWithAudit(t)
	defer closeDatabases()

	for _, fixture := range []struct {
		method, username, password string
	}{
		{method: http.MethodHead, username: "client", password: "wrong"},
		{method: http.MethodHead, username: "client", password: "secret"},
		{method: http.MethodPost, username: "client", password: "secret"},
		{method: http.MethodPut, username: "client", password: "secret"},
		{method: http.MethodPatch, username: "client", password: "secret"},
		{method: http.MethodDelete, username: "client", password: "secret"},
		{method: http.MethodOptions, username: "client", password: "secret"},
	} {
		contractRequest := httptest.NewRequest(
			fixture.method, "http://quordon.test/query-shapes?profile=reader", nil,
		)
		if valid, _ := contract.ValidateHttpRequestSync(contractRequest); valid {
			t.Fatalf("%s /query-shapes unexpectedly satisfies the GET-only OpenAPI contract", fixture.method)
		}

		request := httptest.NewRequest(
			fixture.method, "http://quordon.test/query-shapes?profile=reader", nil,
		)
		request.SetBasicAuth(fixture.username, fixture.password)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405; body=%s", response.Code, response.Body.String())
		}
		if response.Header().Get("Allow") != http.MethodGet {
			t.Fatalf("Allow = %q, want GET", response.Header().Get("Allow"))
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
		}
		if response.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("%s reached Basic authentication middleware", fixture.method)
		}
		var apiResponse apiError
		if err := json.Unmarshal(response.Body.Bytes(), &apiResponse); err != nil {
			t.Fatalf("decode 405 response: %v", err)
		}
		if apiResponse.Code != "METHOD_NOT_ALLOWED" || apiResponse.RequestID == "" {
			t.Fatalf("405 response = %+v", apiResponse)
		}
		if len(sink.Events) != 0 {
			t.Fatalf("%s produced audit events: %+v", fixture.method, sink.Events)
		}
	}
}

func TestQueryShapesContractRequiresNonemptyRequestIDHeader(t *testing.T) {
	contract := loadQueryShapesContractValidator(t)
	defer contract.Release()

	request := httptest.NewRequest(http.MethodGet, "http://quordon.test/query-shapes?profile=analytics", nil)
	request.SetBasicAuth("contract-client", "contract-password")
	body := `{
		"policy_profile":"analytics",
		"policy_version":"1",
		"datasource":"primary-mysql",
		"adapter":"mysql8",
		"shapes":[{
			"name":"count_orders",
			"operation":"aggregate",
			"query":{
				"mode":"scalar",
				"source":{"schema":"application","name":"orders"},
				"projection":[{"kind":"measure","function":"count_all","alias":"total"}]
			}
		}]
	}`

	for _, fixture := range []struct {
		name      string
		requestID *string
		wantValid bool
	}{
		{name: "nonempty", requestID: stringPointer("req-contract"), wantValid: true},
		{name: "missing", requestID: nil, wantValid: false},
		{name: "empty", requestID: stringPointer(""), wantValid: false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			response := &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Type":  []string{"application/json"},
					"Cache-Control": []string{"no-store"},
					"Vary":          []string{"Accept"},
				},
				Body: io.NopCloser(strings.NewReader(body)),
			}
			if fixture.requestID != nil {
				response.Header.Set("X-Request-ID", *fixture.requestID)
			}

			valid, validationErrors := contract.ValidateHttpResponse(request, response)
			if valid != fixture.wantValid {
				t.Fatalf("OpenAPI response validity = %t, want %t; errors=%v", valid, fixture.wantValid, validationErrors)
			}
		})
	}
}

func TestQueryShapesContractValidatesAggregateBranches(t *testing.T) {
	contract := loadQueryShapesContractValidator(t)
	defer contract.Release()

	request := httptest.NewRequest(http.MethodGet, "http://quordon.test/query-shapes?profile=analytics", nil)
	request.SetBasicAuth("contract-client", "contract-password")
	validScalar := `{
		"policy_profile":"analytics","policy_version":"1","datasource":"primary-mysql","adapter":"mysql8",
		"shapes":[{"name":"count_orders","operation":"aggregate","query":{
			"mode":"scalar","source":{"schema":"application","name":"orders"},
			"projection":[{"kind":"measure","function":"count_all","alias":"total"}]
		}}]
	}`
	validGrouped := `{
		"policy_profile":"analytics","policy_version":"1","datasource":"primary-mysql","adapter":"mysql8",
		"shapes":[{"name":"orders_by_status","operation":"aggregate","query":{
			"mode":"grouped","source":{"schema":"application","name":"orders"},
			"projection":[
				{"kind":"dimension","field":"status"},
				{"kind":"measure","function":"count_all","alias":"total"}
			],
			"order_by":[{"kind":"measure","alias":"total","direction":"desc"}],
			"maximum_limit":100
		}}]
	}`

	for _, fixture := range []struct {
		name      string
		body      string
		wantValid bool
	}{
		{name: "scalar measure", body: validScalar, wantValid: true},
		{
			name:      "C1 control in public description",
			body:      strings.Replace(validScalar, `"operation":"aggregate"`, `"description":"\u0085","operation":"aggregate"`, 1),
			wantValid: false,
		},
		{
			name:      "scalar dimension is not a measure",
			body:      strings.Replace(validScalar, `{"kind":"measure","function":"count_all","alias":"total"}`, `{"kind":"dimension","field":"status"}`, 1),
			wantValid: false,
		},
		{name: "grouped dimension measure and order", body: validGrouped, wantValid: true},
		{
			name:      "unknown grouped order branch",
			body:      strings.Replace(validGrouped, `{"kind":"measure","alias":"total","direction":"desc"}`, `{"kind":"sideways","alias":"total","direction":"desc"}`, 1),
			wantValid: false,
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			response := queryShapesContractResponse(fixture.body, "req-contract")
			valid, validationErrors := contract.ValidateHttpResponse(request, response)
			if valid != fixture.wantValid {
				t.Fatalf("OpenAPI response validity = %t, want %t; errors=%v", valid, fixture.wantValid, validationErrors)
			}
		})
	}
}

func TestQueryShapesContractBoundsDenialAttributionAndAuditsInternalFailures(t *testing.T) {
	specification, err := os.ReadFile("../../openapi/query-shapes.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document queryShapesContractDocument
	if err := yaml.Unmarshal(specification, &document); err != nil {
		t.Fatal(err)
	}

	audit := document.Paths["/query-shapes"].Get.Audit
	if !slices.Contains(audit.CommonRecords, "redacted-policy-hash") ||
		audit.PolicyHash.FieldName != "policy_hash" ||
		audit.PolicyHash.Source != "canonical-redacted-policy-snapshot-bound-to-the-authorization-decision" ||
		!audit.PolicyHash.Required {
		t.Fatalf("common audit records do not bind the redacted policy snapshot: %+v", audit.PolicyHash)
	}
	if audit.PreTokenDenial.RecordsRaw ||
		audit.PreTokenDenial.Hash.Algorithm != "sha-256" ||
		audit.PreTokenDenial.Hash.Output != "lowercase-hex" ||
		audit.PreTokenDenial.Hash.Payload != "exact-valid-utf8-query-parameter-bytes" ||
		audit.PreTokenDenial.ByteLength.Representation != "bounded-unsigned-integer" {
		t.Fatalf("denial attribution is not fixed-size and non-raw: %+v", audit.PreTokenDenial)
	}
	for name, internal := range map[string]queryShapesInternalAudit{
		"before token": audit.InternalBefore,
		"after token":  audit.InternalAfter,
	} {
		if internal.Event != "operation_completion" || internal.Outcome != "error" ||
			internal.ErrorKind != "internal" || internal.DurationMS != "required-including-zero" {
			t.Fatalf("%s internal completion is incomplete: %+v", name, internal)
		}
	}
}

func loadQueryShapesContractValidator(t *testing.T) openapivalidator.Validator {
	t.Helper()
	specification, err := os.ReadFile("../../openapi/query-shapes.yaml")
	if err != nil {
		t.Fatal(err)
	}

	configuration := datamodel.NewDocumentConfiguration()
	configuration.BasePath = "../../openapi"
	configuration.SpecFilePath = "query-shapes.yaml"
	configuration.FileFilter = []string{"query-shapes.yaml", "openapi.yaml", "aggregate.yaml", "table-statistics.yaml"}
	configuration.AllowFileReferences = true
	document, err := libopenapi.NewDocumentWithConfiguration(specification, configuration)
	if err != nil {
		t.Fatalf("parse query-shapes contract: %v", err)
	}

	contract, problems := openapivalidator.NewValidator(document)
	if len(problems) != 0 {
		t.Fatalf("create query-shapes contract validator: %v", problems)
	}

	valid, validationErrors := contract.ValidateDocument()
	if !valid {
		contract.Release()
		t.Fatalf("query-shapes OpenAPI 3.1 validation failed: %v", validationErrors)
	}
	return contract
}

func stringPointer(value string) *string {
	return &value
}

func queryShapesContractResponse(body, requestID string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":  []string{"application/json"},
			"Cache-Control": []string{"no-store"},
			"X-Request-ID":  []string{requestID},
			"Vary":          []string{"Accept"},
		},
		Body: io.NopCloser(strings.NewReader(body)),
	}
}

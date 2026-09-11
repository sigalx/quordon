package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/pb33f/libopenapi"
	openapivalidator "github.com/pb33f/libopenapi-validator"
	"github.com/pb33f/libopenapi/datamodel"
)

func TestTableStatisticsContractCompilesWithContractValidator(t *testing.T) {
	contract := loadTableStatisticsContractValidator(t)
	contract.Release()
}

func TestTableStatisticsRuntimeRejectsBodiesBeforeProfileResolution(t *testing.T) {
	server, sink, closeDatabases := successfulContractServerWithAudit(t)
	defer closeDatabases()

	fixtures := []struct {
		name             string
		body             io.Reader
		contentLength    int64
		transferEncoding []string
	}{
		{name: "positive content length", body: strings.NewReader("x"), contentLength: 1},
		{name: "decoded byte with unknown length", body: strings.NewReader("x"), contentLength: -1},
		{name: "handler visible transfer encoding", body: http.NoBody, transferEncoding: []string{"chunked"}},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodGet, "/schemas/app/objects/orders/statistics?profile=reader", fixture.body,
			)
			request.SetBasicAuth("client", "secret")
			request.ContentLength = fixture.contentLength
			request.TransferEncoding = fixture.transferEncoding
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("response = %d headers=%v body=%s", response.Code, response.Header(), response.Body)
			}
			var result apiError
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Code != "INVALID_REQUEST" {
				t.Fatalf("error response = %#v, %v", result, err)
			}
			if len(sink.Events) != 0 {
				t.Fatalf("body rejection reached profile/audit path: %+v", sink.Events)
			}
		})
	}
}

func TestTableStatisticsAuthenticatesBeforeBodyValidation(t *testing.T) {
	server, sink, closeDatabases := successfulContractServerWithAudit(t)
	defer closeDatabases()
	request := httptest.NewRequest(
		http.MethodGet, "/schemas/app/objects/orders/statistics?profile=reader", strings.NewReader("x"),
	)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || response.Header().Get("WWW-Authenticate") == "" ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response = %d headers=%v body=%s", response.Code, response.Header(), response.Body)
	}
	if len(sink.Events) != 0 {
		t.Fatalf("unauthenticated body reached audit: %+v", sink.Events)
	}
}

func TestTableStatisticsRuntimeRejectsUnsupportedMethodsBeforeAuthentication(t *testing.T) {
	server, sink, closeDatabases := successfulContractServerWithAudit(t)
	defer closeDatabases()
	for _, method := range []string{http.MethodHead, http.MethodPost, http.MethodPut, http.MethodOptions} {
		request := httptest.NewRequest(method, "/schemas/app/objects/orders/statistics?profile=reader", nil)
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet ||
			response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("%s response = %d headers=%v body=%s", method, response.Code, response.Header(), response.Body)
		}
		if method == http.MethodHead && response.Header().Get("X-Quordon-Error-Code") != "METHOD_NOT_ALLOWED" {
			t.Fatalf("HEAD stable error header = %q", response.Header().Get("X-Quordon-Error-Code"))
		}
		if len(sink.Events) != 0 {
			t.Fatalf("%s reached audit: %+v", method, sink.Events)
		}
	}
}

func TestTableStatisticsContractRejectsNoncanonicalMetrics(t *testing.T) {
	contract := loadTableStatisticsContractValidator(t)
	defer contract.Release()
	request := httptest.NewRequest(
		http.MethodGet, "http://quordon.test/schemas/app/objects/orders/statistics?profile=reader", nil,
	)
	request.SetBasicAuth("client", "secret")
	validBody := `{"policy_profile":"reader","policy_version":"1","datasource":"mysql","adapter":"mysql8","schema":"app","name":"orders","observed_at":"2026-09-02T12:00:00Z","engine":"InnoDB","table":{"estimated_rows":{"value":"1","estimated":true},"data_bytes":null,"index_bytes":null,"auto_increment":null},"partitioning":{"kind":"none"}}`
	for _, fixture := range []struct {
		name, body string
		valid      bool
	}{
		{name: "canonical", body: validBody, valid: true},
		{name: "number", body: strings.Replace(validBody, `"value":"1"`, `"value":1`, 1)},
		{name: "leading zero", body: strings.Replace(validBody, `"value":"1"`, `"value":"01"`, 1)},
		{name: "wrong estimated flag", body: strings.Replace(validBody, `"estimated":true`, `"estimated":false`, 1)},
	} {
		response := &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type": []string{"application/json"}, "Cache-Control": []string{"no-store"},
				"X-Request-ID": []string{"req-contract"},
			},
			Body: io.NopCloser(strings.NewReader(fixture.body)),
		}
		valid, validationErrors := contract.ValidateHttpResponse(request, response)
		if valid != fixture.valid {
			t.Fatalf("%s validity=%t want=%t errors=%v", fixture.name, valid, fixture.valid, validationErrors)
		}
	}
}

func TestTableStatisticsContractAcceptsEveryRuntimePartitioningBranch(t *testing.T) {
	contract := loadTableStatisticsContractValidator(t)
	defer contract.Release()
	request := httptest.NewRequest(
		http.MethodGet, "http://quordon.test/schemas/app/objects/orders/statistics?profile=reader", nil,
	)
	request.SetBasicAuth("client", "secret")
	const prefix = `{"policy_profile":"reader","policy_version":"1","datasource":"mysql","adapter":"mysql8","schema":"app","name":"orders","observed_at":"2026-09-02T12:00:00.123456789Z","engine":"InnoDB","table":{"estimated_rows":{"value":"18446744073709551615","estimated":true},"data_bytes":null,"index_bytes":{"value":"0","estimated":true},"auto_increment":{"value":"1","estimated":false}},"partitioning":`
	for _, fixture := range []struct {
		name, partitioning string
	}{
		{name: "none", partitioning: `{"kind":"none"}`},
		{name: "partitioned", partitioning: `{"kind":"partitioned","method":"range_columns","partitions":[{"name":"p0","ordinal":1,"statistics":{"estimated_rows":{"value":"1","estimated":true},"data_bytes":null,"index_bytes":null}}]}`},
		{name: "subpartitioned", partitioning: `{"kind":"subpartitioned","method":"list","subpartition_method":"linear_hash","partitions":[{"name":"p0","ordinal":1,"subpartitions":[{"name":"p0s0","ordinal":1,"statistics":{"estimated_rows":null,"data_bytes":{"value":"2","estimated":true},"index_bytes":null}}]}]}`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			response := &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Type": []string{"application/json"}, "Cache-Control": []string{"no-store"},
					"X-Request-ID": []string{"req-contract"},
				},
				Body: io.NopCloser(strings.NewReader(prefix + fixture.partitioning + `}`)),
			}
			valid, validationErrors := contract.ValidateHttpResponse(request, response)
			if !valid {
				t.Fatalf("response invalid: %v", validationErrors)
			}
		})
	}
}

func TestTableStatisticsRawJSONRejectsDuplicateMembers(t *testing.T) {
	for _, fixture := range []string{
		`{"schema":"app","schema":"other"}`,
		`{"table":{"estimated_rows":null,"estimated_rows":null}}`,
	} {
		if err := rejectDuplicateJSONMembers(strings.NewReader(fixture)); err == nil {
			t.Fatalf("duplicate-member response unexpectedly passed raw scan: %s", fixture)
		}
	}
	if err := rejectDuplicateJSONMembers(strings.NewReader(
		`{"table":{"estimated_rows":null},"partitioning":{"kind":"none"}}`,
	)); err != nil {
		t.Fatalf("unique response rejected: %v", err)
	}
}

func rejectDuplicateJSONMembers(reader io.Reader) error {
	decoder := json.NewDecoder(reader)
	if err := scanUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple top-level JSON values")
		}
		return err
	}
	return nil
}

func scanUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object member name is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON member %q", key)
			}
			seen[key] = struct{}{}
			if err := scanUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("invalid object terminator: %v", err)
		}
	case '[':
		for decoder.More() {
			if err := scanUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("invalid array terminator: %v", err)
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func loadTableStatisticsContractValidator(t *testing.T) openapivalidator.Validator {
	t.Helper()
	specification, err := os.ReadFile("../../openapi/table-statistics.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configuration := datamodel.NewDocumentConfiguration()
	configuration.BasePath = "../../openapi"
	configuration.SpecFilePath = "table-statistics.yaml"
	configuration.FileFilter = []string{"table-statistics.yaml", "openapi.yaml", "aggregate.yaml", "query-shapes.yaml"}
	configuration.AllowFileReferences = true
	document, err := libopenapi.NewDocumentWithConfiguration(specification, configuration)
	if err != nil {
		t.Fatalf("parse table-statistics contract: %v", err)
	}
	contract, problems := openapivalidator.NewValidator(document)
	if len(problems) != 0 {
		t.Fatalf("create table-statistics validator: %v", problems)
	}
	valid, validationErrors := contract.ValidateDocument()
	if !valid {
		contract.Release()
		t.Fatalf("table-statistics OpenAPI 3.1 validation failed: %v", validationErrors)
	}
	return contract
}

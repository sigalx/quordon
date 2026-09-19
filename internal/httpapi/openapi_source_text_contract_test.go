package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sigalx/quordon/internal/queryspec"
)

func TestSourceTextContractFixturesMatchOpenAPIAndStrictRuntime(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()
	selectBody := `{"profile":"reader","datasource":"mysql","query":{"source":{"schema":"app","name":"events"},"projection":[{"kind":"field","field":"event_date","representation":"source_text"}],"filter":{"kind":"predicate","field":"event_date","representation":"source_text","operator":"eq","values":[{"type":"string","value":"2026-02-31"}]},"order_by":[{"field":"event_date","direction":"asc","representation":"source_text"}],"limit":2}}`
	aggregateBody := `{"profile":"reader","datasource":"mysql","query":{"mode":"grouped","source":{"schema":"app","name":"events"},"projection":[{"kind":"dimension","field":"event_date","representation":"source_text"},{"kind":"measure","function":"count_all","alias":"total"}],"filter":{"kind":"predicate","field":"event_date","representation":"source_text","operator":"eq","values":[{"type":"string","value":"0000-00-00"}]},"order_by":[{"kind":"dimension","field":"event_date","direction":"asc","representation":"source_text"}],"limit":2}}`
	keysetBody := `{"kind":"keyset","profile":"reader","datasource":"mysql","shape":"events_page","query":{"source":{"schema":"app","name":"events"},"projection":[{"kind":"field","field":"event_date","representation":"source_text"}],"filter":{"kind":"predicate","field":"event_date","representation":"source_text","operator":"eq","values":[{"type":"string","value":"0000-00-00"}]},"order_by":[{"field":"event_date","direction":"asc","representation":"source_text"}],"limit":2},"page":{"kind":"after","cursor":[{"type":"string","value":"2026-02-31"}]}}`
	for _, endpoint := range []struct {
		path, body string
		decode     func([]byte) error
	}{
		{"/queries/select", selectBody, func(b []byte) error { _, e := queryspec.DecodeStrictSelectVNext(b, 8, 20, 30); return e }},
		{"/queries/select", keysetBody, func(b []byte) error { _, e := queryspec.DecodeStrictSelectVNext(b, 8, 20, 30); return e }},
		{"/queries/aggregate", aggregateBody, func(b []byte) error { _, e := queryspec.DecodeStrictAggregate(b, 8, 20, 30); return e }},
	} {
		fixtures := []selectRequestContractFixture{{name: "source_text", body: endpoint.body, valid: true}, {name: "omitted", body: strings.ReplaceAll(endpoint.body, `,"representation":"source_text"`, ``), valid: true}}
		for position := 0; position < 3; position++ {
			for _, token := range []string{`null`, `""`, `"unknown"`, `true`, `1`, `[]`, `{}`} {
				parts := strings.Split(endpoint.body, `"representation":"source_text"`)
				parts[position+1] = `"representation":` + token + parts[position+1]
				body := strings.Join(parts[:position+1], `"representation":"source_text"`) + strings.Join(parts[position+1:], `"representation":"source_text"`)
				fixtures = append(fixtures, selectRequestContractFixture{name: token, body: body})
			}
		}
		fixtures = append(fixtures, selectRequestContractFixture{name: "temporal bind", body: strings.Replace(endpoint.body, `"type":"string","value":"0000-00-00"`, `"type":"date","value":"2026-01-01"`, 1)})
		// The select baseline contains a different diagnostic value.
		fixtures[len(fixtures)-1].body = strings.Replace(fixtures[len(fixtures)-1].body, `"type":"string","value":"2026-02-31"`, `"type":"date","value":"2026-01-01"`, 1)
		for _, fixture := range fixtures {
			request := httptest.NewRequest(http.MethodPost, "http://quordon.test"+endpoint.path, strings.NewReader(fixture.body))
			request.Header.Set("Content-Type", "application/json")
			request.SetBasicAuth("contract-client", "contract-password")
			valid, errs := contract.ValidateHttpRequestSync(request)
			if valid != fixture.valid {
				t.Fatalf("%s %s OpenAPI=%t expected=%t errors=%v body=%s", endpoint.path, fixture.name, valid, fixture.valid, errs, fixture.body)
			}
			err := endpoint.decode([]byte(fixture.body))
			if (err == nil) != fixture.valid {
				t.Fatalf("%s %s runtime=%v expected valid=%t body=%s", endpoint.path, fixture.name, err, fixture.valid, fixture.body)
			}
		}
	}
}

func TestDiscoveryRejectsRetiredMediaTypesBeforeDatasourceCalls(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()
	server, closeDatabases := successfulContractServer(t)
	defer closeDatabases()
	for _, media := range []string{"application/vnd.quordon.query-shapes.v2+json", "application/vnd.quordon.query-shapes.v3+json", "application/json; charset=utf-8", "application/json,text/plain"} {
		request := httptest.NewRequest(http.MethodGet, "http://quordon.test/query-shapes?profile=reader&datasource=mysql", nil)
		request.SetBasicAuth("client", "secret")
		request.Header.Set("Accept", media)
		if valid, _ := contract.ValidateHttpRequestSync(request); valid {
			t.Fatalf("retired media schema-valid: %s", media)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"INVALID_REQUEST"`) {
			t.Fatalf("retired media accepted: %d %s", response.Code, response.Body.String())
		}
	}
}

func TestSourceTextAggregateOrderMismatchIsSchemaValidSemantic422(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()
	server, closeDatabases := successfulContractServer(t)
	defer closeDatabases()
	body := `{"profile":"reader","datasource":"mysql","query":{"mode":"grouped","source":{"schema":"app","name":"orders"},"projection":[{"kind":"dimension","field":"id","representation":"source_text"},{"kind":"measure","function":"count_all","alias":"total"}],"order_by":[{"kind":"dimension","field":"id","direction":"asc"}],"limit":2}}`
	request := httptest.NewRequest(http.MethodPost, "http://quordon.test/queries/aggregate", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("client", "secret")
	if valid, errs := contract.ValidateHttpRequestSync(request); !valid {
		t.Fatalf("semantic fixture must be schema-valid: %v", errs)
	}
	if _, err := queryspec.DecodeStrictAggregate([]byte(body), 8, 20, 30); err != nil {
		t.Fatalf("semantic fixture failed transport decode: %v", err)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), `"code":"UNSUPPORTED_QUERY"`) {
		t.Fatalf("diagnostic order mismatch returned %d: %s", response.Code, response.Body.String())
	}
	if valid, errs := contract.ValidateHttpResponse(request, response.Result()); !valid {
		t.Fatalf("semantic failure violates response contract: %v", errs)
	}
}

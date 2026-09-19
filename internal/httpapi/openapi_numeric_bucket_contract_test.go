package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sigalx/quordon/internal/queryspec"
)

const numericRequestFixture = `{"profile":"reader","datasource":"mysql","query":{"mode":"grouped","source":{"schema":"app","name":"orders"},"projection":[{"kind":"numeric_bucket","field":"id","alias":"id_bucket"},{"kind":"measure","function":"count_all","alias":"bucket_count"}],"order_by":[{"kind":"numeric_bucket","alias":"id_bucket","direction":"asc"}],"limit":10}}`

func TestNumericBucketRequestsMatchOpenAPIAndRuntime(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()
	server, _, closeDB := successfulContractServerWithOptions(t, false, false, true)
	defer closeDB()
	fixtures := []selectRequestContractFixture{{name: "valid", body: numericRequestFixture, valid: true}, {name: "integral decimal limit", body: strings.Replace(numericRequestFixture, `"limit":10`, `"limit":1e1`, 1), valid: true}}
	for _, change := range [][2]string{
		{`"kind":"numeric_bucket",`, `"kind":null,`}, {`"kind":"numeric_bucket",`, ``},
		{`"field":"id",`, ``}, {`"field":"id"`, `"field":null`}, {`"field":"id"`, `"field":1`}, {`"field":"id"`, `"field":""`},
		{`"alias":"id_bucket"`, `"alias":null`}, {`"alias":"id_bucket"`, `"alias":true`}, {`"alias":"id_bucket"`, `"alias":""`}, {`,"alias":"id_bucket"`, ``},
		{`"kind":"numeric_bucket","field"`, `"kind":"numeric_bucket","boundaries":["0"],"field"`},
		{`"kind":"numeric_bucket","field"`, `"kind":"numeric_bucket","function":"min","field"`},
		{`"kind":"numeric_bucket","field"`, `"kind":"numeric_bucket","unit":"day","field"`},
		{`"kind":"numeric_bucket","field"`, `"kind":"numeric_bucket","timezone":"UTC","field"`},
		{`"kind":"numeric_bucket","field"`, `"kind":"numeric_bucket","representation":"source_text","field"`},
		{`"kind":"numeric_bucket","alias"`, `"kind":"numeric_bucket","boundaries":["0"],"alias"`},
		{`"kind":"numeric_bucket","alias"`, `"kind":"numeric_bucket","field":"id","alias"`},
		{`"kind":"numeric_bucket","alias"`, `"kind":"numeric_bucket","representation":"source_text","alias"`},
		{`"direction":"asc"`, `"direction":null`}, {`"direction":"asc"`, `"direction":1`}, {`,"direction":"asc"`, ``},
		{`"mode":"grouped"`, `"mode":"scalar"`}, {`"limit":10`, `"limit":"10"`}, {`"limit":10`, `"limit":null`}, {`"limit":10`, `"limit":1.5`},
	} {
		fixtures = append(fixtures, selectRequestContractFixture{name: change[1], body: strings.Replace(numericRequestFixture, change[0], change[1], 1)})
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			req := newContractRequest(http.MethodPost, "/queries/aggregate", fixture.body)
			valid, errs := contract.ValidateHttpRequest(req)
			if valid != fixture.valid {
				t.Fatalf("schema valid=%t want=%t errors=%v", valid, fixture.valid, errs)
			}
			_, err := queryspec.DecodeStrictAggregate([]byte(fixture.body), 4, 10, 20)
			if (err == nil) != fixture.valid {
				t.Fatalf("decoder error=%v want valid=%t", err, fixture.valid)
			}
			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, newContractRequest(http.MethodPost, "/queries/aggregate", fixture.body))
			want := http.StatusBadRequest
			if fixture.valid {
				want = http.StatusOK
			}
			if recorder.Code != want {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if fixture.valid {
				if valid, errs := contract.ValidateHttpResponse(newContractRequest(http.MethodPost, "/queries/aggregate", fixture.body), recorder.Result()); !valid {
					t.Fatalf("response errors=%v", errs)
				}
			}
		})
	}
	// Duplicate members and exact/case-folded keys are transport restrictions that
	// a JSON Schema operating on decoded objects cannot express.
	for _, body := range []string{
		strings.Replace(numericRequestFixture, `"field":"id"`, `"field":"id","field":"id"`, 1),
		strings.Replace(numericRequestFixture, `"kind":"numeric_bucket"`, `"kind":"numeric_bucket","Kind":"numeric_bucket"`, 1),
		strings.Replace(numericRequestFixture, `"direction":"asc"`, `"direction":"asc","direction":"asc"`, 1),
		strings.Replace(numericRequestFixture, `"field":"id"`, `"Field":"id"`, 1),
		strings.Replace(numericRequestFixture, `"field":"id"`, `"field":"`+string([]byte{0xff})+`"`, 1),
		`[]`, `null`,
	} {
		if _, err := queryspec.DecodeStrictAggregate([]byte(body), 4, 10, 20); err == nil {
			t.Fatalf("accepted invalid transport %q", body)
		}
	}
}

func TestNumericBucketRequestCanBeBuiltFromDiscovery(t *testing.T) {
	rootContract := loadOpenAPI31Validator(t)
	defer rootContract.Release()
	discoveryContract := loadQueryShapesContractValidator(t)
	defer discoveryContract.Release()
	server, _, closeDB := successfulContractServerWithOptions(t, false, false, true)
	defer closeDB()
	req := newContractRequest(http.MethodGet, "/query-shapes?profile=reader&datasource=mysql", "")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, req)
	if response.Code != 200 {
		t.Fatalf("discovery=%s", response.Body)
	}
	valid, errs := discoveryContract.ValidateHttpResponse(newContractRequest(http.MethodGet, "/query-shapes?profile=reader&datasource=mysql", ""), response.Result())
	if !valid {
		t.Fatalf("discovery contract=%v", errs)
	}
	valid, errs = rootContract.ValidateHttpResponse(newContractRequest(http.MethodGet, "/query-shapes?profile=reader&datasource=mysql", ""), response.Result())
	if !valid {
		t.Fatalf("root discovery=%v", errs)
	}
	var payload struct {
		Shapes []struct {
			Name  string                     `json:"name"`
			Query map[string]json.RawMessage `json:"query"`
		} `json:"shapes"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	var query map[string]json.RawMessage
	for _, shape := range payload.Shapes {
		if shape.Name == "orders_by_numeric" {
			query = shape.Query
		}
	}
	if query == nil {
		t.Fatal("numeric shape missing")
	}
	var projection []map[string]json.RawMessage
	if err := json.Unmarshal(query["projection"], &projection); err != nil {
		t.Fatal(err)
	}
	if string(projection[0]["boundaries"]) != `["0","100","500","1000"]` {
		t.Fatalf("boundaries=%s", projection[0]["boundaries"])
	}
	delete(projection[0], "boundaries")
	query["projection"], _ = json.Marshal(projection)
	query["limit"] = query["maximum_limit"]
	delete(query, "maximum_limit")
	body, err := json.Marshal(map[string]interface{}{"profile": "reader", "datasource": "mysql", "query": query})
	if err != nil {
		t.Fatal(err)
	}
	executed := httptest.NewRecorder()
	server.Handler().ServeHTTP(executed, newContractRequest(http.MethodPost, "/queries/aggregate", string(body)))
	if executed.Code != 200 {
		t.Fatalf("execution=%s", executed.Body)
	}
	valid, errs = rootContract.ValidateHttpResponse(newContractRequest(http.MethodPost, "/queries/aggregate", string(body)), executed.Result())
	if !valid {
		t.Fatalf("execution contract=%v", errs)
	}
}

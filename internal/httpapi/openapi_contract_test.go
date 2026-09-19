package httpapi

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/pb33f/libopenapi"
	openapivalidator "github.com/pb33f/libopenapi-validator"
	"github.com/pb33f/libopenapi/datamodel"
	"github.com/sigalx/quordon/internal/audit"
	"github.com/sigalx/quordon/internal/auth"
	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryservice"
	"github.com/sigalx/quordon/internal/queryspec"
	"github.com/sigalx/quordon/internal/secrets"
	"golang.org/x/crypto/bcrypt"
)

type selectRequestContractFixture struct {
	name  string
	body  string
	valid bool
}

var selectRequestContractFixtures = []selectRequestContractFixture{
	{
		name:  "field select",
		valid: true,
		body:  `{"profile":"reader","datasource":"mysql","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"order_by":[{"field":"id","direction":"asc"}],"limit":10}}`,
	},
	{
		name:  "RFC 3339 lower-case date-time separators",
		valid: true,
		body:  `{"profile":"reader","datasource":"mysql","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"predicate","field":"created_at","operator":"eq","values":[{"type":"datetime","value":"2026-01-01t00:00:00z"}]}}}`,
	},
	{
		name: "empty projection",
		body: `{"profile":"reader","datasource":"mysql","query":{"source":{"schema":"app","name":"orders"},"projection":[]}}`,
	},
	{
		name: "invalid source identifier",
		body: `{"profile":"reader","datasource":"mysql","query":{"source":{"schema":"bad-name","name":"orders"},"projection":[{"kind":"field","field":"id"}]}}`,
	},
	{
		name: "invalid order direction",
		body: `{"profile":"reader","datasource":"mysql","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"order_by":[{"field":"id","direction":"sideways"}]}}`,
	},
	{
		name: "aggregate projection",
		body: `{"profile":"reader","datasource":"mysql","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"aggregate","function":"count"}]}}`,
	},
	{
		name: "typed value mismatch",
		body: `{"profile":"reader","datasource":"mysql","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"predicate","field":"active","operator":"eq","values":[{"type":"boolean","value":"true"}]}}}`,
	},
}

var aggregateRequestContractFixtures = []selectRequestContractFixture{
	{
		name:  "scalar aggregate",
		valid: true,
		body:  `{"profile":"analytics","datasource":"mysql","query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"total"}]}}`,
	},
	{
		name:  "case-folded output collision is transport-valid",
		valid: true,
		body:  `{"profile":"analytics","datasource":"mysql","query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"total"},{"kind":"measure","function":"count_all","alias":"TOTAL"}]}}`,
	},
	{
		name:  "grouped aggregate",
		valid: true,
		body:  `{"profile":"analytics","datasource":"mysql","query":{"mode":"grouped","source":{"schema":"app","name":"orders"},"projection":[{"kind":"dimension","field":"status"},{"kind":"measure","function":"count_all","alias":"total"}],"order_by":[{"kind":"measure","alias":"total","direction":"desc"}],"limit":10}}`,
	},
	{
		name:  "grouped UTC time bucket",
		valid: true,
		body:  `{"profile":"analytics","datasource":"mysql","query":{"mode":"grouped","source":{"schema":"app","name":"orders"},"projection":[{"kind":"time_bucket","field":"created_at","unit":"day","timezone":"UTC","alias":"created_day"},{"kind":"measure","function":"count_all","alias":"total"}],"order_by":[{"kind":"time_bucket","alias":"created_day","direction":"asc"}],"limit":10}}`,
	},
	{
		name: "time bucket missing timezone",
		body: `{"profile":"analytics","datasource":"mysql","query":{"mode":"grouped","source":{"schema":"app","name":"orders"},"projection":[{"kind":"time_bucket","field":"created_at","unit":"day","alias":"created_day"},{"kind":"measure","function":"count_all","alias":"total"}],"limit":10}}`,
	},
	{
		name: "time bucket unknown unit",
		body: `{"profile":"analytics","datasource":"mysql","query":{"mode":"grouped","source":{"schema":"app","name":"orders"},"projection":[{"kind":"time_bucket","field":"created_at","unit":"minute","timezone":"UTC","alias":"created_day"},{"kind":"measure","function":"count_all","alias":"total"}],"limit":10}}`,
	},
	{
		name:  "integral exponent and canonical base64 binds",
		valid: true,
		body:  `{"profile":"analytics","datasource":"mysql","query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"total"}],"filter":{"kind":"group","operator":"and","expressions":[{"kind":"predicate","field":"id","operator":"eq","values":[{"type":"integer","value":1e2}]},{"kind":"predicate","field":"payload","operator":"eq","values":[{"type":"bytes","value":"YQ=="}]}]}}}`,
	},
	{
		name:  "large negative int64 bind",
		valid: true,
		body:  `{"profile":"analytics","datasource":"mysql","query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"total"}],"filter":{"kind":"predicate","field":"id","operator":"eq","values":[{"type":"integer","value":-9223372036854775000}]}}}`,
	},
	{
		name: "missing measure alias",
		body: `{"profile":"analytics","datasource":"mysql","query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all"}]}}`,
	},
	{
		name: "scalar limit",
		body: `{"profile":"analytics","datasource":"mysql","query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"total"}],"limit":1}}`,
	},
	{
		name: "grouped missing limit",
		body: `{"profile":"analytics","datasource":"mysql","query":{"mode":"grouped","source":{"schema":"app","name":"orders"},"projection":[{"kind":"dimension","field":"status"},{"kind":"measure","function":"count_all","alias":"total"}]}}`,
	},
	{
		name: "dimension branch with alias",
		body: `{"profile":"analytics","datasource":"mysql","query":{"mode":"grouped","source":{"schema":"app","name":"orders"},"projection":[{"kind":"dimension","field":"status","alias":"state"},{"kind":"measure","function":"count_all","alias":"total"}],"limit":10}}`,
	},
	{
		name: "typed value mismatch",
		body: `{"profile":"analytics","datasource":"mysql","query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"total"}],"filter":{"kind":"predicate","field":"active","operator":"eq","values":[{"type":"boolean","value":"true"}]}}}`,
	},
	{
		name: "duplicate filter expressions",
		body: `{"profile":"analytics","datasource":"mysql","query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"total"}],"filter":{"kind":"group","operator":"and","expressions":[{"kind":"predicate","field":"status","operator":"eq","values":[{"type":"string","value":"active"}]},{"kind":"predicate","field":"status","operator":"eq","values":[{"type":"string","value":"active"}]}]}}}`,
	},
	{
		name: "JSON-equal numeric duplicate filter expressions",
		body: `{"profile":"analytics","datasource":"mysql","query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"total"}],"filter":{"kind":"group","operator":"and","expressions":[{"kind":"predicate","field":"id","operator":"eq","values":[{"type":"integer","value":1}]},{"kind":"predicate","field":"id","operator":"eq","values":[{"type":"integer","value":1.0}]}]}}}`,
	},
	{
		name: "case-folded query key",
		body: `{"profile":"analytics","datasource":"mysql","Query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"total"}]}}`,
	},
	{
		name: "null optional filter",
		body: `{"profile":"analytics","datasource":"mysql","query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"total"}],"filter":null}}`,
	},
	{
		name: "integer bind overflow",
		body: `{"profile":"analytics","datasource":"mysql","query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"total"}],"filter":{"kind":"predicate","field":"id","operator":"eq","values":[{"type":"integer","value":9223372036854775808}]}}}`,
	},
	{
		name: "non-integral integer bind",
		body: `{"profile":"analytics","datasource":"mysql","query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"total"}],"filter":{"kind":"predicate","field":"id","operator":"eq","values":[{"type":"integer","value":1.5}]}}}`,
	},
	{
		name: "non-canonical base64 bind",
		body: `{"profile":"analytics","datasource":"mysql","query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"total"}],"filter":{"kind":"predicate","field":"payload","operator":"eq","values":[{"type":"bytes","value":"YR=="}]}}}`,
	},
}

func TestSelectContractFixturesMatchOpenAPI31AndRuntime(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()

	for _, fixture := range selectRequestContractFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodPost, "http://quordon.test/queries/select", strings.NewReader(fixture.body),
			)
			request.Header.Set("Content-Type", "application/json")
			request.SetBasicAuth("contract-client", "contract-password")
			openAPIValid, validationErrors := contract.ValidateHttpRequestSync(request)
			if openAPIValid != fixture.valid {
				t.Fatalf(
					"OpenAPI validity = %t, want %t; errors=%v",
					openAPIValid, fixture.valid, validationErrors,
				)
			}

			_, runtimeError := queryspec.DecodeStrictSelectVNext([]byte(fixture.body), 8, 200, 200)
			runtimeValid := runtimeError == nil
			if runtimeValid != fixture.valid {
				t.Fatalf(
					"runtime validity = %t, want %t; error=%v",
					runtimeValid, fixture.valid, runtimeError,
				)
			}
		})
	}
}

func TestAggregateContractFixturesMatchOpenAPI31AndRuntime(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()
	for _, fixture := range aggregateRequestContractFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodPost, "http://quordon.test/queries/aggregate", strings.NewReader(fixture.body),
			)
			request.Header.Set("Content-Type", "application/json")
			request.SetBasicAuth("contract-client", "contract-password")
			openAPIValid, validationErrors := contract.ValidateHttpRequestSync(request)
			if openAPIValid != fixture.valid {
				t.Fatalf("OpenAPI validity = %t, want %t; errors=%v", openAPIValid, fixture.valid, validationErrors)
			}
			_, runtimeError := queryspec.DecodeStrictAggregate([]byte(fixture.body), 8, 200, 200)
			if (runtimeError == nil) != fixture.valid {
				t.Fatalf("runtime validity = %t, want %t; error=%v", runtimeError == nil, fixture.valid, runtimeError)
			}
		})
	}
}

func TestSelectResponseFixturesMatchOpenAPI31(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()
	request := httptest.NewRequest(http.MethodPost, "http://quordon.test/queries/select", nil)
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("contract-client", "contract-password")

	validResponse := `{
		"query_id":"q-contract",
		"policy_profile":"reader",
		"policy_version":"1",
		"datasource":"mysql",
		"adapter":"mysql8",
		"columns":[{"name":"id","type":"integer","encoding":"string","nullable":false}],
		"rows":[["1"],[null]],
		"row_count":2,
		"truncated":false,
		"limits":{
			"deadline_ms":1000,
			"max_request_bytes":65536,
			"max_projection_fields":10,
			"max_group_by_fields":10,
			"max_order_by_fields":10,
			"max_predicates":10,
			"max_expression_depth":4,
			"max_parameters":20,
			"max_rows":100,
			"max_result_bytes":65536,
			"max_offset":100,
			"max_concurrency":1
		},
		"warnings":[]
	}`
	assertOpenAPIResponseValidity(t, contract, request, validResponse, true)

	invalidResponse := strings.Replace(validResponse, `"rows":[["1"],[null]]`, `"rows":[[1],[null]]`, 1)
	assertOpenAPIResponseValidity(t, contract, request, invalidResponse, false)
}

func TestAggregateResponseFixturesMatchOpenAPI31(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()
	request := httptest.NewRequest(http.MethodPost, "http://quordon.test/queries/aggregate", nil)
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("contract-client", "contract-password")
	limits := `"limits":{"deadline_ms":1000,"max_request_bytes":65536,"max_projection_fields":10,"max_group_by_fields":10,"max_order_by_fields":10,"max_predicates":10,"max_expression_depth":4,"max_parameters":20,"max_rows":100,"max_result_bytes":65536,"max_offset":100,"max_concurrency":1}`
	scalar := `{"mode":"scalar","query_id":"q-contract","policy_profile":"analytics","policy_version":"1","datasource":"mysql","adapter":"mysql8","columns":[{"name":"total","type":"integer","encoding":"string","nullable":false}],"rows":[["2"]],"row_count":1,"truncated":false,` + limits + `,"warnings":[]}`
	assertOpenAPIResponseValidity(t, contract, request, scalar, true)
	assertOpenAPIResponseValidity(t, contract, request, strings.Replace(scalar, `"rows":[["2"]]`, `"rows":[]`, 1), false)
	grouped := `{"mode":"grouped","query_id":"q-contract","policy_profile":"analytics","policy_version":"1","datasource":"mysql","adapter":"mysql8","columns":[{"name":"status","type":"string","encoding":"string","nullable":false},{"name":"total","type":"integer","encoding":"string","nullable":false}],"rows":[["active","2"]],"row_count":1,"truncated":false,` + limits + `,"warnings":[]}`
	assertOpenAPIResponseValidity(t, contract, request, grouped, true)
	assertOpenAPIResponseValidity(t, contract, request, strings.Replace(grouped, `["active","2"]`, `["active",2]`, 1), false)
}

func TestSuccessfulNewHandlersMatchOpenAPI31(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()
	server, closeDatabases := successfulContractServer(t)
	defer closeDatabases()

	fixtures := []struct {
		name, method, path, body string
	}{
		{
			name: "object list", method: http.MethodGet,
			path: "/schemas/app/objects?profile=reader&datasource=mysql",
		},
		{
			name: "object description", method: http.MethodGet,
			path: "/schemas/app/objects/orders?profile=reader&datasource=mysql",
		},
		{
			name: "object statistics", method: http.MethodGet,
			path: "/schemas/app/objects/orders/statistics?profile=reader&datasource=mysql",
		},
		{
			name: "bounded select", method: http.MethodPost, path: "/queries/select",
			body: `{"profile":"reader","datasource":"mysql","query":{"source":{"schema":"app","name":"orders"},"projection":[{"kind":"field","field":"id"}],"limit":2}}`,
		},
		{
			name: "grouped aggregate", method: http.MethodPost, path: "/queries/aggregate",
			body: `{"profile":"reader","datasource":"mysql","query":{"mode":"grouped","source":{"schema":"app","name":"orders"},"projection":[{"kind":"dimension","field":"id"},{"kind":"measure","function":"count_all","alias":"total"}],"limit":2}}`,
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			openAPIRequest := newContractRequest(fixture.method, fixture.path, fixture.body)
			requestValid, requestErrors := contract.ValidateHttpRequestSync(openAPIRequest)
			if !requestValid {
				t.Fatalf("successful handler request violates OpenAPI: %v", requestErrors)
			}

			runtimeRequest := newContractRequest(fixture.method, fixture.path, fixture.body)
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, runtimeRequest)
			if response.Code != http.StatusOK {
				t.Fatalf("runtime status = %d, want 200; body=%s", response.Code, response.Body)
			}

			responseRequest := newContractRequest(fixture.method, fixture.path, fixture.body)
			responseValid, responseErrors := contract.ValidateHttpResponse(responseRequest, response.Result())
			if !responseValid {
				t.Fatalf("successful runtime response violates OpenAPI: %v; body=%s", responseErrors, response.Body)
			}
		})
	}
}

type contractDriver struct{}

func (contractDriver) Open(string) (driver.Conn, error) { return nil, errors.New("not used") }

type contractConnector struct{}

func (contractConnector) Connect(context.Context) (driver.Conn, error) {
	return nil, errors.New("not used")
}
func (contractConnector) Driver() driver.Driver { return contractDriver{} }

type contractAdapter struct{}

func (*contractAdapter) Name() string { return domain.AdapterMySQL8 }
func (*contractAdapter) Capabilities() []domain.Operation {
	return []domain.Operation{
		domain.OperationListObjects, domain.OperationDescribeObject, domain.OperationDescribeObjectStatistics,
		domain.OperationSelect, domain.OperationSelectKeyset, domain.OperationAggregate,
	}
}
func (*contractAdapter) Features() []domain.AdapterFeature {
	return []domain.AdapterFeature{domain.FeatureTimeBucketUTC, domain.FeatureNumericBucketExact}
}
func (*contractAdapter) Validate(context.Context, *sql.DB) error { return nil }
func (*contractAdapter) IdentifierSemantics(context.Context, *sql.DB) (domain.IdentifierSemantics, error) {
	return domain.IdentifierSemantics{}, nil
}
func (*contractAdapter) Open(string, config.Datasource) (*sql.DB, error) {
	return sql.OpenDB(contractConnector{}), nil
}
func (*contractAdapter) Explain(context.Context, *sql.DB, policy.AuthorizedQuery) (database.ExplainResult, error) {
	panic("Explain is outside the successful handler contract fixtures")
}
func (*contractAdapter) ListObjects(context.Context, *sql.DB, string) ([]database.SchemaObject, error) {
	return []database.SchemaObject{{Name: "orders"}}, nil
}
func (*contractAdapter) DescribeObject(context.Context, *sql.DB, queryspec.ResourceRef) (database.ObjectDescription, error) {
	return database.ObjectDescription{
		Schema: "app", Name: "orders",
		Columns: []database.ColumnDescription{{
			Name: "id", Type: "integer", NativeType: "bigint unsigned",
			Nullable: false, PrimaryKey: true, Indexed: true,
		}},
	}, nil
}
func (*contractAdapter) Select(context.Context, *sql.DB, policy.AuthorizedQuery) (database.SelectResult, error) {
	value := "1"
	return database.SelectResult{
		Columns: []database.ResultColumn{{
			Name: "id", Type: "integer", Encoding: "string", Nullable: false,
		}},
		Rows: [][]*string{{&value}}, RowCount: 1, ResultBytes: 128,
	}, nil
}

func (*contractAdapter) SelectKeyset(
	_ context.Context, _ *sql.DB, authorized policy.AuthorizedKeysetSelect, budget database.KeysetEnvelopeBudget,
) (database.KeysetSelectResult, error) {
	value := "1"
	result := database.KeysetSelectResult{
		Columns: []database.ResultColumn{{Name: "id", Type: "integer", Encoding: "string", Nullable: false}},
		Rows:    [][]*string{{&value}}, RowCount: 1,
	}
	columns, _ := json.Marshal(result.Columns)
	rows, _ := json.Marshal(result.Rows)
	result.ResultBytes = budget.FinalBaseBytes + len(columns) - len(`[]`) + len(rows) - len(`[]`)
	if authorized.Query().Page.Kind != "first" {
		panic("contract adapter received an unexpected keyset page")
	}
	return result, nil
}

func (*contractAdapter) Aggregate(
	_ context.Context, _ *sql.DB, authorized policy.AuthorizedAggregate, _ int,
) (database.AggregateResult, error) {
	if queryspec.AggregateUsesNumericBucket(authorized.Query()) {
		if authorized.Operation() != domain.OperationAggregate || len(authorized.NumericBoundaries()["id_bucket"]) != 4 {
			panic("numeric bucket was not authorized")
		}
		bucket, total := "1", "2"
		return database.AggregateResult{Mode: "grouped", Columns: []database.ResultColumn{
			{Name: "id_bucket", Type: "integer", Encoding: "string", Nullable: true}, {Name: "bucket_count", Type: "integer", Encoding: "string", Nullable: false},
		}, Rows: [][]*string{{nil, &total}, {&bucket, &total}}, RowCount: 2, ResultBytes: 256}, nil
	}
	if queryspec.AggregateUsesTimeBucket(authorized.Query()) {
		bucket := "2026-09-01T00:00:00Z"
		total := "1"
		return database.AggregateResult{
			Mode: queryspec.AggregateModeGrouped,
			Columns: []database.ResultColumn{
				{Name: "created_day", Type: "datetime", Encoding: "string", Nullable: false},
				{Name: "daily_count", Type: "integer", Encoding: "string", Nullable: false},
			},
			Rows: [][]*string{{&bucket, &total}}, RowCount: 1, ResultBytes: 256,
		}, nil
	}
	id := "1"
	total := "1"
	return database.AggregateResult{
		Mode: queryspec.AggregateModeGrouped,
		Columns: []database.ResultColumn{
			{Name: "id", Type: "integer", Encoding: "string", Nullable: false},
			{Name: "total", Type: "integer", Encoding: "string", Nullable: false},
		},
		Rows: [][]*string{{&id, &total}}, RowCount: 1, ResultBytes: 256,
	}, nil
}

func TestSuccessfulTimeBucketHandlerMatchesOpenAPI31(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()
	server, _, closeDatabases := successfulTimeBucketContractServer(t)
	defer closeDatabases()
	body := `{"profile":"reader","datasource":"mysql","query":{"mode":"grouped","source":{"schema":"app","name":"orders"},"projection":[{"kind":"time_bucket","field":"created_at","unit":"day","timezone":"UTC","alias":"created_day"},{"kind":"measure","function":"count_all","alias":"daily_count"}],"order_by":[{"kind":"time_bucket","alias":"created_day","direction":"asc"}],"limit":10}}`
	runtimeRequest := newContractRequest(http.MethodPost, "/queries/aggregate", body)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, runtimeRequest)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"2026-09-01T00:00:00Z"`) {
		t.Fatalf("time-bucket handler status=%d body=%s", response.Code, response.Body.String())
	}
	contractRequest := newContractRequest(http.MethodPost, "/queries/aggregate", body)
	valid, validationErrors := contract.ValidateHttpResponse(contractRequest, response.Result())
	if !valid {
		t.Fatalf("time-bucket runtime response violates OpenAPI: %v; body=%s", validationErrors, response.Body.String())
	}
}

func (*contractAdapter) DescribeObjectStatistics(
	_ context.Context, _ *sql.DB, authorized policy.AuthorizedObjectStatistics, envelopeBaseBytes int,
) (database.ObjectStatisticsResult, error) {
	if authorized.Object() == "orders_view" {
		return database.ObjectStatisticsResult{}, &database.Error{Kind: database.ErrorInvalid}
	}
	return database.ObjectStatisticsResult{
		ObservedAt: "2026-09-02T12:00:00Z", Engine: "InnoDB",
		Table:        database.TableStatistics{},
		Partitioning: database.PartitioningResult{Kind: "none"},
		ResultBytes:  envelopeBaseBytes,
	}, nil
}

func successfulContractServer(t *testing.T) (*Server, func()) {
	server, _, closeDatabases := successfulContractServerWithAudit(t)
	return server, closeDatabases
}

func successfulContractServerWithAudit(t *testing.T) (*Server, *audit.MemorySink, func()) {
	return successfulContractServerWithOptions(t, false, false)
}

func successfulTimeBucketContractServer(t *testing.T) (*Server, *audit.MemorySink, func()) {
	return successfulContractServerWithOptions(t, true, false)
}

func successfulKeysetContractServer(t *testing.T) (*Server, *audit.MemorySink, func()) {
	return successfulContractServerWithOptions(t, false, true)
}

func successfulContractServerWithOptions(t *testing.T, withTimeBucket, withKeyset bool, numeric ...bool) (*Server, *audit.MemorySink, func()) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 65536, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10, MaxPredicates: 10,
		MaxExpressionDepth: 4, MaxParameters: 20, MaxRows: 100,
		MaxResultBytes: 65536, MaxOffset: 100, MaxConcurrency: 1,
	}
	shapeDescription := "Count matching orders and report their latest creation time."
	activeValueTypes := []string{"boolean"}
	cfg := config.Config{
		Version: 1, PolicyHash: "contract-hash", HardLimits: limits,
		Authentication: config.Authentication{Basic: config.BasicAuth{
			Realm: "quordon",
			Users: map[string]config.BasicUser{
				"client": {Principal: "contract-client", PasswordHashSecretRef: "env:PASSWORD_HASH"},
			},
		}},
		Principals: map[string]config.Principal{
			"contract-client": {Profiles: []string{"reader"}, Datasources: []string{"mysql"}},
		},
		Datasources: map[string]config.Datasource{
			"mysql": {Adapter: domain.AdapterMySQL8, DSN: "opaque"},
		},
		Profiles: map[string]config.Profile{
			"reader": {
				Datasources: []string{"mysql"},
				Operations: []domain.Operation{
					domain.OperationListObjects, domain.OperationDescribeObject,
					domain.OperationDescribeObjectStatistics, domain.OperationSelect,
					domain.OperationAggregate, domain.OperationListQueryShapes,
				},
				Limits: limits,
				Resources: config.ResourcePolicy{
					Schemas: config.PatternPolicy{Allow: []string{"app"}},
					Objects: config.PatternPolicy{Allow: []string{"app.orders", "app.orders_view"}},
					Fields: config.PatternPolicy{Allow: []string{
						"app.orders.id", "app.orders.active", "app.orders.created_at",
					}},
				},
				Query: config.QueryPolicy{
					AllowFiltering:         true,
					AllowGroupBy:           true,
					AllowedFilterOperators: []string{"eq"},
					AllowedAggregates:      []string{"count", "max"},
					AggregateShapes: []config.AggregateShape{
						{
							Name: "orders_by_id", Mode: queryspec.AggregateModeGrouped,
							Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
							Projection: []config.AggregateShapeOutput{
								{Kind: "dimension", Field: "id"},
								{Kind: "measure", Function: "count_all", Alias: "total"},
							},
							MaximumLimit: 10, RequiredIndex: "PRIMARY", MaximumRowsExaminedPerScan: 100,
						},
						{
							Name: "active_order_summary", PublicDescription: &shapeDescription,
							Mode:   queryspec.AggregateModeScalar,
							Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
							Projection: []config.AggregateShapeOutput{
								{Kind: "measure", Function: "count_all", Alias: "total"},
								{Kind: "measure", Function: "max", Field: "created_at", Alias: "latest"},
							},
							Filter: &config.AggregateShapeFilter{
								Kind: "predicate", Field: "active", Operator: "eq", ValueTypes: &activeValueTypes,
							},
							RequiredIndex: "PRIMARY", MaximumRowsExaminedPerScan: 100,
						},
					},
				},
			},
		},
	}
	if withTimeBucket {
		profile := cfg.Profiles["reader"]
		profile.Query.AllowSorting = true
		profile.Query.AggregateShapes = append(profile.Query.AggregateShapes, config.AggregateShape{
			Name: "orders_by_created_day", Mode: queryspec.AggregateModeGrouped,
			Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
			Projection: []config.AggregateShapeOutput{
				{Kind: "time_bucket", Field: "created_at", Unit: "day", Timezone: "UTC", Alias: "created_day"},
				{Kind: "measure", Function: "count_all", Alias: "daily_count"},
			},
			OrderBy:      []config.AggregateShapeOrder{{Kind: "time_bucket", Alias: "created_day", Direction: "asc"}},
			MaximumLimit: 10, RequiredIndex: "idx_created_at", MaximumRowsExaminedPerScan: 100,
			AllowTemporaryTable: boolPointer(true), AllowFilesort: boolPointer(true),
		})
		cfg.Profiles["reader"] = profile
	}
	if withKeyset {
		profile := cfg.Profiles["reader"]
		profile.Operations = append(profile.Operations, domain.OperationSelectKeyset)
		profile.Query.AllowSorting = true
		profile.Query.KeysetSelectShapes = []config.KeysetSelectShape{
			{
				Name: "orders_page", Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
				Projection:   []config.KeysetShapeProjection{{Kind: "field", Field: "id"}},
				OrderBy:      []config.KeysetShapeOrder{{Field: "id", Direction: "asc"}},
				MaximumLimit: 10, RequiredIndex: "PRIMARY", MaximumRowsExaminedPerScan: 100,
			},
			{
				Name: "orders_page_aliased", Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
				Projection:   []config.KeysetShapeProjection{{Kind: "field", Field: "id", Alias: "order_id"}},
				OrderBy:      []config.KeysetShapeOrder{{Field: "id", Direction: "asc"}},
				MaximumLimit: 10, RequiredIndex: "PRIMARY", MaximumRowsExaminedPerScan: 100,
			},
		}
		cfg.Profiles["reader"] = profile
	}
	if len(numeric) != 0 && numeric[0] {
		p := cfg.Profiles["reader"]
		p.Query.AllowSorting = true
		p.Query.AggregateShapes = append(p.Query.AggregateShapes, config.AggregateShape{
			Name: "orders_by_numeric", Mode: "grouped", Source: config.AggregateShapeSource{Schema: "app", Name: "orders"},
			Projection: []config.AggregateShapeOutput{{Kind: "numeric_bucket", Field: "id", Alias: "id_bucket", Boundaries: []string{"0", "100", "500", "1000"}}, {Kind: "measure", Function: "count_all", Alias: "bucket_count"}},
			OrderBy:    []config.AggregateShapeOrder{{Kind: "numeric_bucket", Alias: "id_bucket", Direction: "asc"}}, MaximumLimit: 10, MaximumRowsExaminedPerScan: 100,
			AllowTemporaryTable: boolPointer(true), AllowFilesort: boolPointer(true),
		})
		cfg.Profiles["reader"] = p
	}
	resolver := secrets.Map{"env:PASSWORD_HASH": string(hash)}
	authenticator, authProblems := auth.NewBasic(cfg.Authentication.Basic, resolver)
	if len(authProblems) != 0 {
		t.Fatalf("auth problems: %v", authProblems)
	}
	databases, databaseProblems := database.NewManager(cfg, resolver, &contractAdapter{})
	if len(databaseProblems) != 0 {
		t.Fatalf("database problems: %v", databaseProblems)
	}
	sink := &audit.MemorySink{}
	service := queryservice.New(policy.NewSnapshot(cfg), databases, sink, cfg, "test")
	if problems, err := service.InitializeQueryShapeDiscovery(context.Background()); err != nil || len(problems) != 0 {
		t.Fatalf("query-shape discovery initialization: problems=%v error=%v", problems, err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(authenticator, service, logger), sink, func() { _ = databases.Close() }
}

func newContractRequest(method, path, body string) *http.Request {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, "http://quordon.test"+path, reader)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	request.SetBasicAuth("client", "secret")
	return request
}

func TestMetadataQueryParametersMatchDocumentedOpenAPISemantics(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()
	server, closeDatabases := testServer(t)
	defer closeDatabases()

	fixtures := []struct {
		name           string
		path           string
		openAPIValid   bool
		wantStatus     int
		semanticStrict bool
	}{
		{
			name: "list with one profile", path: "/schemas/application/objects?profile=explain&datasource=mysql",
			openAPIValid: true, wantStatus: http.StatusForbidden,
		},
		{
			name: "list without profile", path: "/schemas/application/objects",
			openAPIValid: false, wantStatus: http.StatusBadRequest,
		},
		{
			name: "list without datasource", path: "/schemas/application/objects?profile=explain",
			openAPIValid: false, wantStatus: http.StatusBadRequest,
		},
		{
			name: "list with unknown parameter", path: "/schemas/application/objects?profile=explain&datasource=mysql&extra=value",
			openAPIValid: true, wantStatus: http.StatusBadRequest, semanticStrict: true,
		},
		{
			name: "list with repeated profile", path: "/schemas/application/objects?profile=explain&datasource=mysql&profile=other",
			openAPIValid: true, wantStatus: http.StatusBadRequest, semanticStrict: true,
		},
		{
			name: "list with repeated datasource", path: "/schemas/application/objects?profile=explain&datasource=mysql&datasource=other",
			openAPIValid: true, wantStatus: http.StatusBadRequest, semanticStrict: true,
		},
		{
			name: "list with case-folded datasource", path: "/schemas/application/objects?profile=explain&Datasource=mysql",
			openAPIValid: false, wantStatus: http.StatusBadRequest,
		},
		{
			name: "describe with unknown parameter", path: "/schemas/application/objects/orders?profile=explain&datasource=mysql&extra=value",
			openAPIValid: true, wantStatus: http.StatusBadRequest, semanticStrict: true,
		},
		{
			name: "describe with repeated profile", path: "/schemas/application/objects/orders?profile=explain&datasource=mysql&profile=other",
			openAPIValid: true, wantStatus: http.StatusBadRequest, semanticStrict: true,
		},
		{
			name: "list with invalid UTF-8 profile", path: "/schemas/application/objects?profile=%FF&datasource=mysql",
			openAPIValid: true, wantStatus: http.StatusBadRequest, semanticStrict: true,
		},
		{
			name: "describe with invalid UTF-8 profile", path: "/schemas/application/objects/orders?profile=%FF&datasource=mysql",
			openAPIValid: true, wantStatus: http.StatusBadRequest, semanticStrict: true,
		},
		{
			name: "describe with invalid UTF-8 datasource", path: "/schemas/application/objects/orders?profile=explain&datasource=%FF",
			openAPIValid: true, wantStatus: http.StatusBadRequest, semanticStrict: true,
		},
		{
			name: "statistics with unknown parameter", path: "/schemas/application/objects/orders/statistics?profile=explain&datasource=mysql&extra=value",
			openAPIValid: true, wantStatus: http.StatusBadRequest, semanticStrict: true,
		},
		{
			name: "statistics with repeated profile", path: "/schemas/application/objects/orders/statistics?profile=explain&datasource=mysql&profile=other",
			openAPIValid: true, wantStatus: http.StatusBadRequest, semanticStrict: true,
		},
		{
			name: "statistics with invalid UTF-8 profile", path: "/schemas/application/objects/orders/statistics?profile=%FF&datasource=mysql",
			openAPIValid: true, wantStatus: http.StatusBadRequest, semanticStrict: true,
		},
		{
			name: "statistics with invalid schema", path: "/schemas/bad-name/objects/orders/statistics?profile=explain&datasource=mysql",
			openAPIValid: false, wantStatus: http.StatusBadRequest,
		},
		{
			name: "statistics with invalid object", path: "/schemas/application/objects/bad-name/statistics?profile=explain&datasource=mysql",
			openAPIValid: false, wantStatus: http.StatusBadRequest,
		},
	}

	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			contractRequest := httptest.NewRequest(http.MethodGet, "http://quordon.test"+fixture.path, nil)
			contractRequest.SetBasicAuth("client", "secret")
			openAPIValid, validationErrors := contract.ValidateHttpRequestSync(contractRequest)
			if openAPIValid != fixture.openAPIValid {
				t.Fatalf(
					"OpenAPI validity = %t, want %t; errors=%v",
					openAPIValid, fixture.openAPIValid, validationErrors,
				)
			}

			runtimeRequest := httptest.NewRequest(http.MethodGet, fixture.path, nil)
			runtimeRequest.SetBasicAuth("client", "secret")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, runtimeRequest)
			if response.Code != fixture.wantStatus {
				t.Fatalf("runtime status = %d, want %d; body=%s", response.Code, fixture.wantStatus, response.Body)
			}
			if fixture.semanticStrict && (!openAPIValid || response.Code != http.StatusBadRequest) {
				t.Fatal("documented strict query-string semantic was not enforced by the handler")
			}

			responseValid, responseErrors := contract.ValidateHttpResponse(contractRequest, response.Result())
			if !responseValid {
				t.Fatalf("runtime response violates OpenAPI: %v; body=%s", responseErrors, response.Body)
			}
		})
	}
}

func loadOpenAPI31Validator(t *testing.T) openapivalidator.Validator {
	t.Helper()
	specification, err := os.ReadFile("../../openapi/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configuration := datamodel.NewDocumentConfiguration()
	// Preload every modular contract file before resolving circular file refs;
	// lazy cross-file indexing in libopenapi can deadlock. Sequential extraction
	// retains the complete schema checks with deterministic resolution.
	configuration.ExtractRefsSequentially = true
	configuration.BasePath = "../../openapi"
	configuration.LocalFS = os.DirFS("../../openapi")
	configuration.SpecFilePath = "openapi.yaml"
	configuration.FileFilter = []string{"openapi.yaml", "aggregate.yaml", "query-shapes.yaml", "table-statistics.yaml", "keyset-pagination.yaml"}
	configuration.AllowFileReferences = true
	document, err := libopenapi.NewDocumentWithConfiguration(specification, configuration)
	if err != nil {
		t.Fatalf("parse OpenAPI document: %v", err)
	}
	contract, problems := openapivalidator.NewValidator(document)
	if len(problems) != 0 {
		t.Fatalf("create OpenAPI validator: %v", problems)
	}
	valid, validationErrors := contract.ValidateDocument()
	if !valid {
		contract.Release()
		t.Fatalf("OpenAPI 3.1 document validation failed: %v", validationErrors)
	}
	return contract
}

func assertOpenAPIResponseValidity(
	t *testing.T,
	contract openapivalidator.Validator,
	request *http.Request,
	body string,
	want bool,
) {
	t.Helper()
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
			"X-Request-ID": []string{"req-contract"},
		},
		Body: io.NopCloser(strings.NewReader(body)),
	}
	valid, validationErrors := contract.ValidateHttpResponse(request, response)
	if valid != want {
		t.Fatalf("OpenAPI response validity = %t, want %t; errors=%v", valid, want, validationErrors)
	}
}

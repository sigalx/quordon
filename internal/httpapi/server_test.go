package httpapi

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sigalx/quordon/internal/adapters/mysql8"
	"github.com/sigalx/quordon/internal/audit"
	"github.com/sigalx/quordon/internal/auth"
	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryservice"
	"github.com/sigalx/quordon/internal/secrets"
	"golang.org/x/crypto/bcrypt"
)

func TestWriteJSONDoesNotAppendUnbudgetedWhitespace(t *testing.T) {
	response := httptest.NewRecorder()
	writeJSON(response, http.StatusOK, map[string]string{"status": "ok"})
	if got, want := response.Body.String(), `{"status":"ok"}`; got != want {
		t.Fatalf("JSON response body = %q, want exact budgeted payload %q", got, want)
	}
}

func TestMVPRouteSurfaceAndAuthentication(t *testing.T) {
	server, closeDatabases := testServer(t)
	defer closeDatabases()

	tests := []struct {
		name     string
		method   string
		path     string
		username string
		password string
		status   int
	}{
		{name: "liveness is public", method: http.MethodGet, path: "/health/live", status: http.StatusOK},
		{name: "capabilities requires auth", method: http.MethodGet, path: "/capabilities", status: http.StatusUnauthorized},
		{name: "capabilities accepts auth", method: http.MethodGet, path: "/capabilities", username: "client", password: "secret", status: http.StatusOK},
		{name: "schema endpoint requires auth", method: http.MethodGet, path: "/schemas/application/objects?profile=explain&datasource=mysql", status: http.StatusUnauthorized},
		{name: "select endpoint requires auth", method: http.MethodPost, path: "/queries/select", status: http.StatusUnauthorized},
		{name: "versioned endpoint is absent", method: http.MethodGet, path: "/v1/capabilities", status: http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			if test.username != "" {
				request.SetBasicAuth(test.username, test.password)
			}
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.status, response.Body.String())
			}
			if response.Header().Get("X-Request-ID") == "" {
				t.Fatal("X-Request-ID is missing")
			}
		})
	}
}

func TestMixedAggregateWithoutGroupByReturnsUnprocessable(t *testing.T) {
	server, closeDatabases := testServer(t)
	defer closeDatabases()

	body := `{
		"profile":"explain","datasource":"mysql",
		"query":{
			"source":{"schema":"application","name":"orders"},
			"projection":[
				{"kind":"field","field":"status"},
				{"kind":"aggregate","function":"count"}
			]
		}
	}`
	request := httptest.NewRequest(http.MethodPost, "/queries/explain", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("client", "secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", response.Code, response.Body.String())
	}
}

func TestNullRequestEnvelopeReturnsBadRequest(t *testing.T) {
	server, closeDatabases := testServer(t)
	defer closeDatabases()

	request := httptest.NewRequest(http.MethodPost, "/queries/explain", strings.NewReader("null"))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("client", "secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
	}
}

func TestSelectRejectsShapesExcludedByItsOpenAPIContract(t *testing.T) {
	server, closeDatabases := testServer(t)
	defer closeDatabases()

	tests := []struct {
		name string
		body string
	}{
		{
			name: "explicit empty group_by",
			body: `{"profile":"explain","datasource":"mysql","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"id"}],"group_by":[]}}`,
		},
		{
			name: "aggregate projection",
			body: `{"profile":"explain","datasource":"mysql","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"aggregate","function":"count"}]}}`,
		},
		{
			name: "empty projection",
			body: `{"profile":"explain","datasource":"mysql","query":{"source":{"schema":"application","name":"orders"},"projection":[]}}`,
		},
		{
			name: "invalid source identifier",
			body: `{"profile":"explain","datasource":"mysql","query":{"source":{"schema":"bad-name","name":"orders"},"projection":[{"kind":"field","field":"id"}]}}`,
		},
		{
			name: "invalid order direction",
			body: `{"profile":"explain","datasource":"mysql","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"id"}],"order_by":[{"field":"id","direction":"sideways"}]}}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/queries/select", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			request.SetBasicAuth("client", "secret")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), `"code":"INVALID_REQUEST"`) {
				t.Fatalf("body = %s, want INVALID_REQUEST", response.Body.String())
			}
		})
	}
}

func TestSchemaEndpointsRequireStrictProfileAndIdentifiers(t *testing.T) {
	server, closeDatabases := testServer(t)
	defer closeDatabases()

	for _, path := range []string{
		"/schemas/application/objects",
		"/schemas/application/objects?profile=explain",
		"/schemas/application/objects?profile=explain&datasource=",
		"/schemas/application/objects?profile=explain&datasource=mysql&profile=other",
		"/schemas/application/objects?profile=explain&datasource=mysql&datasource=other",
		"/schemas/application/objects?profile=explain&Datasource=mysql",
		"/schemas/application/objects?Profile=explain&datasource=mysql",
		"/schemas/application/objects?profile=explain&datasource=mysql&unknown=value",
		"/schemas/application/objects?profile=explain&datasource=mysql&unknown=a;b",
		"/schemas/application/objects?profile=%FF&datasource=mysql",
		"/schemas/application/objects?profile=explain&datasource=%FF",
		"/schemas/application/objects/orders?profile=%FF&datasource=mysql",
		"/schemas/not-valid!/objects?profile=explain&datasource=mysql",
		"/schemas/application/objects/not-valid!?profile=explain&datasource=mysql",
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.SetBasicAuth("client", "secret")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("path %q status = %d, want 400; body=%s", path, response.Code, response.Body.String())
		}
	}
}

func TestInvalidUTF8ReturnsBadRequest(t *testing.T) {
	server, closeDatabases := testServer(t)
	defer closeDatabases()

	body := []byte(`{"profile":"explain","datasource":"mysql","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"predicate","field":"status","operator":"eq","values":[{"type":"string","value":"active"}]}}}`)
	body[bytes.Index(body, []byte("active"))] = 0xff
	request := httptest.NewRequest(http.MethodPost, "/queries/explain", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("client", "secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"code":"INVALID_REQUEST"`) {
		t.Fatalf("body = %s, want INVALID_REQUEST", response.Body.String())
	}
}

func TestMissingRequiredRequestFieldReturnsBadRequest(t *testing.T) {
	server, closeDatabases := testServer(t)
	defer closeDatabases()

	body := `{"query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"id"}]}}`
	request := httptest.NewRequest(http.MethodPost, "/queries/explain", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth("client", "secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
	}
}

func TestExplainRequiresExactJSONMediaType(t *testing.T) {
	server, closeDatabases := testServer(t)
	defer closeDatabases()

	tests := []struct {
		name        string
		contentType string
		wantStatus  int
	}{
		{name: "json", contentType: "application/json", wantStatus: http.StatusBadRequest},
		{name: "json with charset", contentType: "application/json; charset=utf-8", wantStatus: http.StatusBadRequest},
		{name: "missing", wantStatus: http.StatusUnsupportedMediaType},
		{name: "jsonp", contentType: "application/jsonp", wantStatus: http.StatusUnsupportedMediaType},
		{name: "invalid json prefix", contentType: "application/json-invalid", wantStatus: http.StatusUnsupportedMediaType},
		{name: "different type", contentType: "text/json", wantStatus: http.StatusUnsupportedMediaType},
		{name: "invalid parameter", contentType: "application/json; charset", wantStatus: http.StatusUnsupportedMediaType},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/queries/explain", strings.NewReader(`{}`))
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			request.SetBasicAuth("client", "secret")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			if test.wantStatus == http.StatusUnsupportedMediaType && !strings.Contains(response.Body.String(), `"code":"UNSUPPORTED_MEDIA_TYPE"`) {
				t.Fatalf("body = %s, want UNSUPPORTED_MEDIA_TYPE", response.Body.String())
			}
		})
	}
}

func TestServiceAndDatabaseUnavailableHaveDistinctCodes(t *testing.T) {
	server, closeDatabases := testServer(t)
	defer closeDatabases()

	tests := []struct {
		kind     queryservice.ErrorKind
		wantCode string
	}{
		{kind: queryservice.ErrorServiceUnavailable, wantCode: "SERVICE_UNAVAILABLE"},
		{kind: queryservice.ErrorUnavailable, wantCode: "DATABASE_UNAVAILABLE"},
	}
	for _, test := range tests {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/queries/explain", nil)
		server.writeServiceError(response, request, &queryservice.Error{Kind: test.kind})
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("kind %q status = %d, want 503", test.kind, response.Code)
		}
		if !strings.Contains(response.Body.String(), `"code":"`+test.wantCode+`"`) {
			t.Fatalf("kind %q body = %s, want code %s", test.kind, response.Body.String(), test.wantCode)
		}
	}
}

func TestCorrectCredentialsAcceptedAfterRepeatedFailures(t *testing.T) {
	server, closeDatabases := testServer(t)
	defer closeDatabases()

	for attempt := 0; attempt < 12; attempt++ {
		request := httptest.NewRequest(http.MethodGet, "/capabilities", nil)
		request.SetBasicAuth("client", "wrong-password")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", attempt+1, response.Code)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/capabilities", nil)
	request.SetBasicAuth("client", "secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("correct credentials status = %d, want 200", response.Code)
	}
}

func TestAuthenticationContextPreservesBasicUsername(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	authenticator, problems := auth.NewBasic(config.BasicAuth{Users: map[string]config.BasicUser{
		"deployment-a": {Principal: "shared-principal", PasswordHash: string(hash)},
	}}, secrets.Map{})
	if len(problems) != 0 {
		t.Fatalf("auth problems = %v", problems)
	}
	server := &Server{authenticator: authenticator}
	handler := server.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		client := principalFromContext(r.Context())
		if client.principal != "shared-principal" || client.clientIdentifier != "deployment-a" {
			t.Fatalf("authenticated client = %#v", client)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.SetBasicAuth("deployment-a", "secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
}

func testServer(t *testing.T) (*Server, func()) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	limits := domain.Limits{
		DeadlineMS: 1000, MaxRequestBytes: 65536, MaxProjectionFields: 10,
		MaxGroupByFields: 10, MaxOrderByFields: 10,
		MaxPredicates: 10, MaxExpressionDepth: 4, MaxParameters: 20, MaxRows: 100,
		MaxResultBytes: 65536, MaxOffset: 100, MaxConcurrency: 1,
	}
	cfg := config.Config{
		Version: 1, PolicyHash: "test-hash", HardLimits: limits,
		Authentication: config.Authentication{Basic: config.BasicAuth{Realm: "quordon", Users: map[string]config.BasicUser{
			"client": {Principal: "test-client", PasswordHashSecretRef: "env:PASSWORD_HASH"},
		}}},
		Principals: map[string]config.Principal{"test-client": {Profiles: []string{"explain"}, Datasources: []string{"mysql"}}},
		Datasources: map[string]config.Datasource{"mysql": {
			Adapter: "mysql8", DSNSecretRef: "env:MYSQL_DSN", TLSRequired: boolPointer(false), Pool: config.PoolConfig{
				MaxOpenConnections: 1, MaxIdleConnections: 0, MaxConnectionLifetimeSeconds: 60,
			},
		}},
		Profiles: map[string]config.Profile{"explain": {
			Datasources: []string{"mysql"}, Operations: []domain.Operation{domain.OperationExplainSelect},
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"application"}},
				Objects: config.PatternPolicy{Allow: []string{"application.*"}},
			},
			Query: config.QueryPolicy{}, Limits: limits,
		}},
	}
	resolver := secrets.Map{
		"env:PASSWORD_HASH": string(hash),
		"env:MYSQL_DSN":     "user:password@tcp(127.0.0.1:1)/",
	}
	authenticator, problems := auth.NewBasic(cfg.Authentication.Basic, resolver)
	if len(problems) != 0 {
		t.Fatalf("auth problems: %v", problems)
	}
	databases, problems := database.NewManager(cfg, resolver, mysql8.New())
	if len(problems) != 0 {
		t.Fatalf("database problems: %v", problems)
	}
	sink := audit.NewJSONSink(io.Discard)
	service := queryservice.New(policy.NewSnapshot(cfg), databases, sink, cfg, "test")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(authenticator, service, logger), func() { _ = databases.Close() }
}

func boolPointer(value bool) *bool { return &value }

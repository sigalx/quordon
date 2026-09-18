package httpapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/pb33f/libopenapi"
	openapivalidator "github.com/pb33f/libopenapi-validator"
	"github.com/pb33f/libopenapi/datamodel"
	"gopkg.in/yaml.v3"
)

type aggregateContractDocument struct {
	Status          string `yaml:"x-quordon-status"`
	RuntimeContract bool   `yaml:"x-quordon-runtime-contract"`
	Paths           map[string]struct {
		Post struct {
			SourceWork aggregateContractSourceWork `yaml:"x-quordon-source-work-controls"`
		} `yaml:"post"`
	} `yaml:"paths"`
}

type aggregateContractSourceWork struct {
	ShapeBinds           []string `yaml:"shape-binds"`
	NormalizedQueryShape struct {
		Projection struct {
			OrderSignificant bool     `yaml:"order-significant"`
			Bind             []string `yaml:"bind"`
		} `yaml:"projection"`
		Filter struct {
			BindEntireTree         bool     `yaml:"bind-entire-recursive-tree"`
			BindPresence           bool     `yaml:"bind-absence-vs-presence"`
			BindGroupOperators     bool     `yaml:"bind-group-operators"`
			BindPredicateCount     bool     `yaml:"bind-predicate-multiplicity"`
			BindPerPredicate       []string `yaml:"bind-per-predicate"`
			ParameterValuesInShape bool     `yaml:"parameter-values-in-shape"`
		} `yaml:"filter"`
		OrderBy struct {
			OrderSignificant bool     `yaml:"order-significant"`
			BindPresence     bool     `yaml:"bind-absence-vs-presence"`
			Bind             []string `yaml:"bind"`
		} `yaml:"order-by"`
		Limit struct {
			BindRequested bool `yaml:"bind-requested-value"`
			UnderMaximum  bool `yaml:"must-not-exceed-shape-maximum"`
		} `yaml:"limit"`
		PartialMatch                 string `yaml:"partial-or-field-only-match"`
		AuthorizationTokenBindsShape bool   `yaml:"authorization-token-binds-normalized-shape"`
	} `yaml:"normalized-query-shape"`
	RowsExaminedMetric struct {
		SourceNodeIdentification struct {
			RequiredCount int    `yaml:"minimum-required-node-count"`
			RejectOthers  string `yaml:"additional-table-or-materialized-nodes"`
		} `yaml:"source-node-identification"`
		JSONField         string   `yaml:"json-field"`
		ExplicitlyNotUsed []string `yaml:"explicitly-not-used"`
		AcceptedToken     string   `yaml:"accepted-json-token"`
		PolicyMaximum     struct {
			Name              string `yaml:"name"`
			Minimum           uint64 `yaml:"minimum"`
			Maximum           uint64 `yaml:"maximum"`
			InvalidOrOverflow string `yaml:"invalid-or-overflowing-config"`
		} `yaml:"policy-maximum"`
		Arithmetic struct {
			Representation string `yaml:"representation"`
			Overflow       string `yaml:"overflow"`
		} `yaml:"arithmetic"`
		MissingOrMalformed string `yaml:"missing-null-fractional-negative-string-or-malformed"`
		Ambiguous          string `yaml:"malformed-read-nodes"`
		Comparison         string `yaml:"comparison"`
		RejectionStatus    int    `yaml:"rejection-status"`
		RejectionCode      string `yaml:"rejection-code"`
	} `yaml:"rows-examined-admission-metric"`
}

func TestAggregateContractRejectsDuplicateFilterExpressions(t *testing.T) {
	contract := loadAggregateContractValidator(t)
	defer contract.Release()

	uniquePredicates := `[
		{"kind":"predicate","field":"deleted_at","operator":"is_null","values":[]},
		{"kind":"predicate","field":"active","operator":"eq","values":[{"type":"boolean","value":true}]}
	]`
	duplicatePredicates := `[
		{"kind":"predicate","field":"deleted_at","operator":"is_null","values":[]},
		{"kind":"predicate","field":"deleted_at","operator":"is_null","values":[]}
	]`

	for _, fixture := range []struct {
		name        string
		expressions string
		wantValid   bool
	}{
		{name: "unique expressions", expressions: uniquePredicates, wantValid: true},
		{name: "duplicate expressions", expressions: duplicatePredicates, wantValid: false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			body := `{
				"profile":"analytics",
				"query":{
					"mode":"scalar",
					"source":{"schema":"application","name":"employees"},
					"projection":[{"kind":"measure","function":"count_all","alias":"total"}],
					"filter":{"kind":"group","operator":"and","expressions":` + fixture.expressions + `}
				}
			}`
			request := httptest.NewRequest(
				http.MethodPost,
				"http://quordon.test/queries/aggregate",
				strings.NewReader(body),
			)
			request.Header.Set("Content-Type", "application/json")
			request.SetBasicAuth("contract-client", "contract-password")

			valid, validationErrors := contract.ValidateHttpRequestSync(request)
			if valid != fixture.wantValid {
				t.Fatalf("OpenAPI validity = %t, want %t; errors=%v", valid, fixture.wantValid, validationErrors)
			}
		})
	}
}

func TestAggregateModuleAcceptsRuntimeCapabilitiesWithQueryShapeDiscovery(t *testing.T) {
	contract := loadAggregateContractValidator(t)
	defer contract.Release()
	server, closeDatabases := successfulContractServer(t)
	defer closeDatabases()

	runtimeRequest := httptest.NewRequest(http.MethodGet, "/capabilities", nil)
	runtimeRequest.SetBasicAuth("client", "secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, runtimeRequest)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"list_query_shapes"`) {
		t.Fatalf("runtime capabilities omitted published query-shape discovery: %s", response.Body.String())
	}

	contractRequest := httptest.NewRequest(http.MethodGet, "http://quordon.test/capabilities", nil)
	contractRequest.SetBasicAuth("client", "secret")
	valid, validationErrors := contract.ValidateHttpResponse(contractRequest, response.Result())
	if !valid {
		t.Fatalf("runtime capabilities violate aggregate OpenAPI module: %v; body=%s", validationErrors, response.Body.String())
	}
}

func TestAggregateContractBindsCompleteShapeAndRowsExaminedMetric(t *testing.T) {
	specification, err := os.ReadFile("../../openapi/aggregate.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document aggregateContractDocument
	if err := yaml.Unmarshal(specification, &document); err != nil {
		t.Fatalf("decode aggregate contract extensions: %v", err)
	}
	if document.Status != "runtime" || !document.RuntimeContract {
		t.Fatalf("aggregate module is not marked as an executable runtime contract: %+v", document)
	}
	controls := document.Paths["/queries/aggregate"].Post.SourceWork
	if !containsString(controls.ShapeBinds, "complete-normalized-filter-tree") {
		t.Fatal("aggregate policy shape does not bind the complete normalized filter tree")
	}
	filter := controls.NormalizedQueryShape.Filter
	projection := controls.NormalizedQueryShape.Projection
	if !projection.OrderSignificant || !containsString(projection.Bind, "alias") ||
		!filter.BindEntireTree || !filter.BindPresence || !filter.BindGroupOperators || !filter.BindPredicateCount ||
		filter.ParameterValuesInShape ||
		!containsString(filter.BindPerPredicate, "placeholder-types") ||
		!containsString(filter.BindPerPredicate, "placeholder-arity") {
		t.Fatalf("incomplete normalized filter binding: %+v", filter)
	}
	orderBy := controls.NormalizedQueryShape.OrderBy
	limit := controls.NormalizedQueryShape.Limit
	if !orderBy.OrderSignificant || !orderBy.BindPresence || !containsString(orderBy.Bind, "direction") ||
		!limit.BindRequested || !limit.UnderMaximum ||
		controls.NormalizedQueryShape.PartialMatch != "forbidden" ||
		!controls.NormalizedQueryShape.AuthorizationTokenBindsShape {
		t.Fatalf("incomplete normalized query binding: %+v", controls.NormalizedQueryShape)
	}
	metric := controls.RowsExaminedMetric
	if metric.SourceNodeIdentification.RequiredCount != 1 || metric.SourceNodeIdentification.RejectOthers != "bounded-and-work-controlled" ||
		metric.JSONField != "rows_examined_per_scan" ||
		!containsString(metric.ExplicitlyNotUsed, "rows_produced_per_join") ||
		metric.AcceptedToken != "JSON number matching 0|[1-9][0-9]*" ||
		metric.PolicyMaximum.Name != "maximum_rows_examined_per_scan" ||
		metric.PolicyMaximum.Minimum != 1 || metric.PolicyMaximum.Maximum != ^uint64(0) ||
		metric.PolicyMaximum.InvalidOrOverflow != "reject-startup" ||
		metric.Arithmetic.Representation != "unsigned-64-bit" || metric.Arithmetic.Overflow != "reject" ||
		metric.Comparison != "reject-when-metric-greater-than-policy-maximum" ||
		metric.MissingOrMalformed != "reject" || metric.Ambiguous != "reject" ||
		metric.RejectionStatus != http.StatusUnprocessableEntity || metric.RejectionCode != "UNSUPPORTED_QUERY" {
		t.Fatalf("ambiguous rows-examined admission metric: %+v", metric)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func loadAggregateContractValidator(t *testing.T) openapivalidator.Validator {
	t.Helper()
	specification, err := os.ReadFile("../../openapi/aggregate.yaml")
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
	configuration.SpecFilePath = "aggregate.yaml"
	configuration.FileFilter = []string{"openapi.yaml", "aggregate.yaml", "query-shapes.yaml", "table-statistics.yaml", "keyset-pagination.yaml"}
	configuration.AllowFileReferences = true
	document, err := libopenapi.NewDocumentWithConfiguration(specification, configuration)
	if err != nil {
		t.Fatalf("parse aggregate contract: %v", err)
	}
	contract, problems := openapivalidator.NewValidator(document)
	if len(problems) != 0 {
		t.Fatalf("create aggregate contract validator: %v", problems)
	}
	valid, validationErrors := contract.ValidateDocument()
	if !valid {
		contract.Release()
		t.Fatalf("aggregate contract validation failed: %v", validationErrors)
	}
	return contract
}

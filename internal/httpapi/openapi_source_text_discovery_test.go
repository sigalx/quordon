package httpapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
)

func TestSourceTextDiscoveryRuntimePayloadMatchesOpenAPI(t *testing.T) {
	contract := loadOpenAPI31Validator(t)
	defer contract.Release()
	data, err := os.ReadFile("../../config/policy.integration.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := policy.NewSnapshot(cfg)
	discovery, err := snapshot.BuildQueryShapeDiscovery("diagnostic-reader", domain.AdapterMySQL8, domain.IdentifierSemantics{CaseInsensitiveFields: true})
	if err != nil {
		t.Fatal(err)
	}
	var principal string
	for name, configured := range cfg.Principals {
		for _, profile := range configured.Profiles {
			if profile == "diagnostic-reader" {
				principal = name
			}
		}
	}
	authorized, err := snapshot.AuthorizeQueryShapeList(principal, "contract-credential", "diagnostic-reader", &discovery)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := authorized.ResponsePayload()
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://quordon.test/query-shapes?profile=diagnostic-reader", nil)
	request.SetBasicAuth("contract-client", "contract-password")
	for _, fixture := range []struct {
		body  string
		valid bool
	}{
		{string(payload), true},
		{strings.Replace(string(payload), `"representation":"source_text"`, `"representation":null`, 1), false},
		{strings.Replace(string(payload), `"value_types":["string"]`, `"value_types":["date"]`, 1), false},
	} {
		response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{
			"Content-Type": {"application/json"}, "X-Request-ID": {"req-contract"}, "Cache-Control": {"no-store"}, "Vary": {"Accept"},
		}, Body: io.NopCloser(strings.NewReader(fixture.body))}
		if valid, errs := contract.ValidateHttpResponse(request, response); valid != fixture.valid {
			t.Fatalf("diagnostic discovery schema validity=%t expected=%t errors=%v", valid, fixture.valid, errs)
		}
	}
}

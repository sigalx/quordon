package policy

import (
	"testing"

	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/queryspec"
)

func TestAuthorizeObjectStatisticsMintsCanonicalOperationBoundToken(t *testing.T) {
	limits := domain.Limits{MaxResultBytes: 1024}
	snapshot := NewSnapshot(config.Config{
		Version: 7, PolicyHash: "redacted-policy-hash", HardLimits: limits,
		Principals: map[string]config.Principal{"observer": {Profiles: []string{"production"}}},
		Profiles: map[string]config.Profile{"production": {
			Datasource: "primary", Operations: []domain.Operation{domain.OperationDescribeObjectStatistics},
			Limits: limits,
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"application"}},
				Objects: config.PatternPolicy{Allow: []string{"application.orders"}},
			},
		}},
	})
	semantics := domain.IdentifierSemantics{
		CaseInsensitiveSchemas: true, CaseInsensitiveObjects: true, CaseInsensitiveFields: true,
	}
	authorized, err := snapshot.AuthorizeObjectStatistics(
		"observer", "basic-user", "production", domain.AdapterMySQL8,
		queryspec.ResourceRef{Schema: "APPLICATION", Name: "ORDERS"}, semantics,
	)
	if err != nil {
		t.Fatal(err)
	}
	if authorized.Operation() != domain.OperationDescribeObjectStatistics ||
		authorized.Schema() != "application" || authorized.Object() != "orders" ||
		authorized.Principal() != "observer" || authorized.CredentialIdentifier() != "basic-user" ||
		authorized.Profile() != "production" || authorized.Datasource() != "primary" ||
		authorized.Adapter() != domain.AdapterMySQL8 || authorized.PolicyVersion() != "7" ||
		authorized.PolicyHash() != "redacted-policy-hash" || authorized.IdentifierSemantics() != semantics ||
		authorized.IdentifierSemanticsGeneration() == "" {
		t.Fatalf("unexpected authorization token: %#v", authorized)
	}
}

func TestAuthorizeObjectStatisticsRequiresIndependentOperationAndResource(t *testing.T) {
	base := config.Config{
		Principals: map[string]config.Principal{"observer": {Profiles: []string{"production"}}},
		Profiles: map[string]config.Profile{"production": {
			Datasource: "primary", Operations: []domain.Operation{domain.OperationDescribeObject},
			Resources: config.ResourcePolicy{
				Schemas: config.PatternPolicy{Allow: []string{"application"}},
				Objects: config.PatternPolicy{Allow: []string{"application.orders"}},
			},
		}},
	}
	_, err := NewSnapshot(base).AuthorizeObjectStatistics(
		"observer", "basic-user", "production", domain.AdapterMySQL8,
		queryspec.ResourceRef{Schema: "application", Name: "orders"}, domain.IdentifierSemantics{},
	)
	reason := ""
	if !IsDenial(err, &reason) || reason != ReasonDeniedOperation {
		t.Fatalf("describe_object-only authorization error = %v, reason=%q", err, reason)
	}
	profile := base.Profiles["production"]
	profile.Operations = []domain.Operation{domain.OperationDescribeObjectStatistics}
	base.Profiles["production"] = profile
	_, err = NewSnapshot(base).AuthorizeObjectStatistics(
		"observer", "basic-user", "production", domain.AdapterMySQL8,
		queryspec.ResourceRef{Schema: "application", Name: "secret"}, domain.IdentifierSemantics{},
	)
	if !IsDenial(err, &reason) || reason != ReasonDeniedResource {
		t.Fatalf("denied resource error = %v, reason=%q", err, reason)
	}
}

func TestAuthorizeObjectStatisticsRejectsIncompleteTokenIdentity(t *testing.T) {
	snapshot := NewSnapshot(config.Config{})
	for _, fixture := range []struct {
		principal, credential, profile, adapter string
	}{
		{credential: "credential", profile: "profile", adapter: domain.AdapterMySQL8},
		{principal: "principal", profile: "profile", adapter: domain.AdapterMySQL8},
		{principal: "principal", credential: "credential", adapter: domain.AdapterMySQL8},
		{principal: "principal", credential: "credential", profile: "profile"},
	} {
		_, err := snapshot.AuthorizeObjectStatistics(
			fixture.principal, fixture.credential, fixture.profile, fixture.adapter,
			queryspec.ResourceRef{Schema: "app", Name: "orders"}, domain.IdentifierSemantics{},
		)
		reason := ""
		if !IsDenial(err, &reason) || reason != ReasonDeniedOperation {
			t.Fatalf("incomplete identity produced error=%v reason=%q", err, reason)
		}
	}
}

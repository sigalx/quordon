package queryspec

import (
	"crypto/sha256"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/sigalx/quordon/internal/domain"
)

func TestDecodeStrictAggregateAcceptsClosedScalarAndGroupedShapes(t *testing.T) {
	for _, body := range []string{
		`{"profile":"analytics","datasource":"mysql","query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"total"}]}}`,
		`{"profile":"analytics","datasource":"mysql","query":{"mode":"grouped","source":{"schema":"app","name":"orders"},"projection":[{"kind":"dimension","field":"status"},{"kind":"measure","function":"count_distinct","field":"customer_id","alias":"customers"}],"filter":{"kind":"predicate","field":"active","operator":"eq","values":[{"type":"boolean","value":true}]},"order_by":[{"kind":"measure","alias":"customers","direction":"desc"}],"limit":10}}`,
	} {
		if _, err := DecodeStrictAggregate([]byte(body), 8, 200, 200); err != nil {
			t.Fatalf("DecodeStrictAggregate() error = %v for %s", err, body)
		}
	}
}

func TestDecodeStrictAggregateAcceptsUTCTimeBucket(t *testing.T) {
	body := `{"profile":"analytics","datasource":"mysql","query":{"mode":"grouped","source":{"schema":"app","name":"orders"},"projection":[{"kind":"time_bucket","field":"created_at","unit":"day","timezone":"UTC","alias":"created_day"},{"kind":"measure","function":"count_all","alias":"total"}],"order_by":[{"kind":"time_bucket","alias":"created_day","direction":"asc"}],"limit":10}}`
	request, err := DecodeStrictAggregate([]byte(body), 8, 200, 200)
	if err != nil {
		t.Fatalf("DecodeStrictAggregate() error = %v", err)
	}
	validated, err := ValidateAggregate(request.Query, 10, 10, 10, 10, 8, 20, 100)
	if err != nil {
		t.Fatalf("ValidateAggregate() error = %v", err)
	}
	if !AggregateUsesTimeBucket(validated.Spec()) {
		t.Fatal("validated aggregate lost the time-bucket discriminator")
	}
}

func TestDecodeStrictAggregateRejectsInvalidTimeBucketBranches(t *testing.T) {
	valid := `{"profile":"analytics","datasource":"mysql","query":{"mode":"grouped","source":{"schema":"app","name":"orders"},"projection":[{"kind":"time_bucket","field":"created_at","unit":"day","timezone":"UTC","alias":"created_day"},{"kind":"measure","function":"count_all","alias":"total"}],"limit":10}}`
	tests := map[string]string{
		"missing unit":         strings.Replace(valid, `,"unit":"day"`, "", 1),
		"null timezone":        strings.Replace(valid, `"timezone":"UTC"`, `"timezone":null`, 1),
		"numeric unit":         strings.Replace(valid, `"unit":"day"`, `"unit":1`, 1),
		"unknown unit":         strings.Replace(valid, `"unit":"day"`, `"unit":"minute"`, 1),
		"lowercase timezone":   strings.Replace(valid, `"timezone":"UTC"`, `"timezone":"utc"`, 1),
		"forbidden function":   strings.Replace(valid, `"alias":"created_day"`, `"alias":"created_day","function":"count"`, 1),
		"case-folded unit key": strings.Replace(valid, `"unit":"day"`, `"Unit":"day"`, 1),
		"duplicate unit key":   strings.Replace(valid, `"unit":"day"`, `"unit":"day","unit":"hour"`, 1),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeStrictAggregate([]byte(body), 8, 200, 200); err == nil {
				t.Fatalf("DecodeStrictAggregate() accepted %s", body)
			}
		})
	}
}

func TestValidateAggregateRejectsRepeatedTimeBucketSourceBeforeNormalization(t *testing.T) {
	limit := 10
	_, err := ValidateAggregate(AggregateSpec{
		Mode: AggregateModeGrouped, Source: ResourceRef{Schema: "app", Name: "orders"},
		Projection: []AggregateOutput{
			{Kind: "time_bucket", Field: "created_at", Unit: "day", Timezone: "UTC", Alias: "created_day"},
			{Kind: "time_bucket", Field: "created_at", Unit: "month", Timezone: "UTC", Alias: "created_month"},
			{Kind: "measure", Function: "count_all", Alias: "total"},
		}, Limit: &limit,
	}, 10, 10, 10, 10, 8, 20, 100)
	if err == nil || !strings.Contains(err.Error(), "repeated time-bucket") {
		t.Fatalf("ValidateAggregate() error = %v", err)
	}
}

func TestDecodeStrictAggregateLeavesCaseFoldedOutputCollisionToSemanticValidation(t *testing.T) {
	body := `{"profile":"analytics","datasource":"mysql","query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"total"},{"kind":"measure","function":"count_all","alias":"TOTAL"}]}}`
	if _, err := DecodeStrictAggregate([]byte(body), 8, 200, 200); err != nil {
		t.Fatalf("OpenAPI-valid request was rejected by transport validation: %v", err)
	}
}

func TestDecodeStrictAggregateRejectsTransportContractViolations(t *testing.T) {
	valid := `{"profile":"analytics","datasource":"mysql","query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"total"}]}}`
	tests := map[string]string{
		"non-object":                    `[]`,
		"missing profile":               strings.Replace(valid, `"profile":"analytics","datasource":"mysql",`, "", 1),
		"missing datasource":            strings.Replace(valid, `"datasource":"mysql",`, "", 1),
		"empty datasource":              strings.Replace(valid, `"datasource":"mysql"`, `"datasource":""`, 1),
		"null datasource":               strings.Replace(valid, `"datasource":"mysql"`, `"datasource":null`, 1),
		"numeric datasource":            strings.Replace(valid, `"datasource":"mysql"`, `"datasource":1`, 1),
		"case-folded datasource":        strings.Replace(valid, `"datasource"`, `"Datasource"`, 1),
		"null query":                    `{"profile":"analytics","datasource":"mysql","query":null}`,
		"case-folded key":               strings.Replace(valid, `"query"`, `"Query"`, 1),
		"duplicate key":                 strings.Replace(valid, `"profile":"analytics"`, `"profile":"analytics","profile":"other"`, 1),
		"duplicate datasource":          strings.Replace(valid, `"datasource":"mysql"`, `"datasource":"mysql","datasource":"other"`, 1),
		"null optional filter":          strings.Replace(valid, `}}`, `,"filter":null}}`, 1),
		"quoted grouped limit":          `{"profile":"analytics","datasource":"mysql","query":{"mode":"grouped","source":{"schema":"app","name":"orders"},"projection":[{"kind":"dimension","field":"status"},{"kind":"measure","function":"count_all","alias":"total"}],"limit":"10"}}`,
		"scalar order":                  strings.Replace(valid, `}}`, `,"order_by":[]}}`, 1),
		"branch-specific field":         strings.Replace(valid, `"alias":"total"`, `"field":"id","alias":"total"`, 1),
		"empty projection":              strings.Replace(valid, `[{"kind":"measure","function":"count_all","alias":"total"}]`, `[]`, 1),
		"duplicate projection output":   strings.Replace(valid, `[{"kind":"measure","function":"count_all","alias":"total"}]`, `[{"kind":"measure","function":"count_all","alias":"total"},{"kind":"measure","function":"count_all","alias":"total"}]`, 1),
		"JSON-equal numeric duplicates": `{"profile":"analytics","datasource":"mysql","query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"total"}],"filter":{"kind":"group","operator":"and","expressions":[{"kind":"predicate","field":"id","operator":"eq","values":[{"type":"integer","value":1}]},{"kind":"predicate","field":"id","operator":"eq","values":[{"type":"integer","value":1.0}]}]}}}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeStrictAggregate([]byte(body), 8, 200, 200); err == nil {
				t.Fatalf("DecodeStrictAggregate() accepted %s", body)
			}
		})
	}
}

func TestAggregateTokenScanEnforcesHardFilterTotals(t *testing.T) {
	thirdPredicate := `,{"kind":"predicate","field":"c","operator":"eq","values":[{"type":"integer","value":3}]}`
	predicateBody := `{"profile":"analytics","datasource":"mysql","query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"total"}],"filter":{"kind":"group","operator":"and","expressions":[` +
		`{"kind":"predicate","field":"a","operator":"eq","values":[{"type":"integer","value":1}]},` +
		`{"kind":"predicate","field":"b","operator":"eq","values":[{"type":"integer","value":2}]}` +
		thirdPredicate +
		`]}}}`
	validAtLimit := strings.Replace(predicateBody, thirdPredicate, "", 1)
	if _, err := DecodeStrictAggregate([]byte(validAtLimit), 8, 2, 2); err != nil {
		t.Fatalf("DecodeStrictAggregate() rejected filter exactly at hard totals: %v", err)
	}
	if err := scanAggregateRequestShape([]byte(predicateBody), 8, 2, 10); err == nil ||
		!strings.Contains(err.Error(), "predicate limit") {
		t.Fatalf("predicate scan error = %v", err)
	}
	if _, err := DecodeStrictAggregate([]byte(predicateBody), 8, 2, 10); err == nil ||
		!strings.Contains(err.Error(), "predicate limit") {
		t.Fatalf("DecodeStrictAggregate() predicate error = %v", err)
	}

	parameterBody := `{"profile":"analytics","datasource":"mysql","query":{"mode":"scalar","source":{"schema":"app","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"total"}],"filter":{"kind":"predicate","field":"id","operator":"in","values":[` +
		`{"type":"integer","value":1},{"type":"integer","value":2},{"type":"integer","value":3}` +
		`]}}}`
	if err := scanAggregateRequestShape([]byte(parameterBody), 8, 10, 2); err == nil ||
		!strings.Contains(err.Error(), "parameter limit") {
		t.Fatalf("parameter scan error = %v", err)
	}
	if _, err := DecodeStrictAggregate([]byte(parameterBody), 8, 10, 2); err == nil ||
		!strings.Contains(err.Error(), "parameter limit") {
		t.Fatalf("DecodeStrictAggregate() parameter error = %v", err)
	}

	groupedBody := `{"profile":"analytics","datasource":"mysql","query":{"mode":"grouped","source":{"schema":"app","name":"orders"},"projection":[{"kind":"dimension","field":"status"},{"kind":"measure","function":"count_all","alias":"total"}],"filter":{"kind":"predicate","field":"id","operator":"in","values":[{"type":"integer","value":1},{"type":"integer","value":2}]},"limit":10}}`
	if err := scanAggregateRequestShape([]byte(groupedBody), 8, 10, 2); err == nil ||
		!strings.Contains(err.Error(), "parameter limit") {
		t.Fatalf("grouped server-parameter scan error = %v", err)
	}
}

func TestNormalizeAggregateIdentifiersRejectsCaseCollisions(t *testing.T) {
	limit := 10
	validated, validateErr := validateAggregate(AggregateSpec{
		Mode:   AggregateModeGrouped,
		Source: ResourceRef{Schema: "App", Name: "Orders"},
		Projection: []AggregateOutput{
			{Kind: "dimension", Field: "Status"},
			{Kind: "measure", Function: "count_all", Alias: "STATUS"},
		},
		Limit: &limit,
	}, 10, 10, 10, 10, 4, 20, 100, false)
	if validateErr != nil {
		t.Fatalf("transport validation failed before identifier normalization: %v", validateErr)
	}
	_, err := NormalizeAggregateIdentifiers(validated, domain.IdentifierSemantics{
		CaseInsensitiveSchemas: true,
		CaseInsensitiveObjects: true,
		CaseInsensitiveFields:  true,
	})
	if err == nil {
		t.Fatal("case-colliding aggregate outputs were accepted")
	}
}

func TestValidateAggregateRejectsCaseInsensitiveOutputCollisions(t *testing.T) {
	_, err := ValidateAggregate(AggregateSpec{
		Mode:   AggregateModeScalar,
		Source: ResourceRef{Schema: "app", Name: "orders"},
		Projection: []AggregateOutput{
			{Kind: "measure", Function: "count_all", Alias: "total"},
			{Kind: "measure", Function: "count_all", Alias: "TOTAL"},
		},
	}, 10, 10, 10, 10, 4, 20, 100)
	if err == nil || !strings.Contains(err.Error(), "colliding output names") {
		t.Fatalf("ValidateAggregate() error = %v", err)
	}
}

func TestNormalizeAggregateFilterIsCommutativeAndRejectsNormalizedDuplicates(t *testing.T) {
	valueOne := TypedValue{Type: "integer", Value: json.RawMessage(`1`)}
	valueOneDecimal := TypedValue{Type: "integer", Value: json.RawMessage(`1.0`)}
	filter := Filter{Kind: "group", Operator: "and", Expressions: []Filter{
		{Kind: "predicate", Field: "STATUS", Operator: "eq", Values: []TypedValue{valueOne}},
		{Kind: "predicate", Field: "status", Operator: "eq", Values: []TypedValue{valueOneDecimal}},
	}}
	limit := 10
	validated := mustValidateAggregate(t, AggregateSpec{
		Mode:   AggregateModeGrouped,
		Source: ResourceRef{Schema: "app", Name: "orders"},
		Projection: []AggregateOutput{
			{Kind: "dimension", Field: "status"},
			{Kind: "measure", Function: "count_all", Alias: "total"},
		},
		Filter: &filter, Limit: &limit,
	})
	_, err := NormalizeAggregateIdentifiers(validated, domain.IdentifierSemantics{CaseInsensitiveFields: true})
	if err == nil {
		t.Fatal("semantically duplicate filter expressions were accepted")
	}
}

func TestNormalizeAggregateFilterUsesFixedDigestsAtDeepValidDepth(t *testing.T) {
	integerValue := func(value int) TypedValue {
		return TypedValue{Type: "integer", Value: json.RawMessage(strconv.Itoa(value))}
	}
	filter := Filter{Kind: "predicate", Field: "status", Operator: "eq", Values: []TypedValue{integerValue(1)}}
	for depth := 2; depth <= 20; depth++ {
		filter = Filter{Kind: "group", Operator: "and", Expressions: []Filter{
			filter,
			{Kind: "predicate", Field: "status", Operator: "eq", Values: []TypedValue{integerValue(depth)}},
		}}
	}
	validated, err := ValidateAggregate(AggregateSpec{
		Mode:       AggregateModeScalar,
		Source:     ResourceRef{Schema: "app", Name: "orders"},
		Projection: []AggregateOutput{{Kind: "measure", Function: "count_all", Alias: "total"}},
		Filter:     &filter,
	}, 100, 100, 100, 20, 20, 20, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeAggregateIdentifiers(
		validated, domain.IdentifierSemantics{CaseInsensitiveFields: true},
	); err != nil {
		t.Fatalf("NormalizeAggregateIdentifiers() error = %v", err)
	}
	_, shapeDigest, valueDigest, err := normalizeAggregateFilterNode(filter, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(shapeDigest) != sha256.Size || len(valueDigest) != sha256.Size {
		t.Fatalf("digest sizes = %d/%d, want %d", len(shapeDigest), len(valueDigest), sha256.Size)
	}
}

func TestExactAggregateFilterDigestUsesBottomUpFixedKeys(t *testing.T) {
	largeValue, err := json.Marshal(strings.Repeat("x", 128<<10))
	if err != nil {
		t.Fatal(err)
	}
	filter := Filter{Kind: "predicate", Field: "payload", Operator: "eq", Values: []TypedValue{{
		Type: "string", Value: largeValue,
	}}}
	for depth := 2; depth <= 20; depth++ {
		filter = Filter{Kind: "group", Operator: "and", Expressions: []Filter{
			filter,
			{Kind: "predicate", Field: "sequence", Operator: "eq", Values: []TypedValue{{
				Type: "integer", Value: json.RawMessage(strconv.Itoa(depth)),
			}}},
		}}
	}
	digest, err := exactAggregateFilterDigest(filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != sha256.Size {
		t.Fatalf("digest size = %d, want %d", len(digest), sha256.Size)
	}
}

func TestAggregateShapeHashExcludesBoundValues(t *testing.T) {
	shapeHash := func(value string) string {
		t.Helper()
		filter := Filter{Kind: "predicate", Field: "status", Operator: "eq", Values: []TypedValue{{
			Type: "string", Value: json.RawMessage(`"` + value + `"`),
		}}}
		validated := mustValidateAggregate(t, AggregateSpec{
			Mode:       AggregateModeScalar,
			Source:     ResourceRef{Schema: "app", Name: "orders"},
			Projection: []AggregateOutput{{Kind: "measure", Function: "count_all", Alias: "total"}},
			Filter:     &filter,
		})
		return AggregateShapeHash(validated.Spec())
	}
	if shapeHash("active") != shapeHash("closed") {
		t.Fatal("aggregate shape hash includes bound values")
	}
}

func TestValidateAggregateEnforcesEffectiveGroupByLimit(t *testing.T) {
	limit := 10
	spec := AggregateSpec{
		Mode:   AggregateModeGrouped,
		Source: ResourceRef{Schema: "app", Name: "orders"},
		Projection: []AggregateOutput{
			{Kind: "dimension", Field: "status"},
			{Kind: "dimension", Field: "region"},
			{Kind: "measure", Function: "count_all", Alias: "total"},
		},
		Limit: &limit,
	}
	if _, err := ValidateAggregate(spec, 10, 1, 10, 10, 4, 20, 100); err == nil {
		t.Fatal("aggregate exceeding max_group_by_fields was accepted")
	}
	validated, err := ValidateAggregate(spec, 10, 2, 10, 10, 4, 20, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RevalidateAggregate(validated, 10, 1, 10, 10, 4, 20, 100); err == nil {
		t.Fatal("aggregate bypassed max_group_by_fields during revalidation")
	}
}

func mustValidateAggregate(t *testing.T, spec AggregateSpec) ValidatedAggregate {
	t.Helper()
	validated, err := ValidateAggregate(spec, 100, 100, 100, 200, 8, 200, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return validated
}

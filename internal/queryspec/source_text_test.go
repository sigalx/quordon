package queryspec

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sigalx/quordon/internal/domain"
)

const diagnosticSelectJSON = `{"profile":"reader","datasource":"mysql","query":{"source":{"schema":"app","name":"events"},"projection":[{"kind":"field","field":"event_date","representation":"source_text"}],"filter":{"kind":"predicate","field":"event_date","representation":"source_text","operator":"eq","values":[{"type":"string","value":"0000-00-00"}]},"order_by":[{"field":"event_date","direction":"asc","representation":"source_text"}],"limit":2}}`

func TestSourceTextStrictDecodeAndShapeIdentity(t *testing.T) {
	request, err := DecodeStrictSelect([]byte(diagnosticSelectJSON), 8)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := Validate(request.Query, 10, 10, 10, 20, 8, 30, 10, 0)
	if err != nil || !UsesSourceText(validated.Spec()) {
		t.Fatalf("diagnostic spec lost: %v", err)
	}
	ordinary := validated.Spec()
	ordinary.Projection[0].Representation = ""
	ordinary.OrderBy[0].Representation = ""
	ordinary.Filter.Representation = ""
	if ShapeHash(ordinary) == ShapeHash(validated.Spec()) {
		t.Fatal("representation absent from shape hash")
	}
	if validated.Spec().Filter.Representation != RepresentationSourceText {
		t.Fatal("mutable normalized alias")
	}
	ordinaryFilter := *validated.Spec().Filter
	ordinaryFilter.Representation = ""
	if AggregateFilterShapeDigest(ordinaryFilter) == AggregateFilterShapeDigest(*validated.Spec().Filter) {
		t.Fatal("representation absent from filter digest")
	}
	for _, member := range []string{`null`, `""`, `"raw"`, `false`, `1`, `[]`, `{}`} {
		t.Run(member, func(t *testing.T) {
			body := strings.Replace(diagnosticSelectJSON, `"representation":"source_text"`, `"representation":`+member, 1)
			if _, err := DecodeStrictSelect([]byte(body), 8); err == nil {
				t.Fatal("invalid representation accepted")
			}
		})
	}
	for _, member := range []string{`"Representation":"source_text"`, `"representation":"source_text","representation":"source_text"`, `"unexpected":"source_text"`} {
		body := strings.Replace(diagnosticSelectJSON, `"representation":"source_text"`, member, 1)
		if _, err := DecodeStrictSelect([]byte(body), 8); err == nil {
			t.Fatalf("invalid exact/duplicate key accepted: %s", member)
		}
	}
	badValue := strings.Replace(diagnosticSelectJSON, `"type":"string","value":"0000-00-00"`, `"type":"date","value":"2026-01-01"`, 1)
	if _, err := DecodeStrictSelect([]byte(badValue), 8); err == nil {
		t.Fatal("source_text accepted a temporal bind")
	}
}

func TestSourceTextKeysetRepresentationAndCursor(t *testing.T) {
	request := KeysetRequest{Kind: "keyset", Profile: "reader", Datasource: "mysql", Shape: "events_page", Query: KeysetSpec{
		Source: ResourceRef{Schema: "app", Name: "events"}, Projection: []Selection{{Kind: "field", Field: "event_date", Representation: RepresentationSourceText}},
		OrderBy: []Sort{{Field: "event_date", Direction: "asc", Representation: RepresentationSourceText}}, Limit: 2,
	}, Page: KeysetPage{Kind: "after", Cursor: []KeysetCursorValue{{Type: "string", Value: "2026-02-31"}}}}
	validated, err := ValidateKeyset(request, 10, 8, 20, 8, 30, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeKeysetIdentifiers(validated, domain.IdentifierSemantics{CaseInsensitiveFields: true}); err != nil {
		t.Fatal(err)
	}
	request.Query.Projection[0].Representation = ""
	validated, err = ValidateKeyset(request, 10, 8, 20, 8, 30, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeKeysetIdentifiers(validated, domain.IdentifierSemantics{CaseInsensitiveFields: true}); err == nil {
		t.Fatal("mismatched key representations accepted")
	}
	request.Query.Projection[0].Representation = RepresentationSourceText
	request.Page.Cursor[0] = KeysetCursorValue{Type: "date", Value: "2026-01-01"}
	if _, err := ValidateKeyset(request, 10, 8, 20, 8, 30, 10); err == nil {
		t.Fatal("wrong diagnostic cursor type accepted")
	}
}

func TestTypedCalendarValuesRejectZeroYear(t *testing.T) {
	for _, fixture := range []struct{ kind, value string }{
		{"date", "0001-01-01"}, {"date", "0999-12-31"}, {"date", "1000-01-01"}, {"date", "9999-12-31"},
		{"datetime", "0001-01-01T00:00:00Z"}, {"datetime", "0999-12-31t23:59:59z"},
	} {
		raw, _ := json.Marshal(fixture.value)
		if _, err := (TypedValue{Type: fixture.kind, Value: raw}).BindValue(); err != nil {
			t.Fatalf("early calendar value rejected: %v", err)
		}
	}
	for _, fixture := range []struct{ kind, value string }{
		{"date", "0000-01-01"}, {"date", "2026-00-01"}, {"date", "2026-02-31"},
		{"datetime", "0000-01-01T00:00:00Z"}, {"datetime", "2026-02-31T00:00:00Z"},
	} {
		raw, _ := json.Marshal(fixture.value)
		if _, err := (TypedValue{Type: fixture.kind, Value: raw}).BindValue(); err == nil {
			t.Fatal("noncalendar typed value accepted")
		}
	}
}

package policy

import (
	"slices"
	"testing"

	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/queryspec"
)

func TestSourceTextDiscoveryHashAndExactByteBounds(t *testing.T) {
	r := queryspec.RepresentationSourceText
	valueTypes := []string{"string"}
	aggregate := publicAggregateQueryShape{Name: "dates_count", Operation: domain.OperationAggregate,
		Query: publicAggregateShapeSpec{Mode: "grouped", Source: queryspec.ResourceRef{Schema: "app", Name: "events"},
			Projection: []publicAggregateOutput{{Kind: "dimension", Field: "event_date", Representation: r}, {Kind: "measure", Function: "count_all", Alias: "total"}},
			Filter:     &publicAggregateFilter{Kind: "predicate", Field: "event_date", Operator: "eq", Representation: r, ValueTypes: valueTypes},
			OrderBy:    []publicAggregateOrder{{Kind: "dimension", Field: "event_date", Direction: "asc", Representation: r}}, MaximumLimit: 10}}
	keyset := publicKeysetQueryShape{Name: "dates_page", Operation: domain.OperationSelectKeyset,
		Query: publicKeysetShapeSpec{Source: aggregate.Query.Source,
			Projection: []queryspec.Selection{{Kind: "field", Field: "event_date", Representation: r}},
			Filter:     aggregate.Query.Filter, OrderBy: []queryspec.Sort{{Field: "event_date", Direction: "asc", Representation: r}}, MaximumLimit: 10}}
	encode := func(aggregate publicAggregateQueryShape, keyset publicKeysetQueryShape, maximum int) ([]byte, string, error) {
		return encodeQueryShapeResponse("reader", "1", "primary", "adapter", []publicAggregateQueryShape{aggregate}, []publicKeysetQueryShape{keyset}, maximum)
	}
	payload, hash, err := encode(aggregate, keyset, 65536)
	if err != nil {
		t.Fatal(err)
	}
	if exact, exactHash, err := encode(aggregate, keyset, len(payload)); err != nil || !slices.Equal(payload, exact) || hash != exactHash {
		t.Fatalf("exact discovery byte budget rejected: %v", err)
	}
	if payload, _, err := encode(aggregate, keyset, len(payload)-1); err == nil || payload != nil {
		t.Fatal("discovery allocated a payload beyond its byte budget")
	}
	for _, change := range []func(*publicAggregateQueryShape, *publicKeysetQueryShape){
		func(a *publicAggregateQueryShape, _ *publicKeysetQueryShape) {
			a.Query.Projection[0].Representation = ""
		},
		func(a *publicAggregateQueryShape, _ *publicKeysetQueryShape) { a.Query.OrderBy[0].Representation = "" },
		func(a *publicAggregateQueryShape, _ *publicKeysetQueryShape) { a.Query.Filter.Representation = "" },
		func(_ *publicAggregateQueryShape, k *publicKeysetQueryShape) {
			k.Query.Projection[0].Representation = ""
		},
		func(_ *publicAggregateQueryShape, k *publicKeysetQueryShape) { k.Query.OrderBy[0].Representation = "" },
	} {
		a, k := aggregate, keyset
		a.Query.Projection = slices.Clone(a.Query.Projection)
		a.Query.OrderBy = slices.Clone(a.Query.OrderBy)
		filter := *a.Query.Filter
		a.Query.Filter = &filter
		k.Query.Projection = slices.Clone(k.Query.Projection)
		k.Query.OrderBy = slices.Clone(k.Query.OrderBy)
		change(&a, &k)
		if _, changedHash, err := encode(a, k, 65536); err != nil || changedHash == hash {
			t.Fatalf("discovery identity omitted representation: %v", err)
		}
	}
}

package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/queryspec"
)

const queryShapeV3HashDomain = "quordon/query-shapes/v3\x00"

type publicKeysetQueryShape struct {
	Name        string                `json:"name"`
	Description *string               `json:"description,omitempty"`
	Operation   domain.Operation      `json:"operation"`
	Query       publicKeysetShapeSpec `json:"query"`
}

type publicKeysetShapeSpec struct {
	Source       queryspec.ResourceRef  `json:"source"`
	Projection   []queryspec.Selection  `json:"projection"`
	Filter       *publicAggregateFilter `json:"filter,omitempty"`
	OrderBy      []queryspec.Sort       `json:"order_by"`
	MaximumLimit int                    `json:"maximum_limit"`
}

type publicQueryShapeV3 struct {
	aggregate *publicAggregateQueryShape
	keyset    *publicKeysetQueryShape
}

func (s publicQueryShapeV3) MarshalJSON() ([]byte, error) {
	if s.aggregate != nil && s.keyset == nil {
		return json.Marshal(*s.aggregate)
	}
	if s.keyset != nil && s.aggregate == nil {
		return json.Marshal(*s.keyset)
	}
	return nil, errors.New("invalid public query-shape union")
}

type queryShapeListResponseV3 struct {
	PolicyProfile string               `json:"policy_profile"`
	PolicyVersion string               `json:"policy_version"`
	Datasource    string               `json:"datasource"`
	Adapter       string               `json:"adapter"`
	Shapes        []publicQueryShapeV3 `json:"shapes"`
}

func buildPublicKeysetQueryShapes(
	configured []config.KeysetSelectShape,
	semantics domain.IdentifierSemantics,
) ([]publicKeysetQueryShape, error) {
	shapes := cloneKeysetSelectShapes(configured)
	slices.SortFunc(shapes, func(a, b config.KeysetSelectShape) int { return strings.Compare(a.Name, b.Name) })
	result := make([]publicKeysetQueryShape, len(shapes))
	for index, shape := range shapes {
		if !queryspec.IsIdentifier(shape.Name) || !queryspec.IsIdentifier(shape.Source.Schema) ||
			!queryspec.IsIdentifier(shape.Source.Name) || shape.MaximumLimit < 1 {
			return nil, fmt.Errorf("keyset shape %q has invalid public members", shape.Name)
		}
		public := publicKeysetQueryShape{
			Name: shape.Name, Description: shape.PublicDescription, Operation: domain.OperationSelectKeyset,
			Query: publicKeysetShapeSpec{
				Source:     queryspec.ResourceRef{Schema: shape.Source.Schema, Name: shape.Source.Name},
				Projection: make([]queryspec.Selection, len(shape.Projection)),
				OrderBy:    make([]queryspec.Sort, len(shape.OrderBy)), MaximumLimit: shape.MaximumLimit,
			},
		}
		for outputIndex, output := range shape.Projection {
			public.Query.Projection[outputIndex] = queryspec.Selection{
				Kind: output.Kind, Field: output.Field, Alias: output.Alias,
			}
		}
		if shape.Filter != nil {
			filter, _, err := buildPublicAggregateFilter(*shape.Filter, semantics.CaseInsensitiveFields)
			if err != nil {
				return nil, fmt.Errorf("keyset shape %q filter: %w", shape.Name, err)
			}
			public.Query.Filter = &filter
		}
		for orderIndex, order := range shape.OrderBy {
			public.Query.OrderBy[orderIndex] = queryspec.Sort{Field: order.Field, Direction: order.Direction}
		}
		result[index] = public
	}
	return result, nil
}

func configuredKeysetShapeFields(shape config.KeysetSelectShape) []string {
	fields := make([]string, 0, len(shape.Projection)+len(shape.OrderBy))
	for _, projection := range shape.Projection {
		fields = append(fields, projection.Field)
	}
	if shape.Filter != nil {
		collectConfiguredQueryShapeFilterFields(*shape.Filter, &fields)
	}
	for _, order := range shape.OrderBy {
		fields = append(fields, order.Field)
	}
	slices.Sort(fields)
	return slices.Compact(fields)
}

func collectConfiguredQueryShapeFilterFields(filter config.AggregateShapeFilter, fields *[]string) {
	if filter.Kind == "predicate" {
		*fields = append(*fields, filter.Field)
		return
	}
	for _, child := range filter.Expressions {
		collectConfiguredQueryShapeFilterFields(child, fields)
	}
}

func encodeQueryShapeResponseV3(
	profileName, policyVersion, datasource, adapter string,
	aggregates []publicAggregateQueryShape,
	keysets []publicKeysetQueryShape,
	maximum int,
) ([]byte, string, error) {
	shapes := make([]publicQueryShapeV3, 0, len(aggregates)+len(keysets))
	for index := range aggregates {
		shape := aggregates[index]
		shapes = append(shapes, publicQueryShapeV3{aggregate: &shape})
	}
	for index := range keysets {
		shape := keysets[index]
		shapes = append(shapes, publicQueryShapeV3{keyset: &shape})
	}
	slices.SortFunc(shapes, func(a, b publicQueryShapeV3) int {
		return strings.Compare(publicQueryShapeV3Name(a), publicQueryShapeV3Name(b))
	})
	response := queryShapeListResponseV3{
		PolicyProfile: profileName, PolicyVersion: policyVersion, Datasource: datasource,
		Adapter: adapter, Shapes: shapes,
	}
	encodedSize, ok := queryShapeListResponseV3Size(response, maximum)
	if !ok || len(shapes) == 0 {
		return nil, "", fmt.Errorf("profile %q query-shape v3 response exceeds max_result_bytes or is empty", profileName)
	}
	payload, err := json.Marshal(response)
	if err != nil {
		return nil, "", fmt.Errorf("marshal public query shapes v3: %w", err)
	}
	if len(payload) != encodedSize {
		return nil, "", errors.New("public query-shape v3 size invariant failed")
	}
	shapeSetHash, err := publicQueryShapeSetHashV3(shapes)
	if err != nil {
		return nil, "", err
	}
	return payload, shapeSetHash, nil
}

func publicQueryShapeSetHashV3(shapes []publicQueryShapeV3) (string, error) {
	digest := sha256.New()
	_, _ = io.WriteString(digest, queryShapeV3HashDomain)
	_, _ = io.WriteString(digest, "[")
	for index, shape := range shapes {
		if index != 0 {
			_, _ = io.WriteString(digest, ",")
		}
		switch {
		case shape.aggregate != nil && shape.keyset == nil:
			if err := writeJCSShape(digest, *shape.aggregate); err != nil {
				return "", fmt.Errorf("canonicalize aggregate query shape v3: %w", err)
			}
		case shape.keyset != nil && shape.aggregate == nil:
			if err := writeJCSKeysetShape(digest, *shape.keyset); err != nil {
				return "", fmt.Errorf("canonicalize keyset query shape v3: %w", err)
			}
		default:
			return "", errors.New("canonicalize invalid query-shape v3 union")
		}
	}
	_, _ = io.WriteString(digest, "]")
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func writeJCSKeysetShape(writer hash.Hash, shape publicKeysetQueryShape) error {
	_, _ = io.WriteString(writer, "{")
	separator := ""
	if shape.Description != nil {
		_, _ = io.WriteString(writer, `"description":`)
		if err := writeJCSString(writer, *shape.Description); err != nil {
			return err
		}
		separator = ","
	}
	_, _ = io.WriteString(writer, separator+`"name":`)
	if err := writeJCSString(writer, shape.Name); err != nil {
		return err
	}
	_, _ = io.WriteString(writer, `,"operation":"select_keyset","query":`)
	if err := writeJCSKeysetQuery(writer, shape.Query); err != nil {
		return err
	}
	_, _ = io.WriteString(writer, "}")
	return nil
}

func writeJCSKeysetQuery(writer hash.Hash, spec publicKeysetShapeSpec) error {
	_, _ = io.WriteString(writer, "{")
	if spec.Filter != nil {
		_, _ = io.WriteString(writer, `"filter":`)
		if err := writeJCSFilter(writer, *spec.Filter); err != nil {
			return err
		}
		_, _ = io.WriteString(writer, ",")
	}
	_, _ = io.WriteString(writer, `"maximum_limit":`+strconv.Itoa(spec.MaximumLimit)+`,"order_by":[`)
	for index, order := range spec.OrderBy {
		if index != 0 {
			_, _ = io.WriteString(writer, ",")
		}
		_, _ = io.WriteString(writer, `{"direction":`)
		if err := writeJCSString(writer, order.Direction); err != nil {
			return err
		}
		_, _ = io.WriteString(writer, `,"field":`)
		if err := writeJCSString(writer, order.Field); err != nil {
			return err
		}
		_, _ = io.WriteString(writer, "}")
	}
	_, _ = io.WriteString(writer, `],"projection":[`)
	for index, projection := range spec.Projection {
		if index != 0 {
			_, _ = io.WriteString(writer, ",")
		}
		_, _ = io.WriteString(writer, "{")
		separator := ""
		if projection.Alias != "" {
			_, _ = io.WriteString(writer, `"alias":`)
			if err := writeJCSString(writer, projection.Alias); err != nil {
				return err
			}
			separator = ","
		}
		_, _ = io.WriteString(writer, separator+`"field":`)
		if err := writeJCSString(writer, projection.Field); err != nil {
			return err
		}
		_, _ = io.WriteString(writer, `,"kind":"field"}`)
	}
	_, _ = io.WriteString(writer, `],"source":{"name":`)
	if err := writeJCSString(writer, spec.Source.Name); err != nil {
		return err
	}
	_, _ = io.WriteString(writer, `,"schema":`)
	if err := writeJCSString(writer, spec.Source.Schema); err != nil {
		return err
	}
	_, _ = io.WriteString(writer, "}}")
	return nil
}

func publicQueryShapeV3Name(shape publicQueryShapeV3) string {
	if shape.aggregate != nil {
		return shape.aggregate.Name
	}
	if shape.keyset != nil {
		return shape.keyset.Name
	}
	return ""
}

func queryShapeListResponseV3Size(response queryShapeListResponseV3, maximum int) (int, bool) {
	size := newBoundedSize(maximum)
	size.add(len(`{"policy_profile":`))
	size.string(response.PolicyProfile)
	size.add(len(`,"policy_version":`))
	size.string(response.PolicyVersion)
	size.add(len(`,"datasource":`))
	size.string(response.Datasource)
	size.add(len(`,"adapter":`))
	size.string(response.Adapter)
	size.add(len(`,"shapes":[`))
	for index, shape := range response.Shapes {
		if index != 0 {
			size.add(1)
		}
		if shape.aggregate != nil && shape.keyset == nil {
			queryShapeEncodedSize(size, *shape.aggregate)
		} else if shape.keyset != nil && shape.aggregate == nil {
			keysetQueryShapeEncodedSize(size, *shape.keyset)
		} else {
			size.ok = false
		}
	}
	size.add(len(`]}`))
	return size.value, size.ok
}

func keysetQueryShapeEncodedSize(size *boundedSize, shape publicKeysetQueryShape) {
	size.add(len(`{"name":`))
	size.string(shape.Name)
	if shape.Description != nil {
		size.add(len(`,"description":`))
		size.string(*shape.Description)
	}
	size.add(len(`,"operation":`))
	size.string(string(shape.Operation))
	size.add(len(`,"query":{"source":{"schema":`))
	size.string(shape.Query.Source.Schema)
	size.add(len(`,"name":`))
	size.string(shape.Query.Source.Name)
	size.add(len(`},"projection":[`))
	for index, projection := range shape.Query.Projection {
		if index != 0 {
			size.add(1)
		}
		size.add(len(`{"kind":`))
		size.string(projection.Kind)
		size.add(len(`,"field":`))
		size.string(projection.Field)
		if projection.Alias != "" {
			size.add(len(`,"alias":`))
			size.string(projection.Alias)
		}
		size.add(1)
	}
	size.add(1)
	if shape.Query.Filter != nil {
		size.add(len(`,"filter":`))
		queryShapeFilterEncodedSize(size, *shape.Query.Filter)
	}
	size.add(len(`,"order_by":[`))
	for index, order := range shape.Query.OrderBy {
		if index != 0 {
			size.add(1)
		}
		size.add(len(`{"field":`))
		size.string(order.Field)
		size.add(len(`,"direction":`))
		size.string(order.Direction)
		size.add(1)
	}
	size.add(len(`],"maximum_limit":`))
	size.add(len(strconv.Itoa(shape.Query.MaximumLimit)))
	size.add(len(`}}`))
}

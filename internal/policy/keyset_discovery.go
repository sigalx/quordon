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

type publicQueryShape struct {
	aggregate *publicAggregateQueryShape
	keyset    *publicKeysetQueryShape
}

func (s publicQueryShape) MarshalJSON() ([]byte, error) {
	if s.aggregate != nil && s.keyset == nil {
		return json.Marshal(*s.aggregate)
	}
	if s.keyset != nil && s.aggregate == nil {
		return json.Marshal(*s.keyset)
	}
	return nil, errors.New("invalid public query-shape union")
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
				Representation: output.Representation, Kind: output.Kind, Field: output.Field, Alias: output.Alias,
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
			public.Query.OrderBy[orderIndex] = queryspec.Sort{Representation: order.Representation, Field: order.Field, Direction: order.Direction}
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

func encodeQueryShapeResponse(
	profileName, policyVersion, datasource, adapter string,
	aggregates []publicAggregateQueryShape,
	keysets []publicKeysetQueryShape,
	maximum int,
) ([]byte, string, error) {
	shapesPayload, shapeSetHash, err := encodeQueryShapeDocument(profileName, aggregates, keysets, maximum)
	if err != nil {
		return nil, "", err
	}
	prefix, resultBytes, err := encodeQueryShapeEnvelope(
		profileName, policyVersion, datasource, adapter, len(shapesPayload), maximum,
	)
	if err != nil {
		return nil, "", err
	}
	payload := make([]byte, 0, resultBytes)
	payload = append(payload, prefix...)
	payload = append(payload, shapesPayload...)
	payload = append(payload, '}')
	if len(payload) != resultBytes {
		return nil, "", errors.New("public query-shape size invariant failed")
	}
	return payload, shapeSetHash, nil
}

func encodeQueryShapeDocument(
	profileName string,
	aggregates []publicAggregateQueryShape,
	keysets []publicKeysetQueryShape,
	maximum int,
) ([]byte, string, error) {
	shapes := make([]publicQueryShape, 0, len(aggregates)+len(keysets))
	for index := range aggregates {
		shape := aggregates[index]
		shapes = append(shapes, publicQueryShape{aggregate: &shape})
	}
	for index := range keysets {
		shape := keysets[index]
		shapes = append(shapes, publicQueryShape{keyset: &shape})
	}
	slices.SortFunc(shapes, func(a, b publicQueryShape) int {
		return strings.Compare(publicQueryShapeName(a), publicQueryShapeName(b))
	})
	encodedSize, ok := queryShapeArraySize(shapes, maximum)
	if !ok || len(shapes) == 0 {
		return nil, "", fmt.Errorf("profile %q query-shape response exceeds max_result_bytes or is empty", profileName)
	}
	payload, err := json.Marshal(shapes)
	if err != nil {
		return nil, "", fmt.Errorf("marshal public query shapes: %w", err)
	}
	if len(payload) != encodedSize {
		return nil, "", errors.New("public query-shape size invariant failed")
	}
	shapeSetHash, err := publicQueryShapeSetHash(shapes)
	if err != nil {
		return nil, "", err
	}
	return payload, shapeSetHash, nil
}

func encodeQueryShapeEnvelope(
	profileName, policyVersion, datasource, adapter string,
	shapesPayloadBytes, maximum int,
) ([]byte, int, error) {
	size := newBoundedSize(maximum)
	size.add(len(`{"policy_profile":`))
	size.string(profileName)
	size.add(len(`,"policy_version":`))
	size.string(policyVersion)
	size.add(len(`,"datasource":`))
	size.string(datasource)
	size.add(len(`,"adapter":`))
	size.string(adapter)
	size.add(len(`,"shapes":`))
	size.add(shapesPayloadBytes)
	size.add(1) // }
	if !size.ok || shapesPayloadBytes < 0 {
		return nil, 0, fmt.Errorf("profile %q query-shape response exceeds max_result_bytes or is empty", profileName)
	}
	prefixSize := size.value - shapesPayloadBytes - 1
	prefix := make([]byte, 0, prefixSize)
	prefix = append(prefix, `{"policy_profile":`...)
	var err error
	prefix, err = appendQueryShapeJSONString(prefix, profileName)
	if err != nil {
		return nil, 0, err
	}
	prefix = append(prefix, `,"policy_version":`...)
	prefix, err = appendQueryShapeJSONString(prefix, policyVersion)
	if err != nil {
		return nil, 0, err
	}
	prefix = append(prefix, `,"datasource":`...)
	prefix, err = appendQueryShapeJSONString(prefix, datasource)
	if err != nil {
		return nil, 0, err
	}
	prefix = append(prefix, `,"adapter":`...)
	prefix, err = appendQueryShapeJSONString(prefix, adapter)
	if err != nil {
		return nil, 0, err
	}
	prefix = append(prefix, `,"shapes":`...)
	if len(prefix) != prefixSize {
		return nil, 0, errors.New("public query-shape envelope size invariant failed")
	}
	return prefix, size.value, nil
}

func appendQueryShapeJSONString(destination []byte, value string) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal public query-shape envelope: %w", err)
	}
	return append(destination, encoded...), nil
}

func queryShapeArraySize(shapes []publicQueryShape, maximum int) (int, bool) {
	size := newBoundedSize(maximum)
	size.add(1) // [
	for index, shape := range shapes {
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
	size.add(1) // ]
	return size.value, size.ok
}

func publicQueryShapeSetHash(shapes []publicQueryShape) (string, error) {
	digest := sha256.New()
	_, _ = io.WriteString(digest, queryShapeHashDomain)
	_, _ = io.WriteString(digest, "[")
	for index, shape := range shapes {
		if index != 0 {
			_, _ = io.WriteString(digest, ",")
		}
		switch {
		case shape.aggregate != nil && shape.keyset == nil:
			if err := writeJCSShape(digest, *shape.aggregate); err != nil {
				return "", fmt.Errorf("canonicalize aggregate query shape: %w", err)
			}
		case shape.keyset != nil && shape.aggregate == nil:
			if err := writeJCSKeysetShape(digest, *shape.keyset); err != nil {
				return "", fmt.Errorf("canonicalize keyset query shape: %w", err)
			}
		default:
			return "", errors.New("canonicalize invalid query-shape union")
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
		if order.Representation != "" {
			_, _ = io.WriteString(writer, `,"representation":`)
			if err := writeJCSString(writer, string(order.Representation)); err != nil {
				return err
			}
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
		_, _ = io.WriteString(writer, `,"kind":"field"`)
		if projection.Representation != "" {
			_, _ = io.WriteString(writer, `,"representation":`)
			if err := writeJCSString(writer, string(projection.Representation)); err != nil {
				return err
			}
		}
		_, _ = io.WriteString(writer, "}")
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

func publicQueryShapeName(shape publicQueryShape) string {
	if shape.aggregate != nil {
		return shape.aggregate.Name
	}
	if shape.keyset != nil {
		return shape.keyset.Name
	}
	return ""
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
		if projection.Representation != "" {
			size.add(len(`,"representation":"source_text"`))
		}
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
		if order.Representation != "" {
			size.add(len(`,"representation":"source_text"`))
		}
		size.add(1)
	}
	size.add(len(`],"maximum_limit":`))
	size.add(len(strconv.Itoa(shape.Query.MaximumLimit)))
	size.add(len(`}}`))
}

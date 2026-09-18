package domain

import "time"

const (
	APIMajorVersion         = "1"
	AdapterMySQL8           = "mysql8"
	MaxSupportedResultBytes = 16 * 1024 * 1024
	QueryShapesMediaType    = "application/json"
)

type AdapterFeature string

const (
	FeatureTimeBucketUTC AdapterFeature = "time_bucket_utc"
	FeatureSourceText    AdapterFeature = "source_text"
)

func (f AdapterFeature) Valid() bool { return f == FeatureTimeBucketUTC || f == FeatureSourceText }

type Operation string

const (
	OperationListObjects              Operation = "list_objects"
	OperationDescribeObject           Operation = "describe_object"
	OperationExplainSelect            Operation = "explain_select"
	OperationSelect                   Operation = "select"
	OperationSelectKeyset             Operation = "select_keyset"
	OperationAggregate                Operation = "aggregate"
	OperationListQueryShapes          Operation = "list_query_shapes"
	OperationDescribeObjectStatistics Operation = "describe_object_statistics"
)

func (o Operation) Valid() bool {
	switch o {
	case OperationListObjects, OperationDescribeObject, OperationExplainSelect, OperationSelect, OperationSelectKeyset, OperationAggregate,
		OperationListQueryShapes, OperationDescribeObjectStatistics:
		return true
	default:
		return false
	}
}

type IdentifierSemantics struct {
	CaseInsensitiveSchemas bool
	CaseInsensitiveObjects bool
	CaseInsensitiveFields  bool
}

type Limits struct {
	DeadlineMS          int `json:"deadline_ms" yaml:"deadline_ms"`
	MaxRequestBytes     int `json:"max_request_bytes" yaml:"max_request_bytes"`
	MaxProjectionFields int `json:"max_projection_fields" yaml:"max_projection_fields"`
	MaxGroupByFields    int `json:"max_group_by_fields" yaml:"max_group_by_fields"`
	MaxOrderByFields    int `json:"max_order_by_fields" yaml:"max_order_by_fields"`
	MaxPredicates       int `json:"max_predicates" yaml:"max_predicates"`
	MaxExpressionDepth  int `json:"max_expression_depth" yaml:"max_expression_depth"`
	MaxParameters       int `json:"max_parameters" yaml:"max_parameters"`
	MaxRows             int `json:"max_rows" yaml:"max_rows"`
	MaxResultBytes      int `json:"max_result_bytes" yaml:"max_result_bytes"`
	MaxOffset           int `json:"max_offset" yaml:"max_offset"`
	MaxConcurrency      int `json:"max_concurrency" yaml:"max_concurrency"`
}

func (l Limits) Deadline() time.Duration {
	return time.Duration(l.DeadlineMS) * time.Millisecond
}

func (l Limits) Min(other Limits) Limits {
	return Limits{
		DeadlineMS:          min(l.DeadlineMS, other.DeadlineMS),
		MaxRequestBytes:     min(l.MaxRequestBytes, other.MaxRequestBytes),
		MaxProjectionFields: min(l.MaxProjectionFields, other.MaxProjectionFields),
		MaxGroupByFields:    min(l.MaxGroupByFields, other.MaxGroupByFields),
		MaxOrderByFields:    min(l.MaxOrderByFields, other.MaxOrderByFields),
		MaxPredicates:       min(l.MaxPredicates, other.MaxPredicates),
		MaxExpressionDepth:  min(l.MaxExpressionDepth, other.MaxExpressionDepth),
		MaxParameters:       min(l.MaxParameters, other.MaxParameters),
		MaxRows:             min(l.MaxRows, other.MaxRows),
		MaxResultBytes:      min(l.MaxResultBytes, other.MaxResultBytes),
		MaxOffset:           min(l.MaxOffset, other.MaxOffset),
		MaxConcurrency:      min(l.MaxConcurrency, other.MaxConcurrency),
	}
}

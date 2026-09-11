package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryspec"
	"github.com/sigalx/quordon/internal/secrets"
)

type ErrorKind string

const (
	ErrorInvalid         ErrorKind = "invalid"
	ErrorNotImplemented  ErrorKind = "not_implemented"
	ErrorUnavailable     ErrorKind = "unavailable"
	ErrorTimeout         ErrorKind = "timeout"
	ErrorUpstream        ErrorKind = "upstream"
	ErrorRequestTooLarge ErrorKind = "request_too_large"
	ErrorResultTooLarge  ErrorKind = "result_too_large"
)

type Error struct {
	Kind ErrorKind
	Err  error
}

func (e *Error) Error() string { return string(e.Kind) }
func (e *Error) Unwrap() error { return e.Err }

func IsKind(err error, kind ErrorKind) bool {
	var databaseError *Error
	return errors.As(err, &databaseError) && databaseError.Kind == kind
}

type ConfigurationError struct {
	Err error
}

func (e *ConfigurationError) Error() string { return e.Err.Error() }
func (e *ConfigurationError) Unwrap() error { return e.Err }

func IsConfigurationError(err error) bool {
	var configurationError *ConfigurationError
	return errors.As(err, &configurationError)
}

type ExplainResult struct {
	Format string
	Plan   json.RawMessage
}

type SchemaObject struct {
	Name string `json:"name"`
}

type ColumnDescription struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	NativeType string `json:"native_type"`
	Nullable   bool   `json:"nullable"`
	PrimaryKey bool   `json:"primary_key"`
	Indexed    bool   `json:"indexed"`
}

type ObjectDescription struct {
	Schema  string              `json:"schema"`
	Name    string              `json:"name"`
	Columns []ColumnDescription `json:"columns"`
}

type ResultColumn struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Encoding string `json:"encoding"`
	Nullable bool   `json:"nullable"`
}

type SelectResult struct {
	Columns     []ResultColumn `json:"columns"`
	Rows        [][]*string    `json:"rows"`
	RowCount    int            `json:"row_count"`
	Truncated   bool           `json:"truncated"`
	ResultBytes int            `json:"-"`
}

type KeysetEnvelopeBudget struct {
	FinalBaseBytes int
	MoreBaseBytes  int
}

type KeysetSelectResult struct {
	Columns     []ResultColumn
	Rows        [][]*string
	RowCount    int
	HasMore     bool
	NextCursor  []queryspec.KeysetCursorValue
	ResultBytes int
}

type AggregateResult struct {
	Mode        string         `json:"mode"`
	Columns     []ResultColumn `json:"columns"`
	Rows        [][]*string    `json:"rows"`
	RowCount    int            `json:"row_count"`
	Truncated   bool           `json:"truncated"`
	ResultBytes int            `json:"-"`
}

type UnsignedMetric struct {
	Value     string `json:"value"`
	Estimated bool   `json:"estimated"`
}

type TableStatistics struct {
	EstimatedRows *UnsignedMetric `json:"estimated_rows"`
	DataBytes     *UnsignedMetric `json:"data_bytes"`
	IndexBytes    *UnsignedMetric `json:"index_bytes"`
	AutoIncrement *UnsignedMetric `json:"auto_increment"`
}

type PartitionStatistics struct {
	EstimatedRows *UnsignedMetric `json:"estimated_rows"`
	DataBytes     *UnsignedMetric `json:"data_bytes"`
	IndexBytes    *UnsignedMetric `json:"index_bytes"`
}

type PartitionEntry struct {
	Name       string              `json:"name"`
	Ordinal    int                 `json:"ordinal"`
	Statistics PartitionStatistics `json:"statistics"`
}

type SubpartitionEntry struct {
	Name       string              `json:"name"`
	Ordinal    int                 `json:"ordinal"`
	Statistics PartitionStatistics `json:"statistics"`
}

type PartitionGroup struct {
	Name          string              `json:"name"`
	Ordinal       int                 `json:"ordinal"`
	Subpartitions []SubpartitionEntry `json:"subpartitions"`
}

// PartitioningResult is a closed wire union. Kind controls which optional
// members are populated; the MySQL adapter validates the branch before this
// value crosses the trusted executor boundary.
type PartitioningResult struct {
	Kind               string           `json:"kind"`
	Method             string           `json:"method,omitempty"`
	SubpartitionMethod string           `json:"subpartition_method,omitempty"`
	Partitions         []PartitionEntry `json:"partitions,omitempty"`
	PartitionGroups    []PartitionGroup `json:"-"`
}

func (p PartitioningResult) MarshalJSON() ([]byte, error) {
	switch p.Kind {
	case "none":
		return json.Marshal(struct {
			Kind string `json:"kind"`
		}{Kind: p.Kind})
	case "partitioned":
		return json.Marshal(struct {
			Kind       string           `json:"kind"`
			Method     string           `json:"method"`
			Partitions []PartitionEntry `json:"partitions"`
		}{Kind: p.Kind, Method: p.Method, Partitions: p.Partitions})
	case "subpartitioned":
		return json.Marshal(struct {
			Kind               string           `json:"kind"`
			Method             string           `json:"method"`
			SubpartitionMethod string           `json:"subpartition_method"`
			Partitions         []PartitionGroup `json:"partitions"`
		}{Kind: p.Kind, Method: p.Method, SubpartitionMethod: p.SubpartitionMethod, Partitions: p.PartitionGroups})
	default:
		return nil, errors.New("invalid partitioning result kind")
	}
}

type ObjectStatisticsResult struct {
	ObservedAt        string             `json:"observed_at"`
	Engine            string             `json:"engine"`
	Table             TableStatistics    `json:"table"`
	Partitioning      PartitioningResult `json:"partitioning"`
	ResultBytes       int                `json:"-"`
	PartitionCount    int                `json:"-"`
	SubpartitionCount int                `json:"-"`
}

type Adapter interface {
	Name() string
	Capabilities() []domain.Operation
	Validate(context.Context, *sql.DB) error
	IdentifierSemantics(context.Context, *sql.DB) (domain.IdentifierSemantics, error)
	Open(dsn string, cfg config.Datasource) (*sql.DB, error)
	Explain(context.Context, *sql.DB, policy.AuthorizedQuery) (ExplainResult, error)
}

type FeatureAdapter interface {
	Features() []domain.AdapterFeature
}

type SchemaAdapter interface {
	ListObjects(context.Context, *sql.DB, string) ([]SchemaObject, error)
	DescribeObject(context.Context, *sql.DB, queryspec.ResourceRef) (ObjectDescription, error)
}

type SelectAdapter interface {
	Select(context.Context, *sql.DB, policy.AuthorizedQuery) (SelectResult, error)
}

type KeysetSelectAdapter interface {
	SelectKeyset(
		context.Context, *sql.DB, policy.AuthorizedKeysetSelect, KeysetEnvelopeBudget,
	) (KeysetSelectResult, error)
}

type AggregateAdapter interface {
	Aggregate(context.Context, *sql.DB, policy.AuthorizedAggregate, int) (AggregateResult, error)
}

type ObjectStatisticsAdapter interface {
	DescribeObjectStatistics(
		context.Context, *sql.DB, policy.AuthorizedObjectStatistics, int,
	) (ObjectStatisticsResult, error)
}

func (m *Manager) IdentifierSemantics(ctx context.Context, datasource string) (domain.IdentifierSemantics, error) {
	m.mu.RLock()
	source, ok := m.sources[datasource]
	m.mu.RUnlock()
	if !ok || source.adapter == nil || source.db == nil || source.initErr != nil {
		return domain.IdentifierSemantics{}, &Error{Kind: ErrorUnavailable}
	}
	return source.adapter.IdentifierSemantics(ctx, source.db)
}

type source struct {
	adapter      Adapter
	adapterName  string
	capabilities []domain.Operation
	features     []domain.AdapterFeature
	db           *sql.DB
	initErr      error
	required     bool
}

type Manager struct {
	mu      sync.RWMutex
	sources map[string]source
}

func NewManager(cfg config.Config, resolver secrets.Resolver, adapters ...Adapter) (*Manager, []error) {
	registry := make(map[string]Adapter, len(adapters))
	for _, adapter := range adapters {
		registry[adapter.Name()] = adapter
	}
	manager := &Manager{sources: make(map[string]source, len(cfg.Datasources))}
	var problems []error
	for name, datasource := range cfg.Datasources {
		adapter, ok := registry[datasource.Adapter]
		if !ok {
			problem := &ConfigurationError{Err: fmt.Errorf("datasource %q uses unknown adapter %q", name, datasource.Adapter)}
			manager.sources[name] = source{initErr: problem, required: datasource.RequiredForReadiness}
			problems = append(problems, problem)
			continue
		}
		capabilities, err := validateAdapterCapabilities(adapter)
		if err != nil {
			problem := &ConfigurationError{Err: fmt.Errorf(
				"datasource %q adapter %q contract is invalid: %w", name, datasource.Adapter, err,
			)}
			manager.sources[name] = source{
				adapter: adapter, adapterName: datasource.Adapter,
				initErr: problem, required: datasource.RequiredForReadiness,
			}
			problems = append(problems, problem)
			continue
		}
		features, err := validateAdapterFeatures(adapter)
		if err != nil {
			problem := &ConfigurationError{Err: fmt.Errorf(
				"datasource %q adapter %q feature contract is invalid: %w", name, datasource.Adapter, err,
			)}
			manager.sources[name] = source{
				adapter: adapter, adapterName: datasource.Adapter,
				capabilities: capabilities, initErr: problem,
				required: datasource.RequiredForReadiness,
			}
			problems = append(problems, problem)
			continue
		}
		dsn := datasource.DSN
		if dsn == "" {
			var err error
			dsn, err = resolver.Resolve(datasource.DSNSecretRef)
			if err != nil {
				problem := fmt.Errorf("datasource %q DSN is unavailable", name)
				manager.sources[name] = source{
					adapter: adapter, adapterName: datasource.Adapter,
					capabilities: capabilities, features: features, initErr: problem,
					required: datasource.RequiredForReadiness,
				}
				problems = append(problems, problem)
				continue
			}
		}
		db, err := adapter.Open(dsn, datasource)
		if err != nil {
			problem := &ConfigurationError{Err: fmt.Errorf("datasource %q configuration is invalid: %w", name, err)}
			manager.sources[name] = source{
				adapter: adapter, adapterName: datasource.Adapter,
				capabilities: capabilities, features: features, initErr: problem,
				required: datasource.RequiredForReadiness,
			}
			problems = append(problems, problem)
			continue
		}
		manager.sources[name] = source{
			adapter: adapter, adapterName: datasource.Adapter,
			capabilities: capabilities, features: features, db: db,
			required: datasource.RequiredForReadiness,
		}
	}
	return manager, problems
}

func validateAdapterFeatures(adapter Adapter) ([]domain.AdapterFeature, error) {
	provider, ok := adapter.(FeatureAdapter)
	if !ok {
		return nil, nil
	}
	features := slices.Clone(provider.Features())
	seen := make(map[domain.AdapterFeature]struct{}, len(features))
	for _, feature := range features {
		if !feature.Valid() {
			return nil, fmt.Errorf("advertises unknown feature %q", feature)
		}
		if _, duplicate := seen[feature]; duplicate {
			return nil, fmt.Errorf("advertises duplicate feature %q", feature)
		}
		seen[feature] = struct{}{}
	}
	return features, nil
}

func validateAdapterCapabilities(adapter Adapter) ([]domain.Operation, error) {
	capabilities := append([]domain.Operation(nil), adapter.Capabilities()...)
	_, hasSchemaAdapter := adapter.(SchemaAdapter)
	_, hasSelectAdapter := adapter.(SelectAdapter)
	_, hasKeysetSelectAdapter := adapter.(KeysetSelectAdapter)
	_, hasAggregateAdapter := adapter.(AggregateAdapter)
	_, hasObjectStatisticsAdapter := adapter.(ObjectStatisticsAdapter)
	seen := make(map[domain.Operation]struct{}, len(capabilities))
	for _, operation := range capabilities {
		if !operation.Valid() {
			return nil, fmt.Errorf("advertises unknown capability %q", operation)
		}
		if operation == domain.OperationListQueryShapes {
			return nil, fmt.Errorf("advertises core-owned capability %q", operation)
		}
		if _, duplicate := seen[operation]; duplicate {
			return nil, fmt.Errorf("advertises duplicate capability %q", operation)
		}
		seen[operation] = struct{}{}
		switch operation {
		case domain.OperationListObjects, domain.OperationDescribeObject:
			if !hasSchemaAdapter {
				return nil, fmt.Errorf("advertises %q without implementing SchemaAdapter", operation)
			}
		case domain.OperationSelect:
			if !hasSelectAdapter {
				return nil, fmt.Errorf("advertises %q without implementing SelectAdapter", operation)
			}
		case domain.OperationSelectKeyset:
			if !hasKeysetSelectAdapter {
				return nil, fmt.Errorf("advertises %q without implementing KeysetSelectAdapter", operation)
			}
		case domain.OperationAggregate:
			if !hasAggregateAdapter {
				return nil, fmt.Errorf("advertises %q without implementing AggregateAdapter", operation)
			}
		case domain.OperationDescribeObjectStatistics:
			if !hasObjectStatisticsAdapter {
				return nil, fmt.Errorf("advertises %q without implementing ObjectStatisticsAdapter", operation)
			}
		}
	}
	return capabilities, nil
}

func (m *Manager) DescribeObjectStatistics(
	ctx context.Context, authorized policy.AuthorizedObjectStatistics, envelopeBaseBytes int,
) (ObjectStatisticsResult, string, error) {
	if authorized.Operation() != domain.OperationDescribeObjectStatistics ||
		authorized.Schema() == "" || authorized.Object() == "" ||
		envelopeBaseBytes < 0 || envelopeBaseBytes > authorized.Limits().MaxResultBytes {
		return ObjectStatisticsResult{}, "", &Error{
			Kind: ErrorUpstream, Err: errors.New("invalid describe_object_statistics authorization"),
		}
	}
	source, err := m.availableSource(authorized.Datasource())
	if err != nil {
		return ObjectStatisticsResult{}, "", err
	}
	if source.adapterName != authorized.Adapter() {
		return ObjectStatisticsResult{}, source.adapterName, &Error{
			Kind: ErrorUpstream, Err: errors.New("authorization adapter mismatch"),
		}
	}
	if err := requireCapability(source, domain.OperationDescribeObjectStatistics); err != nil {
		return ObjectStatisticsResult{}, source.adapterName, err
	}
	adapter, ok := source.adapter.(ObjectStatisticsAdapter)
	if !ok {
		return ObjectStatisticsResult{}, source.adapterName, &Error{
			Kind: ErrorUpstream, Err: errors.New("adapter capability mismatch"),
		}
	}
	result, err := adapter.DescribeObjectStatistics(ctx, source.db, authorized, envelopeBaseBytes)
	return result, source.adapterName, err
}

func (m *Manager) Explain(ctx context.Context, query policy.AuthorizedQuery) (ExplainResult, string, error) {
	if query.Operation() != domain.OperationExplainSelect {
		return ExplainResult{}, "", invalidQueryAuthorization("explain_select")
	}
	source, err := m.availableSource(query.Datasource())
	if err != nil {
		return ExplainResult{}, "", err
	}
	if err := requireCapability(source, domain.OperationExplainSelect); err != nil {
		return ExplainResult{}, source.adapterName, err
	}
	result, err := source.adapter.Explain(ctx, source.db, query)
	return result, source.adapterName, err
}

func (m *Manager) ListObjects(
	ctx context.Context, authorized policy.AuthorizedSchema,
) ([]SchemaObject, string, error) {
	if authorized.Operation() != domain.OperationListObjects || authorized.Schema() == "" || authorized.Object() != "" {
		return nil, "", &Error{Kind: ErrorUpstream, Err: errors.New("invalid list_objects authorization")}
	}
	source, err := m.availableSource(authorized.Datasource())
	if err != nil {
		return nil, "", err
	}
	if err := requireCapability(source, domain.OperationListObjects); err != nil {
		return nil, source.adapterName, err
	}
	adapter, ok := source.adapter.(SchemaAdapter)
	if !ok {
		return nil, source.adapterName, &Error{Kind: ErrorUpstream, Err: errors.New("adapter capability mismatch")}
	}
	objects, err := adapter.ListObjects(ctx, source.db, authorized.Schema())
	if err != nil {
		return nil, source.adapterName, err
	}
	filtered := make([]SchemaObject, 0, len(objects))
	for _, object := range objects {
		if queryspec.IsIdentifier(object.Name) && authorized.AllowsObject(object.Name) {
			filtered = append(filtered, object)
		}
	}
	return filtered, source.adapterName, nil
}

func (m *Manager) DescribeObject(
	ctx context.Context, authorized policy.AuthorizedSchema,
) (ObjectDescription, string, error) {
	if authorized.Operation() != domain.OperationDescribeObject || authorized.Schema() == "" || authorized.Object() == "" {
		return ObjectDescription{}, "", &Error{Kind: ErrorUpstream, Err: errors.New("invalid describe_object authorization")}
	}
	source, err := m.availableSource(authorized.Datasource())
	if err != nil {
		return ObjectDescription{}, "", err
	}
	if err := requireCapability(source, domain.OperationDescribeObject); err != nil {
		return ObjectDescription{}, source.adapterName, err
	}
	adapter, ok := source.adapter.(SchemaAdapter)
	if !ok {
		return ObjectDescription{}, source.adapterName, &Error{Kind: ErrorUpstream, Err: errors.New("adapter capability mismatch")}
	}
	description, err := adapter.DescribeObject(ctx, source.db, queryspec.ResourceRef{
		Schema: authorized.Schema(), Name: authorized.Object(),
	})
	if err != nil {
		return ObjectDescription{}, source.adapterName, err
	}
	columns := make([]ColumnDescription, 0, len(description.Columns))
	for _, column := range description.Columns {
		if queryspec.IsIdentifier(column.Name) && authorized.AllowsField(column.Name) {
			columns = append(columns, column)
		}
	}
	description.Columns = columns
	return description, source.adapterName, nil
}

func (m *Manager) Select(ctx context.Context, query policy.AuthorizedQuery) (SelectResult, string, error) {
	if query.Operation() != domain.OperationSelect {
		return SelectResult{}, "", invalidQueryAuthorization("select")
	}
	source, err := m.availableSource(query.Datasource())
	if err != nil {
		return SelectResult{}, "", err
	}
	if err := requireCapability(source, domain.OperationSelect); err != nil {
		return SelectResult{}, source.adapterName, err
	}
	adapter, ok := source.adapter.(SelectAdapter)
	if !ok {
		return SelectResult{}, source.adapterName, &Error{Kind: ErrorUpstream, Err: errors.New("adapter capability mismatch")}
	}
	result, err := adapter.Select(ctx, source.db, query)
	return result, source.adapterName, err
}

func (m *Manager) SelectKeyset(
	ctx context.Context,
	query policy.AuthorizedKeysetSelect,
	budget KeysetEnvelopeBudget,
) (KeysetSelectResult, string, error) {
	if query.Operation() != domain.OperationSelectKeyset || query.Adapter() == "" ||
		budget.FinalBaseBytes < 0 || budget.MoreBaseBytes < 0 ||
		budget.FinalBaseBytes > query.Limits().MaxResultBytes ||
		budget.MoreBaseBytes > query.Limits().MaxResultBytes {
		return KeysetSelectResult{}, "", invalidQueryAuthorization("select_keyset")
	}
	source, err := m.availableSource(query.Datasource())
	if err != nil {
		return KeysetSelectResult{}, "", err
	}
	if source.adapterName != query.Adapter() {
		return KeysetSelectResult{}, source.adapterName, &Error{
			Kind: ErrorUpstream, Err: errors.New("authorization adapter mismatch"),
		}
	}
	if err := requireCapability(source, domain.OperationSelectKeyset); err != nil {
		return KeysetSelectResult{}, source.adapterName, err
	}
	adapter, ok := source.adapter.(KeysetSelectAdapter)
	if !ok {
		return KeysetSelectResult{}, source.adapterName, &Error{
			Kind: ErrorUpstream, Err: errors.New("adapter capability mismatch"),
		}
	}
	result, err := adapter.SelectKeyset(ctx, source.db, query, budget)
	return result, source.adapterName, err
}

func (m *Manager) Aggregate(
	ctx context.Context, query policy.AuthorizedAggregate, envelopeBaseBytes int,
) (AggregateResult, string, error) {
	if query.Operation() != domain.OperationAggregate || envelopeBaseBytes < 0 || envelopeBaseBytes > query.Limits().MaxResultBytes {
		return AggregateResult{}, "", invalidQueryAuthorization("aggregate")
	}
	source, err := m.availableSource(query.Datasource())
	if err != nil {
		return AggregateResult{}, "", err
	}
	if err := requireCapability(source, domain.OperationAggregate); err != nil {
		return AggregateResult{}, source.adapterName, err
	}
	adapter, ok := source.adapter.(AggregateAdapter)
	if !ok {
		return AggregateResult{}, source.adapterName, &Error{Kind: ErrorUpstream, Err: errors.New("adapter capability mismatch")}
	}
	result, err := adapter.Aggregate(ctx, source.db, query, envelopeBaseBytes)
	return result, source.adapterName, err
}

func invalidQueryAuthorization(operation string) *Error {
	return &Error{
		Kind: ErrorUpstream,
		Err:  fmt.Errorf("invalid %s authorization", operation),
	}
}

func (m *Manager) availableSource(datasource string) (source, error) {
	m.mu.RLock()
	source, ok := m.sources[datasource]
	m.mu.RUnlock()
	if !ok || source.initErr != nil || source.db == nil || source.adapter == nil {
		return source, &Error{Kind: ErrorUnavailable}
	}
	return source, nil
}

func requireCapability(source source, operation domain.Operation) error {
	if !slices.Contains(source.capabilities, operation) {
		return &Error{
			Kind: ErrorNotImplemented,
			Err:  fmt.Errorf("adapter does not advertise capability %q", operation),
		}
	}
	return nil
}

func (m *Manager) AdapterName(datasource string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	source, ok := m.sources[datasource]
	if !ok || source.adapter == nil {
		return ""
	}
	return source.adapterName
}

func (m *Manager) Capabilities(datasource string) []domain.Operation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	source, ok := m.sources[datasource]
	if !ok || source.adapter == nil {
		return nil
	}
	return append([]domain.Operation(nil), source.capabilities...)
}

func (m *Manager) Features(datasource string) []domain.AdapterFeature {
	m.mu.RLock()
	source, ok := m.sources[datasource]
	m.mu.RUnlock()
	if !ok || source.adapter == nil {
		return nil
	}
	return slices.Clone(source.features)
}

func (m *Manager) Ready(ctx context.Context) error {
	m.mu.RLock()
	sources := make([]source, 0, len(m.sources))
	for _, source := range m.sources {
		if source.required {
			sources = append(sources, source)
		}
	}
	m.mu.RUnlock()
	for _, source := range sources {
		if source.initErr != nil || source.db == nil {
			return &Error{Kind: ErrorUnavailable}
		}
		probeContext, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := source.adapter.Validate(probeContext, source.db)
		cancel()
		if err != nil {
			return &Error{Kind: ErrorUnavailable, Err: err}
		}
	}
	return nil
}

func (m *Manager) Close() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result error
	for _, source := range m.sources {
		if source.db != nil {
			result = errors.Join(result, source.db.Close())
		}
	}
	return result
}

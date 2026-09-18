package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/sigalx/quordon/internal/domain"
	"github.com/sigalx/quordon/internal/queryspec"
	"gopkg.in/yaml.v3"
)

var portableIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

const (
	redactedSecretMarker        = "__QUORDON_REDACTED__"
	maxSupportedDeadlineMS      = 5 * 60 * 1000
	maxSupportedRequestBytes    = 16 * 1024 * 1024
	maxSupportedPredicates      = 10_000
	maxSupportedExpressionDepth = 64
	maxSupportedParameters      = 10_000
	maxSupportedConcurrency     = 1024
	maxSupportedPoolConnections = 1024
	maxSupportedConnLifetimeSec = 24 * 60 * 60
	maxSupportedQueryShapes     = 1000
	maxPublicDescriptionRunes   = 512
)

type Config struct {
	Version        int                   `yaml:"version"`
	Server         ServerConfig          `yaml:"server"`
	HardLimits     domain.Limits         `yaml:"hard_limits"`
	Authentication Authentication        `yaml:"authentication"`
	Principals     map[string]Principal  `yaml:"principals"`
	Datasources    map[string]Datasource `yaml:"datasources"`
	Profiles       map[string]Profile    `yaml:"profiles"`
	PolicyHash     string                `yaml:"-" json:"-"`
}

type ServerConfig struct {
	Listen string `yaml:"listen"`
}

type Authentication struct {
	Basic BasicAuth `yaml:"basic"`
}

type BasicAuth struct {
	Realm string               `yaml:"realm"`
	Users map[string]BasicUser `yaml:"users"`
}

type BasicUser struct {
	Principal             string `yaml:"principal"`
	PasswordHash          string `yaml:"password_hash"`
	PasswordHashSecretRef string `yaml:"password_hash_secret_ref"`
}

type Principal struct {
	Profiles []string `yaml:"profiles"`
}

type Datasource struct {
	Adapter              string     `yaml:"adapter"`
	DSN                  string     `yaml:"dsn"`
	DSNSecretRef         string     `yaml:"dsn_secret_ref"`
	TLSRequired          *bool      `yaml:"tls_required"`
	RequiredForReadiness bool       `yaml:"required_for_readiness"`
	Pool                 PoolConfig `yaml:"pool"`
}

type PoolConfig struct {
	MaxOpenConnections           int `yaml:"max_open_connections"`
	MaxIdleConnections           int `yaml:"max_idle_connections"`
	MaxConnectionLifetimeSeconds int `yaml:"max_connection_lifetime_seconds"`
}

type Profile struct {
	Datasource string             `yaml:"datasource"`
	Operations []domain.Operation `yaml:"operations"`
	Resources  ResourcePolicy     `yaml:"resources"`
	Query      QueryPolicy        `yaml:"query"`
	Limits     domain.Limits      `yaml:"limits"`
}

type ResourcePolicy struct {
	Schemas PatternPolicy `yaml:"schemas"`
	Objects PatternPolicy `yaml:"objects"`
	Fields  PatternPolicy `yaml:"fields"`
}

type PatternPolicy struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

type QueryPolicy struct {
	AllowSourceText        bool                `yaml:"allow_source_text"`
	AllowFiltering         bool                `yaml:"allow_filtering"`
	AllowGroupBy           bool                `yaml:"allow_group_by"`
	AllowSorting           bool                `yaml:"allow_sorting"`
	AllowedFilterOperators []string            `yaml:"allowed_filter_operators"`
	AllowedAggregates      []string            `yaml:"allowed_aggregates"`
	AggregateShapes        []AggregateShape    `yaml:"aggregate_shapes"`
	KeysetSelectShapes     []KeysetSelectShape `yaml:"keyset_select_shapes"`
}

type KeysetSelectShape struct {
	Name                       string                  `yaml:"name"`
	PublicDescription          *string                 `yaml:"public_description"`
	Source                     AggregateShapeSource    `yaml:"source"`
	Projection                 []KeysetShapeProjection `yaml:"projection"`
	Filter                     *AggregateShapeFilter   `yaml:"filter"`
	OrderBy                    []KeysetShapeOrder      `yaml:"order_by"`
	MaximumLimit               int                     `yaml:"maximum_limit"`
	RequiredIndex              string                  `yaml:"required_index"`
	MaximumRowsExaminedPerScan uint64                  `yaml:"maximum_rows_examined_per_scan"`
	AllowTemporaryTable        *bool                   `yaml:"allow_temporary_table"`
	AllowFilesort              *bool                   `yaml:"allow_filesort"`
}

type KeysetShapeProjection struct {
	Representation queryspec.Representation `yaml:"representation"`
	Kind           string                   `yaml:"kind"`
	Field          string                   `yaml:"field"`
	Alias          string                   `yaml:"alias"`
}

type KeysetShapeOrder struct {
	Representation queryspec.Representation `yaml:"representation"`
	Field          string                   `yaml:"field"`
	Direction      string                   `yaml:"direction"`
}

type AggregateShape struct {
	Name                       string                 `yaml:"name"`
	PublicDescription          *string                `yaml:"public_description"`
	Mode                       string                 `yaml:"mode"`
	Source                     AggregateShapeSource   `yaml:"source"`
	Projection                 []AggregateShapeOutput `yaml:"projection"`
	Filter                     *AggregateShapeFilter  `yaml:"filter"`
	OrderBy                    []AggregateShapeOrder  `yaml:"order_by"`
	MaximumLimit               int                    `yaml:"maximum_limit"`
	RequiredIndex              string                 `yaml:"required_index"`
	MaximumRowsExaminedPerScan uint64                 `yaml:"maximum_rows_examined_per_scan"`
	AllowTemporaryTable        *bool                  `yaml:"allow_temporary_table"`
	AllowFilesort              *bool                  `yaml:"allow_filesort"`
}

type AggregateShapeSource struct {
	Schema string `yaml:"schema"`
	Name   string `yaml:"name"`
}

type AggregateShapeOutput struct {
	Representation queryspec.Representation `yaml:"representation"`
	Kind           string                   `yaml:"kind"`
	Field          string                   `yaml:"field"`
	Function       string                   `yaml:"function"`
	Alias          string                   `yaml:"alias"`
	Unit           string                   `yaml:"unit"`
	Timezone       string                   `yaml:"timezone"`
}

type AggregateShapeFilter struct {
	Representation queryspec.Representation `yaml:"representation"`
	Kind           string                   `yaml:"kind"`
	Field          string                   `yaml:"field"`
	Operator       string                   `yaml:"operator"`
	ValueTypes     *[]string                `yaml:"value_types"`
	Expressions    []AggregateShapeFilter   `yaml:"expressions"`
}

type AggregateShapeOrder struct {
	Representation queryspec.Representation `yaml:"representation"`
	Kind           string                   `yaml:"kind"`
	Field          string                   `yaml:"field"`
	Alias          string                   `yaml:"alias"`
	Direction      string                   `yaml:"direction"`
}

func Load(data []byte) (Config, error) {
	if err := validatePolicyYAMLValues(data); err != nil {
		return Config{}, fmt.Errorf("decode policy: %w", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode policy: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("decode policy: multiple YAML documents are not allowed")
		}
		return Config{}, fmt.Errorf("decode policy: %w", err)
	}
	if cfg.Authentication.Basic.Realm == "" {
		cfg.Authentication.Basic.Realm = "quordon"
	}
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = "127.0.0.1:8080"
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	fingerprint, err := policyFingerprint(cfg)
	if err != nil {
		return Config{}, fmt.Errorf("fingerprint policy: %w", err)
	}
	cfg.PolicyHash = fingerprint
	return cfg, nil
}

func validatePolicyYAMLValues(data []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return err
	}
	return validatePolicyYAMLNode(&document, "policy", make(map[*yaml.Node]struct{}))
}

func validatePolicyYAMLNode(node *yaml.Node, path string, active map[*yaml.Node]struct{}) error {
	if node == nil {
		return nil
	}
	if _, recursive := active[node]; recursive {
		return fmt.Errorf("%s contains a recursive YAML alias", path)
	}
	active[node] = struct{}{}
	defer delete(active, node)
	if strings.HasSuffix(path, ".query.allow_source_text") && node.Kind == yaml.ScalarNode && (node.Tag != "!!bool" || node.Value != "true" && node.Value != "false") {
		return fmt.Errorf("%s must be a YAML boolean", path)
	}
	if node.Tag == "!!null" {
		return fmt.Errorf("%s must not be null", path)
	}
	if isQueryShapeStringPolicyPath(path) && node.Kind == yaml.ScalarNode && node.Tag != "!!str" {
		return fmt.Errorf("%s must be a YAML string", path)
	}
	if isWithinQueryShapePolicyPath(path) && node.Kind == yaml.ScalarNode && node.Tag == "!!str" && node.Value == "" {
		return fmt.Errorf("%s must not be empty when present", path)
	}
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			if err := validatePolicyYAMLNode(child, path, active); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		aggregateShape := isAggregateShapePolicyPath(path)
		keysetShape := isKeysetShapePolicyPath(path)
		queryShape := aggregateShape || keysetShape
		aggregateMode := ""
		hasMaximumLimit := false
		hasAllowTemporaryTable := false
		hasAllowFilesort := false
		for index := 0; index+1 < len(node.Content); index += 2 {
			keyNode := node.Content[index]
			key := keyNode.Value
			value := node.Content[index+1]
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			if keyNode.Tag == "!!merge" || key == "<<" {
				return fmt.Errorf("%s must not use YAML merge keys", childPath)
			}
			if err := validatePolicyYAMLNode(value, childPath, active); err != nil {
				return err
			}
			if !queryShape {
				continue
			}
			switch key {
			case "mode":
				resolved, err := resolveYAMLAlias(value, childPath)
				if err != nil {
					return err
				}
				aggregateMode = resolved.Value
			case "maximum_limit":
				hasMaximumLimit = true
				resolved, err := resolveYAMLAlias(value, childPath)
				if err != nil {
					return err
				}
				if err := validateCanonicalYAMLUnsignedInteger(resolved, childPath, strconv.IntSize); err != nil {
					return err
				}
			case "maximum_rows_examined_per_scan":
				resolved, err := resolveYAMLAlias(value, childPath)
				if err != nil {
					return err
				}
				if err := validateCanonicalYAMLUnsignedInteger(resolved, childPath, 64); err != nil {
					return err
				}
			case "allow_temporary_table", "allow_filesort":
				resolved, err := resolveYAMLAlias(value, childPath)
				if err != nil {
					return err
				}
				if resolved.Kind != yaml.ScalarNode || resolved.Tag != "!!bool" ||
					(resolved.Value != "true" && resolved.Value != "false") {
					return fmt.Errorf("%s must be a YAML boolean", childPath)
				}
				if key == "allow_temporary_table" {
					hasAllowTemporaryTable = true
				} else {
					hasAllowFilesort = true
				}
			}
		}
		if aggregateShape && aggregateMode == queryspec.AggregateModeScalar && hasMaximumLimit {
			return fmt.Errorf("%s.maximum_limit must be omitted in scalar mode", path)
		}
		if aggregateShape {
			hasTimeBucket, err := aggregateShapeYAMLHasTimeBucket(node, path)
			if err != nil {
				return err
			}
			if hasTimeBucket && (!hasAllowTemporaryTable || !hasAllowFilesort) {
				return fmt.Errorf("%s time_bucket shape requires allow_temporary_table and allow_filesort", path)
			}
		}
	case yaml.SequenceNode:
		for index, child := range node.Content {
			if err := validatePolicyYAMLNode(child, fmt.Sprintf("%s[%d]", path, index), active); err != nil {
				return err
			}
		}
	case yaml.AliasNode:
		return validatePolicyYAMLNode(node.Alias, path, active)
	}
	return nil
}

func resolveYAMLAlias(node *yaml.Node, path string) (*yaml.Node, error) {
	seen := make(map[*yaml.Node]struct{})
	for node != nil && node.Kind == yaml.AliasNode {
		if _, duplicate := seen[node]; duplicate {
			return nil, fmt.Errorf("%s contains a recursive YAML alias", path)
		}
		seen[node] = struct{}{}
		node = node.Alias
	}
	if node == nil {
		return nil, fmt.Errorf("%s contains an unresolved YAML alias", path)
	}
	return node, nil
}

func isAggregateShapePolicyPath(path string) bool {
	indexEnd, within := aggregateShapePolicyPathIndexEnd(path)
	return within && indexEnd == len(path)-1
}

func isWithinAggregateShapePolicyPath(path string) bool {
	_, within := aggregateShapePolicyPathIndexEnd(path)
	return within
}

func isKeysetShapePolicyPath(path string) bool {
	indexEnd, within := keysetShapePolicyPathIndexEnd(path)
	return within && indexEnd == len(path)-1
}

func isWithinKeysetShapePolicyPath(path string) bool {
	_, within := keysetShapePolicyPathIndexEnd(path)
	return within
}

func isWithinQueryShapePolicyPath(path string) bool {
	return isWithinAggregateShapePolicyPath(path) || isWithinKeysetShapePolicyPath(path)
}

func isQueryShapeStringPolicyPath(path string) bool {
	if !isWithinQueryShapePolicyPath(path) {
		return false
	}
	segment := path
	if separator := strings.LastIndexByte(path, '.'); separator >= 0 {
		segment = path[separator+1:]
	}
	if strings.HasPrefix(segment, "value_types[") && strings.HasSuffix(segment, "]") {
		return true
	}
	switch segment {
	case "name", "public_description", "mode", "schema", "kind", "field", "function", "alias", "unit", "timezone", "operator", "direction", "required_index", "representation":
		return true
	default:
		return false
	}
}

func aggregateShapeYAMLHasTimeBucket(node *yaml.Node, path string) (bool, error) {
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value != "projection" {
			continue
		}
		projection, err := resolveYAMLAlias(node.Content[index+1], path+".projection")
		if err != nil {
			return false, err
		}
		if projection.Kind != yaml.SequenceNode {
			return false, nil
		}
		for outputIndex, rawOutput := range projection.Content {
			output, err := resolveYAMLAlias(rawOutput, fmt.Sprintf("%s.projection[%d]", path, outputIndex))
			if err != nil {
				return false, err
			}
			if output.Kind != yaml.MappingNode {
				continue
			}
			for member := 0; member+1 < len(output.Content); member += 2 {
				if output.Content[member].Value != "kind" {
					continue
				}
				kind, err := resolveYAMLAlias(
					output.Content[member+1], fmt.Sprintf("%s.projection[%d].kind", path, outputIndex),
				)
				if err != nil {
					return false, err
				}
				if kind.Kind == yaml.ScalarNode && kind.Tag == "!!str" && kind.Value == "time_bucket" {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func aggregateShapePolicyPathIndexEnd(path string) (int, bool) {
	return queryShapePolicyPathIndexEnd(path, ".query.aggregate_shapes[")
}

func keysetShapePolicyPathIndexEnd(path string) (int, bool) {
	return queryShapePolicyPathIndexEnd(path, ".query.keyset_select_shapes[")
}

func queryShapePolicyPathIndexEnd(path, marker string) (int, bool) {
	markerIndex := strings.LastIndex(path, marker)
	if markerIndex < 0 {
		return 0, false
	}
	indexStart := markerIndex + len(marker)
	relativeEnd := strings.IndexByte(path[indexStart:], ']')
	if relativeEnd <= 0 {
		return 0, false
	}
	indexEnd := indexStart + relativeEnd
	if _, err := strconv.ParseUint(path[indexStart:indexEnd], 10, 64); err != nil {
		return 0, false
	}
	if indexEnd+1 < len(path) && path[indexEnd+1] != '.' && path[indexEnd+1] != '[' {
		return 0, false
	}
	return indexEnd, true
}

func validateCanonicalYAMLUnsignedInteger(node *yaml.Node, path string, bitSize int) error {
	if node.Kind != yaml.ScalarNode || node.Style != 0 || !canonicalUnsignedDecimal(node.Value) {
		return fmt.Errorf("%s must be a canonical decimal integer", path)
	}
	if _, err := strconv.ParseUint(node.Value, 10, bitSize); err != nil {
		return fmt.Errorf("%s is outside the supported integer range", path)
	}
	if node.Tag != "!!int" {
		return fmt.Errorf("%s must be a canonical decimal integer", path)
	}
	return nil
}

func canonicalUnsignedDecimal(value string) bool {
	if value == "0" {
		return true
	}
	if value == "" || value[0] < '1' || value[0] > '9' {
		return false
	}
	for index := 1; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func policyFingerprint(cfg Config) (string, error) {
	redacted := cfg
	redacted.Authentication.Basic.Users = make(map[string]BasicUser, len(cfg.Authentication.Basic.Users))
	for username, user := range cfg.Authentication.Basic.Users {
		if user.PasswordHash != "" {
			user.PasswordHash = redactedSecretMarker
		}
		redacted.Authentication.Basic.Users[username] = user
	}
	redacted.Datasources = make(map[string]Datasource, len(cfg.Datasources))
	for name, datasource := range cfg.Datasources {
		if datasource.DSN != "" {
			datasource.DSN = redactedSecretMarker
		}
		redacted.Datasources[name] = datasource
	}
	canonical, err := json.Marshal(redacted)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(canonical)
	return hex.EncodeToString(hash[:]), nil
}

func (c Config) PolicyVersion() string {
	return strconv.Itoa(c.Version)
}

func ValidateListenAddress(address string) error {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("server.listen must be a host:port address")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("server.listen port must be between 1 and 65535")
	}
	return nil
}

func (c Config) Validate() error {
	if c.Version < 1 {
		return errors.New("policy version must be at least 1")
	}
	if err := ValidateListenAddress(c.Server.Listen); err != nil {
		return err
	}
	if err := validateLimits("hard_limits", c.HardLimits); err != nil {
		return err
	}
	if strings.TrimSpace(c.Authentication.Basic.Realm) == "" {
		return errors.New("authentication.basic.realm must not be empty")
	}
	if len(c.Authentication.Basic.Users) == 0 {
		return errors.New("authentication.basic.users must not be empty")
	}
	if len(c.Principals) == 0 {
		return errors.New("principals must not be empty")
	}
	if len(c.Datasources) == 0 {
		return errors.New("datasources must not be empty")
	}
	if len(c.Profiles) == 0 {
		return errors.New("profiles must not be empty")
	}

	for username, user := range c.Authentication.Basic.Users {
		if err := validateName("authentication.basic.users", username); err != nil {
			return err
		}
		if _, ok := c.Principals[user.Principal]; !ok {
			return fmt.Errorf("authentication.basic.users.%s references unknown principal", username)
		}
		hasInlineHash := user.PasswordHash != ""
		hasSecretRef := user.PasswordHashSecretRef != ""
		if hasInlineHash == hasSecretRef {
			return fmt.Errorf("authentication.basic.users.%s must define exactly one of password_hash or password_hash_secret_ref", username)
		}
		if hasSecretRef {
			if err := validateSecretRef(user.PasswordHashSecretRef); err != nil {
				return fmt.Errorf("authentication.basic.users.%s.password_hash_secret_ref: %w", username, err)
			}
		}
	}

	for name, principal := range c.Principals {
		if err := validateName("principals", name); err != nil {
			return err
		}
		if len(principal.Profiles) == 0 {
			return fmt.Errorf("principals.%s.profiles must not be empty", name)
		}
		if duplicates(principal.Profiles) {
			return fmt.Errorf("principals.%s.profiles contains duplicates", name)
		}
		for _, profile := range principal.Profiles {
			if _, ok := c.Profiles[profile]; !ok {
				return fmt.Errorf("principals.%s references unknown profile %q", name, profile)
			}
		}
	}

	for name, datasource := range c.Datasources {
		if err := validateName("datasources", name); err != nil {
			return err
		}
		if datasource.Adapter == "" {
			return fmt.Errorf("datasources.%s.adapter must not be empty", name)
		}
		if datasource.TLSRequired == nil {
			return fmt.Errorf("datasources.%s.tls_required must be set explicitly", name)
		}
		hasInlineDSN := datasource.DSN != ""
		hasSecretRef := datasource.DSNSecretRef != ""
		if hasInlineDSN == hasSecretRef {
			return fmt.Errorf("datasources.%s must define exactly one of dsn or dsn_secret_ref", name)
		}
		if hasSecretRef {
			if err := validateSecretRef(datasource.DSNSecretRef); err != nil {
				return fmt.Errorf("datasources.%s.dsn_secret_ref: %w", name, err)
			}
		}
		if datasource.Pool.MaxOpenConnections < 1 {
			return fmt.Errorf("datasources.%s.pool.max_open_connections must be at least 1", name)
		}
		if datasource.Pool.MaxOpenConnections > maxSupportedPoolConnections {
			return fmt.Errorf(
				"datasources.%s.pool.max_open_connections must not exceed %d",
				name, maxSupportedPoolConnections,
			)
		}
		if datasource.Pool.MaxIdleConnections < 0 || datasource.Pool.MaxIdleConnections > datasource.Pool.MaxOpenConnections {
			return fmt.Errorf("datasources.%s.pool.max_idle_connections must be between 0 and max_open_connections", name)
		}
		if datasource.Pool.MaxConnectionLifetimeSeconds < 1 {
			return fmt.Errorf("datasources.%s.pool.max_connection_lifetime_seconds must be at least 1", name)
		}
		if datasource.Pool.MaxConnectionLifetimeSeconds > maxSupportedConnLifetimeSec {
			return fmt.Errorf(
				"datasources.%s.pool.max_connection_lifetime_seconds must not exceed %d",
				name, maxSupportedConnLifetimeSec,
			)
		}
	}

	for name, profile := range c.Profiles {
		if err := validateName("profiles", name); err != nil {
			return err
		}
		if _, ok := c.Datasources[profile.Datasource]; !ok {
			return fmt.Errorf("profiles.%s references unknown datasource %q", name, profile.Datasource)
		}
		if len(profile.Operations) == 0 {
			return fmt.Errorf("profiles.%s.operations must not be empty", name)
		}
		seenOperations := make(map[domain.Operation]struct{}, len(profile.Operations))
		for _, operation := range profile.Operations {
			if !operation.Valid() {
				return fmt.Errorf("profiles.%s contains unsupported operation %q", name, operation)
			}
			if _, exists := seenOperations[operation]; exists {
				return fmt.Errorf("profiles.%s.operations contains duplicates", name)
			}
			seenOperations[operation] = struct{}{}
		}
		if len(profile.Resources.Schemas.Allow) == 0 {
			return fmt.Errorf("profiles.%s.resources.schemas.allow must not be empty", name)
		}
		if len(profile.Resources.Objects.Allow) == 0 {
			return fmt.Errorf("profiles.%s.resources.objects.allow must not be empty", name)
		}
		if err := validatePatterns(profile.Resources.Schemas, 1); err != nil {
			return fmt.Errorf("profiles.%s.resources.schemas: %w", name, err)
		}
		if err := validatePatterns(profile.Resources.Objects, 2); err != nil {
			return fmt.Errorf("profiles.%s.resources.objects: %w", name, err)
		}
		if err := validatePatterns(profile.Resources.Fields, 3); err != nil {
			return fmt.Errorf("profiles.%s.resources.fields: %w", name, err)
		}
		if err := validateQueryPolicy(name, profile.Query); err != nil {
			return err
		}
		if err := validateLimits("profiles."+name+".limits", profile.Limits); err != nil {
			return err
		}
		if profile.Limits != c.HardLimits.Min(profile.Limits) {
			return fmt.Errorf("profiles.%s.limits must not exceed hard_limits", name)
		}
		hasAggregateOperation := slices.Contains(profile.Operations, domain.OperationAggregate)
		hasKeysetOperation := slices.Contains(profile.Operations, domain.OperationSelectKeyset)
		hasListQueryShapesOperation := slices.Contains(profile.Operations, domain.OperationListQueryShapes)
		if hasAggregateOperation && len(profile.Query.AggregateShapes) == 0 {
			return fmt.Errorf("profiles.%s.query.aggregate_shapes must not be empty for aggregate operation", name)
		}
		if !hasAggregateOperation && len(profile.Query.AggregateShapes) != 0 {
			return fmt.Errorf("profiles.%s.query.aggregate_shapes requires aggregate operation", name)
		}
		if hasKeysetOperation && len(profile.Query.KeysetSelectShapes) == 0 {
			return fmt.Errorf("profiles.%s.query.keyset_select_shapes must not be empty for select_keyset operation", name)
		}
		if !hasKeysetOperation && len(profile.Query.KeysetSelectShapes) != 0 {
			return fmt.Errorf("profiles.%s.query.keyset_select_shapes requires select_keyset operation", name)
		}
		if hasListQueryShapesOperation && !hasAggregateOperation && !hasKeysetOperation {
			return fmt.Errorf("profiles.%s list_query_shapes operation requires aggregate or select_keyset operation", name)
		}
		if len(profile.Query.AggregateShapes)+len(profile.Query.KeysetSelectShapes) > maxSupportedQueryShapes {
			return fmt.Errorf("profiles.%s query shapes must not exceed %d entries", name, maxSupportedQueryShapes)
		}
		if err := validateAggregateShapes(name, profile.Query, profile.Limits); err != nil {
			return err
		}
		if err := validateKeysetSelectShapes(name, profile.Query, profile.Limits); err != nil {
			return err
		}
		if err := validateUniqueQueryShapeNames(name, profile.Query); err != nil {
			return err
		}
	}
	return nil
}

func validateLimits(path string, limits domain.Limits) error {
	values := []struct {
		name    string
		value   int
		minimum int
		maximum int
	}{
		{"deadline_ms", limits.DeadlineMS, 1, maxSupportedDeadlineMS},
		{"max_request_bytes", limits.MaxRequestBytes, 1, maxSupportedRequestBytes},
		{"max_projection_fields", limits.MaxProjectionFields, 1, queryspec.ProtocolMaxProjectionFields},
		{"max_group_by_fields", limits.MaxGroupByFields, 1, queryspec.ProtocolMaxGroupByFields},
		{"max_order_by_fields", limits.MaxOrderByFields, 1, queryspec.ProtocolMaxOrderByFields},
		{"max_predicates", limits.MaxPredicates, 1, maxSupportedPredicates},
		{"max_expression_depth", limits.MaxExpressionDepth, 1, maxSupportedExpressionDepth},
		{"max_parameters", limits.MaxParameters, 2, maxSupportedParameters},
		{"max_rows", limits.MaxRows, 1, queryspec.ProtocolMaxRows},
		{"max_result_bytes", limits.MaxResultBytes, 1, domain.MaxSupportedResultBytes},
		{"max_offset", limits.MaxOffset, 0, queryspec.ProtocolMaxOffset},
		{"max_concurrency", limits.MaxConcurrency, 1, maxSupportedConcurrency},
	}
	for _, item := range values {
		if item.value < item.minimum {
			return fmt.Errorf("%s.%s must be at least %d", path, item.name, item.minimum)
		}
		if item.value > item.maximum {
			return fmt.Errorf("%s.%s must not exceed %d", path, item.name, item.maximum)
		}
	}
	return nil
}

func validateQueryPolicy(profile string, policy QueryPolicy) error {
	if err := validateSourceTextShapes(profile, policy); err != nil {
		return err
	}
	validOperators := []string{"eq", "ne", "lt", "lte", "gt", "gte", "in", "not_in", "like", "is_null", "is_not_null"}
	validAggregates := []string{"count", "count_distinct", "min", "max", "sum", "avg"}
	if duplicates(policy.AllowedFilterOperators) || duplicates(policy.AllowedAggregates) {
		return fmt.Errorf("profiles.%s.query allowlists contain duplicates", profile)
	}
	for _, operator := range policy.AllowedFilterOperators {
		if !slices.Contains(validOperators, operator) {
			return fmt.Errorf("profiles.%s.query contains unsupported filter operator %q", profile, operator)
		}
	}
	for _, aggregate := range policy.AllowedAggregates {
		if !slices.Contains(validAggregates, aggregate) {
			return fmt.Errorf("profiles.%s.query contains unsupported aggregate %q", profile, aggregate)
		}
	}
	return nil
}

func validateAggregateShapes(profile string, policy QueryPolicy, limits domain.Limits) error {
	seenNames := make(map[string]struct{}, len(policy.AggregateShapes))
	type shapeIdentity struct {
		index int
		name  string
	}
	seenSignatures := make(map[[sha256.Size]byte]shapeIdentity, len(policy.AggregateShapes))
	for index, shape := range policy.AggregateShapes {
		path := fmt.Sprintf("profiles.%s.query.aggregate_shapes[%d]", profile, index)
		if !validPortableIdentifier(shape.Name) {
			return fmt.Errorf("%s.name must be a portable identifier", path)
		}
		if shape.PublicDescription != nil && !validPublicDescription(*shape.PublicDescription) {
			return fmt.Errorf("%s.public_description must contain 1 to %d non-control Unicode code points", path, maxPublicDescriptionRunes)
		}
		if _, duplicate := seenNames[shape.Name]; duplicate {
			return fmt.Errorf("profiles.%s.query.aggregate_shapes contains duplicate name %q", profile, shape.Name)
		}
		seenNames[shape.Name] = struct{}{}
		if shape.Mode != queryspec.AggregateModeScalar && shape.Mode != queryspec.AggregateModeGrouped {
			return fmt.Errorf("%s.mode must be scalar or grouped", path)
		}
		if !validPortableIdentifier(shape.Source.Schema) || !validPortableIdentifier(shape.Source.Name) {
			return fmt.Errorf("%s.source must contain portable schema and object identifiers", path)
		}
		if len(shape.Projection) == 0 || len(shape.Projection) > limits.MaxProjectionFields {
			return fmt.Errorf("%s.projection must contain between 1 and %d outputs", path, limits.MaxProjectionFields)
		}
		dimensions := 0
		measures := 0
		outputNames := make(map[string]struct{}, len(shape.Projection))
		dimensionFields := make(map[string]queryspec.Representation)
		measureAliases := make(map[string]struct{})
		timeBucketAliases := make(map[string]struct{})
		timeBucketFields := make(map[string]struct{})
		for outputIndex, output := range shape.Projection {
			outputPath := fmt.Sprintf("%s.projection[%d]", path, outputIndex)
			outputName := ""
			switch output.Kind {
			case "dimension":
				dimensions++
				if shape.Mode != queryspec.AggregateModeGrouped || !validPortableIdentifier(output.Field) ||
					output.Function != "" || output.Alias != "" || output.Unit != "" || output.Timezone != "" {
					return fmt.Errorf("%s must be a grouped dimension with only field", outputPath)
				}
				outputName = strings.ToLower(output.Field)
				dimensionFields[outputName] = output.Representation
			case "time_bucket":
				dimensions++
				if shape.Mode != queryspec.AggregateModeGrouped || !validPortableIdentifier(output.Field) ||
					!validPortableIdentifier(output.Alias) || output.Function != "" ||
					!slices.Contains([]string{"hour", "day", "week", "month"}, output.Unit) || output.Timezone != "UTC" {
					return fmt.Errorf("%s must contain a valid grouped UTC time bucket", outputPath)
				}
				fieldKey := strings.ToLower(output.Field)
				if _, duplicate := timeBucketFields[fieldKey]; duplicate {
					return fmt.Errorf("%s.projection contains repeated time-bucket source fields", path)
				}
				timeBucketFields[fieldKey] = struct{}{}
				outputName = strings.ToLower(output.Alias)
				timeBucketAliases[outputName] = struct{}{}
			case "measure":
				measures++
				if !validPortableIdentifier(output.Alias) || output.Unit != "" || output.Timezone != "" {
					return fmt.Errorf("%s.alias must be a portable identifier", outputPath)
				}
				outputName = strings.ToLower(output.Alias)
				measureAliases[outputName] = struct{}{}
				policyFunction := output.Function
				if policyFunction == "count_all" {
					policyFunction = "count"
					if output.Field != "" {
						return fmt.Errorf("%s count_all must not contain field", outputPath)
					}
				} else if !validPortableIdentifier(output.Field) {
					return fmt.Errorf("%s.field must be a portable identifier", outputPath)
				}
				if !slices.Contains([]string{"count", "count_distinct", "min", "max", "sum", "avg"}, policyFunction) ||
					!slices.Contains(policy.AllowedAggregates, policyFunction) {
					return fmt.Errorf("%s.function is not enabled by allowed_aggregates", outputPath)
				}
			default:
				return fmt.Errorf("%s.kind must be dimension, time_bucket, or measure", outputPath)
			}
			if _, duplicate := outputNames[outputName]; duplicate {
				return fmt.Errorf("%s.projection contains colliding output names", path)
			}
			outputNames[outputName] = struct{}{}
		}
		if len(timeBucketAliases) != 0 && (shape.AllowTemporaryTable == nil || shape.AllowFilesort == nil) {
			return fmt.Errorf("%s time_bucket shape requires allow_temporary_table and allow_filesort", path)
		}
		if shape.Mode == queryspec.AggregateModeScalar {
			if dimensions != 0 || shape.OrderBy != nil || shape.MaximumLimit != 0 {
				return fmt.Errorf("%s scalar shape must not contain dimensions, order_by, or maximum_limit", path)
			}
		} else if dimensions == 0 || measures == 0 || shape.MaximumLimit < 1 || shape.MaximumLimit > limits.MaxRows {
			return fmt.Errorf("%s grouped shape requires dimensions, measures, and maximum_limit within profile max_rows", path)
		}
		if dimensions > limits.MaxGroupByFields {
			return fmt.Errorf("%s.projection exceeds the effective group-by limit", path)
		}
		if shape.Mode == queryspec.AggregateModeGrouped && !policy.AllowGroupBy {
			return fmt.Errorf("%s requires allow_group_by", path)
		}
		if len(shape.OrderBy) != 0 && !policy.AllowSorting {
			return fmt.Errorf("%s.order_by requires allow_sorting", path)
		}
		if shape.OrderBy != nil && len(shape.OrderBy) == 0 {
			return fmt.Errorf("%s.order_by must not be empty when present", path)
		}
		if len(shape.OrderBy) > limits.MaxOrderByFields {
			return fmt.Errorf("%s.order_by exceeds the effective order limit", path)
		}
		seenOrderTargets := make(map[string]struct{}, len(shape.OrderBy))
		for orderIndex, order := range shape.OrderBy {
			orderPath := fmt.Sprintf("%s.order_by[%d]", path, orderIndex)
			if order.Direction != "asc" && order.Direction != "desc" {
				return fmt.Errorf("%s.direction must be asc or desc", orderPath)
			}
			target := ""
			if order.Kind == "dimension" {
				if !validPortableIdentifier(order.Field) || order.Alias != "" {
					return fmt.Errorf("%s dimension order requires only field", orderPath)
				}
				target = "dimension:" + strings.ToLower(order.Field)
				if representation, projected := dimensionFields[strings.ToLower(order.Field)]; !projected || representation != order.Representation {
					return fmt.Errorf("%s.field must reference a projected dimension", orderPath)
				}
			} else if order.Kind == "measure" {
				if !validPortableIdentifier(order.Alias) || order.Field != "" {
					return fmt.Errorf("%s measure order requires only alias", orderPath)
				}
				target = "measure:" + strings.ToLower(order.Alias)
				if _, projected := measureAliases[strings.ToLower(order.Alias)]; !projected {
					return fmt.Errorf("%s.alias must reference a projected measure", orderPath)
				}
			} else if order.Kind == "time_bucket" {
				if !validPortableIdentifier(order.Alias) || order.Field != "" {
					return fmt.Errorf("%s time_bucket order requires only alias", orderPath)
				}
				target = "time_bucket:" + strings.ToLower(order.Alias)
				if _, projected := timeBucketAliases[strings.ToLower(order.Alias)]; !projected {
					return fmt.Errorf("%s.alias must reference a projected time bucket", orderPath)
				}
			} else {
				return fmt.Errorf("%s.kind must be dimension, time_bucket, or measure", orderPath)
			}
			if _, duplicate := seenOrderTargets[target]; duplicate {
				return fmt.Errorf("%s.order_by contains repeated normalized targets", path)
			}
			seenOrderTargets[target] = struct{}{}
		}
		stats := aggregateShapeStats{}
		if shape.Mode == queryspec.AggregateModeGrouped {
			stats.parameters = 1
		}
		if shape.Filter != nil {
			if !policy.AllowFiltering {
				return fmt.Errorf("%s.filter requires allow_filtering", path)
			}
			if err := validateAggregateShapeFilter(path+".filter", *shape.Filter, 1, limits, policy.AllowedFilterOperators, &stats); err != nil {
				return err
			}
		}
		if shape.RequiredIndex != "" && !validPortableIdentifier(shape.RequiredIndex) {
			return fmt.Errorf("%s.required_index must be a portable identifier", path)
		}
		if shape.MaximumRowsExaminedPerScan == 0 {
			return fmt.Errorf("%s.maximum_rows_examined_per_scan must be positive", path)
		}
		signature := canonicalAggregateRequestSignature(shape)
		if previous, overlap := seenSignatures[signature]; overlap {
			return fmt.Errorf(
				"%s overlaps aggregate shape %q at index %d",
				path, previous.name, previous.index,
			)
		}
		seenSignatures[signature] = shapeIdentity{index: index, name: shape.Name}
	}
	return nil
}

func validPortableIdentifier(value string) bool {
	return len(value) <= queryspec.ProtocolMaxIdentifierBytes && portableIdentifier.MatchString(value)
}

func validPublicDescription(value string) bool {
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxPublicDescriptionRunes {
		return false
	}
	for _, character := range value {
		if character <= 0x1f || character >= 0x7f && character <= 0x9f {
			return false
		}
	}
	return true
}

type aggregateShapeStats struct {
	predicates int
	parameters int
}

func validateAggregateShapeFilter(
	path string, filter AggregateShapeFilter, depth int, limits domain.Limits,
	allowedOperators []string, stats *aggregateShapeStats,
) error {
	if depth > limits.MaxExpressionDepth {
		return fmt.Errorf("%s exceeds the effective expression depth limit", path)
	}
	if filter.Kind == "predicate" {
		if !validPortableIdentifier(filter.Field) || filter.Expressions != nil || filter.ValueTypes == nil {
			return fmt.Errorf("%s predicate requires field and value_types and forbids expressions", path)
		}
		expected := 1
		switch filter.Operator {
		case "eq", "ne", "lt", "lte", "gt", "gte", "like":
		case "in", "not_in":
			expected = -1
		case "is_null", "is_not_null":
			expected = 0
		default:
			return fmt.Errorf("%s.operator is unsupported", path)
		}
		if !slices.Contains(allowedOperators, filter.Operator) {
			return fmt.Errorf("%s.operator is not enabled by allowed_filter_operators", path)
		}
		if expected >= 0 && len(*filter.ValueTypes) != expected || expected == -1 && len(*filter.ValueTypes) == 0 {
			return fmt.Errorf("%s.value_types has invalid arity", path)
		}
		if len(*filter.ValueTypes) > queryspec.ProtocolMaxFilterItems {
			return fmt.Errorf("%s.value_types exceeds the protocol filter item limit", path)
		}
		for _, valueType := range *filter.ValueTypes {
			if !slices.Contains([]string{"boolean", "integer", "decimal", "string", "uuid", "date", "datetime", "bytes"}, valueType) {
				return fmt.Errorf("%s.value_types contains unsupported type %q", path, valueType)
			}
		}
		stats.predicates++
		stats.parameters += len(*filter.ValueTypes)
		if stats.predicates > limits.MaxPredicates || stats.parameters > limits.MaxParameters {
			return fmt.Errorf("%s exceeds effective predicate or parameter limits", path)
		}
		return nil
	}
	if filter.Kind != "group" || filter.Field != "" || filter.ValueTypes != nil ||
		(filter.Operator != "and" && filter.Operator != "or") || len(filter.Expressions) < 2 ||
		len(filter.Expressions) > queryspec.ProtocolMaxFilterItems {
		return fmt.Errorf("%s group has an invalid shape", path)
	}
	seenExpressions := make(map[aggregateShapeFilterDigest]struct{}, len(filter.Expressions))
	for index, child := range filter.Expressions {
		if err := validateAggregateShapeFilter(
			fmt.Sprintf("%s.expressions[%d]", path, index), child, depth+1, limits, allowedOperators, stats,
		); err != nil {
			return err
		}
		key := canonicalAggregateShapeFilter(child)
		if _, duplicate := seenExpressions[key]; duplicate {
			return fmt.Errorf("%s.expressions contains duplicate normalized shapes", path)
		}
		seenExpressions[key] = struct{}{}
	}
	return nil
}

type aggregateShapeFilterDigest [sha256.Size]byte

func canonicalAggregateRequestSignature(shape AggregateShape) [sha256.Size]byte {
	type canonicalOutput struct {
		Representation queryspec.Representation `json:"representation,omitempty"`
		Kind           string                   `json:"kind"`
		Field          string                   `json:"field,omitempty"`
		Function       string                   `json:"function,omitempty"`
		Alias          string                   `json:"alias,omitempty"`
		Unit           string                   `json:"unit,omitempty"`
		Timezone       string                   `json:"timezone,omitempty"`
	}
	type canonicalOrder struct {
		Representation queryspec.Representation `json:"representation,omitempty"`
		Kind           string                   `json:"kind"`
		Field          string                   `json:"field,omitempty"`
		Alias          string                   `json:"alias,omitempty"`
		Direction      string                   `json:"direction"`
	}
	type canonicalSignature struct {
		Mode       string                      `json:"mode"`
		Schema     string                      `json:"schema"`
		Object     string                      `json:"object"`
		Projection []canonicalOutput           `json:"projection"`
		Filter     *aggregateShapeFilterDigest `json:"filter,omitempty"`
		OrderBy    []canonicalOrder            `json:"order_by,omitempty"`
	}
	value := canonicalSignature{
		Mode: shape.Mode, Schema: strings.ToLower(shape.Source.Schema), Object: strings.ToLower(shape.Source.Name),
		Projection: make([]canonicalOutput, len(shape.Projection)),
		OrderBy:    make([]canonicalOrder, len(shape.OrderBy)),
	}
	for index, output := range shape.Projection {
		value.Projection[index] = canonicalOutput{
			Representation: output.Representation, Kind: output.Kind, Field: strings.ToLower(output.Field), Function: output.Function,
			Alias: strings.ToLower(output.Alias), Unit: output.Unit, Timezone: output.Timezone,
		}
	}
	if shape.Filter != nil {
		digest := canonicalAggregateShapeFilter(*shape.Filter)
		value.Filter = &digest
	}
	for index, order := range shape.OrderBy {
		value.OrderBy[index] = canonicalOrder{
			Representation: order.Representation, Kind: order.Kind, Field: strings.ToLower(order.Field), Alias: strings.ToLower(order.Alias),
			Direction: order.Direction,
		}
	}
	if shape.OrderBy == nil {
		value.OrderBy = nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		panic("config: marshal aggregate request signature: " + err.Error())
	}
	return sha256.Sum256(encoded)
}

func canonicalAggregateShapeFilter(filter AggregateShapeFilter) aggregateShapeFilterDigest {
	type canonicalFilter struct {
		Representation queryspec.Representation     `json:"representation,omitempty"`
		Kind           string                       `json:"kind"`
		Field          string                       `json:"field,omitempty"`
		Operator       string                       `json:"operator"`
		ValueTypes     []string                     `json:"value_types,omitempty"`
		Expressions    []aggregateShapeFilterDigest `json:"expressions,omitempty"`
	}
	value := canonicalFilter{
		Representation: filter.Representation, Kind: filter.Kind, Field: strings.ToLower(filter.Field), Operator: filter.Operator,
	}
	if filter.ValueTypes != nil {
		value.ValueTypes = slices.Clone(*filter.ValueTypes)
	}
	if len(filter.Expressions) != 0 {
		value.Expressions = make([]aggregateShapeFilterDigest, len(filter.Expressions))
		for index, child := range filter.Expressions {
			value.Expressions[index] = canonicalAggregateShapeFilter(child)
		}
		slices.SortFunc(value.Expressions, func(a, b aggregateShapeFilterDigest) int {
			return bytes.Compare(a[:], b[:])
		})
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		panic("config: marshal aggregate shape filter: " + err.Error())
	}
	return sha256.Sum256(encoded)
}

func validatePatterns(policy PatternPolicy, segments int) error {
	for _, pattern := range append(append([]string(nil), policy.Allow...), policy.Deny...) {
		parts := strings.Split(pattern, ".")
		if len(parts) != segments {
			return fmt.Errorf("pattern %q must contain %d segments", pattern, segments)
		}
		for _, part := range parts {
			if part != "*" && !validPortableIdentifier(part) {
				return fmt.Errorf("pattern %q contains an invalid segment", pattern)
			}
		}
	}
	return nil
}

func validateName(section, name string) error {
	if !portableIdentifier.MatchString(strings.ReplaceAll(name, "-", "_")) {
		return fmt.Errorf("%s contains invalid name %q", section, name)
	}
	return nil
}

func validateSecretRef(ref string) error {
	scheme, value, ok := strings.Cut(ref, ":")
	if !ok || value == "" {
		return errors.New("must use env:NAME or file:/absolute/path")
	}
	switch scheme {
	case "env":
		if !portableIdentifier.MatchString(value) {
			return errors.New("environment variable name is invalid")
		}
	case "file":
		if !strings.HasPrefix(value, "/") {
			return errors.New("file secret path must be absolute")
		}
	default:
		return errors.New("unsupported secret reference scheme")
	}
	return nil
}

func duplicates[T comparable](values []T) bool {
	seen := make(map[T]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

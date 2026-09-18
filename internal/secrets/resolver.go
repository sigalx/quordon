package secrets

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

type Resolver interface {
	Resolve(reference string) (string, error)
}

type EnvironmentAndFile struct{}

func (EnvironmentAndFile) Resolve(reference string) (string, error) {
	scheme, value, ok := strings.Cut(reference, ":")
	if !ok || value == "" {
		return "", errors.New("invalid secret reference")
	}
	var secret string
	switch scheme {
	case "env":
		resolved, exists := os.LookupEnv(value)
		if !exists {
			return "", fmt.Errorf("environment secret is unavailable")
		}
		secret = resolved
	case "file":
		content, err := os.ReadFile(value)
		if err != nil {
			return "", fmt.Errorf("file secret is unavailable")
		}
		secret = string(content)
	default:
		return "", errors.New("unsupported secret reference scheme")
	}
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return "", errors.New("secret is empty")
	}
	return secret, nil
}

type Map map[string]string

func (m Map) Resolve(reference string) (string, error) {
	value, ok := m[reference]
	if !ok || value == "" {
		return "", errors.New("secret is unavailable")
	}
	return value, nil
}

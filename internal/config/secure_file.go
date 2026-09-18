package config

import (
	"errors"
	"fmt"
	"io"
	"os"
)

const RequiredFileMode os.FileMode = 0o600

func ReadSecureFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open configuration: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect configuration: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("configuration must be a regular file")
	}
	if permissions := info.Mode().Perm(); permissions != RequiredFileMode {
		return nil, fmt.Errorf("configuration permissions must be 0600, got %04o", permissions)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}
	return data, nil
}

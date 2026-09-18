package config

import (
	"errors"
	"io"
	"os"
)

const RequiredFileMode os.FileMode = 0o600

func ReadSecureFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open configuration")
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, errors.New("cannot inspect configuration")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("configuration must be a regular file")
	}
	if info.Mode() != RequiredFileMode {
		return nil, errors.New("configuration permissions must be 0600")
	}
	if info.Size() > maxPolicyFileBytes {
		return nil, errors.New("configuration file size limit exceeded")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPolicyFileBytes))
	if err != nil {
		return nil, errors.New("cannot read configuration")
	}
	if len(data) == maxPolicyFileBytes {
		after, err := file.Stat()
		if err != nil {
			return nil, errors.New("cannot inspect configuration")
		}
		if after.Size() > maxPolicyFileBytes {
			return nil, errors.New("configuration file size limit exceeded")
		}
	}
	return data, nil
}

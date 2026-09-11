package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadSecureFileAcceptsMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	want := []byte("version: 1\n")
	if err := os.WriteFile(path, want, RequiredFileMode); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSecureFile(path)
	if err != nil {
		t.Fatalf("ReadSecureFile() error = %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("content = %q, want %q", got, want)
	}
}

func TestReadSecureFileRejectsAnyOtherMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o400, 0o600 | 0o040, 0o640, 0o644, 0o660} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.yaml")
			if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			_, err := ReadSecureFile(path)
			if err == nil || !strings.Contains(err.Error(), "permissions must be 0600") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestReadSecureFileRejectsDirectory(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, RequiredFileMode); err != nil {
		t.Fatal(err)
	}
	_, err := ReadSecureFile(path)
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("error = %v", err)
	}
}

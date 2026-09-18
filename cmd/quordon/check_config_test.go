package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigalx/quordon/internal/config"
)

func TestCheckConfigHasNoRuntimeDependencies(t *testing.T) {
	data, err := os.ReadFile("../../config/policy.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	base := filepath.Join(dir, "base.yaml")
	// These secrets do not exist; validation must not try to resolve them or
	// initialize an adapter, open a connection or start an HTTP listener.
	if err := os.WriteFile(base, data, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("$ref: './base.yaml'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	calls := 0
	start := func(config.Config, string, *slog.Logger) int { calls++; return 99 }
	if code := runWithArguments([]string{"--check-config", "--config", path}, &stdout, &stderr, start); code != 0 || calls != 0 {
		t.Fatalf("exit=%d, starts=%d, error=%s", code, calls, stderr.String())
	}
	if !strings.Contains(stdout.String(), "readiness not checked") {
		t.Fatal("check-config implies readiness")
	}
	if code := runWithArguments([]string{"--config", path}, &stdout, &stderr, start); code != 99 || calls != 1 {
		t.Fatalf("normal startup exit=%d, starts=%d", code, calls)
	}
	if err := os.WriteFile(path, []byte("$ref: 'https://opaque-secret.invalid/policy'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--config", path}, {"--check-config", "--config", path}} {
		if code := runWithArguments(args, &stdout, &stderr, start); code != 1 || calls != 1 {
			t.Fatalf("rejected config exit=%d, starts=%d", code, calls)
		}
	}
	if strings.Contains(stderr.String(), "opaque-secret") {
		t.Fatal("diagnostic leaked a value")
	}
}

func TestCheckConfigArgumentExitCodes(t *testing.T) {
	for _, args := range [][]string{
		{"--check-config", "--version"}, {"--version", "--check-config"}, {"-v", "--check-config"},
		{"--check-config", "positional"}, {"--unknown=opaque-secret"}, {"--check-config=opaque-secret"},
		{"-check-config"}, {"--config"},
	} {
		var stdout, stderr bytes.Buffer
		calls := 0
		start := func(config.Config, string, *slog.Logger) int { calls++; return 99 }
		if code := runWithArguments(args, &stdout, &stderr, start); code != 2 || calls != 0 {
			t.Fatalf("args=%v, exit=%d, starts=%d", args, code, calls)
		}
		if strings.Contains(stderr.String(), "opaque-secret") {
			t.Fatal("argument error leaked a value")
		}
	}
}

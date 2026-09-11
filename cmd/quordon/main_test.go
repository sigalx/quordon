package main

import (
	"context"
	"net/http"
	"testing"
	"time"
)

type blockingShutdownServer struct {
	shutdownStarted chan struct{}
	listenReturned  chan struct{}
	releaseShutdown chan struct{}
}

func (s *blockingShutdownServer) ListenAndServe() error {
	<-s.shutdownStarted
	close(s.listenReturned)
	return http.ErrServerClosed
}

func (s *blockingShutdownServer) Shutdown(ctx context.Context) error {
	close(s.shutdownStarted)
	select {
	case <-s.releaseShutdown:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (*blockingShutdownServer) Close() error { return nil }

func TestValidateFlagStyle(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		wantError bool
	}{
		{name: "long option", arguments: []string{"--listen", "127.0.0.1:8085"}},
		{name: "long option with value", arguments: []string{"--listen=127.0.0.1:8085"}},
		{name: "short option", arguments: []string{"-l", "127.0.0.1:8085"}},
		{name: "short option with value", arguments: []string{"-l=127.0.0.1:8085"}},
		{name: "old single-dash long option", arguments: []string{"-listen", "127.0.0.1:8085"}, wantError: true},
		{name: "arguments after separator", arguments: []string{"--", "-listen"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateFlagStyle(test.arguments)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError = %v", err, test.wantError)
			}
		})
	}
}

func TestValidateNoPositionalArguments(t *testing.T) {
	if err := validateNoPositionalArguments(nil); err != nil {
		t.Fatalf("empty arguments error = %v", err)
	}
	if err := validateNoPositionalArguments([]string{"accidental", "--version"}); err == nil {
		t.Fatal("expected positional arguments to be rejected")
	}
}

func TestEffectiveListenAddressValidatesOverrides(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		override   string
		want       string
		wantError  bool
	}{
		{name: "configured address", configured: "127.0.0.1:8085", want: "127.0.0.1:8085"},
		{name: "valid override", configured: "127.0.0.1:8085", override: "0.0.0.0:9090", want: "0.0.0.0:9090"},
		{name: "ephemeral port", configured: "127.0.0.1:8085", override: ":0", wantError: true},
		{name: "missing port", configured: "127.0.0.1:8085", override: "127.0.0.1", wantError: true},
		{name: "port overflow", configured: "127.0.0.1:8085", override: "127.0.0.1:65536", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := effectiveListenAddress(test.configured, test.override)
			if (err != nil) != test.wantError {
				t.Fatalf("effectiveListenAddress() error = %v, wantError = %v", err, test.wantError)
			}
			if got != test.want {
				t.Fatalf("effectiveListenAddress() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestHTTPWriteTimeoutIncludesBodyReadAndQueryDeadline(t *testing.T) {
	readTimeout := 15 * time.Second
	deadline := 30 * time.Second
	want := readTimeout + deadline + httpResponseGracePeriod
	if got := httpWriteTimeout(readTimeout, deadline); got != want {
		t.Fatalf("httpWriteTimeout() = %s, want %s", got, want)
	}
}

func TestHTTPWriteTimeoutSaturatesOnOverflow(t *testing.T) {
	const maxDuration = time.Duration(1<<63 - 1)
	if got := httpWriteTimeout(maxDuration, time.Second); got != maxDuration {
		t.Fatalf("httpWriteTimeout() = %s, want maximum duration", got)
	}
}

func TestServeWaitsForGracefulShutdown(t *testing.T) {
	server := &blockingShutdownServer{
		shutdownStarted: make(chan struct{}),
		listenReturned:  make(chan struct{}),
		releaseShutdown: make(chan struct{}),
	}
	shutdownSignal := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- serveUntilShutdown(server, shutdownSignal, time.Second)
	}()

	close(shutdownSignal)
	<-server.listenReturned
	select {
	case err := <-result:
		t.Fatalf("serveUntilShutdown returned before Shutdown completed: %v", err)
	default:
	}
	close(server.releaseShutdown)
	if err := <-result; err != nil {
		t.Fatalf("serveUntilShutdown() error = %v", err)
	}
}

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sigalx/quordon/internal/adapters/mysql8"
	"github.com/sigalx/quordon/internal/audit"
	"github.com/sigalx/quordon/internal/auth"
	"github.com/sigalx/quordon/internal/config"
	"github.com/sigalx/quordon/internal/database"
	"github.com/sigalx/quordon/internal/httpapi"
	"github.com/sigalx/quordon/internal/policy"
	"github.com/sigalx/quordon/internal/queryservice"
	"github.com/sigalx/quordon/internal/secrets"
)

var version = "dev"

const (
	httpReadTimeout         = 15 * time.Second
	httpResponseGracePeriod = 5 * time.Second
	gracefulShutdownTimeout = 10 * time.Second
)

type gracefulHTTPServer interface {
	ListenAndServe() error
	Shutdown(context.Context) error
	Close() error
}

func main() {
	os.Exit(run())
}

func run() int {
	if err := validateFlagStyle(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	var configPath string
	var listenOverride string
	var showVersion bool
	flag.StringVar(&configPath, "config", envOr("QUORDON_CONFIG", "config/policy.yaml"), "policy configuration path")
	flag.StringVar(&configPath, "c", envOr("QUORDON_CONFIG", "config/policy.yaml"), "policy configuration path")
	flag.StringVar(&listenOverride, "listen", os.Getenv("QUORDON_LISTEN"), "override the HTTP listen address from policy")
	flag.StringVar(&listenOverride, "l", os.Getenv("QUORDON_LISTEN"), "override the HTTP listen address from policy")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&showVersion, "v", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options]\n", os.Args[0])
		fmt.Fprintln(flag.CommandLine.Output(), "  -c, --config PATH     policy configuration path")
		fmt.Fprintln(flag.CommandLine.Output(), "  -l, --listen ADDRESS  override server.listen")
		fmt.Fprintln(flag.CommandLine.Output(), "  -v, --version         print version and exit")
	}
	flag.Parse()
	if err := validateNoPositionalArguments(flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if showVersion {
		fmt.Println(version)
		return 0
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	data, err := config.ReadSecureFile(configPath)
	if err != nil {
		logger.Error("read policy configuration", "error", err)
		return 1
	}
	cfg, err := config.Load(data)
	if err != nil {
		logger.Error("load policy configuration", "error", err)
		return 1
	}
	listen, err := effectiveListenAddress(cfg.Server.Listen, listenOverride)
	if err != nil {
		logger.Error("invalid HTTP listen address", "error", err)
		return 1
	}
	resolver := secrets.EnvironmentAndFile{}
	authenticator, authProblems := auth.NewBasic(cfg.Authentication.Basic, resolver)
	databases, databaseProblems := database.NewManager(cfg, resolver, mysql8.New())
	defer databases.Close()
	for _, problem := range databaseProblems {
		if database.IsConfigurationError(problem) {
			logger.Error("invalid datasource configuration", "error", problem)
			return 1
		}
	}
	auditSink := audit.NewJSONSink(os.Stdout)
	service := queryservice.New(policy.NewSnapshot(cfg), databases, auditSink, cfg, version)
	discoveryProblems, err := service.InitializeQueryShapeDiscovery(context.Background())
	if err != nil {
		logger.Error("initialize query-shape discovery", "error", err)
		return 1
	}
	for _, problem := range append(append(authProblems, databaseProblems...), discoveryProblems...) {
		logger.Warn("service starts unready", "problem", problem)
	}
	api := httpapi.New(authenticator, service, logger)

	httpServer := &http.Server{
		Addr: listen, Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:  httpReadTimeout,
		WriteTimeout: httpWriteTimeout(httpReadTimeout, cfg.HardLimits.Deadline()),
		IdleTimeout:  60 * time.Second,
	}
	shutdownSignal, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.Info("Quordon started", "listen", listen, "version", version, "policy_version", cfg.PolicyVersion())
	if err := serveUntilShutdown(httpServer, shutdownSignal.Done(), gracefulShutdownTimeout); err != nil {
		logger.Error("HTTP server stopped", "error", err)
		return 1
	}
	return 0
}

func validateNoPositionalArguments(arguments []string) error {
	if len(arguments) == 0 {
		return nil
	}
	return fmt.Errorf("unexpected positional argument %q", arguments[0])
}

func effectiveListenAddress(configured, override string) (string, error) {
	listen := configured
	if override != "" {
		listen = override
	}
	if err := config.ValidateListenAddress(listen); err != nil {
		return "", err
	}
	return listen, nil
}

func serveUntilShutdown(server gracefulHTTPServer, shutdownSignal <-chan struct{}, timeout time.Duration) error {
	shutdownStarted := make(chan struct{})
	shutdownDone := make(chan error, 1)
	go func() {
		<-shutdownSignal
		close(shutdownStarted)
		shutdownContext, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		shutdownDone <- server.Shutdown(shutdownContext)
	}()

	serveErr := server.ListenAndServe()
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	select {
	case <-shutdownStarted:
		if shutdownErr := <-shutdownDone; shutdownErr != nil {
			_ = server.Close()
			return fmt.Errorf("graceful HTTP shutdown: %w", shutdownErr)
		}
	default:
	}
	return nil
}

func httpWriteTimeout(readTimeout, queryDeadline time.Duration) time.Duration {
	const maxDuration = time.Duration(1<<63 - 1)
	total := time.Duration(0)
	for _, duration := range []time.Duration{readTimeout, queryDeadline, httpResponseGracePeriod} {
		if duration > maxDuration-total {
			return maxDuration
		}
		total += duration
	}
	return total
}

func validateFlagStyle(arguments []string) error {
	for _, argument := range arguments {
		if argument == "--" {
			break
		}
		if !strings.HasPrefix(argument, "-") || strings.HasPrefix(argument, "--") || argument == "-" {
			continue
		}
		name := strings.SplitN(strings.TrimPrefix(argument, "-"), "=", 2)[0]
		if len(name) != 1 {
			return fmt.Errorf("invalid option %q: long options must start with --", argument)
		}
	}
	return nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

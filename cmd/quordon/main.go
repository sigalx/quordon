package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
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
	return runWithArguments(os.Args[1:], os.Stdout, os.Stderr, startGateway)
}

type commandOptions struct {
	configPath, listenOverride string
	showVersion, checkConfig   bool
}

func runWithArguments(arguments []string, stdout, stderr io.Writer, start func(config.Config, string, *slog.Logger) int) int {
	if err := validateFlagStyle(arguments); err != nil {
		fmt.Fprintln(stderr, "invalid option style: long options must start with --")
		return 2
	}
	var options commandOptions
	flags := flag.NewFlagSet("quordon", flag.ContinueOnError)
	// flag's raw errors can repeat arbitrary argument values. Print safe errors
	// ourselves; help still goes to the caller's stderr.
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.configPath, "config", envOr("QUORDON_CONFIG", "config/policy.yaml"), "policy configuration path")
	flags.StringVar(&options.configPath, "c", envOr("QUORDON_CONFIG", "config/policy.yaml"), "policy configuration path")
	flags.StringVar(&options.listenOverride, "listen", os.Getenv("QUORDON_LISTEN"), "override the HTTP listen address from policy")
	flags.StringVar(&options.listenOverride, "l", os.Getenv("QUORDON_LISTEN"), "override the HTTP listen address from policy")
	flags.BoolVar(&options.showVersion, "version", false, "print version and exit")
	flags.BoolVar(&options.showVersion, "v", false, "print version and exit")
	flags.BoolVar(&options.checkConfig, "check-config", false, "assemble and validate policy without external dependencies")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: quordon [options]")
		fmt.Fprintln(stderr, "  -c, --config PATH     policy configuration path")
		fmt.Fprintln(stderr, "  -l, --listen ADDRESS  override server.listen")
		fmt.Fprintln(stderr, "      --check-config    assemble and validate policy; no readiness checks")
		fmt.Fprintln(stderr, "  -v, --version         print version and exit")
	}
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "invalid command arguments")
		return 2
	}
	if len(flags.Args()) != 0 || options.showVersion && options.checkConfig {
		fmt.Fprintln(stderr, "positional arguments and --version with --check-config are not allowed")
		return 2
	}
	if options.showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}

	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	cfg, err := config.LoadFile(options.configPath)
	if err != nil {
		logger.Error("load policy configuration", "error", err)
		return 1
	}
	listen, err := effectiveListenAddress(cfg.Server.Listen, options.listenOverride)
	if err != nil {
		logger.Error("invalid HTTP listen address", "error", err)
		return 1
	}
	if options.checkConfig {
		fmt.Fprintln(stdout, "configuration valid (database readiness not checked)")
		return 0
	}
	return start(cfg, listen, logger)
}

func startGateway(cfg config.Config, listen string, logger *slog.Logger) int {
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

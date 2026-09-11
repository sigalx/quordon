package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

type Event struct {
	Timestamp             time.Time      `json:"timestamp"`
	Type                  string         `json:"type"`
	RequestID             string         `json:"request_id"`
	QueryID               string         `json:"query_id,omitempty"`
	Principal             string         `json:"principal,omitempty"`
	ClientIdentifier      string         `json:"client_identifier,omitempty"`
	PolicyProfile         string         `json:"policy_profile,omitempty"`
	PolicyVersion         string         `json:"policy_version"`
	PolicyHash            string         `json:"policy_hash"`
	Datasource            string         `json:"datasource,omitempty"`
	Adapter               string         `json:"adapter,omitempty"`
	Operation             string         `json:"operation,omitempty"`
	Decision              string         `json:"decision,omitempty"`
	ReasonCode            string         `json:"reason_code,omitempty"`
	Outcome               string         `json:"outcome,omitempty"`
	ErrorKind             string         `json:"error_kind,omitempty"`
	DurationMS            *int64         `json:"duration_ms,omitempty"`
	ResultBytes           int            `json:"result_bytes,omitempty"`
	QueryShapeHash        string         `json:"query_shape_hash,omitempty"`
	PublicShapeSetHash    string         `json:"public_shape_set_hash,omitempty"`
	ShapeCount            int            `json:"shape_count,omitempty"`
	RequestedProfileHash  string         `json:"requested_profile_hash,omitempty"`
	RequestedProfileBytes int            `json:"requested_profile_bytes,omitempty"`
	Resources             []Resource     `json:"resources,omitempty"`
	Fields                []string       `json:"fields,omitempty"`
	Metadata              map[string]any `json:"metadata,omitempty"`
}

type Resource struct {
	Schema string `json:"schema"`
	Object string `json:"object,omitempty"`
}

type Sink interface {
	Write(context.Context, Event) error
	Ready() bool
}

var ErrUnavailable = errors.New("audit sink is unavailable")

const defaultWriteTimeout = 2 * time.Second

type writeRequest struct {
	payload []byte
	result  chan error
}

type JSONSink struct {
	writer   io.Writer
	requests chan writeRequest
	timeout  time.Duration
	ready    atomic.Bool
}

func NewJSONSink(writer io.Writer) *JSONSink {
	return NewJSONSinkWithTimeout(writer, defaultWriteTimeout)
}

func NewJSONSinkWithTimeout(writer io.Writer, timeout time.Duration) *JSONSink {
	if timeout <= 0 {
		timeout = defaultWriteTimeout
	}
	sink := &JSONSink{
		writer:   writer,
		requests: make(chan writeRequest, 1),
		timeout:  timeout,
	}
	sink.ready.Store(true)
	go sink.run()
	return sink
}

func (s *JSONSink) Write(ctx context.Context, event Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.ready.Load() {
		return ErrUnavailable
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	payload, err := json.Marshal(event)
	if err != nil {
		s.ready.Store(false)
		return err
	}
	payload = append(payload, '\n')

	boundedContext, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	request := writeRequest{payload: payload, result: make(chan error, 1)}
	select {
	case s.requests <- request:
	case <-boundedContext.Done():
		return s.writeTimeoutError(ctx, boundedContext, "enqueue")
	}

	select {
	case err := <-request.result:
		return err
	case <-boundedContext.Done():
		return s.writeTimeoutError(ctx, boundedContext, "write")
	}
}

func (s *JSONSink) Ready() bool { return s.ready.Load() }

func (s *JSONSink) run() {
	for request := range s.requests {
		if !s.ready.Load() {
			request.result <- ErrUnavailable
			continue
		}
		written, err := s.writer.Write(request.payload)
		if err == nil && written != len(request.payload) {
			err = io.ErrShortWrite
		}
		if err != nil {
			s.ready.Store(false)
		}
		request.result <- err
	}
}

func (s *JSONSink) writeTimeoutError(parent, bounded context.Context, operation string) error {
	if err := parent.Err(); err != nil {
		return err
	}
	s.ready.Store(false)
	return fmt.Errorf("%w: %s did not complete within %s: %v", ErrUnavailable, operation, s.timeout, bounded.Err())
}

type MemorySink struct {
	mu     sync.Mutex
	Events []Event
	Err    error
}

func (s *MemorySink) Write(_ context.Context, event Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Err != nil {
		return s.Err
	}
	s.Events = append(s.Events, event)
	return nil
}

func (s *MemorySink) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Err == nil
}

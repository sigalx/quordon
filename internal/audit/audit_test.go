package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"
)

func TestEventJSONPreservesZeroCompletionDuration(t *testing.T) {
	zero := int64(0)
	completion, err := json.Marshal(Event{Type: "query_completion", DurationMS: &zero})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(completion, []byte(`"duration_ms":0`)) {
		t.Fatalf("completion event = %s, want explicit zero duration", completion)
	}

	decision, err := json.Marshal(Event{Type: "query_decision"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(decision, []byte(`"duration_ms"`)) {
		t.Fatalf("decision event = %s, want omitted duration", decision)
	}
}

type blockingWriter struct {
	started chan struct{}
	release chan struct{}
}

func (w *blockingWriter) Write(payload []byte) (int, error) {
	close(w.started)
	<-w.release
	return len(payload), nil
}

func TestJSONSinkAcknowledgesCompletedWrite(t *testing.T) {
	t.Parallel()

	writer := &blockingWriter{started: make(chan struct{}), release: make(chan struct{})}
	sink := NewJSONSinkWithTimeout(writer, time.Second)
	result := make(chan error, 1)
	go func() {
		result <- sink.Write(context.Background(), Event{Type: "query_decision"})
	}()

	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("audit writer was not called")
	}
	select {
	case err := <-result:
		t.Fatalf("Write() returned before the underlying write completed: %v", err)
	default:
	}

	close(writer.release)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Write() did not acknowledge the completed write")
	}
}

func TestJSONSinkTimesOutBlockedWriteAndBecomesUnready(t *testing.T) {
	t.Parallel()

	writer := &blockingWriter{started: make(chan struct{}), release: make(chan struct{})}
	sink := NewJSONSinkWithTimeout(writer, 20*time.Millisecond)
	defer close(writer.release)

	result := make(chan error, 1)
	go func() {
		result <- sink.Write(context.Background(), Event{Type: "query_decision"})
	}()
	select {
	case err := <-result:
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Write() error = %v, want ErrUnavailable", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Write() remained blocked")
	}
	if sink.Ready() {
		t.Fatal("Ready() = true after a blocked write")
	}
	if err := sink.Write(context.Background(), Event{Type: "query_completion"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("subsequent Write() error = %v, want ErrUnavailable", err)
	}
}

func TestJSONSinkBecomesUnreadyOnWriterError(t *testing.T) {
	t.Parallel()

	sink := NewJSONSinkWithTimeout(errorWriter{}, time.Second)
	err := sink.Write(context.Background(), Event{Type: "query_decision"})
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Write() error = %v, want io.ErrClosedPipe", err)
	}
	if sink.Ready() {
		t.Fatal("Ready() = true after a writer error")
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

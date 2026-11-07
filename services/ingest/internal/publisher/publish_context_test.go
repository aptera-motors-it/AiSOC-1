package publisher

import (
	"context"
	"testing"
	"time"
)

type publishContextKey struct{}

func TestPublishContextDetachesCancellationWithBoundedDeadline(t *testing.T) {
	parent, cancelParent := context.WithCancel(
		context.WithValue(context.Background(), publishContextKey{}, "trace"),
	)
	ctx, cancel := detachedPublishContext(parent)
	defer cancel()

	if got := ctx.Value(publishContextKey{}); got != "trace" {
		t.Fatalf("context value = %v, want trace", got)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("detached publish context has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > detachedPublishTimeout {
		t.Fatalf("publish deadline is outside the configured bound: %s", remaining)
	}

	cancelParent()
	select {
	case <-ctx.Done():
		t.Fatalf("caller cancellation reached detached publish context: %v", context.Cause(ctx))
	default:
	}
}

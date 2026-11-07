package handler

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/graph"
	"github.com/beenuar/aisoc/services/ingest/internal/publisher"
)

type recordingGraphWriter struct {
	events []*graph.Event
}

func (w *recordingGraphWriter) WriteEvent(_ context.Context, event *graph.Event) error {
	w.events = append(w.events, event)
	return nil
}

func TestIngest_KafkaFailureDoesNotWriteToGraph(t *testing.T) {
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve Kafka address: %v", err)
	}
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Errorf("close Kafka listener: %v", err)
		}
		<-acceptDone
	})
	broker := listener.Addr().String()

	cfg := testConfig()
	cfg.KafkaBrokers = broker
	cfg.KafkaTopic = "aisoc.raw_events"
	pub, err := publisher.New(cfg)
	if err != nil {
		t.Fatalf("publisher: %v", err)
	}
	t.Cleanup(pub.Close)

	h, _ := newAuthHandler(t, "")
	h.pub = pub
	graphWriter := &recordingGraphWriter{}
	h.SetGraphWriter(graphWriter)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rec := push(t, h, acmeToken, acmeTenant.String(), func(req *http.Request) {
		*req = *req.WithContext(ctx)
	})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("dead Kafka broker should return 500; got %d %s", rec.Code, rec.Body)
	}
	if got := len(graphWriter.events); got != 0 {
		t.Fatalf("graph received %d event(s) that Kafka rejected", got)
	}
}

func TestIngest_KafkaSuccessWritesToGraph(t *testing.T) {
	h, _ := newAuthHandler(t, "")
	graphWriter := &recordingGraphWriter{}
	h.SetGraphWriter(graphWriter)

	rec := push(t, h, acmeToken, acmeTenant.String())

	if rec.Code != http.StatusOK {
		t.Fatalf("successful Kafka publish should return 200; got %d %s", rec.Code, rec.Body)
	}
	if got := len(graphWriter.events); got != 1 {
		t.Fatalf("graph received %d event(s) after Kafka accepted one", got)
	}
}

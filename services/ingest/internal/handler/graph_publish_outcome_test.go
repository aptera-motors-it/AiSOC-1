package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/publisher"
	"github.com/segmentio/kafka-go/protocol"
	"github.com/segmentio/kafka-go/protocol/apiversions"
	"github.com/segmentio/kafka-go/protocol/metadata"
	"github.com/segmentio/kafka-go/protocol/produce"
)

type outcomeBroker struct {
	listener     net.Listener
	host         string
	port         int32
	responseWait time.Duration
	partitions   int32
	failedPart   int32
	failureCode  int16
	appendOnFail bool
	received     atomic.Int64
	mu           sync.Mutex
	accepted     map[string]struct{}
	rejected     map[string]struct{}
	connections  sync.Map
	wg           sync.WaitGroup
}

func startOutcomeBroker(t *testing.T, responseWait time.Duration) *outcomeBroker {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().(*net.TCPAddr)
	broker := &outcomeBroker{
		listener:     listener,
		host:         "127.0.0.1",
		port:         int32(addr.Port),
		responseWait: responseWait,
		partitions:   1,
		failedPart:   -1,
		accepted:     map[string]struct{}{},
		rejected:     map[string]struct{}{},
	}
	broker.wg.Add(1)
	go func() {
		defer broker.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			broker.connections.Store(conn, struct{}{})
			broker.wg.Add(1)
			go func() {
				defer broker.wg.Done()
				defer broker.connections.Delete(conn)
				broker.serve(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		broker.connections.Range(func(conn, _ any) bool {
			_ = conn.(net.Conn).Close()
			return true
		})
		broker.wg.Wait()
	})
	return broker
}

func (b *outcomeBroker) address() string {
	return b.host + ":" + strconv.Itoa(int(b.port))
}

func (b *outcomeBroker) serve(conn net.Conn) {
	defer conn.Close()
	for {
		version, correlationID, _, message, err := protocol.ReadRequest(conn)
		if err != nil {
			return
		}
		var response protocol.Message
		switch request := message.(type) {
		case *apiversions.Request:
			response = &apiversions.Response{ApiKeys: []apiversions.ApiKeyResponse{
				{ApiKey: int16(protocol.Produce), MinVersion: 0, MaxVersion: 7},
				{ApiKey: int16(protocol.Metadata), MinVersion: 0, MaxVersion: 6},
				{ApiKey: int16(protocol.ApiVersions), MinVersion: 0, MaxVersion: 2},
			}}
		case *metadata.Request:
			names := request.TopicNames
			if len(names) == 0 {
				names = []string{"aisoc.raw_events"}
			}
			topics := make([]metadata.ResponseTopic, 0, len(names))
			for _, name := range names {
				partitions := make([]metadata.ResponsePartition, 0, b.partitions)
				for i := int32(0); i < b.partitions; i++ {
					partitions = append(partitions, metadata.ResponsePartition{
						PartitionIndex: i,
						LeaderID:       1,
						ReplicaNodes:   []int32{1},
						IsrNodes:       []int32{1},
					})
				}
				topics = append(topics, metadata.ResponseTopic{Name: name, Partitions: partitions})
			}
			response = &metadata.Response{
				Brokers:      []metadata.ResponseBroker{{NodeID: 1, Host: b.host, Port: b.port}},
				ClusterID:    "test",
				ControllerID: 1,
				Topics:       topics,
			}
		case *produce.Request:
			result := &produce.Response{}
			outcomes := map[int32][]string{}
			for _, topic := range request.Topics {
				responseTopic := produce.ResponseTopic{Topic: topic.Topic}
				for _, partition := range topic.Partitions {
					for partition.RecordSet.Records != nil {
						record, err := partition.RecordSet.Records.ReadRecord()
						if err != nil {
							break
						}
						value, err := io.ReadAll(record.Value)
						if err != nil {
							return
						}
						var event struct {
							ID string `json:"id"`
						}
						if err := json.Unmarshal(value, &event); err != nil {
							return
						}
						outcomes[partition.Partition] = append(outcomes[partition.Partition], event.ID)
						b.received.Add(1)
					}
					entry := produce.ResponsePartition{Partition: partition.Partition}
					if partition.Partition == b.failedPart {
						entry.ErrorCode = b.failureCode
					}
					responseTopic.Partitions = append(responseTopic.Partitions, entry)
				}
				result.Topics = append(result.Topics, responseTopic)
			}
			time.Sleep(b.responseWait)
			if err := protocol.WriteResponse(conn, version, correlationID, result); err != nil {
				return
			}
			b.mu.Lock()
			for partition, ids := range outcomes {
				target := b.accepted
				if partition == b.failedPart && !b.appendOnFail {
					target = b.rejected
				}
				for _, id := range ids {
					target[id] = struct{}{}
				}
			}
			b.mu.Unlock()
			continue
		default:
			return
		}
		if err := protocol.WriteResponse(conn, version, correlationID, response); err != nil {
			return
		}
	}
}

func (b *outcomeBroker) eventSets() (map[string]struct{}, map[string]struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	accepted := make(map[string]struct{}, len(b.accepted))
	rejected := make(map[string]struct{}, len(b.rejected))
	for id := range b.accepted {
		accepted[id] = struct{}{}
	}
	for id := range b.rejected {
		rejected[id] = struct{}{}
	}
	return accepted, rejected
}

func newOutcomePublisher(t *testing.T, broker string) *publisher.Publisher {
	t.Helper()
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")
	cfg := testConfig()
	cfg.KafkaBrokers = broker
	cfg.KafkaTopic = "aisoc.raw_events"
	pub, err := publisher.New(cfg)
	if err != nil {
		t.Fatalf("publisher: %v", err)
	}
	t.Cleanup(pub.Close)
	return pub
}

func pushEvents(t *testing.T, h *Handler, count int, ctx context.Context) *httptest.ResponseRecorder {
	t.Helper()
	events := make([]map[string]any, 0, count)
	for i := 0; i < count; i++ {
		events = append(events, map[string]any{
			"severity": "high",
			"title":    "Encoded PowerShell",
			"host":     "WIN-" + strconv.Itoa(i),
		})
	}
	body, err := json.Marshal(map[string]any{
		"connector_id":   "edr-1",
		"connector_type": "crowdstrike",
		"source_format":  "json",
		"events":         events,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/ingest/batch", bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+acmeToken)
	req.Header.Set("X-Tenant-ID", acmeTenant.String())
	rec := httptest.NewRecorder()
	h.IngestEvents(rec, req)
	return rec
}

func TestIngest_KafkaAckAfterRequestCancelWritesGraph(t *testing.T) {
	broker := startOutcomeBroker(t, 100*time.Millisecond)
	h, _ := newAuthHandler(t, "")
	h.pub = newOutcomePublisher(t, broker.address())
	graphWriter := &recordingGraphWriter{}
	h.SetGraphWriter(graphWriter)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for broker.received.Load() == 0 {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()
	pushEvents(t, h, 1, ctx)

	deadline := time.Now().Add(3 * time.Second)
	for {
		accepted, _ := broker.eventSets()
		if len(accepted) == 1 || time.Now().After(deadline) {
			if len(accepted) != 1 || len(graphWriter.events) != 1 {
				t.Fatalf("Kafka accepted %d event(s), graph received %d", len(accepted), len(graphWriter.events))
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func TestIngest_PartialKafkaBatchProjectsAcceptedEvents(t *testing.T) {
	broker := startOutcomeBroker(t, 0)
	broker.partitions = 2
	broker.failedPart = 1
	broker.failureCode = 10
	h, _ := newAuthHandler(t, "")
	h.pub = newOutcomePublisher(t, broker.address())
	graphWriter := &recordingGraphWriter{}
	h.SetGraphWriter(graphWriter)

	pushEvents(t, h, 6, context.Background())

	accepted, rejected := broker.eventSets()
	projected := make(map[string]struct{}, len(graphWriter.events))
	for _, event := range graphWriter.events {
		projected[event.EventID] = struct{}{}
	}
	if len(accepted) == 0 || len(rejected) == 0 {
		t.Fatalf("test broker did not split the batch: accepted=%d rejected=%d", len(accepted), len(rejected))
	}
	if len(projected) != len(accepted) {
		t.Fatalf("Kafka accepted %d event(s), graph received %d", len(accepted), len(projected))
	}
	for id := range accepted {
		if _, ok := projected[id]; !ok {
			t.Fatalf("accepted event %s was not projected", id)
		}
	}
	for id := range rejected {
		if _, ok := projected[id]; ok {
			t.Fatalf("rejected event %s was projected", id)
		}
	}
}

func TestIngest_KafkaAppendErrorProjectsEvent(t *testing.T) {
	broker := startOutcomeBroker(t, 0)
	broker.failedPart = 0
	broker.failureCode = 20
	broker.appendOnFail = true
	h, _ := newAuthHandler(t, "")
	h.pub = newOutcomePublisher(t, broker.address())
	graphWriter := &recordingGraphWriter{}
	h.SetGraphWriter(graphWriter)

	pushEvents(t, h, 1, context.Background())

	accepted, _ := broker.eventSets()
	if len(accepted) != 1 || len(graphWriter.events) != 1 {
		t.Fatalf("Kafka appended %d event(s), graph received %d", len(accepted), len(graphWriter.events))
	}
}

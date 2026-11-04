package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/config"
	"github.com/beenuar/aisoc/services/ingest/internal/graph"
	"github.com/beenuar/aisoc/services/ingest/internal/graph_ws"
	"github.com/beenuar/aisoc/services/ingest/internal/handler"
	"github.com/beenuar/aisoc/services/ingest/internal/inbox"
	"github.com/beenuar/aisoc/services/ingest/internal/ingestauth"
	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
	"github.com/google/uuid"
)

var (
	tenantA = uuid.MustParse("11111111-1111-4111-8111-111111111111")
	tenantB = uuid.MustParse("22222222-2222-4222-8222-222222222222")
)

const (
	tokenA       = "aitnb_tenant_a_push_token_aaaaaaaa"
	serviceToken = "svc-token-for-the-graph-proxy"
)

type memTokens struct {
	rows map[string]*inbox.Token
}

func (m *memTokens) Resolve(_ context.Context, token string) (*inbox.Token, error) {
	row, ok := m.rows[token]
	if !ok {
		return nil, inbox.ErrTokenNotFound
	}
	return row, nil
}

type memTenants struct{ active map[uuid.UUID]bool }

func (m *memTenants) IsActive(_ context.Context, id uuid.UUID) (bool, error) {
	return m.active[id], nil
}

type nopPub struct{}

func (nopPub) PublishBatch(context.Context, []*normalizer.NormalizedEvent) error { return nil }
func (nopPub) Ready(context.Context) error                                       { return nil }

type chanSource struct {
	ch chan graph.GraphUpdate
}

func (s *chanSource) Next(ctx context.Context) (graph.GraphUpdate, error) {
	select {
	case <-ctx.Done():
		return graph.GraphUpdate{}, ctx.Err()
	case env, ok := <-s.ch:
		if !ok {
			return graph.GraphUpdate{}, fmt.Errorf("source closed")
		}
		return env, nil
	}
}

func (s *chanSource) Close() error { return nil }

func graphAuthenticator() *ingestauth.Authenticator {
	tokens := &memTokens{rows: map[string]*inbox.Token{
		tokenA: {Token: tokenA, TenantID: tenantA, TemplateID: ingestauth.PushTemplateID},
	}}
	tenants := &memTenants{active: map[uuid.UUID]bool{tenantA: true, tenantB: true}}
	return ingestauth.New(tokens, tenants, serviceToken, "X-Tenant-ID")
}

func testRouter(t *testing.T, ws *graph_ws.Server, auth *ingestauth.Authenticator) http.Handler {
	t.Helper()
	cfg := &config.Config{
		TenantHeaderKey:    "X-Tenant-ID",
		NormalizerMode:     "lenient",
		MaxBatchSize:       10,
		IngestMaxBodyBytes: 1 << 20,
		HTTPPort:           1,
	}
	norm, err := normalizer.New(cfg)
	if err != nil {
		t.Fatalf("normalizer: %v", err)
	}
	h := handler.New(norm, nopPub{}, cfg)
	h.SetAuthenticator(auth)
	return New(cfg, h, nil, ws, nil).httpServer.Handler
}

type graphFix struct {
	url string
	src *chanSource
	b   *graph_ws.Broadcaster
}

func startGraph(t *testing.T) graphFix {
	t.Helper()
	src := &chanSource{ch: make(chan graph.GraphUpdate, 8)}
	b := graph_ws.New(src, graph_ws.Options{BufferSize: 8, Topic: "security.graph_updates"})
	ctx, cancel := context.WithCancel(context.Background())
	b.Start(ctx)
	t.Cleanup(func() {
		cancel()
		b.Stop()
	})
	deadline := time.Now().Add(2 * time.Second)
	for !b.Health().Healthy() {
		if time.Now().After(deadline) {
			t.Fatalf("broadcaster not healthy: %+v", b.Health())
		}
		time.Sleep(5 * time.Millisecond)
	}
	ts := httptest.NewServer(testRouter(t, graph_ws.NewServer(b), graphAuthenticator()))
	t.Cleanup(ts.Close)
	return graphFix{url: ts.URL, src: src, b: b}
}

func dialGraph(t *testing.T, base, tenant string, headers map[string]string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	host := strings.TrimPrefix(strings.TrimPrefix(base, "http://"), "https://")
	path := "/v1/graph_ws/stream"
	if tenant != "" {
		path += "?tenant_id=" + tenant
	}
	conn, err := net.DialTimeout("tcp", host, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	var req strings.Builder
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\nHost: %s\r\n", path, host)
	req.WriteString("Upgrade: websocket\r\nConnection: Upgrade\r\n")
	req.WriteString("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n")
	req.WriteString("Sec-WebSocket-Version: 13\r\n")
	for k, v := range headers {
		fmt.Fprintf(&req, "%s: %s\r\n", k, v)
	}
	req.WriteString("\r\n")
	if _, err := io.WriteString(conn, req.String()); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("status line: %v", err)
	}
	var code int
	if _, err := fmt.Sscanf(line, "%s %d", new(string), &code); err != nil {
		t.Fatalf("parse %q: %v", line, err)
	}
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("header: %v", err)
		}
		if h == "\r\n" || h == "\n" {
			break
		}
	}
	return conn, br, code
}

func waitSubscribed(t *testing.T, b *graph_ws.Broadcaster, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for b.SubscriberCount() < n {
		if time.Now().After(deadline) {
			t.Fatalf("subscribers = %d, want >= %d", b.SubscriberCount(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func readText(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		t.Fatalf("frame header: %v", err)
	}
	if hdr[0]&0x0F != 0x1 {
		t.Fatalf("opcode %d, want text", hdr[0]&0x0F)
	}
	n := int(hdr[1] & 0x7F)
	switch n {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(br, ext); err != nil {
			t.Fatalf("extended length: %v", err)
		}
		n = int(ext[0])<<8 | int(ext[1])
	case 127:
		t.Fatal("64-bit websocket frame")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("frame body: %v", err)
	}
	return string(buf)
}

func envelope(tenant, id string) graph.GraphUpdate {
	return graph.GraphUpdate{
		EntityID:      id,
		ChangeType:    graph.ChangeUpsertNode,
		TS:            time.Now().UTC(),
		TenantID:      tenant,
		SchemaVersion: graph.SchemaVersion,
	}
}

func TestGraphStream_NoCredentialIsNotAccepted(t *testing.T) {
	g := startGraph(t)
	_, _, code := dialGraph(t, g.url, tenantB.String(), nil)
	if code == http.StatusSwitchingProtocols {
		t.Fatal("a graph websocket with no credential was accepted")
	}
	if code != http.StatusUnauthorized {
		t.Fatalf("missing credential must be 401; got %d", code)
	}
}

func TestGraphStream_OtherTenantsQueryDoesNotDeliverThatTenantsEvents(t *testing.T) {
	g := startGraph(t)
	_, br, code := dialGraph(t, g.url, tenantB.String(), map[string]string{
		"Authorization": "Bearer " + tokenA,
	})
	if code == http.StatusSwitchingProtocols {
		waitSubscribed(t, g.b, 1)
		g.src.ch <- envelope(tenantB.String(), "belongs-to-b")
		got := readText(t, br)
		t.Fatalf("tenant A's credential with ?tenant_id=B was accepted and received %s", got)
	}
	if code != http.StatusForbidden {
		t.Fatalf("cross-tenant subscription must be 403; got %d", code)
	}
	if n := g.b.SubscriberCount(); n != 0 {
		t.Fatalf("refused handshake still subscribed %d client(s)", n)
	}
}

func TestGraphStream_ServiceCredentialCannotFollowADifferentQueryTenant(t *testing.T) {
	g := startGraph(t)
	_, br, code := dialGraph(t, g.url, tenantB.String(), map[string]string{
		"Authorization": "Bearer " + serviceToken,
		"X-Tenant-ID":   tenantA.String(),
	})
	if code == http.StatusSwitchingProtocols {
		waitSubscribed(t, g.b, 1)
		g.src.ch <- envelope(tenantB.String(), "belongs-to-b")
		got := readText(t, br)
		t.Fatalf("service credential for A with ?tenant_id=B was accepted and received %s", got)
	}
	if code != http.StatusForbidden {
		t.Fatalf("query tenant outside the declared tenant must be 403; got %d", code)
	}
}

func TestGraphStream_CredentialReceivesOnlyItsOwnTenant(t *testing.T) {
	g := startGraph(t)
	_, br, code := dialGraph(t, g.url, tenantA.String(), map[string]string{
		"Authorization": "Bearer " + tokenA,
	})
	if code != http.StatusSwitchingProtocols {
		t.Fatalf("tenant A's credential subscribing to A must upgrade; got %d", code)
	}
	waitSubscribed(t, g.b, 1)
	g.src.ch <- envelope(tenantB.String(), "belongs-to-b")
	g.src.ch <- envelope(tenantA.String(), "belongs-to-a")
	got := readText(t, br)
	if strings.Contains(got, tenantB.String()) {
		t.Fatalf("tenant A's socket received tenant B: %s", got)
	}
	if !strings.Contains(got, tenantA.String()) || !strings.Contains(got, "belongs-to-a") {
		t.Fatalf("tenant A's socket did not receive its own event: %s", got)
	}
}

func TestGraphStream_ServiceCredentialHonoursItsDeclaredTenant(t *testing.T) {
	g := startGraph(t)
	_, br, code := dialGraph(t, g.url, tenantB.String(), map[string]string{
		"Authorization": "Bearer " + serviceToken,
		"X-Tenant-ID":   tenantB.String(),
	})
	if code != http.StatusSwitchingProtocols {
		t.Fatalf("service credential declaring B must upgrade; got %d", code)
	}
	waitSubscribed(t, g.b, 1)
	g.src.ch <- envelope(tenantA.String(), "belongs-to-a")
	g.src.ch <- envelope(tenantB.String(), "belongs-to-b")
	got := readText(t, br)
	if strings.Contains(got, tenantA.String()) {
		t.Fatalf("B's socket received tenant A: %s", got)
	}
	if !strings.Contains(got, "belongs-to-b") {
		t.Fatalf("B's socket did not receive its own event: %s", got)
	}
}

func getMetrics(t *testing.T, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	h := testRouter(t, nil, graphAuthenticator())
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMetrics_RefusesAnAnonymousScrapeWhenTokenIsSet(t *testing.T) {
	t.Setenv("ENV", "production")
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("METRICS_TOKEN", "s3cret")
	rec := getMetrics(t, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous scrape with METRICS_TOKEN set must be 401; got %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "# HELP") {
		t.Fatal("refused scrape still wrote metrics")
	}
}

func TestMetrics_RefusesAWrongToken(t *testing.T) {
	t.Setenv("ENV", "production")
	t.Setenv("METRICS_TOKEN", "s3cret")
	rec := getMetrics(t, map[string]string{"Authorization": "Bearer not-the-token"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong metrics token must be 401; got %d", rec.Code)
	}
	bare := getMetrics(t, map[string]string{"Authorization": "s3cret"})
	if bare.Code != http.StatusUnauthorized {
		t.Fatalf("token without the Bearer scheme must be 401; got %d", bare.Code)
	}
}

func TestMetrics_RefusesWhenUnsetOutsideDevelopment(t *testing.T) {
	t.Setenv("ENV", "production")
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("METRICS_TOKEN", "")
	rec := getMetrics(t, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unset METRICS_TOKEN outside development must be 401; got %d %s", rec.Code, rec.Body)
	}
}

func TestMetrics_AcceptsTheConfiguredToken(t *testing.T) {
	t.Setenv("ENV", "production")
	t.Setenv("METRICS_TOKEN", "s3cret")
	rec := getMetrics(t, map[string]string{"Authorization": "Bearer s3cret"})
	if rec.Code != http.StatusOK {
		t.Fatalf("correct metrics token must scrape; got %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "# HELP") {
		t.Fatalf("scrape body is not prometheus text: %s", rec.Body)
	}
}

func TestMetrics_UnsetTokenStaysOpenInDevelopment(t *testing.T) {
	for _, env := range []string{"development", "dev", "local", "demo", "test"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv("ENV", env)
			t.Setenv("ENVIRONMENT", "")
			t.Setenv("METRICS_TOKEN", "")
			rec := getMetrics(t, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: anonymous scrape must stay open; got %d %s", env, rec.Code, rec.Body)
			}
		})
	}
}

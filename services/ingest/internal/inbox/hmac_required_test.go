package inbox

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beenuar/aisoc/services/ingest/internal/normalizer"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// capturePub records what the real handler published. A refusal that still
// enqueued would be worse than no refusal, because the caller would see an
// error and the event would be in the spine anyway.
type capturePub struct {
	events []*normalizer.NormalizedEvent
}

func (c *capturePub) PublishBatch(_ context.Context, events []*normalizer.NormalizedEvent) error {
	c.events = append(c.events, events...)
	return nil
}

func inboxFixture(t *testing.T, secret string) (*Handler, *capturePub, string) {
	t.Helper()
	const token = "aitnb_inbox_hmac_token_eeeeeeeeeeee"
	reg := NewRegistry()
	if err := reg.LoadEmbedded(); err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	store := newTestStore()
	store.cacheHit(token, &Token{
		Token:      token,
		TenantID:   uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		TemplateID: "generic-json",
		HMACSecret: secret,
	})
	pub := &capturePub{}
	h := NewHandler(store, reg, nil, 1<<20)
	h.pub = pub
	return h, pub, token
}

func postInbox(t *testing.T, h *Handler, token string, body []byte, signature string) *httptest.ResponseRecorder {
	t.Helper()
	r := chi.NewRouter()
	r.Post("/v1/inbox/{token}", h.ServeJSON)
	req := httptest.NewRequest(http.MethodPost, "/v1/inbox/"+token, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if signature != "" {
		req.Header.Set("X-Signature", signature)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func signed(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// A token whose hmac_secret is empty used to skip the check, so the
// submission was accepted with no signature. A signature under the empty
// key is the same hole: anyone who can see the URL can compute it.
func TestInbox_EmptyHMACSecretIsRefused(t *testing.T) {
	body := []byte(`{"message":"sensor tripped","severity":"high"}`)
	h, pub, token := inboxFixture(t, "")

	rec := postInbox(t, h, token, body, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("empty hmac_secret was accepted (%d): %s", rec.Code, rec.Body)
	}

	rec = postInbox(t, h, token, body, signed("", body))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("signature under the empty key was accepted (%d): %s", rec.Code, rec.Body)
	}
	if n := len(pub.events); n != 0 {
		t.Fatalf("refused submissions still published %d event(s)", n)
	}
}

// The refusal above is only meaningful if a token that actually has a
// secret still accepts a matching signature and rejects a missing one.
func TestInbox_SignedTokenAcceptsOnlyAMatchingSignature(t *testing.T) {
	const secret = "inbox-signing-secret"
	body := []byte(`{"message":"sensor tripped","severity":"high"}`)
	h, pub, token := inboxFixture(t, secret)

	if rec := postInbox(t, h, token, body, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing signature on a secret-bearing token: got %d %s", rec.Code, rec.Body)
	}
	if rec := postInbox(t, h, token, body, signed("other-secret", body)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong signature: got %d %s", rec.Code, rec.Body)
	}
	rec := postInbox(t, h, token, body, signed(secret, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("matching signature must be accepted; got %d %s", rec.Code, rec.Body)
	}
	if len(pub.events) != 1 {
		t.Fatalf("expected 1 published event, got %d", len(pub.events))
	}
	if pub.events[0].TenantID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("published tenant %q", pub.events[0].TenantID)
	}
}

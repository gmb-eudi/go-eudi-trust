package trust_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	trust "github.com/gmb-eudi/go-eudi-trust"
)

const (
	snapV1        = "3f7a1c9e5b2d8f4a6c0e2b7d9f1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a"
	snapV2        = "a1d3f5b7c9e1a3d5f7b9c1e3a5d7f9b1c3e5a7d9f1b3c5e7a9d1f3b5c7e9a1d3"
	statusGranted = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
)

func newTestClient(t *testing.T, srv *httptest.Server, clock *fakeClock) *trust.HTTPClient {
	t.Helper()
	c, err := trust.NewClient(srv.URL, srv.Client(), trust.WithClock(clock.Now))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Fixture round-trip (T-06.2 acceptance): wire fixture → public AnchorSet.
func TestAnchorsGoldenMapping(t *testing.T) {
	srv, _ := newFixtureServer(t, "anchors-pid-lv-v1.json")
	clock := newClock(t0)
	c := newTestClient(t, srv, clock)

	set, ok, err := c.Anchors(context.Background(), trust.PIDProvider, "LV", "")
	if err != nil {
		t.Fatalf("Anchors: %v", err)
	}
	if !ok {
		t.Fatal("ok = false, want true (200 response)")
	}
	if set.Snapshot != snapV1 {
		t.Errorf("Snapshot = %q, want %q", set.Snapshot, snapV1)
	}
	if set.Stale {
		t.Error("Stale = true, want false")
	}
	if !set.FetchedAt.Equal(t0) {
		t.Errorf("FetchedAt = %v, want injected clock %v", set.FetchedAt, t0)
	}
	if len(set.Anchors) != 2 {
		t.Fatalf("len(Anchors) = %d, want 2", len(set.Anchors))
	}
	for i, a := range set.Anchors {
		if a.Cert == nil {
			t.Fatalf("anchor %d: nil Cert", i)
		}
		if !strings.HasPrefix(a.Cert.Subject.CommonName, "LV PID Provider CA") {
			t.Errorf("anchor %d: CN = %q", i, a.Cert.Subject.CommonName)
		}
		if a.Type != trust.PIDProvider {
			t.Errorf("anchor %d: Type = %q, want %q", i, a.Type, trust.PIDProvider)
		}
		if a.Country != "LV" {
			t.Errorf("anchor %d: Country = %q, want LV", i, a.Country)
		}
		if a.Status != statusGranted {
			t.Errorf("anchor %d: Status = %q, want %q", i, a.Status, statusGranted)
		}
		if want := time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC); !a.ValidUntil.Equal(want) {
			t.Errorf("anchor %d: ValidUntil = %v, want %v", i, a.ValidUntil, want)
		}
		if a.TLSequence != 42 {
			t.Errorf("anchor %d: TLSequence = %d, want 42", i, a.TLSequence)
		}
	}
}

func TestAnchorsRequestShape(t *testing.T) {
	srv, h := newFixtureServer(t, "anchors-pid-lv-v1.json")
	c := newTestClient(t, srv, newClock(t0))
	ctx := context.Background()

	if _, _, err := c.Anchors(ctx, trust.PIDProvider, "LV", ""); err != nil {
		t.Fatal(err)
	}
	if got := h.lastQuery(); got != "territory=LV&type=pid_provider" {
		t.Errorf("query = %q, want territory=LV&type=pid_provider", got)
	}
	if inm := h.lastHeader().Get("If-None-Match"); inm != "" {
		t.Errorf("If-None-Match = %q, want unset on first fetch", inm)
	}

	// Revalidation: etag → If-None-Match, quoted (strong ETag).
	if _, _, err := c.Anchors(ctx, trust.PIDProvider, "LV", snapV1); err != nil {
		t.Fatal(err)
	}
	if inm := h.lastHeader().Get("If-None-Match"); inm != `"`+snapV1+`"` {
		t.Errorf("If-None-Match = %q, want quoted %q", inm, snapV1)
	}

	// EU-level fetch: no territory parameter at all.
	if _, _, err := c.Anchors(ctx, trust.PIDProvider, "", ""); err != nil {
		t.Fatal(err)
	}
	if got := h.lastQuery(); got != "type=pid_provider" {
		t.Errorf("query = %q, want type=pid_provider (no territory)", got)
	}
}

// 304 = freshness confirmation: ok=false, nil error (WP-06 README).
func TestAnchors304NotModified(t *testing.T) {
	srv, _ := newFixtureServer(t, "anchors-pid-lv-v1.json")
	c := newTestClient(t, srv, newClock(t0))

	set, ok, err := c.Anchors(context.Background(), trust.PIDProvider, "LV", snapV1)
	if err != nil {
		t.Fatalf("Anchors on 304: %v", err)
	}
	if ok {
		t.Error("ok = true, want false on 304")
	}
	if len(set.Anchors) != 0 || set.Snapshot != "" {
		t.Errorf("AnchorSet on 304 = %+v, want zero value", set)
	}
}

func TestAnchorsStaleFlag(t *testing.T) {
	srv, _ := newFixtureServer(t, "anchors-stale.json")
	c := newTestClient(t, srv, newClock(t0))

	set, ok, err := c.Anchors(context.Background(), trust.PIDProvider, "LV", "")
	if err != nil || !ok {
		t.Fatalf("Anchors: ok=%v err=%v", ok, err)
	}
	if !set.Stale {
		t.Error("Stale = false, want true (X-Trust-Stale + body stale)")
	}
}

// Schema strictness (T-06.2 acceptance): missing valid_until = error;
// ETag/body divergence = error. Negative tests — must fail first.
func TestAnchorsSchemaViolations(t *testing.T) {
	t.Run("missing_valid_until", func(t *testing.T) {
		srv, _ := newFixtureServer(t, "anchors-missing-notafter.json")
		c := newTestClient(t, srv, newClock(t0))
		_, _, err := c.Anchors(context.Background(), trust.PIDProvider, "LV", "")
		if !errors.Is(err, trust.ErrSchema) {
			t.Fatalf("err = %v, want ErrSchema", err)
		}
	})
	t.Run("body_not_json", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("<html>bad gateway</html>"))
		}))
		t.Cleanup(srv.Close)
		c := newTestClient(t, srv, newClock(t0))
		_, _, err := c.Anchors(context.Background(), trust.PIDProvider, "LV", "")
		if !errors.Is(err, trust.ErrSchema) {
			t.Fatalf("err = %v, want ErrSchema", err)
		}
	})
	t.Run("etag_body_mismatch", func(t *testing.T) {
		body := fixture(t, "anchors-pid-lv-v1.json")
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("ETag", `"`+snapV2+`"`) // body says snapV1
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		}))
		t.Cleanup(srv.Close)
		c := newTestClient(t, srv, newClock(t0))
		_, _, err := c.Anchors(context.Background(), trust.PIDProvider, "LV", "")
		if !errors.Is(err, trust.ErrSchema) {
			t.Fatalf("err = %v, want ErrSchema", err)
		}
	})
}

func TestAnchorsHTTPStatusAndTransport(t *testing.T) {
	t.Run("http_500", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(srv.Close)
		c := newTestClient(t, srv, newClock(t0))
		_, _, err := c.Anchors(context.Background(), trust.PIDProvider, "LV", "")
		if !errors.Is(err, trust.ErrStatus) {
			t.Fatalf("err = %v, want ErrStatus", err)
		}
	})
	t.Run("transport_error", func(t *testing.T) {
		c, err := trust.NewClient("https://trust.invalid", failingDoer{}, trust.WithClock(newClock(t0).Now))
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = c.Anchors(context.Background(), trust.PIDProvider, "LV", "")
		if !errors.Is(err, trust.ErrUnavailable) {
			t.Fatalf("err = %v, want ErrUnavailable", err)
		}
	})
}

type failingDoer struct{}

func (failingDoer) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial tcp: connection refused")
}

// countingDoer proves doer injection: the lib performs I/O ONLY through the
// injected doer (mTLS/DPoP-readiness — any *http.Client satisfies Doer).
type countingDoer struct {
	next  trust.Doer
	calls int
}

func (d *countingDoer) Do(req *http.Request) (*http.Response, error) {
	d.calls++
	return d.next.Do(req)
}

func TestDoerInjection(t *testing.T) {
	srv, _ := newFixtureServer(t, "anchors-pid-lv-v1.json")
	d := &countingDoer{next: srv.Client()}
	c, err := trust.NewClient(srv.URL, d, trust.WithClock(newClock(t0).Now))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Anchors(context.Background(), trust.PIDProvider, "LV", ""); err != nil {
		t.Fatal(err)
	}
	if d.calls != 1 {
		t.Errorf("doer calls = %d, want 1", d.calls)
	}
}

// Unknown anchor type = reject before any I/O (fail closed).
func TestAnchorsUnknownType(t *testing.T) {
	d := &countingDoer{next: failingDoer{}}
	c, err := trust.NewClient("https://trust.invalid", d)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = c.Anchors(context.Background(), trust.AnchorType("bogus"), "LV", "")
	if !errors.Is(err, trust.ErrUnknownAnchorType) {
		t.Fatalf("err = %v, want ErrUnknownAnchorType", err)
	}
	if d.calls != 0 {
		t.Errorf("doer calls = %d, want 0 (reject before I/O)", d.calls)
	}
}

func TestNewClientValidation(t *testing.T) {
	if _, err := trust.NewClient("://not-a-url", failingDoer{}); err == nil {
		t.Error("invalid base URL accepted")
	}
	if _, err := trust.NewClient("", failingDoer{}); err == nil {
		t.Error("empty base URL accepted")
	}
	if _, err := trust.NewClient("https://ok.example", nil); err == nil {
		t.Error("nil doer accepted")
	}
}

func TestSnapshotGolden(t *testing.T) {
	body := fixture(t, "snapshot.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/snapshot" {
			t.Errorf("path = %q, want /v1/snapshot", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	c := newTestClient(t, srv, newClock(t0))

	meta, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if meta.ID != snapV1 {
		t.Errorf("ID = %q, want %q", meta.ID, snapV1)
	}
	if meta.LOTLSequence != 351 {
		t.Errorf("LOTLSequence = %d, want 351", meta.LOTLSequence)
	}
	if len(meta.Territories) != 2 {
		t.Fatalf("len(Territories) = %d, want 2", len(meta.Territories))
	}
	ee := meta.Territories[1]
	if ee.Code != "EE" || !ee.Stale || !ee.CarriedOver || ee.TLSequence != 97 || ee.AnchorCount != 5 {
		t.Errorf("EE territory = %+v", ee)
	}
	if !meta.PendingBootstrap {
		t.Error("PendingBootstrap = false, want true (staged OJ update in fixture)")
	}
	if meta.PendingAnchors != 0 {
		t.Errorf("PendingAnchors = %d, want 0", meta.PendingAnchors)
	}
}

func TestSnapshotErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable) // "no trust snapshot loaded yet"
	}))
	t.Cleanup(srv.Close)
	c := newTestClient(t, srv, newClock(t0))
	if _, err := c.Snapshot(context.Background()); !errors.Is(err, trust.ErrStatus) {
		t.Fatalf("err = %v, want ErrStatus", err)
	}
}

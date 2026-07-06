package trust_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	trust "github.com/gmb-eudi/go-eudi-trust"
)

// matchServer replays a match fixture and records the request.
func matchServer(t *testing.T, file string) (*httptest.Server, *struct {
	Method, Path string
	Body         []byte
}) {
	t.Helper()
	rec := &struct {
		Method, Path string
		Body         []byte
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.Method, rec.Path = r.Method, r.URL.Path
		rec.Body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture(t, file))
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

// Verdict fields surface unmodified into the report (T-06.5 acceptance):
// Raw is the exact response body, byte for byte.
func TestMatchCertificateGolden(t *testing.T) {
	srv, rec := matchServer(t, "match-passed.json")
	c := newTestClient(t, srv, newClock(t0))
	certDER := fixtureCert(t).Raw

	v, err := c.MatchCertificate(context.Background(), certDER)
	if err != nil {
		t.Fatalf("MatchCertificate: %v", err)
	}
	if rec.Method != http.MethodPost || rec.Path != "/v1/match" {
		t.Errorf("request = %s %s, want POST /v1/match", rec.Method, rec.Path)
	}
	var req struct {
		CertDER []byte `json:"certDer"`
	}
	mustUnmarshal(t, rec.Body, &req)
	if !bytes.Equal(req.CertDER, certDER) {
		t.Error("request certDer does not round-trip the input DER")
	}
	if v.Verdict != "PASSED" {
		t.Errorf("Verdict = %q, want PASSED", v.Verdict)
	}
	if v.Snapshot != snapV1 {
		t.Errorf("Snapshot = %q, want %q", v.Snapshot, snapV1)
	}
	if want := time.Date(2026, 7, 1, 6, 5, 0, 0, time.UTC); !v.CheckedAt.Equal(want) {
		t.Errorf("CheckedAt = %v, want %v", v.CheckedAt, want)
	}
	if !bytes.Equal(v.Raw, fixture(t, "match-passed.json")) {
		t.Error("Raw != fixture bytes — verdict must surface unmodified")
	}
}

func TestMatchFailedVerdictUnmodified(t *testing.T) {
	srv, _ := matchServer(t, "match-failed.json")
	c := newTestClient(t, srv, newClock(t0))

	v, err := c.MatchCertificate(context.Background(), fixtureCert(t).Raw)
	if err != nil {
		t.Fatalf("MatchCertificate: %v (FAILED is a valid verdict, not an error)", err)
	}
	if v.Verdict != "FAILED" {
		t.Errorf("Verdict = %q, want FAILED", v.Verdict)
	}
	// The failing check detail must survive verbatim in Raw.
	var raw struct {
		Checks []struct {
			Name   string `json:"name"`
			Result string `json:"result"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
	mustUnmarshal(t, v.Raw, &raw)
	if len(raw.Checks) != 3 || raw.Checks[1].Detail != "service status withdrawn" {
		t.Errorf("Raw checks mangled: %+v", raw.Checks)
	}
}

// Unknown verdict = reject (fail closed), HTTP failure = ErrStatus /
// ErrUnavailable, empty input = ErrChainParse. Negative tests first.
func TestMatchCertificateErrors(t *testing.T) {
	t.Run("unknown_verdict", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"verdict":"MAYBE","snapshot":"x","checkedAt":"2026-07-01T06:05:00Z"}`))
		}))
		t.Cleanup(srv.Close)
		c := newTestClient(t, srv, newClock(t0))
		_, err := c.MatchCertificate(context.Background(), fixtureCert(t).Raw)
		if !errors.Is(err, trust.ErrSchema) {
			t.Fatalf("err = %v, want ErrSchema", err)
		}
	})
	t.Run("http_502", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		t.Cleanup(srv.Close)
		c := newTestClient(t, srv, newClock(t0))
		if _, err := c.MatchCertificate(context.Background(), fixtureCert(t).Raw); !errors.Is(err, trust.ErrStatus) {
			t.Fatalf("err = %v, want ErrStatus", err)
		}
	})
	t.Run("transport", func(t *testing.T) {
		c, err := trust.NewClient("https://trust.invalid", failingDoer{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.MatchCertificate(context.Background(), fixtureCert(t).Raw); !errors.Is(err, trust.ErrUnavailable) {
			t.Fatalf("err = %v, want ErrUnavailable", err)
		}
	})
	t.Run("empty_cert", func(t *testing.T) {
		c, err := trust.NewClient("https://trust.invalid", failingDoer{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.MatchCertificate(context.Background(), nil); !errors.Is(err, trust.ErrChainParse) {
			t.Fatalf("err = %v, want ErrChainParse", err)
		}
	})
}

// countingMatcher counts upstream calls for the cache tests.
type countingMatcher struct {
	mu    sync.Mutex
	calls int
	v     trust.MatchVerdict
	err   error
}

func (m *countingMatcher) MatchCertificate(context.Context, []byte) (trust.MatchVerdict, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.err != nil {
		return trust.MatchVerdict{}, m.err
	}
	return m.v, nil
}

func (m *countingMatcher) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func passedVerdict() trust.MatchVerdict {
	return trust.MatchVerdict{
		Verdict:   "PASSED",
		Snapshot:  snapV1,
		CheckedAt: t0,
		Raw:       json.RawMessage(`{"verdict":"PASSED"}`),
	}
}

// Verdict caching, short TTL (T-06.5): hit within TTL, keyed per
// certificate, expired entries refetched, errors never cached.
func TestVerdictCache(t *testing.T) {
	certA := fixtureCert(t).Raw
	certB := decodeFixtureAnchors(t, "anchors-pid-lv-v1.json")[1].Raw
	ctx := context.Background()

	t.Run("hit_within_ttl", func(t *testing.T) {
		clock := newClock(t0)
		up := &countingMatcher{v: passedVerdict()}
		vc, err := trust.NewVerdictCache(up, 5*time.Minute, clock.Now)
		if err != nil {
			t.Fatal(err)
		}
		for range 3 {
			v, err := vc.MatchCertificate(ctx, certA)
			if err != nil || v.Verdict != "PASSED" {
				t.Fatalf("verdict=%+v err=%v", v, err)
			}
		}
		if up.count() != 1 {
			t.Errorf("upstream calls = %d, want 1 (cached)", up.count())
		}
	})

	t.Run("keyed_per_certificate", func(t *testing.T) {
		clock := newClock(t0)
		up := &countingMatcher{v: passedVerdict()}
		vc, err := trust.NewVerdictCache(up, 5*time.Minute, clock.Now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := vc.MatchCertificate(ctx, certA); err != nil {
			t.Fatal(err)
		}
		if _, err := vc.MatchCertificate(ctx, certB); err != nil {
			t.Fatal(err)
		}
		if up.count() != 2 {
			t.Errorf("upstream calls = %d, want 2 (distinct certs)", up.count())
		}
	})

	t.Run("expired_refetches", func(t *testing.T) {
		clock := newClock(t0)
		up := &countingMatcher{v: passedVerdict()}
		vc, err := trust.NewVerdictCache(up, 5*time.Minute, clock.Now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := vc.MatchCertificate(ctx, certA); err != nil {
			t.Fatal(err)
		}
		clock.Advance(6 * time.Minute)
		if _, err := vc.MatchCertificate(ctx, certA); err != nil {
			t.Fatal(err)
		}
		if up.count() != 2 {
			t.Errorf("upstream calls = %d, want 2 (TTL expired)", up.count())
		}
	})

	t.Run("errors_not_cached", func(t *testing.T) {
		clock := newClock(t0)
		up := &countingMatcher{v: passedVerdict(), err: trust.ErrUnavailable}
		vc, err := trust.NewVerdictCache(up, 5*time.Minute, clock.Now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := vc.MatchCertificate(ctx, certA); !errors.Is(err, trust.ErrUnavailable) {
			t.Fatalf("err = %v, want ErrUnavailable", err)
		}
		up.mu.Lock()
		up.err = nil
		up.mu.Unlock()
		v, err := vc.MatchCertificate(ctx, certA)
		if err != nil || v.Verdict != "PASSED" {
			t.Fatalf("after recovery: verdict=%+v err=%v", v, err)
		}
		if up.count() != 2 {
			t.Errorf("upstream calls = %d, want 2 (error was not cached)", up.count())
		}
	})

	t.Run("constructor_validation", func(t *testing.T) {
		if _, err := trust.NewVerdictCache(nil, time.Minute, nil); err == nil {
			t.Error("nil matcher accepted")
		}
		if _, err := trust.NewVerdictCache(&countingMatcher{}, 0, nil); err == nil {
			t.Error("zero TTL accepted")
		}
	})
}

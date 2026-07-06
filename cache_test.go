package trust_test

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	trust "github.com/gmb-eudi/go-eudi-trust"
)

// stubClient scripts Client responses without HTTP (clock-driven tests).
type stubClient struct {
	mu    sync.Mutex
	sets  map[trust.AnchorType]trust.AnchorSet
	err   error
	calls []string // "type|territory|etag"
}

func (s *stubClient) Anchors(_ context.Context, t trust.AnchorType, territory, etag string) (trust.AnchorSet, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, string(t)+"|"+territory+"|"+etag)
	if s.err != nil {
		return trust.AnchorSet{}, false, s.err
	}
	set := s.sets[t]
	if etag != "" && etag == set.Snapshot {
		return trust.AnchorSet{}, false, nil // 304 — still fresh
	}
	return set, true, nil
}

func (s *stubClient) Snapshot(context.Context) (trust.SnapshotMeta, error) {
	return trust.SnapshotMeta{}, nil
}

func (s *stubClient) setErr(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

// testAnchor builds a synthetic anchor (self-signed CA parsed once per test
// run would be overkill here — cache logic never touches Cert contents, so a
// minimal parsed certificate from Task 2 fixtures is reused).
func testAnchor(t *testing.T, typ trust.AnchorType, country string, validUntil time.Time) trust.Anchor {
	t.Helper()
	return trust.Anchor{
		Cert:       fixtureCert(t),
		Type:       typ,
		Country:    country,
		Status:     statusGranted,
		ValidUntil: validUntil,
		TLSequence: 42,
	}
}

// fixtureCert parses the first certificate of the v1 fixture.
func fixtureCert(t *testing.T) *x509.Certificate {
	t.Helper()
	set := decodeFixtureAnchors(t, "anchors-pid-lv-v1.json")
	return set[0]
}

func decodeFixtureAnchors(t *testing.T, name string) []*x509.Certificate {
	t.Helper()
	var resp struct {
		Anchors []struct {
			CertDER []byte `json:"certDer"`
		} `json:"anchors"`
	}
	mustUnmarshal(t, fixture(t, name), &resp)
	out := make([]*x509.Certificate, 0, len(resp.Anchors))
	for _, a := range resp.Anchors {
		c, err := x509.ParseCertificate(a.CertDER)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func newCache(t *testing.T, client trust.Client, clock *fakeClock, grace time.Duration) *trust.CachingSource {
	t.Helper()
	src, err := trust.NewCachingSource(client, trust.CacheConfig{
		Types:  []trust.AnchorType{trust.PIDProvider},
		MaxAge: time.Hour,
		Grace:  map[trust.AnchorType]time.Duration{trust.PIDProvider: grace},
		Clock:  clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func freshStub(t *testing.T, clock *fakeClock) *stubClient {
	t.Helper()
	return &stubClient{sets: map[trust.AnchorType]trust.AnchorSet{
		trust.PIDProvider: {
			Anchors:  []trust.Anchor{testAnchor(t, trust.PIDProvider, "LV", clock.Now().Add(24*time.Hour))},
			Snapshot: "s1",
		},
	}}
}

// Clock-driven ladder (T-06.3 acceptance): fresh→serve; stale-within-grace→
// serve+flag; stale-beyond→ErrCacheExpired. Negative rungs must fail first.
func TestCacheFreshnessLadder(t *testing.T) {
	clock := newClock(t0)
	stub := freshStub(t, clock)
	src := newCache(t, stub, clock, 30*time.Minute) // MaxAge 1h, grace 30m

	if err := src.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// fresh → serve
	anchors, err := src.AnchorsFor(trust.PIDProvider, "LV")
	if err != nil || len(anchors) != 1 {
		t.Fatalf("fresh: anchors=%d err=%v, want 1/nil", len(anchors), err)
	}
	if st := src.Status(trust.PIDProvider); st.State != trust.StateFresh || st.Snapshot != "s1" {
		t.Errorf("fresh: Status = %+v", st)
	}

	// stale within grace → serve + flag
	clock.Advance(75 * time.Minute) // age 1h15m: past MaxAge, within grace
	anchors, err = src.AnchorsFor(trust.PIDProvider, "LV")
	if err != nil || len(anchors) != 1 {
		t.Fatalf("stale-within-grace: anchors=%d err=%v, want 1/nil", len(anchors), err)
	}
	if st := src.Status(trust.PIDProvider); st.State != trust.StateStale {
		t.Errorf("stale-within-grace: State = %v, want StateStale", st.State)
	}

	// stale beyond grace → fail closed
	clock.Advance(20 * time.Minute) // age 1h35m > 1h30m
	if _, err := src.AnchorsFor(trust.PIDProvider, "LV"); !errors.Is(err, trust.ErrCacheExpired) {
		t.Fatalf("beyond grace: err = %v, want ErrCacheExpired", err)
	}
	if st := src.Status(trust.PIDProvider); st.State != trust.StateExpired {
		t.Errorf("beyond grace: State = %v, want StateExpired", st.State)
	}
}

func TestCacheNeverRefreshedFailsClosed(t *testing.T) {
	clock := newClock(t0)
	src := newCache(t, freshStub(t, clock), clock, 0)
	if _, err := src.AnchorsFor(trust.PIDProvider, "LV"); !errors.Is(err, trust.ErrCacheExpired) {
		t.Fatalf("err = %v, want ErrCacheExpired before first Refresh", err)
	}
}

func TestCacheUnconfiguredTypeRejected(t *testing.T) {
	clock := newClock(t0)
	src := newCache(t, freshStub(t, clock), clock, 0)
	if _, err := src.AnchorsFor(trust.WalletProvider, "LV"); !errors.Is(err, trust.ErrUnknownAnchorType) {
		t.Fatalf("err = %v, want ErrUnknownAnchorType", err)
	}
}

// 304 revalidation restores freshness without replacing data.
func TestCacheRevalidation304(t *testing.T) {
	clock := newClock(t0)
	stub := freshStub(t, clock)
	src := newCache(t, stub, clock, 0)
	ctx := context.Background()

	if err := src.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	clock.Advance(50 * time.Minute)
	if err := src.Refresh(ctx); err != nil { // stub answers 304 for etag "s1"
		t.Fatal(err)
	}
	stub.mu.Lock()
	last := stub.calls[len(stub.calls)-1]
	stub.mu.Unlock()
	if last != "pid_provider||s1" {
		t.Errorf("revalidation call = %q, want pid_provider||s1 (If-None-Match with stored ETag)", last)
	}
	clock.Advance(50 * time.Minute) // 50m since revalidation < MaxAge 1h
	anchors, err := src.AnchorsFor(trust.PIDProvider, "LV")
	if err != nil || len(anchors) != 1 {
		t.Fatalf("after 304: anchors=%d err=%v, want 1/nil (FetchedAt renewed)", len(anchors), err)
	}
}

// Withdrawal via snapshot replacement (WP-06 Decisions / trust-anchor D9 —
// NOT a changes feed): the v2 fixture drops "LV PID Provider CA 2"; after
// the ETag changes, the withdrawn anchor is unusable on the next call.
func TestCacheWithdrawalViaSnapshotReplacement(t *testing.T) {
	srv, h := newFixtureServer(t, "anchors-pid-lv-v1.json")
	clock := newClock(t0)
	client, err := trust.NewClient(srv.URL, srv.Client(), trust.WithClock(clock.Now))
	if err != nil {
		t.Fatal(err)
	}
	src, err := trust.NewCachingSource(client, trust.CacheConfig{
		Types:     []trust.AnchorType{trust.PIDProvider},
		Territory: "LV",
		MaxAge:    time.Hour,
		Clock:     clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := src.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := src.AnchorsFor(trust.PIDProvider, "LV")
	if err != nil || len(before) != 2 {
		t.Fatalf("v1: anchors=%d err=%v, want 2/nil", len(before), err)
	}
	withdrawn := fingerprintOf(before[1].Cert) // CA 2 — dropped in v2

	h.SetFile("anchors-pid-lv-v2.json") // snapshot replaced upstream
	if err := src.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := src.AnchorsFor(trust.PIDProvider, "LV")
	if err != nil || len(after) != 1 {
		t.Fatalf("v2: anchors=%d err=%v, want 1/nil", len(after), err)
	}
	for _, a := range after {
		if fingerprintOf(a.Cert) == withdrawn {
			t.Fatal("withdrawn anchor still served after snapshot replacement")
		}
	}
	if st := src.Status(trust.PIDProvider); st.Snapshot != snapV2 {
		t.Errorf("Snapshot = %q, want %q (provenance follows the new ETag)", st.Snapshot, snapV2)
	}
}

func fingerprintOf(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// X-Trust-Stale (upstream degraded): never Fresh; only the grace window
// applies; grace 0 ⇒ fail closed immediately (docs/trust-service-api.md §4).
func TestCacheUpstreamStale(t *testing.T) {
	t.Run("within_grace_served_flagged", func(t *testing.T) {
		clock := newClock(t0)
		stub := freshStub(t, clock)
		set := stub.sets[trust.PIDProvider]
		set.Stale = true
		stub.sets[trust.PIDProvider] = set
		src := newCache(t, stub, clock, 30*time.Minute)
		if err := src.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
		anchors, err := src.AnchorsFor(trust.PIDProvider, "LV")
		if err != nil || len(anchors) != 1 {
			t.Fatalf("anchors=%d err=%v, want 1/nil", len(anchors), err)
		}
		st := src.Status(trust.PIDProvider)
		if st.State != trust.StateStale || !st.UpstreamStale {
			t.Errorf("Status = %+v, want StateStale + UpstreamStale", st)
		}
	})
	t.Run("grace_zero_fails_closed", func(t *testing.T) {
		clock := newClock(t0)
		stub := freshStub(t, clock)
		set := stub.sets[trust.PIDProvider]
		set.Stale = true
		stub.sets[trust.PIDProvider] = set
		src := newCache(t, stub, clock, 0)
		if err := src.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
		clock.Advance(time.Second)
		if _, err := src.AnchorsFor(trust.PIDProvider, "LV"); !errors.Is(err, trust.ErrCacheExpired) {
			t.Fatalf("err = %v, want ErrCacheExpired (upstream stale, no grace)", err)
		}
	})
}

// Refresh failure = carry-over: keep serving the old set until expiry, then
// fail closed; Refresh reports the error to the caller (worker alerting).
func TestCacheRefreshErrorCarryOver(t *testing.T) {
	clock := newClock(t0)
	stub := freshStub(t, clock)
	src := newCache(t, stub, clock, 0)
	ctx := context.Background()

	if err := src.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	stub.setErr(errors.New("upstream 503"))
	clock.Advance(30 * time.Minute)
	if err := src.Refresh(ctx); err == nil {
		t.Fatal("Refresh error swallowed; want joined error for worker alerting")
	}
	anchors, err := src.AnchorsFor(trust.PIDProvider, "LV")
	if err != nil || len(anchors) != 1 {
		t.Fatalf("carry-over: anchors=%d err=%v, want 1/nil (still within MaxAge)", len(anchors), err)
	}
	clock.Advance(31 * time.Minute) // past MaxAge, grace 0
	if _, err := src.AnchorsFor(trust.PIDProvider, "LV"); !errors.Is(err, trust.ErrCacheExpired) {
		t.Fatalf("err = %v, want ErrCacheExpired after carry-over ages out", err)
	}
}

// Per-anchor valid_until honored at serve time (ARF §6.6.3.2: an expired
// trust anchor must not validate anything).
func TestCachePerAnchorValidUntil(t *testing.T) {
	clock := newClock(t0)
	stub := &stubClient{sets: map[trust.AnchorType]trust.AnchorSet{
		trust.PIDProvider: {
			Anchors: []trust.Anchor{
				testAnchor(t, trust.PIDProvider, "LV", t0.Add(10*time.Minute)), // expires soon
				testAnchor(t, trust.PIDProvider, "LV", t0.Add(24*time.Hour)),
			},
			Snapshot: "s1",
		},
	}}
	src := newCache(t, stub, clock, 0)
	if err := src.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	anchors, err := src.AnchorsFor(trust.PIDProvider, "LV")
	if err != nil || len(anchors) != 2 {
		t.Fatalf("t0: anchors=%d err=%v, want 2/nil", len(anchors), err)
	}
	clock.Advance(20 * time.Minute) // first anchor now past ValidUntil
	anchors, err = src.AnchorsFor(trust.PIDProvider, "LV")
	if err != nil || len(anchors) != 1 {
		t.Fatalf("t0+20m: anchors=%d err=%v, want 1/nil (expired anchor dropped)", len(anchors), err)
	}
}

// Country filter: exact fold match; country=="" selects EU-level anchors
// only (territory "EU" or empty/overlay) — cross-country anchors are never
// mixed into a national query (feeds T-06.4 acceptance).
func TestCacheCountryFilter(t *testing.T) {
	clock := newClock(t0)
	valid := t0.Add(24 * time.Hour)
	stub := &stubClient{sets: map[trust.AnchorType]trust.AnchorSet{
		trust.PIDProvider: {
			Anchors: []trust.Anchor{
				testAnchor(t, trust.PIDProvider, "LV", valid),
				testAnchor(t, trust.PIDProvider, "EU", valid),
				testAnchor(t, trust.PIDProvider, "", valid), // manual overlay
				testAnchor(t, trust.PIDProvider, "EE", valid),
			},
			Snapshot: "s1",
		},
	}}
	src := newCache(t, stub, clock, 0)
	if err := src.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		country string
		want    int
	}{
		{"LV", 1},
		{"lv", 1}, // case-insensitive territory codes
		{"EE", 1},
		{"", 2}, // EU-level: "EU" + overlay ""
		{"DE", 0},
	}
	for _, tt := range tests {
		anchors, err := src.AnchorsFor(trust.PIDProvider, tt.country)
		if err != nil {
			t.Fatalf("country %q: %v", tt.country, err)
		}
		if len(anchors) != tt.want {
			t.Errorf("country %q: anchors = %d, want %d", tt.country, len(anchors), tt.want)
		}
	}
}

func TestNewCachingSourceValidation(t *testing.T) {
	clock := newClock(t0)
	stub := freshStub(t, clock)
	tests := []struct {
		name   string
		client trust.Client
		cfg    trust.CacheConfig
	}{
		{"nil_client", nil, trust.CacheConfig{Types: []trust.AnchorType{trust.PIDProvider}, MaxAge: time.Hour}},
		{"no_types", stub, trust.CacheConfig{MaxAge: time.Hour}},
		{"invalid_type", stub, trust.CacheConfig{Types: []trust.AnchorType{"bogus"}, MaxAge: time.Hour}},
		{"zero_max_age", stub, trust.CacheConfig{Types: []trust.AnchorType{trust.PIDProvider}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := trust.NewCachingSource(tt.client, tt.cfg); err == nil {
				t.Error("invalid config accepted")
			}
		})
	}
}

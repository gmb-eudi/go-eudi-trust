package trust_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	trust "github.com/gmb-eudi/go-eudi-trust"
)

// recorder collects StateChange events (callbacks are synchronous; the
// mutex guards against -race noise from parallel test helpers only).
type recorder struct {
	mu     sync.Mutex
	events []trust.StateChange
}

func (r *recorder) cb(ch trust.StateChange) {
	r.mu.Lock()
	r.events = append(r.events, ch)
	r.mu.Unlock()
}

func (r *recorder) all() []trust.StateChange {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]trust.StateChange, len(r.events))
	copy(out, r.events)
	return out
}

func newCacheWithCallback(t *testing.T, client trust.Client, clock *fakeClock, grace time.Duration, cb trust.StateCallback) *trust.CachingSource {
	t.Helper()
	src, err := trust.NewCachingSource(client, trust.CacheConfig{
		Types:         []trust.AnchorType{trust.PIDProvider},
		MaxAge:        time.Hour,
		Grace:         map[trust.AnchorType]time.Duration{trust.PIDProvider: grace},
		Clock:         clock.Now,
		OnStateChange: cb,
	})
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// Full lifecycle (T-06.6 acceptance: state transitions observable via the
// callback interface): Unknown→Fresh→Stale→Expired→Fresh, each fired
// exactly once, with snapshot id and injected-clock timestamps.
func TestStateTransitionLifecycle(t *testing.T) {
	clock := newClock(t0)
	stub := freshStub(t, clock)
	rec := &recorder{}
	src := newCacheWithCallback(t, stub, clock, 30*time.Minute, rec.cb)
	ctx := context.Background()

	// Unknown → Fresh (observed by Refresh)
	if err := src.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	// Fresh → Stale (observed by AnchorsFor after aging past MaxAge)
	clock.Advance(75 * time.Minute)
	if _, err := src.AnchorsFor(trust.PIDProvider, "LV"); err != nil {
		t.Fatal(err)
	}
	// Stale → Expired (observed by AnchorsFor, which now fails closed)
	clock.Advance(20 * time.Minute)
	if _, err := src.AnchorsFor(trust.PIDProvider, "LV"); !errors.Is(err, trust.ErrCacheExpired) {
		t.Fatalf("err = %v, want ErrCacheExpired", err)
	}
	// Expired → Fresh (successful refresh; stub serves a new snapshot when
	// the stored ETag no longer matches — set a new one to force a 200)
	stub.mu.Lock()
	set := stub.sets[trust.PIDProvider]
	set.Snapshot = "s2"
	set.Anchors = []trust.Anchor{testAnchor(t, trust.PIDProvider, "LV", clock.Now().Add(24*time.Hour))}
	stub.sets[trust.PIDProvider] = set
	stub.mu.Unlock()
	if err := src.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	want := []struct {
		from, to trust.SourceState
		snapshot string
	}{
		{trust.StateUnknown, trust.StateFresh, "s1"},
		{trust.StateFresh, trust.StateStale, "s1"},
		{trust.StateStale, trust.StateExpired, "s1"},
		{trust.StateExpired, trust.StateFresh, "s2"},
	}
	events := rec.all()
	if len(events) != len(want) {
		t.Fatalf("events = %d (%+v), want %d", len(events), events, len(want))
	}
	for i, w := range want {
		e := events[i]
		if e.Type != trust.PIDProvider {
			t.Errorf("event %d: Type = %q", i, e.Type)
		}
		if e.From != w.from || e.To != w.to {
			t.Errorf("event %d: %v→%v, want %v→%v", i, e.From, e.To, w.from, w.to)
		}
		if e.Snapshot != w.snapshot {
			t.Errorf("event %d: Snapshot = %q, want %q", i, e.Snapshot, w.snapshot)
		}
		if e.At.IsZero() || e.At.Before(t0) {
			t.Errorf("event %d: At = %v, want injected clock time ≥ t0", i, e.At)
		}
	}
}

// Edge-triggered: repeated observations in the same state fire nothing.
func TestStateNoDuplicateEvents(t *testing.T) {
	clock := newClock(t0)
	rec := &recorder{}
	src := newCacheWithCallback(t, freshStub(t, clock), clock, 0, rec.cb)

	if err := src.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, err := src.AnchorsFor(trust.PIDProvider, "LV"); err != nil {
			t.Fatal(err)
		}
		_ = src.Status(trust.PIDProvider)
	}
	if events := rec.all(); len(events) != 1 {
		t.Fatalf("events = %d (%+v), want exactly 1 (Unknown→Fresh)", len(events), events)
	}
}

// Status/States also observe transitions (a health endpoint polling States
// must flip the state and fire the callback even if AnchorsFor is idle).
func TestStatesObservesAndReportsAllTypes(t *testing.T) {
	clock := newClock(t0)
	stub := freshStub(t, clock)
	stub.sets[trust.AccessCA] = trust.AnchorSet{
		Anchors:  []trust.Anchor{testAnchor(t, trust.AccessCA, "EU", clock.Now().Add(24*time.Hour))},
		Snapshot: "s1",
	}
	rec := &recorder{}
	src, err := trust.NewCachingSource(stub, trust.CacheConfig{
		Types:         []trust.AnchorType{trust.PIDProvider, trust.AccessCA},
		MaxAge:        time.Hour,
		Clock:         clock.Now,
		OnStateChange: rec.cb,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := src.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Hour) // both types past MaxAge, grace 0 ⇒ Expired

	states := src.States()
	if len(states) != 2 {
		t.Fatalf("States() = %d entries, want 2", len(states))
	}
	if states[0].Type != trust.PIDProvider || states[1].Type != trust.AccessCA {
		t.Errorf("States() order = %v,%v — want config order", states[0].Type, states[1].Type)
	}
	for _, st := range states {
		if st.State != trust.StateExpired {
			t.Errorf("%s: State = %v, want StateExpired", st.Type, st.State)
		}
	}
	// Events: 2× Unknown→Fresh (Refresh) + 2× Fresh→Expired (States).
	if events := rec.all(); len(events) != 4 {
		t.Fatalf("events = %d (%+v), want 4", len(events), events)
	}
}

// A nil callback stays safe (Task 4's tests already run without one; this
// pins it explicitly).
func TestStateNilCallbackSafe(t *testing.T) {
	clock := newClock(t0)
	src := newCache(t, freshStub(t, clock), clock, 0)
	if err := src.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Hour)
	if _, err := src.AnchorsFor(trust.PIDProvider, "LV"); !errors.Is(err, trust.ErrCacheExpired) {
		t.Fatalf("err = %v, want ErrCacheExpired (and no panic)", err)
	}
}

func TestSourceStateString(t *testing.T) {
	tests := []struct {
		s    trust.SourceState
		want string
	}{
		{trust.StateUnknown, "unknown"},
		{trust.StateFresh, "fresh"},
		{trust.StateStale, "stale"},
		{trust.StateExpired, "expired"},
		{trust.SourceState(42), "state(42)"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("String(%d) = %q, want %q", int(tt.s), got, tt.want)
		}
	}
}

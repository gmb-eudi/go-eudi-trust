package trust

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// AnchorSource is what the verification pipeline consumes: anchors served from memory, fed by
// trust-cache-worker via Refresh. Implemented by CachingSource.
type AnchorSource interface {
	// AnchorsFor returns the usable anchors of one type for one country
	// ("" = EU-level lists only). ErrCacheExpired when the cache is stale
	// beyond grace or never filled (fail closed).
	AnchorsFor(t AnchorType, country string) ([]Anchor, error)
}

// CacheConfig configures a CachingSource. The refresh LOOP lives in the
// consuming service (trust-cache-worker) — this library runs no goroutines
// or timers; it only exposes the Refresh hook.
type CacheConfig struct {
	// Types to maintain. Required, non-empty, all valid taxonomy values.
	Types []AnchorType
	// Territory restricts upstream fetches ("" = all territories).
	Territory string
	// MaxAge is the freshness window measured from FetchedAt. Required > 0.
	MaxAge time.Duration
	// Grace extends serving per type beyond MaxAge (served stale + flagged).
	// Types without an entry get zero grace: stale = expired immediately.
	Grace map[AnchorType]time.Duration
	// Clock is the injected time source. Defaults to time.Now().UTC.
	Clock func() time.Time
	// OnStateChange is invoked synchronously on every per-type state
	// transition (edge-triggered). Optional. See StateCallback.
	OnStateChange StateCallback
}

type cacheEntry struct {
	set       AnchorSet
	etag      string
	haveData  bool
	lastState SourceState // zero value = StateUnknown
}

// CachingSource is the in-memory AnchorSource fed by Refresh. Safe for
// concurrent use. The ONLY path from the trust service to the pipeline.
type CachingSource struct {
	client  Client
	cfg     CacheConfig
	mu      sync.Mutex
	entries map[AnchorType]*cacheEntry
}

var _ AnchorSource = (*CachingSource)(nil)

// NewCachingSource validates the config and returns an empty (fail-closed)
// source: every type is StateUnknown until its first successful Refresh.
func NewCachingSource(client Client, cfg CacheConfig) (*CachingSource, error) {
	if client == nil {
		return nil, errors.New("trust: nil client")
	}
	if len(cfg.Types) == 0 {
		return nil, errors.New("trust: CacheConfig.Types is required")
	}
	for _, t := range cfg.Types {
		if !ValidAnchorType(t) {
			return nil, fmt.Errorf("%w: %q", ErrUnknownAnchorType, t)
		}
	}
	if cfg.MaxAge <= 0 {
		return nil, errors.New("trust: CacheConfig.MaxAge must be > 0")
	}
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time { return time.Now().UTC() }
	}
	entries := make(map[AnchorType]*cacheEntry, len(cfg.Types))
	for _, t := range cfg.Types {
		entries[t] = &cacheEntry{}
	}
	return &CachingSource{client: client, cfg: cfg, entries: entries}, nil
}

// Now exposes the injected clock. ResolveIssuerKey uses it for
// [RFC 5280 §6.1] time checks so the whole trust path shares one time source.
func (s *CachingSource) Now() time.Time { return s.cfg.Clock() }

// Refresh fetches every configured type once with If-None-Match
// revalidation — the hook the trust-cache-worker loop calls.
//
// Trust-service API contract (ETag polling, no changes
// cursor): a 304 confirms the cached snapshot is still current (FetchedAt
// renewed); a 200 with a new ETag carries the COMPLETE new set which fully
// REPLACES the cached one — anchor withdrawal arrives exactly this way and
// the withdrawn anchor is unusable on the next AnchorsFor.
// Fetch errors keep the previous set (carry-over) and are returned joined;
// the entry keeps aging toward fail-closed expiry.
// State transitions observed here fire the OnStateChange callback.
func (s *CachingSource) Refresh(ctx context.Context) error {
	var errs []error
	for _, t := range s.cfg.Types {
		s.mu.Lock()
		etag := s.entries[t].etag
		s.mu.Unlock()

		set, ok, err := s.client.Anchors(ctx, t, s.cfg.Territory, etag)

		s.mu.Lock()
		e := s.entries[t]
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("refresh %s: %w", t, err))
		case !ok: // 304 — same snapshot, freshness window restarts
			e.set.FetchedAt = s.cfg.Clock()
		default:
			set.FetchedAt = s.cfg.Clock() // cache ages by its own clock
			e.set = set
			e.etag = set.Snapshot
			e.haveData = true
		}
		_, change := s.observe(t, e, s.cfg.Clock())
		s.mu.Unlock()
		s.fire(change)
	}
	return errors.Join(errs...)
}

// stateOf derives the fail-closed state ladder. Upstream-flagged staleness
// (X-Trust-Stale) voids the MaxAge freshness window: only the grace window
// (from FetchedAt) applies, and grace 0 fails closed immediately.
func (s *CachingSource) stateOf(e *cacheEntry, t AnchorType, now time.Time) SourceState {
	if !e.haveData {
		return StateUnknown
	}
	age := now.Sub(e.set.FetchedAt)
	grace := s.cfg.Grace[t]
	deadline := s.cfg.MaxAge + grace
	if e.set.Stale {
		deadline = grace
	}
	switch {
	case age > deadline:
		return StateExpired
	case e.set.Stale || age > s.cfg.MaxAge:
		return StateStale
	default:
		return StateFresh
	}
}

// observe computes the current state under the lock, records an
// edge-triggered transition, and returns the state plus the change to fire
// AFTER the lock is released (nil when the state did not move).
func (s *CachingSource) observe(t AnchorType, e *cacheEntry, now time.Time) (SourceState, *StateChange) {
	st := s.stateOf(e, t, now)
	if st == e.lastState {
		return st, nil
	}
	change := &StateChange{Type: t, From: e.lastState, To: st, Snapshot: e.set.Snapshot, At: now}
	e.lastState = st
	return st, change
}

// fire delivers a pending change to the configured callback (lock NOT held).
func (s *CachingSource) fire(changes ...*StateChange) {
	if s.cfg.OnStateChange == nil {
		return
	}
	for _, ch := range changes {
		if ch != nil {
			s.cfg.OnStateChange(*ch)
		}
	}
}

// AnchorsFor implements AnchorSource. Fail closed: StateUnknown/StateExpired
// ⇒ ErrCacheExpired (services map to err:trust:anchor-unavailable);
// StateStale serves with the flag observable via Status/StateCallback.
// Per-anchor validity: anchors past ValidUntil are never served
// ([ARF §6.6.3.2]: an expired trust anchor must not validate anything).
func (s *CachingSource) AnchorsFor(t AnchorType, country string) ([]Anchor, error) {
	s.mu.Lock()
	e, ok := s.entries[t]
	if !ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: %q not configured on this source", ErrUnknownAnchorType, t)
	}
	now := s.cfg.Clock()
	st, change := s.observe(t, e, now)
	if st == StateUnknown || st == StateExpired {
		s.mu.Unlock()
		s.fire(change)
		return nil, fmt.Errorf("%w: %s anchors are %s", ErrCacheExpired, t, st)
	}
	var out []Anchor
	for _, a := range e.set.Anchors {
		if !matchesCountry(a.Country, country) {
			continue
		}
		if !a.ValidUntil.After(now) {
			continue // expired anchor — fail closed per anchor
		}
		out = append(out, a)
	}
	s.mu.Unlock()
	s.fire(change)
	return out, nil
}

// matchesCountry: country=="" selects EU-level anchors only (territory "EU"
// or empty = manual overlay); cross-country anchors are honored only via
// the EU-level query. Codes compare case-folded.
func matchesCountry(anchorCountry, query string) bool {
	if query == "" {
		return anchorCountry == "" || strings.EqualFold(anchorCountry, "EU")
	}
	return strings.EqualFold(anchorCountry, query)
}

// Status reports the serve-time status of one type (health + provenance).
// Observing a transition here fires the callback.
func (s *CachingSource) Status(t AnchorType) SourceStatus {
	s.mu.Lock()
	e, ok := s.entries[t]
	if !ok {
		s.mu.Unlock()
		return SourceStatus{Type: t, State: StateUnknown}
	}
	now := s.cfg.Clock()
	st, change := s.observe(t, e, now)
	status := SourceStatus{
		Type:          t,
		State:         st,
		Snapshot:      e.set.Snapshot,
		FetchedAt:     e.set.FetchedAt,
		UpstreamStale: e.set.Stale,
	}
	s.mu.Unlock()
	s.fire(change)
	return status
}

// States reports every configured type in config order — one call for a
// consumer /health endpoint (staleness state for /health of
// consumers). Observed transitions fire the callback.
func (s *CachingSource) States() []SourceStatus {
	s.mu.Lock()
	now := s.cfg.Clock()
	out := make([]SourceStatus, 0, len(s.cfg.Types))
	changes := make([]*StateChange, 0, len(s.cfg.Types))
	for _, t := range s.cfg.Types {
		e := s.entries[t]
		st, change := s.observe(t, e, now)
		changes = append(changes, change)
		out = append(out, SourceStatus{
			Type:          t,
			State:         st,
			Snapshot:      e.set.Snapshot,
			FetchedAt:     e.set.FetchedAt,
			UpstreamStale: e.set.Stale,
		})
	}
	s.mu.Unlock()
	s.fire(changes...)
	return out
}

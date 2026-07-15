package trust

import (
	"fmt"
	"time"
)

// SourceState is the degraded-mode state of one anchor type in a
// CachingSource. The ladder implements the fail-closed staleness policy of
// docs/trust-service-api.md §4: X-Trust-Stale or cache older than MaxAge ⇒
// degraded; beyond the per-type grace ⇒ fail closed.
type SourceState int

const (
	// StateUnknown means no successful fetch has happened yet — serving
	// fails closed.
	StateUnknown SourceState = iota
	// StateFresh means the cache is within MaxAge and not flagged stale
	// upstream.
	StateFresh
	// StateStale means the cache is past MaxAge but within grace, or
	// upstream flagged X-Trust-Stale — served WITH the flag
	// (Status/StateCallback).
	StateStale
	// StateExpired means the cache is past the deadline — AnchorsFor
	// returns ErrCacheExpired.
	StateExpired
)

// String implements fmt.Stringer (health endpoints, tests).
func (s SourceState) String() string {
	switch s {
	case StateUnknown:
		return "unknown"
	case StateFresh:
		return "fresh"
	case StateStale:
		return "stale"
	case StateExpired:
		return "expired"
	default:
		return fmt.Sprintf("state(%d)", int(s))
	}
}

// SourceStatus is a serve-time status snapshot for one anchor type —
// consumers surface it in /health and in verification-report provenance.
type SourceStatus struct {
	Type          AnchorType
	State         SourceState
	Snapshot      string    // snapshot id of the cached set ("" while Unknown)
	FetchedAt     time.Time // zero while Unknown
	UpstreamStale bool      // X-Trust-Stale / body stale on the last 200
}

// StateChange is one observed per-type state transition of a CachingSource.
type StateChange struct {
	Type     AnchorType
	From, To SourceState
	Snapshot string    // snapshot id of the cached set ("" while Unknown)
	At       time.Time // injected-clock time of the observation
}

// StateCallback receives state transitions synchronously, in the goroutine
// of the Refresh/AnchorsFor/Status/States call that observed the change,
// WITHOUT the cache lock held (re-entrant calls into the source are safe).
// The library never logs (ADR-0004) — consumers turn transitions into
// /health state and metrics (WP-09 eudi-verifier-core, WP-12 trust-cache-worker).
// Callbacks must be fast and non-blocking.
type StateCallback func(StateChange)

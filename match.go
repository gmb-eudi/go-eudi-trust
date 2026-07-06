package trust

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gmb-eudi/go-eudi-trust/internal/wire"
)

// MatchVerdict is an ETSI TS 119 615 certificate-vs-trusted-list verdict
// from the trust service. Raw carries the full response body UNMODIFIED —
// it is surfaced verbatim into the verification report (T-06.5 acceptance:
// verdict fields surface unmodified).
type MatchVerdict struct {
	Verdict   string // TS 119 615 §4.4: PASSED | FAILED | WARNING
	Snapshot  string
	CheckedAt time.Time
	Raw       json.RawMessage
}

// Matcher is the MatchCertificate capability. *HTTPClient implements it;
// *VerdictCache decorates any Matcher.
type Matcher interface {
	MatchCertificate(ctx context.Context, certDER []byte) (MatchVerdict, error)
}

var (
	_ Matcher = (*HTTPClient)(nil)
	_ Matcher = (*VerdictCache)(nil)
)

// MatchCertificate calls POST /v1/match (trust-anchor extension E4 — the
// recorded fixtures under testdata/trust/ are the contract until the
// endpoint lands upstream; WP-06 Decisions). v1 verification does NOT
// depend on it: chains are validated locally by ResolveIssuerKey; this
// passthrough exists for report enrichment where a server-side
// TS 119 615 §4.3/§4.4 verdict is wanted.
func (c *HTTPClient) MatchCertificate(ctx context.Context, certDER []byte) (MatchVerdict, error) {
	if len(certDER) == 0 {
		return MatchVerdict{}, fmt.Errorf("%w: empty certificate", ErrChainParse)
	}
	body, err := json.Marshal(struct {
		CertDER []byte `json:"certDer"`
	}{CertDER: certDER})
	if err != nil {
		return MatchVerdict{}, fmt.Errorf("trust: encode match request: %w", err)
	}
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/match"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return MatchVerdict{}, fmt.Errorf("trust: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.doer.Do(req)
	if err != nil {
		return MatchVerdict{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer drainClose(resp)
	if resp.StatusCode != http.StatusOK {
		return MatchVerdict{}, fmt.Errorf("%w: %d on /v1/match", ErrStatus, resp.StatusCode)
	}
	raw, err := readBody(resp)
	if err != nil {
		return MatchVerdict{}, err
	}
	dec, err := wire.DecodeMatch(raw)
	if err != nil {
		return MatchVerdict{}, fmt.Errorf("%w: %v", ErrSchema, err)
	}
	return MatchVerdict{
		Verdict:   dec.Verdict,
		Snapshot:  dec.Snapshot,
		CheckedAt: dec.CheckedAt,
		Raw:       json.RawMessage(raw),
	}, nil
}

// VerdictCache caches verdicts by certificate SHA-256 for a short TTL
// (T-06.5). Verdicts are snapshot-scoped and cheap to refetch — consuming
// services should keep the TTL low (order of minutes). Errors are never
// cached. Safe for concurrent use.
type VerdictCache struct {
	next  Matcher
	ttl   time.Duration
	clock func() time.Time
	mu    sync.Mutex
	m     map[string]verdictEntry
}

type verdictEntry struct {
	v       MatchVerdict
	expires time.Time
}

// NewVerdictCache decorates next with a TTL cache. clock nil ⇒ time.Now().UTC.
func NewVerdictCache(next Matcher, ttl time.Duration, clock func() time.Time) (*VerdictCache, error) {
	if next == nil {
		return nil, errors.New("trust: nil matcher")
	}
	if ttl <= 0 {
		return nil, errors.New("trust: verdict TTL must be > 0")
	}
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &VerdictCache{next: next, ttl: ttl, clock: clock, m: map[string]verdictEntry{}}, nil
}

// MatchCertificate implements Matcher with cache-aside semantics.
func (v *VerdictCache) MatchCertificate(ctx context.Context, certDER []byte) (MatchVerdict, error) {
	sum := sha256.Sum256(certDER)
	key := hex.EncodeToString(sum[:])
	now := v.clock()

	v.mu.Lock()
	if e, ok := v.m[key]; ok && now.Before(e.expires) {
		v.mu.Unlock()
		return e.v, nil
	}
	v.mu.Unlock()

	verdict, err := v.next.MatchCertificate(ctx, certDER)
	if err != nil {
		return MatchVerdict{}, err // errors are never cached
	}
	v.mu.Lock()
	v.m[key] = verdictEntry{v: verdict, expires: now.Add(v.ttl)}
	v.mu.Unlock()
	return verdict, nil
}

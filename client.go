package trust

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gmb-eudi/go-eudi-trust/internal/wire"
)

// Doer is the injected HTTP transport. Services wire a
// DPoP-signing client, an mTLS *http.Client, or a plain internal-network
// client per TRUST_AUTH_MODE — this library never constructs transports or
// credentials (per the trust-service API contract).
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client is the typed trust-service API client.
// *HTTPClient implements it; CachingSource consumes it.
type Client interface {
	// Anchors fetches GET /v1/anchors.json?type=&territory= with
	// If-None-Match revalidation. ok=false on 304 (cache still fresh).
	Anchors(ctx context.Context, t AnchorType, territory string, etag string) (AnchorSet, bool, error)
	// Snapshot fetches GET /v1/snapshot.
	Snapshot(ctx context.Context) (SnapshotMeta, error)
}

// HTTPClient implements Client over an injected Doer.
type HTTPClient struct {
	base  *url.URL
	doer  Doer
	clock func() time.Time
}

var _ Client = (*HTTPClient)(nil)

// ClientOption configures HTTPClient.
type ClientOption func(*HTTPClient)

// WithClock injects the time source stamped into AnchorSet.FetchedAt
// (inject clocks). Defaults to time.Now().UTC.
func WithClock(clock func() time.Time) ClientOption {
	return func(c *HTTPClient) { c.clock = clock }
}

// NewClient builds a trust-service client for a base URL such as
// "https://trust-anchor.internal".
func NewClient(baseURL string, doer Doer, opts ...ClientOption) (*HTTPClient, error) {
	if doer == nil {
		return nil, fmt.Errorf("trust: nil doer")
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("trust: invalid base URL %q", baseURL)
	}
	c := &HTTPClient{base: u, doer: doer, clock: func() time.Time { return time.Now().UTC() }}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// maxBodyBytes bounds trust-service response bodies before decoding — the
// decoders are fuzzed, but the transport must still cap memory.
const maxBodyBytes = 32 << 20

func (c *HTTPClient) get(ctx context.Context, path string, query url.Values, etag string) (*http.Response, error) {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	if query != nil {
		u.RawQuery = query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("trust: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if etag != "" {
		// Strong quoted ETag — the snapshot id (trust-anchor routes/anchors.go).
		req.Header.Set("If-None-Match", `"`+strings.Trim(etag, `"`)+`"`)
	}
	resp, err := c.doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return resp, nil
}

func readBody(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: reading body: %w", ErrUnavailable, err)
	}
	return body, nil
}

func drainClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
}

// Anchors implements Client.
// Trust-service API contract: GET /v1/anchors.json with type=
// (+ optional territory=), If-None-Match revalidation (304 = freshness
// confirmation), X-Trust-Stale mapped onto AnchorSet.Stale. Contract
// strictness: schema violations (including missing valid_until and
// ETag/body snapshot divergence) fail closed with ErrSchema.
func (c *HTTPClient) Anchors(ctx context.Context, t AnchorType, territory, etag string) (AnchorSet, bool, error) {
	if !ValidAnchorType(t) {
		return AnchorSet{}, false, fmt.Errorf("%w: %q", ErrUnknownAnchorType, t)
	}
	q := url.Values{}
	q.Set("type", string(t))
	if territory != "" {
		q.Set("territory", territory)
	}
	resp, err := c.get(ctx, "/v1/anchors.json", q, etag)
	if err != nil {
		return AnchorSet{}, false, err
	}
	defer drainClose(resp)

	switch resp.StatusCode {
	case http.StatusNotModified:
		return AnchorSet{}, false, nil
	case http.StatusOK:
		// fall through to decoding
	default:
		return AnchorSet{}, false, fmt.Errorf("%w: %d on /v1/anchors.json", ErrStatus, resp.StatusCode)
	}

	body, err := readBody(resp)
	if err != nil {
		return AnchorSet{}, false, err
	}
	dec, err := wire.DecodeAnchors(body)
	if err != nil {
		return AnchorSet{}, false, fmt.Errorf("%w: %w", ErrSchema, err)
	}
	// The strong ETag IS the snapshot id — divergence means a broken proxy
	// or server; fail closed rather than record wrong provenance.
	if hdr := strings.Trim(resp.Header.Get("ETag"), `"`); hdr != "" && hdr != dec.Snapshot {
		return AnchorSet{}, false, fmt.Errorf("%w: ETag %q != body snapshot %q", ErrSchema, hdr, dec.Snapshot)
	}

	set := AnchorSet{
		Snapshot:  dec.Snapshot,
		Stale:     dec.Stale || strings.EqualFold(resp.Header.Get("X-Trust-Stale"), "true"),
		FetchedAt: c.clock(),
		Anchors:   make([]Anchor, 0, len(dec.Anchors)),
	}
	for i := range dec.Anchors {
		w := &dec.Anchors[i]
		cert, err := w.Certificate()
		if err != nil { // unreachable after DecodeAnchors; kept fail-closed
			return AnchorSet{}, false, fmt.Errorf("%w: anchor %d: %w", ErrSchema, i, err)
		}
		set.Anchors = append(set.Anchors, Anchor{
			Cert:       cert,
			Type:       t, // request-scoped: type= defines the returned set
			Country:    w.Territory,
			Status:     w.Status,
			ValidUntil: w.NotAfter,
			TLSequence: w.TLSequence,
			UseCases:   w.UseCases, // GAP-04: accredited EAA use cases (extension E2)
		})
	}
	return set, true, nil
}

// Snapshot implements Client (trust-service API contract: /v1/snapshot
// feeds trust-cache-worker telemetry).
func (c *HTTPClient) Snapshot(ctx context.Context) (SnapshotMeta, error) {
	resp, err := c.get(ctx, "/v1/snapshot", nil, "")
	if err != nil {
		return SnapshotMeta{}, err
	}
	defer drainClose(resp)
	if resp.StatusCode != http.StatusOK {
		return SnapshotMeta{}, fmt.Errorf("%w: %d on /v1/snapshot", ErrStatus, resp.StatusCode)
	}
	body, err := readBody(resp)
	if err != nil {
		return SnapshotMeta{}, err
	}
	dec, err := wire.DecodeSnapshot(body)
	if err != nil {
		return SnapshotMeta{}, fmt.Errorf("%w: %w", ErrSchema, err)
	}
	meta := SnapshotMeta{
		ID:               dec.ID,
		GeneratedAt:      dec.GeneratedAt,
		LOTLSequence:     dec.LOTLSequence,
		LOTLIssueTime:    dec.LOTLIssueTime,
		LOTLNextUpdate:   dec.LOTLNextUpdate,
		PendingAnchors:   len(dec.Pending),
		PendingBootstrap: len(dec.PendingBootstrap) > 0,
	}
	for _, tr := range dec.Territories {
		meta.Territories = append(meta.Territories, TerritoryStatus{
			Code:        tr.Code,
			TLSequence:  tr.TLSequence,
			NextUpdate:  tr.NextUpdate,
			Stale:       tr.Stale,
			CarriedOver: tr.CarriedOver,
			AnchorCount: tr.AnchorCount,
		})
	}
	return meta, nil
}

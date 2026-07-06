// Package wire holds the JSON DTOs of the trust-anchor service API,
// mirroring docs/trust-service-api.md and the service's
// routes/response/response.go + trust/anchor.go. Responses are UNTRUSTED
// input: every decoder is fuzzed and must not panic (CLAUDE.md rule 5).
//
// Contract strictness: required fields must be present and valid (fail
// closed); unknown fields are tolerated because the upstream API evolves
// additively (extensions E1–E3 never break existing consumers).
package wire

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrInvalid marks a contract-schema violation. The root trust package maps
// it to trust.ErrSchema; it never carries certificate bytes or attribute
// values — fingerprints, field names and indexes only.
var ErrInvalid = errors.New("wire: response violates trust-service contract")

// Anchor mirrors the trust-anchor service's trust.Anchor JSON, plus the
// additive verifier-contract field tlSequence (rides extension E3; the
// recorded fixtures are the contract until E3 lands upstream).
type Anchor struct {
	Territory          string    `json:"territory"`
	Source             string    `json:"source"`
	TSPName            string    `json:"tspName"`
	ServiceName        string    `json:"serviceName"`
	ServiceType        string    `json:"serviceType"`
	Status             string    `json:"status"`
	StatusStartingTime time.Time `json:"statusStartingTime"`
	CertDER            []byte    `json:"certDer"`
	FingerprintSHA256  string    `json:"fingerprintSha256"`
	Subject            string    `json:"subject"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	Qualifiers         []string  `json:"qualifiers,omitempty"`
	QCWithQSCD         bool      `json:"qcWithQscd"`
	Uses               []string  `json:"uses,omitempty"`
	// TLSequence is additive (absent on older servers ⇒ 0).
	TLSequence int64 `json:"tlSequence,omitempty"`
}

// AnchorsResponse mirrors GET /v1/anchors.json.
type AnchorsResponse struct {
	Snapshot    string    `json:"snapshot"`
	GeneratedAt time.Time `json:"generatedAt"`
	Stale       bool      `json:"stale"`
	Anchors     []Anchor  `json:"anchors"`
}

// TerritorySummary mirrors one territory entry of GET /v1/snapshot.
type TerritorySummary struct {
	Code              string     `json:"code"`
	TLSequence        int64      `json:"tlSequence"`
	IssueTime         time.Time  `json:"issueTime"`
	NextUpdate        *time.Time `json:"nextUpdate,omitempty"`
	Stale             bool       `json:"stale"`
	CarriedOver       bool       `json:"carriedOver,omitempty"`
	CarriedOverReason string     `json:"carriedOverReason,omitempty"`
	AnchorCount       int        `json:"anchorCount"`
}

// SnapshotResponse mirrors GET /v1/snapshot. Pending/PendingBootstrap/
// Bootstrap are kept raw — the verifier only needs presence/counts
// (docs/trust-service-api.md §4: pending bootstrap presence → ops alert).
type SnapshotResponse struct {
	ID               string             `json:"id"`
	PrevID           string             `json:"prevId,omitempty"`
	GeneratedAt      time.Time          `json:"generatedAt"`
	LOTLSequence     uint64             `json:"lotlSequence"`
	LOTLIssueTime    time.Time          `json:"lotlIssueTime"`
	LOTLNextUpdate   *time.Time         `json:"lotlNextUpdate,omitempty"`
	Territories      []TerritorySummary `json:"territories"`
	OverlayCount     int                `json:"overlayCount"`
	Pending          []json.RawMessage  `json:"pending,omitempty"`
	PendingBootstrap json.RawMessage    `json:"pendingBootstrap,omitempty"`
	Bootstrap        json.RawMessage    `json:"bootstrap,omitempty"`
}

// MatchResponse mirrors POST /v1/match (extension E4 — mock contract;
// ETSI TS 119 615 §4.4 verdicts).
type MatchResponse struct {
	Verdict   string          `json:"verdict"`
	Snapshot  string          `json:"snapshot"`
	CheckedAt time.Time       `json:"checkedAt"`
	Checks    json.RawMessage `json:"checks,omitempty"`
}

// DecodeAnchors decodes and validates a /v1/anchors.json body.
// docs/trust-service-api.md §4 + WP-06 T-06.2: required fields present,
// certDer parses, recomputed SHA-256 equals fingerprintSha256, and
// notAfter (valid_until) is non-zero — an anchor without an expiry cannot
// be aged fail-closed.
func DecodeAnchors(raw []byte) (*AnchorsResponse, error) {
	var resp AnchorsResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if resp.Snapshot == "" {
		return nil, fmt.Errorf("%w: missing snapshot id", ErrInvalid)
	}
	if resp.GeneratedAt.IsZero() {
		return nil, fmt.Errorf("%w: missing generatedAt", ErrInvalid)
	}
	for i := range resp.Anchors {
		if err := resp.Anchors[i].validate(); err != nil {
			return nil, fmt.Errorf("anchor %d: %w", i, err)
		}
	}
	return &resp, nil
}

// validate enforces per-anchor contract strictness. Error text carries
// fingerprints and field names only — never certificate bytes (rule 3).
func (a *Anchor) validate() error {
	if len(a.CertDER) == 0 {
		return fmt.Errorf("%w: missing certDer", ErrInvalid)
	}
	cert, err := x509.ParseCertificate(a.CertDER)
	if err != nil {
		return fmt.Errorf("%w: certDer does not parse as a certificate", ErrInvalid)
	}
	sum := sha256.Sum256(cert.Raw)
	if hex.EncodeToString(sum[:]) != strings.ToLower(a.FingerprintSHA256) {
		return fmt.Errorf("%w: fingerprint mismatch (advertised %q)", ErrInvalid, a.FingerprintSHA256)
	}
	if a.Status == "" {
		return fmt.Errorf("%w: missing status", ErrInvalid)
	}
	if a.NotAfter.IsZero() {
		return fmt.Errorf("%w: missing notAfter (valid_until)", ErrInvalid)
	}
	return nil
}

// Certificate parses certDer. Call after DecodeAnchors validated the anchor.
func (a *Anchor) Certificate() (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(a.CertDER)
	if err != nil {
		return nil, fmt.Errorf("%w: certDer does not parse as a certificate", ErrInvalid)
	}
	return cert, nil
}

// DecodeSnapshot decodes and validates a /v1/snapshot body.
func DecodeSnapshot(raw []byte) (*SnapshotResponse, error) {
	var resp SnapshotResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if resp.ID == "" {
		return nil, fmt.Errorf("%w: missing snapshot id", ErrInvalid)
	}
	if resp.GeneratedAt.IsZero() {
		return nil, fmt.Errorf("%w: missing generatedAt", ErrInvalid)
	}
	return &resp, nil
}

// DecodeMatch decodes and validates a /v1/match body (E4 mock contract).
// ETSI TS 119 615 §4.4: only PASSED/FAILED/WARNING are defined — an unknown
// verdict is rejected, never interpreted (CLAUDE.md rule 7).
func DecodeMatch(raw []byte) (*MatchResponse, error) {
	var resp MatchResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	switch resp.Verdict {
	case "PASSED", "FAILED", "WARNING":
	default:
		return nil, fmt.Errorf("%w: unknown verdict %q", ErrInvalid, resp.Verdict)
	}
	if resp.Snapshot == "" {
		return nil, fmt.Errorf("%w: missing snapshot id", ErrInvalid)
	}
	if resp.CheckedAt.IsZero() {
		return nil, fmt.Errorf("%w: missing checkedAt", ErrInvalid)
	}
	return &resp, nil
}

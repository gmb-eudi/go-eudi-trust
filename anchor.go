package trust

import (
	"crypto/x509"
	"time"
)

// AnchorType is the verifier anchor-type taxonomy — the values of the
// additive type= query parameter on /v1/anchors.json (trust-service
// extension E3, docs/trust-service-api.md §3). ARF §6.6.3.6 scopes which
// anchor type may authenticate which artefact; unknown type = reject.
type AnchorType string

// Anchor-type taxonomy values (docs/trust-service-api.md §3): the additive
// type= query parameter values accepted by /v1/anchors.json.
const (
	PIDProvider    AnchorType = "pid_provider"     // ARF §6.6.3.2: PID provider anchors
	QEAAProvider   AnchorType = "qeaa_provider"    // qualified EAA providers (qtsp-tl)
	PubEAAProvider AnchorType = "pub_eaa_provider" // public-body EAA providers
	EAAProvider    AnchorType = "eaa_provider"     // non-qualified EAA providers
	WalletProvider AnchorType = "wallet_provider"  // wallet-provider trusted list
	AccessCA       AnchorType = "access_ca"        // wallet Access-CA LoTE
	WRPRCIssuer    AnchorType = "wrprc_issuer"     // registrar / WRPRC issuer keys
	// PIDProviderStatus and its *_status siblings are status-list /
	// Identifiers-list signer anchors (ADR-0010, GAP-01): the status service
	// may be distinct from the issuer. Resolved status-first with issuer
	// fallback by verifier-core statusAnchorTypesFor (WP-09).
	PIDProviderStatus    AnchorType = "pid_provider_status"
	QEAAProviderStatus   AnchorType = "qeaa_provider_status"
	PubEAAProviderStatus AnchorType = "pub_eaa_provider_status"
	EAAProviderStatus    AnchorType = "eaa_provider_status"
)

// AnchorTypes lists every accepted taxonomy value.
var AnchorTypes = []AnchorType{
	PIDProvider, QEAAProvider, PubEAAProvider, EAAProvider,
	WalletProvider, AccessCA, WRPRCIssuer,
	PIDProviderStatus, QEAAProviderStatus, PubEAAProviderStatus, EAAProviderStatus,
}

// ValidAnchorType reports whether t is an accepted taxonomy value.
func ValidAnchorType(t AnchorType) bool {
	for _, v := range AnchorTypes {
		if t == v {
			return true
		}
	}
	return false
}

// StatusType maps an issuer provider anchor type to its status-signer
// counterpart (ADR-0010): PIDProvider→PIDProviderStatus, etc. ok is false for
// types with no status pairing (WalletProvider, AccessCA, WRPRCIssuer) and for
// the *_status types themselves. Keeps the provider↔status pairing authoritative
// in one place; consumers (verifier-core credtrust, GAP-03) derive status
// anchor types from issuer types instead of hardcoding the string mapping.
func StatusType(t AnchorType) (AnchorType, bool) {
	switch t { //nolint:exhaustive // only issuer provider types have a status pairing; every other AnchorType (including the *_status types themselves) falls through to the explicit default below.
	case PIDProvider:
		return PIDProviderStatus, true
	case QEAAProvider:
		return QEAAProviderStatus, true
	case PubEAAProvider:
		return PubEAAProviderStatus, true
	case EAAProvider:
		return EAAProviderStatus, true
	default:
		return "", false
	}
}

// Anchor is one trust anchor as consumed by the verification pipeline
// (WP-06 README target interface — binding).
type Anchor struct {
	Cert       *x509.Certificate
	Type       AnchorType
	Country    string    // TL territory code; "" or "EU" = EU-level list
	Status     string    // TS 119 612 service-status URI, verbatim
	ValidUntil time.Time // anchor cert notAfter — REQUIRED upstream (T-06.2)
	TLSequence int64     // sequence of the TL the anchor came from
	UseCases   []string  // GAP-04: EAA use cases this anchor is accredited for (from the trusted list); empty = not use-case-scoped
}

// AnchorSet is one 200 result of /v1/anchors.json: the COMPLETE anchor set
// of one type. A new snapshot (changed ETag) fully replaces the previous
// set — anchor withdrawal arrives as snapshot replacement; there is no
// changes cursor (WP-06 Decisions; trust-anchor D9).
type AnchorSet struct {
	Anchors   []Anchor
	Snapshot  string    // snapshot id == strong ETag; report provenance
	Stale     bool      // X-Trust-Stale / body stale: upstream degraded
	FetchedAt time.Time // injected clock at fetch; drives cache aging
}

// SnapshotMeta is the /v1/snapshot summary: LOTL sequence, per-territory
// staleness, pending bootstrap presence — trust-cache-worker telemetry
// (docs/trust-service-api.md §4).
type SnapshotMeta struct {
	ID               string
	GeneratedAt      time.Time
	LOTLSequence     uint64
	LOTLIssueTime    time.Time
	LOTLNextUpdate   *time.Time
	Territories      []TerritoryStatus
	PendingAnchors   int
	PendingBootstrap bool // staged OJ bootstrap awaiting approval → ops alert
}

// TerritoryStatus summarizes one territory of the snapshot.
type TerritoryStatus struct {
	Code        string
	TLSequence  int64
	NextUpdate  *time.Time
	Stale       bool
	CarriedOver bool
	AnchorCount int
}

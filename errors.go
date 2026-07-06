package trust

import "errors"

// Sentinel errors. Services map these to err:domain:reason problem codes
// (docs/conventions.md): ErrCacheExpired/ErrUnavailable →
// err:trust:anchor-unavailable, ErrChainUntrusted →
// err:credential:issuer-untrusted. This library never carries HTTP
// semantics or framework dependencies (ADR-0004). Error text never contains
// certificate bytes or attribute values (CLAUDE.md rule 3).
var (
	// ErrSchema: a trust-service response violates the contract in
	// docs/trust-service-api.md (missing valid_until, fingerprint mismatch,
	// ETag/body divergence, undecodable body). Fail closed.
	ErrSchema = errors.New("trust: trust-service response violates contract schema")
	// ErrStatus: unexpected HTTP status from the trust service.
	ErrStatus = errors.New("trust: unexpected trust-service HTTP status")
	// ErrUnavailable: transport-level failure reaching the trust service.
	ErrUnavailable = errors.New("trust: trust service unreachable")
	// ErrCacheExpired: the anchor cache for the requested type is beyond
	// MaxAge+grace, or was never filled (CLAUDE.md rule 7: fail closed).
	ErrCacheExpired = errors.New("trust: anchor cache expired")
	// ErrUnknownAnchorType: not one of the valid AnchorType taxonomy values
	// (see ValidAnchorType), or not configured on this source. Unknown =
	// reject, never fall through.
	ErrUnknownAnchorType = errors.New("trust: unknown anchor type")
	// ErrChainParse: the presented x5chain/x5c could not be parsed.
	ErrChainParse = errors.New("trust: issuer chain malformed")
	// ErrChainUntrusted: the chain does not terminate at any anchor of the
	// requested type in the resolution territories.
	ErrChainUntrusted = errors.New("trust: issuer chain does not reach a trust anchor")
)

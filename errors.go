package trust

import "errors"

// Sentinel errors. Services map these to err:domain:reason problem codes:
// ErrCacheExpired/ErrUnavailable →
// err:trust:anchor-unavailable, ErrChainUntrusted →
// err:credential:issuer-untrusted. This library never carries HTTP
// semantics or framework dependencies. Error text never contains
// certificate bytes or attribute values.
var (
	// ErrSchema: a trust-service response violates the trust-service API
	// contract (missing valid_until, fingerprint mismatch,
	// ETag/body divergence, undecodable body). Fail closed.
	ErrSchema = errors.New("trust: trust-service response violates contract schema")
	// ErrStatus: unexpected HTTP status from the trust service.
	ErrStatus = errors.New("trust: unexpected trust-service HTTP status")
	// ErrUnavailable: transport-level failure reaching the trust service.
	ErrUnavailable = errors.New("trust: trust service unreachable")
	// ErrCacheExpired: the anchor cache for the requested type is beyond
	// MaxAge+grace, or was never filled (fail closed).
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
	// ErrChainOutOfValidity: a certificate in the chain is outside its own
	// validity window at the validation time the caller supplied. Kept
	// distinct from ErrChainUntrusted deliberately: the remedy is the issuer's
	// certificate rotation, or the caller's choice of validation time — not a
	// missing trust anchor. Services map it to
	// err:credential:issuer-cert-expired.
	ErrChainOutOfValidity = errors.New("trust: certificate outside its validity window at the validation time")
)

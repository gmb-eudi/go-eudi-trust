package trust

import (
	stdcrypto "crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// ResolvedIssuer identifies the trust anchor an issuer chain resolved to.
// It is recorded verbatim in the verification-report provenance
// (territory resolution order recorded verbatim). It carries
// subjects, fingerprints and territory codes only — never key material or
// attribute values.
type ResolvedIssuer struct {
	Subject           string     // leaf certificate subject (RFC 2253 string)
	AnchorSubject     string     // matched anchor certificate subject
	AnchorFingerprint string     // SHA-256 hex of the matched anchor cert
	AnchorType        AnchorType // the type the caller demanded
	AnchorCountry     string     // anchor's territory verbatim ("EU"/"" = EU-level)
	TerritoriesTried  []string   // resolution order, verbatim (e.g. ["LV", ""])
	UseCases          []string   // matched anchor's accredited EAA use cases (Anchor.UseCases passthrough)
}

// clocked is the optional interface an AnchorSource implements to expose
// its injected time source. *CachingSource implements it (Now). A source
// without it falls back to time.Now().UTC() — production sources MUST
// provide Now (inject clocks into validity checks).
type clocked interface{ Now() time.Time }

func sourceNow(src AnchorSource) time.Time {
	if c, ok := src.(clocked); ok {
		return c.Now()
	}
	return time.Now().UTC()
}

// ResolveIssuerKey resolves an mdoc x5chain / SD-JWT x5c (raw DER
// certificates, leaf first) to a verified issuer public key against
// anchors of the required type.
//
// [ARF §6.6.3.2]: issuer chains terminate at the provider trust anchors from
// the trusted-list infrastructure. [ARF §6.6.3.6]: the anchor TYPE scopes
// what it may authenticate — the caller names the type and a chain to any
// other type fails (ErrChainUntrusted). Path validation is [RFC 5280 §6.1]
// via go-eudi-crypto.VerifyChain: explicit anchors only, required At time,
// never the system pool. EKU enforcement is the
// format profiles' concern, so no EKUs are passed here.
//
// Territory resolution order: the issuing territory from
// the certificate country attribute (leaf subject C, else leaf issuer C)
// first, then EU-level ("") — recorded verbatim in TerritoriesTried. A
// source error (e.g. ErrCacheExpired) aborts immediately: a degraded cache
// must not silently fall through to the next territory.
func ResolveIssuerKey(src AnchorSource, chain [][]byte, t AnchorType) (stdcrypto.PublicKey, ResolvedIssuer, error) {
	if !ValidAnchorType(t) {
		return nil, ResolvedIssuer{}, fmt.Errorf("%w: %q", ErrUnknownAnchorType, t)
	}
	if len(chain) == 0 {
		return nil, ResolvedIssuer{}, fmt.Errorf("%w: empty chain", ErrChainParse)
	}
	certs := make([]*x509.Certificate, 0, len(chain))
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, ResolvedIssuer{}, fmt.Errorf("%w: certificate %d does not parse", ErrChainParse, i)
		}
		certs = append(certs, c)
	}
	leaf, intermediates := certs[0], certs[1:]
	now := sourceNow(src)

	territories := territoryOrder(leaf)
	resolved := ResolvedIssuer{
		Subject:          leaf.Subject.String(),
		AnchorType:       t,
		TerritoriesTried: territories,
	}
	for _, terr := range territories {
		// AnchorsFor(t, terr) is trusted to have already scoped its result to
		// type t: the cache is keyed by AnchorType and the only writer is
		// Client.Anchors(ctx, t, ...) for that same type (cache.go Refresh),
		// so anchors here does not need an independent per-anchor Type==t
		// re-check — the trust service is the authoritative boundary for
		// type= filtering, and this correctness is enforced by construction.
		anchors, err := src.AnchorsFor(t, terr)
		if err != nil {
			return nil, ResolvedIssuer{}, fmt.Errorf("anchors for %s territory %q: %w", t, terr, err)
		}
		if len(anchors) == 0 {
			continue
		}
		anchorCerts := make([]*x509.Certificate, 0, len(anchors))
		for _, a := range anchors {
			anchorCerts = append(anchorCerts, a.Cert)
		}
		chains, err := eudicrypto.VerifyChain(leaf, intermediates, eudicrypto.ChainOptions{
			Anchors: anchorCerts,
			At:      now, // [RFC 5280 §6.1] time from the source's injected clock
		})
		if err != nil {
			continue // not trusted in this territory — try the next in order
		}
		root := chains[0][len(chains[0])-1]
		for _, a := range anchors {
			if a.Cert.Equal(root) {
				resolved.AnchorSubject = a.Cert.Subject.String()
				resolved.AnchorFingerprint = certFingerprint(a.Cert)
				resolved.AnchorCountry = a.Country
				resolved.UseCases = a.UseCases // GAP-04: surface accredited EAA use cases
				return leaf.PublicKey, resolved, nil
			}
		}
		// A verified chain must terminate at a supplied anchor; anything
		// else is unreachable — fail closed regardless.
		return nil, ResolvedIssuer{}, fmt.Errorf("%w: verified root not in anchor set", ErrChainUntrusted)
	}
	return nil, ResolvedIssuer{}, fmt.Errorf("%w: no %s anchor matched in territories %v", ErrChainUntrusted, t, territories)
}

// territoryOrder derives the resolution order from the certificate country
// attribute: leaf subject C, else leaf issuer C, always followed by
// EU-level "". Codes are upper-cased for TL territory
// comparison.
func territoryOrder(leaf *x509.Certificate) []string {
	if len(leaf.Subject.Country) > 0 && leaf.Subject.Country[0] != "" {
		return []string{strings.ToUpper(leaf.Subject.Country[0]), ""}
	}
	if len(leaf.Issuer.Country) > 0 && leaf.Issuer.Country[0] != "" {
		return []string{strings.ToUpper(leaf.Issuer.Country[0]), ""}
	}
	return []string{""}
}

func certFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

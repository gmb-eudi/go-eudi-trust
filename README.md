# go-eudi-trust

Verifier-side client for the EUDI trust-anchor service: typed API client
with strong-ETag polling, a fail-closed in-memory trust-anchor cache, and
issuer-chain resolution against typed anchor sets.

- `Client`: `GET /v1/anchors.json?type=&territory=` with `If-None-Match`
  revalidation (304 = freshness confirmation), `X-Trust-Stale` mapping,
  `GET /v1/snapshot` telemetry. Auth is an injected HTTP doer — wire DPoP,
  mTLS, or internal-network clients as your deployment requires.
- `CachingSource`: in-memory anchor source fed by an external refresh loop.
  Per-anchor-type grace windows; expired-beyond-grace fails closed with
  `ErrCacheExpired`. Degraded-mode state transitions are observable via a
  callback (the library never logs).
- `ResolveIssuerKey`: resolves an mdoc x5chain / SD-JWT x5c to a verified
  issuer key against anchors of the required type — issuing territory
  first, then EU-level — via go-eudi-crypto RFC 5280 path validation
  (explicit anchors only, no system pool). The **validation time is the
  caller's argument**, not this library's clock: a document signer is
  short-lived while the credentials it signed stay in wallets much longer, so
  only the caller knows whether the question is "was this issuer trusted when it
  signed" (pass the signing time) or "is it trusted now" (pass `Now(src)`). A
  certificate outside its own window at that time fails with
  `ErrChainOutOfValidity`, kept distinct from `ErrChainUntrusted` so an expiry is
  never reported as an unknown anchor.
- `MatchCertificate`: ETSI TS 119 615 verdict passthrough (server-side
  check, optional extension) with a short-TTL verdict cache.

This library NEVER parses ETSI TS 119 612 trusted-list XML. Trusted-list
ingestion, LOTL verification, and TS 119 612/615 processing live in the
trust-anchor service; this client consumes its JSON contract only.

Implemented contract: the verifier trust-service API (ETag polling against
snapshots, no changes cursor). See SPECREFS.md for pinned references.

Status: pre-v1. API frozen no earlier than OIDF conformance pass.

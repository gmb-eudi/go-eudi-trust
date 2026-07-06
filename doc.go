// Package trust is the verifier-side client for the central Trust Service
// (the trust-anchor service) — the ONLY path to trust anchors in the EUDI
// verifier: typed API client with ETag polling, a fail-closed in-memory
// anchor cache, and chain-resolution glue over go-eudi-crypto.
//
// The library is framework-free: it takes an injected HTTP Doer (services
// wire DPoP or internal-network auth per TRUST_AUTH_MODE), an injected
// clock, and returns typed errors. It never logs, never touches the system
// certificate pool, and never parses ETSI TS 119 612 trusted-list XML —
// trusted-list knowledge stays server-side.
package trust

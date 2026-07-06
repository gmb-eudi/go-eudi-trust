# Pinned specification versions

| Spec | Version pinned |
|---|---|
| Trust-service API contract | verifier `docs/trust-service-api.md` (reconciled 2026-07-03 against trust-anchor @ develop; recorded fixtures in `testdata/trust/` are the contract for extensions E1–E4) |
| EUDI ARF — trust anchor usage | 2.9, §6.6.3.2 / §6.6.3.6 |
| X.509 path validation | RFC 5280 §6.1 (delegated to go-eudi-crypto.VerifyChain) |
| TL conformance verdicts | ETSI TS 119 615 §4.3/§4.4 (server-side; verdict passthrough only) |
| Trusted lists | ETSI TS 119 612 — **server-side only; this library never parses TL XML** |
| EUDI service-type URIs | CID (EU) 2025/2164 — mock values until extension E1 lands (see testdata/trust/SOURCE.md) |

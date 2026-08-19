# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency.

## v0.1.0

### Changed — BREAKING

- **`ResolveIssuerKey` takes the validation time as a required fourth argument:**

  ```go
  // before
  ResolveIssuerKey(src, chain, anchorType)
  // after
  ResolveIssuerKey(src, chain, anchorType, at)
  ```

  It no longer reads the source's clock on the caller's behalf. A document signer is
  short-lived while the credentials it signed stay in wallets far longer, so only the caller
  knows whether the question is "was this issuer trusted when it signed" (pass the
  credential's signing time) or "is it trusted now" (pass `Now(src)`). A zero `at` is
  refused rather than defaulted — the choice has to be made, not inherited.

  **Migration:** `ResolveIssuerKey(src, chain, t, trust.Now(src))` reproduces the previous
  behaviour exactly.

### Added

- `Now(src AnchorSource) time.Time` — the source's injected clock, exported so that "these
  certificates must be valid now" is visible at the call site instead of defaulted inside
  this library.
- `ErrChainOutOfValidity` — a certificate involved in the decision was outside its own
  validity window at the validation time. This used to surface as `ErrChainUntrusted`, which
  sent operators hunting for a missing trust anchor when nothing was untrusted: an issuer
  rotating a document signer and an unknown issuer are different problems with different
  remedies. The error names the certificate, its window and the time used.

  One caveat worth knowing before you map it: a chain that is *both* out of window and
  unreachable is reported as out of window. Both statements are true; this is the one whose
  remedy differs.

### Notes

- Dependency update

- Path validation itself is unchanged — explicit anchors only, no system pool, and every
  certificate window is still asserted at the time you pass.

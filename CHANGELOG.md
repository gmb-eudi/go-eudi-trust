# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency.

## v0.1.2

Dependency maintenance. No source changed here and nothing this library does behaves differently.

### Notes

- **`github.com/gmb-eudi/go-eudi-crypto` → v0.0.8** (was v0.0.7). That release changed no source of
  its own either — it took `github.com/lestrrat-go/jwx/v3` to **v3.3.0** and `golang.org/x/crypto`
  to **v0.57.0**. Both reach this library only through it: **nothing here imports jwx**, it arrives
  as an indirect requirement. The `x/crypto` move crosses the release that fixed **GO-2026-6354**
  and **GO-2026-6355** upstream.

- The gate is green on the new set: `go mod verify`, `go mod tidy -diff`, build, vet, `gofmt`, and
  `go test -race` with **0 races**; `govulncheck` finds nothing.

- Repository hygiene, with no effect on code that uses the library: CI now also runs on pushes to
  `develop`, the pinned GitHub Actions moved to their current commits, the `setup-go` pin rolled forward, and a stray comment was dropped from `.gitattributes`.

## v0.1.1

Compatible: no signature changes, no message-text changes, nothing that passed before now
fails.

### Changed

- **Errors now wrap their cause as well as their sentinel — 10 sites** in `client.go`,
  `match.go` and `internal/wire`. Each was built as
  `fmt.Errorf("%w: …: %v", ErrSentinel, err)`: the sentinel wrapped, the cause printed into
  the string and then unreachable. Both are now `%w`.

  Here the distinction the sentinels draw is *unavailable* versus *schema*, and the cause is
  what tells you which flavour of unavailable you have — a timeout you should retry, or a
  refused connection you should not:

  ```go
  if errors.Is(err, ErrUnavailable) {
      var netErr net.Error
      if errors.As(err, &netErr) && netErr.Timeout() { /* retry */ }
  }
  ```

  `errors.Is(err, ErrUnavailable)` / `ErrSchema` / `ErrInvalid` still hold and every rendered
  message is byte-identical (`%v` and `%w` print an error the same way), so no existing caller
  needs to change.

### Dependencies

- `github.com/lestrrat-go/dsig` v1.3.0 → v1.4.0 (indirect).

### Notes

- The `go` directive is now `1.26.6`, which is the minimum Go version a consumer needs. The
  previous `1.26` resolved to whatever patch the toolchain happened to have; the exact patch
  is pinned because earlier 1.26 releases carry standard-library security fixes this library's
  callers should not silently miss.

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

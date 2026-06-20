# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-06-20

### Added

- Sender-constrained access tokens (RFC 9449 DPoP / RFC 8705 mTLS): the typed
  `cnf` confirmation claim (`Confirmation`, RFC 7800) with `jkt` and `x5t#S256`
  members, plus opt-in binding validation via `WithDPoPKeyThumbprint` and
  `WithCertificateThumbprint` (new `ErrConfirmationMismatch` sentinel). The
  caller computes the thumbprint from the verified DPoP proof / client
  certificate; the library checks the binding only.
- `Builder` — a fluent constructor for the authorization-server side, with
  `Build` (validates required claims) and `Encode`.
- `BearerToken(*http.Request)` — RFC 6750 §2.1 Authorization-header token
  extraction (new `ErrNoBearerToken` sentinel).
- `Parse` now reports a JWE (5-segment) token with `ErrEncrypted` instead of a
  generic malformed error, signalling the caller to decrypt upstream.

## [0.1.0] - 2026-06-20

### Added

- Typed `Claims` for the RFC 9068 §2.2 access-token claim set, with `Audience`
  (string-or-array) and `NumericDate` wire types and an `Extra` open-claims map
  for identity/extension claims (§2.2.2).
- `Parse` / `ParseClaims` decoders (base64url + JSON; no signature
  verification) and the minimal JOSE `Header` with `NewHeader`.
- `Claims.Validate` / `Token.Validate` for the §4 claim checks owned by this
  library — `typ` is `at+jwt` (§2.1), required claims present, `iss`
  exact-match, `aud` membership, `exp`/`nbf`/`iat` time validity — configurable
  via `WithIssuer`, `WithAudience`, `WithClock`, `WithLeeway`. Typed
  `*ValidationError` wrapping `errors.Is`-matchable sentinels.
- `Claims.Encode` (strict required-claim check at the marshal boundary) plus
  `ScopeValues`/`SetScope` and `GetExtra`/`SetExtra` helpers.

[Unreleased]: https://github.com/hstern/go-access-tokens/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/hstern/go-access-tokens/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/hstern/go-access-tokens/releases/tag/v0.1.0

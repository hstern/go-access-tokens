# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

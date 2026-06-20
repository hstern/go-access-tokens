# go-access-tokens

a typed parser and validator for RFC 9068 JWT-profile OAuth 2.0 access tokens.

Implements **RFC 9068 — JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens** (Proposed Standard (RFC 9068), 2021-10).
Spec: <https://www.rfc-editor.org/rfc/rfc9068.html>

## What this library is and is not

It is a claim-set codec for the RFC 9068 access token — typed Go
structs for the `at+jwt` header and the §2.2 claim set, a stdlib
(`encoding/base64` + `encoding/json`) decoder and encoder, and
validation of the §4 claim MUSTs (required claims present, `typ` is
`at+jwt`, `aud` names the resource server, time validity). Zero
non-test dependencies — standard library only.

It is not a JWT/JOSE stack. The following are deliberately out of
scope and belong in dedicated libraries:

- **JWS signature verification** (RFC 9068 §4, step 1). Verifying the
  token's signature is RFC 7515/7519 crypto — JWT-library work. Verify
  the JWS with a JOSE library (for example
  [`github.com/go-jose/go-jose`](https://github.com/go-jose/go-jose))
  and hand the verified token, or its claims, to this library.
- **Key discovery / JWKS.** Fetching and caching issuer signing keys
  is the JOSE / discovery layer's job.
- **Issuer & authorization-server metadata discovery** (RFC 8414, OIDC
  discovery). Sibling-library territory.
- **Opaque (non-JWT) access tokens.** Validated by introspection — see
  the sibling [`go-token-introspection`](https://github.com/hstern/go-token-introspection)
  (RFC 7662).

## Status

Bootstrap / pre-v0.1.0. The public API is not yet stable.

## Install

```bash
go get github.com/hstern/go-access-tokens
```

## License

Apache-2.0 — see [LICENSE](LICENSE).

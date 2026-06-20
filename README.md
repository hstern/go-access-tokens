# go-access-tokens

a typed parser and validator for RFC 9068 JWT-profile OAuth 2.0 access tokens.

Implements **RFC 9068 — JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens** (Proposed Standard (RFC 9068), 2021-10).
Spec: <https://www.rfc-editor.org/rfc/rfc9068.html>

## What this library is and is not

It is a claim-set codec for the RFC 9068 access token — typed Go
structs for the `at+jwt` header and the §2.2 claim set, a stdlib
(`encoding/base64` + `encoding/json`) decoder and encoder, and
validation of the §4 claim MUSTs (required claims present, `typ` is
`at+jwt`, `aud` names the resource server, time validity). It also
carries the `cnf` sender-constraining binding (RFC 9449 DPoP / RFC 8705
mTLS) and checks it on request, and provides a fluent `Builder` for the
producer side. Zero non-test dependencies — standard library only.

Bearer-token transport (RFC 6750 — pulling the token off the
`Authorization` header) is a separate concern and lives in
[`go-bearer-token`](https://github.com/hstern/go-bearer-token); a resource
server composes the two.

It is not a JWT/JOSE stack. The following are deliberately out of
scope and belong in dedicated libraries:

- **JWS signature verification** (RFC 9068 §4, step 1). Verifying the
  token's signature is RFC 7515/7519 crypto — JWT-library work. Verify
  the JWS with a JOSE library (for example
  [`github.com/go-jose/go-jose`](https://github.com/go-jose/go-jose))
  and hand the verified token, or its claims, to this library.
- **JWE decryption.** Encrypted access tokens are recognized (`Parse`
  returns `ErrEncrypted`) but not decrypted — decrypt with a JOSE
  library, then pass the plaintext payload to `ParseClaims`.
- **DPoP-proof / client-certificate verification.** The library checks
  that the token's `cnf` binding matches a thumbprint *you* supply; it
  does not verify the DPoP proof JWT or the TLS client certificate
  (that crypto is the caller's, same boundary as JWS verification).
- **Key discovery / JWKS.** Fetching and caching issuer signing keys
  is the JOSE / discovery layer's job.
- **Issuer & authorization-server metadata discovery** (RFC 8414, OIDC
  discovery). Sibling-library territory.
- **Opaque (non-JWT) access tokens.** Validated by introspection — see
  the sibling [`go-token-introspection`](https://github.com/hstern/go-token-introspection)
  (RFC 7662).

For worked examples of wiring [go-jose](https://github.com/go-jose/go-jose)
around this library for each of those crypto concerns — JWS verification,
JWE decryption, and DPoP / mTLS sender-constraint binding — see
**[docs/integration.md](docs/integration.md)**.

## Status

**v0.2.0.** Pre-1.0: the public API may still change within the `v0.x`
series per [SemVer](https://semver.org/). Runtime dependencies: standard
library only.

## Install

```bash
go get github.com/hstern/go-access-tokens
```

## Quickstart

### Resource server — validate an access token

Verify the JWS signature with your JOSE library first, then validate the
RFC 9068 claim profile (see [docs/integration.md](docs/integration.md) for the
go-jose verification, decryption, and DPoP/mTLS code):

```go
tok, err := accesstoken.Parse(rawToken) // decodes; does NOT verify the signature
if err != nil {
	// malformed token
}

// ... verify tok.Raw's JWS signature with your JOSE library here ...

err = tok.Validate(
	accesstoken.WithIssuer("https://as.example.com/"),
	accesstoken.WithAudience("https://rs.example.com/"), // this RS's identifier
)
if err != nil {
	// map any failure to RFC 6750 invalid_token / HTTP 401
	if errors.Is(err, accesstoken.ErrExpired) { /* ... */ }
}

subject := tok.Claims.Subject
scopes := tok.Claims.ScopeValues()
```

If your JOSE layer already handed you the verified payload bytes, skip `Parse`
and use `accesstoken.ParseClaims(payload)` + `claims.Validate(...)`.

### Authorization server — build an access token

```go
payload, err := accesstoken.NewBuilder().
	Issuer("https://as.example.com/").
	Subject("user-123").
	Audience("https://rs.example.com/").
	ClientID("client-abc").
	ID("id-1").
	Lifetime(time.Now(), time.Hour). // sets iat=now, exp=now+1h
	Scope("read", "write").
	Encode()                         // strict: errors if a required claim is missing

header := accesstoken.NewHeader("RS256", "key-1") // {"typ":"at+jwt",...}
// ... sign header + payload with your JOSE library ...
```

The plain `&accesstoken.Claims{...}` struct + `c.Encode()` works too if you
prefer it over the builder.

### Sender-constrained tokens (DPoP / mTLS)

Bind a token to a DPoP key (RFC 9449) or mTLS certificate (RFC 8705) when
issuing, and require the binding when validating. You compute the thumbprint
from the verified proof / certificate; the library checks the `cnf` claim:

```go
// issuing: bind to the DPoP key
payload, _ := accesstoken.NewBuilder().
	/* required claims … */
	DPoPKeyThumbprint(jkt). // RFC 7638 JWK thumbprint of the DPoP key
	Encode()

// resource server: pull the bearer token, then require the binding
raw, err := bearer.Token(req) // RFC 6750, from github.com/hstern/go-bearer-token
tok, _ := accesstoken.Parse(raw) // (verify its JWS signature out of band)
err = tok.Validate(
	accesstoken.WithIssuer("https://as.example.com/"),
	accesstoken.WithAudience("https://rs.example.com/"),
	accesstoken.WithDPoPKeyThumbprint(jktFromProof), // ErrConfirmationMismatch on miss
)
```

### Typed extension claims

Claims outside the typed §2.2 surface (identity claims, custom claims) round-trip
through `Extra`; read and write them typed:

```go
var email string
present, _ := tok.Claims.GetExtra("email", &email)

_ = c.SetExtra("tenant", Tenant{ID: 42, Name: "acme"})
```

## License

Apache-2.0 — see [LICENSE](LICENSE).

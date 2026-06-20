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

## Quickstart

### Resource server — validate an access token

Verify the JWS signature with your JOSE library first, then validate the
RFC 9068 claim profile:

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
c := &accesstoken.Claims{
	Issuer:   "https://as.example.com/",
	Subject:  "user-123",
	Audience: accesstoken.Audience{"https://rs.example.com/"},
	Expires:  accesstoken.NewNumericDate(time.Now().Add(time.Hour)),
	IssuedAt: accesstoken.NewNumericDate(time.Now()),
	JWTID:    "id-1",
	ClientID: "client-abc",
}
c.SetScope("read", "write")

payload, err := c.Encode()           // strict: errors if a required claim is missing
header := accesstoken.NewHeader("RS256", "key-1") // {"typ":"at+jwt",...}
// ... sign header + payload with your JOSE library ...
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

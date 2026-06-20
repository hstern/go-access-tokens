# Integrating with a JOSE library (go-jose)

`go-access-tokens` is a claim-set codec and validator. It deliberately does
**not** do cryptography: it never verifies a JWS signature, decrypts a JWE,
verifies a DPoP proof, or validates a TLS client certificate. Those are the
caller's job, handled by a JOSE library and the standard library. This keeps the
library at **zero runtime dependencies** (see the design rationale in the
README's "What this library is and is not").

This guide shows how to wire [`github.com/go-jose/go-jose/v4`][go-jose] (and
stdlib) around `go-access-tokens` for each crypto concern:

1. [Verify a signed access token (JWS)](#1-verify-a-signed-access-token-jws)
2. [Decrypt an encrypted access token (JWE)](#2-decrypt-an-encrypted-access-token-jwe)
3. [DPoP sender-constraining (RFC 9449)](#3-dpop-sender-constraining-rfc-9449)
4. [mTLS sender-constraining (RFC 8705)](#4-mtls-sender-constraining-rfc-8705)
5. [Key discovery (JWKS)](#5-key-discovery-jwks)

> `go-jose` is *your* dependency, not this library's. Add it to your own module:
>
> ```bash
> go get github.com/go-jose/go-jose/v4
> ```
>
> The snippets below abbreviate error handling and imports for readability.

## 1. Verify a signed access token (JWS)

The common case: the access token is a signed JWT. Verify the signature with
go-jose, then hand the verified payload bytes to `ParseClaims` and validate the
RFC 9068 claim profile. This one helper is reused by the DPoP and mTLS sections
below, which only add a binding option.

```go
import (
	"time"

	jose "github.com/go-jose/go-jose/v4"
	accesstoken "github.com/hstern/go-access-tokens"
)

// verifyAndValidate verifies the JWS signature of a compact access token with
// the issuer's public key, then validates the RFC 9068 claim profile. extra
// carries any additional options (e.g. a sender-constraint binding).
func verifyAndValidate(raw string, key any, extra ...accesstoken.Option) (*accesstoken.Claims, error) {
	// Pin the signature algorithms you accept — go-jose v4 requires this.
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil {
		return nil, err
	}

	// Verify the signature; payload is the verified claim-set bytes.
	payload, err := jws.Verify(key)
	if err != nil {
		return nil, err // signature invalid
	}

	// Check the at+jwt media type from the *verified* JOSE header (RFC 9068 §2.1).
	typ, _ := jws.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string)
	if !accesstoken.ValidType(typ) {
		return nil, accesstoken.ErrInvalidType
	}

	// Decode and validate the claim profile from the verified bytes.
	claims, err := accesstoken.ParseClaims(payload)
	if err != nil {
		return nil, err
	}
	opts := append([]accesstoken.Option{
		accesstoken.WithIssuer("https://as.example.com/"),
		accesstoken.WithAudience("https://rs.example.com/"), // this RS's identifier
		accesstoken.WithLeeway(60 * time.Second),
	}, extra...)
	if err := claims.Validate(opts...); err != nil {
		return nil, err
	}
	return claims, nil
}
```

`claims.Validate` returns an `*accesstoken.ValidationError` wrapping a sentinel
(`ErrExpired`, `ErrAudienceMismatch`, …). At the HTTP boundary, map any of them
to an RFC 6750 `invalid_token` 401 response. Use `bearer.Token(r)` from
[`go-bearer-token`](https://github.com/hstern/go-bearer-token) to pull the token
from the `Authorization: Bearer` header first.

## 2. Decrypt an encrypted access token (JWE)

`Parse` reports an encrypted (5-segment) token with `ErrEncrypted` so you know
to decrypt first. RFC 9068 access tokens are typically *nested* — a JWE wrapping
a signed JWT — so after decrypting you still verify the inner JWS exactly as
above.

```go
import (
	"errors"

	jose "github.com/go-jose/go-jose/v4"
	accesstoken "github.com/hstern/go-access-tokens"
)

func decryptAndValidate(raw string, decKey, sigKey any) (*accesstoken.Claims, error) {
	// Optional: confirm it really is encrypted before reaching for the decrypter.
	if _, err := accesstoken.Parse(raw); !errors.Is(err, accesstoken.ErrEncrypted) {
		// Not a JWE — it is a plain JWS; verify it directly.
		return verifyAndValidate(raw, sigKey)
	}

	// Pin the key-management and content-encryption algorithms you accept.
	jwe, err := jose.ParseEncrypted(raw,
		[]jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.ECDH_ES_A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	if err != nil {
		return nil, err
	}
	plaintext, err := jwe.Decrypt(decKey)
	if err != nil {
		return nil, err
	}

	// Nested case (JWE → JWS → claims): the plaintext is a signed JWT, so
	// verify its signature and claims as in section 1.
	return verifyAndValidate(string(plaintext), sigKey)

	// Direct case (JWE → claims, no inner signature): there is no signature to
	// verify, so use accesstoken.ParseClaims(plaintext) + claims.Validate(...)
	// instead — but confirm your issuer really emits unsigned, encrypted-only
	// tokens before trusting them.
}
```

## 3. DPoP sender-constraining (RFC 9449)

A DPoP-bound token is sent with the `DPoP` authorization scheme (not `Bearer`)
and a proof JWT in the `DPoP` header:

```
Authorization: DPoP <access-token>
DPoP: <proof-jwt>
```

You verify the proof, derive the proof key's JWK thumbprint (`jkt`), and require
the access token's `cnf` claim to match it via
[`WithDPoPKeyThumbprint`](https://pkg.go.dev/github.com/hstern/go-access-tokens#WithDPoPKeyThumbprint).

```go
import (
	"crypto"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
	accesstoken "github.com/hstern/go-access-tokens"
)

func validateDPoP(r *http.Request, sigKey any) (*accesstoken.Claims, error) {
	scheme, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, "DPoP") {
		return nil, errors.New("expected DPoP authorization scheme")
	}

	// The proof is a JWS signed by the client's key, which it embeds in its
	// "jwk" header. Parse and verify the proof against that embedded key.
	proof, err := jose.ParseSigned(r.Header.Get("DPoP"), []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	if err != nil {
		return nil, err
	}
	jwk := proof.Signatures[0].Header.JSONWebKey
	if jwk == nil || !jwk.IsPublic() {
		return nil, errors.New("DPoP proof missing public jwk header")
	}
	proofClaims, err := proof.Verify(jwk.Key)
	if err != nil {
		return nil, err
	}

	// Validate the proof's own claims per RFC 9449 §4.3 — this is YOUR code:
	//   htm  == r.Method
	//   htu  == the request URI (scheme+host+path, no query/fragment)
	//   iat  within a small acceptance window
	//   jti  unseen (replay cache)
	//   ath  == base64url(SHA-256(access token))  [for protected-resource access]
	_ = proofClaims // ... your RFC 9449 proof checks here ...

	// Derive jkt = base64url(SHA-256 JWK Thumbprint) of the proof key (RFC 7638).
	sum, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	jkt := base64.RawURLEncoding.EncodeToString(sum)

	// Verify the access token and require its cnf.jkt to equal the proof key's.
	return verifyAndValidate(token, sigKey, accesstoken.WithDPoPKeyThumbprint(jkt))
}
```

A token whose `cnf` is absent or whose `jkt` differs fails with
`accesstoken.ErrConfirmationMismatch`.

## 4. mTLS sender-constraining (RFC 8705)

mTLS-bound tokens use the normal `Bearer` scheme; the binding is the client
certificate from the TLS handshake. The `x5t#S256` thumbprint is just the
base64url SHA-256 of the certificate's DER bytes — **pure stdlib, no go-jose
needed** — checked via
[`WithCertificateThumbprint`](https://pkg.go.dev/github.com/hstern/go-access-tokens#WithCertificateThumbprint).

```go
import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"

	accesstoken "github.com/hstern/go-access-tokens"
	bearer "github.com/hstern/go-bearer-token"
)

func validateMTLS(r *http.Request, sigKey any) (*accesstoken.Claims, error) {
	raw, err := bearer.Token(r)
	if err != nil {
		return nil, err
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, errors.New("no client certificate presented")
	}

	// x5t#S256 = base64url(SHA-256(DER-encoded client certificate)).
	sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	x5t := base64.RawURLEncoding.EncodeToString(sum[:])

	return verifyAndValidate(raw, sigKey, accesstoken.WithCertificateThumbprint(x5t))
}
```

## 5. Key discovery (JWKS)

The `key` passed to `jws.Verify` (and `decKey` to `jwe.Decrypt`) is the issuer's
signing/encryption key. Fetching it from the authorization server's `jwks_uri`
is also out of scope here — but go-jose models it directly: parse the JWKS into a
`*jose.JSONWebKeySet` and pass it to `Verify`, which selects the right key by the
token's `kid` header.

```go
var jwks jose.JSONWebKeySet
_ = json.Unmarshal(jwksBytes, &jwks) // jwksBytes fetched + cached from jwks_uri
claims, err := verifyAndValidate(raw, &jwks)
```

Fetching, caching, and rotating the JWKS (honoring HTTP cache headers, refreshing
on an unknown `kid`) is your concern or that of a dedicated helper library.

[go-jose]: https://github.com/go-jose/go-jose

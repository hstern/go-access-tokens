// Copyright 2026 The go-access-tokens Authors
// SPDX-License-Identifier: Apache-2.0

package accesstoken

import "time"

// Builder constructs an RFC 9068 access-token claim set with a fluent API for
// the authorization-server (producer) side. Setters return the Builder for
// chaining; Build validates that the seven required §2.2 claims are present, and
// Encode produces the signer-ready JSON payload.
//
// A Builder is single-use: Build / Encode return the accumulated claim set.
//
//	payload, err := accesstoken.NewBuilder().
//		Issuer("https://as.example.com/").
//		Subject("user-123").
//		Audience("https://rs.example.com/").
//		ClientID("client-abc").
//		ID("jti-1").
//		Lifetime(now, time.Hour).
//		Scope("read", "write").
//		Encode()
type Builder struct {
	claims Claims
	err    error
}

// NewBuilder returns an empty Builder.
func NewBuilder() *Builder { return &Builder{} }

// Issuer sets the iss claim.
func (b *Builder) Issuer(iss string) *Builder { b.claims.Issuer = iss; return b }

// Subject sets the sub claim.
func (b *Builder) Subject(sub string) *Builder { b.claims.Subject = sub; return b }

// Audience sets the aud claim to the given resource indicator(s).
func (b *Builder) Audience(aud ...string) *Builder { b.claims.Audience = Audience(aud); return b }

// ClientID sets the client_id claim.
func (b *Builder) ClientID(id string) *Builder { b.claims.ClientID = id; return b }

// ID sets the jti claim. The caller supplies a unique value.
func (b *Builder) ID(jti string) *Builder { b.claims.JWTID = jti; return b }

// IssuedAt sets the iat claim.
func (b *Builder) IssuedAt(t time.Time) *Builder { b.claims.IssuedAt = NewNumericDate(t); return b }

// Expires sets the exp claim.
func (b *Builder) Expires(t time.Time) *Builder { b.claims.Expires = NewNumericDate(t); return b }

// NotBefore sets the optional nbf claim.
func (b *Builder) NotBefore(t time.Time) *Builder { b.claims.NotBefore = NewNumericDate(t); return b }

// Lifetime sets iat to issuedAt and exp to issuedAt+d — the common case.
func (b *Builder) Lifetime(issuedAt time.Time, d time.Duration) *Builder {
	b.claims.IssuedAt = NewNumericDate(issuedAt)
	b.claims.Expires = NewNumericDate(issuedAt.Add(d))
	return b
}

// Scope sets the space-delimited scope claim from the given scopes.
func (b *Builder) Scope(scopes ...string) *Builder { b.claims.SetScope(scopes...); return b }

// DPoPKeyThumbprint sets the cnf claim to bind the token to the DPoP key whose
// JWK SHA-256 thumbprint is jkt (RFC 9449 §6).
func (b *Builder) DPoPKeyThumbprint(jkt string) *Builder {
	b.confirmation().JWKThumbprint = jkt
	return b
}

// CertificateThumbprint sets the cnf claim to bind the token to the mTLS client
// certificate whose SHA-256 thumbprint is x5t (the cnf "x5t#S256" member,
// RFC 8705 §3.1).
func (b *Builder) CertificateThumbprint(x5t string) *Builder {
	b.confirmation().X509Thumbprint = x5t
	return b
}

func (b *Builder) confirmation() *Confirmation {
	if b.claims.Confirmation == nil {
		b.claims.Confirmation = &Confirmation{}
	}
	return b.claims.Confirmation
}

// Claim sets an arbitrary extension claim (identity or custom). It records the
// first marshalling error, which Build and Encode then return.
func (b *Builder) Claim(name string, v any) *Builder {
	if err := b.claims.SetExtra(name, v); err != nil && b.err == nil {
		b.err = err
	}
	return b
}

// Build returns the accumulated claim set, erroring if a Claim call failed or a
// required §2.2 claim is missing.
func (b *Builder) Build() (*Claims, error) {
	if b.err != nil {
		return nil, b.err
	}
	if err := b.claims.requirePresent(); err != nil {
		return nil, err
	}
	c := b.claims
	return &c, nil
}

// Encode validates the claim set and returns its JSON payload, ready to hand to
// a JWS signer together with a header from NewHeader.
func (b *Builder) Encode() ([]byte, error) {
	c, err := b.Build()
	if err != nil {
		return nil, err
	}
	return c.Encode()
}

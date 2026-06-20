// Copyright 2026 The go-access-tokens Authors
// SPDX-License-Identifier: Apache-2.0

package accesstoken

import (
	"errors"
	"strings"
	"time"
)

// Sentinel errors for the RFC 9068 §4 claim checks. Every error returned by
// Validate, Token.Validate, Parse, and Encode wraps one of these; match them
// with errors.Is. At the HTTP boundary a caller maps any of them to the RFC
// 6750 "invalid_token" error and a 401 response.
var (
	// ErrMalformed indicates the token or payload could not be decoded.
	ErrMalformed = errors.New("accesstoken: malformed token")
	// ErrInvalidType indicates the JOSE "typ" header is not at+jwt (§2.1).
	ErrInvalidType = errors.New("accesstoken: invalid typ header")
	// ErrMissingClaim indicates a required §2.2 claim is absent.
	ErrMissingClaim = errors.New("accesstoken: required claim missing")
	// ErrIssuerMismatch indicates iss did not match the expected issuer (§4).
	ErrIssuerMismatch = errors.New("accesstoken: issuer mismatch")
	// ErrAudienceMismatch indicates aud did not name this resource server (§4).
	ErrAudienceMismatch = errors.New("accesstoken: audience mismatch")
	// ErrExpired indicates the current time is at or after exp (§4).
	ErrExpired = errors.New("accesstoken: token expired")
	// ErrNotYetValid indicates the current time is before nbf/iat (§4).
	ErrNotYetValid = errors.New("accesstoken: token not yet valid")
	// ErrConfirmationMismatch indicates the cnf binding (RFC 7800) did not
	// match the expected DPoP key or client-certificate thumbprint.
	ErrConfirmationMismatch = errors.New("accesstoken: confirmation mismatch")
	// ErrEncrypted indicates the token is a JWE (encrypted); decrypt it with a
	// JOSE library, then decode the plaintext payload with ParseClaims.
	ErrEncrypted = errors.New("accesstoken: token is encrypted (JWE)")
)

// ValidationError is the typed error returned by the validation and codec
// surface. It names the failing claim (when applicable) and wraps a sentinel.
type ValidationError struct {
	// Claim is the claim or header field at fault, if any (e.g. "aud", "typ").
	Claim string
	// Reason is a human-readable explanation.
	Reason string
	err    error
}

func (e *ValidationError) Error() string {
	switch {
	case e.Claim != "" && e.Reason != "":
		return "accesstoken: " + e.Claim + ": " + e.Reason
	case e.Reason != "":
		return "accesstoken: " + e.Reason
	case e.err != nil:
		return e.err.Error()
	default:
		return "accesstoken: validation error"
	}
}

// Unwrap exposes the wrapped sentinel for errors.Is.
func (e *ValidationError) Unwrap() error { return e.err }

// Option configures Validate / Token.Validate.
type Option func(*config)

type config struct {
	issuer      string
	checkIssuer bool
	audience    string
	checkAud    bool
	now         func() time.Time
	leeway      time.Duration
	jkt         string
	checkJKT    bool
	x5t         string
	checkX5T    bool
}

func newConfig(opts []Option) config {
	cfg := config{now: time.Now}
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// WithIssuer requires iss to exactly match issuer (§4). Without it, iss is
// checked only for presence.
func WithIssuer(issuer string) Option {
	return func(c *config) { c.issuer, c.checkIssuer = issuer, true }
}

// WithAudience requires aud to contain audience — this resource server's
// identifier (§4, RFC 8707). Without it, aud is checked only for presence.
func WithAudience(audience string) Option {
	return func(c *config) { c.audience, c.checkAud = audience, true }
}

// WithClock overrides the time source used for exp/nbf/iat checks. Defaults to
// time.Now; inject a fixed clock in tests.
func WithClock(now func() time.Time) Option {
	return func(c *config) {
		if now != nil {
			c.now = now
		}
	}
}

// WithLeeway tolerates up to d of clock skew on the exp/nbf/iat checks (§4
// permits a small leeway). Defaults to zero.
func WithLeeway(d time.Duration) Option {
	return func(c *config) { c.leeway = d }
}

// WithDPoPKeyThumbprint requires the token's cnf claim to bind the DPoP
// proof-of-possession key whose JWK SHA-256 thumbprint is jkt (RFC 9449 §6,
// RFC 7800). The caller computes jkt from the verified DPoP proof's public key;
// this library only checks that cnf.jkt matches. A token with no cnf, or a
// mismatched jkt, fails with ErrConfirmationMismatch.
func WithDPoPKeyThumbprint(jkt string) Option {
	return func(c *config) { c.jkt, c.checkJKT = jkt, true }
}

// WithCertificateThumbprint requires the token's cnf claim to bind the mTLS
// client certificate whose SHA-256 thumbprint is x5t (the cnf "x5t#S256"
// member; RFC 8705 §3.1, RFC 7800). The caller computes x5t from the presented
// client certificate; this library only checks that cnf matches. A token with
// no cnf, or a mismatched thumbprint, fails with ErrConfirmationMismatch.
func WithCertificateThumbprint(x5t string) Option {
	return func(c *config) { c.x5t, c.checkX5T = x5t, true }
}

// ValidType reports whether typ is an acceptable access-token media type
// (at+jwt or application/at+jwt, case-insensitive per §2.1).
func ValidType(typ string) bool {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case TypeAccessToken, TypeAccessTokenLong:
		return true
	default:
		return false
	}
}

// Validate runs the RFC 9068 §4 claim checks this library owns: all seven §2.2
// required claims present; iss exact-match (with WithIssuer); aud membership
// (with WithAudience); exp in the future; nbf/iat respected when present. It
// does NOT check the typ header (that needs the JOSE header — use
// Token.Validate) and never verifies the signature.
func (c *Claims) Validate(opts ...Option) error {
	cfg := newConfig(opts)

	if err := c.requirePresent(); err != nil {
		return err
	}

	if cfg.checkIssuer && c.Issuer != cfg.issuer {
		return &ValidationError{Claim: "iss", Reason: "does not match expected issuer", err: ErrIssuerMismatch}
	}
	if cfg.checkAud && !c.Audience.Contains(cfg.audience) {
		return &ValidationError{Claim: "aud", Reason: "does not contain this resource server", err: ErrAudienceMismatch}
	}

	now := cfg.now()
	if c.Expires != nil && !now.Add(-cfg.leeway).Before(c.Expires.Time) {
		return &ValidationError{Claim: "exp", Reason: "token has expired", err: ErrExpired}
	}
	if c.NotBefore != nil && now.Add(cfg.leeway).Before(c.NotBefore.Time) {
		return &ValidationError{Claim: "nbf", Reason: "token is not yet valid", err: ErrNotYetValid}
	}
	if c.IssuedAt != nil && now.Add(cfg.leeway).Before(c.IssuedAt.Time) {
		return &ValidationError{Claim: "iat", Reason: "issued in the future", err: ErrNotYetValid}
	}

	if cfg.checkJKT {
		if c.Confirmation == nil || c.Confirmation.JWKThumbprint != cfg.jkt {
			return &ValidationError{Claim: "cnf", Reason: "DPoP key thumbprint (jkt) does not match", err: ErrConfirmationMismatch}
		}
	}
	if cfg.checkX5T {
		if c.Confirmation == nil || c.Confirmation.X509Thumbprint != cfg.x5t {
			return &ValidationError{Claim: "cnf", Reason: "certificate thumbprint (x5t#S256) does not match", err: ErrConfirmationMismatch}
		}
	}
	return nil
}

// requirePresent checks the §2.2 required claims are present.
func (c *Claims) requirePresent() error {
	switch {
	case c.Issuer == "":
		return missing("iss")
	case c.Subject == "":
		return missing("sub")
	case len(c.Audience) == 0:
		return missing("aud")
	case c.Expires == nil:
		return missing("exp")
	case c.IssuedAt == nil:
		return missing("iat")
	case c.JWTID == "":
		return missing("jti")
	case c.ClientID == "":
		return missing("client_id")
	}
	return nil
}

// requireForEncode is the marshal-boundary required-claim check (design §5).
func (c *Claims) requireForEncode() error { return c.requirePresent() }

func missing(claim string) error {
	return &ValidationError{Claim: claim, Reason: "required claim is missing", err: ErrMissingClaim}
}

// Validate checks the §2.1 typ header and then the §4 claim profile. It is the
// resource-server entry point after the JWS signature has been verified out of
// band.
func (t *Token) Validate(opts ...Option) error {
	if !ValidType(t.Header.Type) {
		return &ValidationError{Claim: "typ", Reason: "must be " + TypeAccessToken, err: ErrInvalidType}
	}
	return t.Claims.Validate(opts...)
}

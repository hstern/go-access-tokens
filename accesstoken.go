// Copyright 2026 The go-access-tokens Authors
// SPDX-License-Identifier: Apache-2.0

// Package accesstoken is a typed parser, validator, and encoder for RFC 9068
// JWT-profile OAuth 2.0 access tokens.
//
// It implements the claim-set side of RFC 9068: the typed [Claims] surface
// (§2.2), the at+jwt media type check (§2.1), and the resource-server claim
// validation procedure (§4). It is the codec and validator, not the crypto.
//
// # Scope: verified bytes in, claims out
//
// JWS signature verification is deliberately out of scope. This package never
// verifies (or requires) a signature, fetches keys, or discovers issuer
// metadata — that is JOSE-library work (for example go-jose). The intended
// resource-server flow is:
//
//  1. extract the bearer token from the request (RFC 6750);
//  2. verify its JWS signature with a JOSE library;
//  3. hand the token here to decode and validate the RFC 9068 claim profile.
//
// Use [Parse] for the compact token string (header + claims), or [ParseClaims]
// when your JOSE layer already gave you the verified payload bytes. Then call
// [Token.Validate] or [Claims.Validate]. Authorization servers build a [Claims]
// and call [Claims.Encode] to produce a payload for their signer, paired with
// [NewHeader].
//
// All validation failures wrap a sentinel (see the Err* variables) so a caller
// can map any of them to the RFC 6750 invalid_token error with errors.Is.
//
// Spec: https://www.rfc-editor.org/rfc/rfc9068.html
package accesstoken

// SpecVersion is the version of the specification this package targets.
const SpecVersion = "RFC 9068"

// Media types for the JWT access-token "typ" header (§2.1). TypeAccessToken is
// the short form the library emits; TypeAccessTokenLong is the equivalent long
// form a validator must also accept. Media-type comparison is case-insensitive.
const (
	TypeAccessToken     = "at+jwt"
	TypeAccessTokenLong = "application/at+jwt"
)

// Header is the minimal JOSE header this library reads. Only Type (§2.1) is
// acted on; Algorithm and KeyID are surfaced for the caller's JWS verifier but
// are never interpreted here — signature verification and key selection are out
// of scope (see package docs).
type Header struct {
	Type      string `json:"typ,omitempty"`
	Algorithm string `json:"alg,omitempty"`
	KeyID     string `json:"kid,omitempty"`
}

// NewHeader builds an access-token JOSE header with typ set to "at+jwt" and the
// caller's signing algorithm and (optional) key id.
func NewHeader(alg, kid string) Header {
	return Header{Type: TypeAccessToken, Algorithm: alg, KeyID: kid}
}

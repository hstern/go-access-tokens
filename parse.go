// Copyright 2026 The go-access-tokens Authors
// SPDX-License-Identifier: Apache-2.0

package accesstoken

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Token is a parsed JWT access token: its JOSE header, its decoded claim set,
// and the raw segments. It is the result of Parse.
//
// Parse does NOT verify the JWS signature. The caller must verify the
// signature with a JOSE library before trusting a Token's claims; this library
// only decodes and validates the RFC 9068 claim profile (see package docs).
type Token struct {
	Header Header
	Claims Claims

	// Raw is the original compact serialization, suitable to hand to a JWS
	// verifier.
	Raw string
	// HeaderJSON and PayloadJSON are the base64url-decoded segment bytes.
	HeaderJSON  []byte
	PayloadJSON []byte
	// Signature is the decoded JWS signature (empty for an unsecured token).
	Signature []byte
}

// Parse decodes a compact-serialized JWT (header.payload.signature) into a
// Token. It splits on dots, base64url-decodes each segment, and JSON-unmarshals
// the header and payload. It performs no validation beyond well-formedness and,
// in particular, does not verify the signature.
func Parse(token string) (*Token, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, malformedf("compact serialization must have 3 segments, got %d", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, malformedf("header segment: %v", err)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, malformedf("payload segment: %v", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, malformedf("signature segment: %v", err)
	}

	t := &Token{
		Raw:         token,
		HeaderJSON:  headerJSON,
		PayloadJSON: payloadJSON,
		Signature:   sig,
	}
	if err := json.Unmarshal(headerJSON, &t.Header); err != nil {
		return nil, malformedf("header JSON: %v", err)
	}
	if err := json.Unmarshal(payloadJSON, &t.Claims); err != nil {
		return nil, malformedf("payload JSON: %v", err)
	}
	return t, nil
}

// ParseClaims decodes a JWT payload (the already base64url-decoded JSON bytes)
// into a Claims. Use this in the verified-bytes-in flow: verify the JWS with a
// JOSE library, then hand the verified payload here. It does not see the JOSE
// header, so the caller is responsible for the typ check (or use Parse +
// Token.Validate).
func ParseClaims(payload []byte) (*Claims, error) {
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, malformedf("payload JSON: %v", err)
	}
	return &c, nil
}

// Encode marshals the claim set to its JSON payload representation, enforcing
// the RFC 9068 §2.2 required-claim presence at the marshal boundary (strict
// marshal). It does not sign; hand the result to a JWS signer together with a
// header from NewHeader.
func (c *Claims) Encode() ([]byte, error) {
	if err := c.requireForEncode(); err != nil {
		return nil, err
	}
	return json.Marshal(c)
}

// malformedf builds a *ValidationError wrapping ErrMalformed.
func malformedf(format string, args ...any) error {
	return &ValidationError{Reason: fmt.Sprintf(format, args...), err: ErrMalformed}
}

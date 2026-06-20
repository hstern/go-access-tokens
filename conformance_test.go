// Copyright 2026 The go-access-tokens Authors
// SPDX-License-Identifier: Apache-2.0

package accesstoken

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

// RFC 9068 conformance fixtures. RFC 9068 ships no machine-readable test
// vectors, so these are derived from the §2.2 example (Figure 2): one canonical
// valid token, and a family of invalid tokens each mutating the figure to break
// exactly one §2.1/§2.2/§4 (claim-side) MUST. Every case is driven through the
// full compact-token path — Parse then Token.Validate — so the typ check, the
// base64url/JSON decode, and the claim checks are all exercised together.

// validHeader / validPayload are the canonical conformant token, with exp set
// comfortably after midWindow (the fixed validation clock).
func validHeader() map[string]any {
	return map[string]any{"typ": "at+jwt", "alg": "RS256", "kid": "k1"}
}

func validPayload() map[string]any {
	return map[string]any{
		"iss":       testIssuer,
		"sub":       "5ba552d67",
		"aud":       testAudience,
		"exp":       1639528912, // > midWindow
		"iat":       1618354090, // < midWindow
		"jti":       "dbe39bf3a3ba4238a513f51d6e1691c4",
		"client_id": "s6BhdRkqt3",
		"scope":     "openid profile reademail",
	}
}

func encodeToken(t *testing.T, header, payload map[string]any) string {
	t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc(hb) + "." + enc(pb) + "." + enc([]byte("signature"))
}

func TestConformance(t *testing.T) {
	tests := []struct {
		name    string
		header  func(map[string]any) // header mutation; nil = leave canonical
		payload func(map[string]any) // payload mutation; nil = leave canonical
		raw     string               // raw token, overriding the builders (malformed cases)
		wantErr error                // nil = must validate
	}{
		{name: "canonical valid token"},
		{name: "typ long form accepted", header: func(h map[string]any) { h["typ"] = "application/at+jwt" }},
		{name: "typ uppercase accepted", header: func(h map[string]any) { h["typ"] = "AT+JWT" }},
		{name: "aud as array containing RS", payload: func(p map[string]any) {
			p["aud"] = []string{"https://other/", testAudience}
		}},

		{name: "wrong typ", header: func(h map[string]any) { h["typ"] = "JWT" }, wantErr: ErrInvalidType},
		{name: "missing typ", header: func(h map[string]any) { delete(h, "typ") }, wantErr: ErrInvalidType},

		{name: "missing iss", payload: func(p map[string]any) { delete(p, "iss") }, wantErr: ErrMissingClaim},
		{name: "missing sub", payload: func(p map[string]any) { delete(p, "sub") }, wantErr: ErrMissingClaim},
		{name: "missing aud", payload: func(p map[string]any) { delete(p, "aud") }, wantErr: ErrMissingClaim},
		{name: "missing exp", payload: func(p map[string]any) { delete(p, "exp") }, wantErr: ErrMissingClaim},
		{name: "missing iat", payload: func(p map[string]any) { delete(p, "iat") }, wantErr: ErrMissingClaim},
		{name: "missing jti", payload: func(p map[string]any) { delete(p, "jti") }, wantErr: ErrMissingClaim},
		{name: "missing client_id", payload: func(p map[string]any) { delete(p, "client_id") }, wantErr: ErrMissingClaim},

		{name: "issuer mismatch", payload: func(p map[string]any) { p["iss"] = "https://evil.example.com/" }, wantErr: ErrIssuerMismatch},
		{name: "audience mismatch", payload: func(p map[string]any) { p["aud"] = "https://other-rs.example.com/" }, wantErr: ErrAudienceMismatch},
		{name: "expired", payload: func(p map[string]any) { p["exp"] = midWindow.Unix() - 1 }, wantErr: ErrExpired},
		{name: "not yet valid (nbf)", payload: func(p map[string]any) { p["nbf"] = midWindow.Unix() + 3600 }, wantErr: ErrNotYetValid},

		{name: "malformed: two segments", raw: "a.b", wantErr: ErrMalformed},
		{name: "malformed: bad base64 payload", raw: "eyJ0eXAiOiJhdCtqd3QifQ.!!!.sig", wantErr: ErrMalformed},
	}

	opts := []Option{
		WithIssuer(testIssuer),
		WithAudience(testAudience),
		WithClock(fixedClock(midWindow)),
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.raw
			if raw == "" {
				h, p := validHeader(), validPayload()
				if tc.header != nil {
					tc.header(h)
				}
				if tc.payload != nil {
					tc.payload(p)
				}
				raw = encodeToken(t, h, p)
			}

			tok, err := Parse(raw)
			if err != nil {
				// Parse failures are only expected for the malformed cases.
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Parse error = %v, want %v", err, tc.wantErr)
				}
				return
			}

			err = tok.Validate(opts...)
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("Validate = %v, want valid", err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("Validate = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

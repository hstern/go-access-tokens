// Copyright 2026 The go-access-tokens Authors
// SPDX-License-Identifier: Apache-2.0

package accesstoken

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// compact builds a compact-serialized JWT from a header and payload (JSON
// strings) plus an arbitrary signature. It does not sign anything.
func compact(headerJSON, payloadJSON string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(headerJSON)) + "." + enc([]byte(payloadJSON)) + "." + enc([]byte("signature"))
}

func TestParse(t *testing.T) {
	tok := compact(`{"typ":"at+jwt","alg":"RS256","kid":"k1"}`, figure2)

	got, err := Parse(tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Header.Type != "at+jwt" || got.Header.Algorithm != "RS256" || got.Header.KeyID != "k1" {
		t.Errorf("header = %+v", got.Header)
	}
	if got.Claims.ClientID != "s6BhdRkqt3" {
		t.Errorf("client_id = %q", got.Claims.ClientID)
	}
	if got.Raw != tok {
		t.Error("Raw not preserved")
	}
	if string(got.PayloadJSON) != figure2 {
		t.Errorf("PayloadJSON = %s", got.PayloadJSON)
	}
	if string(got.Signature) != "signature" {
		t.Errorf("Signature = %s", got.Signature)
	}
}

func TestParseMalformed(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"two segments", "a.b"},
		{"four segments", "a.b.c.d"},
		{"bad base64 header", "!!!." + base64.RawURLEncoding.EncodeToString([]byte(figure2)) + ".sig"},
		{"bad json payload", compact(`{"typ":"at+jwt"}`, `{not json}`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.in)
			if !errors.Is(err, ErrMalformed) {
				t.Errorf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestParseClaims(t *testing.T) {
	c, err := ParseClaims([]byte(figure2))
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if c.Issuer == "" {
		t.Error("iss not decoded")
	}
	if _, err := ParseClaims([]byte(`{bad`)); !errors.Is(err, ErrMalformed) {
		t.Errorf("malformed err = %v", err)
	}
}

func TestEncodeRequiresClaims(t *testing.T) {
	// a half-built claim set fails at the marshal boundary
	c := &Claims{Issuer: "https://as.example.com/"}
	if _, err := c.Encode(); !errors.Is(err, ErrMissingClaim) {
		t.Fatalf("Encode err = %v, want ErrMissingClaim", err)
	}

	// a complete claim set encodes and round-trips
	full := completeClaims()
	b, err := full.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !strings.Contains(string(b), `"client_id":"s6BhdRkqt3"`) {
		t.Errorf("encoded payload missing client_id: %s", b)
	}
	round, err := ParseClaims(b)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	if round.ClientID != full.ClientID || round.Issuer != full.Issuer {
		t.Errorf("round-trip mismatch: %+v", round)
	}
}

func TestEncodeHeader(t *testing.T) {
	h := NewHeader("ES256", "abc")
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	if string(b) != `{"typ":"at+jwt","alg":"ES256","kid":"abc"}` {
		t.Errorf("header JSON = %s", b)
	}
}

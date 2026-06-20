// Copyright 2026 The go-access-tokens Authors
// SPDX-License-Identifier: Apache-2.0

package accesstoken

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestBuilderBuild(t *testing.T) {
	iat := time.Unix(1600000000, 0)
	c, err := NewBuilder().
		Issuer(testIssuer).
		Subject("user-123").
		Audience(testAudience).
		ClientID("client-abc").
		ID("jti-1").
		Lifetime(iat, time.Hour).
		Scope("read", "write").
		DPoPKeyThumbprint("jkt-xyz").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if c.Issuer != testIssuer || c.Subject != "user-123" || c.ClientID != "client-abc" || c.JWTID != "jti-1" {
		t.Errorf("required claims wrong: %+v", c)
	}
	if !c.Audience.Contains(testAudience) {
		t.Errorf("aud = %v", c.Audience)
	}
	if c.IssuedAt.Unix() != iat.Unix() || c.Expires.Unix() != iat.Add(time.Hour).Unix() {
		t.Errorf("lifetime wrong: iat=%v exp=%v", c.IssuedAt, c.Expires)
	}
	if got := c.ScopeValues(); !reflect.DeepEqual(got, []string{"read", "write"}) {
		t.Errorf("scope = %v", got)
	}
	if c.Confirmation == nil || c.Confirmation.JWKThumbprint != "jkt-xyz" {
		t.Errorf("cnf = %+v", c.Confirmation)
	}
}

func TestBuilderMissingRequired(t *testing.T) {
	_, err := NewBuilder().Issuer(testIssuer).Subject("u").Build()
	if !errors.Is(err, ErrMissingClaim) {
		t.Fatalf("err = %v, want ErrMissingClaim", err)
	}
}

func TestBuilderEncodeRoundTrip(t *testing.T) {
	iat := time.Unix(1600000000, 0)
	payload, err := NewBuilder().
		Issuer(testIssuer).Subject("user-123").Audience(testAudience).
		ClientID("client-abc").ID("jti-1").Lifetime(iat, time.Hour).
		Claim("email", "jane@example.com").
		Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	c, err := ParseClaims(payload)
	if err != nil {
		t.Fatalf("ParseClaims: %v", err)
	}
	var email string
	if present, _ := c.GetExtra("email", &email); !present || email != "jane@example.com" {
		t.Errorf("email extra = %q present=%v", email, present)
	}
}

func TestBuilderClaimError(t *testing.T) {
	// SetExtra refuses a reserved (typed) claim name; Build surfaces it.
	_, err := NewBuilder().Claim("iss", "x").Build()
	if err == nil {
		t.Fatal("expected error from Claim(\"iss\", …)")
	}
}

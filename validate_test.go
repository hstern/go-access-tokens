// Copyright 2026 The go-access-tokens Authors
// SPDX-License-Identifier: Apache-2.0

package accesstoken

import (
	"errors"
	"testing"
	"time"
)

const (
	testIssuer   = "https://authorization-server.example.com/"
	testAudience = "https://rs.example.com/"
)

// fixedClock returns a clock function pinned to t.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// completeClaims returns a Claims with every required §2.2 claim set, valid at
// the 2021-04 / 2021-12 window of the spec figure.
func completeClaims() *Claims {
	return &Claims{
		Issuer:   testIssuer,
		Subject:  "5ba552d67",
		Audience: Audience{testAudience},
		Expires:  NewNumericDate(time.Unix(1639528912, 0)),
		IssuedAt: NewNumericDate(time.Unix(1618354090, 0)),
		JWTID:    "dbe39bf3a3ba4238a513f51d6e1691c4",
		ClientID: "s6BhdRkqt3",
	}
}

// midWindow is a time strictly between the figure's iat and exp.
var midWindow = time.Unix(1620000000, 0)

func TestValidateHappyPath(t *testing.T) {
	c := completeClaims()
	err := c.Validate(
		WithIssuer(testIssuer),
		WithAudience(testAudience),
		WithClock(fixedClock(midWindow)),
	)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateMissingRequiredClaims(t *testing.T) {
	for _, claim := range []string{"iss", "sub", "aud", "exp", "iat", "jti", "client_id"} {
		t.Run(claim, func(t *testing.T) {
			c := completeClaims()
			switch claim {
			case "iss":
				c.Issuer = ""
			case "sub":
				c.Subject = ""
			case "aud":
				c.Audience = nil
			case "exp":
				c.Expires = nil
			case "iat":
				c.IssuedAt = nil
			case "jti":
				c.JWTID = ""
			case "client_id":
				c.ClientID = ""
			}
			err := c.Validate(WithClock(fixedClock(midWindow)))
			if !errors.Is(err, ErrMissingClaim) {
				t.Fatalf("err = %v, want ErrMissingClaim", err)
			}
			if ve, ok := errors.AsType[*ValidationError](err); !ok || ve.Claim != claim {
				t.Errorf("ValidationError.Claim = %q, want %q", veClaim(err), claim)
			}
		})
	}
}

func veClaim(err error) string {
	if ve, ok := errors.AsType[*ValidationError](err); ok {
		return ve.Claim
	}
	return ""
}

func TestValidateIssuerMismatch(t *testing.T) {
	c := completeClaims()
	err := c.Validate(WithIssuer("https://evil.example.com/"), WithClock(fixedClock(midWindow)))
	if !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("err = %v, want ErrIssuerMismatch", err)
	}
}

func TestValidateAudienceMismatch(t *testing.T) {
	c := completeClaims()
	err := c.Validate(WithAudience("https://other-rs.example.com/"), WithClock(fixedClock(midWindow)))
	if !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("err = %v, want ErrAudienceMismatch", err)
	}
}

func TestValidateExpired(t *testing.T) {
	c := completeClaims()
	after := c.Expires.Add(time.Second)
	if err := c.Validate(WithClock(fixedClock(after))); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
	// leeway covers the skew
	if err := c.Validate(WithClock(fixedClock(after)), WithLeeway(2*time.Second)); err != nil {
		t.Errorf("with leeway: %v", err)
	}
}

func TestValidateNotYetValid(t *testing.T) {
	c := completeClaims()
	c.NotBefore = NewNumericDate(midWindow)
	before := midWindow.Add(-time.Minute)
	if err := c.Validate(WithClock(fixedClock(before))); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("err = %v, want ErrNotYetValid", err)
	}
	if err := c.Validate(WithClock(fixedClock(before)), WithLeeway(2*time.Minute)); err != nil {
		t.Errorf("with leeway: %v", err)
	}
}

func TestValidateIssuedInFuture(t *testing.T) {
	c := completeClaims()
	before := c.IssuedAt.Add(-time.Hour)
	if err := c.Validate(WithClock(fixedClock(before))); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("err = %v, want ErrNotYetValid", err)
	}
}

func TestValidType(t *testing.T) {
	good := []string{"at+jwt", "AT+JWT", "application/at+jwt", "application/AT+JWT", " at+jwt "}
	for _, typ := range good {
		if !ValidType(typ) {
			t.Errorf("ValidType(%q) = false, want true", typ)
		}
	}
	bad := []string{"", "jwt", "JWT", "at_jwt", "application/jwt"}
	for _, typ := range bad {
		if ValidType(typ) {
			t.Errorf("ValidType(%q) = true, want false", typ)
		}
	}
}

func TestTokenValidate(t *testing.T) {
	tok := compact(`{"typ":"at+jwt","alg":"RS256"}`, figure2)
	parsed, err := Parse(tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := parsed.Validate(WithIssuer(testIssuer), WithAudience(testAudience), WithClock(fixedClock(midWindow))); err != nil {
		t.Fatalf("Token.Validate: %v", err)
	}

	// wrong typ is rejected before claim checks
	bad := compact(`{"typ":"JWT","alg":"RS256"}`, figure2)
	parsedBad, err := Parse(bad)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := parsedBad.Validate(WithClock(fixedClock(midWindow))); !errors.Is(err, ErrInvalidType) {
		t.Errorf("err = %v, want ErrInvalidType", err)
	}
}

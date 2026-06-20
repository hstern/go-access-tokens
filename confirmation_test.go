// Copyright 2026 The go-access-tokens Authors
// SPDX-License-Identifier: Apache-2.0

package accesstoken

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestConfirmationDecode(t *testing.T) {
	const payload = `{"sub":"x","cnf":{"jkt":"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I","kid":"k1"}}`
	var c Claims
	if err := json.Unmarshal([]byte(payload), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.Confirmation == nil {
		t.Fatal("cnf not decoded")
	}
	if c.Confirmation.JWKThumbprint != "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" {
		t.Errorf("jkt = %q", c.Confirmation.JWKThumbprint)
	}
	// unknown cnf member preserved
	if _, ok := c.Confirmation.Extra["kid"]; !ok {
		t.Errorf("cnf.kid not preserved in Extra: %v", c.Confirmation.Extra)
	}
	// cnf must not leak into Claims.Extra (it is a known claim)
	if _, ok := c.Extra["cnf"]; ok {
		t.Error("cnf leaked into Claims.Extra")
	}

	// round-trip byte-stable
	b1, _ := json.Marshal(c)
	var c2 Claims
	if err := json.Unmarshal(b1, &c2); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	b2, _ := json.Marshal(c2)
	if string(b1) != string(b2) {
		t.Errorf("not byte-stable:\n %s\n %s", b1, b2)
	}
}

func TestValidateDPoPBinding(t *testing.T) {
	const jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
	c := completeClaims()
	c.Confirmation = &Confirmation{JWKThumbprint: jkt}

	// matching jkt validates
	if err := c.Validate(WithClock(fixedClock(midWindow)), WithDPoPKeyThumbprint(jkt)); err != nil {
		t.Fatalf("matching jkt: %v", err)
	}
	// mismatched jkt fails
	if err := c.Validate(WithClock(fixedClock(midWindow)), WithDPoPKeyThumbprint("other")); !errors.Is(err, ErrConfirmationMismatch) {
		t.Fatalf("mismatch err = %v, want ErrConfirmationMismatch", err)
	}
	// no cnf at all fails when binding is required
	bare := completeClaims()
	if err := bare.Validate(WithClock(fixedClock(midWindow)), WithDPoPKeyThumbprint(jkt)); !errors.Is(err, ErrConfirmationMismatch) {
		t.Fatalf("missing cnf err = %v, want ErrConfirmationMismatch", err)
	}
	// without the option, cnf is not checked
	if err := bare.Validate(WithClock(fixedClock(midWindow))); err != nil {
		t.Fatalf("no binding option: %v", err)
	}
}

func TestValidateCertBinding(t *testing.T) {
	const x5t = "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"
	c := completeClaims()
	c.Confirmation = &Confirmation{X509Thumbprint: x5t}

	if err := c.Validate(WithClock(fixedClock(midWindow)), WithCertificateThumbprint(x5t)); err != nil {
		t.Fatalf("matching x5t: %v", err)
	}
	if err := c.Validate(WithClock(fixedClock(midWindow)), WithCertificateThumbprint("other")); !errors.Is(err, ErrConfirmationMismatch) {
		t.Fatalf("mismatch err = %v, want ErrConfirmationMismatch", err)
	}
}

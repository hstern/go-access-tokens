// Copyright 2026 The go-access-tokens Authors
// SPDX-License-Identifier: Apache-2.0

package accesstoken

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// figure2 is the RFC 9068 §2.2 example access-token payload.
const figure2 = `{` +
	`"iss":"https://authorization-server.example.com/",` +
	`"sub":"5ba552d67",` +
	`"aud":"https://rs.example.com/",` +
	`"exp":1639528912,` +
	`"iat":1618354090,` +
	`"jti":"dbe39bf3a3ba4238a513f51d6e1691c4",` +
	`"client_id":"s6BhdRkqt3",` +
	`"scope":"openid profile reademail"` +
	`}`

func TestClaimsDecodeFigure2(t *testing.T) {
	var c Claims
	if err := json.Unmarshal([]byte(figure2), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.Issuer != "https://authorization-server.example.com/" {
		t.Errorf("iss = %q", c.Issuer)
	}
	if c.Subject != "5ba552d67" {
		t.Errorf("sub = %q", c.Subject)
	}
	if !c.Audience.Contains("https://rs.example.com/") {
		t.Errorf("aud = %v", c.Audience)
	}
	if c.Expires == nil || c.Expires.Unix() != 1639528912 {
		t.Errorf("exp = %v", c.Expires)
	}
	if c.IssuedAt == nil || c.IssuedAt.Unix() != 1618354090 {
		t.Errorf("iat = %v", c.IssuedAt)
	}
	if c.JWTID != "dbe39bf3a3ba4238a513f51d6e1691c4" {
		t.Errorf("jti = %q", c.JWTID)
	}
	if c.ClientID != "s6BhdRkqt3" {
		t.Errorf("client_id = %q", c.ClientID)
	}
	if got := c.ScopeValues(); !reflect.DeepEqual(got, []string{"openid", "profile", "reademail"}) {
		t.Errorf("scope values = %v", got)
	}
	if len(c.Extra) != 0 {
		t.Errorf("Extra should be empty, got %v", c.Extra)
	}
}

func TestAudienceWireForms(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Audience
		out  string
	}{
		{"single string", `"a"`, Audience{"a"}, `"a"`},
		{"array one", `["a"]`, Audience{"a"}, `"a"`},
		{"array many", `["a","b"]`, Audience{"a", "b"}, `["a","b"]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var a Audience
			if err := json.Unmarshal([]byte(tc.in), &a); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if !reflect.DeepEqual(a, tc.want) {
				t.Errorf("decoded %v, want %v", a, tc.want)
			}
			b, err := json.Marshal(a)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(b) != tc.out {
				t.Errorf("encoded %s, want %s", b, tc.out)
			}
		})
	}
}

func TestAudienceNullIsAbsent(t *testing.T) {
	// aud:null must decode to an absent (nil) audience, not a phantom
	// single empty-string member, so the required-claim check still fires.
	var c Claims
	if err := json.Unmarshal([]byte(`{"sub":"x","aud":null}`), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(c.Audience) != 0 {
		t.Fatalf("aud:null decoded to %v, want empty", c.Audience)
	}
}

func TestNumericDateRoundTrip(t *testing.T) {
	// integer seconds round-trip exactly
	var n NumericDate
	if err := json.Unmarshal([]byte("1618354090"), &n); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if n.Unix() != 1618354090 {
		t.Errorf("unix = %d", n.Unix())
	}
	b, err := json.Marshal(n)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != "1618354090" {
		t.Errorf("encoded %s", b)
	}

	// fractional seconds decode without error and floor toward the second
	var f NumericDate
	if err := json.Unmarshal([]byte("1618354090.5"), &f); err != nil {
		t.Fatalf("unmarshal fractional: %v", err)
	}
	if f.Unix() != 1618354090 {
		t.Errorf("fractional unix = %d", f.Unix())
	}
}

func TestNewNumericDate(t *testing.T) {
	now := time.Now()
	n := NewNumericDate(now)
	if n.Unix() != now.Unix() {
		t.Errorf("unix = %d, want %d", n.Unix(), now.Unix())
	}
}

func TestExtraPreservedAndByteStable(t *testing.T) {
	payload := figure2[:len(figure2)-1] + `,"email":"jane@example.com","tenant":{"id":42,"name":"acme"}}`

	var c Claims
	if err := json.Unmarshal([]byte(payload), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := c.Extra["email"]; !ok {
		t.Fatalf("email not captured in Extra: %v", c.Extra)
	}
	if _, ok := c.Extra["tenant"]; !ok {
		t.Fatalf("tenant not captured in Extra")
	}

	// typed access to an extension claim
	var email string
	present, err := c.GetExtra("email", &email)
	if err != nil || !present || email != "jane@example.com" {
		t.Errorf("GetExtra email = %q present=%v err=%v", email, present, err)
	}

	// re-marshalling is byte-stable
	b1, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var c2 Claims
	if err := json.Unmarshal(b1, &c2); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	b2, err := json.Marshal(c2)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if string(b1) != string(b2) {
		t.Errorf("round-trip not byte-stable:\n %s\n %s", b1, b2)
	}
}

func TestSetExtraRejectsKnownClaim(t *testing.T) {
	var c Claims
	if err := c.SetExtra("iss", "x"); err == nil {
		t.Error("SetExtra(iss) should be rejected")
	}
	if err := c.SetExtra("custom", map[string]int{"a": 1}); err != nil {
		t.Errorf("SetExtra(custom): %v", err)
	}
	var got map[string]int
	present, err := c.GetExtra("custom", &got)
	if err != nil || !present || got["a"] != 1 {
		t.Errorf("GetExtra custom = %v present=%v err=%v", got, present, err)
	}
}

// Copyright 2026 The go-access-tokens Authors
// SPDX-License-Identifier: Apache-2.0

package accesstoken

import (
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Claims is the RFC 9068 §2.2 access-token claim set.
//
// The seven required claims (iss, exp, aud, sub, client_id, iat, jti) are
// typed directly, as are the optional authentication (§2.2.1) and
// authorization (§2.2.3) claims. Any other claim — identity claims (§2.2.2)
// and future registrations — is preserved verbatim in Extra so a decode/encode
// cycle does not lose information.
//
// Decoding is liberal (Postel's law): Claims will unmarshal whatever the wire
// gave it. Call Validate to enforce the RFC 9068 §4 claim profile, or Encode
// to produce a payload with required-claim checking at the marshal boundary.
type Claims struct {
	// Required (§2.2).
	Issuer   string       `json:"iss,omitempty"`
	Subject  string       `json:"sub,omitempty"`
	Audience Audience     `json:"aud,omitempty"`
	Expires  *NumericDate `json:"exp,omitempty"`
	IssuedAt *NumericDate `json:"iat,omitempty"`
	JWTID    string       `json:"jti,omitempty"`
	ClientID string       `json:"client_id,omitempty"`

	// NotBefore (nbf) is a standard JWT claim (RFC 7519); RFC 9068 does not
	// require it, but Validate honours it when present.
	NotBefore *NumericDate `json:"nbf,omitempty"`

	// Authentication information (§2.2.1).
	AuthTime *NumericDate `json:"auth_time,omitempty"`
	ACR      string       `json:"acr,omitempty"`
	AMR      []string     `json:"amr,omitempty"`

	// Authorization (§2.2.3). Scope is space-delimited (RFC 8693 §4.2);
	// the SCIM-derived list claims come from RFC 7643 §4.1.2.
	Scope        string   `json:"scope,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	Roles        []string `json:"roles,omitempty"`
	Entitlements []string `json:"entitlements,omitempty"`

	// Confirmation (cnf, RFC 7800) carries the sender-constraining key
	// binding: jkt for DPoP (RFC 9449), x5t#S256 for mTLS (RFC 8705).
	Confirmation *Confirmation `json:"cnf,omitempty"`

	// Extra holds claims not captured by the typed fields above — identity
	// claims (§2.2.2) and any extension/registered claim. Values are kept as
	// raw JSON for byte-stable round-trips and zero-cost pass-through; use
	// GetExtra / SetExtra for typed access.
	Extra map[string]json.RawMessage `json:"-"`
}

// knownClaims are the JSON keys mapped to typed Claims fields. Anything else
// decoded from a payload lands in Extra.
var knownClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "exp": {}, "iat": {}, "jti": {},
	"client_id": {}, "nbf": {}, "auth_time": {}, "acr": {}, "amr": {},
	"scope": {}, "groups": {}, "roles": {}, "entitlements": {}, "cnf": {},
}

// UnmarshalJSON decodes the typed claims and routes every other member of the
// JSON object into Extra.
func (c *Claims) UnmarshalJSON(data []byte) error {
	type alias Claims
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*c = Claims(a)

	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	for k := range knownClaims {
		delete(all, k)
	}
	if len(all) > 0 {
		c.Extra = all
	}
	return nil
}

// MarshalJSON serializes the typed claims and merges Extra back in. Typed
// claims win on key collision. Output is byte-stable: with no extension claims
// the known claims serialize in their declared order; with extension claims the
// whole object serializes in encoding/json's sorted-key order. Either way a
// given Claims value always marshals to the same bytes.
func (c Claims) MarshalJSON() ([]byte, error) {
	type alias Claims
	known, err := json.Marshal(alias(c))
	if err != nil {
		return nil, err
	}
	if len(c.Extra) == 0 {
		return known, nil
	}

	merged := make(map[string]json.RawMessage, len(c.Extra)+8)
	if err := json.Unmarshal(known, &merged); err != nil {
		return nil, err
	}
	for k, v := range c.Extra {
		if _, taken := merged[k]; taken {
			continue
		}
		merged[k] = v
	}
	return json.Marshal(merged)
}

// GetExtra unmarshals the extension claim named name into v. It reports whether
// the claim was present; a missing claim is not an error.
func (c *Claims) GetExtra(name string, v any) (bool, error) {
	raw, ok := c.Extra[name]
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(raw, v)
}

// SetExtra marshals v and stores it as the extension claim named name. It
// refuses to shadow a claim backed by a typed field.
func (c *Claims) SetExtra(name string, v any) error {
	if _, reserved := knownClaims[name]; reserved {
		return &ValidationError{Claim: name, Reason: "claim is backed by a typed field; set it directly"}
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if c.Extra == nil {
		c.Extra = make(map[string]json.RawMessage, 1)
	}
	c.Extra[name] = raw
	return nil
}

// ScopeValues splits the space-delimited scope claim (§2.2.3) into individual
// scope tokens. It returns nil when scope is empty.
func (c *Claims) ScopeValues() []string {
	if c.Scope == "" {
		return nil
	}
	return strings.Fields(c.Scope)
}

// SetScope joins scopes with single spaces and stores them in the scope claim.
func (c *Claims) SetScope(scopes ...string) {
	c.Scope = strings.Join(scopes, " ")
}

// Audience is the RFC 9068 §2.2 "aud" claim. Per RFC 7519 it is carried on the
// wire as either a single string or an array of strings; Audience decodes both
// and encodes a single-element audience as a bare string (the JWT idiom).
type Audience []string

// Contains reports whether aud is present in the audience.
func (a Audience) Contains(aud string) bool {
	return slices.Contains(a, aud)
}

// UnmarshalJSON accepts both the string and []string wire forms. A JSON null
// is treated as an absent audience (left nil), not a single empty member.
func (a *Audience) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = Audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// MarshalJSON emits a single-element audience as a bare string and any other
// audience as a JSON array.
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// NumericDate is an RFC 7519 NumericDate: a JSON number of seconds since the
// Unix epoch. It decodes integer and fractional values and encodes integer
// seconds.
type NumericDate struct {
	time.Time
}

// NewNumericDate wraps t as a *NumericDate, truncated to whole seconds.
func NewNumericDate(t time.Time) *NumericDate {
	return &NumericDate{Time: time.Unix(t.Unix(), 0).UTC()}
}

// MarshalJSON encodes the time as integer seconds since the Unix epoch.
func (n NumericDate) MarshalJSON() ([]byte, error) {
	return strconv.AppendInt(nil, n.Unix(), 10), nil
}

// UnmarshalJSON decodes a JSON number of seconds since the Unix epoch,
// accepting fractional values.
func (n *NumericDate) UnmarshalJSON(data []byte) error {
	s := string(data)
	if s == "null" {
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return err
	}
	sec, frac := math.Modf(f)
	n.Time = time.Unix(int64(sec), int64(math.Round(frac*1e9))).UTC()
	return nil
}

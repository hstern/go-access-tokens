// Copyright 2026 The go-access-tokens Authors
// SPDX-License-Identifier: Apache-2.0

package accesstoken

import "encoding/json"

// Confirmation is the "cnf" (confirmation) claim of RFC 7800 — the
// sender-constraining key binding carried by an access token. The two members
// relevant to RFC 9068 access tokens are typed:
//
//   - JWKThumbprint ("jkt") — the base64url SHA-256 JWK Thumbprint of the
//     DPoP proof-of-possession public key (RFC 9449 §6).
//   - X509Thumbprint ("x5t#S256") — the base64url SHA-256 hash of the client
//     certificate for mTLS-bound tokens (RFC 8705 §3.1).
//
// Any other cnf member (jwk, kid, jwe, jku, …) is preserved verbatim in Extra
// so a decode/encode cycle is lossless.
//
// This library only carries and compares the binding value; it does not verify
// the DPoP proof or the TLS client certificate — that crypto belongs to the
// caller (see [WithDPoPKeyThumbprint] and [WithCertificateThumbprint]).
type Confirmation struct {
	JWKThumbprint  string `json:"jkt,omitempty"`
	X509Thumbprint string `json:"x5t#S256,omitempty"`

	// Extra holds cnf members without a typed field above.
	Extra map[string]json.RawMessage `json:"-"`
}

var knownConfirmation = map[string]struct{}{"jkt": {}, "x5t#S256": {}}

// UnmarshalJSON decodes the typed cnf members and routes the rest into Extra.
func (c *Confirmation) UnmarshalJSON(data []byte) error {
	type alias Confirmation
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*c = Confirmation(a)

	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	for k := range knownConfirmation {
		delete(all, k)
	}
	if len(all) > 0 {
		c.Extra = all
	}
	return nil
}

// MarshalJSON serializes the typed cnf members and merges Extra back in. Typed
// members win on key collision.
func (c Confirmation) MarshalJSON() ([]byte, error) {
	type alias Confirmation
	known, err := json.Marshal(alias(c))
	if err != nil {
		return nil, err
	}
	if len(c.Extra) == 0 {
		return known, nil
	}

	merged := make(map[string]json.RawMessage, len(c.Extra)+2)
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

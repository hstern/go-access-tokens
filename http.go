// Copyright 2026 The go-access-tokens Authors
// SPDX-License-Identifier: Apache-2.0

package accesstoken

import (
	"errors"
	"net/http"
	"strings"
)

// ErrNoBearerToken indicates the request carried no bearer token in its
// Authorization header.
var ErrNoBearerToken = errors.New("accesstoken: no bearer token in request")

// BearerToken extracts an OAuth 2.0 bearer token from the Authorization header
// of r, per RFC 6750 §2.1 ("Authorization: Bearer <token>"). The scheme name is
// matched case-insensitively.
//
// It returns ErrNoBearerToken when there is no Authorization header, and a
// *ValidationError wrapping ErrMalformed when the header is present but is not a
// well-formed Bearer credential. The returned token is still unverified — pass
// it to Parse (and verify its signature with a JOSE library) before trusting it.
//
// Only the Authorization-header form is handled. The form-encoded body and URI
// query forms (RFC 6750 §2.2–2.3) are intentionally not read here: the query
// form is NOT RECOMMENDED by the spec, and consuming the request body is the
// caller's concern.
func BearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", ErrNoBearerToken
	}
	scheme, token, found := strings.Cut(h, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", &ValidationError{Reason: `Authorization header is not a "Bearer" credential`, err: ErrMalformed}
	}
	if token = strings.TrimSpace(token); token == "" {
		return "", &ValidationError{Reason: "empty bearer token", err: ErrMalformed}
	}
	return token, nil
}

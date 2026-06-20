// Copyright 2026 The go-access-tokens Authors
// SPDX-License-Identifier: Apache-2.0

package accesstoken_test

import (
	"errors"
	"fmt"
	"time"

	accesstoken "github.com/hstern/go-access-tokens"
)

// Example_resourceServer shows the consumer (resource-server) flow: the JWS
// signature is verified out of band by a JOSE library, then this package
// decodes and validates the RFC 9068 §4 claim profile.
func Example_resourceServer() {
	// In production this comes from the request's Authorization: Bearer header,
	// and you would verify its JWS signature with a JOSE library first.
	raw := "eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJSUzI1NiJ9." +
		"eyJpc3MiOiJodHRwczovL2FzLmV4YW1wbGUuY29tLyIsInN1YiI6InVzZXItMTIzIiwi" +
		"YXVkIjoiaHR0cHM6Ly9ycy5leGFtcGxlLmNvbS8iLCJleHAiOjQ3MDAwMDAwMDAsImlh" +
		"dCI6MTYwMDAwMDAwMCwianRpIjoiaWQtMSIsImNsaWVudF9pZCI6ImNsaWVudC1hYmMi" +
		"LCJzY29wZSI6InJlYWQgd3JpdGUifQ." +
		"c2lnbmF0dXJl"

	tok, err := accesstoken.Parse(raw)
	if err != nil {
		fmt.Println("parse:", err)
		return
	}

	err = tok.Validate(
		accesstoken.WithIssuer("https://as.example.com/"),
		accesstoken.WithAudience("https://rs.example.com/"),
	)
	if err != nil {
		fmt.Println("validate:", err)
		return
	}

	fmt.Println("subject:", tok.Claims.Subject)
	fmt.Println("scopes:", tok.Claims.ScopeValues())
	// Output:
	// subject: user-123
	// scopes: [read write]
}

// Example_authorizationServer shows the producer flow: build a conformant
// claim set, then Encode it for handing to a JWS signer.
func Example_authorizationServer() {
	c := &accesstoken.Claims{
		Issuer:   "https://as.example.com/",
		Subject:  "user-123",
		Audience: accesstoken.Audience{"https://rs.example.com/"},
		Expires:  accesstoken.NewNumericDate(time.Unix(4700000000, 0)),
		IssuedAt: accesstoken.NewNumericDate(time.Unix(1600000000, 0)),
		JWTID:    "id-1",
		ClientID: "client-abc",
	}
	c.SetScope("read", "write")

	payload, err := c.Encode()
	if err != nil {
		fmt.Println("encode:", err)
		return
	}

	header := accesstoken.NewHeader("RS256", "key-1")
	fmt.Println("typ:", header.Type)
	fmt.Println(string(payload))
	// Output:
	// typ: at+jwt
	// {"iss":"https://as.example.com/","sub":"user-123","aud":"https://rs.example.com/","exp":4700000000,"iat":1600000000,"jti":"id-1","client_id":"client-abc","scope":"read write"}
}

// ExampleClaims_GetExtra reads an identity claim that has no typed field.
func ExampleClaims_GetExtra() {
	c, _ := accesstoken.ParseClaims([]byte(`{"sub":"user-123","email":"jane@example.com"}`))

	var email string
	present, _ := c.GetExtra("email", &email)
	fmt.Println(present, email)
	// Output: true jane@example.com
}

// Example_errorHandling shows matching the typed sentinels with errors.Is so a
// resource server can map any validation failure to RFC 6750 "invalid_token".
func Example_errorHandling() {
	c, _ := accesstoken.ParseClaims([]byte(`{"sub":"user-123"}`)) // missing required claims

	err := c.Validate(accesstoken.WithAudience("https://rs.example.com/"))
	fmt.Println(errors.Is(err, accesstoken.ErrMissingClaim))
	fmt.Println(err)
	// Output:
	// true
	// accesstoken: iss: required claim is missing
}

// ExampleBuilder builds a conformant claim set with the fluent producer API.
func ExampleBuilder() {
	iat := time.Unix(1600000000, 0)
	payload, err := accesstoken.NewBuilder().
		Issuer("https://as.example.com/").
		Subject("user-123").
		Audience("https://rs.example.com/").
		ClientID("client-abc").
		ID("id-1").
		Lifetime(iat, time.Hour).
		Scope("read", "write").
		Encode()
	if err != nil {
		fmt.Println("encode:", err)
		return
	}
	fmt.Println(string(payload))
	// Output:
	// {"iss":"https://as.example.com/","sub":"user-123","aud":"https://rs.example.com/","exp":1600003600,"iat":1600000000,"jti":"id-1","client_id":"client-abc","scope":"read write"}
}

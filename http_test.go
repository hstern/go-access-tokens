// Copyright 2026 The go-access-tokens Authors
// SPDX-License-Identifier: Apache-2.0

package accesstoken

import (
	"errors"
	"net/http"
	"testing"
)

func TestBearerToken(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		set     bool
		want    string
		wantErr error
	}{
		{name: "valid", header: "Bearer abc.def.ghi", set: true, want: "abc.def.ghi"},
		{name: "scheme case-insensitive", header: "bearer abc", set: true, want: "abc"},
		{name: "no header", set: false, wantErr: ErrNoBearerToken},
		{name: "wrong scheme", header: "Basic xyz", set: true, wantErr: ErrMalformed},
		{name: "no scheme", header: "abc", set: true, wantErr: ErrMalformed},
		{name: "empty token", header: "Bearer    ", set: true, wantErr: ErrMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "https://rs.example.com/", nil)
			if tc.set {
				r.Header.Set("Authorization", tc.header)
			}
			got, err := BearerToken(r)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tc.want {
				t.Errorf("token = %q, want %q", got, tc.want)
			}
		})
	}
}

// Copyright 2026 The go-access-tokens Authors
// SPDX-License-Identifier: Apache-2.0

package accesstoken

import "testing"

func TestSpecVersion(t *testing.T) {
	if SpecVersion == "" {
		t.Fatal("SpecVersion must be set")
	}
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import "testing"

func TestTypedDenialIsOnlyTheServersOwnRefusal(t *testing.T) {
	for status, want := range map[int]bool{0: false, 200: false, 500: false, 502: false, 503: false, 400: false, 401: true, 403: true, 404: true} {
		if got := typedDenial(status); got != want {
			t.Errorf("typedDenial(%d) = %v, want %v", status, got, want)
		}
	}
}

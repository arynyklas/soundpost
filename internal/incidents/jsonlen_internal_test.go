// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package incidents

import (
	"encoding/json"
	"math/rand/v2"
	"strings"
	"testing"
)

// The note budget is counted in the bytes the control group sees, which are the
// bytes encoding/json writes (HTML escaping included): the count must equal them.
func TestJSONLenIsTheEncodersSize(t *testing.T) {
	check := func(s string) {
		t.Helper()
		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := jsonLen(s), len(raw)-2; got != want {
			t.Fatalf("jsonLen(%q) = %d, the encoder writes %d", s, got, want)
		}
	}
	for _, s := range []string{"", "plain", "quote\"back\\slash", "<tag>&amp;", "line\nbreak", "a\u2028b\u2029", "日本語", "emoji 😀 ✓", "\ufffd", "\u00e9", strings.Repeat("<", 100), "mixed <日\"\\\n&>\u2028é", "\t\r\x00\x1f\x7f"} {
		check(s)
	}
	pool := []rune{'a', 'Z', '0', ' ', '"', '\\', '\n', '<', '>', '&', '\u2028', '\u2029', 'é', '日', '😀', '\ufffd', '\x7f', '\u0085', '\ufeff', '\u00a0'}
	rng := rand.New(rand.NewPCG(7, 11))
	for range 2000 {
		var b strings.Builder
		for range rng.IntN(40) {
			b.WriteRune(pool[rng.IntN(len(pool))])
		}
		check(b.String())
	}
}

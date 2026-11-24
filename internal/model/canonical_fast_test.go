// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"bytes"
	"encoding/json"
	"math"
	"math/rand"
	"strings"
	"testing"
)

// canonicalJSONReference is CanonicalJSON as it was before canonicalizeJSON: the encoding, decoded into a
// generic tree with numbers kept as literals and encoded again with HTML escaping off.
func canonicalJSONReference(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	var x any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e = d.Decode(&x); e != nil {
		return nil, e
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if e = enc.Encode(x); e != nil {
		return nil, e
	}
	return bytes.TrimSuffix(out.Bytes(), []byte{'\n'}), nil
}

type canonSample struct {
	Zeta   string            `json:"zeta"`
	Alpha  []string          `json:"alpha"`
	Mid    map[string]any    `json:"mid"`
	N      float64           `json:"n"`
	I      int64             `json:"i"`
	U      uint64            `json:"u"`
	P      *canonSample      `json:"p,omitempty"`
	Labels map[string]string `json:"labels"`
	Raw    json.RawMessage   `json:"raw,omitempty"`
	B      bool              `json:"b"`
	Z      any               `json:"z"`
}

func randString(r *rand.Rand) string {
	pool := []string{"", "a", "plain text", "<b>&amp;</b>", "tab\there", "new\nline", "quote\"back\\slash", "caf\u00e9", "\u2028\u2029", "emoji \U0001F600", "\x00\x01\x1f", "\xff\xfe invalid utf8", "a/b?c=d&e=f>g<h", "\u007f", "key with space"}
	if r.Intn(4) == 0 {
		var sb strings.Builder
		for range r.Intn(12) {
			sb.WriteRune(rune(r.Intn(0x2fff)))
		}
		return sb.String()
	}
	return pool[r.Intn(len(pool))]
}

func randValue(r *rand.Rand, depth int) any {
	switch k := r.Intn(9); {
	case k == 0:
		return nil
	case k == 1:
		return r.Intn(2) == 0
	case k == 2:
		return r.Int63() - r.Int63()
	case k == 3:
		return []float64{0, 1.5, -2.25, 1e21, 1e-9, 123456789.125, math.MaxFloat64, 5e-324}[r.Intn(8)]
	case k == 4:
		return randString(r)
	case k == 5 && depth < 4:
		a := make([]any, r.Intn(4))
		for i := range a {
			a[i] = randValue(r, depth+1)
		}
		return a
	case k == 6 && depth < 4:
		m := map[string]any{}
		for range r.Intn(5) {
			m[randString(r)] = randValue(r, depth+1)
		}
		return m
	case k == 7:
		return uint64(r.Uint64())
	}
	return randString(r)
}

// CanonicalJSON gives, byte for byte, what the generic decode and encode gave.
func TestCanonicalJSONMatchesTheGenericRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(20261120))
	check := func(v any) {
		t.Helper()
		want, werr := canonicalJSONReference(v)
		got, gerr := CanonicalJSON(v)
		if (werr == nil) != (gerr == nil) || !bytes.Equal(want, got) {
			t.Fatalf("value %#v:\nreference %q (%v)\ngot       %q (%v)", v, want, werr, got, gerr)
		}
	}
	for _, v := range []any{nil, true, 0, "", "x", []int{}, map[string]int{}, struct{}{}, []any{}, map[string]any{"b": 1, "a": []any{map[string]any{"z": 1, "y": 2}}}, math.NaN(), make(chan int)} {
		check(v)
	}
	for i := 0; i < 4000; i++ {
		v := randValue(r, 0)
		check(v)
		s := canonSample{Zeta: randString(r), Alpha: []string{randString(r), randString(r)}, Mid: map[string]any{randString(r): randValue(r, 2), randString(r): randValue(r, 2)}, N: float64(r.Intn(1000)) / 8, I: r.Int63() - r.Int63(), U: r.Uint64(), Labels: map[string]string{randString(r): randString(r), randString(r): randString(r)}, B: r.Intn(2) == 0, Z: randValue(r, 3)}
		if r.Intn(2) == 0 {
			s.P = &canonSample{Zeta: randString(r), Labels: map[string]string{"k": randString(r)}}
		}
		if r.Intn(3) == 0 {
			s.Raw = json.RawMessage(`{"b":[1, 2 ,3],"a":{"y":"<>","x":1.0e5}}`)
		}
		check(s)
	}
}

func BenchmarkCanonicalJSON(b *testing.B) {
	v := canonSample{Zeta: "z", Alpha: []string{"a", "b"}, Mid: map[string]any{"k": 1, "j": "v"}, N: 1.5, I: 7, U: 9, Labels: map[string]string{"service": "api", "env": "prod", "region": "eu"}, B: true}
	b.Run("fast", func(b *testing.B) {
		for range b.N {
			_, _ = CanonicalJSON(v)
		}
	})
	b.Run("reference", func(b *testing.B) {
		for range b.N {
			_, _ = canonicalJSONReference(v)
		}
	})
}

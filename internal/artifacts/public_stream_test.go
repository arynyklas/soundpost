// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"bytes"
	"encoding/json"
	"io"
	"runtime"
	"strings"
	"testing"
)

// The streamed public document is byte for byte what json.Marshal gave the same value: the
// manifest hash and size are computed over these bytes, so a difference would change content
// identity.
func TestPublicMapStreamMatchesJSONMarshal(t *testing.T) {
	for name, doc := range map[string]string{
		"flat":            `{"version":3,"file":"a.js","sources":["a.ts"],"names":["a"],"mappings":"AAAA","sourceRoot":"/r","sourcesContent":["x"],"x_extension":"<&>"}`,
		"html escaping":   `{"version":3,"sources":["<a>&.ts"],"names":["\u2028","<b>"],"mappings":"A  A"}`,
		"spaced raw":      `{ "version" : 3 , "sources" : [ "a" , "b" ] , "names" : [ ] , "mappings" : "" }`,
		"empty":           `{}`,
		"raw separator":   "{\"version\":3,\"names\":[\"a\u2028b\u2029c\"],\"mappings\":\"A\"}",
		"escaped quotes":  `{"version":3,"names":["a\"<b>\\","\\\"&"],"mappings":"AAAA,CAAC;AACA"}`,
		"compact nesting": `{"version":3,"sources":["a.ts","b.ts"],"names":[],"mappings":"AAAA,CAAC;AACA,EAAE","sourceRoot":""}`,
		"sections":        `{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":{"version":3,"sources":["a"],"names":[],"mappings":"AAAA","sourcesContent":["s"]}},{"offset":{"line":9,"column":2},"map":{"version":3,"sources":[],"mappings":""}}]}`,
		"empty sections":  `{"version":3,"sections":[]}`,
		"nested sections": `{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":{"version":3,"sections":[{"offset":{"line":1,"column":1},"map":{"version":3,"mappings":"AAAA"}}]}}]}`,
	} {
		var input map[string]json.RawMessage
		if err := json.Unmarshal([]byte(doc), &input); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		clean, _, err := transformDocument(input, false, 1)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want, err := json.Marshal(clean)
		if err != nil {
			t.Fatal(err)
		}
		var got bytes.Buffer
		n, err := (&publicMap{doc: clean}).WriteTo(&got)
		if err != nil || n != int64(len(want)) || !bytes.Equal(got.Bytes(), want) {
			t.Fatalf("%s: streamed %q (%d, %v), json.Marshal %q", name, got.Bytes(), n, err, want)
		}
	}
}

// Measured against the buffer-then-read shape Put had: encoding a retained document of about
// 8 MiB with json.Marshal allocates its buffer and a copy of it; the streamed encoding allocates
// the leaf values only. Cumulative allocation is deterministic, so the saving is asserted.
func TestPublicMapStreamAllocatesLessThanMarshal(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts differ under the race detector")
	}
	mappings := strings.Repeat("AAAA,CAAC;", 8<<20/10)
	doc := `{"version":3,"sources":["a.ts"],"names":["a"],"mappings":"` + mappings + `"}`
	var input map[string]json.RawMessage
	if err := json.Unmarshal([]byte(doc), &input); err != nil {
		t.Fatal(err)
	}
	clean, _, err := transformDocument(input, false, 1)
	if err != nil {
		t.Fatal(err)
	}
	measure := func(fn func()) uint64 {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		fn()
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}
	var size int
	marshaled := measure(func() {
		b, err := json.Marshal(clean)
		if err != nil {
			t.Fatal(err)
		}
		size = len(b)
		_, _ = io.Copy(io.Discard, bytes.NewReader(b))
	})
	var streamedSize int64
	streamed := measure(func() {
		streamedSize, err = (&publicMap{doc: clean}).WriteTo(io.Discard)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Logf("PUBLIC-ENCODE-MEM public=%d marshal_then_read=%d (%.2fx) streamed=%d (%.2fx)", size, marshaled, float64(marshaled)/float64(size), streamed, float64(streamed)/float64(size))
	if streamedSize != int64(size) {
		t.Fatalf("streamed %d bytes, json.Marshal %d", streamedSize, size)
	}
	if streamed+uint64(size) > marshaled {
		t.Fatalf("streamed %d allocated bytes is not at least one document (%d) below json.Marshal's %d", streamed, size, marshaled)
	}
}

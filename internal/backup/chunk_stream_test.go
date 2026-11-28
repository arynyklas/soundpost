// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"bytes"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// The chunk size passed to the stream functions decides where the object is cut: the ciphertext
// length follows encryptedSize for that size, it round-trips only when read with the same size, and a
// size outside the accepted bounds is refused typed.
func TestStreamChunkSizeDrivesTheCutAndIsVerifiedOnRead(t *testing.T) {
	dek, aad := randomBytes(t, 32), []byte("chunk-size-context")
	for _, chunk := range []int{MinChunkSize, 8 << 10, 64 << 10} {
		for _, n := range []int{0, 1, chunk - 1, chunk, chunk + 1, 3*chunk + 5} {
			plain := randomBytes(t, n)
			var sealed bytes.Buffer
			res, err := encryptStream(dek, aad, chunk, bytes.NewReader(plain), &sealed)
			if err != nil {
				t.Fatal(err)
			}
			chunks := (n + chunk - 1) / chunk
			if chunks == 0 {
				chunks = 1
			}
			if want := headerSize + n + chunks*tagSize; sealed.Len() != want || res.Cipher != int64(want) || encryptedSize(int64(n), chunk) != int64(want) {
				t.Fatalf("chunk=%d n=%d: sealed %d bytes (reported %d), want %d", chunk, n, sealed.Len(), res.Cipher, want)
			}
			var back bytes.Buffer
			if _, err = decryptStream(dek, aad, chunk, bytes.NewReader(sealed.Bytes()), &back); err != nil || !bytes.Equal(back.Bytes(), plain) {
				t.Fatalf("chunk=%d n=%d: round trip failed: %v", chunk, n, err)
			}
			if n > chunk { // a different chunk size cannot read it: the size is part of the format
				var other bytes.Buffer
				if _, err = decryptStream(dek, aad, chunk*2, bytes.NewReader(sealed.Bytes()), &other); err == nil {
					t.Fatalf("chunk=%d n=%d: decrypted with the wrong chunk size", chunk, n)
				}
			}
		}
	}
}

func TestStreamRefusesChunkSizesOutsideTheBounds(t *testing.T) {
	dek, aad := randomBytes(t, 32), []byte("chunk-size-context")
	for _, bad := range []int{0, -4096, 1000, MinChunkSize / 2, MinChunkSize + 1, MaxChunkSize * 2, MaxChunkSize + MinChunkSize} {
		if ValidChunkSize(bad) {
			t.Fatalf("chunk size %d accepted", bad)
		}
		var out bytes.Buffer
		if _, err := encryptStream(dek, aad, bad, bytes.NewReader([]byte("x")), &out); err == nil || out.Len() != 0 {
			t.Fatalf("encrypt with chunk size %d: %v (%d bytes written)", bad, err, out.Len())
		}
		if _, err := decryptStream(dek, aad, bad, bytes.NewReader(make([]byte, 64)), &out); err == nil {
			t.Fatalf("decrypt with chunk size %d: %v", bad, err)
		} else if f, ok := err.(*model.Fault); !ok || f.Code != model.Corrupt {
			t.Fatalf("decrypt with chunk size %d: untyped %v", bad, err)
		}
	}
	for _, good := range []int{MinChunkSize, DefaultChunkSize, MaxChunkSize} {
		if !ValidChunkSize(good) {
			t.Fatalf("chunk size %d refused", good)
		}
	}
}

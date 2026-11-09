// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"soundpost/internal/model"
)

func testKey(t *testing.T, id string) Key {
	t.Helper()
	k, err := GenerateKey(id)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func sealAll(t *testing.T, dek, aad, plain []byte) ([]byte, streamResult) {
	t.Helper()
	var out bytes.Buffer
	res, err := encryptStream(dek, aad, bytes.NewReader(plain), &out)
	if err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), res
}

func TestStreamRoundTripAtChunkBoundaries(t *testing.T) {
	dek, err := newDataKey()
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("backup-1/object-a")
	for _, n := range []int{0, 1, chunkSize - 1, chunkSize, chunkSize + 1, 3*chunkSize + 5} {
		plain := randomBytes(t, n)
		sealed, res := sealAll(t, dek, aad, plain)
		if res.Plain != int64(n) || res.Cipher != int64(len(sealed)) || res.Cipher != encryptedSize(int64(n)) {
			t.Fatalf("n=%d: reported plain=%d cipher=%d, actual cipher=%d, predicted=%d", n, res.Plain, res.Cipher, len(sealed), encryptedSize(int64(n)))
		}
		if res.PlainSum != model.Hash(sha256.Sum256(plain)) || res.CipherSum != model.Hash(sha256.Sum256(sealed)) {
			t.Fatalf("n=%d: stream hashes do not match the bytes", n)
		}
		var back bytes.Buffer
		got, err := decryptStream(dek, aad, bytes.NewReader(sealed), &back)
		if err != nil || !bytes.Equal(back.Bytes(), plain) || got.PlainSum != res.PlainSum {
			t.Fatalf("n=%d: round trip failed: %v", n, err)
		}
	}
}

func TestStreamRejectsTamperTruncationReorderWrongKeyAndWrongContext(t *testing.T) {
	dek, _ := newDataKey()
	other, _ := newDataKey()
	aad := []byte("backup-1/object-a")
	plain := randomBytes(t, 3*chunkSize+17)
	sealed, _ := sealAll(t, dek, aad, plain)
	open := func(name string, key, context, data []byte) {
		t.Helper()
		var out bytes.Buffer
		if _, err := decryptStream(key, context, bytes.NewReader(data), &out); err == nil {
			t.Fatalf("%s: tampered stream decrypted (%d bytes released)", name, out.Len())
		}
	}
	open("wrong key", other, aad, sealed)
	open("wrong object name", dek, []byte("backup-1/object-b"), sealed)
	open("wrong backup", dek, []byte("backup-2/object-a"), sealed)
	for _, at := range []int{0, 3, 19, 40, chunkSize / 2, len(sealed) / 2, len(sealed) - 1} {
		flipped := bytes.Clone(sealed)
		flipped[at] ^= 0x01
		open(fmt.Sprintf("flip byte %d", at), dek, aad, flipped)
	}
	full := 20 + chunkSize + 16 // header + one full chunk
	open("truncated at a chunk boundary", dek, aad, sealed[:full])
	open("truncated mid chunk", dek, aad, sealed[:full+100])
	open("empty", dek, aad, nil)
	open("trailing bytes", dek, aad, append(bytes.Clone(sealed), 0))
	// Reordering two whole chunks must fail even though each chunk is intact.
	swapped := bytes.Clone(sealed)
	a, b := swapped[20:20+chunkSize+16], swapped[20+chunkSize+16:20+2*(chunkSize+16)]
	tmp := bytes.Clone(a)
	copy(a, b)
	copy(b, tmp)
	open("swapped chunks", dek, aad, swapped)
	// Dropping the first chunk shifts every counter.
	open("dropped first chunk", dek, aad, append(bytes.Clone(sealed[:20]), sealed[20+chunkSize+16:]...))
	// Releasing no plaintext of a bad stream into the writer before it is verified
	// is not promised chunk-wise, but the error must be returned; the caller discards.
}

func TestStreamKeysAndNoncesAreFreshPerObject(t *testing.T) {
	dek, _ := newDataKey()
	plain := randomBytes(t, 4096)
	first, _ := sealAll(t, dek, []byte("x"), plain)
	second, _ := sealAll(t, dek, []byte("x"), plain)
	if bytes.Equal(first[:20], second[:20]) {
		t.Fatal("two encryptions of the same object reused the per-object salt")
	}
	if bytes.Equal(first[20:], second[20:]) {
		t.Fatal("identical plaintext produced identical ciphertext")
	}
}

func TestKeyNeverFormatsItsMaterial(t *testing.T) {
	material := randomBytes(t, 32)
	k, err := NewKey("backup-key-1", material)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewKey("short", material[:31]); err == nil {
		t.Fatal("a 31 byte key was accepted")
	}
	forms := []string{fmt.Sprint(k), fmt.Sprintf("%v %+v %#v %s %x %q", k, k, k, k, k, k), fmt.Sprintf("%v", &k)}
	if raw, err := json.Marshal(k); err == nil {
		forms = append(forms, string(raw))
	}
	for _, form := range forms {
		for _, needle := range []string{hex.EncodeToString(material), base64.StdEncoding.EncodeToString(material), base64.RawURLEncoding.EncodeToString(material), string(material)} {
			if bytes.Contains([]byte(form), []byte(needle)) {
				t.Fatalf("key material leaked through formatting: %q", form)
			}
		}
	}
}

func TestWrappedKeysBindTheirContext(t *testing.T) {
	kek, other := testKey(t, "kek-1"), testKey(t, "kek-2")
	dek, _ := newDataKey()
	aad := []byte("backup-1/data")
	wrapped, err := wrapKey(kek, dek, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("wrapped key contains the data key in the clear")
	}
	if got, err := unwrapKey(kek, wrapped, aad); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err = unwrapKey(other, wrapped, aad); err == nil {
		t.Fatal("a different key-encryption key unwrapped the data key")
	}
	if _, err = unwrapKey(kek, wrapped, []byte("backup-2/data")); err == nil {
		t.Fatal("a wrapped key was usable in another backup/purpose")
	}
}

func TestKeyDirLoadsOnlyPrivateKeyFiles(t *testing.T) {
	dir := privateTempDir(t)
	k := testKey(t, "backup-key-1")
	if err := WriteKeyFile(dir, k); err != nil {
		t.Fatal(err)
	}
	if err := WriteKeyFile(dir, k); err == nil {
		t.Fatal("an existing key file was overwritten")
	}
	got, err := KeyDir(dir).Key(context.Background(), "backup-key-1")
	if err != nil || got.ID() != "backup-key-1" || got.b != k.b {
		t.Fatalf("key file did not round trip: %v", err)
	}
	if _, err = KeyDir(dir).Key(context.Background(), "../backup-key-1"); err == nil {
		t.Fatal("key ids may not escape the key directory")
	}
	if _, err = KeyDir(dir).Key(context.Background(), "absent"); err == nil {
		t.Fatal("a missing key was invented")
	}
	if runtime.GOOS != "windows" {
		path := filepath.Join(dir, "backup-key-1.key")
		if err = os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err = KeyDir(dir).Key(context.Background(), "backup-key-1"); err == nil {
			t.Fatal("a world-readable key file was accepted")
		}
	}
	// A file whose recorded id differs from its name is somebody else's key.
	if err = os.WriteFile(filepath.Join(dir, "renamed.key"), mustRead(t, filepath.Join(dir, "backup-key-1.key")), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = KeyDir(dir).Key(context.Background(), "renamed"); err == nil {
		t.Fatal("a key file under the wrong name was accepted")
	}
}

// The directory is part of the secret's protection: a 0600 key file inside a
// directory group- or world-accessible (listable, replaceable by a symlink) is refused.
func TestKeyDirRefusesAGroupOrOtherAccessibleDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	dir := privateTempDir(t)
	if err := WriteKeyFile(dir, testKey(t, "backup-key-1")); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o750, 0o705, 0o755, 0o770} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := KeyDir(dir).Key(context.Background(), "backup-key-1"); faultCode(err) != model.Forbidden {
			t.Fatalf("a key directory with mode %o was accepted: %v", mode, err)
		}
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := KeyDir(dir).Key(context.Background(), "backup-key-1"); err != nil {
		t.Fatalf("a private key directory was refused: %v", err)
	}
	// A key is never written where it could not be read back.
	shared := t.TempDir()
	if err := os.Chmod(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteKeyFile(shared, testKey(t, "backup-key-2")); faultCode(err) != model.Forbidden {
		t.Fatalf("a key was written into a world-readable directory: %v", err)
	}
	if entries, _ := os.ReadDir(shared); len(entries) != 0 {
		t.Fatalf("a refused key write left %d files behind", len(entries))
	}
}

// privateTempDir is a test directory only its owner can enter (t.TempDir is 0755 on POSIX).
func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

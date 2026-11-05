// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"soundpost/internal/durablefs"
	"soundpost/internal/model"
)

// Backup objects are AES-256-GCM in 1 MiB chunks (STREAM construction). Every
// object has its own key: HKDF-SHA256 over the bundle data key, a fresh random
// 16-byte salt and the object's context (backup ID, object name, class). Chunk
// nonces are the chunk counter plus a "final" flag, so a key is never used with
// a repeated nonce, chunks cannot be reordered, dropped or duplicated, and a
// stream cut at a chunk boundary does not authenticate. Bundle data keys are
// wrapped under a key-encryption key (KEK) that lives outside the destination.
const (
	AlgorithmAES256GCM = "aes-256-gcm-chunked-v1"
	chunkSize          = 1 << 20
	streamMagic        = "SPB1"
	saltSize           = 16
	headerSize         = len(streamMagic) + saltSize
	tagSize            = 16
	keyContext         = "soundpost/backup/object/v1\x00"
	wrapContext        = "soundpost/backup/keywrap/v1\x00"
)

var keyID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Key is 256-bit secret material with an identifier. It formats as its ID only
// and refuses to marshal, so it cannot reach a log, manifest or error by accident.
type Key struct {
	id string
	b  [32]byte
}

// NewKey wraps 32 bytes of secret material under id.
func NewKey(id string, material []byte) (Key, error) {
	if !keyID.MatchString(id) || len(material) != 32 {
		return Key{}, model.Fail(model.Invalid)
	}
	k := Key{id: id}
	copy(k.b[:], material)
	return k, nil
}

// GenerateKey creates a fresh random key.
func GenerateKey(id string) (Key, error) {
	var material [32]byte
	if _, err := rand.Read(material[:]); err != nil {
		return Key{}, err
	}
	k, err := NewKey(id, material[:])
	clear(material[:])
	return k, err
}

// ID is the public identifier recorded in manifests.
func (k Key) ID() string { return k.id }

func (k Key) String() string               { return "key:" + k.id }
func (k Key) GoString() string             { return "backup.Key{" + k.id + "}" }
func (k Key) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, k.String()) }
func (k Key) MarshalJSON() ([]byte, error) { return nil, errors.New("backup keys are never marshaled") }
func (k Key) MarshalText() ([]byte, error) { return nil, errors.New("backup keys are never marshaled") }
func (k Key) valid() bool                  { return keyID.MatchString(k.id) && k.b != [32]byte{} }
func (k Key) material() []byte             { return k.b[:] }
func (k Key) aead() (cipher.AEAD, error)   { return gcm(k.b[:]) }
func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// KeyProvider resolves key-encryption keys by ID. Production providers read
// operator-held files or a KMS; the destination never holds a KEK.
type KeyProvider interface {
	Key(ctx context.Context, id string) (Key, error)
}

// StaticKeys is an in-memory provider (tests, tools that already hold the keys).
type StaticKeys map[string]Key

func (s StaticKeys) Key(ctx context.Context, id string) (Key, error) {
	k, ok := s[id]
	if !ok || !k.valid() || k.id != id {
		return Key{}, model.Fail(model.NotFound)
	}
	return k, nil
}

// KeyDir reads <dir>/<id>.key files created by WriteKeyFile. On POSIX systems a
// file readable by group or others is refused.
type KeyDir string

const keyFileMagic = "soundpost-backup-key-v1"

func (d KeyDir) Key(ctx context.Context, id string) (Key, error) {
	if ctx.Err() != nil {
		return Key{}, model.Fail(model.Cancelled)
	}
	if !keyID.MatchString(id) {
		return Key{}, model.Fail(model.Invalid)
	}
	path := filepath.Join(string(d), id+".key")
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return Key{}, model.Fail(model.NotFound)
	}
	if err != nil || !info.Mode().IsRegular() {
		return Key{}, model.Fail(model.Unavailable)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return Key{}, model.Fail(model.Forbidden)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Key{}, model.Fail(model.Unavailable)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 || lines[0] != keyFileMagic || lines[1] != id {
		return Key{}, model.Fail(model.Corrupt)
	}
	material, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return Key{}, model.Fail(model.Corrupt)
	}
	k, err := NewKey(id, material)
	clear(material)
	if err != nil {
		return Key{}, model.Fail(model.Corrupt)
	}
	return k, nil
}

// WriteKeyFile stores k as <dir>/<id>.key with mode 0600; it never overwrites.
func WriteKeyFile(dir string, k Key) error {
	if !k.valid() {
		return model.Fail(model.Invalid)
	}
	if err := durablefs.MkdirAll(dir); err != nil {
		return err
	}
	content := keyFileMagic + "\n" + k.id + "\n" + base64.StdEncoding.EncodeToString(k.b[:]) + "\n"
	return durablefs.Exclusive(filepath.Join(dir, k.id+".key"), []byte(content))
}

type streamResult struct {
	Plain     int64
	Cipher    int64
	PlainSum  model.Hash
	CipherSum model.Hash
}

func newDataKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// wrapKey seals a data key for storage next to the backup. aad binds backup and purpose.
func wrapKey(kek Key, dek, aad []byte) ([]byte, error) {
	if !kek.valid() || len(dek) != 32 {
		return nil, model.Fail(model.Invalid)
	}
	g, err := kek.aead()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize(), g.NonceSize()+len(dek)+g.Overhead())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, dek, append([]byte(wrapContext), aad...)), nil
}

func unwrapKey(kek Key, wrapped, aad []byte) ([]byte, error) {
	if !kek.valid() {
		return nil, model.Fail(model.Invalid)
	}
	g, err := kek.aead()
	if err != nil {
		return nil, err
	}
	if len(wrapped) < g.NonceSize()+g.Overhead() {
		return nil, model.Fail(model.Corrupt)
	}
	dek, err := g.Open(nil, wrapped[:g.NonceSize()], wrapped[g.NonceSize():], append([]byte(wrapContext), aad...))
	if err != nil || len(dek) != 32 {
		return nil, model.Fail(model.Corrupt)
	}
	return dek, nil
}

// encryptedSize is the exact ciphertext length of plain bytes (so a destination
// that needs Content-Length can be told before the first byte is encrypted).
func encryptedSize(plain int64) int64 {
	chunks := (plain + chunkSize - 1) / chunkSize
	if chunks == 0 {
		chunks = 1
	}
	return int64(headerSize) + plain + chunks*tagSize
}

func objectAEAD(dek, salt, aad []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, dek, salt, keyContext+string(aad), 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return gcm(key)
}

func chunkNonce(counter uint64, final bool) []byte {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[:8], counter)
	if final {
		nonce[8] = 1
	}
	return nonce[:]
}

type sumWriter struct {
	w io.Writer
	h hash.Hash
	n int64
}

func (s *sumWriter) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	s.h.Write(p[:n])
	s.n += int64(n)
	return n, err
}

func readFull(r io.Reader, buf []byte) (int, error) {
	n, err := io.ReadFull(r, buf)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return n, nil
	}
	return n, err
}

// encryptStream reads r to EOF and writes the encrypted object to w.
func encryptStream(dek, aad []byte, r io.Reader, w io.Writer) (streamResult, error) {
	var salt [saltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return streamResult{}, err
	}
	g, err := objectAEAD(dek, salt[:], aad)
	if err != nil {
		return streamResult{}, err
	}
	out := &sumWriter{w: w, h: sha256.New()}
	plain := sha256.New()
	if _, err = out.Write(append([]byte(streamMagic), salt[:]...)); err != nil {
		return streamResult{}, err
	}
	cur, nxt := make([]byte, chunkSize), make([]byte, chunkSize)
	curN, err := readFull(r, cur)
	if err != nil {
		return streamResult{}, err
	}
	var total int64
	sealed := make([]byte, 0, chunkSize+tagSize)
	for counter := uint64(0); ; counter++ {
		final, nxtN := true, 0
		if curN == chunkSize {
			if nxtN, err = readFull(r, nxt); err != nil {
				return streamResult{}, err
			}
			final = nxtN == 0
		}
		plain.Write(cur[:curN])
		total += int64(curN)
		sealed = g.Seal(sealed[:0], chunkNonce(counter, final), cur[:curN], aad)
		if _, err = out.Write(sealed); err != nil {
			return streamResult{}, err
		}
		if final {
			break
		}
		cur, nxt = nxt, cur
		curN = nxtN
	}
	res := streamResult{Plain: total, Cipher: out.n}
	copy(res.PlainSum[:], plain.Sum(nil))
	copy(res.CipherSum[:], out.h.Sum(nil))
	return res, nil
}

// decryptStream authenticates and decrypts an object, releasing each chunk's
// plaintext to w only after that chunk verified. A failure means the object is
// unusable; callers write to a temporary file and discard it.
func decryptStream(dek, aad []byte, r io.Reader, w io.Writer) (streamResult, error) {
	cipherSum := sha256.New()
	tee := io.TeeReader(r, cipherSum)
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(tee, header); err != nil || string(header[:len(streamMagic)]) != streamMagic {
		return streamResult{}, model.Fail(model.Corrupt)
	}
	g, err := objectAEAD(dek, header[len(streamMagic):], aad)
	if err != nil {
		return streamResult{}, err
	}
	plain := sha256.New()
	cur, nxt := make([]byte, chunkSize+tagSize), make([]byte, chunkSize+tagSize)
	curN, err := readFull(tee, cur)
	if err != nil {
		return streamResult{}, model.Fail(model.Unavailable)
	}
	cipherLen := int64(headerSize)
	var total int64
	open := make([]byte, 0, chunkSize)
	for counter := uint64(0); ; counter++ {
		final, nxtN := true, 0
		if curN == chunkSize+tagSize {
			if nxtN, err = readFull(tee, nxt); err != nil {
				return streamResult{}, model.Fail(model.Unavailable)
			}
			final = nxtN == 0
		}
		if curN < tagSize {
			return streamResult{}, model.Fail(model.Corrupt)
		}
		open, err = g.Open(open[:0], chunkNonce(counter, final), cur[:curN], aad)
		if err != nil {
			return streamResult{}, model.Fail(model.Corrupt)
		}
		cipherLen += int64(curN)
		plain.Write(open)
		total += int64(len(open))
		if _, err = w.Write(open); err != nil {
			return streamResult{}, err
		}
		if final {
			break
		}
		cur, nxt = nxt, cur
		curN = nxtN
	}
	res := streamResult{Plain: total, Cipher: cipherLen}
	copy(res.PlainSum[:], plain.Sum(nil))
	copy(res.CipherSum[:], cipherSum.Sum(nil))
	return res, nil
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"soundpost/internal/model"
	"strings"
)

func (s *Store) keyPath(id string) (string, error) {
	if id == "local-v1" {
		return filepath.Join(s.dir, "envelope.key"), nil
	}
	if _, err := model.ParseID(id); err != nil {
		return "", os.ErrInvalid
	}
	return filepath.Join(s.dir, "envelope-"+id+".key"), nil
}
func writeSecretFile(path string, value []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(value)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	return err
}
func (s *Store) Seal(secret string) (string, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	id := "local-v1"
	active, err := os.ReadFile(filepath.Join(s.dir, "envelope.active"))
	if err == nil {
		id = string(active)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	path, err := s.keyPath(id)
	if err != nil {
		return "", err
	}
	key, err := os.ReadFile(path)
	if os.IsNotExist(err) && id == "local-v1" {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return "", err
		}
		err = writeSecretFile(path, key)
	}
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return id + ":" + base64.RawStdEncoding.EncodeToString(g.Seal(nonce, nonce, []byte(secret), []byte("soundpost-secret-v1"))), nil
}
func (s *Store) OpenSecret(sealed string) (string, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	id, encoded, ok := strings.Cut(sealed, ":")
	if !ok {
		return "", os.ErrInvalid
	}
	path, err := s.keyPath(id)
	if err != nil {
		return "", err
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(raw) < g.NonceSize() {
		return "", os.ErrInvalid
	}
	value, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], []byte("soundpost-secret-v1"))
	return string(value), err
}

// RotateSecretKey retains old decrypt-only key IDs. Removing them is a separate
// explicitly authorized migration/backup lifecycle, never implicit rotation.
func (s *Store) RotateSecretKey() (string, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	id := model.NewID().String()
	path, err := s.keyPath(id)
	if err != nil {
		return "", err
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return "", err
	}
	if err = writeSecretFile(path, key); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(s.dir, ".envelope-active-")
	if err != nil {
		return "", err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return "", err
	}
	_, err = f.WriteString(id)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	if err = os.Rename(name, filepath.Join(s.dir, "envelope.active")); err != nil {
		return "", err
	}
	return id, nil
}

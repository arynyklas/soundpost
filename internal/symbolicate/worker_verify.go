// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync/atomic"
	"time"
)

// workerCacheQuiet is how long a worker file must have been unchanged (by both
// its modification and status-change time) before a verified hash may be reused.
// File timestamps come from the kernel's coarse clock, so a rewrite within the
// same tick as the last change would not move them; only a file that is older
// than this at verification time can be trusted to show a later change.
var workerCacheQuiet = 2 * time.Second

// workerHashes counts full reads of a worker file made to verify provenance.
var workerHashes atomic.Int64

// fileIdentity is what the kernel changes whenever a regular file's content or
// metadata is written: device, inode, size, mtime and ctime. User space cannot set the ctime of
// a local kernel filesystem (identityOf refuses every other filesystem), so a rewrite that
// restores the old mtime still moves it.
type fileIdentity struct {
	dev, ino           uint64
	size, mtime, ctime int64
}

// verifyWorker proves the native worker file hashes to the configured SHA-256.
// The result is reused only while the opened file keeps the identity it had when
// it was hashed and had been quiet for workerCacheQuiet. It is a parent-side
// pre-check: the worker's own pre-sandbox hash handshake stays authoritative and
// is never skipped.
func (s *Service) verifyWorker() error {
	f, e := os.Open(s.config.WorkerPath)
	if e != nil {
		return e
	}
	defer f.Close()
	id, ok := identityOf(f)
	if ok {
		s.verifyMu.Lock()
		hit := s.verifiedSet && s.verified == id
		s.verifyMu.Unlock()
		if hit {
			return nil
		}
	}
	h := sha256.New()
	workerHashes.Add(1)
	_, e = io.Copy(h, f)
	if e != nil || hex.EncodeToString(h.Sum(nil)) != hex.EncodeToString(s.config.WorkerSHA256[:]) {
		s.verifyMu.Lock()
		s.verifiedSet = false
		s.verifyMu.Unlock()
		return errors.New("worker provenance mismatch")
	}
	if ok {
		// Cache only an identity that held across the read and is old enough.
		after, ok2 := identityOf(f)
		quiet := time.Since(time.Unix(0, max(id.mtime, id.ctime))) >= workerCacheQuiet
		if ok2 && after == id && quiet {
			s.verifyMu.Lock()
			s.verified, s.verifiedSet = id, true
			s.verifyMu.Unlock()
		}
	}
	return nil
}

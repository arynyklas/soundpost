// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/backup"
	"github.com/arynyklas/soundpost/internal/model"
)

const sealedHeader, sealedTag = 20, 16 // stream header and per-chunk tag bytes

// Config.ChunkSize drives the chunking of every object, the manifest records it, and a restore reads
// with the recorded size: a backup made with a non-default chunk size round-trips.
func TestBackupHonoursConfiguredChunkSizeAndRestoreRoundTrips(t *testing.T) {
	l := newLive(t)
	l.append(100, "kept_early")
	l.append(300, "kept_late")
	l.reconcile()
	const chunk = 4096
	plane := backup.EngineDataPlane(l.app.Storage)
	svc, err := backup.New(backup.Config{Control: l.app.Control, Data: l.plane, Processed: backup.AppliedProcessed(plane), Authority: l.authority, Authorizer: l.app.Auth, Keys: l.keys, DataKEK: "data-kek", SecretKEK: "secret-kek", Attempts: backup.DirAttempts(filepath.Join(t.TempDir(), "attempts")), ChunkSize: chunk, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := l.app.Auth.InstanceScope(l.ctx, l.owner, "chunked backup")
	if err != nil {
		t.Fatal(err)
	}
	m, err := svc.Run(l.ctx, scope, l.dest)
	if err != nil {
		t.Fatal(err)
	}
	if m.Encryption.ChunkSize != chunk {
		t.Fatalf("manifest records chunk size %d, want %d", m.Encryption.ChunkSize, chunk)
	}
	multi := 0
	for _, o := range m.Objects {
		chunks := (uint64(o.Size) + chunk - 1) / chunk
		if chunks == 0 {
			chunks = 1
		}
		if want := sealedHeader + uint64(o.Size) + chunks*sealedTag; uint64(o.CipherSize) != want {
			t.Fatalf("object %s: %d plaintext bytes sealed to %d, want %d for %d-byte chunks", o.Name, o.Size, o.CipherSize, want, chunk)
		}
		if chunks > 1 {
			multi++
		}
	}
	if multi == 0 {
		t.Fatal("no object spans two chunks: the fixture does not exercise the chunk size")
	}

	root := l.newRoot()
	if _, err = l.restoreTo(root, m, l.authority); err != nil {
		t.Fatalf("restore of a %d-byte-chunk backup: %v", chunk, err)
	}
	r := l.openRestored(root)
	if _, err = r.activate(l.authority); err != nil {
		t.Fatal(err)
	}
	rows, err := l.rows(r.app, r.reader())
	if err != nil || !rows[100] || !rows[300] {
		t.Fatalf("restored rows %v (%v)", rows, err)
	}
}

// A manifest whose chunk size is outside the accepted bounds (or not a power of two) is refused typed,
// before any backup data is read; so is a Config that asks for one.
func TestManifestChunkSizeOutsideBoundsIsRefusedTyped(t *testing.T) {
	l := newLive(t)
	l.append(100, "row")
	l.reconcile()
	m := l.mustBackup()
	if m.Encryption.ChunkSize != backup.DefaultChunkSize {
		t.Fatalf("default chunk size recorded as %d", m.Encryption.ChunkSize)
	}
	kek, err := l.keys.Key(l.ctx, "data-kek")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []uint32{0, 1000, backup.MinChunkSize / 2, backup.MinChunkSize + 1, backup.MaxChunkSize * 2, 1 << 31} {
		forged := m
		forged.Encryption.ChunkSize = bad
		if err = forged.Sign(kek); err != nil {
			t.Fatal(err)
		}
		raw, err := forged.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = backup.ParseManifest(raw); code(err) != model.Corrupt {
			t.Fatalf("chunk size %d parsed: %v", bad, err)
		}
		dest := &countingDest{Destination: l.dest}
		root := l.newRoot()
		if _, err = l.restorer(l.keys, dest).Restore(l.ctx, forged, backup.DestinationRoot(root), l.authority); code(err) != model.Corrupt {
			t.Fatalf("restore of a manifest with chunk size %d: %v", bad, err)
		}
		if dest.dataOpens() != 0 || fileExists(root) {
			t.Fatalf("chunk size %d: restore touched backup data before refusing", bad)
		}
	}
	for _, bad := range []uint32{1000, backup.MinChunkSize / 2, backup.MaxChunkSize * 2} {
		plane := backup.EngineDataPlane(l.app.Storage)
		_, err = backup.New(backup.Config{Control: l.app.Control, Data: plane, Processed: backup.AppliedProcessed(plane), Authority: l.authority, Authorizer: l.app.Auth, Keys: l.keys, DataKEK: "data-kek", SecretKEK: "secret-kek", Attempts: backup.DirAttempts(filepath.Join(t.TempDir(), "attempts")), ChunkSize: bad})
		if code(err) != model.Invalid {
			t.Fatalf("Config.ChunkSize %d accepted: %v", bad, err)
		}
	}
}

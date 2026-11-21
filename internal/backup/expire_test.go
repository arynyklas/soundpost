// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/backup"
	"github.com/arynyklas/soundpost/internal/model"
)

func objectsOf(t *testing.T, d backup.Destination, id model.ID) []string {
	t.Helper()
	names, err := d.List(context.Background(), "backups/"+id.String()+"/")
	if err != nil {
		t.Fatal(err)
	}
	return names
}

func put(t *testing.T, d backup.Destination, name, body string) {
	t.Helper()
	if err := d.Create(context.Background(), name, strings.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}
}

// Backups past their manifest's expiry are deleted object by object (manifest first), the ones still
// within it are untouched, and a restore of a deleted one finds nothing.
func TestExpireDeletesTheObjectsOfAnExpiredBackupOnly(t *testing.T) {
	l := newLive(t)
	l.append(100, "row")
	l.reconcile()
	first := l.mustBackup()
	second := l.mustBackup()
	if first.ExpiresAt >= second.ExpiresAt {
		t.Fatal("fixture: the two backups must expire at different instants")
	}
	before := objectsOf(t, l.dest, first.ID)
	if len(before) < 67 {
		t.Fatalf("a backup holds %d objects", len(before))
	}
	stamped := false
	for _, n := range before {
		stamped = stamped || strings.HasSuffix(n, "/started")
	}
	if !stamped {
		t.Fatal("an upload leaves no start stamp")
	}
	at := time.Unix(0, int64(first.ExpiresAt)+1)
	opts := backup.ExpireOptions{Keys: l.keys, Now: func() time.Time { return at }}

	early := opts
	early.Now = func() time.Time { return time.Unix(0, int64(first.ExpiresAt)-1) }
	if r, err := backup.ExpireBackups(l.ctx, l.dest, early); err != nil || r.Deleted != 0 || r.Kept != 2 {
		t.Fatalf("before any expiry: %+v %v", r, err)
	}
	report, err := backup.ExpireBackups(l.ctx, l.dest, opts)
	if err != nil || report.Expired != 1 || report.Kept != 1 || report.Deleted != len(before) {
		t.Fatalf("expire: %+v %v (want 1 expired, %d objects)", report, err, len(before))
	}
	if left := objectsOf(t, l.dest, first.ID); len(left) != 0 {
		t.Fatalf("the expired backup left %v", left)
	}
	if _, err = backup.LoadManifest(l.ctx, l.dest, first.ID, l.keys); err == nil {
		t.Fatal("the manifest of a deleted backup loads")
	}
	if _, err = backup.LoadManifest(l.ctx, l.dest, second.ID, l.keys); err != nil {
		t.Fatalf("a backup within its expiry was damaged: %v", err)
	}
	if _, err = l.restoreTo(l.newRoot(), second, l.authority); err != nil {
		t.Fatalf("the surviving backup does not restore: %v", err)
	}
}

// A manifest that does not authenticate is never a reason to delete anything, and uploads are told
// apart from abandoned ones by their start stamp: a fresh one is kept, an old one deleted, one with no
// stamp left alone.
func TestExpireTrustsOnlyAuthenticatedManifestsAndDatedAbandonedUploads(t *testing.T) {
	l := newLive(t)
	l.append(100, "row")
	l.reconcile()
	m := l.mustBackup()
	now := time.Unix(0, int64(m.ExpiresAt)+1)

	t.Run("a forged manifest is left alone", func(t *testing.T) {
		raw := readDest(t, l.dest, backup.ManifestName(m.ID))
		forged := bytes.Replace(raw, []byte(`"sequence":"0"`), []byte(`"sequence":"9"`), 1)
		if bytes.Equal(raw, forged) {
			t.Fatal("fixture: nothing to forge")
		}
		dir := filepath.Join(t.TempDir(), "copy")
		copyTree(t, l.destDir, dir)
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(backup.ManifestName(m.ID))), forged, 0o600); err != nil {
			t.Fatal(err)
		}
		d, err := backup.NewLocalDestination(dir)
		if err != nil {
			t.Fatal(err)
		}
		report, err := backup.ExpireBackups(l.ctx, d, backup.ExpireOptions{Keys: l.keys, Now: func() time.Time { return now }})
		if err != nil || report.Untrusted != 1 || report.Deleted != 0 {
			t.Fatalf("a manifest that does not authenticate: %+v %v", report, err)
		}
	})
	t.Run("a manifest under a key this process does not hold is left alone", func(t *testing.T) {
		report, err := backup.ExpireBackups(l.ctx, l.dest, backup.ExpireOptions{Keys: backup.StaticKeys{}, Now: func() time.Time { return now }})
		if err != nil || report.Untrusted != 1 || report.Deleted != 0 {
			t.Fatalf("an unverifiable manifest: %+v %v", report, err)
		}
	})
	t.Run("abandoned uploads", func(t *testing.T) {
		dir := t.TempDir()
		d, err := backup.NewLocalDestination(dir)
		if err != nil {
			t.Fatal(err)
		}
		old, fresh, unstamped := model.NewID(), model.NewID(), model.NewID()
		stamp := func(at time.Time) string {
			return `{"version":1,"started_ns":"` + strconv.FormatInt(at.UnixNano(), 10) + `"}`
		}
		for id, at := range map[model.ID]time.Time{old: now.Add(-48 * time.Hour), fresh: now.Add(-time.Hour)} {
			put(t, d, "backups/"+id.String()+"/started", stamp(at))
			put(t, d, "backups/"+id.String()+"/obj/slot-00", "partial ciphertext")
			put(t, d, "backups/"+id.String()+"/key/k-data", "wrapped")
		}
		put(t, d, "backups/"+unstamped.String()+"/obj/slot-00", "who knows")
		report, err := backup.ExpireBackups(l.ctx, d, backup.ExpireOptions{Keys: l.keys, Now: func() time.Time { return now }, AbandonedAfter: 24 * time.Hour})
		if err != nil || report.Abandoned != 1 || report.Kept != 1 || report.Untrusted != 1 || report.Deleted != 3 {
			t.Fatalf("abandoned uploads: %+v %v", report, err)
		}
		if got := len(objectsOf(t, d, old)); got != 0 {
			t.Fatalf("the abandoned upload left %d objects", got)
		}
		if got := len(objectsOf(t, d, fresh)); got != 3 {
			t.Fatalf("an upload that may still be running lost objects: %d left", got)
		}
		if got := len(objectsOf(t, d, unstamped)); got != 1 {
			t.Fatalf("objects with neither manifest nor stamp were deleted: %d left", got)
		}
	})
}

// A destination without a delete primitive cannot expire anything and says so.
func TestExpireNeedsADestinationThatCanDelete(t *testing.T) {
	l := newLive(t)
	if _, err := backup.ExpireBackups(l.ctx, createOnly{l.dest}, backup.ExpireOptions{Keys: l.keys}); code(err) != model.Unsupported {
		t.Fatalf("a create-only destination: %v", err)
	}
}

type createOnly struct{ backup.Destination }

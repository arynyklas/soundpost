// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/backup"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/storage"
)

// Tests for the mutants the 01.09 review reported as surviving (see
// l1w18-evidence/backup-survivors-report.md for the id -> test table).

// resigned is m with fn applied and the manifest MAC recomputed: the manifest is authentic, only its
// content differs, so the restore must refuse it on what it says and not on the MAC.
func (l *live) resigned(m backup.BackupManifest, fn func(*backup.BackupManifest)) backup.BackupManifest {
	l.t.Helper()
	c := m
	c.Objects = append([]backup.ObjectRef(nil), m.Objects...)
	c.Encryption.Keys = append([]backup.KeyRef(nil), m.Encryption.Keys...)
	fn(&c)
	if err := backup.ResignForTest(&c, l.keys["data-kek"]); err != nil {
		l.t.Fatal(err)
	}
	return c
}

// refuses restores m from src into a fresh root and requires the refusal want, nothing left behind
// and, when noData, no backup data object read.
func (l *live) refuses(t *testing.T, m backup.BackupManifest, src backup.Destination, want model.Code, noData bool) {
	t.Helper()
	counted := &countingDest{Destination: src}
	root := l.newRoot()
	_, err := l.restorer(l.keys, counted).Restore(l.ctx, m, backup.DestinationRoot(root), l.authority)
	if err == nil || code(err) != want {
		t.Fatalf("restore returned %v, want a %s refusal", err, want)
	}
	if fileExists(root) || len(stageLeftovers(root)) != 0 {
		t.Fatalf("a refused restore left a root or staging directory behind: %v", stageLeftovers(root))
	}
	if noData && counted.dataOpens() != 0 {
		t.Fatalf("the refusal came after %d data objects were read", counted.dataOpens())
	}
}

// corruptOnReadBack stores objects faithfully but reads every data object back with one byte flipped.
type corruptOnReadBack struct{ backup.Destination }

func (d corruptOnReadBack) Open(ctx context.Context, name string) (io.ReadCloser, error) {
	rc, err := d.Destination.Open(ctx, name)
	if err != nil || !strings.Contains(name, "/obj/") {
		return rc, err
	}
	raw, _ := io.ReadAll(rc)
	rc.Close()
	raw[len(raw)/2] ^= 1
	return io.NopCloser(bytes.NewReader(raw)), nil
}

// Every statement of a manifest is checked on its own against what the restore sees, even when the
// manifest is authentic (re-signed): C3, C5, T6, T7, D14, C12, C2, T5, D13, E5, D10.
func TestRestoreHoldsEveryManifestStatementToTheBackupItDescribes(t *testing.T) {
	l := newLive(t)
	l.append(100, "row")
	l.reconcile()
	m := l.mustBackup()
	last := len(m.Objects) - 1

	t.Run("the ciphertext hash of an object (C3)", func(t *testing.T) {
		l.refuses(t, l.resigned(m, func(c *backup.BackupManifest) { c.Objects[last].CipherSHA256[0] ^= 1 }), l.dest, model.Corrupt, false)
	})
	t.Run("the ciphertext size of an object (C3)", func(t *testing.T) {
		l.refuses(t, l.resigned(m, func(c *backup.BackupManifest) { c.Objects[last].CipherSize++ }), l.dest, model.Corrupt, false)
	})
	t.Run("an object the manifest does not list (C5)", func(t *testing.T) {
		l.refuses(t, l.resigned(m, func(c *backup.BackupManifest) { c.Objects = c.Objects[:last] }), l.dest, model.Corrupt, true)
	})
	t.Run("an object under the wrong class (T6)", func(t *testing.T) {
		l.refuses(t, l.resigned(m, func(c *backup.BackupManifest) {
			if c.Objects[0].Class == backup.ClassData {
				c.Objects[0].Class = backup.ClassKeys
			} else {
				c.Objects[0].Class = backup.ClassData
			}
		}), l.dest, model.Corrupt, true)
	})
	t.Run("the reservations digest of the control binding (T7)", func(t *testing.T) {
		l.refuses(t, l.resigned(m, func(c *backup.BackupManifest) { c.Control.ReservationsSHA256[0] ^= 1 }), l.dest, model.Corrupt, false)
	})
	t.Run("an algorithm that is not the one the objects use (D14, C12)", func(t *testing.T) {
		l.refuses(t, l.resigned(m, func(c *backup.BackupManifest) { c.Encryption.Algorithm = "none" }), l.dest, model.Corrupt, true)
	})
	t.Run("a manifest with one key reference (C2, C12)", func(t *testing.T) {
		l.refuses(t, l.resigned(m, func(c *backup.BackupManifest) { c.Encryption.Keys = c.Encryption.Keys[:1] }), l.dest, model.Corrupt, true)
	})
	t.Run("a root that is not empty is refused as a conflict before anything is read (T5)", func(t *testing.T) {
		root := l.newRoot()
		if err := os.MkdirAll(root, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "precious"), []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
		counted := &countingDest{Destination: l.dest}
		if _, err := l.restorer(l.keys, counted).Restore(l.ctx, m, backup.DestinationRoot(root), l.authority); code(err) != model.Conflict {
			t.Fatalf("a non-empty root was refused as %v, want a conflict", err)
		}
		if len(counted.opens) != 0 || len(stageLeftovers(root)) != 0 || string(mustRead(t, filepath.Join(root, "precious"))) != "keep" {
			t.Fatalf("the refusal came after the backup was opened (%d opens) or touched the root", len(counted.opens))
		}
	})
	t.Run("a wrapped key file that names another key or key-encryption key (D13)", func(t *testing.T) {
		for field, value := range map[string]string{"key_id": "someone-elses-key", "kek": "another-kek"} {
			dir := filepath.Join(t.TempDir(), "copy")
			copyTree(t, l.destDir, dir)
			ref := m.Encryption.Keys[0]
			path := filepath.Join(dir, filepath.FromSlash(ref.Object))
			var file map[string]json.RawMessage
			if err := json.Unmarshal(mustRead(t, path), &file); err != nil {
				t.Fatal(err)
			}
			if _, ok := file[field]; !ok {
				t.Fatalf("fixture: wrapped key file has no %q", field)
			}
			file[field], _ = json.Marshal(value)
			raw, err := json.Marshal(file)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(raw)
			forged := l.resigned(m, func(c *backup.BackupManifest) { c.Encryption.Keys[0].ObjectSHA256 = model.Hash(sum) })
			d, err := backup.NewLocalDestination(dir)
			if err != nil {
				t.Fatal(err)
			}
			l.refuses(t, forged, d, model.Corrupt, true)
		}
	})
	t.Run("a manifest stored under another backup's name (E5)", func(t *testing.T) {
		raw := readDest(t, l.dest, backup.ManifestName(m.ID))
		d, err := backup.NewLocalDestination(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		other := model.NewID()
		for _, id := range []model.ID{m.ID, other} {
			if err = d.Create(l.ctx, backup.ManifestName(id), bytes.NewReader(raw), int64(len(raw))); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = backup.LoadManifest(l.ctx, d, m.ID, l.keys); err != nil {
			t.Fatalf("the manifest under its own name was refused: %v", err)
		}
		if _, err = backup.LoadManifest(l.ctx, d, other, l.keys); code(err) != model.Corrupt {
			t.Fatalf("a manifest named for another backup was loaded: %v", err)
		}
	})
	t.Run("an upload the destination stores differently from what was sent (D10)", func(t *testing.T) {
		dest, err := backup.NewLocalDestination(filepath.Join(t.TempDir(), "offhost"))
		if err != nil {
			t.Fatal(err)
		}
		scope, err := l.app.Auth.InstanceScope(l.ctx, l.owner, "scheduled backup")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = l.svc.Run(l.ctx, scope, corruptOnReadBack{dest}); code(err) != model.Unavailable {
			t.Fatalf("a backup whose stored bytes differ from the uploaded ones was published: %v", err)
		}
		names, _ := dest.List(l.ctx, "")
		for _, n := range names {
			if strings.HasSuffix(n, "manifest.json") {
				t.Fatalf("a manifest was published over a corrupt upload: %v", names)
			}
		}
	})
}

// A restore fences the snapshot store of every data group at the backup's own deletion-ledger
// generation before any data is read (D9): afterwards no older generation can be installed there.
func TestRestoreFencesEveryDataGroupAtTheBackupsGeneration(t *testing.T) {
	l := newLive(t)
	l.append(100, "kept")
	l.append(200, "deleted")
	l.reconcile()
	if receipt := l.deleteRange(150, 250); receipt.Phase != model.DeletePhaseComplete {
		t.Fatalf("deletion did not complete: %+v", receipt)
	}
	m := l.mustBackup()
	if m.Data.Generation < 1 {
		t.Fatalf("fixture: the backup is at generation %d, a fence below it cannot be observed", m.Data.Generation)
	}
	root := l.newRoot()
	if _, err := l.restoreTo(root, m, l.authority); err != nil {
		t.Fatal(err)
	}
	for slot := range 64 {
		store, err := replica.OpenSnapshotStore(storage.SlotDirectory(filepath.Join(root, "raft", "data"), uint16(slot)), m.Data.Applied[slot].Group, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = store.RequireGeneration(uint64(m.Data.Generation) - 1); !errors.Is(err, replica.ErrStale) {
			t.Fatalf("slot %d: the restored store accepts a snapshot older than the backup's generation: %v", slot, err)
		}
	}
}

// Restore quarantines every pre-restore structure by itself, not through the one that happens to
// mask it (Q4, Q6-Q9, E11-E14): the state the restored installation opens holds no old session, no
// live server token, no elevation, no member, admin, grant or team, no unrevoked source, a bumped
// epoch and the audit record of the quarantine.
func TestRestoreQuarantinesEveryPreRestoreStructureItself(t *testing.T) {
	l := newLive(t)
	l.append(100, "row")
	l.reconcile()
	org := l.org.String()
	err := l.app.Control.Update(l.ctx, func(st *control.State) error {
		o := st.Orgs[org]
		o.Admins = map[string]bool{l.ownerS.User.String(): true}
		o.Teams = map[string]model.ControlTeam{model.NewID().String(): {Members: []model.ID{l.ownerS.User}, Projects: []model.ID{l.project}, Permissions: []string{string(auth.Read)}, Enabled: true}}
		st.Orgs[org] = o
		st.ServerTokens = map[string]model.ControlServerToken{"token-digest": {ID: model.NewID(), Principal: l.ownerS.User, Org: l.org, Projects: []model.ID{l.project}, Permissions: []string{string(auth.Read)}}}
		st.OIDC = map[string]json.RawMessage{"elevation:test": json.RawMessage(`{"user":"x"}`)}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var epoch uint64
	_ = l.app.Control.View(l.ctx, func(st control.State) error {
		o := st.Orgs[org]
		epoch = uint64(o.Epoch)
		if len(st.Sessions) == 0 || len(o.Members) == 0 || len(o.Admins) == 0 || len(o.Grants) == 0 || len(o.Teams) == 0 || len(st.ServerTokens) == 0 || len(st.OIDC) == 0 {
			t.Fatalf("fixture: the live state lacks a structure the quarantine must clear: sessions=%d members=%d admins=%d grants=%d teams=%d tokens=%d oidc=%d", len(st.Sessions), len(o.Members), len(o.Admins), len(o.Grants), len(o.Teams), len(st.ServerTokens), len(st.OIDC))
		}
		for _, s := range st.Sources {
			if s.Revoked || s.Retired {
				t.Fatal("fixture: the source is already inactive")
			}
		}
		return nil
	})
	m := l.mustBackup()
	root := l.newRoot()
	if _, err = l.restoreTo(root, m, l.authority); err != nil {
		t.Fatal(err)
	}
	r := l.openRestored(root)
	_ = r.app.Control.View(l.ctx, func(st control.State) error {
		if len(st.Sessions) != 0 {
			t.Errorf("%d pre-restore sessions survived", len(st.Sessions))
		}
		for key := range st.OIDC {
			if !strings.HasPrefix(key, "restore:") {
				t.Errorf("the pre-restore OIDC/elevation entry %q survived", key)
			}
		}
		for key, tok := range st.ServerTokens {
			if !tok.Revoked {
				t.Errorf("server token %q is still active", key)
			}
		}
		for id, s := range st.Sources {
			if !s.Revoked {
				t.Errorf("source %s is still active", id)
			}
		}
		if len(st.SourceCredentials) != 0 {
			t.Errorf("%d source credential digests survived", len(st.SourceCredentials))
		}
		o := st.Orgs[org]
		if len(o.Members) != 0 || len(o.Admins) != 0 || len(o.Grants) != 0 || len(o.Teams) != 0 {
			t.Errorf("org access survived: members=%d admins=%d grants=%d teams=%d", len(o.Members), len(o.Admins), len(o.Grants), len(o.Teams))
		}
		if uint64(o.Epoch) <= epoch {
			t.Errorf("the org epoch did not advance (%d -> %d): scopes minted before the restore still live", epoch, o.Epoch)
		}
		for id, u := range st.Users {
			if !u.Disabled {
				t.Errorf("account %s is still enabled", id)
			}
		}
		audited := false
		for _, a := range st.Audits {
			audited = audited || a.Action == "restore.quarantine"
		}
		if !audited {
			t.Error("the quarantine left no audit record")
		}
		return nil
	})
}

// A backup is verified from the backup side before it is published (G2): a sealed certificate
// whose gap interval is not what its attestation says never becomes a manifest, even though the
// attestation names a committed fact for it.
func TestBackupDoesNotPublishACertificateItsOwnRestoreWouldRefuse(t *testing.T) {
	l := newLive(t)
	l.append(100, "processed_before_h")
	l.reconcile()
	plane := backup.EngineDataPlane(l.app.Storage)
	h := fixedProcessed{}
	for _, c := range plane.Applied() {
		h[c.Group] = uint64(c.Index)
	}
	perSlot := map[uint16]uint64{}
	for i := range 5 {
		a := l.append(int64(200+i), "unprocessed_then_reclaimed")
		perSlot[a.batch.RouteSlot]++
	}
	l.reconcile()
	if _, err := l.app.Storage.CreateSnapshots(l.ctx); err != nil {
		t.Fatal(err)
	}
	if err := l.app.Storage.CompactJournals(l.ctx); err != nil {
		t.Fatal(err)
	}
	for slot, n := range perSlot {
		group := plane.Applied()[slot].Group
		after := h[group]
		if _, err := l.app.Control.RecordEvidenceGap(l.ctx, model.EvidenceGap{Org: l.org, Project: l.project, Group: group, After: model.Uint64(after), Through: model.Uint64(after + n), Count: model.Uint64(n), Start: 200, End: 204, Signals: []model.Kind{model.Metric}, Reason: "unprocessed_expiry", RecordedAt: model.UnixNano(time.Now().UnixNano())}); err != nil {
			t.Fatal(err)
		}
	}
	run := func(tamper bool) (backup.BackupManifest, error) {
		tp := &tamperPlane{DataPlane: l.plane, tamper: tamper}
		svc, err := backup.New(backup.Config{Control: l.app.Control, Data: tp, Processed: h, Authority: l.authority, Authorizer: l.app.Auth, Keys: l.keys, DataKEK: "data-kek", SecretKEK: "secret-kek", Attempts: backup.DirAttempts(filepath.Join(t.TempDir(), "attempts")), Clock: time.Now})
		if err != nil {
			t.Fatal(err)
		}
		scope, err := l.app.Auth.InstanceScope(l.ctx, l.owner, "gap backup")
		if err != nil {
			t.Fatal(err)
		}
		return svc.Run(l.ctx, scope, l.dest)
	}
	if m, err := run(false); err != nil || len(m.Gaps) == 0 {
		t.Fatalf("fixture: the honest backup over committed gaps failed (%d gaps): %v", len(m.Gaps), err)
	}
	if _, err := run(true); code(err) != model.Corrupt {
		t.Fatalf("a backup over a gap interval its attestation does not describe was published: %v", err)
	}
}

// tamperPlane lets a test change the certificate a session sealed before the driver builds the backup from it.
type tamperPlane struct {
	backup.DataPlane
	tamper bool
}

func (p *tamperPlane) Begin(ctx context.Context, owner model.ID, cut storage.ControlCut) (backup.PlaneSession, error) {
	s, err := p.DataPlane.Begin(ctx, owner, cut)
	if err != nil {
		return nil, err
	}
	return &tamperSession{PlaneSession: s, tamper: p.tamper}, nil
}

type tamperSession struct {
	backup.PlaneSession
	tamper bool
}

func (s *tamperSession) Seal(ctx context.Context, gaps []storage.DeclaredGap) (storage.SealedBackup, error) {
	sealed, err := s.PlaneSession.Seal(ctx, gaps)
	if err != nil || !s.tamper {
		return sealed, err
	}
	intervals := append([]storage.ReplayInterval(nil), sealed.Bundle.Replay.Intervals...)
	for i := range intervals {
		if intervals[i].Mode == "gap" {
			intervals[i].Count++
		}
	}
	sealed.Bundle.Replay.Intervals = intervals
	return sealed, nil
}

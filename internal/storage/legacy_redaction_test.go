// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// A backup sealed before the Redacted/Retained markers existed (version 1 evidence, whole-history
// slot snapshots) lists the erased batches of an installation without them. Its evidence digest is
// the digest of the evidence WITHOUT markers, so the installed bytes - which do carry redacted
// batches - derive evidence with markers and the digests differ. 09.01x-W1 gives exactly that shape
// a typed refusal instead of the generic corrupt, and keeps every other mismatch corrupt.

const legacyReason = "legacy_bundle_needs_reseal" // the stable SafeDetail, spelled out so a rename is a test failure

func fileBytes(t *testing.T, s replica.Snapshot, name string) []byte {
	t.Helper()
	f, err := s.File(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// wholeHistoryBundle rebuilds a real sealed backup of an erased installation in the form the code
// before the windowed cut wrote: every slot snapshot carries its whole command history
// (slotMachine.Snapshot, the form a snapshot sent to a peer has), the evidence is version 1 and it
// is derived from those histories exactly as a build that records the markers derives it. It
// returns the bundle and the 64 slot streams.
func wholeHistoryBundle(t *testing.T, x *eraseEnv, sealed SealedBackup) (BackupBundle, [][]byte) {
	t.Helper()
	ctx := context.Background()
	bundle := sealed.Bundle
	bundle.Version = 1
	bundle.Snapshots = make([]replica.SnapshotManifest, len(sealed.Snapshots))
	streams := make([][]byte, len(sealed.Snapshots))
	scratch := t.TempDir()
	installed := make([]replica.Snapshot, len(sealed.Snapshots))
	for slot, orig := range sealed.Snapshots {
		state, err := (&slotMachine{engine: x.e, slot: uint16(slot)}).Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		var envelope map[string]json.RawMessage
		if err = json.Unmarshal(fileBytes(t, orig, "envelope.json"), &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope["state"], err = json.Marshal(state); err != nil {
			t.Fatal(err)
		}
		body := map[string][]byte{"ledger.json": fileBytes(t, orig, "ledger.json"), "raft.conf": fileBytes(t, orig, "raft.conf")}
		if body["envelope.json"], err = json.Marshal(envelope); err != nil {
			t.Fatal(err)
		}
		m := orig.Manifest
		m.Files = nil
		for _, name := range []string{"envelope.json", "ledger.json", "raft.conf"} { // manifest order is sorted by name
			sum := sha256.Sum256(body[name])
			m.Files = append(m.Files, replica.SnapshotFile{Name: name, Size: uint64(len(body[name])), SHA256: model.Hash(sum)})
			streams[slot] = append(streams[slot], body[name]...)
		}
		m.Checksum = model.Hash{}
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		m.Checksum = model.HashCanonical(raw)
		bundle.Snapshots[slot] = m
		store, err := replica.OpenSnapshotStore(SlotDirectory(scratch, uint16(slot)), m.Group, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = store.InstallSnapshot(ctx, m, bytes.NewReader(streams[slot])); err != nil {
			t.Fatalf("slot %d: whole-history snapshot: %v", slot, err)
		}
		cur, ok := store.Current()
		if !ok {
			t.Fatalf("slot %d: no installed snapshot", slot)
		}
		installed[slot] = cur
	}
	var err error
	if bundle.Quota, err = quotaEvidence(installed); err != nil {
		t.Fatal(err)
	}
	bundle.Digest = bundle.seal()
	if err = verifyReplayAgainstSnapshots(bundle, installed); err != nil {
		t.Fatalf("fixture: the whole-history bundle does not verify its own replay: %v", err)
	}
	return bundle, streams
}

// stripMarkers turns a bundle into what a build before the markers sealed: the same evidence
// without Redacted/Retained, resealed with valid digests.
func stripMarkers(b BackupBundle) BackupBundle {
	b.Quota.Consumed = append([]ReservationEvidence(nil), b.Quota.Consumed...)
	for i := range b.Quota.Consumed {
		b.Quota.Consumed[i].Redacted, b.Quota.Consumed[i].Retained = false, nil
	}
	return resealBundle(b)
}

func resealBundle(b BackupBundle) BackupBundle {
	b.Quota.Digest = b.Quota.seal()
	b.Digest = b.seal()
	return b
}

// erasedHistoryBackup erases one of two metric series, seals a backup and returns it in whole-history form.
func erasedHistoryBackup(t *testing.T) (*eraseEnv, BackupBundle, [][]byte) {
	t.Helper()
	ctx := context.Background()
	x := newEraseEnv(t)
	if err := x.store.BindAdmissionOwner(x.e); err != nil {
		t.Fatal(err)
	}
	x.appendRecords(model.NewID(), bothDeadlines, x.metric("gone_series", 5))
	x.appendRecords(model.NewID(), bothDeadlines, x.metric("kept_series", 500))
	if _, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}, nil); err != nil {
		t.Fatal(err)
	}
	if err := x.store.ReconcileAdmissions(ctx); err != nil {
		t.Fatal(err)
	}
	backup, err := x.e.BeginBackup(ctx, controlCut(t, x.e, x.store))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := backup.Seal(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	bundle, streams := wholeHistoryBundle(t, x, sealed)
	marked := 0
	for _, c := range bundle.Quota.Consumed {
		if c.Redacted {
			marked++
		}
	}
	if marked != 1 || len(bundle.Quota.Consumed) != 2 {
		t.Fatalf("fixture: %d of %d consumed batches are marked redacted, want 1 of 2", marked, len(bundle.Quota.Consumed))
	}
	return x, bundle, streams
}

func installLegacy(t *testing.T, x *eraseEnv, b BackupBundle, streams [][]byte) (*Engine, error) {
	t.Helper()
	return openRestoredEngine(t, t.TempDir(), x.a, x.store, b.Identity, func(e *Engine, raft string) error {
		return e.InstallBackup(context.Background(), raft, b, func(slot uint16) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(streams[slot])), nil
		})
	})
}

// Control for the harness: the whole-history form of a backup that records its markers installs
// and activates, so the refusals below are about the markers and nothing else.
func TestWholeHistoryBundleWithRedactedBatchActivates(t *testing.T) {
	x, bundle, streams := erasedHistoryBackup(t)
	cert, err := ReconcileQuota(bundle)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := installLegacy(t, x, bundle, streams)
	if err != nil {
		t.Fatalf("a whole-history bundle with its markers must install: %v", err)
	}
	if err = restored.CommitQuotaReconciliation(context.Background(), cert); err != nil {
		t.Fatalf("a whole-history bundle with its markers must activate: %v", err)
	}
}

// A bundle sealed before the markers: refused with a typed reason the operator can act on, not corrupt.
func TestLegacyBundleWithRedactedBatchesIsRefusedWithATypedReason(t *testing.T) {
	x, bundle, streams := erasedHistoryBackup(t)
	legacy := stripMarkers(bundle)
	if _, err := ReconcileQuota(legacy); err != nil {
		t.Fatalf("fixture: the legacy bundle must be self-consistent: %v", err)
	}
	restored, err := installLegacy(t, x, legacy, streams)
	if err == nil {
		t.Fatal("a bundle whose evidence lacks the markers of its redacted batches was installed")
	}
	if restored != nil {
		t.Fatal("a refused install returned an engine")
	}
	f := faultOf(t, err)
	if f == nil || f.Code != model.Unsupported || f.SafeDetail != legacyReason {
		t.Fatalf("refusal is %v, want unsupported (%s)", err, legacyReason)
	}
}

// The typed reason is for the exact legacy shape only: the bundle's evidence equals what the
// installed bytes derive once their markers are removed, and carries none of its own. Every other
// disagreement stays what it was (corrupt where the install's own comparison refuses, the
// reconciliation's code where that refuses first), and no forgery is ever accepted as legacy.
func TestLegacyShapeIsNotAForgeryLoophole(t *testing.T) {
	x, bundle, streams := erasedHistoryBackup(t)
	type forgery struct {
		forge func(b BackupBundle) BackupBundle
		want  model.Code
	}
	retainedOf := func(b BackupBundle, f func(*ReservationEvidence)) BackupBundle {
		b.Quota.Consumed = append([]ReservationEvidence(nil), b.Quota.Consumed...)
		for i := range b.Quota.Consumed {
			f(&b.Quota.Consumed[i])
		}
		return resealBundle(b)
	}
	forgeries := map[string]forgery{
		"markers stripped and a charged source changed": {func(b BackupBundle) BackupBundle {
			b = stripMarkers(b)
			b.Quota.Consumed[0].Source = model.NewID()
			return resealBundle(b)
		}, model.Corrupt},
		"markers stripped and a charged series added": {func(b BackupBundle) BackupBundle {
			b = stripMarkers(b)
			b.Quota.Consumed[0].Series = append(append([]string(nil), b.Quota.Consumed[0].Series...), "phantom")
			return resealBundle(b)
		}, model.Corrupt},
		"markers stripped and a charged byte count changed": {func(b BackupBundle) BackupBundle {
			b = stripMarkers(b)
			b.Quota.Consumed[0].Bytes += 7
			return resealBundle(b)
		}, model.Conflict},
		"markers stripped and a batch dropped from the evidence": {func(b BackupBundle) BackupBundle {
			b = stripMarkers(b)
			b.Quota.Consumed = b.Quota.Consumed[1:]
			return resealBundle(b)
		}, model.Unavailable},
		"the marker moved to the batch nobody erased": {func(b BackupBundle) BackupBundle {
			return retainedOf(b, func(c *ReservationEvidence) {
				if c.Redacted {
					c.Redacted, c.Retained = false, nil
				} else {
					c.Redacted, c.Retained = true, []string{}
				}
			})
		}, model.Corrupt},
		"a redaction claimed for the batch nobody erased": {func(b BackupBundle) BackupBundle {
			return retainedOf(b, func(c *ReservationEvidence) { c.Redacted = true })
		}, model.Corrupt},
		"a retained series the erased batch does not keep": {func(b BackupBundle) BackupBundle {
			return retainedOf(b, func(c *ReservationEvidence) {
				if c.Redacted {
					c.Retained = []string{"phantom"}
				}
			})
		}, model.Corrupt},
	}
	for name, f := range forgeries {
		t.Run(name, func(t *testing.T) {
			restored, err := installLegacy(t, x, f.forge(bundle), streams)
			if err == nil {
				t.Fatalf("a forged bundle was installed (engine returned: %v)", restored != nil)
			}
			fault := faultOf(t, err)
			if fault == nil || fault.SafeDetail == legacyReason || fault.Code != f.want {
				t.Fatalf("forged evidence refused as %v, want %s and never the legacy reason", err, f.want)
			}
		})
	}
}

// A backup of an installation that erased nothing has no marker to be missing: it installs.
func TestWholeHistoryBundleWithoutRedactionsIsNotLegacy(t *testing.T) {
	ctx := context.Background()
	x := newEraseEnv(t)
	if err := x.store.BindAdmissionOwner(x.e); err != nil {
		t.Fatal(err)
	}
	x.appendRecords(model.NewID(), bothDeadlines, x.metric("only_series", 500))
	if err := x.store.ReconcileAdmissions(ctx); err != nil {
		t.Fatal(err)
	}
	backup, err := x.e.BeginBackup(ctx, controlCut(t, x.e, x.store))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := backup.Seal(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	bundle, streams := wholeHistoryBundle(t, x, sealed)
	cert, err := ReconcileQuota(bundle)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := installLegacy(t, x, bundle, streams)
	if err != nil {
		t.Fatalf("a bundle with nothing erased was refused: %v", err)
	}
	if err = restored.CommitQuotaReconciliation(ctx, cert); err != nil {
		t.Fatal(err)
	}
}

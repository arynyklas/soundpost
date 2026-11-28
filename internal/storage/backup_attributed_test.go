// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"testing"
)

// A voter's erasure loop proposes its own statements (its protocol declaration, its disk
// incarnation) whenever it has a leader, which on a node that has just started is at any moment, so
// they land in slot 0 after the control cut's highwater H and before the data cut D of a backup taken
// from that node. The replica layer records who proposed them and the apply copies it into the stored
// command (adaptedEntry), while the journal form the replay certificate is built from never carries
// it: the digest of the same command differed between the two forms, and the seal of a perfectly good
// cut answered `corrupt` (cmd/soundpost TestBackupCLIBacksUpAVoterAndSeedsARestoredCluster failed in CI
// with it, and failed 5 of 90 runs under CPU load on a worker VM: the journal side was erase_ack or
// erase_unack without a proposer, the snapshot side the same command with one).
func TestBackupSealsACutHoldingTheVotersOwnErasureStatements(t *testing.T) {
	store, service, credential, descriptor := fixture(t)
	scope, first := normalized(t, store, service, credential, descriptor)
	engine, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err = engine.Append(ctx, scope, first); err != nil {
		t.Fatal(err)
	}
	cut := controlCut(t, engine, store)
	backup, err := engine.BeginBackup(ctx, cut)
	if err != nil {
		t.Fatal(err)
	}
	// After H: the declaration of the protocol this voter speaks (erase_ack), then, every member having
	// declared, the incarnation of its disk (erase_unack).
	if err = engine.declareErasure(ctx); err != nil {
		t.Fatal(err)
	}
	sealed, err := backup.Seal(ctx, nil)
	if err != nil {
		t.Fatalf("the seal of a cut that holds this voter's own erase_ack and erase_unack failed: %v", err)
	}
	var after uint64
	for _, in := range sealed.Bundle.Replay.Intervals {
		if in.Group == engine.group(eraseAckSlot) {
			if in.Mode != "replay" {
				t.Fatalf("slot %d interval is %q, want replay", eraseAckSlot, in.Mode)
			}
			after += uint64(in.Count)
		}
	}
	if after != 2 {
		t.Fatalf("the certificate covers %d commands of slot %d after H, want the 2 statements", after, eraseAckSlot)
	}
	// What a restore re-derives from the sealed snapshot bytes agrees with what was sealed.
	if err = verifyReplayAgainstSnapshots(sealed.Bundle, sealed.Snapshots); err != nil {
		t.Fatalf("the sealed bundle does not verify against its own snapshots: %v", err)
	}
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// The replica layer recognizes a retry by the bytes of the proposal (replica.sameProposal), and the
// binary envelope and the JSON form are different bytes for one fragment. A retry of an applied
// fragment must therefore never be a second proposal of the same replica command under the other
// form. It is not: commitReplicated mints a fresh command ID for every proposal and encodes the
// payload once, the replica layer forwards that payload verbatim, and the retry of an upload
// (WriteBlob after a lost acknowledgement) is deduplicated by the artifact's own receipt, ordinal
// and hash, never by command ID. This test is that guarantee, in both directions: an upload
// interrupted after its first fragment under one wire form is retried under the other (the
// switch flipped between the attempts) and completes with the one receipt every voter verifies.
func TestFragmentUploadRetriedAcrossAWireFormFlip(t *testing.T) {
	for _, tc := range []struct {
		name          string
		first, second bool
	}{
		{"envelope then json", true, false},
		{"json then envelope", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newBlobOnVoters(t, false)
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			leader := x.v.engines[1]
			m := orphanManifest(t, x.store, x.scope, x.manifest)
			slot := int(model.BlobOwnerSlot(m.Org, m.Project, m.Root))

			start := leader.envelopesProposed.Load()
			leader.EnableFragmentEnvelope(tc.first)
			commits := 0
			leader.setFault(func(at string) error {
				if at == "blob_fragment_committed" {
					if commits++; commits == 1 {
						return errors.New("acknowledgement lost after the first fragment")
					}
				}
				return nil
			})
			x.v.leadSlot(t, slot, 1, time.Now().Add(30*time.Second))
			if _, err := leader.WriteBlob(ctx, x.scope, m, bytes.NewReader(x.raw)); err == nil {
				t.Fatal("fixture invalid: the interrupted upload succeeded")
			}
			leader.setFault(nil)
			if commits != 1 {
				t.Fatalf("fixture invalid: %d fragments committed before the interruption", commits)
			}
			wantFirst := uint64(0)
			if tc.first {
				wantFirst = 1
			}
			if got := leader.envelopesProposed.Load() - start; got != wantFirst {
				t.Fatalf("first attempt proposed %d envelopes, want %d", got, wantFirst)
			}

			// The switch flips between the attempts: the retry proposes the remaining fragments in the
			// other form and meets the applied one in the receipt, not in the replica's retry table.
			leader.EnableFragmentEnvelope(tc.second)
			before := leader.envelopesProposed.Load()
			x.v.leadSlot(t, slot, 1, time.Now().Add(30*time.Second))
			receipt, err := leader.WriteBlob(ctx, x.scope, m, bytes.NewReader(x.raw))
			if err != nil {
				t.Fatalf("the retry under the other wire form failed: %v", err)
			}
			remaining := uint64(len(receipt.Fragments) - 1)
			if got := leader.envelopesProposed.Load() - before; tc.second && got != remaining || !tc.second && got != 0 {
				t.Fatalf("retry proposed %d envelopes for %d remaining fragments (envelope on: %v)", got, remaining, tc.second)
			}
			leader.EnableFragmentEnvelope(false)
			// And a second retry of the finished upload, in either form, answers the same receipt.
			again, err := leader.WriteBlob(ctx, x.scope, m, bytes.NewReader(x.raw))
			if err != nil {
				t.Fatalf("the retry of a complete upload failed: %v", err)
			}
			want, _ := model.CanonicalJSON(receipt)
			if got, _ := model.CanonicalJSON(again); !bytes.Equal(got, want) {
				t.Fatal("the retry of a complete upload answered another receipt")
			}
			x.v.converge(t, nil)
			for node := uint64(1); node <= 3; node++ {
				if err := x.v.engines[node].VerifyBlob(ctx, receipt); err != nil {
					t.Fatalf("voter %d cannot verify the artifact written across the flip: %v", node, err)
				}
				for i := range receipt.Fragments {
					if got := x.holds(node, m, uint32(i)); len(got) == 0 || !bytes.Equal(got, x.holds(1, m, uint32(i))) {
						t.Fatalf("voter %d holds other bytes for fragment %d", node, i)
					}
				}
			}
		})
	}
}

// A retry of an applied fragment by command ID never reaches the replica's proposal comparison:
// slotMachine.Validate runs first and answers Stale for an application index the engine has passed.
// So the wire form of the retry cannot turn it into a conflict; the form is only compared for a
// duplicate that is still in the log, and no caller proposes one command ID twice (commitReplicated
// mints a fresh ID for every proposal).
func TestRetryByCommandIDOfAnAppliedFragmentIsStaleInEitherForm(t *testing.T) {
	for _, first := range []string{"envelope", "json"} {
		t.Run(first+" first", func(t *testing.T) {
			x := newBlobOnVoters(t, false)
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			leader := x.v.engines[1]
			m := orphanManifest(t, x.store, x.scope, x.manifest)
			slot := model.BlobOwnerSlot(m.Org, m.Project, m.Root)
			x.v.leadSlot(t, int(slot), 1, time.Now().Add(30*time.Second))
			reservation, err := x.scope.ValidateBlobReservation(ctx, m)
			if err != nil {
				t.Fatal(err)
			}
			size := min(len(x.raw), model.ArtifactFragmentLimit)
			leader.mu.Lock()
			index := leader.indexes[slot] + 1
			leader.mu.Unlock()
			bytesOf := bytes.Clone(x.raw[:size])
			command := walEntry{Type: "artifact_fragment", Artifact: &model.ArtifactFragment{Manifest: m, Reservation: reservation, Bytes: bytesOf, Hash: model.HashCanonical(bytesOf), Cursor: model.Cursor{Group: leader.group(slot), Index: model.Uint64(index)}}}
			envelope, ok, err := encodeFragmentEnvelope(command)
			if err != nil || !ok {
				t.Fatalf("envelope: %v %v", ok, err)
			}
			text, err := encodeWAL(command)
			if err != nil {
				t.Fatal(err)
			}
			forms := map[string][]byte{"envelope": envelope, "json": text}
			other := map[string]string{"envelope": "json", "json": "envelope"}[first]
			id := model.NewID()
			propose := func(form string) error {
				_, err := leader.repl.groups[slot].Propose(ctx, replica.Entry{ID: id, Kind: replica.Artifact, Payload: forms[form], ApplicationIndex: index})
				return err
			}
			if err := propose(first); err != nil {
				t.Fatalf("the first proposal: %v", err)
			}
			same, otherForm := propose(first), propose(other)
			if same == nil || otherForm == nil {
				t.Fatalf("a retry of an applied command by ID was accepted (same form: %v, other form: %v)", same, otherForm)
			}
			if errors.Is(same, replica.ErrConflict) || errors.Is(otherForm, replica.ErrConflict) {
				t.Fatalf("a retry became a conflict (same form: %v, other form: %v)", same, otherForm)
			}
			if faultOf(t, same).Code != faultOf(t, otherForm).Code {
				t.Fatalf("the form changed the answer: same form %v, other form %v", same, otherForm)
			}
		})
	}
}

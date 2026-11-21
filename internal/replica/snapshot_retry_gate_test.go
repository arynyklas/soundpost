// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	pb "go.etcd.io/raft/v3/raftpb"

	"github.com/arynyklas/soundpost/internal/model"
)

// 10.13-W2. A snapshot envelope whose retry table is kept by digest (Entry.Original set, no
// payload: DigestRetryMachine) is a format a build that predates the digest table cannot read
// correctly. The protocol gate carries that fact, the way the erase gate carries its token:
//
//   - the sender names the capability in the message Context, in front of the erase gate's own
//     advertisement, so a receiver that only knows the erase gate finds the advertisement missing
//     and refuses the install (Step, before AdmitSnapshot);
//   - the envelope itself says so, in a field a reader that predates it does not know and so
//     refuses (StrictJSON), also on a receiver that runs no gate at all (the control machine);
//   - a receiver of this build refuses an envelope with digest-kept entries whose sender did not
//     name the capability, and reads an older, payload-bearing envelope unchanged.

// gatedDigestMachine is a machine with both the erase gate and a retry table kept by digest (the
// storage slot machine's shape).
type gatedDigestMachine struct{ *gatedMachine }

func (gatedDigestMachine) RetryByDigest(k Kind) bool { return k == Control }

func openGatedDigest(t *testing.T, token []byte) (*Group, *gatedMachine, *captureTransport) {
	t.Helper()
	id, dir := model.NewID(), t.TempDir()
	inner := newLedgerMachine(id, filepath.Join(dir, "machine"))
	if err := os.MkdirAll(inner.dir, 0700); err != nil {
		t.Fatal(err)
	}
	machine := &gatedMachine{ledgerMachine: inner, token: token}
	transport := &captureTransport{Loopback: NewLoopback()}
	group, err := Open(Config{ID: 1, Group: id, Directory: filepath.Join(dir, "raft"), Transport: transport, Members: soloMembers(), Machine: gatedDigestMachine{machine}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { group.Close(); transport.Loopback.Close() })
	return group, machine, transport
}

// retryEnvelope is the bytes of a snapshot envelope of this build whose retry table holds one
// Control command: kept by digest (payload nil, Original set) or carrying its payload (what a
// build that predates the digest table wrote).
func retryEnvelope(t *testing.T, group model.ID, byDigest bool) []byte {
	t.Helper()
	payload := []byte(`{"revision":"7"}`)
	e := Entry{ID: model.NewID(), Kind: Control, ApplicationIndex: 1}
	if byDigest {
		h := model.HashCanonical(payload)
		e.Original = &h
	} else {
		e.Payload = payload
	}
	raw, err := json.Marshal(snapshotEnvelope{Application: 1, State: []byte("{}"), Members: soloMembers(), Completed: []CommittedEntry{{Group: group, Term: 1, Index: 1, ApplicationCursor: model.Cursor{Group: group, Index: 1}, Entry: e}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func snapMessageWith(to uint64, context, data []byte) *pb.Message {
	m := snapMessage(to, context)
	m.Snapshot = &pb.Snapshot{Data: data}
	return m
}

// legacyReadEnvelope is snapshotEnvelope.UnmarshalJSON as the build that predates the digest
// table ran it: the five fields it knew, decoded strictly.
func legacyReadEnvelope(raw []byte) error {
	var wire struct {
		Application model.Uint64     `json:"application"`
		State       []byte           `json:"state"`
		Completed   []CommittedEntry `json:"completed"`
		Members     Members          `json:"members"`
		Retiring    []Member         `json:"retiring,omitempty"`
	}
	return model.StrictJSON(raw, &wire)
}

// A receiver that runs the gate refuses an envelope with digest-kept entries from a sender that
// did not name the capability (a sender that runs the erase gate only advertises that), whatever
// its token; it did not ask the machine to admit it. The same sender's payload-bearing envelope,
// the only form a build without the digest table writes, is admitted.
func TestGatedReceiverRefusesDigestKeptEnvelopeFromASenderWithoutTheCapability(t *testing.T) {
	group, machine, _ := openGatedDigest(t, nil)
	digest := retryEnvelope(t, group.group, true)
	for _, cx := range [][]byte{nil, gateContext(nil), gateContext([]byte{1, 2, 3, 4, 5, 6, 7, 8})} {
		err := group.Step(t.Context(), snapMessageWith(1, cx, digest))
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("digest-kept envelope under context %q: got %v, want %v", cx, err, ErrUnavailable)
		}
	}
	if admits, _ := machine.counts(); admits != 0 {
		t.Fatalf("the gate was asked to admit %d digest-kept snapshots from a sender without the capability", admits)
	}
	// The old format on the new build: stale for the group, so Step may answer with raft's own
	// verdict; what matters is that the gate was consulted and released.
	_ = group.Step(t.Context(), snapMessageWith(1, gateContext([]byte{9, 9, 9, 9, 9, 9, 9, 9}), retryEnvelope(t, group.group, false)))
	if admits, releases := machine.counts(); admits != 1 || releases != 1 {
		t.Fatalf("payload-bearing envelope from an older sender: %d admitted, %d released, want 1 and 1", admits, releases)
	}
}

// A receiver with no gate refuses the same envelope the same way: the control machine runs no
// gate, and a digest-kept table must still not be installed from a sender that never named it.
func TestReceiverWithoutAGateRefusesDigestKeptEnvelopeFromASenderWithoutTheCapability(t *testing.T) {
	s := openDigest(t, t.TempDir(), model.NewID())
	err := s.group.Step(t.Context(), snapMessageWith(1, nil, retryEnvelope(t, s.id, true)))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("digest-kept envelope without the capability: got %v, want %v", err, ErrUnavailable)
	}
	if err = s.group.Step(t.Context(), snapMessageWith(1, nil, retryEnvelope(t, s.id, false))); errors.Is(err, ErrUnavailable) {
		t.Fatalf("payload-bearing envelope from an older sender: refused (%v)", err)
	}
}

// What the sender's group puts on the wire. A snapshot with a digest-kept table leaves under a
// context the erase gate of a build that predates the capability does not recognise (its
// advertisement is not the context's prefix: it refuses before it admits), and the capable
// receiver reads token and capability back. A payload-bearing table leaves exactly as before.
func TestSenderNamesTheCapabilityOnlyForADigestKeptEnvelope(t *testing.T) {
	token := []byte{7, 7, 7, 7, 7, 7, 7, 7}
	for _, byDigest := range []bool{true, false} {
		sender, _, transport := openGatedDigest(t, token)
		data := retryEnvelope(t, sender.group, byDigest)
		sender.mu.Lock()
		sender.sendGatedSnapshot(&pb.Message{Type: pb.MsgSnap.Enum(), To: new(uint64(2)), From: new(uint64(1)), Snapshot: &pb.Snapshot{Data: data}})
		sender.mu.Unlock()
		sender.gateWG.Wait()
		transport.mu.Lock()
		var sent *pb.Message
		for _, m := range transport.sent {
			if m.GetType() == pb.MsgSnap {
				sent = m
			}
		}
		transport.mu.Unlock()
		if sent == nil {
			t.Fatalf("digest-kept=%v: nothing was sent", byDigest)
		}
		legacyAdmits := bytes.HasPrefix(sent.GetContext(), gateAdvert)
		if byDigest == legacyAdmits {
			t.Fatalf("digest-kept=%v: a receiver that knows only the erase gate would admit it = %v (context %q)", byDigest, legacyAdmits, sent.GetContext())
		}
		if !byDigest && !bytes.Equal(sent.GetContext(), gateContext(token)) {
			t.Fatalf("payload-bearing envelope left under context %q, want the unchanged %q", sent.GetContext(), gateContext(token))
		}
		// The capable pair: the message the sender produced is admitted, with the token, on a
		// receiver of this build.
		receiver, machine, _ := openGatedDigest(t, nil)
		sent.To = new(uint64(1))
		if err := receiver.Step(t.Context(), sent); errors.Is(err, ErrUnavailable) {
			t.Fatalf("digest-kept=%v: the capable receiver refused the capable sender: %v", byDigest, err)
		}
		if admits, releases := machine.counts(); admits != 1 || releases != 1 || !bytes.Equal(machine.admitted[0], token) {
			t.Fatalf("digest-kept=%v: capable pair: %d admitted, %d released, token %v", byDigest, admits, releases, machine.admitted)
		}
	}
}

// A reader that predates the digest table refuses what this build writes for a digest-kept
// table, at every place an envelope is cut (the Raft snapshot the leader sends, the snapshot
// store's envelope file), and reads what it writes for a table that holds payloads.
func TestOlderReaderRefusesADigestKeptEnvelopeAndReadsAPayloadBearingOne(t *testing.T) {
	s := openDigest(t, t.TempDir(), model.NewID())
	for i := range 3 {
		s.put(bigState(i))
	}
	if err := s.group.Snapshot(); err != nil {
		t.Fatal(err)
	}
	snap, err := s.group.memory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err = legacyReadEnvelope(snap.GetData()); err == nil {
		t.Fatal("a reader that predates the digest table accepted a digest-kept envelope (Group.Snapshot)")
	}
	stored := s.cut()
	raw, err := os.ReadFile(filepath.Join(stored.Dir(), fileEnvelope))
	if err != nil {
		t.Fatal(err)
	}
	if err = legacyReadEnvelope(raw); err == nil {
		t.Fatal("a reader that predates the digest table accepted a digest-kept envelope (CreateSnapshot)")
	}

	// A group whose machine keeps payloads writes the form every build reads.
	plain := openSolo(t, t.TempDir(), model.NewID(), nil)
	plain.propose(Data, "a")
	if err = plain.group.Snapshot(); err != nil {
		t.Fatal(err)
	}
	if snap, err = plain.group.memory.Snapshot(); err != nil {
		t.Fatal(err)
	}
	if err = legacyReadEnvelope(snap.GetData()); err != nil {
		t.Fatalf("a reader that predates the digest table cannot read a payload-bearing envelope: %v", err)
	}
}

// This build reads an older, payload-bearing envelope: the retry table is converted to digests, a
// retry of a command in it is still answered with its original receipt (wave 8 review R02).
func TestPayloadBearingEnvelopeIsInstalledAsDigestsOnTheNewBuild(t *testing.T) {
	id := model.NewID()
	leader := openDigest(t, t.TempDir(), id)
	rows := []wholeRow{leader.put(bigState(0)), leader.put(bigState(1))}
	state, err := leader.machine.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	envelope := snapshotEnvelope{Application: uint64(leader.group.Status().ApplicationCursor.Index), State: state, Members: soloMembers()}
	for _, r := range rows {
		c := r.acked
		c.Entry = r.entry
		envelope.Completed = append(envelope.Completed, c)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err = legacyReadEnvelope(raw); err != nil {
		t.Fatalf("fixture invalid: an older reader must read what an older sender wrote: %v", err)
	}
	follower := openDigest(t, t.TempDir(), id)
	index := leader.group.Status().Applied + 1
	meta := &pb.SnapshotMetadata{Index: new(index), Term: new(rows[1].acked.Term)}
	follower.group.mu.Lock()
	err = follower.group.restoreSnapshot(&pb.Snapshot{Data: raw, Metadata: meta})
	var held []CommittedEntry
	for _, r := range rows {
		held = append(held, follower.group.completed[r.entry.ID])
	}
	follower.group.mu.Unlock()
	if err != nil {
		t.Fatalf("a payload-bearing envelope was refused: %v", err)
	}
	for i, r := range rows {
		if held[i].Entry.Payload != nil || held[i].Entry.Original == nil || *held[i].Entry.Original != model.HashCanonical(r.entry.Payload) {
			t.Fatalf("row %d is not held by digest: %+v", i, held[i].Entry)
		}
		if held[i].Index != r.acked.Index || held[i].Term != r.acked.Term {
			t.Fatalf("row %d: receipt %d/%d changed to %d/%d", i, r.acked.Term, r.acked.Index, held[i].Term, held[i].Index)
		}
	}
}

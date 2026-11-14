// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/retention"
)

// noData is the storage half of a receipt: it owes nothing, so a receipt names exactly what the
// control store reports.
type noData struct{ retention.DataPlane }

func (noData) ResidualStores() []string { return nil }

// receiptOn is the residual list a deletion receipt answered by voter id carries: the
// retention plane the application hands the service, over that voter's control store.
func (v *controlVoters) receiptOn(id uint64) []string {
	v.t.Helper()
	return retention.NewResidualPlane(noData{}, v.stores[id]).ResidualStores()
}

// erasedWithVoter3Idle runs the three-voter erasure the tests below start from: the payload is
// on all three voters, the project is retired on the leader, voters 1 and 2 hold it no more once
// they ran their own scrub and pass; voter 3 has applied the erasure and has run nothing.
func (v *controlVoters) erasedWithVoter3Idle(canary string) {
	v.t.Helper()
	leader := v.fx[1]
	for range 40 { // the replaced state spans freed pages that later writes do not all reuse
		leader.seedAll(leader.newSeed(leader.project, canary), 50)
	}
	for _, id := range []uint64{2, 3} {
		v.await(id, v.mustRevision(1))
	}
	leader.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{leader.project}})
	for _, id := range []uint64{2, 3} {
		v.await(id, v.mustRevision(1))
	}
	leader.pass()
	v.fx[2].pass()
	if err := v.stores[2].ScrubErased(context.Background()); err != nil {
		v.t.Fatal(err)
	}
	for _, id := range []uint64{1, 2} {
		if got := v.stores[id].ResidualStores(); len(got) != 0 {
			v.t.Fatalf("fixture invalid: voter %d's own residue after its own pass and scrub: %v", id, got)
		}
	}
}

// attest runs voter id's worker step and waits until every voter has the commit.
func (v *controlVoters) attest(id uint64) {
	v.t.Helper()
	if err := v.stores[id].AttestControlResidue(context.Background()); err != nil {
		v.t.Fatalf("voter %d: %v", id, err)
	}
	v.converge()
}

// converge waits until every running voter reached the newest revision any of them has.
func (v *controlVoters) converge() {
	v.t.Helper()
	var top model.Revision
	for id, s := range v.stores {
		if s == nil || v.down[id] {
			continue
		}
		if r, ok := v.revision(id); ok && r > top {
			top = r
		}
	}
	for id := range v.stores {
		if !v.down[id] {
			v.await(id, top)
		}
	}
}

// finish is the retention worker's own sequence on voter id.
func (v *controlVoters) finish(id uint64) {
	v.t.Helper()
	if err := v.stores[id].ScrubErased(context.Background()); err != nil {
		v.t.Fatal(err)
	}
	v.fx[id].pass()
	v.attest(id)
}

// facts reads, on voter `on`, which facts the record of `node` states for the current erasures.
func (v *controlVoters) facts(on, node uint64) (journal, state bool) {
	v.t.Helper()
	err := v.stores[on].View(context.Background(), func(st control.State) error {
		raw, ok := st.OIDC[fmt.Sprintf("control_attest:%d", node)]
		if !ok {
			return nil
		}
		var rec struct {
			Journal *struct{ Erasures uint64 } `json:"journal"`
			State   *struct{ Erasures uint64 } `json:"state"`
		}
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		journal, state = rec.Journal != nil, rec.State != nil
		return nil
	})
	if err != nil {
		v.t.Fatal(err)
	}
	return
}

func (v *controlVoters) eventually(what string, cond func() bool) {
	v.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	v.t.Fatalf("timed out waiting for: %s", what)
}

func (v *controlVoters) noResidue(canary string, ids ...uint64) {
	v.t.Helper()
	for _, id := range ids {
		if hits := v.fx[id].raftHits(canary); len(hits) != 0 {
			v.t.Fatalf("voter %d's journal still holds the payload: %v", id, hits)
		}
		if hits := controlDBHits(v.t, v.dirs[id], canary); len(hits) != 0 {
			v.t.Fatalf("voter %d's control.db still holds the payload: %v", id, hits)
		}
	}
}

func (v *controlVoters) holdsPayload(canary string, id uint64) bool {
	v.t.Helper()
	return len(v.fx[id].raftHits(canary)) != 0 && len(controlDBHits(v.t, v.dirs[id], canary)) != 0
}

// IM-1. Every voter redacts and scrubs only its own files, so a receipt built from the
// answering voter alone stopped naming the control journal and control.db while another voter's
// ready.wal, snapshots and control.db free pages still held the erased payload. The receipt,
// whichever voter answers it, names each store until every node has attested it for itself.
func TestReceiptNamesControlResidueUntilEveryVoterAttests(t *testing.T) {
	v := newControlVoters(t)
	const gone = "CANARYATTESTIDLE0d2b86a7c41e"
	v.erasedWithVoter3Idle(gone)
	if !v.holdsPayload(gone, 3) {
		t.Fatalf("fixture invalid: voter 3 holds no copy in its journal %v and control.db %v", v.fx[3].raftHits(gone), controlDBHits(t, v.dirs[3], gone))
	}
	for _, id := range []uint64{1, 2} {
		got := v.receiptOn(id)
		if !contains(got, control.ResidualControlJournal) || !contains(got, control.ResidualControlState) {
			t.Fatalf("FALSE CLEAN: the receipt answered by voter %d is %v while voter 3's files still hold the erased payload", id, got)
		}
	}

	// Voters 1 and 2 attest: it is not every voter.
	v.attest(1)
	v.attest(2)
	for id := uint64(1); id <= 3; id++ {
		got := v.receiptOn(id)
		if id == 3 && len(got) == 0 {
			t.Fatalf("voter 3 answered clean while it holds the payload: %v", got)
		}
		if id != 3 && (!contains(got, control.ResidualControlJournal) || !contains(got, control.ResidualControlState)) {
			t.Fatalf("FALSE CLEAN: two attestations of three, the receipt answered by voter %d is %v", id, got)
		}
	}
	if j, s := v.facts(1, 1); !j || !s {
		t.Fatalf("voter 1 attested neither fact: journal=%v state=%v", j, s)
	}

	// Voter 3 asked to attest before its own pass: it has no proof, so it states nothing.
	v.attest(3)
	if j, s := v.facts(1, 3); j || s {
		t.Fatalf("FORGED: voter 3 attested journal=%v state=%v without having run its scrub or its pass", j, s)
	}
	if got := v.receiptOn(1); !contains(got, control.ResidualControlJournal) || !contains(got, control.ResidualControlState) {
		t.Fatalf("an attestation request without a proof cleaned the receipt: %v", got)
	}

	// The two facts are independent: the scrub alone clears control.db, not the journal.
	if err := v.stores[3].ScrubErased(context.Background()); err != nil {
		t.Fatal(err)
	}
	v.attest(3)
	if j, s := v.facts(1, 3); j || !s {
		t.Fatalf("after its scrub voter 3 states journal=%v state=%v, want state only", j, s)
	}
	if got := v.receiptOn(1); contains(got, control.ResidualControlState) || !contains(got, control.ResidualControlJournal) {
		t.Fatalf("after every voter scrubbed and one has not redacted its journal: %v", got)
	}

	v.finish(3)
	v.noResidue(gone, 1, 2, 3)
	for id := uint64(1); id <= 3; id++ {
		if got := v.receiptOn(id); len(got) != 0 {
			t.Fatalf("every voter attested and the receipt answered by voter %d still names %v", id, got)
		}
	}

	// A repeat commits nothing (bounded writes) and AttestControl never moved authority.
	before := v.mustRevision(1)
	for id := uint64(1); id <= 3; id++ {
		v.attest(id)
	}
	if after := v.mustRevision(1); after != before {
		t.Fatalf("a repeated attestation committed: revision %d -> %d", before, after)
	}
}

// An attestation is evidence, not authority: committing one must not move AuthorityRevision,
// or every voter's pass would starve a deletion Begin.
func TestAnAttestationDoesNotMoveAuthorityRevision(t *testing.T) {
	v := newControlVoters(t)
	v.erasedWithVoter3Idle("CANARYATTESTAUTH0d2b86a7c41e")
	var authority model.Revision
	read := func() (r, a model.Revision) {
		if err := v.stores[1].View(context.Background(), func(st control.State) error { r, a = st.Revision, st.AuthorityRevision; return nil }); err != nil {
			t.Fatal(err)
		}
		return
	}
	_, authority = read()
	rev, _ := read()
	v.attest(1)
	v.attest(2)
	v.finish(3)
	rev2, authority2 := read()
	if rev2 <= rev {
		t.Fatalf("fixture invalid: attestations committed nothing (%d -> %d)", rev, rev2)
	}
	// finish(3) runs voter 3's pass, whose empty revision is a classified non-authority writer.
	if authority2 != authority {
		t.Fatalf("attestations moved AuthorityRevision %d -> %d", authority, authority2)
	}
}

// A snapshot install replaces the voter's files and withdraws its redaction proof: its earlier
// attestation must not outlive that, so the receipt names the residue again, answered by ANOTHER
// voter, until the voter has scrubbed, redacted and attested once more.
func TestAnAttestationIsSupersededByASnapshotInstall(t *testing.T) {
	v := newControlVoters(t)
	const gone = "CANARYATTESTINSTALL0d2b86a7c41e"
	v.erasedWithVoter3Idle(gone)
	v.attest(1)
	v.attest(2)
	v.finish(3)
	if got := v.receiptOn(1); len(got) != 0 {
		t.Fatalf("fixture invalid: every voter attested and the receipt names %v", got)
	}
	v.mesh.cut(3, true)
	var lead uint64 // the fixture's passes move leadership: find the leader among the connected voters
	v.eventually("a leader among voters 1 and 2", func() bool {
		for _, id := range []uint64{1, 2} {
			if st := v.stores[id].ReplicaGroup().Status(); st.Leader == id && st.ID == id {
				lead = id
				return true
			}
		}
		return false
	})
	v.eventually("the leader serves writes", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := v.stores[lead].ReplicaGroup().Fence(ctx)
		return err == nil
	})
	for i := range 60 { // voter 3 never receives these commands; a commit retries while leadership settles
		v.eventually("a commit while voter 3 is cut off", func() bool {
			return v.stores[1].Update(context.Background(), func(st *control.State) error {
				if st.Quotas == nil {
					st.Quotas = map[string]model.QuotaState{}
				}
				st.Quotas[fmt.Sprintf("after:%d", i)] = model.QuotaState{MaxBytes: 1}
				return nil
			}) == nil
		})
	}
	v.fx[lead].cutControl() // the leader's journal no longer holds what voter 3 needs: it will be sent a snapshot
	v.mesh.cut(3, false)
	v.await(3, v.mustRevision(1))
	// The install withdrew voter 3's proof and owes its file a scrub: voter 1's receipt says so.
	v.eventually("voter 1's receipt names the residue of the voter that installed a snapshot", func() bool {
		got := v.receiptOn(1)
		return contains(got, control.ResidualControlJournal) && contains(got, control.ResidualControlState)
	})
	if j, s := v.facts(1, 3); j || s {
		t.Fatalf("voter 3's attestation outlived the install: journal=%v state=%v", j, s)
	}
	if got := v.receiptOn(3); !contains(got, control.ResidualControlJournal) || !contains(got, control.ResidualControlState) {
		t.Fatalf("voter 3's own receipt after the install: %v", got)
	}
	// Voters 1 and 2 keep their own attestations: the install says nothing about their files.
	for _, id := range []uint64{1, 2} {
		if j, s := v.facts(1, id); !j || !s {
			t.Fatalf("voter %d's attestation was withdrawn by voter 3's install: journal=%v state=%v", id, j, s)
		}
	}
	v.finish(3)
	v.converge()
	for id := uint64(1); id <= 3; id++ {
		if got := v.receiptOn(id); len(got) != 0 {
			t.Fatalf("voter 3 scrubbed, redacted and attested again: the receipt answered by voter %d names %v", id, got)
		}
	}
	v.noResidue(gone, 3)
}

// A process that restarted holds no redaction proof (it is memory), so it withdraws what it
// attested and states it again from its next pass.
func TestARestartedVoterWithdrawsItsAttestationUntilItsNextPass(t *testing.T) {
	v := newControlVoters(t)
	const gone = "CANARYATTESTRESTART0d2b86a7c41e"
	v.erasedWithVoter3Idle(gone)
	v.attest(1)
	v.attest(2)
	v.finish(3)
	if got := v.receiptOn(1); len(got) != 0 {
		t.Fatalf("fixture invalid: %v", got)
	}
	v.restart(3)
	v.eventually("voter 3's journal attestation is withdrawn by its restart", func() bool {
		j, _ := v.facts(1, 3)
		return !j
	})
	if got := v.receiptOn(1); !contains(got, control.ResidualControlJournal) {
		t.Fatalf("a restarted voter holds no proof and the receipt does not name the journal: %v", got)
	}
	if _, s := v.facts(1, 3); !s {
		t.Fatalf("a restart withdrew the scrub fact: the marker is a fact about the file and survives it")
	}
	v.fx[3].pass() // finds its files already clean and proves it
	v.attest(3)
	for id := uint64(1); id <= 3; id++ {
		if got := v.receiptOn(id); len(got) != 0 {
			t.Fatalf("after its next pass the receipt answered by voter %d names %v", id, got)
		}
	}
}

// restart closes voter id's store and group and opens them again over the same files.
func (v *controlVoters) restart(id uint64) {
	v.t.Helper()
	old := v.stores[id]
	position := old.ReplicaGroup().Status()
	if err := old.Close(); err != nil {
		v.t.Fatal(err)
	}
	store, err := control.Open(v.dirs[id])
	if err != nil {
		v.t.Fatal(err)
	}
	v.stores[id] = store
	seed, application, err := store.ReplicationSeed()
	if err != nil {
		v.t.Fatal(err)
	}
	for _, bind := range []func() error{store.BindRuleEvaluation, store.BindIncidentAction, store.BindConditionApply, store.BindDeliveryOutbox, store.BindRetention} {
		if err = bind(); err != nil {
			v.t.Fatal(err)
		}
	}
	group, err := store.EnableReplication(replica.Config{ID: id, Group: position.Group, Directory: filepath.Join(v.dirs[id], "raft-control"), TickInterval: voterTick(), Members: position.Members,
		Transport: voterTransport{mesh: v.mesh, node: id}, Seed: seed, Application: application})
	if err != nil {
		v.t.Fatal(err)
	}
	v.mesh.set(id, group)
	svc, err := auth.NewService(auth.AuthDependencies{Control: store, Now: func() time.Time { return v.fx[id].now }})
	if err != nil {
		v.t.Fatal(err)
	}
	v.fx[id].store, v.fx[id].svc = store, svc
	v.await(id, v.mustRevision(1))
}

// Nobody can write an attestation but the voter's own worker path.
func TestAnAttestationCannotBeForged(t *testing.T) {
	v := newControlVoters(t)
	v.erasedWithVoter3Idle("CANARYATTESTFORGE0d2b86a7c41e")
	leader := v.fx[1]
	var erasures int
	if err := v.stores[1].View(context.Background(), func(st control.State) error {
		for _, a := range st.Audits {
			if a.Action == "delete.control_erased" {
				erasures++
			}
		}
		return nil
	}); err != nil || erasures == 0 {
		t.Fatalf("fixture invalid: erasures=%d err=%v", erasures, err)
	}
	forged := json.RawMessage(fmt.Sprintf(`{"node":3,"identity":"voter-3","journal":{"erasures":%d,"applied":1},"state":{"erasures":%d,"applied":1}}`, erasures, erasures))
	expect := func(err error, code model.Code, what string) {
		t.Helper()
		var fault *model.Fault
		if !errors.As(err, &fault) || fault.Code != code {
			t.Fatalf("%s: %v, want %s", what, err, code)
		}
	}
	untouched := func(what string) {
		t.Helper()
		if j, s := v.facts(1, 3); j || s {
			t.Fatalf("%s: a forged attestation of voter 3 is in the state", what)
		}
		if got := v.receiptOn(1); !contains(got, control.ResidualControlJournal) || !contains(got, control.ResidualControlState) {
			t.Fatalf("%s: the receipt is %v", what, got)
		}
	}

	// A client scope has no command kind to write it with: the vocabulary is closed.
	for _, kind := range []string{"AttestControlResidue", "AttestControl", "Attest"} {
		_, err := v.stores[1].Transact(leader.ctx, leader.adminScope(), control.Command{CommandID: model.NewID(), ExpectedRevision: v.mustRevision(1), Kind: kind, Payload: forged})
		expect(err, model.Invalid, "kind "+kind)
	}
	untouched("closed vocabulary")

	// Even a handler registered for a real kind cannot write one on behalf of a client.
	if err := v.stores[1].RegisterHandler(control.KindRegisterRelease, func(_ auth.Scope, st *control.State, _ control.Command) (control.Effect, error) {
		if st.OIDC == nil {
			st.OIDC = map[string]json.RawMessage{}
		}
		st.OIDC["control_attest:3"] = forged
		return control.Effect{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err := v.stores[1].Transact(leader.ctx, leader.adminScope(), control.Command{CommandID: model.NewID(), ExpectedRevision: v.mustRevision(1), Kind: string(control.KindRegisterRelease), Payload: json.RawMessage(`{}`)})
	expect(err, model.Forbidden, "a Transact handler writing an attestation")
	untouched("Transact handler")

	// Nor the exported Update, from any package.
	err = v.stores[1].Update(leader.ctx, func(st *control.State) error {
		if st.OIDC == nil {
			st.OIDC = map[string]json.RawMessage{}
		}
		st.OIDC["control_attest:3"] = forged
		return nil
	})
	expect(err, model.Forbidden, "Update writing an attestation")
	untouched("Update")

	// It may delete one (a receipt only names more), and it may write unrelated records.
	if err = v.stores[1].Update(leader.ctx, func(st *control.State) error {
		if st.OIDC == nil {
			st.OIDC = map[string]json.RawMessage{}
		}
		st.OIDC["unrelated:key"] = json.RawMessage(`{}`)
		return nil
	}); err != nil {
		t.Fatalf("an unrelated OIDC record was refused: %v", err)
	}

	// A voter whose local proof does not hold: voter 3 has not scrubbed nor redacted. Its
	// request (the only way to write its record) states nothing, and nobody else can name it.
	v.attest(3)
	untouched("a voter without a local proof")
}

// A replacement voter (the group moves from {1,2,3} to {1,2,4}) is not covered by the others'
// attestations and must attest before the receipt is clean; the voter it replaced no longer
// counts, though its files still hold the payload.
func TestAJoinedVoterMustAttestAndARemovedOneNoLongerCounts(t *testing.T) {
	v := newControlVoters(t)
	const gone = "CANARYATTESTMEMBERS0d2b86a7c41e"
	v.erasedWithVoter3Idle(gone)
	v.attest(1)
	v.attest(2)
	if got := v.receiptOn(1); !contains(got, control.ResidualControlJournal) {
		t.Fatalf("fixture invalid: voter 3 has not attested and the receipt names %v", got)
	}

	// Voter 4 joins as a learner and receives the cluster by snapshot.
	leader := v.fx[1]
	genesis := v.genesis
	var err error
	position := v.stores[1].ReplicaGroup().Status()
	members := position.Members
	learner := replica.Members{Revision: members.Revision + 1, Nodes: append(append([]replica.Member(nil), members.Nodes...), replica.Member{ID: 4, Address: "https://voter4.invalid", NodeIdentity: "voter-4", FailureDomain: "disk-4", Learner: true})}
	dir := t.TempDir()
	v.dirs[4] = dir
	store, err := control.OpenSeed(dir, genesis.seed)
	if err != nil {
		t.Fatal(err)
	}
	v.stores[4] = store
	for _, bind := range []func() error{store.BindRuleEvaluation, store.BindIncidentAction, store.BindConditionApply, store.BindDeliveryOutbox, store.BindRetention} {
		if err = bind(); err != nil {
			t.Fatal(err)
		}
	}
	group, err := store.EnableReplication(replica.Config{ID: 4, Group: position.Group, Directory: filepath.Join(dir, "raft-control"), TickInterval: voterTick(), Members: learner,
		Transport: voterTransport{mesh: v.mesh, node: 4}, Seed: genesis.seed, Application: genesis.application, SeedIndex: genesis.index, SeedTerm: genesis.term})
	if err != nil {
		t.Fatal(err)
	}
	v.mesh.set(4, group)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err = v.changeMembers(ctx, members.Revision, learner, 0); err != nil {
		t.Fatal(err)
	}
	v.eventually("voter 4 caught up", func() bool { r, ok := v.revision(4); return ok && r >= v.mustRevision(1) })
	if got := v.receiptOn(1); !contains(got, control.ResidualControlJournal) || !contains(got, control.ResidualControlState) {
		t.Fatalf("a node that joined after the erasure is not covered by the others' attestations: %v", got)
	}

	// Voter 3 leaves; voter 4 becomes a voter. Voter 3 never attested and still holds the payload.
	next := replica.Members{Revision: learner.Revision + 1}
	for _, n := range learner.Nodes {
		switch n.ID {
		case 3:
			continue
		case 4:
			n.Learner = false
		}
		next.Nodes = append(next.Nodes, n)
	}
	if err = v.changeMembers(ctx, learner.Revision, next, 3); err != nil {
		t.Fatal(err)
	}
	if !v.holdsPayload(gone, 3) {
		t.Fatal("fixture invalid: the removed voter holds no copy of the payload")
	}
	v.eventually("voter 1 sees the new configuration", func() bool {
		return v.stores[1].ReplicaGroup().Status().Members.Revision == next.Revision
	})
	// The configuration moved but voter 4 has attested nothing: it is the one that is missing.
	if got := v.receiptOn(1); !contains(got, control.ResidualControlJournal) || !contains(got, control.ResidualControlState) {
		t.Fatalf("the replacement voter has not attested and the receipt is %v", got)
	}
	v.markDown(3)
	v.fx[4] = &eraseFx{&delFx{fenceFx: &fenceFx{t: t, dir: dir, ctx: leader.ctx, store: store, now: leader.now}, dest: leader.dest, policy: leader.policy, subject: leader.subject}}
	v.finish(4)
	v.eventually("voter 1's receipt is clean once the replacement attested", func() bool { return len(v.receiptOn(1)) == 0 })
	for _, id := range []uint64{1, 2, 4} {
		if got := v.receiptOn(id); len(got) != 0 {
			t.Fatalf("voter %d's receipt names %v although every current voter attested", id, got)
		}
	}
	v.noResidue(gone, 4)
}

// Without a replication group the local view is the whole cluster.
func TestAStoreWithoutAGroupAnswersForItself(t *testing.T) {
	store, err := control.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if got, want := store.ClusterResidualStores(), store.ResidualStores(); len(got) != len(want) {
		t.Fatalf("cluster %v, local %v", got, want)
	}
	if err = store.AttestControlResidue(context.Background()); err != nil {
		t.Fatalf("attesting without a group: %v", err)
	}
}

// markDown records that voter id is no longer part of the running group, so converge and
// attest stop waiting for it.
func (v *controlVoters) markDown(id uint64) {
	if v.down == nil {
		v.down = map[uint64]bool{}
	}
	v.down[id] = true
}

// CheckReadiness is what a leader asks before it promotes a learner: the learner's applied index.
func (t voterTransport) CheckReadiness(_ context.Context, _ model.ID, node uint64) (uint64, error) {
	t.mesh.mu.Lock()
	g := t.mesh.groups[node]
	t.mesh.mu.Unlock()
	if g == nil {
		return 0, replica.ErrUnavailable
	}
	return g.Status().Applied, nil
}

// Once every node attested, an idle group commits nothing for attestations: no withdrawal or
// attestation loop, and leadership does not move.
func TestSettledAttestationsCommitNothingOnAnIdleCluster(t *testing.T) {
	v := newControlVoters(t)
	lg := func(s string) {
		st := v.stores[1].ReplicaGroup().Status()
		t.Logf("DIAG %s: leader=%d term=%d rev=%d", s, st.Leader, st.Term, st.Revision)
	}
	lg("start")
	v.erasedWithVoter3Idle("CANARYATTESTIDLECOMMITS0d2b86a7c41e")
	lg("erased")
	v.attest(1)
	lg("a1")
	v.attest(2)
	lg("a2")
	v.finish(3)
	lg("f3")
	time.Sleep(2 * time.Second) // let any pending withdrawal settle
	v.converge()
	rev := v.mustRevision(1)
	status := v.stores[1].ReplicaGroup().Status()
	time.Sleep(10 * time.Second)
	after := v.stores[1].ReplicaGroup().Status()
	if got := v.mustRevision(1); got != rev {
		t.Fatalf("an idle settled cluster committed %d control revisions in 10 s", got-rev)
	}
	if after.Term != status.Term || after.Leader != status.Leader {
		t.Fatalf("leadership moved on an idle cluster: term %d->%d leader %d->%d", status.Term, after.Term, status.Leader, after.Leader)
	}
	for id := uint64(1); id <= 3; id++ {
		if got := v.receiptOn(id); len(got) != 0 {
			t.Fatalf("voter %d: %v", id, got)
		}
	}
	t.Logf("leader=%d term=%d revision=%d", after.Leader, after.Term, rev)
}

// changeMembers drives a membership change through whichever voter is the leader now (the
// passes of the fixture move leadership), retrying while leadership is moving. avoid names a
// voter that is leaving: leadership is moved off it first.
func (v *controlVoters) changeMembers(ctx context.Context, expected model.Revision, next replica.Members, avoid uint64) error {
	var last error
	for ctx.Err() == nil {
		var lead *replica.Group
		for id, s := range v.stores {
			if s == nil || v.down[id] || s.ReplicaGroup() == nil {
				continue
			}
			if st := s.ReplicaGroup().Status(); st.Leader == id && st.ID == id {
				lead = s.ReplicaGroup()
			}
		}
		if lead != nil {
			if st := lead.Status(); avoid != 0 && st.ID == avoid {
				last = lead.TransferLeadership(ctx, 1)
			} else if last = lead.ChangeMembers(ctx, expected, next); last == nil || !errors.Is(last, replica.ErrConflict) && !errors.Is(last, replica.ErrUnavailable) && !errors.Is(last, replica.ErrStale) {
				return last
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("membership change did not complete: %v", last)
}

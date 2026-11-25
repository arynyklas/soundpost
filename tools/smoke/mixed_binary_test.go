// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/config"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// TestMixedBinaryVoters runs a REAL three-voter cluster (three `soundpost serve --mode=distributed`
// processes, the harness of install-distributed) in which some voters are the previous release's binary
// and some are the candidate's, and drives tracked admin saves (team, membership, a policy write, a source
// policy change) through the HTTPS API on a candidate voter and on a previous-release voter. After every
// save it records every voter's /readyz answer, whether the process is alive, the applied cursor, the
// sha256 of the stored control state and its revision, the protocol declarations in the voter's apply
// database, the state patch commands in the voter's control journal, and the per-object records of the
// organization. Those records live in the organization's Settings (obj_epoch:<object>, obj_floor,
// obj_seen), a map the previous release decodes and every reader of which ignores keys it does not
// know (D59), so the candidate writes them from its first save and nothing is declared or finalized.
//
//	A  a mixed group (one candidate, two previous-release voters): saves through each; a candidate's save
//	   leaves the records current, a previous-release voter's bumps the epoch alone and leaves them behind;
//	C  the conflict rule on real binaries: the previous release applies the whole-organization compare, the
//	   candidate falls back to it while the records are behind the epoch and applies the per-object compare
//	   once its own save made them current, and no same-object stale save is ever accepted;
//	B  the previous-release voters are rolled to the candidate one at a time, saving between the rolls (a
//	   previous-release voter applies the records the candidate writes);
//	D  all three voters run the candidate;
//	E  one voter is rolled BACK to the previous release after the records exist: it restarts on a state, a
//	   journal and snapshots that carry them and applies the saves that follow;
//	F  a previous-release LEARNER joins through `membership add-learner` on an empty directory while the
//	   records exist, receives the state and holds exactly the voters' stored state;
//	G  the rolled-back voter is upgraded again, saves on every voter.
//
// The checks of a green run: no voter stops applying or leaves readyz; the stored states of every pair of
// voters agree (a state that could not be read, a failed seal or an empty digest is a failure, never an
// agreement); the state patch gate is unaffected (each tracked save adds at least one state patch command
// to every voter's control journal).
//
// The test is skipped unless the binaries are named, like TestUpgradeRollbackOfProducedBinaries. Run:
//
//	SOUNDPOST_MIXED_OLD_BINARY=/path/old SOUNDPOST_MIXED_NEW_BINARY=/path/new go test ./tools/smoke -run TestMixedBinaryVoters -count=1 -timeout 60m
//
// Environment:
//
//	SOUNDPOST_MIXED_OLD_BINARY  static soundpost binary of the previous release (ui embedded)
//	SOUNDPOST_MIXED_NEW_BINARY  static soundpost binary of the candidate
//	SOUNDPOST_MIXED_EVIDENCE    directory the trace, snapshots and node logs are written to (optional,
//	                            default a temporary directory; one subdirectory per candidate node)
//	SOUNDPOST_MIXED_NEW_NODE    member (1..3) that starts on the candidate binary; unset: the scenario runs
//	                            three times, with the candidate as voter 1, 2 and 3 (each then rolls
//	                            the other two to the candidate, which is the rolling upgrade)
//	SOUNDPOST_MIXED_EXPECT      "green" (default): every check must hold; "red": the run must observe an old
//	                            voter that stopped applying (not ready / exited) and the test then passes
//	                            (used with a candidate that writes the records as members the previous
//	                            release's strict decoder refuses, to prove the scenario detects that failure)
func TestMixedBinaryVoters(t *testing.T) {
	oldBin, newBin, evidence := os.Getenv("SOUNDPOST_MIXED_OLD_BINARY"), os.Getenv("SOUNDPOST_MIXED_NEW_BINARY"), os.Getenv("SOUNDPOST_MIXED_EVIDENCE")
	if oldBin == "" || newBin == "" {
		t.Skip("set SOUNDPOST_MIXED_OLD_BINARY and SOUNDPOST_MIXED_NEW_BINARY to static soundpost binaries of the previous release and the candidate")
	}
	if evidence == "" {
		evidence = t.TempDir()
	}
	expect := os.Getenv("SOUNDPOST_MIXED_EXPECT")
	if expect == "" {
		expect = "green"
	}
	if expect != "green" && expect != "red" {
		t.Fatalf("SOUNDPOST_MIXED_EXPECT=%q", expect)
	}
	nodes := []uint64{1, 2, 3}
	if v := os.Getenv("SOUNDPOST_MIXED_NEW_NODE"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil || n < 1 || n > 3 {
			t.Fatalf("SOUNDPOST_MIXED_NEW_NODE=%q", v)
		}
		nodes = []uint64{n}
	}
	for _, newNode := range nodes {
		t.Run(fmt.Sprintf("candidate_voter_%d", newNode), func(t *testing.T) {
			runMixedScenario(t, oldBin, newBin, filepath.Join(evidence, fmt.Sprintf("candidate-voter-%d", newNode)), newNode, expect)
		})
	}
}

func runMixedScenario(t *testing.T, oldBin, newBin, evidence string, newNode uint64, expect string) {
	if err := os.MkdirAll(evidence, 0o755); err != nil {
		t.Fatal(err)
	}
	trace, err := os.Create(filepath.Join(evidence, "trace.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer trace.Close()
	m := &mixedRun{t: t, trace: trace, evidence: evidence, oldBin: oldBin, newBin: newBin, release: map[uint64]string{}, expect: expect, patchMax: map[uint64]int{}}
	m.say("scenario expect=%s new_node=%d", expect, newNode)
	for _, b := range []struct{ label, path string }{{"old", oldBin}, {"new", newBin}} {
		sum, _ := fileSHA256(b.path)
		out, verr := exec.Command(b.path, "version", "--json").CombinedOutput()
		m.say("binary %s path=%s sha256=%s version=%s err=%v", b.label, b.path, sum, strings.TrimSpace(string(out)), verr)
	}
	runErr := m.run(newNode)
	m.writeLogs()
	if runErr != nil && m.violation == "" {
		m.violation = "harness_error: " + runErr.Error()
	}
	m.say("RESULT violation=%q harness_error=%v", m.violation, runErr)
	switch {
	case expect == "green" && m.violation != "":
		t.Fatalf("green scenario violated: %s", m.violation)
	case expect == "red" && !m.sawStop:
		t.Fatalf("red scenario did not observe an old voter that stopped applying (violation=%q err=%v)", m.violation, runErr)
	}
}

type mixedRun struct {
	t              *testing.T
	trace          *os.File
	evidence       string
	oldBin, newBin string
	expect         string
	c              *processCluster
	fx             *installFixture
	sites          map[uint64]*installSite
	release        map[uint64]string
	teamID         model.ID
	teamOn         bool
	maxSeries      uint64
	retentionDays  uint32
	stale          int
	step           int
	violation      string
	sawStop        bool
	patchMax       map[uint64]int
	// patchBase and savesBase are the per-voter state patch counts and the tracked saves made when the
	// phase being checked began (markPatches); saveCount counts the tracked saves that completed.
	patchBase map[uint64]int
	savesBase int
	saveCount int
	// lastFacts is what settle observed last, per voter (the three agree, so any one stands for the state).
	lastFacts map[uint64]memberFact
	// exp is the account and the writes of the ledger and replay writes (expandSetup); nil until the scenario makes them.
	exp *mixedExpand
}

// markPatches remembers the patch counts every voter's journal holds and the saves made so far.
func (m *mixedRun) markPatches() {
	m.patchBase = map[uint64]int{}
	for id, n := range m.patchMax {
		m.patchBase[id] = n
	}
	m.savesBase = m.saveCount
}

// requirePatchGrowth checks that every voter's control journal gained at least one state patch command per
// tracked save made since markPatches: every save commits at least one control command, and a group whose
// members all declare 5 or more proposes commands as patches. The bound is per voter and counts the saves,
// so one patch cannot satisfy it (the journal is cut at snapshots, which the cadence makes rare here).
func (m *mixedRun) requirePatchGrowth(label string) error {
	need := m.saveCount - m.savesBase
	for _, id := range []uint64{1, 2, 3} {
		m.observe(id)
	}
	seen := make([]string, 0, 3)
	for _, id := range []uint64{1, 2, 3} {
		seen = append(seen, fmt.Sprintf("voter %d +%d", id, m.patchMax[id]-m.patchBase[id]))
	}
	m.say("state patch commands since the mark (%s), %d tracked saves: %s", label, need, strings.Join(seen, ", "))
	if need == 0 {
		return m.violate("no_saves_to_count", label+": no tracked save was made since the mark")
	}
	if short := patchShortfall(m.patchMax, m.patchBase, need); len(short) > 0 {
		return m.violate("no_state_patches", label+": "+strings.Join(short, "; ")+": the patch gate closed or the commands were whole-state replacements")
	}
	return nil
}

// patchShortfall names every voter of 1..3 whose journal gained fewer state patch commands than need (the
// tracked saves made) between the base counts and the largest counts seen.
func patchShortfall(max, base map[uint64]int, need int) (short []string) {
	for _, id := range []uint64{1, 2, 3} {
		if got := max[id] - base[id]; got < need {
			short = append(short, fmt.Sprintf("voter %d gained %d state patch commands for %d tracked saves", id, got, need))
		}
	}
	return short
}

func (m *mixedRun) say(format string, a ...any) {
	line := time.Now().UTC().Format("15:04:05.000") + " " + fmt.Sprintf(format, a...)
	fmt.Fprintln(m.trace, line)
	m.t.Log(line)
}

// violate records the first violated expectation and returns it as the error that ends the scenario.
func (m *mixedRun) violate(code, detail string) error {
	text := code + ": " + detail
	if m.violation == "" {
		m.violation = text
	}
	m.say("VIOLATION %s", text)
	return errors.New(text)
}

func (m *mixedRun) others(id uint64) []uint64 {
	var out []uint64
	for _, n := range []uint64{1, 2, 3} {
		if n != id {
			out = append(out, n)
		}
	}
	return out
}

// startGroup bootstraps one installation with the previous release's binary, exports its cluster seed, starts the
// three voters on the release releaseOf names for each ("old" or "new"), and waits until they serve, agree on a
// leader, declared their protocols and hold one state. The returned cleanup kills the processes and removes the
// work directory; it is valid whatever the error.
func (m *mixedRun) startGroup(releaseOf func(uint64) string) (func(), error) {
	work, err := os.MkdirTemp("", "soundpost-mixed-")
	if err != nil {
		return func() {}, err
	}
	cleanup := func() {
		if m.c != nil {
			m.c.cleanup()
		}
		os.RemoveAll(work)
	}
	report := map[string]any{}
	cluster, err := newProcessCluster(m.oldBin, "", work, report)
	if err != nil {
		return cleanup, err
	}
	m.c = cluster.(*processCluster)
	cfg := m.c.installConfig()
	if err = config.Validate(cfg); err != nil {
		return cleanup, err
	}
	files, err := config.NodeConfigs(cfg)
	if err != nil {
		return cleanup, err
	}
	m.say("bootstrap one installation with the OLD binary, export its cluster seed")
	fx, seed, err := m.c.bootstrap(report)
	if err != nil {
		return cleanup, err
	}
	m.fx = fx
	if err = m.c.provision(files, seed); err != nil {
		return cleanup, err
	}
	for _, id := range []uint64{1, 2, 3} {
		if releaseOf(id) == "new" {
			m.c.setBinary(id, m.newBin)
			m.release[id] = "new"
		} else {
			m.c.setBinary(id, m.oldBin)
			m.release[id] = "old"
		}
	}
	m.say("start three voters: %s", m.releases())
	if err = m.c.start(1, 2, 3); err != nil {
		return cleanup, err
	}
	m.sites = map[uint64]*installSite{}
	for _, id := range []uint64{1, 2, 3} {
		if m.sites[id], err = m.c.site(id); err != nil {
			return cleanup, err
		}
	}
	for _, id := range []uint64{1, 2, 3} {
		if err = waitNodeReady(m.sites[id], 180*time.Second); err != nil {
			return cleanup, m.violate("start_not_ready", fmt.Sprintf("voter %d: %v", id, err))
		}
	}
	lead, err := leadership(m.sites, []uint64{1, 2, 3}, 60*time.Second)
	if err != nil {
		return cleanup, err
	}
	m.say("leadership leader=%d term=%d", lead.leader, lead.term)
	if err = m.waitDeclarations(); err != nil {
		return cleanup, err
	}
	m.teamID = model.NewID()
	m.maxSeries = 1000
	m.retentionDays = 20
	if err = m.settle("S00 mixed group started, before any save"); err != nil {
		return cleanup, err
	}
	m.markPatches()
	return cleanup, nil
}

func (m *mixedRun) run(newNode uint64) error {
	cleanup, err := m.startGroup(func(id uint64) string {
		if id == newNode {
			return "new"
		}
		return "old"
	})
	defer cleanup()
	if err != nil {
		return err
	}

	// ---- phase A: two previous-release voters and one candidate voter ----
	oldNode := m.others(newNode)[0]
	for _, who := range []struct {
		label string
		id    uint64
	}{{"candidate voter", newNode}, {"previous-release voter", oldNode}} {
		if err = m.saves(who.id, "A "+who.label); err != nil {
			return err
		}
		// The team save is the last of the four: a candidate's leaves the records current (obj_seen = epoch), a
		// previous-release voter's bumps the epoch alone and leaves them behind, which every candidate then reads as
		// "every object changed at the current epoch" (the coarse rule).
		if err = m.requireOrg("A after the "+who.label+"'s saves", who.id == newNode, true); err != nil {
			return err
		}
	}

	// The group is mixed and every member declared 5 or more: the saves above were proposed as state
	// patches, at least one per save on every voter.
	for _, id := range []uint64{1, 2, 3} {
		if raw, err := os.ReadFile(filepath.Join(m.c.data[id], "raft", "control", "ready.wal")); err == nil {
			_ = os.WriteFile(filepath.Join(m.evidence, fmt.Sprintf("control-ready-%d.wal", id)), raw, 0o644)
		}
	}
	for _, id := range []uint64{1, 2, 3} {
		f := m.observe(id)
		m.say("control journal of voter %d [%s]: %d state patches, %s", id, f.Release, f.Patches, f.Journal)
	}
	if err = m.requirePatchGrowth("phase A, a mixed group"); err != nil {
		return err
	}
	// Conflicts in a mixed group: the previous-release voter's saves never lose a same-object conflict and the
	// candidate falls back to the coarse rule behind them, while the candidate's own saves conflict per object.
	if err = m.conflictChecks(newNode, oldNode); err != nil {
		return err
	}

	// ---- phase B/C: roll the previous-release voters one at a time, saving between the rolls ----
	for _, id := range m.others(newNode) {
		if err = m.rollTo(id, "new"); err != nil {
			return err
		}
		if id == m.others(newNode)[0] {
			// One previous-release voter is still a member, and the records are in the state it applies.
			if err = m.saves(newNode, fmt.Sprintf("B after rolling voter %d (one previous-release voter left)", id)); err != nil {
				return err
			}
			if err = m.saves(m.others(newNode)[1], fmt.Sprintf("B' (via the still previous-release voter) after rolling voter %d", id)); err != nil {
				return err
			}
		}
	}

	// ---- phase D: all three voters run the candidate binary ----
	m.say("all three voters run the candidate binary: %s", m.releases())
	m.markPatches()
	for _, id := range []uint64{1, 2, 3} {
		if err = m.saves(id, fmt.Sprintf("D all candidate, save on voter %d", id)); err != nil {
			return err
		}
		if err = m.requireOrg(fmt.Sprintf("D after voter %d's saves", id), true, true); err != nil {
			return err
		}
	}
	if err = m.soak("D soak, all candidate", 10*time.Second); err != nil {
		return err
	}
	if err = m.requirePatchGrowth("phase D, all candidate"); err != nil {
		return err
	}
	// Ledgers and replays written by the all-candidate group (D70): the stored state then holds the sharded
	// index and per-replay pins together with the previous release's per-project values.
	if err = m.expandD(newNode); err != nil {
		return err
	}

	// ---- phase E: the records exist; one voter is rolled BACK to the previous release ----
	// It restarts on a state, a journal and snapshots that carry the records, and applies what the candidates
	// write next.
	back := m.others(newNode)[1]
	if err = m.rollTo(back, "old"); err != nil {
		return err
	}
	if err = m.requireOrg(fmt.Sprintf("E voter %d rolled back to the previous release", back), true, true); err != nil {
		return err
	}
	if err = m.expandE(back, newNode); err != nil {
		return err
	}
	m.markPatches()
	for _, via := range []uint64{back, newNode} {
		if err = m.saves(via, fmt.Sprintf("E voter %d rolled back, save on voter %d", back, via)); err != nil {
			return err
		}
		if err = m.requireOrg(fmt.Sprintf("E after voter %d's saves", via), via == newNode, true); err != nil {
			return err
		}
	}
	if err = m.soak("E soak, one voter rolled back", 10*time.Second); err != nil {
		return err
	}
	if err = m.requirePatchGrowth(fmt.Sprintf("phase E, voter %d rolled back", back)); err != nil {
		return err
	}

	// ---- phase F: the previous release receives a SNAPSHOT of the state with the records ----
	// F1 a lagging previous-release voter (stopped while the candidates commit past the journal cadence) and F2 a
	// previous-release learner on an empty directory both get their state from a leader whose journal was compacted.
	if err = m.lagThenSnapshot(back, newNode); err != nil {
		return err
	}
	if err = m.oldLearner(newNode); err != nil {
		return err
	}

	// ---- phase G: roll it forward again, final saves on every voter ----
	if err = m.rollTo(back, "new"); err != nil {
		return err
	}
	for _, id := range []uint64{1, 2, 3} {
		if err = m.saves(id, fmt.Sprintf("G save on voter %d", id)); err != nil {
			return err
		}
	}
	if err = m.expandG(); err != nil {
		return err
	}
	return m.settle("H final")
}

// teamPayload is the next version of the mixed-binary team.
func (m *mixedRun) teamPayload() auth.AdminPayload {
	m.teamOn = !m.teamOn
	cfg, _ := json.Marshal(model.ControlTeam{Members: []model.ID{m.fx.reader.User}, Projects: []model.ID{m.fx.project}, Permissions: []string{"telemetry.read"}, Enabled: m.teamOn})
	return auth.AdminPayload{ID: m.teamID, Name: "mixed team", Config: cfg}
}

// adminOnce is one admin command on the stated organization epoch, answered as it is (no retry): the status and
// the start of the body.
func (m *mixedRun) adminOnce(id uint64, s auth.Session, kind string, p auth.AdminPayload, epoch uint64) (int, string, error) {
	p.Reason = "mixed-binary smoke"
	payload, _ := json.Marshal(p)
	e := model.Uint64(epoch)
	status, raw, err := postRetryStale(m.sites[id], "/api/v1/admin/commands", auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedEpoch: &e, OrgID: m.fx.org, Kind: kind, Payload: payload}, s.CSRF, "", &m.stale)
	return status, trunc(string(raw), 200), err
}

func (m *mixedRun) epochOf(id uint64, s auth.Session) (uint64, error) {
	view, err := m.adminRead(id, s, "organization")
	return uint64(view.Epoch), err
}

// expectStatus runs one save on a stated epoch and requires the status.
func (m *mixedRun) expectStatus(what string, id uint64, s auth.Session, kind string, p auth.AdminPayload, epoch uint64, want int) error {
	status, body, err := m.adminOnce(id, s, kind, p, epoch)
	m.say("  %s: %s on voter %d (%s) at epoch %d answered %d %s", what, kind, id, m.release[id], epoch, status, body)
	if err != nil {
		return err
	}
	if status != want {
		return m.violate("conflict_rule", fmt.Sprintf("%s: %s on voter %d at epoch %d answered %d, want %d (%s)", what, kind, id, epoch, status, want, body))
	}
	return nil
}

// conflictChecks is the conflict rule of a mixed group, on real binaries. The previous release compares the
// whole organization epoch and bumps it without touching the records; the candidate compares the object's own
// record, and the whole epoch while the records are behind it.
func (m *mixedRun) conflictChecks(newNode, oldNode uint64) error {
	sNew, err := m.login(newNode)
	if err != nil {
		return err
	}
	sOld, err := m.login(oldNode)
	if err != nil {
		return err
	}
	user := auth.AdminPayload{UserID: m.fx.reader.User, Enabled: true}
	// The candidate tracks the team first (the previous-release voter's save of phase A was the last one).
	if err = m.adminSave(newNode, sNew, "team", m.teamPayload()); err != nil {
		return err
	}
	if err = m.settle("C0 the candidate tracked the team, before the conflict checks"); err != nil {
		return err
	}
	before := m.org()
	teamKey := "team:" + m.teamID.String()
	teamAt, tracked := before.Objects[teamKey]
	if !tracked || !before.Tracked {
		return m.violate("object_not_tracked", fmt.Sprintf("the candidate did not track %s before the previous release's save (record %d present %t, tracked %t)", teamKey, teamAt, tracked, before.Tracked))
	}
	read, err := m.epochOf(newNode, sNew)
	if err != nil {
		return err
	}
	if oldTracksRecords() {
		// The previous release tracks the records too: its save leaves them current, and a same-object save based on
		// the earlier read loses on either release.
		if err = m.adminSave(oldNode, sOld, "team", m.teamPayload()); err != nil {
			return err
		}
		if err = m.settle("C1 after the previous-release voter's team save (it tracks)"); err != nil {
			return err
		}
		if err = m.requireOrg("C1", true, true); err != nil {
			return err
		}
		if err = m.expectStatus("same object, stale", newNode, sNew, "team", m.teamPayload(), read, 409); err != nil {
			return err
		}
		readOld, err := m.epochOf(oldNode, sOld)
		if err != nil {
			return err
		}
		if err = m.adminSave(newNode, sNew, "team", m.teamPayload()); err != nil {
			return err
		}
		if err = m.settle("C4 after the candidate's team save"); err != nil {
			return err
		}
		if err = m.expectStatus("previous release, same object, stale", oldNode, sOld, "team", m.teamPayload(), readOld, 409); err != nil {
			return err
		}
		return m.settle("C5 after the conflict checks")
	}
	// The previous-release voter changes the team (epoch bumped, records left behind).
	if err = m.adminSave(oldNode, sOld, "team", m.teamPayload()); err != nil {
		return err
	}
	if err = m.settle("C1 after the previous-release voter's team save"); err != nil {
		return err
	}
	if err = m.requireOrg("C1", false, true); err != nil {
		return err
	}
	// The trigger of the refusals below is the coarse fallback, not a record: the previous release bumped the epoch
	// and left every obj_* entry as the candidate wrote it, so obj_seen is behind the epoch and the object's own
	// record still holds its earlier epoch.
	after := m.org()
	if got, ok := after.Objects[teamKey]; !ok || got != teamAt {
		return m.violate("records_touched", fmt.Sprintf("the previous release's save changed the record of %s: %d -> %d (present %t)", teamKey, teamAt, got, ok))
	}
	if after.Seen == after.Epoch || after.Epoch != before.Epoch+1 {
		return m.violate("records_current", fmt.Sprintf("after the previous release's save obj_seen=%d epoch=%d (before: epoch %d): the coarse fallback is not what is in effect", after.Seen, after.Epoch, before.Epoch))
	}
	m.say("  previous-release save: epoch %d -> %d, obj_seen %d stays behind, %s stays at %d", before.Epoch, after.Epoch, after.Seen, teamKey, teamAt)
	// A save of the same object based on the earlier read loses on the candidate: the lost update is refused.
	if err = m.expectStatus("same object, stale", newNode, sNew, "team", m.teamPayload(), read, 409); err != nil {
		return err
	}
	// And so does a save of ANOTHER object: the records are behind the epoch, so every object counts as changed
	// (the whole-organization rule the previous release applies).
	if err = m.expectStatus("other object, behind an untracked change", newNode, sNew, "membership", user, read, 409); err != nil {
		return err
	}
	// A page read AFTER the previous-release voter's save is current, and its save of the same object commits (the
	// coarse rule compares the epoch the page read with the epoch now).
	readAfter, err := m.epochOf(newNode, sNew)
	if err != nil {
		return err
	}
	if err = m.expectStatus("same object, read after the previous-release voter's save", newNode, sNew, "team", m.teamPayload(), readAfter, 200); err != nil {
		return err
	}
	if err = m.settle("C2 after the candidate's team save"); err != nil {
		return err
	}
	if err = m.requireOrg("C2", true, true); err != nil {
		return err
	}
	// Now an unrelated change by the candidate does not refuse a save of another object (the per-object rule) ...
	read, err = m.epochOf(newNode, sNew)
	if err != nil {
		return err
	}
	if err = m.adminSave(newNode, sNew, "team", m.teamPayload()); err != nil {
		return err
	}
	if err = m.expectStatus("other object, after a tracked change", newNode, sNew, "membership", user, read, 200); err != nil {
		return err
	}
	// ... but a stale save of the object that changed is still refused.
	if err = m.expectStatus("same object, stale after a tracked change", newNode, sNew, "team", m.teamPayload(), read, 409); err != nil {
		return err
	}
	// The previous release applies the whole-organization rule to every save, with records or without.
	if err = m.settle("C3 before the previous-release checks"); err != nil {
		return err
	}
	read, err = m.epochOf(oldNode, sOld)
	if err != nil {
		return err
	}
	if err = m.adminSave(newNode, sNew, "team", m.teamPayload()); err != nil {
		return err
	}
	if err = m.settle("C4 after the candidate's team save"); err != nil {
		return err
	}
	if err = m.expectStatus("previous release, same object, stale", oldNode, sOld, "team", m.teamPayload(), read, 409); err != nil {
		return err
	}
	if err = m.expectStatus("previous release, other object, stale", oldNode, sOld, "membership", user, read, 409); err != nil {
		return err
	}
	return m.settle("C5 after the conflict checks")
}

// bigTeamPayload is a team whose configuration is near the 16 KiB limit (one permission repeated): each save of it
// puts about 30 KB into the control journal, so the 8 MiB journal cadence is reached in a few hundred saves.
func (m *mixedRun) bigTeamPayload() auth.AdminPayload {
	p := m.teamPayload()
	var team model.ControlTeam
	_ = json.Unmarshal(p.Config, &team)
	team.Permissions = slices.Repeat([]string{"telemetry.read"}, 900)
	p.Config, _ = json.Marshal(team)
	return p
}

// controlWAL is the size of the control group's journal of voter id (0: none).
func (m *mixedRun) controlWAL(id uint64) int64 {
	var size int64
	_ = filepath.Walk(filepath.Join(m.c.data[id], "raft", "control"), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && info.Name() == "ready.wal" {
			size = info.Size()
		}
		return nil
	})
	return size
}

// lagThenSnapshot stops the previous-release voter back, commits big saves through the two candidates until each has
// compacted its control journal onto a snapshot (the journal shrinks), then starts back again on the PREVIOUS release's
// binary: the leader's journal no longer holds what it missed, so it receives a snapshot of the state that carries the
// records, installs it and must serve with exactly the other voters' state.
func (m *mixedRun) lagThenSnapshot(back, newNode uint64) error {
	live := []uint64{1, 2, 3}
	live = slices.DeleteFunc(live, func(id uint64) bool { return id == back })
	m.say("F1 stop voter %d (%s), commit past the journal cadence through voters %v", back, m.release[back], live)
	if err := m.c.terminate(back); err != nil {
		return err
	}
	sessions := map[uint64]auth.Session{}
	for _, id := range live {
		s, err := m.login(id)
		if err != nil {
			return err
		}
		sessions[id] = s
	}
	var err error
	peak, compacted := map[uint64]int64{}, map[uint64]bool{}
	for i := range 1500 {
		via := live[i%2]
		if err = m.adminSave(via, sessions[via], "team", m.bigTeamPayload()); err != nil {
			return m.violate("save_failed", fmt.Sprintf("big team save %d through voter %d: %v", i, via, err))
		}
		m.saveCount++
		if i%10 != 0 {
			continue
		}
		done := true
		for _, id := range live {
			size := m.controlWAL(id)
			if size > peak[id] {
				peak[id] = size
			}
			if peak[id] > 1<<20 && size < peak[id]/2 {
				compacted[id] = true
			}
			done = done && compacted[id]
		}
		if done {
			m.say("  after %d big saves every live voter compacted its control journal (peaks %v, now %d / %d bytes)", i+1, peak, m.controlWAL(live[0]), m.controlWAL(live[1]))
			break
		}
	}
	for _, id := range live {
		if !compacted[id] {
			return m.violate("no_journal_cut", fmt.Sprintf("voter %d never compacted its control journal within 1500 big saves (peak %d bytes, now %d)", id, peak[id], m.controlWAL(id)))
		}
	}
	m.say("  control directory of voter %d before it returns: %s", back, dirListing(filepath.Join(m.c.data[back], "raft", "control")))
	m.say("  control directory of voter %d (a live voter): %s", live[0], dirListing(filepath.Join(m.c.data[live[0]], "raft", "control")))
	m.c.setBinary(back, m.oldBin)
	m.release[back] = "old"
	m.say("F1 start voter %d on the previous release", back)
	if err = m.c.start(back); err != nil {
		return err
	}
	if m.sites[back], err = m.c.site(back); err != nil {
		return err
	}
	if err = waitNodeReady(m.sites[back], 240*time.Second); err != nil {
		m.sawStop = true
		return m.violate("lagging_voter_not_ready", fmt.Sprintf("voter %d after the snapshot: %v (log %q)", back, err, lastLines(m.c.logs[back].String(), 6)))
	}
	if err = m.settle("F1 the lagging previous-release voter caught up"); err != nil {
		return err
	}
	m.say("  control directory of voter %d after it caught up: %s", back, dirListing(filepath.Join(m.c.data[back], "raft", "control")))
	m.say("  voter %d log, snapshot lines: %q", back, grepLines(m.c.logs[back].String(), "snapshot"))
	return m.requireOrg("F1", true, true)
}

// prepareLearner makes the identity, directory and node file of a fresh learner (dcFreshNode) that is
// not a member yet and starts nothing: the membership is the other voters' node file plus the learner
// as a learner. It returns the learner as `membership add-learner` is asked to add it.
func (m *mixedRun) prepareLearner() (replica.Member, error) {
	id := dcFreshNode.id
	c := m.c
	pub, e1 := freeAddress()
	peer, e2 := freeAddress()
	if e1 != nil || e2 != nil {
		return replica.Member{}, errors.Join(e1, e2)
	}
	c.public[id], c.peer[id] = pub, peer
	c.data[id] = filepath.Join(c.root, "node-"+dcFreshNode.name)
	c.logs[id] = &syncBuffer{}
	certPEM, keyPEM, err := c.pki.ca.issue(dcFreshNode, c.pki.nextSerial())
	if err != nil {
		return replica.Member{}, err
	}
	cert, key := filepath.Join(c.pki.dir, dcFreshNode.name+".pem"), filepath.Join(c.pki.dir, dcFreshNode.name+".key")
	if err = errors.Join(os.WriteFile(cert, certPEM, 0o600), os.WriteFile(key, keyPEM, 0o600)); err != nil {
		return replica.Member{}, err
	}
	raw, err := os.ReadFile(filepath.Join(c.root, "node-1.json"))
	if err != nil {
		return replica.Member{}, err
	}
	var node appcore.NodeConfig
	if err = model.StrictJSON(raw, &node); err != nil {
		return replica.Member{}, err
	}
	learner := replica.Member{ID: id, Address: "https://" + peer, NodeIdentity: dcFreshNode.identity, FailureDomain: "process-directory-" + dcFreshNode.name, Learner: true}
	node.NodeID, node.PeerListen, node.PeerSourceIP = id, peer, ""
	node.Certificate, node.PrivateKey = cert, key
	node.Members = replica.Members{Revision: node.Members.Revision + 1, Nodes: append(slices.Clone(node.Members.Nodes), learner)}
	encoded, err := json.MarshalIndent(node, "", "  ")
	if err != nil {
		return replica.Member{}, err
	}
	if err = os.WriteFile(filepath.Join(c.root, fmt.Sprintf("node-%d.json", id)), append(encoded, '\n'), 0o600); err != nil {
		return replica.Member{}, err
	}
	return learner, nil
}

// oldLearner adds a learner that runs the PREVIOUS release's binary on an empty directory, through the
// product's membership path, while the state carries the records: it receives the state (a snapshot or the
// log, as the leader decides) and must serve and hold exactly the voters' state.
func (m *mixedRun) oldLearner(through uint64) error {
	learner, err := m.prepareLearner()
	if err != nil {
		return err
	}
	id := dcFreshNode.id
	c := m.c
	m.say("add learner node %d (%s): `membership add-learner` against each voter in turn (every group is led by one of them)", id, dcFreshNode.identity)
	var out []byte
	deadline := time.Now().Add(180 * time.Second)
	voters := []uint64{through}
	for _, v := range []uint64{1, 2, 3} {
		if v != through {
			voters = append(voters, v)
		}
	}
	for round := 0; ; round++ {
		via := voters[round%len(voters)]
		cmd := exec.Command(c.binaryOf(via), "membership", "add-learner", "--data-dir", c.data[via], "--id", strconv.FormatUint(id, 10), "--address", learner.Address, "--identity", learner.NodeIdentity, "--failure-domain", learner.FailureDomain)
		out, err = cmd.CombinedOutput()
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		m.say("  membership add-learner through voter %d: %s (err=%v)", via, lines[len(lines)-1], err)
		if err == nil && strings.Contains(string(out), "not_leader=0 ") {
			break
		}
		if time.Now().After(deadline) {
			return m.violate("learner_not_added", fmt.Sprintf("add-learner: %s (%v)", lines[len(lines)-1], err))
		}
		time.Sleep(time.Second)
	}
	c.setBinary(id, m.oldBin)
	m.release[id] = "old"
	if err = c.start(id); err != nil {
		return err
	}
	if m.sites[id], err = c.site(id); err != nil {
		return err
	}
	if err = waitNodeReady(m.sites[id], 240*time.Second); err != nil {
		m.sawStop = true
		return m.violate("learner_not_ready", fmt.Sprintf("the previous-release learner: %v (log %q)", err, lastLines(c.logs[id].String(), 6)))
	}
	if err = m.settle("F1 the learner is ready"); err != nil {
		return err
	}
	want := m.lastFacts[1].Digest
	var f memberFact
	deadline = time.Now().Add(120 * time.Second)
	for {
		f = m.observe(id)
		if f.Alive && f.Ready && f.StateErr == "" && f.SealOK && f.Digest == want {
			break
		}
		if time.Now().After(deadline) {
			return m.violate("learner_state_differs", fmt.Sprintf("the previous-release learner's state digest %q (state error %q, ready=%t, seal_ok=%t), the voters' %q; log %q", f.Digest, f.StateErr, f.Ready, f.SealOK, want, lastLines(c.logs[id].String(), 6)))
		}
		time.Sleep(time.Second)
	}
	o := f.Orgs[m.fx.org.String()]
	m.say("  the previous-release learner holds the voters' state digest %s (%d object records, obj_seen=%d, epoch=%d)", f.Digest, o.Records, o.Seen, o.Epoch)
	if o.Records == 0 {
		return m.violate("learner_without_records", "the learner's organization holds no object record")
	}
	m.say("  learner control directory: %s", dirListing(filepath.Join(c.data[id], "raft", "control")))
	m.say("  learner log, snapshot lines: %q", grepLines(c.logs[id].String(), "snapshot"))
	return nil
}

// dirListing lists the files below dir with their sizes.
func dirListing(dir string) string {
	var parts []string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			parts = append(parts, fmt.Sprintf("%s=%dB", filepath.ToSlash(rel), info.Size()))
		}
		return nil
	})
	return strings.Join(parts, " ")
}

// grepLines is the lines of s that contain word.
func grepLines(s, word string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, word) {
			out = append(out, trunc(l, 200))
		}
	}
	return strings.Join(out, " ⏎ ")
}

func (m *mixedRun) releases() string {
	return fmt.Sprintf("voter1=%s voter2=%s voter3=%s", m.release[1], m.release[2], m.release[3])
}

// soak keeps saving through the three voters in turn for d, settling after every save.
func (m *mixedRun) soak(label string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for i := 0; time.Now().Before(deadline); i++ {
		id := []uint64{1, 2, 3}[i%3]
		if err := m.teamSave(id); err != nil {
			if snapErr := m.settle(fmt.Sprintf("%s %02d failed (%v)", label, i, err)); snapErr != nil {
				return snapErr
			}
			return m.violate("save_failed", fmt.Sprintf("%s: team save through voter %d: %v", label, id, err))
		}
		m.saveCount++
		if err := m.settle(fmt.Sprintf("%s %02d team save on voter %d", label, i, id)); err != nil {
			return err
		}
		time.Sleep(3 * time.Second)
	}
	return nil
}

// saves runs the four tracked saves through voter id and settles after each.
func (m *mixedRun) saves(id uint64, label string) error {
	for _, s := range []struct {
		name string
		do   func(uint64) error
	}{{"membership", m.membershipSave}, {"policy-write retention", m.policyWrite}, {"source policy", m.sourcePolicy}, {"team", m.teamSave}} {
		m.say("%s: %s save through voter %d (%s)", label, s.name, id, m.release[id])
		if err := s.do(id); err != nil {
			// A refused call on a voter that has stopped applying is the observation, not a harness fault.
			if snapErr := m.settle(fmt.Sprintf("%s / %s failed (%v)", label, s.name, err)); snapErr != nil {
				return snapErr
			}
			return m.violate("save_failed", fmt.Sprintf("%s through voter %d: %v", s.name, id, err))
		}
		m.saveCount++
		if err := m.settle(fmt.Sprintf("%s / %s through voter %d", label, s.name, id)); err != nil {
			return err
		}
	}
	return nil
}

// requireOrg checks what the stored organization says about the per-object records after the last save
// (settle must have run): tracked says whether the save that was just made left obj_seen equal to the
// organization's epoch (a candidate voter's save) or behind it (a previous-release voter's save, which
// bumps the epoch and knows nothing of the records); records says whether any object is recorded.
func (m *mixedRun) requireOrg(label string, tracked, records bool) error {
	o := m.org()
	if oldTracksRecords() {
		tracked = true // the previous release (5475ef6) tracks the records itself: every save leaves obj_seen at the epoch
	}
	m.say("  %s: org epoch=%d obj_seen=%d obj_floor=%d records=%d (newest %q) tracked=%t", label, o.Epoch, o.Seen, o.Floor, o.Records, o.Newest, o.Tracked)
	if o.Tracked != tracked {
		return m.violate("records_state", fmt.Sprintf("%s: the last save left tracked=%t, want %t (obj_seen %d, epoch %d)", label, o.Tracked, tracked, o.Seen, o.Epoch))
	}
	if records && o.Records == 0 {
		return m.violate("records_missing", label+": no object record in the organization")
	}
	return nil
}

// rollTo restarts voter id on the previous release ("old") or the candidate ("new") binary, on the same
// data directory, and waits for it to serve.
func (m *mixedRun) rollTo(id uint64, release string) error {
	bin := m.newBin
	if release == "old" {
		bin = m.oldBin
	}
	m.say("ROLL voter %d from %s to %s: SIGTERM, restart on the %s binary", id, m.release[id], release, release)
	if err := m.c.terminate(id); err != nil {
		return err
	}
	m.c.setBinary(id, bin)
	m.release[id] = release
	if err := m.c.start(id); err != nil {
		return err
	}
	var err error
	if m.sites[id], err = m.c.site(id); err != nil {
		return err
	}
	if err = waitNodeReady(m.sites[id], 180*time.Second); err != nil {
		if release == "old" {
			m.sawStop = true // a previous-release voter that cannot serve the group's state: the failure a red run looks for
		}
		return m.violate("roll_not_ready", fmt.Sprintf("voter %d after restart on %s: %v (log %q)", id, release, err, lastLines(m.c.logs[id].String(), 4)))
	}
	return m.settle(fmt.Sprintf("ROLL voter %d done (%s)", id, m.releases()))
}

// ---- API ----

func (m *mixedRun) login(id uint64) (auth.Session, error) {
	var s auth.Session
	status, raw, err := postRetryStale(m.sites[id], "/api/v1/login", map[string]string{"Email": "owner@install-smoke.invalid", "Password": m.fx.password, "Code": ""}, "", "", &m.stale)
	if err = requireSmokeResponse("owner_login", status, 200, raw, err); err != nil {
		return s, err
	}
	return s, json.Unmarshal(raw, &s)
}

func (m *mixedRun) adminRead(id uint64, s auth.Session, kind string) (auth.AdminView, error) {
	var view auth.AdminView
	status, raw, err := postRetryStale(m.sites[id], "/api/v1/admin/read", auth.AdminReadRequest{OrgID: m.fx.org, Kind: kind}, s.CSRF, "", &m.stale)
	if err = requireSmokeResponse("admin_read_"+kind, status, 200, raw, err); err != nil {
		return view, err
	}
	return view, json.Unmarshal(raw, &view)
}

// adminSave is one admin command on the epoch read just before it (the console's own precondition).
func (m *mixedRun) adminSave(id uint64, s auth.Session, kind string, p auth.AdminPayload) error {
	p.Reason = "mixed-binary smoke"
	payload, _ := json.Marshal(p)
	var last string
	for range 8 {
		view, err := m.adminRead(id, s, "organization")
		if err != nil {
			return err
		}
		epoch := model.Uint64(view.Epoch)
		cmd := auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedEpoch: &epoch, OrgID: m.fx.org, Kind: kind, Payload: payload}
		var (
			status int
			raw    []byte
		)
		// A write that raced a leadership transfer (the balancer moves a group's leader in the first minute of a group) answers 503
		// unavailable and may or may not have committed: it is asked again with the SAME command id, and the stored answer comes back
		// if it did (a command id is applied once).
		for attempt := 0; ; attempt++ {
			if status, raw, err = postRetryStale(m.sites[id], "/api/v1/admin/commands", cmd, s.CSRF, "", &m.stale); err != nil {
				return err
			}
			if status != 503 || attempt >= 40 {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		if status == 200 || status == 202 {
			m.say("  admin %s on voter %d: %d at org epoch %d", kind, id, status, uint64(epoch))
			return nil
		}
		last = fmt.Sprintf("status %d %s", status, trunc(string(raw), 200))
		if status != 409 {
			break
		}
	}
	return errors.New("admin " + kind + ": " + last)
}

func (m *mixedRun) teamSave(id uint64) error {
	s, err := m.login(id)
	if err != nil {
		return err
	}
	return m.adminSave(id, s, "team", m.teamPayload())
}

func (m *mixedRun) membershipSave(id uint64) error {
	s, err := m.login(id)
	if err != nil {
		return err
	}
	return m.adminSave(id, s, "membership", auth.AdminPayload{UserID: m.fx.reader.User, Enabled: true})
}

func (m *mixedRun) policyWrite(id uint64) error {
	s, err := m.login(id)
	if err != nil {
		return err
	}
	site := m.sites[id]
	status, raw, err := postRetryStale(site, "/api/v1/policies", map[string]any{"org": m.fx.org, "project_id": m.fx.project, "operation": "read"}, s.CSRF, "", &m.stale)
	if err = requireSmokeResponse("policy_read", status, 200, raw, err); err != nil {
		return err
	}
	var view struct {
		Revision model.Revision `json:"revision"`
	}
	if err = json.Unmarshal(raw, &view); err != nil {
		return err
	}
	m.retentionDays++
	status, raw, err = postRetryStale(site, "/api/v1/policies", map[string]any{"org": m.fx.org, "project_id": m.fx.project, "operation": "write", "command_id": model.NewID(), "expected_revision": view.Revision,
		"reason": "mixed-binary smoke", "change": map[string]any{"kind": "retention", "retention": map[string]any{"signal": "metrics", "days": m.retentionDays}}}, s.CSRF, "", &m.stale)
	if err = requireSmokeResponse("policy_write", status, 200, raw, err); err != nil {
		return err
	}
	m.say("  policy write on voter %d: 200 (retention metrics %d days)", id, m.retentionDays)
	return nil
}

func (m *mixedRun) waitSourceOpen(id uint64, s auth.Session) (auth.AdminSource, error) {
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		view, err := m.adminRead(id, s, "source")
		if err != nil {
			return auth.AdminSource{}, err
		}
		for _, src := range view.Sources {
			if src.ID == m.fx.source && !src.Closing {
				return src, nil
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return auth.AdminSource{}, errors.New("source still closing after 90 s")
}

// sourcePolicy is the admin "source_policy" setting save of the source and then POST /api/v1/sources/policy,
// each a tracked change, with the fence that follows each completed.
func (m *mixedRun) sourcePolicy(id uint64) error {
	s, err := m.login(id)
	if err != nil {
		return err
	}
	cfg, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: m.fx.project, Origins: []string{}, Readers: []model.ID{}, Enabled: true})
	if err = m.adminSave(id, s, "source_policy", auth.AdminPayload{ID: m.fx.source, Config: cfg}); err != nil {
		return err
	}
	src, err := m.waitSourceOpen(id, s)
	if err != nil {
		return err
	}
	next := src.Policy
	m.maxSeries++
	next.MaxSeries = model.Uint64(m.maxSeries)
	next.Revision = src.Policy.Revision + 1
	status, raw, err := postRetryStale(m.sites[id], "/api/v1/sources/policy", auth.SourcePolicyChange{CommandID: model.NewID(), Source: m.fx.source, ExpectedRevision: src.Policy.Revision, Policy: next, Reason: "mixed-binary smoke"}, s.CSRF, "", &m.stale)
	if err = requireSmokeResponse("source_policy_change", status, 202, raw, err); err != nil {
		return err
	}
	m.say("  sources/policy on voter %d: 202 (policy revision %d, max_series %d)", id, uint64(next.Revision), m.maxSeries)
	_, err = m.waitSourceOpen(id, s)
	return err
}

// ---- observation ----

// orgFact is what a voter's stored organization says about the per-object records, which live in the
// organization's Settings (obj_epoch:<object>, obj_floor, obj_seen): Records is how many objects are
// recorded, Tracked says the last change to the organization was a tracked one (obj_seen equals Epoch).
type orgFact struct {
	Epoch   uint64
	Seen    uint64
	Floor   uint64
	Records int
	Tracked bool
	Newest  string
	// Objects is the epoch each recorded object last changed at.
	Objects map[string]uint64 `json:"-"`
}

type memberFact struct {
	ID       uint64
	Release  string
	Alive    bool
	Exit     string
	Ready    bool
	Readyz   string
	Applied  uint64
	Revision string
	Digest   string
	SealOK   bool
	StateErr string
	Orgs     map[string]orgFact
	Declared map[string]uint64
	Patches  int
	Journal  string
	LogTail  string

	ReadyzCode int
}

func (m *mixedRun) observe(id uint64) memberFact {
	f := memberFact{ID: id, Release: m.release[id], Alive: true}
	m.c.mu.Lock()
	done := m.c.done[id]
	m.c.mu.Unlock()
	if done != nil {
		select {
		case err := <-done:
			done <- err
			f.Alive, f.Exit = false, fmt.Sprint(err)
		default:
		}
	}
	if f.Alive {
		site := withTimeout(m.sites[id], 5*time.Second)
		code, raw, err := site.get("/readyz")
		f.ReadyzCode = code
		if err != nil {
			f.Readyz = "error: " + err.Error()
		} else {
			f.Readyz = strings.TrimSpace(string(raw))
			var st installReadiness
			if json.Unmarshal(raw, &st) == nil {
				f.Ready = st.Ready && code == 200
				if st.Applied != nil {
					f.Applied = uint64(st.Applied.Index)
				}
			}
		}
	}
	f.Patches, f.Journal = countStatePatches(m.c.data[id])
	if f.Patches > m.patchMax[id] {
		m.patchMax[id] = f.Patches
	}
	f.LogTail = lastLines(m.c.logs[id].String(), 4)
	state, seal, err := readControlState(m.c.data[id])
	if err != nil {
		f.StateErr = err.Error()
		return f
	}
	sum := sha256.Sum256(state)
	f.Digest, f.SealOK = hex.EncodeToString(sum[:8]), bytes.Equal(sum[:], seal)
	var st map[string]json.RawMessage
	if err = json.Unmarshal(state, &st); err != nil {
		f.StateErr = "state json: " + err.Error()
		return f
	}
	f.Revision = string(st["Revision"])
	f.Orgs = map[string]orgFact{}
	var orgs map[string]struct {
		Epoch    uint64
		Settings map[string]json.RawMessage
	}
	if raw, ok := st["Orgs"]; ok {
		_ = json.Unmarshal(raw, &orgs)
	} else {
		keys := make([]string, 0, len(st))
		for k := range st {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		f.StateErr = "no Orgs member; members: " + strings.Join(keys, ",")
	}
	for k, o := range orgs {
		of := orgFact{Epoch: o.Epoch, Objects: map[string]uint64{}}
		_ = json.Unmarshal(o.Settings[model.ObjSeenKey], &of.Seen)
		_ = json.Unmarshal(o.Settings[model.ObjFloorKey], &of.Floor)
		var newest uint64
		for key, raw := range o.Settings {
			if !strings.HasPrefix(key, model.ObjEpochKeyPrefix) {
				continue
			}
			of.Records++
			var at uint64
			if json.Unmarshal(raw, &at) == nil {
				of.Objects[strings.TrimPrefix(key, model.ObjEpochKeyPrefix)] = at
				if at >= newest {
					newest, of.Newest = at, strings.TrimPrefix(key, model.ObjEpochKeyPrefix)
				}
			}
		}
		of.Tracked = of.Seen != 0 && of.Seen == of.Epoch
		f.Orgs[k] = of
	}
	f.Declared = readDeclarations(m.c.data[id])
	return f
}

// settle records the observation of all three voters once they agree (applied cursor and state digest) and
// checks the expectations; it polls for up to 60 s for the voters to reach the same state. A voter whose
// state could not be read (or whose copy does not match its stored seal) is a problem of its own, never
// an agreeing empty digest, and every alive voter's digest is compared with every other's.
func (m *mixedRun) settle(label string) error {
	m.step++
	m.say("== %s", label)
	var facts []memberFact
	deadline := time.Now().Add(60 * time.Second)
	for {
		facts = facts[:0]
		for _, id := range []uint64{1, 2, 3} {
			facts = append(facts, m.observe(id))
		}
		agree := true
		for _, f := range facts {
			if !f.Alive || !f.Ready || f.StateErr != "" || !f.SealOK || f.Digest == "" || f.Digest != facts[0].Digest || f.Applied != facts[0].Applied {
				agree = false
			}
		}
		if agree || time.Now().After(deadline) {
			break
		}
		time.Sleep(700 * time.Millisecond)
	}
	m.lastFacts = map[uint64]memberFact{}
	raw, _ := json.Marshal(map[string]any{"step": m.step, "label": label, "voters": facts})
	f, err := os.OpenFile(filepath.Join(m.evidence, "snapshots.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		f.Write(append(raw, '\n'))
		f.Close()
	}
	for _, f := range facts {
		m.lastFacts[f.ID] = f
		decl := make([]string, 0, len(f.Declared))
		for k, v := range f.Declared {
			decl = append(decl, k+"="+strconv.FormatUint(v, 10))
		}
		sort.Strings(decl)
		orgs := make([]string, 0, len(f.Orgs))
		for k, o := range f.Orgs {
			orgs = append(orgs, fmt.Sprintf("org %s epoch=%d obj_seen=%d obj_floor=%d records=%d tracked=%t", k[:8], o.Epoch, o.Seen, o.Floor, o.Records, o.Tracked))
		}
		m.say("  voter %d [%s] alive=%t exit=%q readyz=%d ready=%t applied=%d state_revision=%s digest=%s seal_ok=%t declared{%s} %s %s", f.ID, f.Release, f.Alive, f.Exit, f.ReadyzCode, f.Ready, f.Applied, f.Revision, f.Digest, f.SealOK, strings.Join(decl, " "), strings.Join(orgs, "; "), f.StateErr)
		m.say("    readyz: %s", trunc(f.Readyz, 300))
	}
	problems, stopped := factProblems(facts)
	if stopped {
		m.sawStop = true
	}
	if len(problems) > 0 {
		return m.violate("check_failed", label+": "+strings.Join(problems, " | "))
	}
	return nil
}

// orgFact is the organization of the installation as every voter stores it, once the voters agree
// (settle): the three digests are equal, so voter 1's copy stands for all.
func (m *mixedRun) org() orgFact {
	for _, id := range []uint64{1, 2, 3} {
		if f, ok := m.lastFacts[id]; ok && f.Alive {
			return f.Orgs[m.fx.org.String()]
		}
	}
	return orgFact{}
}

// factProblems is what the observation of the voters alone says is wrong, whatever the phase: a voter that
// does not serve (stopped is then true), one whose stored state could not be read, whose copy does not match
// its seal or whose digest is empty (nothing was observed, which is not an agreement), and every pair of
// alive voters whose digests differ, whichever voter is the reference and whichever voters are down.
func factProblems(facts []memberFact) (problems []string, stopped bool) {
	for _, f := range facts {
		if !f.Alive || !f.Ready {
			stopped = true
			problems = append(problems, fmt.Sprintf("voter %d (%s) not serving: alive=%t ready=%t exit=%q readyz=%s log=%q", f.ID, f.Release, f.Alive, f.Ready, f.Exit, trunc(f.Readyz, 120), f.LogTail))
		}
		switch {
		case f.StateErr != "":
			problems = append(problems, fmt.Sprintf("the stored state of voter %d (%s) could not be read: %s", f.ID, f.Release, f.StateErr))
		case !f.SealOK:
			problems = append(problems, fmt.Sprintf("the stored state of voter %d (%s) does not match its seal", f.ID, f.Release))
		case f.Digest == "":
			problems = append(problems, fmt.Sprintf("voter %d (%s) has no state digest: nothing was observed", f.ID, f.Release))
		}
	}
	for i := range facts {
		for j := i + 1; j < len(facts); j++ {
			a, b := facts[i], facts[j]
			if a.Alive && b.Alive && a.Digest != b.Digest {
				problems = append(problems, fmt.Sprintf("state digest of voter %d (%s) differs from voter %d (%s)", a.ID, a.Digest, b.ID, b.Digest))
			}
		}
	}
	return problems, stopped
}

func (m *mixedRun) writeLogs() {
	if m.c == nil {
		return
	}
	for id, log := range m.c.logs {
		_ = os.WriteFile(filepath.Join(m.evidence, fmt.Sprintf("node-%d.log", id)), []byte(log.String()), 0o644)
	}
}

// countStatePatches is the number of state patch commands (control.statePatchKey) in the voter's control
// journal (<data>/raft/control/ready.wal; the journal is JSON, a command's payload base64, so a patch
// is the base64 of its first 15 bytes `{"state_patch":`). A control command is proposed as a state patch once every member
// declared protocol 5; the journal is cut at snapshots, so the caller keeps the largest count it saw.
func countStatePatches(dir string) (int, string) {
	var path string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && info.Name() == "ready.wal" && filepath.Base(filepath.Dir(p)) == "control" && path == "" {
			path = p
		}
		return nil
	})
	if path == "" {
		return 0, "no control ready.wal below " + dir
	}
	dirEntries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return 0, err.Error()
	}
	total, listing := 0, filepath.Dir(path)+":"
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		raw, rerr := os.ReadFile(filepath.Join(filepath.Dir(path), de.Name()))
		if rerr != nil {
			continue
		}
		n, r := countJournalCommands(raw)
		total += n
		listing += fmt.Sprintf(" %s=%dB/%d patches/%d replacements", de.Name(), len(raw), n, r)
	}
	return total, listing
}

var journalBase64Run = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)

// countJournalCommands counts the state patch and whole-state replacement commands in a journal file.
// The journal stores each entry as base64 of the entry's JSON, whose payload is base64 again, so a
// command is recognised by the base64 of its first member inside every decoded run of the file.
func countJournalCommands(raw []byte) (patches, replacements int) {
	for _, run := range journalBase64Run.FindAll(raw, -1) {
		dec, err := base64.StdEncoding.DecodeString(string(run))
		if err != nil {
			continue
		}
		patches += bytes.Count(dec, []byte(`"payload":"eyJzdGF0ZV9wYXRjaCI6`))
		replacements += bytes.Count(dec, []byte(`"payload":"eyJleHBlY3RlZCI6`))
	}
	return
}

// readDeclarations are the protocol declarations (erase-protocol-1 capability acknowledgements) the voter
// holds in its slot-0 apply database, as "node:identity" -> declared protocol.
func readDeclarations(dir string) map[string]uint64 {
	declared := map[string]uint64{}
	path := findDataFile(dir, "apply.db")
	if path == "" {
		return declared
	}
	db, closeDB, err := copyForRead(path)
	if err != nil {
		return declared
	}
	defer closeDB()
	op := model.ID{'e', 'r', 'a', 's', 'e', '-', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l', '-', '1'}
	prefix := "erase-ack:" + op.String() + ":"
	_ = db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		if meta == nil {
			return nil
		}
		return meta.ForEach(func(k, v []byte) error {
			if len(k) > 2 && k[0] == 0 && k[1] == 0 && strings.HasPrefix(string(k[2:]), prefix) && len(v) == 8 {
				declared[strings.TrimPrefix(string(k[2:]), prefix)] = binary.BigEndian.Uint64(v)
			}
			return nil
		})
	})
	return declared
}

// waitDeclarations waits (up to 90 s) until every voter's own apply database lists the protocol declaration
// of all three members, so the first save is made in the steady state of the mixed group, not in the
// seconds before the voters have declared.
func (m *mixedRun) waitDeclarations() error {
	deadline := time.Now().Add(90 * time.Second)
	var last []memberFact
	for time.Now().Before(deadline) {
		last = last[:0]
		complete := true
		for _, id := range []uint64{1, 2, 3} {
			f := m.observe(id)
			last = append(last, f)
			for _, member := range []string{"1:node-a", "2:node-b", "3:node-c"} {
				if f.Declared[member] == 0 {
					complete = false
				}
			}
		}
		if complete {
			for _, f := range last {
				m.say("declarations seen by voter %d [%s]: %v", f.ID, f.Release, f.Declared)
			}
			return nil
		}
		time.Sleep(time.Second)
	}
	for _, f := range last {
		m.say("declarations seen by voter %d [%s] at the deadline: %v", f.ID, f.Release, f.Declared)
	}
	return m.violate("declarations_incomplete", "not every voter's declaration reached every voter within 90 s")
}

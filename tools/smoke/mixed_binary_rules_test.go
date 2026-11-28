// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

// TestMixedBinaryRuleLedgerMarker drives D108 (the rule books and the rule outbox move out of the control blob into ledger tables) on REAL
// binaries. "old" is a build of the live head (declares protocol 9, keeps the rule facts in the blob and knows nothing of the marker); "new"
// is the candidate, built with -tags soundpost_diag so that /debug/soundpost answers control.rule_layout and control.rule_marker_index
// (SOUNDPOST_DIAG_PPROF is set per voter by the harness; the old binary ignores it).
//
//	control  an all-old group is fed the three rules below; what its evaluations came to (the projection of the books and the outbox that does
//	         not depend on the clock) is the blob control;
//	(a)      three voters start on old, the rules are saved and evaluated; they are rolled to new one by one: while any member is on 9 the
//	         gate is closed and every voter, new ones asked through diag, still keeps the books in the blob, and the evaluations go on;
//	(b)      with the third voter on new every member declares protocol 10 and the files are in the ledger layout (the gate of D104; the index
//	         contraction is not a condition of it): the marker commits once, at the same index on every voter; the evaluations that
//	         follow use the ledger form (diag says ledger on every voter, the books are in the tables and no longer in the blob, books and
//	         outputs are the same on every voter) and came to the outcomes of the blob control;
//	(c)      one voter is restarted (same layout, same marker, same books); the rules are retired and the group is quiet; a member running old
//	         is added after the marker and refused by the layout guard (layout_incompatible), and no voter's state digest moved;
//	(d)      `soundpost upgrade contract-indexes` still succeeds and the marker stays the one index it was.
//
// Environment as TestMixedBinaryContractRefusal, with SOUNDPOST_MIXED_NEW_BINARY a soundpost_diag build.
func TestMixedBinaryRuleLedgerMarker(t *testing.T) {
	oldBin, newBin, evidence := os.Getenv("SOUNDPOST_MIXED_OLD_BINARY"), os.Getenv("SOUNDPOST_MIXED_NEW_BINARY"), os.Getenv("SOUNDPOST_MIXED_EVIDENCE")
	if oldBin == "" || newBin == "" {
		t.Skip("set SOUNDPOST_MIXED_OLD_BINARY and SOUNDPOST_MIXED_NEW_BINARY (a -tags soundpost_diag build) to static soundpost binaries of the previous release and the candidate")
	}
	if evidence == "" {
		evidence = t.TempDir()
	}
	dir := filepath.Join(evidence, "rules")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	trace, err := os.Create(filepath.Join(dir, "trace.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer trace.Close()
	m := &mixedRun{t: t, trace: trace, evidence: dir, oldBin: oldBin, newBin: newBin, release: map[uint64]string{}, expect: "green", patchMax: map[uint64]int{}}
	runErr := m.runRuleLedger()
	m.writeLogs()
	if runErr != nil && m.violation == "" {
		m.violation = "harness_error: " + runErr.Error()
	}
	m.say("RESULT violation=%q harness_error=%v", m.violation, runErr)
	if m.violation != "" {
		t.Fatalf("rule ledger marker scenario violated: %s", m.violation)
	}
}

// ---- the stored rule facts of a voter ----

// ruleStore is the rule books and the rule outbox a voter's control.db holds, whichever layout they are in, as canonical JSON by rule key
// ("org:project:rule") and by output ID.
type ruleStore struct {
	ledger                 bool // the file says it keeps them in the tables (ledger_rules)
	blobBooks, tableBooks  int
	blobOutputs, tableOuts int
	books, outputs         map[string]string
}

func canonicalJSON(raw []byte) (string, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", err
	}
	out, err := json.Marshal(v)
	return string(out), err
}

func readRuleStore(dir string) (ruleStore, error) {
	rs := ruleStore{books: map[string]string{}, outputs: map[string]string{}}
	path := findDataFile(dir, "control.db")
	if path == "" {
		return rs, errors.New("no control.db")
	}
	db, closeDB, err := copyForRead(path)
	if err != nil {
		return rs, err
	}
	defer closeDB()
	err = db.View(func(tx *bolt.Tx) error {
		ctrl := tx.Bucket([]byte("control"))
		if ctrl == nil {
			return errors.New("no control bucket")
		}
		rs.ledger = ctrl.Get([]byte("ledger_rules")) != nil
		var st struct{ RuleBooks, RuleOutputs map[string]json.RawMessage }
		if raw := ctrl.Get([]byte("state")); raw != nil {
			if err := json.Unmarshal(raw, &st); err != nil {
				return err
			}
		}
		for k, raw := range st.RuleBooks {
			c, err := canonicalJSON(raw)
			if err != nil {
				return err
			}
			rs.books[k] = c
			rs.blobBooks++
		}
		for _, raw := range st.RuleOutputs {
			var o control.RuleOutput
			if err := json.Unmarshal(raw, &o); err != nil {
				return err
			}
			c, _ := canonicalJSON(raw)
			rs.outputs[o.ID.String()] = c
			rs.blobOutputs++
		}
		if b := tx.Bucket([]byte("rule_books")); b != nil {
			if err := b.ForEach(func(k, v []byte) error {
				c, err := canonicalJSON(v)
				if err != nil {
					return err
				}
				rs.books[string(k)] = c
				rs.tableBooks++
				return nil
			}); err != nil {
				return err
			}
		}
		if b := tx.Bucket([]byte("rule_outputs")); b != nil {
			if err := b.ForEach(func(k, v []byte) error {
				var o control.RuleOutput
				if err := json.Unmarshal(v, &o); err != nil {
					return err
				}
				c, _ := canonicalJSON(v)
				rs.outputs[o.ID.String()] = c
				rs.tableOuts++
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
	return rs, err
}

func (s ruleStore) same(o ruleStore) bool {
	if len(s.books) != len(o.books) || len(s.outputs) != len(o.outputs) {
		return false
	}
	for k, v := range s.books {
		if o.books[k] != v {
			return false
		}
	}
	for k, v := range s.outputs {
		if o.outputs[k] != v {
			return false
		}
	}
	return true
}

func (s ruleStore) summary() string {
	return fmt.Sprintf("ledger_rules=%t books blob=%d table=%d outputs blob=%d table=%d", s.ledger, s.blobBooks, s.tableBooks, s.blobOutputs, s.tableOuts)
}

// lastAt is the newest evaluation time of every rule in the books.
func (s ruleStore) lastAt() map[string]int64 {
	out := map[string]int64{}
	for k, raw := range s.books {
		var b control.RuleBook
		if json.Unmarshal([]byte(raw), &b) != nil {
			continue
		}
		for _, v := range b.Versions {
			if v.Last != nil && int64(v.Last.At) > out[k] {
				out[k] = int64(v.Last.At)
			}
		}
	}
	return out
}

// projection is what the evaluations came to, without clocks, digests and revisions: per rule label and version the (mode, health) of every
// retained evaluation, and the (kind, signal, notify, mode, phase, reason) of every outbox record. Sets, not counts: two groups do not evaluate
// the same number of grid points.
func (s ruleStore) projection(label map[string]string) []string {
	seen := map[string]bool{}
	for k, raw := range s.books {
		var b control.RuleBook
		if json.Unmarshal([]byte(raw), &b) != nil {
			seen["undecodable book "+label[b.Rule.String()]] = true
			continue
		}
		name := label[b.Rule.String()]
		if name == "" {
			name = "?" + k
		}
		for _, v := range b.Versions {
			evals := append([]control.RuleEvaluationRecord{}, v.Recent...)
			if v.Last != nil {
				evals = append(evals, *v.Last)
			}
			for _, e := range evals {
				seen[fmt.Sprintf("%s v%d eval mode=%s health=%s", name, v.Version, e.Mode, e.Health)] = true
			}
		}
	}
	for _, raw := range s.outputs {
		var o control.RuleOutput
		if json.Unmarshal([]byte(raw), &o) != nil {
			seen["undecodable output"] = true
			continue
		}
		seen[fmt.Sprintf("%s v%d output kind=%s signal=%s notify=%t mode=%s phase=%s reason=%s", label[o.Rule.String()], o.Version, o.Kind, o.Signal, o.Notify, o.Mode, o.Phase, o.Reason)] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- the group ----

func (m *mixedRun) ruleStores() (map[uint64]ruleStore, error) {
	out := map[uint64]ruleStore{}
	for _, id := range []uint64{1, 2, 3} {
		s, err := readRuleStore(m.c.data[id])
		if err != nil {
			return nil, fmt.Errorf("voter %d: %w", id, err)
		}
		out[id] = s
	}
	return out, nil
}

// waitRuleBooks waits until all three voters hold the same books and outbox, every rule of want has evaluated after `after` (unix ns), and
// accept holds for every voter's store. It returns the stores it agreed on.
func (m *mixedRun) waitRuleBooks(label string, want, after int64, accept func(id uint64, s ruleStore) string) (map[uint64]ruleStore, error) {
	deadline := time.Now().Add(150 * time.Second)
	last := ""
	for {
		stores, err := m.ruleStores()
		switch {
		case err != nil:
			last = err.Error()
		default:
			last = ""
			if !stores[1].same(stores[2]) || !stores[1].same(stores[3]) {
				last = "the three voters do not hold the same rule books and outbox"
			}
			if last == "" && len(stores[1].books) != int(want) {
				last = fmt.Sprintf("%d rule books, want %d", len(stores[1].books), want)
			}
			if last == "" {
				for k, at := range stores[1].lastAt() {
					if at <= after {
						last = fmt.Sprintf("rule %s has not evaluated since %d (last %d)", k, after, at)
						break
					}
				}
			}
			for _, id := range []uint64{1, 2, 3} {
				if last == "" && accept != nil {
					last = accept(id, stores[id])
				}
			}
			if last == "" {
				for _, id := range []uint64{1, 2, 3} {
					m.say("  %s: voter %d (%s) %s", label, id, m.release[id], stores[id].summary())
				}
				return stores, nil
			}
		}
		if time.Now().After(deadline) {
			return nil, m.violate("rule_books_not_agreed", label+": "+last)
		}
		time.Sleep(time.Second)
	}
}

// diagRuleLayout is what voter id's diagnostic page says about where it keeps the rule books.
func (m *mixedRun) diagRuleLayout(id uint64) (layout string, marker uint64, err error) {
	var page struct {
		Control map[string]json.RawMessage `json:"control"`
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + m.diag[id] + "/debug/soundpost")
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if err = json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return "", 0, err
	}
	rawLayout, ok := page.Control["rule_layout"]
	if !ok {
		return "", 0, fmt.Errorf("the control section has no rule_layout (is the candidate built with -tags soundpost_diag?): %v", page.Control)
	}
	if err = json.Unmarshal(rawLayout, &layout); err != nil {
		return "", 0, err
	}
	if err = json.Unmarshal(page.Control["rule_marker_index"], &marker); err != nil {
		return "", 0, err
	}
	return layout, marker, nil
}

// requireDiagLayout waits until every voter on the candidate answers the layout and marker want (marker 0 for blob; for ledger any one value that
// all of them share, returned), and that every voter's own file agrees (ledger_rules).
func (m *mixedRun) requireDiagLayout(label, want string) (uint64, error) {
	deadline := time.Now().Add(150 * time.Second)
	for {
		marker, last := uint64(0), ""
		for _, id := range []uint64{1, 2, 3} {
			s, serr := readRuleStore(m.c.data[id])
			if serr != nil {
				last = fmt.Sprintf("voter %d: %v", id, serr)
				break
			}
			if s.ledger != (want == "ledger") {
				last = fmt.Sprintf("voter %d (%s) file: %s, want %s", id, m.release[id], s.summary(), want)
				break
			}
			if m.release[id] != "new" {
				if want != "blob" {
					last = fmt.Sprintf("voter %d runs the previous release in a ledger group", id)
					break
				}
				continue // the previous release has no page and keeps the books in the blob by construction (its file said so above)
			}
			l, at, derr := m.diagRuleLayout(id)
			switch {
			case derr != nil:
				last = fmt.Sprintf("voter %d diag: %v", id, derr)
			case l != want:
				last = fmt.Sprintf("voter %d diag rule_layout=%q rule_marker_index=%d, want %q", id, l, at, want)
			case want == "blob" && at != 0:
				last = fmt.Sprintf("voter %d diag blob with marker %d", id, at)
			case want == "ledger" && at == 0:
				last = fmt.Sprintf("voter %d diag ledger with marker 0", id)
			case want == "ledger" && marker != 0 && at != marker:
				last = fmt.Sprintf("voter %d marker %d, another voter %d", id, at, marker)
			}
			if last != "" {
				break
			}
			marker = max(marker, at)
		}
		if last == "" {
			m.say("%s: rule_layout=%s on every voter that answers, marker index %d (releases %s)", label, want, marker, m.releases())
			return marker, nil
		}
		if time.Now().After(deadline) {
			return 0, m.violate("rule_layout_wrong", label+": "+last)
		}
		time.Sleep(time.Second)
	}
}

// ruleSave saves the rules of the scenario through voter via and returns the label of every rule ID.
func (m *mixedRun) ruleSave(via uint64) (map[string]string, error) {
	s, err := m.login(via)
	if err != nil {
		return nil, err
	}
	post := func(body any, out any) error {
		status, raw, err := postRetryStale(m.sites[via], "/api/v1/rules", body, s.CSRF, "", &m.stale)
		if err = requireSmokeResponse("rules", status, 200, raw, err); err != nil {
			return err
		}
		if out != nil {
			return json.Unmarshal(raw, out)
		}
		return nil
	}
	var list httpapi.RuleListAnswer
	if err = post(map[string]any{"org": m.fx.org.String(), "project_id": m.fx.project.String(), "operation": "list"}, &list); err != nil {
		return nil, err
	}
	profile, featureSet := "promql-prometheus-3.13.5", ""
	for _, p := range list.Profiles {
		if p.ID == profile && len(p.FeatureSets) > 0 {
			featureSet = p.FeatureSets[0]
		}
	}
	if featureSet == "" {
		return nil, fmt.Errorf("the rule list advertises no feature set of %s: %+v", profile, list.Profiles)
	}
	labels := map[string]string{}
	for _, r := range []struct{ label, expr string }{{"nodata", "up == 0"}, {"fires", "vector(1) > 0"}, {"quiet", "vector(1) < 0"}} {
		id := model.NewID()
		spec := map[string]any{"kind": "alert", "profile": profile, "feature_set": featureSet, "expression": r.expr, "interval_seconds": 5, "severity": "critical"}
		body := map[string]any{"org": m.fx.org.String(), "project_id": m.fx.project.String(), "operation": "save", "command_id": model.NewID().String(), "rule_id": id.String(),
			"expected_revision": "0", "reason": "mixed-binary rule ledger smoke", "rule": spec}
		if err = post(body, nil); err != nil {
			return nil, fmt.Errorf("save %s: %w", r.label, err)
		}
		labels[id.String()] = r.label
	}
	m.say("rules saved through voter %d (%s): %d rules at 5 s", via, m.release[via], len(labels))
	return labels, nil
}

// ruleRetireAll retires every rule of the project through voter via.
func (m *mixedRun) ruleRetireAll(via uint64) error {
	s, err := m.login(via)
	if err != nil {
		return err
	}
	post := func(body any, out any) error {
		status, raw, err := postRetryStale(m.sites[via], "/api/v1/rules", body, s.CSRF, "", &m.stale)
		if err = requireSmokeResponse("rules", status, 200, raw, err); err != nil {
			return err
		}
		if out != nil {
			return json.Unmarshal(raw, out)
		}
		return nil
	}
	var list httpapi.RuleListAnswer
	if err = post(map[string]any{"org": m.fx.org.String(), "project_id": m.fx.project.String(), "operation": "list"}, &list); err != nil {
		return err
	}
	for _, r := range list.Rules {
		if r.Retired {
			continue
		}
		body := map[string]any{"org": m.fx.org.String(), "project_id": m.fx.project.String(), "operation": "retire", "command_id": model.NewID().String(), "rule_id": r.RuleID.String(),
			"expected_revision": fmt.Sprint(uint64(r.Revision)), "reason": "mixed-binary rule ledger smoke"}
		if err = post(body, nil); err != nil {
			return err
		}
	}
	return nil
}

// quiet waits until the three voters hold one digest and applied index that did not move over four reads five seconds apart (the workers settle
// conditions and the like for a while after the rules are retired), and returns every voter's digest.
func (m *mixedRun) quiet(label string) (map[uint64]string, error) {
	deadline := time.Now().Add(180 * time.Second)
	var prev string
	same := 0
	for {
		digests, joined := map[uint64]string{}, ""
		agree := true
		for _, id := range []uint64{1, 2, 3} {
			f := m.observe(id)
			digests[id] = f.Digest
			joined += fmt.Sprintf("%d=%s/%d;", id, f.Digest, f.Applied)
			if !f.Alive || f.Digest == "" || f.Digest != digests[1] {
				agree = false
			}
		}
		if agree && joined == prev {
			same++
		} else {
			same = 0
		}
		prev = ""
		if agree {
			prev = joined
		}
		if same >= 3 {
			m.say("%s: every voter holds state digest %s (%s)", label, digests[1], joined)
			return digests, nil
		}
		if time.Now().After(deadline) {
			return nil, m.violate("not_quiet", label+": "+joined)
		}
		time.Sleep(5 * time.Second)
	}
}

func freeLoopback() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return l.Addr().String(), nil
}

// ruleControl is the blob control: an all-old group fed the same rules; what its evaluations came to.
func (m *mixedRun) ruleControl(dir string) ([]string, error) {
	cm := &mixedRun{t: m.t, trace: m.trace, evidence: dir, oldBin: m.oldBin, newBin: m.oldBin, release: map[uint64]string{}, expect: "green", patchMax: map[uint64]int{}}
	cleanup, err := cm.startGroup(func(uint64) string { return "old" })
	defer cleanup()
	defer cm.writeLogs()
	if err != nil {
		return nil, err
	}
	m.say("CONTROL all-old group (blob layout by construction)")
	labels, err := cm.ruleSave(1)
	if err != nil {
		return nil, err
	}
	stores, err := cm.waitRuleBooks("control", int64(len(labels)), time.Now().UnixNano(), func(id uint64, s ruleStore) string {
		if s.ledger || s.tableBooks != 0 {
			return "the previous release keeps rule books in tables: " + s.summary()
		}
		return ""
	})
	if err != nil {
		m.violation = cm.violation
		return nil, err
	}
	p := stores[1].projection(labels)
	m.say("CONTROL projection (%d entries): %s", len(p), strings.Join(p, " | "))
	return p, nil
}

func equalLines(a, b []string) bool { return strings.Join(a, "\n") == strings.Join(b, "\n") }

func (m *mixedRun) runRuleLedger() error {
	// ---- control ----
	blobControl, err := m.ruleControl(filepath.Join(m.evidence, "control"))
	if err != nil {
		return err
	}
	if len(blobControl) == 0 {
		return m.violate("control_empty", "the blob control evaluated nothing")
	}

	// ---- (a) ----
	m.diag = map[uint64]string{}
	for _, id := range []uint64{1, 2, 3} {
		if m.diag[id], err = freeLoopback(); err != nil {
			return err
		}
	}
	cleanup, err := m.startGroup(func(uint64) string { return "old" })
	defer cleanup()
	if err != nil {
		return err
	}
	m.say("PHASE (a): three voters on the previous release (protocol 9), rules saved and evaluated, rolled to the candidate one by one")
	labels, err := m.ruleSave(1)
	if err != nil {
		return err
	}
	want := int64(len(labels))
	if _, err = m.waitRuleBooks("(a) all old", want, time.Now().UnixNano(), func(_ uint64, s ruleStore) string {
		if s.ledger || s.tableBooks != 0 {
			return "blob expected: " + s.summary()
		}
		return ""
	}); err != nil {
		return err
	}
	for _, id := range []uint64{1, 2, 3} {
		if id == 3 {
			break
		}
		if err = m.rollTo(id, "new"); err != nil {
			return err
		}
		if _, err = m.requireDiagLayout(fmt.Sprintf("(a) voter %d rolled, voter 3 still on 9: gate closed", id), "blob"); err != nil {
			return err
		}
		stores, werr := m.waitRuleBooks(fmt.Sprintf("(a) after rolling voter %d", id), want, time.Now().UnixNano(), func(_ uint64, s ruleStore) string {
			if s.ledger || s.tableBooks != 0 || s.tableOuts != 0 {
				return "blob expected: " + s.summary()
			}
			return ""
		})
		if werr != nil {
			return werr
		}
		if p := stores[1].projection(labels); !equalLines(p, blobControl) {
			return m.violate("blob_outcomes_differ", fmt.Sprintf("after rolling voter %d the evaluations came to\n%s\nthe blob control to\n%s", id, strings.Join(p, "\n"), strings.Join(blobControl, "\n")))
		}
	}
	if err = m.rollTo(3, "new"); err != nil {
		return err
	}
	m.say("PHASE (a) ok: while a member was on 9 no voter left the blob layout, and the outcomes equal the blob control")

	// ---- (b) ----
	m.say("PHASE (b): all three voters declare protocol 10: the marker")
	marker, err := m.requireDiagLayout("(b) all three on the candidate", "ledger")
	if err != nil {
		return err
	}
	afterMarker := time.Now().UnixNano()
	post, err := m.waitRuleBooks("(b) evaluations in the ledger form", want, afterMarker, func(_ uint64, s ruleStore) string {
		if !s.ledger || s.blobBooks != 0 || s.blobOutputs != 0 || s.tableBooks != int(want) {
			return "ledger expected: " + s.summary()
		}
		return ""
	})
	if err != nil {
		return err
	}
	if again, aerr := m.requireDiagLayout("(b) the marker after more evaluations", "ledger"); aerr != nil {
		return aerr
	} else if again != marker {
		return m.violate("marker_committed_twice", fmt.Sprintf("marker index %d, then %d", marker, again))
	}
	if p := post[1].projection(labels); !equalLines(p, blobControl) {
		return m.violate("ledger_outcomes_differ", fmt.Sprintf("the evaluations after the marker came to\n%s\nthe blob control to\n%s", strings.Join(p, "\n"), strings.Join(blobControl, "\n")))
	}
	m.say("PHASE (b) ok: marker committed once at index %d on every voter; books and outputs identical on every voter; outcomes equal the blob control", marker)

	// ---- (c) ----
	m.say("PHASE (c): restart, then an old member after the marker")
	if err = m.rollTo(2, "new"); err != nil {
		return err
	}
	if again, lerr := m.requireDiagLayout("(c) after restarting voter 2", "ledger"); lerr != nil {
		return lerr
	} else if again != marker {
		return m.violate("marker_moved_by_restart", fmt.Sprintf("marker index %d, then %d", marker, again))
	}
	if _, err = m.waitRuleBooks("(c) after restarting voter 2", want, time.Now().UnixNano(), func(_ uint64, s ruleStore) string {
		if !s.ledger || s.blobBooks != 0 || s.tableBooks != int(want) {
			return "ledger expected: " + s.summary()
		}
		return ""
	}); err != nil {
		return err
	}
	if err = m.ruleRetireAll(1); err != nil {
		return err
	}
	before, err := m.quiet("(c) rules retired, before the old member")
	if err != nil {
		return err
	}
	if _, _, err = m.refuseOldLearnerThen("(c) old member after the marker", nil); err != nil {
		return err
	}
	after, err := m.quiet("(c) after the refusals")
	if err != nil {
		return err
	}
	for _, id := range []uint64{1, 2, 3} {
		if before[id] != after[id] {
			return m.violate("refused_member_changed_state", fmt.Sprintf("voter %d state digest %s -> %s across the refusals", id, before[id], after[id]))
		}
	}
	if again, lerr := m.requireDiagLayout("(c) after the refusals", "ledger"); lerr != nil {
		return lerr
	} else if again != marker {
		return m.violate("marker_moved_by_refusal", fmt.Sprintf("marker index %d, then %d", marker, again))
	}
	m.say("PHASE (c) ok: restart kept layout and books; the old member was refused and no state digest moved")

	// ---- (d) ----
	m.say("PHASE (d): contract-indexes on a group that holds the marker (the files are already in the contracted layout, the step is a no-op there)")
	out, code, err := m.contract(1)
	if err != nil {
		return err
	}
	m.say("contract-indexes against voter 1: exit %d: %s", code, out)
	if code != 0 || !strings.Contains(out, "contracted") {
		return m.violate("contract_failed", fmt.Sprintf("exit %d output %q", code, out))
	}
	if again, lerr := m.requireDiagLayout("(d) after the contraction", "ledger"); lerr != nil {
		return lerr
	} else if again != marker {
		return m.violate("marker_moved_by_contraction", fmt.Sprintf("marker index %d, then %d", marker, again))
	}
	if _, err = m.waitRuleBooks("(d) after the contraction", want, 0, func(_ uint64, s ruleStore) string {
		if !s.ledger || s.blobBooks != 0 || s.tableBooks != int(want) {
			return "ledger expected: " + s.summary()
		}
		return ""
	}); err != nil {
		return err
	}
	m.say("PHASE (d) ok: the contraction step answers (%q); the marker is still index %d on every voter", out, marker)
	return nil
}

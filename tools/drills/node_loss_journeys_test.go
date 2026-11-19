// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// 07.07#16: the real reference journeys run against the cluster AFTER it lost members and recovered. The criterion's text is the
// specification of these tests: the journeys' rows are those of the real run and all fifteen must pass; the journeys do not start
// before the recovery is proved (a lost acknowledged batch, a member that is not ready, diverging cursors and an open outage each
// stop the scenario); no journey leg may point at a member that is not answering and the reads must go through a member that was
// killed and restored; the acknowledgement ledger of the whole run must be complete.

func journeysObservedFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "smoke", "testdata", "journeys", "observed.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestJourneysAfterNodeLossRecoveryRowsMustAllPass(t *testing.T) {
	rows, err := dcJourneyRows(journeysObservedFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 15 {
		t.Fatalf("the recorded run has %d rows, want 15", len(rows))
	}
	checks := dcJourneyRowChecks(rows)
	if len(checks) != 15 {
		t.Fatalf("%d checks for 15 rows", len(checks))
	}
	for i, ch := range checks {
		if !ch.ok || ch.name != "journey_row_"+dcJourneyRowNames[i] {
			t.Errorf("check %d: %+v", i, ch)
		}
	}
	cases := []struct {
		name   string
		mutate func(rows []dcJourneyRow) []dcJourneyRow
		fails  string // the one check that must fail
	}{
		{"one row is not satisfied", func(r []dcJourneyRow) []dcJourneyRow {
			r[7].Satisfied, r[7].Reason = false, "cross_org_read_allowed"
			return r
		}, "journey_row_same_trace_in_wrong_org_denied"},
		{"a row is missing", func(r []dcJourneyRow) []dcJourneyRow { return slices.Delete(r, 3, 4) }, "journey_row_error_linked_to_request_trace"},
		{"a row is reported twice", func(r []dcJourneyRow) []dcJourneyRow { return append(r, r[0]) }, "journey_row_gateway_dependency_child_span"},
		{"a row is not required", func(r []dcJourneyRow) []dcJourneyRow {
			r[5].Required = false
			return r
		}, "journey_row_mapped_frame_at_known_location"},
		{"a row nobody expects", func(r []dcJourneyRow) []dcJourneyRow {
			return append(r, dcJourneyRow{Name: "an_easy_extra_row", Required: true, Satisfied: true, Reason: "ok"})
		}, "journey_row_unexpected"},
	}
	for _, c := range cases {
		mutated := c.mutate(slices.Clone(rows))
		var failing []string
		for _, ch := range dcJourneyRowChecks(mutated) {
			if !ch.ok {
				failing = append(failing, ch.name)
			}
		}
		if len(failing) != 1 || failing[0] != c.fails {
			t.Errorf("%s: failing checks %v, want exactly %s", c.name, failing, c.fails)
		}
	}
	none := dcJourneyRowChecks(nil)
	for _, ch := range none {
		if ch.ok {
			t.Errorf("a run without rows satisfied %s", ch.name)
		}
	}
	if _, err := dcJourneyRows([]byte(`not json`)); err == nil {
		t.Error("an observation that is not JSON decoded")
	}
}

// The drill cannot import the smoke (both are package main): the list of rows is kept equal to the smoke's by reading its source.
func TestJourneyRowNamesMatchTheSmokeAssertions(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "smoke", "journeys_assert.go"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range regexp.MustCompile(`(?m)^\s+row[A-Za-z]+\s+=\s+"([a-z_]+)"`).FindAllSubmatch(src, -1) {
		got = append(got, string(m[1]))
	}
	want := slices.Clone(dcJourneyRowNames)
	sort.Strings(got)
	sort.Strings(want)
	if !slices.Equal(got, want) {
		t.Fatalf("the smoke's rows %v\nthe drill's rows %v", got, want)
	}
}

// ---- the recovery gate ----

type journeyCluster struct {
	mu        sync.Mutex
	ids, up   []uint64
	notReady  map[uint64]error
	cursors   map[uint64]uint64
	cursorErr error
	stopErr   error
	startErr  error
	readyErr  error // waitReady after a start
	calls     []string
}

func (f *journeyCluster) members() []uint64 { return f.ids }
func (f *journeyCluster) live() []uint64    { return f.up }
func (f *journeyCluster) waitReady(id uint64, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf("ready %d", id))
	if err := f.notReady[id]; err != nil {
		return err
	}
	return f.readyErr
}
func (f *journeyCluster) converged(time.Duration) (map[uint64]uint64, error) {
	return f.cursors, f.cursorErr
}
func (f *journeyCluster) shutdown(id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf("stop %d", id))
	return f.stopErr
}
func (f *journeyCluster) start(id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, fmt.Sprintf("start %d", id))
	return f.startErr
}

func healthyCluster() *journeyCluster {
	return &journeyCluster{ids: []uint64{1, 2, 3}, up: []uint64{1, 2, 3}, cursors: map[uint64]uint64{1: 90, 2: 90, 3: 90}}
}

// recoveredReport is a report as it stands after two node losses that were recovered: three acknowledged batches (their data read
// back from the members is `retained`) and an outage timeline with its four failed attempts kept and closed.
func recoveredReport(t *testing.T) (*Report, map[string]string) {
	t.Helper()
	rep := &Report{Checks: []Check{}}
	retained := map[string]string{}
	for i, id := range []string{"a1", "a2", "a3"} {
		digest := dcDigest(id, uint64(i+1))
		if err := rep.Ledger().Record(Ack{ID: id, Group: "g", Index: uint64(i + 1), Digest: digest}); err != nil {
			t.Fatal(err)
		}
		retained[id] = digest
	}
	for _, victim := range []string{"member_1", "member_3"} {
		rep.Timeline().Fail(victim, "sigkill injected while the write stream was running")
		rep.Timeline().Fail(victim, "probe write to the down member was not acknowledged")
		rep.Timeline().Deliver("ingest", "the refused probe batch was retried unchanged and acknowledged")
		rep.Timeline().Deliver(victim, "the restored member acknowledged a fresh write")
		if err := rep.Timeline().Recover(victim); err != nil {
			t.Fatal(err)
		}
	}
	return rep, retained
}

func failedChecks(rep *Report) []string {
	var out []string
	for _, c := range rep.Checks {
		if !c.OK {
			out = append(out, c.Name)
		}
	}
	return out
}

func TestJourneysAfterNodeLossRecoveryDoNotStartBeforeTheClusterRecovered(t *testing.T) {
	victims := []uint64{1, 3}
	run := func(mutate func(f *journeyCluster, rep *Report, retained map[string]string)) (ran int, failed []string, err error) {
		f := healthyCluster()
		rep, retained := recoveredReport(t)
		mutate(f, rep, retained)
		err = dcJourneysAfterRecovery(f, rep, retained, victims, func() error { ran++; return nil })
		return ran, failedChecks(rep), err
	}
	ran, failed, err := run(func(*journeyCluster, *Report, map[string]string) {})
	if err != nil || ran != 1 || len(failed) != 0 {
		t.Fatalf("a recovered cluster: journeys ran %d times, err %v, failed %v", ran, err, failed)
	}
	for _, c := range []struct {
		name   string
		mutate func(f *journeyCluster, rep *Report, retained map[string]string)
		want   string
	}{
		{"an acknowledged batch is not on the members", func(_ *journeyCluster, _ *Report, r map[string]string) { delete(r, "a2") }, "recovered_every_acknowledged_id_reconciled"},
		{"an acknowledged batch is retained with other data", func(_ *journeyCluster, _ *Report, r map[string]string) { r["a3"] = dcDigest("a3", 99) }, "recovered_every_acknowledged_id_reconciled"},
		{"a member is not ready", func(f *journeyCluster, _ *Report, _ map[string]string) {
			f.notReady = map[uint64]error{3: errors.New("member_ready: timeout_starting")}
		}, "recovered_member_3_ready"},
		{"a member is down", func(f *journeyCluster, _ *Report, _ map[string]string) { f.up = []uint64{1, 2} }, "recovered_no_member_down"},
		{"the control cursors differ", func(f *journeyCluster, _ *Report, _ map[string]string) {
			f.cursors, f.cursorErr = nil, &dcFailure{Stage: "converge", Code: "applied_cursors_differ"}
		}, "recovered_applied_cursors_converged"},
		{"the outage is still open", func(_ *journeyCluster, rep *Report, _ map[string]string) {
			rep.Timeline().Fail("member_1", "a third loss that was never recovered")
		}, "recovered_outage_closed"},
	} {
		ran, failed, err := run(c.mutate)
		if err == nil || ran != 0 {
			t.Errorf("%s: err=%v, journeys ran %d times: the journeys must not run on a cluster that has not recovered", c.name, err, ran)
		}
		if !slices.Contains(failed, c.want) {
			t.Errorf("%s: failed checks %v, want %s among them", c.name, failed, c.want)
		}
	}
}

// ---- the attach document ----

func topologyOf(live ...uint64) dcJourneyTopology {
	t := dcJourneyTopology{Live: map[uint64]bool{}, Victims: []uint64{1, 3}}
	for _, id := range []uint64{1, 2, 3} {
		t.Members = append(t.Members, dcJourneyMember{ID: id, Address: fmt.Sprintf("127.0.0.1:%d", 41000+id), DataDir: fmt.Sprintf("/tmp/soundpost-drills/x/node-%d", id), NodeConfig: fmt.Sprintf("/tmp/soundpost-drills/x/node-%d.json", id)})
	}
	for _, id := range live {
		t.Live[id] = true
	}
	return t
}

func TestJourneysAfterNodeLossRecoveryRefuseLegsOnADeadOrUnrestoredMember(t *testing.T) {
	tlsFiles := &dcPublicTLS{ca: "/tmp/soundpost-drills/x/public-tls/ca.pem", cert: "/tmp/soundpost-drills/x/public-tls/leaf.pem", key: "/tmp/soundpost-drills/x/public-tls/leaf.key"}
	if _, err := dcJourneyAttachDocument(topologyOf(1, 2, 3), tlsFiles, "owner@drills.invalid", "pw", dcDefaultJourneyRoles); err != nil {
		t.Fatalf("a recovered cluster: %v", err)
	}
	for _, c := range []struct {
		name  string
		top   dcJourneyTopology
		roles dcJourneyRoles
	}{
		{"a member that is dead (not a role of any leg)", topologyOf(1, 3), dcDefaultJourneyRoles},
		{"the scan member is dead", topologyOf(2, 3), dcDefaultJourneyRoles},
		{"the gateway's member is dead", topologyOf(1, 2), dcJourneyRoles{Admin: 2, Gateway: 3, API: 2, Jobs: 1, Web: 3, Webbuild: 3, Scan: 1}},
		{"a leg names a member that is not in the cluster", topologyOf(1, 2, 3), dcJourneyRoles{Admin: 2, Gateway: 3, API: 9, Jobs: 1, Web: 3, Webbuild: 3, Scan: 1}},
		{"the reads would go through a member that never lost anything", topologyOf(1, 2, 3), dcJourneyRoles{Admin: 3, Gateway: 3, API: 2, Jobs: 1, Web: 3, Webbuild: 3, Scan: 2}},
	} {
		if _, err := dcJourneyAttachDocument(c.top, tlsFiles, "owner@drills.invalid", "pw", c.roles); err == nil {
			t.Errorf("%s: a document was made", c.name)
		}
	}
	small := topologyOf(1, 2, 3)
	small.Members = small.Members[:2]
	if _, err := dcJourneyAttachDocument(small, tlsFiles, "owner@drills.invalid", "pw", dcDefaultJourneyRoles); err == nil {
		t.Error("a document was made for a cluster of two")
	}
}

// keysOf is the structure of a JSON document: every path of object keys (arrays are walked through their first element).
func keysOf(prefix string, v any, out map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			out[prefix+"/"+k] = true
			keysOf(prefix+"/"+k, child, out)
		}
	case []any:
		if len(x) > 0 {
			keysOf(prefix+"[]", x[0], out)
		}
	}
}

// The smoke reads the document the drill writes. The two packages cannot share a type, so both are held to one committed sample
// (tools/smoke/testdata/journeys/attach.json, which the smoke's own test parses with its strict parser).
func TestJourneyAttachDocumentMatchesTheSmokeSchema(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("..", "smoke", "testdata", "journeys", "attach.json"))
	if err != nil {
		t.Fatal(err)
	}
	tlsFiles := &dcPublicTLS{ca: "/tmp/a/ca.pem", cert: "/tmp/a/leaf.pem", key: "/tmp/a/leaf.key"}
	doc, err := dcJourneyAttachDocument(topologyOf(1, 2, 3), tlsFiles, "owner@drills.invalid", "pw", dcDefaultJourneyRoles)
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	if err = json.Unmarshal(golden, &a); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(doc, &b); err != nil {
		t.Fatal(err)
	}
	ga, gb := map[string]bool{}, map[string]bool{}
	keysOf("", a, ga)
	keysOf("", b, gb)
	for k := range ga {
		if !gb[k] {
			t.Errorf("the sample has %s, the drill's document does not", k)
		}
	}
	for k := range gb {
		if !ga[k] {
			t.Errorf("the drill's document has %s, the sample does not", k)
		}
	}
	// And the drill's own roles are the ones the sample names.
	var sample struct {
		Roles map[string]uint64 `json:"roles"`
	}
	var mine struct {
		Roles map[string]uint64 `json:"roles"`
	}
	_ = json.Unmarshal(golden, &sample)
	_ = json.Unmarshal(doc, &mine)
	if !slices.Equal(keysSorted(sample.Roles), keysSorted(mine.Roles)) {
		t.Errorf("roles: sample %v, drill %v", sample.Roles, mine.Roles)
	}
}

func keysSorted(m map[string]uint64) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- the owner ----

type fakeWrites struct {
	beginErr, endErr error
	calls            []string
}

func (w *fakeWrites) begin() error { w.calls = append(w.calls, "begin"); return w.beginErr }
func (w *fakeWrites) end() error   { w.calls = append(w.calls, "end"); return w.endErr }

func newOwner(f *journeyCluster, w *fakeWrites) (*dcJourneyOwner, map[string]any) {
	facts := map[string]any{}
	return &dcJourneyOwner{host: f, wr: w, scan: 1, facts: func(k string, v any) { facts[k] = v }}, facts
}

func TestJourneysAfterNodeLossRecoveryOwnerFollowsTheJourneysInOrder(t *testing.T) {
	phase := func(name string) dcControlRequest { return dcControlRequest{Op: "phase", Name: name} }
	stop := func(id uint64) dcControlRequest { return dcControlRequest{Op: "stop_member", Member: id} }
	start := func(id uint64) dcControlRequest { return dcControlRequest{Op: "start_member", Member: id} }

	f, w := healthyCluster(), &fakeWrites{}
	o, facts := newOwner(f, w)
	for i, c := range []struct {
		req  dcControlRequest
		want string
	}{
		{stop(1), "out_of_order"},
		{phase("drive_end"), "out_of_order"},
		{phase("nonsense"), "unknown_phase"},
		{dcControlRequest{Op: "format_disk"}, "unknown_op"},
		{phase("drive_begin"), ""},
		{phase("drive_begin"), "out_of_order"},
		{stop(1), "out_of_order"},
		{phase("drive_end"), ""},
		{stop(2), "member_not_allowed"},
		{start(1), "out_of_order"},
		{stop(1), ""},
		{stop(1), "out_of_order"},
		{start(2), "member_not_allowed"},
		{start(1), ""},
		{start(1), "out_of_order"},
	} {
		if got := o.handle(c.req); got != c.want {
			t.Errorf("request %d %+v: code %q, want %q", i, c.req, got, c.want)
		}
	}
	if o.State() != dcOwnerScanRestored {
		t.Errorf("state %s", o.State())
	}
	if want := []string{"stop 1", "start 1", "ready 1"}; !slices.Equal(f.calls, want) {
		t.Errorf("the cluster was asked %v, want %v: nothing else may be stopped or started", f.calls, want)
	}
	if want := []string{"begin", "end"}; !slices.Equal(w.calls, want) {
		t.Errorf("writes %v", w.calls)
	}
	if _, ok := facts["journeys/scan_member_stop_ms"]; !ok {
		t.Error("the stop was not recorded")
	}
	if _, ok := facts["journeys/scan_member_ready_after_start_ms"]; !ok {
		t.Error("the restore was not recorded")
	}

	// A member that does not stop, a member that does not start, a member that starts but does not become ready, and writes that
	// failed are refused with their own closed codes and the state does not move past them.
	for _, c := range []struct {
		name  string
		setup func(f *journeyCluster, w *fakeWrites)
		steps []dcControlRequest
		want  string
		state string
	}{
		{"the stop fails", func(f *journeyCluster, _ *fakeWrites) { f.stopErr = errors.New("x") }, []dcControlRequest{phase("drive_begin"), phase("drive_end"), stop(1)}, "stop_failed", dcOwnerDriven},
		{"the start fails", func(f *journeyCluster, _ *fakeWrites) { f.startErr = errors.New("x") }, []dcControlRequest{phase("drive_begin"), phase("drive_end"), stop(1), start(1)}, "start_failed", dcOwnerScanStopped},
		{"the member does not become ready", func(f *journeyCluster, _ *fakeWrites) { f.readyErr = errors.New("timeout") }, []dcControlRequest{phase("drive_begin"), phase("drive_end"), stop(1), start(1)}, "not_ready_after_start", dcOwnerScanStopped},
		{"the concurrent writes could not start", func(_ *journeyCluster, w *fakeWrites) { w.beginErr = errors.New("x") }, []dcControlRequest{phase("drive_begin")}, "writes_not_started", dcOwnerNew},
		{"the concurrent writes failed", func(_ *journeyCluster, w *fakeWrites) { w.endErr = errors.New("x") }, []dcControlRequest{phase("drive_begin"), phase("drive_end")}, "writes_failed", dcOwnerDriven},
	} {
		f, w := healthyCluster(), &fakeWrites{}
		c.setup(f, w)
		o, _ := newOwner(f, w)
		got := ""
		for _, s := range c.steps {
			got = o.handle(s)
		}
		if got != c.want || o.State() != c.state {
			t.Errorf("%s: last code %q state %s, want %q and %s", c.name, got, o.State(), c.want, c.state)
		}
	}
}

func TestJourneyControlServerAnswersEveryLineAndRefusesGarbage(t *testing.T) {
	f, w := healthyCluster(), &fakeWrites{}
	o, _ := newOwner(f, w)
	in := strings.NewReader(`{"op":"phase","name":"drive_begin"}` + "\n" + `not json` + "\n" + `{"op":"phase","name":"drive_end","extra":1}` + "\n" + `{"op":"phase","name":"drive_end"}` + "\n")
	var out strings.Builder
	if err := dcServeJourneyControl(in, &out, o); err != nil {
		t.Fatal(err)
	}
	var codes []string
	sc := bufio.NewScanner(strings.NewReader(out.String()))
	for sc.Scan() {
		var a dcControlAnswer
		if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
			t.Fatal(err)
		}
		if a.OK != (a.Code == "") {
			t.Errorf("answer %+v is neither ok nor refused", a)
		}
		codes = append(codes, a.Code)
	}
	if want := []string{"", "malformed", "malformed", ""}; !slices.Equal(codes, want) {
		t.Errorf("codes %v, want %v", codes, want)
	}
}

// ---- what the SDKs delivered ----

func TestJourneysAfterNodeLossRecoveryEveryClientDeliveredWhatItSent(t *testing.T) {
	details := func(mutate func(m map[string]any)) []byte {
		ok := func(receipts int) map[string]any {
			return map[string]any{"pending": 0, "lost": 0, "receipts": receipts}
		}
		m := map[string]any{
			"gateway_flush":      ok(3),
			"api_flush":          ok(4),
			"order_driver_flush": ok(2),
			"jobs_output":        map[string]any{"run_id": "x", "flush": ok(5)},
			"replay_driver":      map[string]any{"replay": map[string]any{"flush": ok(1)}},
			"profile_driver":     map[string]any{"profile": map[string]any{"flush": ok(2)}},
		}
		mutate(m)
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	flushes, err := dcJourneyFlushes(details(func(map[string]any) {}))
	if err != nil {
		t.Fatal(err)
	}
	total, err := dcFlushVerdict(flushes)
	if err != nil || total != 17 || len(flushes) != 6 {
		t.Fatalf("all delivered: total %d clients %d err %v", total, len(flushes), err)
	}
	for _, c := range []struct {
		name   string
		mutate func(m map[string]any)
		decode bool // the details document itself is not complete
		accept bool // the delivery verdict holds
	}{
		{"the gateway has something pending", func(m map[string]any) { m["gateway_flush"] = map[string]any{"pending": 1, "lost": 0, "receipts": 3} }, false, false},
		{"the API lost a batch", func(m map[string]any) { m["api_flush"] = map[string]any{"pending": 0, "lost": 1, "receipts": 4} }, false, false},
		{"the job's final flush sent nothing more (its earlier batches had gone out)", func(m map[string]any) {
			m["jobs_output"] = map[string]any{"flush": map[string]any{"pending": 0, "lost": 0, "receipts": 0}}
		}, false, true},
		{"no client reports a receipt at all", func(m map[string]any) {
			zero := map[string]any{"pending": 0, "lost": 0, "receipts": 0}
			m["gateway_flush"], m["api_flush"], m["order_driver_flush"] = zero, zero, zero
			m["jobs_output"] = map[string]any{"flush": zero}
			m["replay_driver"] = map[string]any{"replay": map[string]any{"flush": zero}}
			m["profile_driver"] = map[string]any{"profile": map[string]any{"flush": zero}}
		}, false, false},
		{"the replay page reported nothing", func(m map[string]any) { delete(m, "replay_driver") }, true, false},
		{"the order page reported nothing", func(m map[string]any) { delete(m, "order_driver_flush") }, true, false},
	} {
		raw := details(c.mutate)
		fl, err := dcJourneyFlushes(raw)
		if c.decode {
			if err == nil {
				t.Errorf("%s: the document was accepted", c.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if _, err = dcFlushVerdict(fl); (err == nil) != c.accept {
			t.Errorf("%s: verdict error %v, accepted should be %v", c.name, err, c.accept)
		}
	}
}

// ---- the ledger of the whole run ----

func TestJourneysAfterNodeLossRecoveryLedgerCoversEveryPeriodOfTheRun(t *testing.T) {
	ack := func(id, label string) Ack { return Ack{ID: id, Group: "g", Index: 1, Digest: "d", Label: label} }
	acks := []Ack{ack("a", "kill_initial_leader_member_1"), ack("b", "kill_initial_leader_member_1_probe"), ack("c", "kill_member_3"), ack("d", "journeys_concurrent")}
	if err := dcAckPeriods(acks); err != nil {
		t.Fatalf("every period has acknowledgements: %v", err)
	}
	for name, without := range map[string]string{"before and during the first loss": "kill_initial_leader_member_1", "the second loss": "kill_member_3", "next to the journeys": "journeys_concurrent"} {
		var kept []Ack
		for _, a := range acks {
			if a.Label != without {
				kept = append(kept, a)
			}
		}
		if err := dcAckPeriods(kept); err == nil || !strings.Contains(err.Error(), without) {
			t.Errorf("no acknowledgements %s: %v", name, err)
		}
	}
}

// ---- the cluster pieces the scenario adds ----

func TestPublicTLSIsServedAndVerifiesForTheJourneys(t *testing.T) {
	p, err := dcNewPublicTLS(filepath.Join(t.TempDir(), "public-tls"))
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(p.cert, p.key)
	if err != nil {
		t.Fatalf("the leaf and its key do not belong together: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(p.caCert)
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "localhost", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Errorf("the leaf does not verify for localhost: %v", err)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "127.0.0.1", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Errorf("the leaf does not verify for 127.0.0.1: %v", err)
	}
	for _, path := range []string{p.ca, p.cert, p.key} {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", path, info, err)
		}
	}
}

func TestMemberServeArgsCarryThePublicTLSAndTheOperatorsFlags(t *testing.T) {
	c := &dcCluster{work: "/w", public: map[uint64]string{2: "127.0.0.1:2222"}, data: map[uint64]string{2: "/w/node-b"}, env: &Env{ServeArgs: []string{"--symbolicate-cgroup-root=/sys/fs/cgroup/x"}}}
	plain := strings.Join(c.serveArgs(2), " ")
	if strings.Contains(plain, "--tls-cert") || !strings.HasSuffix(plain, "--symbolicate-cgroup-root=/sys/fs/cgroup/x") {
		t.Errorf("without public TLS: %s", plain)
	}
	c.opts.public = &dcPublicTLS{cert: "/w/public-tls/leaf.pem", key: "/w/public-tls/leaf.key"}
	args := c.serveArgs(2)
	joined := strings.Join(args, " ")
	for _, want := range []string{"serve --mode=distributed --node-id 2", "--cluster-config /w/node-2.json", "--data-dir /w/node-b", "--listen 127.0.0.1:2222", "--tls-cert /w/public-tls/leaf.pem --tls-key /w/public-tls/leaf.key"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%q is missing from %s", want, joined)
		}
	}
	if args[len(args)-1] != "--symbolicate-cgroup-root=/sys/fs/cgroup/x" {
		t.Errorf("the operator's flags come last: %v", args)
	}
}

// shutdown is a clean stop, not a kill: the member must leave by itself with status 0 (a member the journeys stop for the scan).
func TestStopIsAShutdownThatExitsZero(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("drills run on Linux")
	}
	spawn := func(script string) *dcCluster {
		c := &dcCluster{procs: map[uint64]*dcProc{}, down: map[uint64]bool{}}
		cmd := exec.Command("sh", "-c", script)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		time.Sleep(200 * time.Millisecond) // the shell has installed its trap
		c.procs[1] = &dcProc{cmd: cmd, done: done}
		return c
	}
	c := spawn(`trap 'exit 0' TERM; while :; do sleep 0.1; done`)
	if err := c.shutdown(1); err != nil {
		t.Fatalf("a member that exits 0 on SIGTERM: %v", err)
	}
	if !c.down[1] || c.procs[1] != nil {
		t.Errorf("after the stop the member must be down and gone: down=%v proc=%v", c.down[1], c.procs[1])
	}
	c = spawn(`trap 'exit 3' TERM; while :; do sleep 0.1; done`)
	if err := c.shutdown(1); err == nil {
		t.Error("a member that exited 3 was taken for a clean stop")
	}
	c = spawn(`while :; do sleep 0.1; done`)
	if err := c.shutdown(1); err == nil {
		t.Error("a member killed by the signal itself was taken for a clean stop")
	}
}

// A host without the journeys' tools cannot exercise the scenario: the drill says so (not_run with the exact reason, as every drill
// that cannot run here does), it neither passes nor fails, and it starts nothing.
func TestJourneysScenarioWithoutTheJourneysToolsIsNotRun(t *testing.T) {
	m, err := LoadManifest(filepath.Join("..", "..", "drills", "scenarios.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		opts []ExecOption
	}{
		{"no smoke binary was given", nil},
		{"the smoke binary is not there", []ExecOption{WithJourneys(filepath.Join(t.TempDir(), "smoke"), nil)}},
	} {
		rep, err := Execute(t.Context(), m, "node-loss-journeys", "isolated", "../..", "/bin/true", t.TempDir(), c.opts...)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if rep.Status != StatusNotRun || !strings.Contains(rep.Reason, "--journeys-smoke") {
			t.Errorf("%s: status %s reason %q, want not_run naming --journeys-smoke", c.name, rep.Status, rep.Reason)
		}
		if len(rep.AckLedger) != 0 {
			t.Errorf("%s: a drill that did not run acknowledged %d batches", c.name, len(rep.AckLedger))
		}
	}
}

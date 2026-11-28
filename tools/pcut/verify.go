// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type check struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	Pass     bool   `json:"pass"`
	Detail   string `json:"detail"`
}

type recoveryReport struct {
	Healthy        bool              `json:"healthy"`
	WaitedSeconds  float64           `json:"waited_seconds"`
	RecoveredAt    string            `json:"recovered_at,omitempty"`
	Final          map[string]string `json:"final"`
	Leader         uint64            `json:"control_leader,omitempty"`
	Term           uint64            `json:"control_term,omitempty"`
	AppliedCursors map[string]string `json:"applied_cursors,omitempty"`
}

type journalReport struct {
	Path            string         `json:"path"`
	ChainIntact     bool           `json:"chain_intact"`
	TornTail        bool           `json:"torn_tail"`
	Ended           bool           `json:"generator_ended_cleanly"`
	EndInfo         any            `json:"generator_counters,omitempty"`
	Issued          int            `json:"issued"`
	Acked           int            `json:"acked"`
	Lost            int            `json:"issued_never_acked_given_up"`
	Rejected        int            `json:"rejected"`
	InFlightAtEnd   int            `json:"issued_without_ack_or_lost"`
	AckedByMember   map[string]int `json:"acked_by_member"`
	FirstIssue      string         `json:"first_issue"`
	LastAck         string         `json:"last_ack"`
	AckedAfterRecov int            `json:"acked_after_recovery"`
	IssuedBatches   int            `json:"issued_batches"`
	AckedBatches    int            `json:"acked_batches"`
}

type voterReport struct {
	Endpoint              string   `json:"endpoint"`
	ReadSeconds           float64  `json:"read_seconds"`
	ReadError             string   `json:"read_error,omitempty"`
	Series                int      `json:"series_with_data"`
	Samples               int      `json:"samples_retained"`
	Digest                string   `json:"digest_sha256"`
	AckedChecked          int      `json:"acked_checked"`
	AckedMissing          int      `json:"acked_missing"`
	MissingFirst          []string `json:"acked_missing_first,omitempty"`
	IssuedUnackedRetained int      `json:"issued_unacked_retained"`
	IssuedUnackedAbsent   int      `json:"issued_unacked_absent"`
	Duplicates            int      `json:"duplicate_records"`
	DuplicateTimestamps   int      `json:"duplicate_timestamps"`
	Unknown               int      `json:"unknown_or_torn_samples"`
	UnknownFirst          []string `json:"unknown_first,omitempty"`
	TimeMismatch          int      `json:"timestamp_mismatch"`
	PartialBatches        int      `json:"partially_retained_batches"`
}

type availability struct {
	Endpoint     string  `json:"endpoint"`
	Probes       int     `json:"probes"`
	QueryProbes  int     `json:"query_probes"`
	ReadyOK      int     `json:"ready_ok"`
	QueryOK      int     `json:"query_ok"`
	ReadyRatio   float64 `json:"ready_ratio"`
	QueryRatio   float64 `json:"query_ratio"`
	WorstQueryMs int64   `json:"worst_query_ms"`
}

type outageReport struct {
	Observed        bool           `json:"observed"`
	CutEndpoint     string         `json:"cut_endpoint"`
	LastReadyBefore string         `json:"cut_endpoint_last_ready_before,omitempty"`
	FirstFailure    string         `json:"cut_endpoint_first_failure,omitempty"`
	FirstReadyAfter string         `json:"cut_endpoint_first_ready_after,omitempty"`
	Seconds         float64        `json:"down_seconds"`
	GraceSeconds    float64        `json:"grace_seconds"`
	CutProbesInWin  int            `json:"cut_endpoint_probes_in_window"`
	CutReadyInWin   int            `json:"cut_endpoint_ready_in_window"`
	Others          []availability `json:"surviving_voters_after_grace"`
	OthersFull      []availability `json:"surviving_voters_whole_window"`
	AckedInWindow   int            `json:"acked_in_window"`
	AckedAfterGrace int            `json:"acked_in_window_after_grace"`
	AckedByMember   map[string]int `json:"acked_in_window_by_member"`
	MaxAckGapSec    float64        `json:"max_ack_gap_after_grace_seconds"`
	FirstAckAfter   float64        `json:"first_ack_after_first_failure_seconds"`
	ProbeLines      int            `json:"probe_lines"`
}

type report struct {
	Verdict    string         `json:"verdict"`
	Criterion  string         `json:"criterion"`
	StartedAt  string         `json:"started_at"`
	FinishedAt string         `json:"finished_at"`
	Note       string         `json:"note,omitempty"`
	Params     map[string]any `json:"params"`
	Checks     []check        `json:"checks"`
	Recovery   recoveryReport `json:"recovery"`
	Journal    journalReport  `json:"journal"`
	Voters     []voterReport  `json:"voters"`
	Outage     outageReport   `json:"outage"`
}

type key struct {
	w string
	n uint64
}

type issuedRec struct {
	id string
	ts int64
}

// batchRec is one issued batch: cnt records of series w, sequence numbers n.., observed 1 ms apart from ts.
type batchRec struct {
	w   string
	n   uint64
	cnt int
	ts  int64
}

type ackRec struct {
	at     int64
	member string
}

type sample struct {
	ts   int64
	bits uint64
}

func runVerify(args []string) error {
	fl := flag.NewFlagSet("verify", flag.ContinueOnError)
	fixturePath := fl.String("fixture", "", "fixture file written by bootstrap")
	journalPath := fl.String("journal", "", "the generator's ACK journal")
	probeLog := fl.String("probe-log", "", "the prober's log")
	outDir := fl.String("out", "", "directory for pcut-verdict.json")
	pidFile := fl.String("gen-pid-file", "", "the generator's pid file")
	stopFile := fl.String("stop-file", "", "the generator's stop file")
	cut := fl.String("cut", "", "name of the endpoint that was powered off (as named in the fixture)")
	waitRecovery := fl.Duration("wait-recovery", 20*time.Minute, "how long to wait for every voter to be ready with one control leader")
	postRecovery := fl.Duration("post-recovery", 60*time.Second, "how long the load keeps running after the recovery before it is stopped")
	drainWait := fl.Duration("drain-wait", 12*time.Minute, "how long to wait for the generator to drain and exit after the stop request")
	converge := fl.Duration("converge", 8*time.Minute, "how long the voters may take to show identical data")
	minOutage := fl.Duration("min-outage", 90*time.Second, "shortest outage of the cut voter that counts as the power cut")
	grace := fl.Duration("grace", 30*time.Second, "after the cut: time the survivors may need to elect new leaders before availability is judged")
	maxGap := fl.Duration("max-ack-gap", 30*time.Second, "longest tolerated gap between acknowledgements during the outage (after the grace)")
	minAvail := fl.Float64("min-availability", 0.9, "least fraction of probes in the outage window a surviving voter must be ready and serve a complete read")
	note := fl.String("note", "", "free text recorded in the verdict")
	rehearsal := fl.Bool("rehearsal", false, "dry run on a live cluster: do not wait for recovery, do not stop the generator, judge only records older than 30 s, write pcut-verdict-rehearsal.json")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *fixturePath == "" || *journalPath == "" || *probeLog == "" || *outDir == "" || *pidFile == "" || *stopFile == "" || *cut == "" {
		return errors.New("usage: pcut verify --fixture F --journal J --probe-log L --out DIR --gen-pid-file P --stop-file S --cut NAME [...]")
	}
	fx, err := loadFixture(*fixturePath)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	rep := &report{Criterion: "07.07#7 hypervisor power cut of one voter under load: every ACKed record readable after recovery, the 2 survivors keep serving, the cut voter catches up", StartedAt: time.Now().UTC().Format(time.RFC3339), Note: *note,
		Params: map[string]any{"cut": *cut, "wait_recovery": waitRecovery.String(), "post_recovery": postRecovery.String(), "drain_wait": drainWait.String(), "converge": converge.String(), "min_outage": minOutage.String(), "grace": grace.String(), "max_ack_gap": maxGap.String(), "min_availability": *minAvail}}
	add := func(name string, required, pass bool, detail string) {
		rep.Checks = append(rep.Checks, check{Name: name, Required: required, Pass: pass, Detail: detail})
	}
	verdictFile := "pcut-verdict.json"
	if *rehearsal {
		verdictFile = "pcut-verdict-rehearsal.json"
		rep.Note = strings.TrimSpace("REHEARSAL (load still running, no cut) " + rep.Note)
	}
	finish := func() error { return finishVerify(rep, *outDir, verdictFile) }
	type vendpoint struct {
		ep Endpoint
		s  *site
		rd *reader
	}
	var eps []vendpoint
	for _, ep := range fx.Endpoints {
		s, err := newSite(ep.Name, ep.URL, fx.CA, true)
		if err != nil {
			return err
		}
		eps = append(eps, vendpoint{ep, s, newReader(s, fx)})
	}

	// 1. every voter back, one control leader
	t0 := time.Now()
	var recoveredAt time.Time
	for {
		final := map[string]string{}
		ready := map[string]readyz{}
		healthy := true
		for _, e := range eps {
			r := e.s.readyz(3 * time.Second)
			ready[e.ep.Name] = r
			desc := fmt.Sprintf("code=%d ready=%v reason=%s role=%s leader=%d term=%d err=%s", r.Code, r.Ready, r.Reason, r.Role, r.Leader, r.Term, r.Err)
			final[e.ep.Name] = desc
			if r.Code != 200 || !r.Ready {
				healthy = false
			}
		}
		var leader, term uint64
		leaders := 0
		if healthy {
			for _, e := range eps {
				r := ready[e.ep.Name]
				if leader == 0 {
					leader, term = r.Leader, r.Term
				}
				if r.Leader == 0 || r.Leader != leader || r.Term != term {
					healthy = false
				}
				if r.Role == "leader" {
					leaders++
					if r.Leader != e.ep.ID {
						healthy = false
					}
				}
			}
			if leaders != 1 {
				healthy = false
			}
		}
		rep.Recovery = recoveryReport{Healthy: healthy, WaitedSeconds: time.Since(t0).Seconds(), Final: final, Leader: leader, Term: term}
		if healthy {
			recoveredAt = time.Now()
			rep.Recovery.RecoveredAt = recoveredAt.UTC().Format(time.RFC3339)
			break
		}
		if time.Since(t0) > *waitRecovery {
			break
		}
		time.Sleep(2 * time.Second)
	}
	add("membership_healthy", true, rep.Recovery.Healthy, fmt.Sprintf("every voter /readyz 200 ready, one control leader, the same term; waited %.0fs", rep.Recovery.WaitedSeconds))

	// 2. keep the load running a little after the recovery, then stop and drain the generator
	if !*rehearsal {
		if rep.Recovery.Healthy && *postRecovery > 0 {
			time.Sleep(*postRecovery)
		}
		if err = os.WriteFile(*stopFile, []byte("stop\n"), 0o644); err != nil {
			return err
		}
		drained := waitProcessGone(*pidFile, *drainWait)
		add("generator_drained", true, drained, "the generator resent every in-flight batch until acknowledged and exited within "+drainWait.String())
	}

	// 3. the journal
	jr, err := readJournal(*journalPath)
	if err != nil {
		add("journal_intact", true, false, err.Error())
		return finish()
	}
	issued := map[key]issuedRec{}
	acked := map[key]ackRec{}
	batches := map[string]batchRec{}
	ackedBatches := map[string]bool{}
	var ackTimes []ackRec
	jrep := journalReport{Path: *journalPath, ChainIntact: true, TornTail: jr.TornTail, AckedByMember: map[string]int{}}
	var firstIssue, lastAck int64
	ms := int64(time.Millisecond)
	for _, e := range jr.Entries {
		cnt := max(1, e.Cnt)
		switch e.T {
		case "issue":
			batches[e.ID] = batchRec{w: e.W, n: e.N, cnt: cnt, ts: e.Ts}
			for i := range cnt {
				issued[key{e.W, e.N + uint64(i)}] = issuedRec{e.ID, e.Ts + int64(i)*ms}
			}
			if firstIssue == 0 || e.Ts < firstIssue {
				firstIssue = e.Ts
			}
		case "ack":
			if ackedBatches[e.ID] {
				add("journal_no_double_ack", true, false, fmt.Sprintf("batch %s acknowledged twice in the journal", e.ID))
			}
			ackedBatches[e.ID] = true
			for i := range cnt {
				acked[key{e.W, e.N + uint64(i)}] = ackRec{e.At, e.Member}
			}
			ackTimes = append(ackTimes, ackRec{e.At, e.Member})
			jrep.AckedByMember[e.Member]++
			if e.At > lastAck {
				lastAck = e.At
			}
			if !recoveredAt.IsZero() && e.At > recoveredAt.UnixNano() {
				jrep.AckedAfterRecov++
			}
		case "lost":
			jrep.Lost++
		case "reject":
			jrep.Rejected++
		case "end":
			jrep.Ended = true
			var info any
			_ = json.Unmarshal(e.Info, &info)
			jrep.EndInfo = info
		}
	}
	jrep.Issued, jrep.Acked = len(issued), len(acked)
	jrep.IssuedBatches, jrep.AckedBatches = len(batches), len(ackedBatches)
	jrep.InFlightAtEnd = max(0, jrep.IssuedBatches-jrep.AckedBatches-jrep.Lost-jrep.Rejected)
	if firstIssue > 0 {
		jrep.FirstIssue = time.Unix(0, firstIssue).UTC().Format(time.RFC3339)
	}
	if lastAck > 0 {
		jrep.LastAck = time.Unix(0, lastAck).UTC().Format(time.RFC3339)
	}
	rep.Journal = jrep
	add("journal_intact", true, jrep.ChainIntact && (jrep.Ended || *rehearsal) && !jrep.TornTail, fmt.Sprintf("hash chain intact, generator ended cleanly=%v, torn tail=%v; %d batches (%d records) issued, %d batches (%d records) acknowledged", jrep.Ended, jrep.TornTail, jrep.IssuedBatches, jrep.Issued, jrep.AckedBatches, jrep.Acked))
	add("generator_no_rejects", true, jrep.Rejected == 0, fmt.Sprintf("%d batches were answered with a non-retryable refusal", jrep.Rejected))
	add("some_acks_to_verify", true, jrep.Acked > 0, fmt.Sprintf("%d acknowledged records in the journal", jrep.Acked))
	// A rehearsal runs against a live load: only batches that ended at least 30 s ago are judged; the newer ones are left out of
	// the journal view AND skipped when a voter's samples are read.
	var skip map[key]bool
	if *rehearsal {
		cutoff := time.Now().Add(-30 * time.Second).UnixNano()
		skip = map[key]bool{}
		for id, b := range batches {
			if b.ts+int64(b.cnt)*ms >= cutoff {
				for i := range b.cnt {
					k := key{b.w, b.n + uint64(i)}
					delete(issued, k)
					delete(acked, k)
					skip[k] = true
				}
				delete(batches, id)
			}
		}
	}

	// 4. read every series of every voter until the voters show identical data (or the limit passes)
	windowMin := 60
	if firstIssue > 0 {
		windowMin = int(math.Ceil(time.Since(time.Unix(0, firstIssue)).Minutes())) + 15
	}
	deadline := time.Now().Add(*converge)
	var voters []voterReport
	for {
		voters = make([]voterReport, len(eps))
		var wg sync.WaitGroup
		for i, e := range eps {
			wg.Add(1)
			go func() {
				defer wg.Done()
				voters[i] = readVoter(e.ep.Name, e.rd, fx.Series, windowMin, skip, issued, acked, batches)
			}()
		}
		wg.Wait()
		same, clean := true, true
		for _, v := range voters {
			if v.ReadError != "" || v.Digest != voters[0].Digest {
				same = false
			}
			if v.AckedMissing != 0 {
				clean = false
			}
		}
		if (same && clean) || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Second)
	}
	rep.Voters = voters
	rep.Checks = append(rep.Checks, voterChecks(voters, *cut)...)
	cursors := map[string]string{}
	cursorsEqual := true
	for _, e := range eps {
		r := e.s.readyz(3 * time.Second)
		cursors[e.ep.Name] = r.Applied
		if r.Applied == "" || r.Applied != cursors[eps[0].ep.Name] {
			cursorsEqual = false
		}
	}
	rep.Recovery.AppliedCursors = cursors
	add("control_applied_cursors_equal", false, cursorsEqual, fmt.Sprintf("%v", cursors))

	// 5. the outage, from the prober's log and the journal
	rep.Outage = analyzeOutage(*probeLog, *cut, ackTimes, *minOutage, *grace)
	rep.Checks = append(rep.Checks, outageChecks(rep.Outage, *cut, *minOutage, *grace, *maxGap, *minAvail)...)
	add("acked_after_recovery", false, rep.Journal.AckedAfterRecov > 0, fmt.Sprintf("%d acknowledgements after every voter was ready again", rep.Journal.AckedAfterRecov))
	return finish()
}

func ifs(cond bool, s string) string {
	if cond {
		return s
	}
	return ""
}

func finishVerify(rep *report, outDir, file string) error {
	rep.Verdict = "PASS"
	for _, c := range rep.Checks {
		if c.Required && !c.Pass {
			rep.Verdict = "FAIL"
		}
	}
	rep.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(outDir, file), append(raw, '\n'), 0o644); err != nil {
		return err
	}
	for _, c := range rep.Checks {
		mark := "ok  "
		if !c.Pass {
			mark = "FAIL"
			if !c.Required {
				mark = "warn"
			}
		}
		fmt.Printf("%s %-52s %s\n", mark, c.Name, c.Detail)
	}
	fmt.Printf("VERDICT %s -> %s\n", rep.Verdict, filepath.Join(outDir, file))
	if rep.Verdict != "PASS" {
		return errors.New("power cut verdict is FAIL")
	}
	return nil
}

// voterChecks judges what every voter retains: nothing acknowledged missing, no duplicate, no torn or foreign sample, identical data on all
// voters, and the cut voter among them.
func voterChecks(voters []voterReport, cut string) []check {
	var cs []check
	add := func(name string, pass bool, detail string) {
		cs = append(cs, check{Name: name, Required: true, Pass: pass, Detail: detail})
	}
	var digests []string
	for _, v := range voters {
		digests = append(digests, fmt.Sprintf("%s=%s(%d samples)", v.Endpoint, v.Digest[:min(16, len(v.Digest))], v.Samples))
		add("acked_all_readable_on_"+v.Endpoint, v.ReadError == "" && v.AckedMissing == 0, fmt.Sprintf("%d acknowledged records checked, %d missing%s", v.AckedChecked, v.AckedMissing, ifs(v.ReadError != "", ", read error: "+v.ReadError)))
		add("no_duplicate_records_on_"+v.Endpoint, v.ReadError == "" && v.Duplicates == 0 && v.DuplicateTimestamps == 0, fmt.Sprintf("%d records stored more than once, %d series timestamps stored twice", v.Duplicates, v.DuplicateTimestamps))
		add("no_torn_or_unknown_records_on_"+v.Endpoint, v.ReadError == "" && v.Unknown == 0 && v.TimeMismatch == 0 && v.PartialBatches == 0, fmt.Sprintf("%d samples that are no issued record (garbage, torn or foreign), %d with a changed observed time, %d batches retained only in part", v.Unknown, v.TimeMismatch, v.PartialBatches))
	}
	equal := len(voters) > 0
	for _, v := range voters {
		if v.ReadError != "" || v.Digest != voters[0].Digest {
			equal = false
		}
	}
	add("voters_digests_equal", equal, strings.Join(digests, " "))
	for _, v := range voters {
		if v.Endpoint == cut {
			add("cut_voter_caught_up", equal && v.AckedMissing == 0 && v.ReadError == "", fmt.Sprintf("%s retains %d samples, digest equal to the other voters=%v", v.Endpoint, v.Samples, equal))
		}
	}
	return cs
}

// outageChecks judges the outage the probe log and the journal show.
func outageChecks(o outageReport, cut string, minOutage, grace, maxGap time.Duration, minAvail float64) []check {
	var cs []check
	add := func(name string, pass bool, detail string) {
		cs = append(cs, check{Name: name, Required: true, Pass: pass, Detail: detail})
	}
	add("outage_observed", o.Observed, fmt.Sprintf("%s stopped answering for %.0fs (need at least %s)", cut, o.Seconds, minOutage))
	if !o.Observed {
		return cs
	}
	survivors, worstReady, worstQuery := 0, 1.0, 1.0
	for _, a := range o.Others {
		survivors++
		worstReady, worstQuery = math.Min(worstReady, a.ReadyRatio), math.Min(worstQuery, a.QueryRatio)
	}
	add("survivors_ready_and_reading_during_outage", survivors >= 2 && worstReady >= minAvail && worstQuery >= minAvail, fmt.Sprintf("%d surviving voters probed; after %s grace the worst ready ratio %.3f and the worst complete-read ratio %.3f (need %.2f)", survivors, grace, worstReady, worstQuery, minAvail))
	add("cluster_acknowledged_writes_during_outage", o.AckedInWindow > 0 && o.MaxAckGapSec <= maxGap.Seconds(), fmt.Sprintf("%d acknowledgements during the outage (%d after the grace), longest gap after the grace %.1fs (limit %s), first one %.1fs after the first failed probe", o.AckedInWindow, o.AckedAfterGrace, o.MaxAckGapSec, maxGap, o.FirstAckAfter))
	add("cut_voter_really_down", o.CutReadyInWin == 0, fmt.Sprintf("%d of %d probes of %s inside the window were ready", o.CutReadyInWin, o.CutProbesInWin, cut))
	return cs
}

// waitProcessGone waits until the process named in pidFile no longer exists (or the file is gone).
func waitProcessGone(pidFile string, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for {
		raw, err := os.ReadFile(pidFile)
		if err != nil {
			return true
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil || !processAlive(pid) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Second)
	}
}

// readVoter reads every series of one voter as a matrix over the whole run and judges it against the journal.
func readVoter(name string, rd *reader, series []string, windowMin int, skip map[key]bool, issued map[key]issuedRec, acked map[key]ackRec, batches map[string]batchRec) (v voterReport) {
	v = voterReport{Endpoint: name}
	start := time.Now()
	defer func() { v.ReadSeconds = time.Since(start).Seconds() }()
	if err := rd.login(10 * time.Second); err != nil {
		v.ReadError = err.Error()
		return v
	}
	data, err := readAll(rd, series, windowMin)
	if err != nil {
		v.ReadError = err.Error()
		return v
	}
	return judgeSamples(name, series, data, skip, issued, acked, batches)
}

// judgeSamples judges the samples one voter retains against the journal; it does no I/O.
func judgeSamples(name string, series []string, data map[string][]sample, skip map[key]bool, issued map[key]issuedRec, acked map[key]ackRec, batches map[string]batchRec) (v voterReport) {
	v = voterReport{Endpoint: name}
	seen := map[key]int{}
	var lines []string
	for _, w := range series {
		samples := data[w]
		if len(samples) > 0 {
			v.Series++
		}
		stamps := map[int64]int{}
		for _, s := range samples {
			f := math.Float64frombits(s.bits)
			garbage := f < 1 || f != math.Trunc(f) || f > 1<<53
			var k key
			if !garbage {
				k = key{w, uint64(f)}
				if skip[k] {
					continue
				}
			}
			v.Samples++
			lines = append(lines, w+"\x00"+strconv.FormatInt(s.ts, 10)+"\x00"+strconv.FormatUint(s.bits, 16))
			stamps[s.ts]++
			if garbage {
				v.Unknown++
				if len(v.UnknownFirst) < 10 {
					v.UnknownFirst = append(v.UnknownFirst, fmt.Sprintf("%s ts=%d bits=%016x", w, s.ts, s.bits))
				}
				continue
			}
			rec, ok := issued[k]
			if !ok {
				v.Unknown++
				if len(v.UnknownFirst) < 10 {
					v.UnknownFirst = append(v.UnknownFirst, fmt.Sprintf("%s n=%d ts=%d (never issued)", w, k.n, s.ts))
				}
				continue
			}
			if rec.ts != s.ts {
				v.TimeMismatch++
			}
			seen[k]++
		}
		for _, c := range stamps {
			if c > 1 {
				v.DuplicateTimestamps += c - 1
			}
		}
	}
	for _, c := range seen {
		if c > 1 {
			v.Duplicates += c - 1
		}
	}
	for k, a := range acked {
		v.AckedChecked++
		if seen[k] == 0 {
			v.AckedMissing++
			if len(v.MissingFirst) < 20 {
				v.MissingFirst = append(v.MissingFirst, fmt.Sprintf("%s n=%d id=%s member=%s acked_at=%s", k.w, k.n, issued[k].id, a.member, time.Unix(0, a.at).UTC().Format("15:04:05.000")))
			}
		}
	}
	for k := range issued {
		if _, ok := acked[k]; ok {
			continue
		}
		if seen[k] > 0 {
			v.IssuedUnackedRetained++
		} else {
			v.IssuedUnackedAbsent++
		}
	}
	// a batch is atomic: all of its records are retained or none of them
	for id, b := range batches {
		got := 0
		for i := range b.cnt {
			if seen[key{b.w, b.n + uint64(i)}] > 0 {
				got++
			}
		}
		if got > 0 && got < b.cnt {
			v.PartialBatches++
			if len(v.UnknownFirst) < 10 {
				v.UnknownFirst = append(v.UnknownFirst, fmt.Sprintf("batch %s retained %d of %d records", id, got, b.cnt))
			}
		}
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		io.WriteString(h, l)
		h.Write([]byte{'\n'})
	}
	v.Digest = hex.EncodeToString(h.Sum(nil))
	return v
}

// readAll returns every retained sample of every series of one voter: one query for the whole metric, or, when that fails (the
// answer is too big for the service's budget), one query per series, two at a time (the service admits two concurrent queries per
// principal).
func readAll(rd *reader, series []string, windowMin int) (map[string][]sample, error) {
	out, err := readMatrix(rd, fmt.Sprintf(`%s[%dm]`, metricName, windowMin), series)
	if err == nil {
		return out, nil
	}
	out = map[string][]sample{}
	var mu sync.Mutex
	var firstErr error
	var wg sync.WaitGroup
	sem := make(chan struct{}, 2)
	for _, w := range series {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			m, err := readMatrix(rd, fmt.Sprintf(`%s{%s=%q}[%dm]`, metricName, seriesLabel, w, windowMin), []string{w})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("series %s: %w", w, err)
				}
				return
			}
			out[w] = m[w]
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return nil, fmt.Errorf("whole-metric read: %v; per-series read: %w", err, firstErr)
	}
	return out, nil
}

// readMatrix runs one range-selector query (a complete answer or an error) and returns its samples by series label.
func readMatrix(rd *reader, expr string, allowed []string) (map[string][]sample, error) {
	allow := map[string]bool{}
	for _, w := range allowed {
		allow[w] = true
	}
	var lastErr error
	for try := 0; try < 3; try++ {
		if try > 0 {
			time.Sleep(2 * time.Second)
		}
		status, raw, err := rd.query(expr, time.Now().Add(time.Minute), 60*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		val, err := completeValue(status, raw)
		if err != nil {
			lastErr = err
			continue
		}
		out := map[string][]sample{}
		for _, s := range val.Matrix {
			w := ""
			for _, l := range s.Labels {
				switch l.Name {
				case seriesLabel:
					w = l.Value
				case "__name__":
				default:
					return nil, fmt.Errorf("unexpected label %s", safeToken(l.Name))
				}
			}
			if !allow[w] {
				return nil, fmt.Errorf("answer for unknown series %q", w)
			}
			if _, dup := out[w]; dup {
				return nil, fmt.Errorf("series %s answered twice", w)
			}
			samples := make([]sample, 0, len(s.Samples))
			for _, p := range s.Samples {
				if p.Float == nil {
					return nil, errors.New("sample is not a float")
				}
				samples = append(samples, sample{int64(p.Time), uint64(*p.Float)})
			}
			out[w] = samples
		}
		return out, nil
	}
	return nil, lastErr
}

// analyzeOutage finds the longest run of failed readiness probes of the cut voter in the probe log (the power cut and the boot)
// and judges the surviving voters and the acknowledgements inside it.
func analyzeOutage(path, cut string, acks []ackRec, minOutage, grace time.Duration) outageReport {
	o := outageReport{CutEndpoint: cut, GraceSeconds: grace.Seconds(), AckedByMember: map[string]int{}}
	f, err := os.Open(path)
	if err != nil {
		return o
	}
	defer f.Close()
	byEp := map[string][]probeLine{}
	rd := bufio.NewReaderSize(f, 1<<20)
	for {
		line, err := rd.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			var l probeLine
			if json.Unmarshal(line, &l) == nil && l.Ep != "" {
				byEp[l.Ep] = append(byEp[l.Ep], l)
				o.ProbeLines++
			}
		}
		if err != nil {
			break
		}
	}
	for _, ls := range byEp {
		sort.Slice(ls, func(i, j int) bool { return ls[i].T < ls[j].T })
	}
	var cl []probeLine // readiness lines of the cut voter
	for _, l := range byEp[cut] {
		if !l.Q {
			cl = append(cl, l)
		}
	}
	up := func(l probeLine) bool { return l.Code == 200 && l.Ready }
	type run struct{ lastOK, first, after int64 }
	var best run
	var cur *run
	var lastOK int64
	for _, l := range cl {
		if up(l) {
			if cur != nil {
				cur.after = l.T
				if cur.after-cur.first > best.after-best.first {
					best = *cur
				}
				cur = nil
			}
			lastOK = l.T
			continue
		}
		if cur == nil {
			cur = &run{lastOK: lastOK, first: l.T}
		}
	}
	if cur != nil { // never came back inside the log
		cur.after = cl[len(cl)-1].T
		if cur.after-cur.first > best.after-best.first {
			best = *cur
		}
	}
	if best.first == 0 || time.Duration(best.after-best.first)*time.Millisecond < 10*time.Second {
		return o
	}
	o.Seconds = float64(best.after-best.first) / 1000
	o.Observed = time.Duration(best.after-best.first)*time.Millisecond >= minOutage && cur == nil
	stamp := func(ms int64) string {
		if ms == 0 {
			return ""
		}
		return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
	}
	o.LastReadyBefore, o.FirstFailure, o.FirstReadyAfter = stamp(best.lastOK), stamp(best.first), stamp(best.after)
	lo, hi := best.first, best.after
	glo := lo + grace.Milliseconds()
	for _, l := range cl {
		if l.T >= lo && l.T < hi {
			o.CutProbesInWin++
			if up(l) {
				o.CutReadyInWin++
			}
		}
	}
	avail := func(from int64) []availability {
		var out []availability
		names := make([]string, 0, len(byEp))
		for n := range byEp {
			if n != cut {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		for _, n := range names {
			a := availability{Endpoint: n}
			for _, l := range byEp[n] {
				if l.T < from || l.T >= hi {
					continue
				}
				if l.Q {
					a.QueryProbes++
					if l.QOK {
						a.QueryOK++
					}
					if l.QMs > a.WorstQueryMs {
						a.WorstQueryMs = l.QMs
					}
					continue
				}
				a.Probes++
				if up(l) {
					a.ReadyOK++
				}
			}
			if a.Probes > 0 {
				a.ReadyRatio = float64(a.ReadyOK) / float64(a.Probes)
			}
			if a.QueryProbes > 0 {
				a.QueryRatio = float64(a.QueryOK) / float64(a.QueryProbes)
			}
			out = append(out, a)
		}
		return out
	}
	o.Others, o.OthersFull = avail(glo), avail(lo)
	var inWin []int64
	first := int64(math.MaxInt64)
	for _, a := range acks {
		ms := a.at / 1e6
		if ms >= lo && ms < hi {
			o.AckedInWindow++
			o.AckedByMember[a.member]++
			if ms < first {
				first = ms
			}
			if ms >= glo {
				o.AckedAfterGrace++
				inWin = append(inWin, ms)
			}
		}
	}
	if first != math.MaxInt64 {
		o.FirstAckAfter = float64(first-lo) / 1000
	}
	sort.Slice(inWin, func(i, j int) bool { return inWin[i] < inWin[j] })
	prev, maxGap := glo, int64(0)
	for _, ms := range inWin {
		maxGap = max(maxGap, ms-prev)
		prev = ms
	}
	maxGap = max(maxGap, hi-prev)
	o.MaxAckGapSec = float64(maxGap) / 1000
	return o
}

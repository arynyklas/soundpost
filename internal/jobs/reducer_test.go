// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package jobs_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
	"time"

	"soundpost/internal/jobs"
	"soundpost/internal/model"
)

var (
	jobID   = model.ID{1}
	runA    = model.ID{2}
	att1    = model.ID{3}
	att2    = model.ID{4}
	epoch   = model.ID{9}
	observe = model.ID{7}
	march1  = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
)

func ns(t time.Time) model.UnixNano { return model.UnixNano(t.UnixNano()) }

// hm is an instant on 2026-03-01 UTC.
func hm(h, m, s int) model.UnixNano {
	return ns(march1.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + time.Duration(s)*time.Second))
}

func ev(run, attempt model.ID, schedule string, ordinal, seq uint64, state string, observed model.UnixNano, terminal *model.UnixNano) model.JobAttemptEvent {
	return model.JobAttemptEvent{Job: jobID, Run: run, Attempt: attempt, Schedule: schedule, Ordinal: model.Uint64(ordinal), Epoch: epoch, Sequence: model.Uint64(seq), State: state, Observed: observed, Terminal: terminal}
}

func code(err error) model.Code {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fault.Code
	}
	return ""
}

func mustReduce(t *testing.T, st jobs.JobState, e model.JobAttemptEvent) jobs.JobState {
	t.Helper()
	next, err := jobs.Reduce(st, e)
	if err != nil {
		t.Fatalf("reduce %+v: %v", e, err)
	}
	return next
}
func mustObserve(t *testing.T, st jobs.JobState, e jobs.ScheduleEvidence) jobs.JobState {
	t.Helper()
	next, _, err := jobs.Observe(st, e)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	return next
}

func hasReason(h jobs.Health, r jobs.Reason) bool {
	for _, have := range h.Reasons {
		if have == r {
			return true
		}
	}
	return false
}

// -------------------------------------------------------------- attempts

func TestJobRetryPreservesHistory(t *testing.T) {
	t.Run("retry recovers run and current health but attempt one stays failed", func(t *testing.T) {
		st := jobs.JobState{}
		st = mustReduce(t, st, ev(runA, att1, "manual.a", 1, 1, "started", hm(1, 0, 0), nil))
		st = mustReduce(t, st, ev(runA, att1, "manual.a", 1, 2, "failed", hm(1, 0, 0), new(hm(1, 0, 10))))
		if st.CurrentHealth.Status != jobs.StatusFailed || st.Runs[runA].Status != jobs.RunFailed {
			t.Fatalf("failed attempt: health %q run %q", st.CurrentHealth.Status, st.Runs[runA].Status)
		}
		original := st.Attempts[att1]
		st = mustReduce(t, st, ev(runA, att2, "manual.a", 2, 3, "started", hm(1, 0, 30), nil))
		if st.CurrentHealth.Status != jobs.StatusRunning || !hasReason(st.CurrentHealth, jobs.ReasonRetryInProgress) {
			t.Fatalf("retry in progress: %+v", st.CurrentHealth)
		}
		st = mustReduce(t, st, ev(runA, att2, "manual.a", 2, 4, "succeeded", hm(1, 0, 30), new(hm(1, 0, 40))))
		if st.Runs[runA].Status != jobs.RunRecovered || !st.Runs[runA].Recovered || st.Runs[runA].Final != att2 {
			t.Fatalf("run not recovered: %+v", st.Runs[runA])
		}
		if st.CurrentHealth.Status != jobs.StatusSucceeded || !hasReason(st.CurrentHealth, jobs.ReasonRunRecovered) || !st.CurrentHealth.Complete {
			t.Fatalf("health not recovered: %+v", st.CurrentHealth)
		}
		if got := st.Attempts[att1]; !reflect.DeepEqual(got, original) || got.Effective() != jobs.AttemptFailed || got.Terminal.State != jobs.AttemptFailed {
			t.Fatalf("attempt one rewritten: %+v", got)
		}
		if len(st.Attempts) != 2 || len(st.Runs[runA].Attempts) != 2 {
			t.Fatalf("attempt count %d/%d", len(st.Attempts), len(st.Runs[runA].Attempts))
		}
		if st.CurrentHealth.Evidence.AttemptCount != 2 || *st.CurrentHealth.Evidence.Attempt != att2 || *st.CurrentHealth.Evidence.Run != runA {
			t.Fatalf("evidence does not name the attempts used: %+v", st.CurrentHealth.Evidence)
		}
	})

	t.Run("late failure of an older schedule cannot overwrite a newer schedule's health", func(t *testing.T) {
		key1 := jobs.OccurrenceKey("UTC", hm(1, 0, 0), 0)
		key2 := jobs.OccurrenceKey("UTC", hm(2, 0, 0), 0)
		run1, run2 := model.ID{21}, model.ID{22}
		st := jobs.JobState{}
		st = mustReduce(t, st, ev(run2, att2, key2, 1, 1, "started", hm(2, 0, 1), nil))
		st = mustReduce(t, st, ev(run2, att2, key2, 1, 2, "succeeded", hm(2, 0, 1), new(hm(2, 0, 5))))
		if st.CurrentHealth.Status != jobs.StatusSucceeded {
			t.Fatal("newer schedule success not healthy")
		}
		st = mustReduce(t, st, ev(run1, att1, key1, 1, 1, "failed", hm(1, 0, 1), new(hm(1, 0, 9))))
		if st.CurrentHealth.Status != jobs.StatusSucceeded || st.CurrentHealth.Evidence.Occurrence != key2 || st.LatestScheduleKey != key2 {
			t.Fatalf("late old failure overwrote newer health: %+v latest %q", st.CurrentHealth, st.LatestScheduleKey)
		}
		if st.Attempts[att1].Effective() != jobs.AttemptFailed || st.Runs[run1].Status != jobs.RunFailed {
			t.Fatal("late old failure was dropped from history")
		}
	})

	t.Run("conflicting result for the same terminal version is rejected and changes nothing", func(t *testing.T) {
		st := mustReduce(t, jobs.JobState{}, ev(runA, att1, "manual.a", 1, 1, "failed", hm(1, 0, 0), new(hm(1, 0, 10))))
		for name, conflicting := range map[string]model.JobAttemptEvent{
			"other result":        ev(runA, att1, "manual.a", 1, 2, "succeeded", hm(1, 0, 0), new(hm(1, 0, 10))),
			"other terminal time": ev(runA, att1, "manual.a", 1, 3, "failed", hm(1, 0, 0), new(hm(1, 0, 11))),
			"same seq other body": ev(runA, att1, "manual.a", 1, 1, "cancelled", hm(1, 0, 0), new(hm(1, 0, 10))),
			"other start time":    ev(runA, att1, "manual.a", 1, 4, "started", hm(1, 0, 1), nil),
			"other ordinal":       ev(runA, att1, "manual.a", 2, 5, "failed", hm(1, 0, 0), new(hm(1, 0, 10))),
			"other run":           ev(model.ID{55}, att1, "manual.a", 1, 6, "failed", hm(1, 0, 0), new(hm(1, 0, 10))),
			"other occurrence":    ev(runA, att1, "manual.b", 1, 7, "failed", hm(1, 0, 0), new(hm(1, 0, 10))),
		} {
			next, err := jobs.Reduce(st, conflicting)
			if code(err) != model.Conflict {
				t.Fatalf("%s: want conflict, got %v", name, err)
			}
			if !reflect.DeepEqual(next, st) {
				t.Fatalf("%s: rejected event changed state", name)
			}
		}
		// The identical result re-sent from another producer epoch is idempotent.
		again := ev(runA, att1, "manual.a", 1, 9, "failed", hm(1, 0, 0), new(hm(1, 0, 10)))
		again.Epoch = model.ID{10}
		next, outcome, err := jobs.ReduceEvent(st, again)
		if err != nil || outcome != jobs.Applied || next.Attempts[att1].Terminal.State != jobs.AttemptFailed || len(next.Attempts) != 1 {
			t.Fatalf("identical terminal resend: %v %v", outcome, err)
		}
	})

	t.Run("cancellation stays cancelled and is not success", func(t *testing.T) {
		st := mustReduce(t, jobs.JobState{}, ev(runA, att1, "manual.a", 1, 1, "started", hm(1, 0, 0), nil))
		st = mustReduce(t, st, ev(runA, att1, "manual.a", 1, 2, "cancelled", hm(1, 0, 0), new(hm(1, 0, 4))))
		if st.CurrentHealth.Status != jobs.StatusCancelled || st.Runs[runA].Status != jobs.RunCancelled || st.CurrentHealth.Status == jobs.StatusSucceeded {
			t.Fatalf("cancelled became %+v", st.CurrentHealth)
		}
		next, err := jobs.Reduce(st, ev(runA, att1, "manual.a", 1, 3, "succeeded", hm(1, 0, 0), new(hm(1, 0, 5))))
		if code(err) != model.Conflict || next.Attempts[att1].Effective() != jobs.AttemptCancelled {
			t.Fatalf("cancelled attempt became success: %v", err)
		}
	})

	t.Run("overlapping runs are allowed and both retained", func(t *testing.T) {
		runB := model.ID{23}
		st := mustReduce(t, jobs.JobState{}, ev(runA, att1, "manual.a", 1, 1, "started", hm(1, 0, 0), nil))
		st = mustReduce(t, st, ev(runB, att2, "manual.b", 1, 2, "started", hm(1, 0, 1), nil))
		st = mustReduce(t, st, ev(runA, att1, "manual.a", 1, 3, "succeeded", hm(1, 0, 0), new(hm(1, 0, 30))))
		if len(st.Runs) != 2 || st.Runs[runA].Status != jobs.RunSucceeded || st.Runs[runB].Status != jobs.RunRunning {
			t.Fatalf("overlap dropped or merged a run: %+v", st.Runs)
		}
		// The newer started run is the current one; it is not erased by the older success.
		if st.CurrentHealth.Status != jobs.StatusRunning || *st.CurrentHealth.Evidence.Run != runB {
			t.Fatalf("overlap health %+v", st.CurrentHealth)
		}
		if _, _, err := jobs.Observe(jobs.JobState{}, jobs.ScheduleEvidence{Job: jobID, Observer: observe, ObservedAt: hm(1, 0, 0), CompleteThrough: hm(1, 0, 0), Healthy: true, Definition: &jobs.Definition{Revision: 1, EffectiveFrom: hm(0, 0, 0), Overlap: "forbid"}}); code(err) != model.Unsupported {
			t.Fatalf("unimplemented overlap policy accepted: %v", err)
		}
	})
}

func TestJobEventValidation(t *testing.T) {
	good := ev(runA, att1, "manual.a", 1, 1, "failed", hm(1, 0, 0), new(hm(1, 0, 1)))
	for name, mutate := range map[string]func(*model.JobAttemptEvent){
		"zero run":              func(e *model.JobAttemptEvent) { e.Run = model.ID{} },
		"zero attempt":          func(e *model.JobAttemptEvent) { e.Attempt = model.ID{} },
		"zero epoch":            func(e *model.JobAttemptEvent) { e.Epoch = model.ID{} },
		"zero ordinal":          func(e *model.JobAttemptEvent) { e.Ordinal = 0 },
		"unsafe schedule":       func(e *model.JobAttemptEvent) { e.Schedule = "unsafe/path" },
		"empty schedule":        func(e *model.JobAttemptEvent) { e.Schedule = "" },
		"terminal before start": func(e *model.JobAttemptEvent) { e.Terminal = new(hm(0, 59, 0)) },
		"terminal missing":      func(e *model.JobAttemptEvent) { e.Terminal = nil },
		"unknown state":         func(e *model.JobAttemptEvent) { e.State = "paused" },
		"nonpositive start":     func(e *model.JobAttemptEvent) { e.Observed = 0; e.Terminal = new(model.UnixNano(5)) },
	} {
		bad := good
		mutate(&bad)
		if _, err := jobs.Reduce(jobs.JobState{}, bad); code(err) != model.Invalid {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	started := ev(runA, att1, "manual.a", 1, 1, "started", hm(1, 0, 0), new(hm(1, 0, 1)))
	if _, err := jobs.Reduce(jobs.JobState{}, started); code(err) != model.Invalid {
		t.Errorf("started with terminal time accepted: %v", err)
	}
	st := mustReduce(t, jobs.JobState{}, good)
	other := good
	other.Job = model.ID{99}
	if _, err := jobs.Reduce(st, other); code(err) != model.Invalid {
		t.Errorf("event for another job folded into this job: %v", err)
	}
}

// applyAll folds events in order and returns the final state, failing on error.
func applyAll(t *testing.T, events []model.JobAttemptEvent) jobs.JobState {
	t.Helper()
	st := jobs.JobState{}
	for _, e := range events {
		st = mustReduce(t, st, e)
	}
	return st
}

func permutations(n int, visit func([]int)) {
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	var rec func(k int)
	rec = func(k int) {
		if k == n {
			visit(append([]int(nil), idx...))
			return
		}
		for i := k; i < n; i++ {
			idx[k], idx[i] = idx[i], idx[k]
			rec(k + 1)
			idx[k], idx[i] = idx[i], idx[k]
		}
	}
	rec(0)
}

func TestJobAttemptsAreOrderIndependentAndIdempotent(t *testing.T) {
	events := []model.JobAttemptEvent{
		ev(runA, att1, "manual.a", 1, 1, "started", hm(1, 0, 0), nil),
		ev(runA, att1, "manual.a", 1, 2, "failed", hm(1, 0, 0), new(hm(1, 0, 10))),
		ev(runA, att2, "manual.a", 2, 3, "started", hm(1, 0, 30), nil),
		ev(runA, att2, "manual.a", 2, 4, "succeeded", hm(1, 0, 30), new(hm(1, 0, 40))),
	}
	reference := applyAll(t, events)
	permutations(len(events), func(order []int) {
		var shuffled []model.JobAttemptEvent
		for _, i := range order {
			shuffled = append(shuffled, events[i])
		}
		// Re-deliver every event twice, interleaved: duplicates change nothing.
		st := jobs.JobState{}
		for _, e := range shuffled {
			st = mustReduce(t, st, e)
			again, outcome, err := jobs.ReduceEvent(st, e)
			if err != nil || outcome != jobs.Duplicate || !reflect.DeepEqual(again, st) {
				t.Fatalf("order %v: redelivery of %+v was not an exact no-op: %v %v", order, e, outcome, err)
			}
		}
		if !reflect.DeepEqual(st, reference) {
			t.Fatalf("order %v reached a different state:\n%+v\nwant\n%+v", order, st, reference)
		}
	})
	if reference.CurrentHealth.Status != jobs.StatusSucceeded || reference.Runs[runA].Status != jobs.RunRecovered || len(reference.Attempts) != 2 {
		t.Fatalf("reference state wrong: %+v", reference.CurrentHealth)
	}
}

// monotone checks the immutability contract between two consecutive states.
func monotone(t *testing.T, before, after jobs.JobState) {
	t.Helper()
	if after.Version < before.Version {
		t.Fatalf("version went backwards %d -> %d", before.Version, after.Version)
	}
	if after.Compaction.Runs < before.Compaction.Runs {
		t.Fatal("compaction counter went backwards")
	}
	for id, was := range before.Attempts {
		now, ok := after.Attempts[id]
		if !ok {
			if after.Compaction.Runs == before.Compaction.Runs {
				t.Fatalf("attempt %v vanished without compaction", id)
			}
			continue
		}
		if was.Terminal != nil && (now.Terminal == nil || *now.Terminal != *was.Terminal) {
			t.Fatalf("terminal result of %v rewritten: %+v -> %+v", id, was.Terminal, now.Terminal)
		}
		if was.Started && !now.Started || len(now.Events) < len(was.Events) || now.Observed != was.Observed || now.Run != was.Run || now.Ordinal != was.Ordinal {
			t.Fatalf("attempt %v lost facts", id)
		}
	}
	for id, was := range before.Runs {
		if now, ok := after.Runs[id]; ok && len(now.Attempts) < len(was.Attempts) {
			t.Fatalf("run %v lost attempts", id)
		}
	}
}

// randomJournal builds consistent (non-conflicting) events for several runs and
// attempts, then duplicates and shuffles them.
func randomJournal(r *rand.Rand, runs int) []model.JobAttemptEvent {
	var out []model.JobAttemptEvent
	seq := uint64(0)
	for ri := range runs {
		run := model.ID{100, byte(ri)}
		key := "manual." + string(rune('a'+ri))
		if r.IntN(2) == 0 {
			key = jobsKey(hm(ri+1, 0, 0))
		}
		attempts := 1 + r.IntN(3)
		for ai := range attempts {
			attempt := model.ID{200, byte(ri), byte(ai)}
			start := hm(ri+1, ai*5, 1)
			seq++
			out = append(out, ev(run, attempt, key, uint64(ai+1), seq, "started", start, nil))
			if r.IntN(5) > 0 {
				seq++
				state := []string{"succeeded", "failed", "cancelled"}[r.IntN(3)]
				out = append(out, ev(run, attempt, key, uint64(ai+1), seq, state, start, new(start+model.UnixNano(1+r.IntN(1000)))))
				if r.IntN(4) == 0 { // same fact from a restarted producer: new sequence, identical content
					seq++
					dup := out[len(out)-1]
					dup.Sequence = model.Uint64(seq)
					out = append(out, dup)
				}
			}
		}
	}
	for n := r.IntN(len(out)); n > 0; n-- {
		out = append(out, out[r.IntN(len(out))]) // exact redeliveries
	}
	r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}
func jobsKey(at model.UnixNano) string { return jobs.OccurrenceKey("UTC", at, 0) }

func TestJobHistoryIsMonotoneAndOrderIndependentProperty(t *testing.T) {
	for seed := int64(1); seed <= 60; seed++ {
		r := rand.New(rand.NewPCG(uint64(seed), 1))
		journal := randomJournal(r, 1+r.IntN(5))
		st := jobs.JobState{}
		for _, e := range journal {
			next, _, err := jobs.ReduceEvent(st, e)
			if err != nil {
				t.Fatalf("seed %d: consistent journal rejected: %v", seed, err)
			}
			monotone(t, st, next)
			st = next
		}
		// A second, independently shuffled delivery reaches the same state: apart
		// from the version, which counts accepted changes and is order-free too.
		r2 := rand.New(rand.NewPCG(uint64(seed), 2))
		other := append([]model.JobAttemptEvent(nil), journal...)
		r2.Shuffle(len(other), func(i, j int) { other[i], other[j] = other[j], other[i] })
		st2 := applyAll(t, other)
		if !reflect.DeepEqual(st, st2) {
			t.Fatalf("seed %d: delivery order changed the state:\n%+v\n%+v", seed, st.CurrentHealth, st2.CurrentHealth)
		}
		// Applying the whole journal again changes nothing.
		for _, e := range journal {
			again, outcome, err := jobs.ReduceEvent(st, e)
			if err != nil || outcome != jobs.Duplicate || !reflect.DeepEqual(again, st) {
				t.Fatalf("seed %d: replay not idempotent (%v, %v)", seed, outcome, err)
			}
		}
		// No duplicate attempts: every attempt is listed by exactly one run once.
		seen := map[model.ID]int{}
		for _, run := range st.Runs {
			for _, a := range run.Attempts {
				seen[a]++
			}
		}
		for id := range st.Attempts {
			if seen[id] != 1 {
				t.Fatalf("seed %d: attempt %v listed %d times", seed, id, seen[id])
			}
		}
	}
}

func TestJobStateIsBoundedAndCompactionIsExplicit(t *testing.T) {
	st := jobs.JobState{}
	total := jobs.MaxRetainedRuns + 5
	for i := 1; i <= total; i++ {
		run, attempt := model.ID{50, byte(i >> 8), byte(i)}, model.ID{60, byte(i >> 8), byte(i)}
		st = mustReduce(t, st, ev(run, attempt, jobsKey(hm(0, 0, i)), 1, uint64(i), "succeeded", hm(0, 0, i), new(hm(0, 0, i)+1)))
	}
	if len(st.Runs) != jobs.MaxRetainedRuns || len(st.Attempts) != jobs.MaxRetainedRuns || st.Compaction.Runs != 5 {
		t.Fatalf("state not bounded or compaction not explicit: %d runs %d attempts compaction %+v", len(st.Runs), len(st.Attempts), st.Compaction)
	}
	if st.Compaction.Through != hm(0, 0, 5) {
		t.Fatalf("compaction frontier %v", st.Compaction.Through)
	}
	if _, ok := st.Runs[model.ID{50, 0, 1}]; ok {
		t.Fatal("oldest run still retained")
	}
	if st.CurrentHealth.Status != jobs.StatusSucceeded || st.LatestScheduleKey != jobsKey(hm(0, 0, total)) {
		t.Fatalf("newest verdict lost by compaction: %+v", st.CurrentHealth)
	}
	// Evidence for a run that already left the window cannot change anything.
	late := ev(model.ID{50, 0, 1}, model.ID{60, 0, 1}, jobsKey(hm(0, 0, 1)), 1, 99, "failed", hm(0, 0, 1), new(hm(0, 0, 1)+1))
	next, outcome, err := jobs.ReduceEvent(st, late)
	if err != nil || outcome != jobs.Ignored || !reflect.DeepEqual(next, st) {
		t.Fatalf("late evidence beyond the window: %v %v", outcome, err)
	}
}

func TestJobStateSurvivesJSONPersistence(t *testing.T) {
	st := jobs.JobState{Org: model.ID{70}, Project: model.ID{71}, Job: jobID}
	st = mustObserve(t, st, jobs.ScheduleEvidence{Job: jobID, Project: model.ID{71}, Observer: observe, ObservedAt: hm(12, 3, 0), CompleteThrough: hm(12, 3, 0), Healthy: true,
		Definition: &jobs.Definition{Revision: 1, EffectiveFrom: hm(0, 0, 0), Schedule: &jobs.Schedule{Cron: "0 * * * *", Timezone: "UTC"}, MaxRuntime: jobs.Duration(time.Hour)},
		Incomplete: []jobs.Interval{{ID: model.ID{80}, Start: hm(3, 0, 0), End: hm(4, 0, 0), Reason: "source_loss"}}})
	st = mustReduce(t, st, ev(runA, att1, jobsKey(hm(11, 0, 0)), 1, 1, "failed", hm(11, 0, 1), new(hm(11, 0, 9))))
	if st, _, _ = mustCorrect(t, st); st.Attempts[att1].Corrections == nil {
		t.Fatal("correction missing")
	}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"version":"`)) || !bytes.Contains(raw, []byte(`"grace_ns":"300000000000"`)) {
		t.Fatalf("wire integers are not exact decimal strings: %s", raw)
	}
	var back jobs.JobState
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	again, err := json.Marshal(back)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatalf("round trip differs: %v", err)
	}
	if got := jobs.Evaluate(back, hm(12, 3, 0)); !reflect.DeepEqual(got, jobs.Evaluate(st, hm(12, 3, 0))) {
		t.Fatal("persisted state derives a different verdict")
	}
}

func mustCorrect(t *testing.T, st jobs.JobState) (jobs.JobState, jobs.Outcome, error) {
	t.Helper()
	next, outcome, err := jobs.ApplyCorrection(st, jobs.Correction{CommandID: model.ID{1, 1}, Attempt: att1, Version: 1, State: jobs.AttemptSucceeded, Reason: "operator verified output"}, model.ID{5}, hm(13, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	return next, outcome, err
}

// ----------------------------------------------------------- corrections

func TestJobCorrectionsAreAuditedNewerAndNeverRewriteTheOriginal(t *testing.T) {
	actor := model.ID{5}
	st := mustReduce(t, jobs.JobState{}, ev(runA, att1, "manual.a", 1, 1, "failed", hm(1, 0, 0), new(hm(1, 0, 10))))
	original := st.Attempts[att1].Terminal
	fix := func(version uint64, state jobs.AttemptState, reason string) jobs.Correction {
		return jobs.Correction{CommandID: model.NewID(), Attempt: att1, Version: model.Uint64(version), State: state, Reason: reason}
	}
	corrected, outcome, err := jobs.ApplyCorrection(st, fix(1, jobs.AttemptSucceeded, "verified by the data owner"), actor, hm(2, 0, 0))
	if err != nil || outcome != jobs.Applied {
		t.Fatal(err)
	}
	a := corrected.Attempts[att1]
	if a.Terminal.State != jobs.AttemptFailed || a.Terminal != original && *a.Terminal != *original {
		t.Fatal("original terminal event was rewritten")
	}
	if a.Effective() != jobs.AttemptSucceeded || len(a.Corrections) != 1 || a.Corrections[0].Actor != actor || a.Corrections[0].At != hm(2, 0, 0) || a.Corrections[0].Reason != "verified by the data owner" {
		t.Fatalf("correction not audited: %+v", a.Corrections)
	}
	if corrected.CurrentHealth.Status != jobs.StatusSucceeded || !hasReason(corrected.CurrentHealth, jobs.ReasonCorrected) || corrected.Runs[runA].Status != jobs.RunSucceeded {
		t.Fatalf("corrected health: %+v", corrected.CurrentHealth)
	}
	if st.Attempts[att1].Corrections != nil {
		t.Fatal("input state mutated")
	}

	// Same version same content: idempotent. Same version different content: conflict.
	same := fix(1, jobs.AttemptSucceeded, "verified by the data owner")
	if _, outcome, err := jobs.ApplyCorrection(corrected, same, actor, hm(3, 0, 0)); err != nil || outcome != jobs.Duplicate {
		t.Fatalf("identical correction not idempotent: %v %v", outcome, err)
	}
	if _, _, err := jobs.ApplyCorrection(corrected, fix(1, jobs.AttemptCancelled, "verified by the data owner"), actor, hm(3, 0, 0)); code(err) != model.Conflict {
		t.Fatalf("same version other content: %v", err)
	}
	// A newer explicit version supersedes, an older one cannot.
	newer, _, err := jobs.ApplyCorrection(corrected, fix(3, jobs.AttemptCancelled, "retracted: job was stopped"), actor, hm(4, 0, 0))
	if err != nil || newer.Attempts[att1].Effective() != jobs.AttemptCancelled || len(newer.Attempts[att1].Corrections) != 2 || newer.Attempts[att1].Corrections[0].State != jobs.AttemptSucceeded {
		t.Fatalf("newer correction: %v", err)
	}
	if _, _, err := jobs.ApplyCorrection(newer, fix(2, jobs.AttemptSucceeded, "late stale correction"), actor, hm(5, 0, 0)); code(err) != model.Conflict {
		t.Fatalf("older correction version accepted: %v", err)
	}
	// Shape and target errors.
	for name, bad := range map[string]jobs.Correction{
		"version zero":  fix(0, jobs.AttemptSucceeded, "x"),
		"started state": fix(9, jobs.AttemptStarted, "x"),
		"empty reason":  fix(9, jobs.AttemptSucceeded, "  "),
		"control chars": fix(9, jobs.AttemptSucceeded, "line\x00break"),
		"oversize":      fix(9, jobs.AttemptSucceeded, strings.Repeat("r", jobs.MaxReasonBytes+1)),
		"no command id": {Attempt: att1, Version: 9, State: jobs.AttemptSucceeded, Reason: "x"},
	} {
		if _, _, err := jobs.ApplyCorrection(corrected, bad, actor, hm(5, 0, 0)); code(err) != model.Invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	missing := fix(1, jobs.AttemptSucceeded, "x")
	missing.Attempt = model.ID{99}
	if _, _, err := jobs.ApplyCorrection(corrected, missing, actor, hm(5, 0, 0)); code(err) != model.NotFound {
		t.Fatalf("unknown attempt: %v", err)
	}
	running := mustReduce(t, jobs.JobState{}, ev(runA, att1, "manual.a", 1, 1, "started", hm(1, 0, 0), nil))
	if _, _, err := jobs.ApplyCorrection(running, fix(1, jobs.AttemptSucceeded, "x"), actor, hm(5, 0, 0)); code(err) != model.Conflict {
		t.Fatalf("correcting a non-terminal attempt: %v", err)
	}
	if _, _, err := jobs.ApplyCorrection(corrected, fix(7, jobs.AttemptSucceeded, "x"), model.ID{}, hm(5, 0, 0)); code(err) != model.Invalid {
		t.Fatalf("correction without an actor: %v", err)
	}
	// A late duplicate terminal event after a correction is still judged against the original.
	if _, err := jobs.Reduce(corrected, ev(runA, att1, "manual.a", 1, 2, "succeeded", hm(1, 0, 0), new(hm(1, 0, 10)))); code(err) != model.Conflict {
		t.Fatalf("event contradicting the original terminal accepted after correction: %v", err)
	}
}

// -------------------------------------------------------------- schedules

func utc(y int, mo time.Month, d, h, mi int) model.UnixNano {
	return ns(time.Date(y, mo, d, h, mi, 0, 0, time.UTC))
}
func hourly() jobs.Definition {
	return jobs.Definition{Revision: 1, EffectiveFrom: hm(0, 0, 0), Schedule: &jobs.Schedule{Cron: "0 * * * *", Timezone: "UTC"}}
}

// observed folds one observer observation (optionally carrying a definition).
func observed(t *testing.T, st jobs.JobState, at, through model.UnixNano, healthy bool, def *jobs.Definition, gaps ...jobs.Interval) jobs.JobState {
	t.Helper()
	return mustObserve(t, st, jobs.ScheduleEvidence{Job: jobID, Observer: observe, ObservedAt: at, CompleteThrough: through, Healthy: healthy, Definition: def, Incomplete: gaps})
}

func runOf(t *testing.T, st jobs.JobState, run, attempt model.ID, key string, ordinal uint64, state string, start, end model.UnixNano) jobs.JobState {
	t.Helper()
	st = mustReduce(t, st, ev(run, attempt, key, ordinal, uint64(len(st.Attempts)*2+1), "started", start, nil))
	if state == "started" {
		return st
	}
	return mustReduce(t, st, ev(run, attempt, key, ordinal, uint64(len(st.Attempts)*2+2), state, start, new(end)))
}

func TestScheduleExpectedOccurrencesAcrossDST(t *testing.T) {
	type want struct {
		at   model.UnixNano
		fold uint8
	}
	run := func(t *testing.T, zone, cron string, from, through model.UnixNano) jobs.ExpectedWindow {
		t.Helper()
		w, err := jobs.ExpectedOccurrences(jobs.Definition{Schedule: &jobs.Schedule{Cron: cron, Timezone: zone}}, from, through, 1000)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	check := func(t *testing.T, w jobs.ExpectedWindow, wants []want, skipped []string) {
		t.Helper()
		if len(w.Runs) != len(wants) {
			t.Fatalf("got %d occurrences %+v, want %d", len(w.Runs), w.Runs, len(wants))
		}
		for i, e := range wants {
			if w.Runs[i].At != e.at || w.Runs[i].Fold != e.fold {
				t.Fatalf("occurrence %d = %v fold %d (%s), want %v fold %d", i, time.Unix(0, int64(w.Runs[i].At)).UTC(), w.Runs[i].Fold, w.Runs[i].Local, time.Unix(0, int64(e.at)).UTC(), e.fold)
			}
		}
		var got []string
		for _, s := range w.Skipped {
			got = append(got, s.Local)
		}
		if !reflect.DeepEqual(got, skipped) {
			t.Fatalf("skipped %v, want %v", got, skipped)
		}
	}
	t.Run("spring forward skips the nonexistent local time with evidence", func(t *testing.T) {
		w := run(t, "America/New_York", "30 2 * * *", utc(2026, 3, 7, 0, 0), utc(2026, 3, 10, 0, 0))
		check(t, w, []want{{utc(2026, 3, 7, 7, 30), 0}, {utc(2026, 3, 9, 6, 30), 0}}, []string{"2026-03-08T02:30"})
	})
	t.Run("fall back runs once per distinct UTC instant", func(t *testing.T) {
		w := run(t, "America/New_York", "30 1 * * *", utc(2026, 10, 31, 0, 0), utc(2026, 11, 3, 0, 0))
		check(t, w, []want{{utc(2026, 10, 31, 5, 30), 0}, {utc(2026, 11, 1, 5, 30), 0}, {utc(2026, 11, 1, 6, 30), 1}, {utc(2026, 11, 2, 6, 30), 0}}, nil)
		if w.Runs[1].Key == w.Runs[2].Key || w.Runs[1].Local != w.Runs[2].Local {
			t.Fatal("the two instants of one local time must share a wall time but not a key")
		}
	})
	t.Run("hourly schedule has 23 occurrences on the spring day and 25 on the fall day", func(t *testing.T) {
		spring := run(t, "America/New_York", "0 * * * *", utc(2026, 3, 8, 5, 0)-1, utc(2026, 3, 9, 4, 0)-1)
		if len(spring.Runs) != 23 || len(spring.Skipped) != 1 || spring.Skipped[0].Local != "2026-03-08T02:00" {
			t.Fatalf("spring day: %d runs skipped %+v", len(spring.Runs), spring.Skipped)
		}
		fall := run(t, "America/New_York", "0 * * * *", utc(2026, 11, 1, 4, 0)-1, utc(2026, 11, 2, 5, 0)-1)
		keys := map[string]bool{}
		for _, r := range fall.Runs {
			keys[r.Key] = true
		}
		if len(fall.Runs) != 25 || len(keys) != 25 || len(fall.Skipped) != 0 {
			t.Fatalf("fall day: %d runs %d keys", len(fall.Runs), len(keys))
		}
	})
	t.Run("London gap", func(t *testing.T) {
		w := run(t, "Europe/London", "30 1 * * *", utc(2026, 3, 27, 0, 0), utc(2026, 3, 31, 12, 0))
		check(t, w, []want{{utc(2026, 3, 27, 1, 30), 0}, {utc(2026, 3, 28, 1, 30), 0}, {utc(2026, 3, 30, 0, 30), 0}, {utc(2026, 3, 31, 0, 30), 0}}, []string{"2026-03-29T01:30"})
	})
	t.Run("a half hour DST shift folds half an hour apart", func(t *testing.T) {
		w := run(t, "Australia/Lord_Howe", "45 1 * * *", utc(2026, 4, 3, 0, 0), utc(2026, 4, 7, 0, 0))
		var fold []jobs.Expected
		for _, r := range w.Runs {
			if r.Local == "2026-04-05T01:45" {
				fold = append(fold, r)
			}
		}
		if len(fold) != 2 || fold[0].Fold != 0 || fold[1].Fold != 1 || time.Duration(fold[1].At-fold[0].At) != 30*time.Minute {
			t.Fatalf("Lord Howe fold: %+v", fold)
		}
	})
	t.Run("occurrence keys round trip and stay in the SDK alphabet", func(t *testing.T) {
		w := run(t, "America/New_York", "30 1 * * *", utc(2026, 10, 31, 0, 0), utc(2026, 11, 3, 0, 0))
		tags := map[string]bool{}
		for _, r := range w.Runs {
			at, fold, tag, ok := jobs.ParseOccurrenceKey(r.Key)
			if !ok || at != r.At || fold != r.Fold || len(r.Key) > 256 || strings.Trim(r.Key, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != "" {
				t.Fatalf("key %q does not round trip", r.Key)
			}
			tags[tag] = true
		}
		other := jobs.OccurrenceKey("Europe/London", w.Runs[0].At, 0)
		if _, _, tag, _ := jobs.ParseOccurrenceKey(other); len(tags) != 1 || tags[tag] {
			t.Fatal("time zone is not part of the occurrence identity")
		}
		for _, manual := range []string{"manual.abc", "schedule", "s.x.f0.deadbeef", "s.5.f2.deadbeef", "s.05.f0.deadbeef", "s.5.f0.DEADBEEF"} {
			if _, _, _, ok := jobs.ParseOccurrenceKey(manual); ok {
				t.Fatalf("%q parsed as a scheduled occurrence", manual)
			}
		}
	})
}

func TestScheduleCronGrammar(t *testing.T) {
	count := func(cron string, from, through model.UnixNano) int {
		w, err := jobs.ExpectedOccurrences(jobs.Definition{Schedule: &jobs.Schedule{Cron: cron, Timezone: "UTC"}}, from, through, 10000)
		if err != nil {
			t.Fatalf("%q: %v", cron, err)
		}
		return len(w.Runs)
	}
	for _, c := range []struct {
		cron          string
		from, through model.UnixNano
		want          int
	}{
		{"*/15 * * * *", utc(2026, 3, 1, 0, 0), utc(2026, 3, 1, 1, 0), 4},
		{"0 9 * * 1-5", utc(2026, 3, 1, 0, 0), utc(2026, 3, 8, 0, 0), 5},
		{"0 0 13 * 5", utc(2026, 4, 1, 0, 0), utc(2026, 4, 30, 23, 59), 5}, // Fridays or the 13th
		{"0 0 * * 7", utc(2026, 3, 1, 0, 0), utc(2026, 3, 8, 0, 0), 1},     // 7 is Sunday
		{"5,35 8-9 * 3 *", utc(2026, 3, 1, 0, 0), utc(2026, 3, 2, 0, 0), 4},
		{"0 0 29 2 *", utc(2026, 1, 1, 0, 0), utc(2027, 1, 1, 0, 0), 0}, // no Feb 29 in 2026
	} {
		if got := count(c.cron, c.from, c.through); got != c.want {
			t.Errorf("%q: %d occurrences, want %d", c.cron, got, c.want)
		}
	}
	if _, err := jobs.ExpectedOccurrences(jobs.Definition{Schedule: &jobs.Schedule{Cron: "* * * * *", Timezone: "UTC"}}, utc(2026, 3, 1, 0, 0), utc(2026, 3, 2, 0, 0), 100); code(err) != model.TooLarge {
		t.Fatalf("unbounded enumeration: %v", err)
	}
	for name, schedule := range map[string]jobs.Schedule{
		"four fields":   {Cron: "* * * *", Timezone: "UTC"},
		"six fields":    {Cron: "* * * * * *", Timezone: "UTC"},
		"minute 60":     {Cron: "60 * * * *", Timezone: "UTC"},
		"zero step":     {Cron: "*/0 * * * *", Timezone: "UTC"},
		"words":         {Cron: "a * * * *", Timezone: "UTC"},
		"descending":    {Cron: "5-1 * * * *", Timezone: "UTC"},
		"macro":         {Cron: "@daily", Timezone: "UTC"},
		"day zero":      {Cron: "0 0 0 * *", Timezone: "UTC"},
		"empty zone":    {Cron: "* * * * *"},
		"unknown zone":  {Cron: "* * * * *", Timezone: "Mars/Olympus"},
		"path zone":     {Cron: "* * * * *", Timezone: "../etc/localtime"},
		"process local": {Cron: "* * * * *", Timezone: "Local"},
		"absolute zone": {Cron: "* * * * *", Timezone: "/usr/share/zoneinfo/UTC"},
	} {
		sc := schedule
		_, _, err := jobs.Observe(jobs.JobState{}, jobs.ScheduleEvidence{Job: jobID, Observer: observe, ObservedAt: 10, CompleteThrough: 10, Healthy: true, Definition: &jobs.Definition{Revision: 1, EffectiveFrom: 1, Schedule: &sc}})
		if code(err) != model.Invalid {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestScheduleHealthFromObserverEvidence(t *testing.T) {
	key := func(h, m int) string { return jobs.OccurrenceKey("UTC", hm(h, m, 0), 0) }
	def := hourly()

	t.Run("SDK silence under a healthy complete observer is missed and names the occurrence", func(t *testing.T) {
		st := observed(t, jobs.JobState{}, hm(12, 3, 0), hm(12, 3, 0), true, &def)
		h := jobs.Evaluate(st, hm(12, 3, 0))
		if h.Status != jobs.StatusMissed || !h.Complete || h.Evidence.Occurrence != key(11, 0) || *h.Evidence.ExpectedAt != hm(11, 0, 0) || *h.Evidence.WindowEnd != hm(12, 0, 0) {
			t.Fatalf("%+v", h)
		}
		if h.Evidence.Observer == nil || h.Evidence.Observer.CompleteThrough != hm(12, 3, 0) || h.Evidence.DefinitionRevision != 1 || st.CurrentHealth.Status != jobs.StatusMissed {
			t.Fatalf("verdict does not name its evidence: %+v", h.Evidence)
		}
	})
	t.Run("data path behind the window makes absence unknown, never missed", func(t *testing.T) {
		st := observed(t, jobs.JobState{}, hm(12, 3, 0), hm(11, 30, 0), true, &def)
		h := jobs.Evaluate(st, hm(12, 3, 0))
		if h.Status != jobs.StatusUnknown || h.Complete || !hasReason(h, jobs.ReasonAbsenceIncomplete) {
			t.Fatalf("%+v", h)
		}
	})
	t.Run("an unhealthy observer cannot establish missed or healthy", func(t *testing.T) {
		st := observed(t, jobs.JobState{}, hm(12, 3, 0), hm(12, 3, 0), false, &def)
		if h := jobs.Evaluate(st, hm(12, 3, 0)); h.Status != jobs.StatusUnknown || !hasReason(h, jobs.ReasonObserverUnhealthy) {
			t.Fatalf("%+v", h)
		}
		st = runOf(t, st, runA, att1, key(11, 0), 1, "succeeded", hm(11, 0, 2), hm(11, 0, 9))
		if h := jobs.Evaluate(st, hm(12, 3, 0)); h.Status != jobs.StatusUnknown || h.Status == jobs.StatusSucceeded || !hasReason(h, jobs.ReasonObserverUnhealthy) {
			t.Fatalf("success under an unhealthy observer: %+v", h)
		}
	})
	t.Run("no observer at all: schedule health is unknown even after a success", func(t *testing.T) {
		st := jobs.JobState{Definition: def}
		if h := jobs.Evaluate(st, hm(12, 3, 0)); h.Status != jobs.StatusUnknown || !hasReason(h, jobs.ReasonNoObserver) || !hasReason(h, jobs.ReasonNoEvidence) {
			t.Fatalf("%+v", h)
		}
		st = runOf(t, st, runA, att1, key(11, 0), 1, "succeeded", hm(11, 0, 2), hm(11, 0, 9))
		h := jobs.Evaluate(st, hm(12, 3, 0))
		if h.Status != jobs.StatusUnknown || *h.Evidence.Attempt != att1 || h.Complete {
			t.Fatalf("%+v", h)
		}
	})
	t.Run("within grace a success stands, after grace the next occurrence is late", func(t *testing.T) {
		st := observed(t, jobs.JobState{}, hm(11, 5, 0), hm(11, 5, 0), true, &def)
		st = runOf(t, st, runA, att1, key(11, 0), 1, "succeeded", hm(11, 0, 30), hm(11, 0, 40))
		st = observed(t, st, hm(12, 3, 0), hm(12, 3, 0), true, nil)
		if h := jobs.Evaluate(st, hm(12, 3, 0)); h.Status != jobs.StatusSucceeded || !h.Complete || h.Evidence.Occurrence != key(11, 0) {
			t.Fatalf("inside grace: %+v", h)
		}
		st = observed(t, st, hm(12, 10, 0), hm(12, 10, 0), true, nil)
		h := jobs.Evaluate(st, hm(12, 10, 0))
		if h.Status != jobs.StatusLate || !h.Complete || h.Evidence.Occurrence != key(12, 0) || !hasReason(h, jobs.ReasonExpectedNotStarted) {
			t.Fatalf("after grace: %+v", h)
		}
		// Late evidence is not the same claim as missed.
		if st.CurrentHealth.Status != jobs.StatusLate {
			t.Fatalf("stored verdict %v", st.CurrentHealth.Status)
		}
	})
	t.Run("missed persists across later windows until a run happens", func(t *testing.T) {
		st := observed(t, jobs.JobState{}, hm(11, 5, 0), hm(11, 5, 0), true, &def)
		st = runOf(t, st, runA, att1, key(11, 0), 1, "succeeded", hm(11, 0, 30), hm(11, 0, 40))
		st = observed(t, st, hm(14, 30, 0), hm(14, 30, 0), true, nil)
		h := jobs.Evaluate(st, hm(14, 30, 0))
		if h.Status != jobs.StatusMissed || h.Evidence.Occurrence != key(13, 0) {
			t.Fatalf("%+v", h)
		}
		st = runOf(t, st, model.ID{30}, att2, key(14, 0), 1, "succeeded", hm(14, 0, 20), hm(14, 0, 30))
		if h := jobs.Evaluate(st, hm(14, 30, 0)); h.Status != jobs.StatusSucceeded || !h.Complete {
			t.Fatalf("recovered by the next run: %+v", h)
		}
		if st.Attempts[att1].Effective() != jobs.AttemptSucceeded || len(st.Attempts) != 2 {
			t.Fatal("history changed")
		}
	})
	t.Run("a run arriving after missed was derived supersedes it without rewriting anything", func(t *testing.T) {
		st := observed(t, jobs.JobState{}, hm(12, 3, 0), hm(12, 3, 0), true, &def)
		if jobs.Evaluate(st, hm(12, 3, 0)).Status != jobs.StatusMissed {
			t.Fatal("setup")
		}
		st = runOf(t, st, runA, att1, key(11, 0), 1, "succeeded", hm(11, 0, 30), hm(11, 0, 40))
		if h := jobs.Evaluate(st, hm(12, 3, 0)); h.Status != jobs.StatusSucceeded {
			t.Fatalf("late delivery of the run: %+v", h)
		}
	})
	t.Run("an incomplete interval blocks both missed and success", func(t *testing.T) {
		gap := jobs.Interval{ID: model.ID{40}, Start: hm(11, 30, 0), End: hm(11, 45, 0), Reason: "source_loss"}
		st := observed(t, jobs.JobState{}, hm(12, 3, 0), hm(12, 3, 0), true, &def, gap)
		h := jobs.Evaluate(st, hm(12, 3, 0))
		if h.Status != jobs.StatusUnknown || h.Complete || !reflect.DeepEqual(h.Evidence.Gaps, []model.ID{gap.ID}) {
			t.Fatalf("missed inferred across a data gap: %+v", h)
		}
		after := observed(t, jobs.JobState{}, hm(11, 50, 0), hm(11, 50, 0), true, &def, jobs.Interval{ID: model.ID{41}, Start: hm(11, 20, 0), End: hm(11, 40, 0), Reason: "source_loss"})
		after = runOf(t, after, runA, att1, key(11, 0), 1, "succeeded", hm(11, 0, 30), hm(11, 0, 40))
		if h := jobs.Evaluate(after, hm(11, 50, 0)); h.Status != jobs.StatusUnknown || !hasReason(h, jobs.ReasonEvidenceGap) {
			t.Fatalf("success reported across a gap: %+v", h)
		}
		before := observed(t, jobs.JobState{}, hm(11, 50, 0), hm(11, 50, 0), true, &def, jobs.Interval{ID: model.ID{42}, Start: hm(10, 0, 0), End: hm(10, 30, 0), Reason: "source_loss"})
		before = runOf(t, before, runA, att1, key(11, 0), 1, "succeeded", hm(11, 0, 30), hm(11, 0, 40))
		if h := jobs.Evaluate(before, hm(11, 50, 0)); h.Status != jobs.StatusSucceeded || !h.Complete {
			t.Fatalf("a gap before the run downgraded it: %+v", h)
		}
		// A gap while the attempt was running but before its result arrived cannot
		// hide that result; one after the result can hide a newer run.
		during := observed(t, jobs.JobState{}, hm(11, 50, 0), hm(11, 50, 0), true, &def, jobs.Interval{ID: model.ID{47}, Start: hm(11, 0, 30), End: hm(11, 1, 0), Reason: "source_loss"})
		during = runOf(t, during, runA, att1, key(11, 0), 1, "succeeded", hm(11, 0, 0), hm(11, 2, 0))
		if h := jobs.Evaluate(during, hm(11, 50, 0)); h.Status != jobs.StatusSucceeded || !h.Complete {
			t.Fatalf("a gap before the attempt's result downgraded it: %+v", h)
		}
	})
	t.Run("project evidence gaps passed by the service count like job intervals", func(t *testing.T) {
		st := observed(t, jobs.JobState{}, hm(11, 50, 0), hm(11, 50, 0), true, &def)
		st = runOf(t, st, runA, att1, key(11, 0), 1, "succeeded", hm(11, 0, 30), hm(11, 0, 40))
		h := jobs.Evaluate(st, hm(11, 50, 0), jobs.Interval{ID: model.ID{43}, Start: hm(11, 20, 0), End: hm(11, 40, 0), Reason: "evidence_expired"})
		if h.Status != jobs.StatusUnknown || len(h.Evidence.Gaps) != 1 {
			t.Fatalf("%+v", h)
		}
	})
	t.Run("a stale observer withholds positive claims but not an observed failure", func(t *testing.T) {
		st := observed(t, jobs.JobState{}, hm(11, 5, 0), hm(11, 5, 0), true, &def)
		st = runOf(t, st, runA, att1, key(11, 0), 1, "succeeded", hm(11, 0, 30), hm(11, 0, 40))
		if h := jobs.Evaluate(st, hm(11, 14, 0)); h.Status != jobs.StatusSucceeded {
			t.Fatalf("observer 9 minutes old (limit 10): %+v", h)
		}
		h := jobs.Evaluate(st, hm(11, 16, 0))
		if h.Status != jobs.StatusUnknown || !hasReason(h, jobs.ReasonObserverStale) || !h.Evidence.Observer.Stale {
			t.Fatalf("observer outage not unknown: %+v", h)
		}
		failed := observed(t, jobs.JobState{}, hm(11, 5, 0), hm(11, 5, 0), true, &def)
		failed = runOf(t, failed, runA, att1, key(11, 0), 1, "failed", hm(11, 0, 30), hm(11, 0, 40))
		fh := jobs.Evaluate(failed, hm(11, 16, 0))
		if fh.Status != jobs.StatusFailed || fh.Complete || !hasReason(fh, jobs.ReasonObserverStale) {
			t.Fatalf("observed failure hidden or claimed complete: %+v", fh)
		}
		// The observer recovering restores the claim from new evidence only.
		st = observed(t, st, hm(11, 20, 0), hm(11, 20, 0), true, nil)
		if h := jobs.Evaluate(st, hm(11, 21, 0)); h.Status != jobs.StatusSucceeded || !h.Complete {
			t.Fatalf("after observer recovery: %+v", h)
		}
	})
	t.Run("no data yet is unknown", func(t *testing.T) {
		st := observed(t, jobs.JobState{}, hm(12, 2, 0), hm(12, 2, 0), true, &jobs.Definition{Revision: 1, EffectiveFrom: hm(12, 0, 0), Schedule: def.Schedule})
		if h := jobs.Evaluate(st, hm(12, 2, 0)); h.Status != jobs.StatusUnknown || !hasReason(h, jobs.ReasonNoEvidence) {
			t.Fatalf("%+v", h)
		}
		plain := observed(t, jobs.JobState{}, hm(12, 2, 0), hm(12, 2, 0), true, &jobs.Definition{Revision: 1, EffectiveFrom: hm(12, 0, 0)})
		if h := jobs.Evaluate(plain, hm(12, 2, 0)); h.Status != jobs.StatusUnknown || !hasReason(h, jobs.ReasonNoEvidence) {
			t.Fatalf("%+v", h)
		}
	})
}

func TestScheduleDSTHealth(t *testing.T) {
	ny := "America/New_York"
	daily := jobs.Definition{Revision: 1, EffectiveFrom: utc(2026, 3, 1, 0, 0), Schedule: &jobs.Schedule{Cron: "30 2 * * *", Timezone: ny}}
	t.Run("the nonexistent local time is not an expected run and is reported as skipped", func(t *testing.T) {
		st := observed(t, jobs.JobState{}, utc(2026, 3, 7, 8, 0), utc(2026, 3, 7, 8, 0), true, &daily)
		st = runOf(t, st, runA, att1, jobs.OccurrenceKey(ny, utc(2026, 3, 7, 7, 30), 0), 1, "succeeded", utc(2026, 3, 7, 7, 30)+2, utc(2026, 3, 7, 7, 31))
		st = observed(t, st, utc(2026, 3, 8, 12, 0), utc(2026, 3, 8, 12, 0), true, nil)
		h := jobs.Evaluate(st, utc(2026, 3, 8, 12, 0))
		if h.Status != jobs.StatusSucceeded || !h.Complete || !hasReason(h, jobs.ReasonSkippedLocalTime) || !reflect.DeepEqual(h.Evidence.Skipped, []string{"2026-03-08T02:30"}) {
			t.Fatalf("spring-forward day: %+v", h)
		}
		if h := jobs.Evaluate(observed(t, st, utc(2026, 3, 9, 6, 33), utc(2026, 3, 9, 6, 33), true, nil), utc(2026, 3, 9, 6, 33)); h.Status != jobs.StatusSucceeded {
			t.Fatalf("inside grace of 02:30 EDT: %+v", h)
		}
		late := observed(t, st, utc(2026, 3, 9, 6, 40), utc(2026, 3, 9, 6, 40), true, nil)
		if h := jobs.Evaluate(late, utc(2026, 3, 9, 6, 40)); h.Status != jobs.StatusLate || h.Evidence.Occurrence != jobs.OccurrenceKey(ny, utc(2026, 3, 9, 6, 30), 0) {
			t.Fatalf("the EDT occurrence is 06:30Z: %+v", h)
		}
	})
	t.Run("fall back expects both UTC instants", func(t *testing.T) {
		fold := jobs.Definition{Revision: 1, EffectiveFrom: utc(2026, 10, 1, 0, 0), Schedule: &jobs.Schedule{Cron: "30 1 * * *", Timezone: ny}}
		first, second := utc(2026, 11, 1, 5, 30), utc(2026, 11, 1, 6, 30)
		st := observed(t, jobs.JobState{}, first+120e9, first+120e9, true, &fold)
		st = runOf(t, st, runA, att1, jobs.OccurrenceKey(ny, first, 0), 1, "succeeded", first+2e9, first+3e9)
		st = observed(t, st, second+10*60e9, second+10*60e9, true, nil)
		h := jobs.Evaluate(st, second+10*60e9)
		if h.Status != jobs.StatusLate || h.Evidence.Occurrence != jobs.OccurrenceKey(ny, second, 1) {
			t.Fatalf("second instant of the repeated hour not expected: %+v", h)
		}
		st = runOf(t, st, model.ID{31}, att2, jobs.OccurrenceKey(ny, second, 1), 1, "succeeded", second+2e9, second+3e9)
		if h := jobs.Evaluate(st, second+10*60e9); h.Status != jobs.StatusSucceeded || h.Evidence.Occurrence != jobs.OccurrenceKey(ny, second, 1) {
			t.Fatalf("both instants ran: %+v", h)
		}
		if len(st.Occurrences) != 2 {
			t.Fatalf("fold instants collapsed into one occurrence: %d", len(st.Occurrences))
		}
	})
	t.Run("an older definition revision keeps governing windows before the new one", func(t *testing.T) {
		next := jobs.Definition{Revision: 2, EffectiveFrom: hm(24, 0, 0), Schedule: &jobs.Schedule{Cron: "0 12 * * *", Timezone: "UTC"}}
		st := observed(t, jobs.JobState{}, hm(36, 3, 0), hm(36, 3, 0), true, ptr(hourly()))
		st = observed(t, st, hm(36, 3, 0), hm(36, 3, 0), true, &next)
		h := jobs.Evaluate(st, hm(36, 3, 0))
		if h.Status != jobs.StatusMissed || h.Evidence.Occurrence != jobs.OccurrenceKey("UTC", hm(23, 0, 0), 0) {
			t.Fatalf("window before the new revision judged by the new cron: %+v", h)
		}
	})
}

func ptr[T any](v T) *T { return &v }

func TestScheduleObserverStateIsAnOrderFreeJoin(t *testing.T) {
	defs := []jobs.Definition{
		{Revision: 1, EffectiveFrom: hm(0, 0, 0), Schedule: &jobs.Schedule{Cron: "0 * * * *", Timezone: "UTC"}},
		{Revision: 2, EffectiveFrom: hm(24, 0, 0), Schedule: &jobs.Schedule{Cron: "0 12 * * *", Timezone: "UTC"}, MaxRuntime: jobs.Duration(time.Hour)},
		{Revision: 4, EffectiveFrom: hm(48, 0, 0), Schedule: &jobs.Schedule{Cron: "30 6 * * *", Timezone: "UTC"}},
	}
	evidence := []jobs.ScheduleEvidence{
		{Job: jobID, Observer: observe, ObservedAt: hm(10, 0, 0), CompleteThrough: hm(10, 0, 0), Healthy: true, Definition: &defs[0]},
		{Job: jobID, Observer: model.ID{8}, ObservedAt: hm(12, 0, 0), CompleteThrough: hm(11, 0, 0), Healthy: true, Definition: &defs[1], Incomplete: []jobs.Interval{{ID: model.ID{44}, Start: 5, End: 9, Reason: "observer_outage"}}},
		{Job: jobID, Observer: observe, ObservedAt: hm(12, 0, 0), CompleteThrough: hm(11, 30, 0), Healthy: false, Definition: &defs[2]},
		{Job: jobID, Observer: observe, ObservedAt: hm(9, 0, 0), CompleteThrough: hm(9, 0, 0), Healthy: true},
	}
	var reference jobs.JobState
	permutations(len(evidence), func(order []int) {
		st := jobs.JobState{}
		for _, i := range order {
			st = mustObserve(t, st, evidence[i])
			// Repeating any observation is a no-op.
			again, outcome, err := jobs.Observe(st, evidence[i])
			if err != nil || outcome != jobs.Duplicate || !reflect.DeepEqual(again, st) {
				t.Fatalf("order %v: repeat of %d: %v %v", order, i, outcome, err)
			}
		}
		// The entity version counts accepted changes, which legitimately depends on
		// delivery order (a superseded observation is a change when it arrives first).
		st.Version = 0
		if reference.Job == (model.ID{}) {
			reference = st
			return
		}
		if !reflect.DeepEqual(st, reference) {
			t.Fatalf("order %v reached a different observer state:\n%+v\n%+v", order, st, reference)
		}
	})
	// Newest clock wins; at an equal clock the unhealthy, then smaller, attestation wins.
	if o := reference.Observer; o.ObservedAt != hm(12, 0, 0) || o.Healthy || o.CompleteThrough != hm(11, 30, 0) {
		t.Fatalf("winner %+v", o)
	}
	if reference.Definition.Revision != 4 || len(reference.History) != 2 || reference.History[0].Revision != 1 || reference.History[1].Revision != 2 || len(reference.IncompleteIntervals) != 1 {
		t.Fatalf("definitions %+v / %+v", reference.Definition, reference.History)
	}

	for name, bad := range map[string]jobs.ScheduleEvidence{
		"no observer":                  {Job: jobID, ObservedAt: 10, CompleteThrough: 5, Healthy: true},
		"no job":                       {Observer: observe, ObservedAt: 10, CompleteThrough: 5, Healthy: true},
		"attests beyond its own clock": {Job: jobID, Observer: observe, ObservedAt: 10, CompleteThrough: 11, Healthy: true},
		"no clock":                     {Job: jobID, Observer: observe, CompleteThrough: 0, Healthy: true},
		"conflicting same revision":    {Job: jobID, Observer: observe, ObservedAt: 10, CompleteThrough: 5, Healthy: true, Definition: &jobs.Definition{Revision: 1, EffectiveFrom: hm(0, 0, 0), Schedule: &jobs.Schedule{Cron: "5 * * * *", Timezone: "UTC"}}},
		"revision zero":                {Job: jobID, Observer: observe, ObservedAt: 10, CompleteThrough: 5, Healthy: true, Definition: &jobs.Definition{EffectiveFrom: 1}},
		"negative grace":               {Job: jobID, Observer: observe, ObservedAt: 10, CompleteThrough: 5, Healthy: true, Definition: &jobs.Definition{Revision: 9, EffectiveFrom: hm(60, 0, 0), Grace: -1}},
		"effective before predecessor": {Job: jobID, Observer: observe, ObservedAt: 10, CompleteThrough: 5, Healthy: true, Definition: &jobs.Definition{Revision: 3, EffectiveFrom: hm(1, 0, 0)}},
		"empty interval":               {Job: jobID, Observer: observe, ObservedAt: 10, CompleteThrough: 5, Healthy: true, Incomplete: []jobs.Interval{{ID: model.ID{45}, Start: 5, End: 5, Reason: "x"}}},
		"interval changes in place":    {Job: jobID, Observer: observe, ObservedAt: 10, CompleteThrough: 5, Healthy: true, Incomplete: []jobs.Interval{{ID: model.ID{44}, Start: 5, End: 10, Reason: "observer_outage"}}},
	} {
		next, _, err := jobs.Observe(reference, bad)
		if c := code(err); c != model.Invalid && c != model.Conflict {
			t.Errorf("%s: accepted (%v)", name, err)
		}
		if err != nil && !reflect.DeepEqual(next, reference) {
			t.Errorf("%s: rejected observation changed state", name)
		}
	}
}

func TestJobHealthForUnscheduledJobs(t *testing.T) {
	def := jobs.Definition{Revision: 1, EffectiveFrom: hm(0, 0, 0), MaxRuntime: jobs.Duration(time.Hour)}
	t.Run("a result needs no clock, running too long needs the observer clock", func(t *testing.T) {
		st := jobs.JobState{Definition: def}
		st = runOf(t, st, runA, att1, "manual.a", 1, "succeeded", hm(1, 0, 0), hm(1, 0, 5))
		if h := jobs.Evaluate(st, hm(2, 0, 0)); h.Status != jobs.StatusSucceeded || !h.Complete {
			t.Fatalf("unscheduled success: %+v", h)
		}
		running := runOf(t, jobs.JobState{Definition: def}, runA, att1, "manual.a", 1, "started", hm(1, 0, 0), 0)
		h := jobs.Evaluate(running, hm(5, 0, 0))
		if h.Status != jobs.StatusRunning || h.Complete || !hasReason(h, jobs.ReasonNoClock) {
			t.Fatalf("running without a clock must not claim a runtime verdict: %+v", h)
		}
		watched := observed(t, running, hm(1, 30, 0), hm(1, 30, 0), true, nil)
		if h := jobs.Evaluate(watched, hm(1, 30, 0)); h.Status != jobs.StatusRunning || !h.Complete {
			t.Fatalf("within max runtime: %+v", h)
		}
		watched = observed(t, watched, hm(2, 30, 0), hm(2, 30, 0), true, nil)
		if h := jobs.Evaluate(watched, hm(2, 30, 0)); h.Status != jobs.StatusRunningTooLong || !hasReason(h, jobs.ReasonBeyondMaxRuntime) {
			t.Fatalf("beyond max runtime: %+v", h)
		}
		// The terminal event arriving later ends it, whatever the clock said.
		watched = mustReduce(t, watched, ev(runA, att1, "manual.a", 1, 99, "succeeded", hm(1, 0, 0), new(hm(2, 0, 0))))
		if watched.CurrentHealth.Status != jobs.StatusSucceeded {
			t.Fatalf("late terminal: %+v", watched.CurrentHealth)
		}
	})
	t.Run("a running attempt across an evidence gap is unknown, not running", func(t *testing.T) {
		st := jobs.JobState{Definition: def}
		st = runOf(t, st, runA, att1, "manual.a", 1, "started", hm(1, 0, 0), 0)
		st = observed(t, st, hm(1, 20, 0), hm(1, 20, 0), true, nil, jobs.Interval{ID: model.ID{46}, Start: hm(1, 5, 0), End: hm(1, 10, 0), Reason: "source_loss"})
		if h := jobs.Evaluate(st, hm(1, 20, 0)); h.Status != jobs.StatusUnknown || !hasReason(h, jobs.ReasonEvidenceGap) {
			t.Fatalf("%+v", h)
		}
	})
	t.Run("evaluation never mutates the state it reads", func(t *testing.T) {
		st := observed(t, jobs.JobState{}, hm(11, 5, 0), hm(11, 5, 0), true, ptr(hourly()))
		st = runOf(t, st, runA, att1, jobs.OccurrenceKey("UTC", hm(11, 0, 0), 0), 1, "failed", hm(11, 0, 1), hm(11, 0, 2))
		before, _ := json.Marshal(st)
		_ = jobs.Evaluate(st, hm(20, 0, 0))
		after, _ := json.Marshal(st)
		if !bytes.Equal(before, after) {
			t.Fatal("Evaluate changed state")
		}
	})
}

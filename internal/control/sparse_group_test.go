// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// D86: the commits of the workers' books (a job update, an issue commit: about 34 a second at the single-host
// gate, 6.4 ms of control command each) share the commit of the admission round that is running anyway. They
// used to take the lock every control writer shares for a commit of their own, in front of the next round: with
// the admission rounds at 120 a second the lock was held 98.6 % of the time and every rise of a command's cost
// turned into queueing of admission.

// bookFx is one fixture group that has a writer of the job books and a writer of the issue books.
type bookFx struct {
	*jobFx
	iss *issFx
}

func newBookFx(t *testing.T) *bookFx {
	t.Helper()
	fence := newFenceFxPatch(t)
	jf := newJobFxOn(t, fence)
	inf := newIssFxOn(t, fence)
	fence.admin("grant", fence.org, auth.AdminPayload{UserID: fence.user, ProjectID: fence.project, Enabled: true, Permissions: []string{string(auth.Read), string(auth.PolicyWrite), string(issuesWrite)}, Reason: "fixture"})
	var err error
	if jf.writer, err = fence.svc.Authorize(fence.ctx, fence.cred, fence.org, []model.ID{fence.project}, auth.PolicyWrite); err != nil {
		t.Fatal(err)
	}
	if inf.writer, err = fence.svc.Authorize(fence.ctx, fence.cred, fence.org, []model.ID{fence.project}, issuesWrite); err != nil {
		t.Fatal(err)
	}
	return &bookFx{jobFx: jf, iss: inf}
}

// jobStep is the next attempt update of job: its own command, so that a chain is not limited to the tags of a byte.
func (f *bookFx) jobStep(job model.ID, version uint64) (control.Result, error) {
	raw, err := json.Marshal(f.upd(job, version, byte(version%250)+1)) // a zero digest is invalid
	if err != nil {
		return control.Result{}, err
	}
	return f.store.TransactJobs(f.ctx, f.writer, control.Command{CommandID: model.NewID(), Kind: string(control.KindUpdateJob), Payload: raw})
}

func (f *bookFx) issueStep(n byte, revision uint64) error {
	c := control.IssueCommand{ExpectedRevision: model.Revision(revision), Records: []control.IssueRecordChange{f.iss.record(f.iss.issue(n, 1, f.iss.evidence(n, uint64(n))))}, Checkpoint: &control.IssueCheckpoint{Group: f.iss.group, Index: model.Uint64(n)}}
	_, err := f.iss.commit(c)
	return err
}

// admit runs workers writers that admit batches until stop is closed and answers the latency of each admission.
func (f *bookFx) admit(workers int, stop <-chan struct{}) (wait func() []time.Duration, failed func() error) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var all []time.Duration
	var first atomic.Pointer[error]
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var mine []time.Duration
			for {
				select {
				case <-stop:
					mu.Lock()
					all = append(all, mine...)
					mu.Unlock()
					return
				default:
				}
				began := time.Now()
				if _, err := reserveSeries(f.fenceFx, fmt.Sprintf("book_%02d", w)); err != nil { // one series a writer: the quota of series is not the test's
					first.CompareAndSwap(nil, &err)
					mu.Lock()
					all = append(all, mine...)
					mu.Unlock()
					return
				}
				mine = append(mine, time.Since(began))
			}
		}()
	}
	return func() []time.Duration { wg.Wait(); return all }, func() error {
		if e := first.Load(); e != nil {
			return *e
		}
		return nil
	}
}

// feed keeps at least depth admission transitions queued for the group commit until stop is closed; wait returns when the ones still
// running are answered. A node's intake does not wait for the answer of one request before it sends the next, so its queue holds
// admissions whenever a book commit arrives. Writers that each wait for their own answer (admit) do not: one round answers them all, they
// queue again together after the runner has taken whatever queued meanwhile, and the commit of a book writer, which queues faster than
// they do, is that. The rounds then alternate between a lone book commit and a round of every writer (a0+s1, a32+s1, a0+s1, ...: 40 of
// 80 commits alone in every run, each still one round of its own and none held back: the queue was empty when the runner took it).
func (f *bookFx) feed(depth int, stop <-chan struct{}) (wait func(), failed func() error) {
	var wg sync.WaitGroup
	var inflight atomic.Int64
	var first atomic.Pointer[error]
	wg.Add(1)
	go func() {
		defer wg.Done()
		for n := 0; ; n++ {
			select {
			case <-stop:
				return
			default:
			}
			need := depth - f.store.AdmissionQueuedForTest()
			if need <= 0 || inflight.Load() >= int64(4*depth) {
				time.Sleep(50 * time.Microsecond)
				continue
			}
			for range need {
				n++
				inflight.Add(1)
				wg.Add(1)
				go func(series int) {
					defer wg.Done()
					defer inflight.Add(-1)
					if _, err := reserveSeries(f.fenceFx, fmt.Sprintf("book_%02d", series%32)); err != nil { // 32 series: the quota of series is not the test's
						first.CompareAndSwap(nil, &err)
					}
				}(n)
			}
			time.Sleep(100 * time.Microsecond) // what was just started queues within that
		}
	}()
	return wg.Wait, func() error {
		if e := first.Load(); e != nil {
			return *e
		}
		return nil
	}
}

func quantile(d []time.Duration, q float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	s := slices.Clone(d)
	slices.Sort(s)
	return s[min(len(s)-1, int(float64(len(s))*q))]
}

// The red test of the lock: while admission rounds run without a pause, the commits of a job writer and an issue
// writer are carried by those rounds. Every one of them used to be a hold of the lock of its own; now a hold
// beyond the admission rounds is a sparse commit that found no round to ride in.
func TestBookCommitsRideInTheRoundsOfAdmission(t *testing.T) {
	f := newBookFx(t)
	job := f.job(1)
	const jobs, issues = 40, 40
	if _, err := f.jobStep(job, 0); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	// admission rounds run without a pause: the queue holds admissions whenever a book commit arrives (feed)
	wait, failed := f.feed(16, stop)
	holds0, _ := f.store.UpdateLockStatsForTest()
	rounds0, sparse0 := f.store.AdmissionRoundsForTest(), f.store.SparseCommitsForTest()
	var wg sync.WaitGroup
	var errs atomic.Pointer[error]
	wg.Add(2)
	go func() {
		defer wg.Done()
		for v := uint64(1); v <= jobs; v++ {
			if _, err := f.jobStep(job, v); err != nil {
				errs.CompareAndSwap(nil, &err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for n := byte(1); n <= issues; n++ {
			if err := f.issueStep(n, uint64(n-1)); err != nil {
				errs.CompareAndSwap(nil, &err)
				return
			}
		}
	}()
	wg.Wait()
	holds1, _ := f.store.UpdateLockStatsForTest()
	rounds1, sparse1 := f.store.AdmissionRoundsForTest(), f.store.SparseCommitsForTest()
	close(stop)
	wait()
	if e := failed(); e != nil {
		t.Fatal("admission:", e)
	}
	if e := errs.Load(); e != nil {
		t.Fatal("book commit:", *e)
	}
	alone := (holds1 - holds0) - (rounds1 - rounds0)
	t.Logf("%d book commits (%d as records) took %d holds of the lock beside the %d of the admission rounds", jobs+issues, sparse1-sparse0, alone, rounds1-rounds0)
	if sparse1-sparse0 != jobs+issues {
		t.Errorf("%d of %d book commits were committed as records", sparse1-sparse0, jobs+issues)
	}
	if alone > (jobs+issues)/4 {
		t.Errorf("%d of %d book commits held the lock for a commit of their own while admission rounds were running", alone, jobs+issues)
	}
	if snap, ok := f.book(job); !ok || uint64(snap.Version) != jobs+1 {
		t.Errorf("the job is at version %d (found %v), want %d", snap.Version, ok, jobs+1)
	}
	if s := f.iss.snap(); len(s.Issues) != issues {
		t.Errorf("the project holds %d issues, want %d", len(s.Issues), issues)
	}
}

// The latency of admission with the commits of the books running beside it stays within a few rounds of what it
// is without them: 4 writers admit for a second and a half alone, then again while a job writer and an issue
// writer commit at up to 200 and 100 a second (the single-host gate has 34 a second). Every commit of the books
// that rides in a round adds its own cost to the round (the plan of an issue commit decodes the issues of the
// project), so the bound is a multiple and not a round; on the commits of their own, each in front of the next
// round, the p95 was several times that bound in this fixture.
func TestAdmissionLatencyIsBoundedWhileBookCommitsRun(t *testing.T) {
	f := newBookFx(t)
	job := f.job(1)
	if _, err := f.jobStep(job, 0); err != nil {
		t.Fatal(err)
	}
	run := func(books bool) []time.Duration {
		stop := make(chan struct{})
		wait, failed := f.admit(4, stop)
		var wg sync.WaitGroup
		quit := make(chan struct{})
		if books {
			wg.Add(2)
			go func() {
				defer wg.Done()
				tick := time.NewTicker(5 * time.Millisecond)
				defer tick.Stop()
				v := uint64(1)
				for {
					select {
					case <-quit:
						return
					case <-tick.C:
					}
					if _, err := f.jobStep(job, v); err != nil {
						return
					}
					v++
				}
			}()
			go func() {
				defer wg.Done()
				tick := time.NewTicker(10 * time.Millisecond)
				defer tick.Stop()
				for n := byte(1); n != 0; n++ {
					select {
					case <-quit:
						return
					case <-tick.C:
					}
					if err := f.issueStep(n, uint64(n-1)); err != nil {
						return
					}
				}
			}()
		}
		time.Sleep(1500 * time.Millisecond)
		close(quit)
		wg.Wait()
		close(stop)
		lat := wait()
		if e := failed(); e != nil {
			t.Fatal("admission:", e)
		}
		return lat
	}
	alone := run(false)
	withBooks := run(true)
	p95a, p95b := quantile(alone, 0.95), quantile(withBooks, 0.95)
	t.Logf("admission p95 %v alone (%d admissions), %v with the books committing (%d)", p95a, len(alone), p95b, len(withBooks))
	if len(alone) < 50 || len(withBooks) < 50 {
		t.Fatalf("too few admissions to tell the latency: %d alone, %d with the books", len(alone), len(withBooks))
	}
	if p95b > 3*p95a+6*time.Millisecond {
		t.Errorf("admission p95 is %v with the commits of the books running and %v without them: they hold the admission back", p95b, p95a)
	}
}

// Updates of one job that name the same version, and the same command sent twice, are judged one after the
// other whether the writers arrive together or not: one update of a version wins, the others are stale, and a
// command that is sent twice commits once and answers the same both times.
func TestConcurrentBookCommitsAreJudgedOneAfterTheOther(t *testing.T) {
	f := newBookFx(t)
	job := f.job(1)
	if _, err := f.jobStep(job, 0); err != nil {
		t.Fatal(err)
	}
	const writers = 12
	for round := 1; round <= 5; round++ {
		version := uint64(round)
		same := model.NewID()
		raw, err := json.Marshal(f.upd(job, version, byte(round)))
		if err != nil {
			t.Fatal(err)
		}
		results := make([]error, writers)
		phases := make([]string, writers)
		var wg sync.WaitGroup
		for w := range writers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				id := model.NewID()
				if w%2 == 0 {
					id = same // half of the writers send one command
				}
				r, err := f.store.TransactJobs(f.ctx, f.writer, control.Command{CommandID: id, Kind: string(control.KindUpdateJob), Payload: raw})
				results[w], phases[w] = err, r.Phase
			}()
		}
		wg.Wait()
		applied, replayed, stale := 0, 0, 0
		for w := range writers {
			switch {
			case results[w] == nil && phases[w] == "applied":
				applied++
			case results[w] == nil && phases[w] == "replayed":
				replayed++
			case results[w] != nil:
				stale++
			}
		}
		if applied != 1 {
			t.Fatalf("round %d: %d of the writers of one version were applied (%d replayed, %d refused), want 1", round, applied, replayed, stale)
		}
		if snap, ok := f.book(job); !ok || uint64(snap.Version) != version+1 {
			t.Fatalf("round %d: the job is at version %d (found %v), want %d", round, snap.Version, ok, version+1)
		}
		// the books are the ones of one writer at a time: the record names the command that won
		rec := f.record(job)
		if len(rec.Commands) == 0 {
			t.Fatalf("round %d: the job keeps no command", round)
		}
	}
}

// The per-record cost of a commit that carries many: sixteen writers of sixteen jobs of one project and a
// writer of the issues commit together; the control commands they took are fewer than the commits.
func TestBookCommitsOfOneProjectShareTheirCommands(t *testing.T) {
	f := newBookFx(t)
	const jobsN, each = 8, 12
	for j := byte(1); j <= jobsN; j++ {
		if _, err := f.jobStep(f.job(j), 0); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := f.store.StatePatchStatsForTest()
	var wg sync.WaitGroup
	var errs atomic.Pointer[error]
	for j := byte(1); j <= jobsN; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for v := uint64(1); v <= each; v++ {
				if _, err := f.jobStep(f.job(j), v); err != nil {
					errs.CompareAndSwap(nil, &err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if e := errs.Load(); e != nil {
		t.Fatal(*e)
	}
	after, _ := f.store.StatePatchStatsForTest()
	commands, commits := after-before, uint64(jobsN*each)
	t.Logf("%d job updates of %d jobs took %d control commands", commits, jobsN, commands)
	if commands > commits*3/4 {
		t.Errorf("%d job updates took %d control commands: the writers that waited for a commit were not committed together", commits, commands)
	}
	for j := byte(1); j <= jobsN; j++ {
		if snap, ok := f.book(f.job(j)); !ok || uint64(snap.Version) != each+1 {
			t.Errorf("job %d is at version %d (found %v), want %d", j, snap.Version, ok, each+1)
		}
	}
}

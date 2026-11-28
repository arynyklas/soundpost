// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/conditions"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/rules"
	"github.com/arynyklas/soundpost/internal/staleretry"
)

// LeaderFence is the control group's leadership authority (*replica.Group).
// Fence returns this node's lease only while it is the leader; ValidateFence
// re-proves a lease against a fresh quorum observation. Every effect the
// workers perform is validated by the constructors they hand it to.
type LeaderFence interface {
	Fence(ctx context.Context) (replica.FenceToken, error)
	ValidateFence(ctx context.Context, token replica.FenceToken) error
}

// WorkerClock supplies wall-clock instants to the worker pass.
type WorkerClock interface{ Now() model.UnixNano }

type systemWorkerClock struct{}

func (systemWorkerClock) Now() model.UnixNano { return model.UnixNano(time.Now().UnixNano()) }

// The workers act as the in-process system principal of each organization they
// serve (auth.Service.AuthorizeSystem, audit actor "system:runner"): no human
// session, no stored token, nothing a client can present. Every pass derives its
// scopes afresh, so an organization or project that has ended, or an
// organization policy that moved, applies at the next pass.

// ProducerScopes derives the runner's scopes for one project of one
// organization. Each Scope call is a fresh auth.AuthorizeSystem derivation.
type ProducerScopes struct {
	authority *auth.Service
	org       model.ID
	project   model.ID
	clock     WorkerClock
}

// Now is the runner's clock of this pass (WorkerConfig.Clock): every instant a
// producer stamps or compares with comes from it, never from the wall clock, so
// the test clock and the production clock drive the producers alike. A scope
// built without a pass (tests of one producer) reads the system clock.
func (p ProducerScopes) Now() model.UnixNano {
	if p.clock == nil {
		return systemWorkerClock{}.Now()
	}
	return p.clock.Now()
}

// Org and Project name what the scopes are for.
func (p ProducerScopes) Org() model.ID     { return p.org }
func (p ProducerScopes) Project() model.ID { return p.project }

// Scope derives the system scope for one permission over exactly this project.
// Only the runner's roles (read, org.admin, issues.write, policy.write) exist.
func (p ProducerScopes) Scope(ctx context.Context, permission auth.Permission) (auth.Scope, error) {
	return p.authority.AuthorizeSystem(ctx, p.org, []model.ID{p.project}, permission)
}

// Producer is a leader-only per-project stage that turns evidence the product
// ingested into durable control state (issues, incidents, job health). Produce
// is called under the pass's leadership lease, must be idempotent and bounded,
// and returns how many records it committed. A produced record is the product's
// own work, committed under the system scope the producer derives from scopes.
type Producer interface {
	Produce(ctx context.Context, scopes ProducerScopes, lease replica.FenceToken) (committed int, err error)
}

// RuleSource lists the active rule definitions of one project (the newest
// version of each). Production binds the rule catalogue (App.RuleCatalogue, the
// definitions an administrator saves over POST /api/v1/rules); a node without a
// RuleSource schedules no rule.
// The scope is the project-scoped read scope of the worker principal.
type RuleSource interface {
	Rules(ctx context.Context, scope auth.Scope, project model.ID) ([]rules.Rule, error)
}

// OutputAdmission admits recording-rule batches through the data plane and looks
// receipts up again. It needs the source credential of the recording producer:
// production binds App.NewRecordingSource (the operator hands the node the
// credential of a registered source at start). Without one, recording outputs
// stay pending in the control outbox. Condition outputs do not need it.
type OutputAdmission interface {
	rules.Admitter
	rules.ReceiptLookup
}

// WorkerConfig configures the background workers. Every optional seam that is
// nil switches exactly that stage off; none is replaced by a stand-in.
type WorkerConfig struct {
	// Orgs are the organizations to serve. Empty serves every organization in
	// control state that has not been retired, listed again at every pass.
	Orgs []model.ID
	// Producers turn ingested evidence into control state (issues, incidents,
	// jobs) for each project before conditions are consumed. Nil produces nothing.
	Producers []Producer
	// Fence defaults to the control group's replica group.
	Fence LeaderFence
	// Clock defaults to the system clock.
	Clock WorkerClock

	// Rules enables rule scheduling and evaluation.
	Rules RuleSource
	// Producer resolves the registered recording producer (recording rules only).
	Producer rules.ProducerResolver
	// Admission enables the recording output worker.
	Admission OutputAdmission
	// Routing enables the condition to notification bridge.
	Routing NotificationRouting
	// Sender enables delivery. It is the one place a real provider plugs in.
	Sender notify.Sender

	// Interval is the pause between passes (default 5s, at least 10ms).
	Interval time.Duration
	// MaxBackoff caps the pause after failing passes (default 1m).
	MaxBackoff time.Duration
	// PassTimeout bounds one pass (default 2m).
	PassTimeout time.Duration
	// MaxProjects bounds the projects served per pass (default 64); the rest
	// are served by later passes in rotation.
	MaxProjects int
	// MaxRules bounds the rules scheduled per project per pass (default 32),
	// also in rotation.
	MaxRules int
	// RuleWorkers bounds the projects whose rules the rule loop of Run evaluates at the same time
	// (default 4). The rules of one project are evaluated one after the other whatever it is.
	RuleWorkers int
	// OutputLimit, ConsumeLimit, NotifyLimit and DeliveryBatch bound the work of
	// the other stages per project per pass (defaults 64, 256, 64, 16).
	OutputLimit   int
	ConsumeLimit  int
	NotifyLimit   int
	DeliveryBatch int

	// Observe receives each pass's report.
	Observe func(PassReport)
}

// Stages of a pass, as they appear in StageError.
const (
	StageAuth     = "auth"
	StageFence    = "fence"
	StageProduce  = "produce"
	StageRules    = "rules"
	StageOutputs  = "outputs"
	StageConsume  = "consume"
	StageNotify   = "notify"
	StageCutover  = "cutover"
	StageDelivery = "delivery"
)

// StageError is one safe failure of a pass: a closed stage and fault code.
type StageError struct {
	Project model.ID
	Stage   string
	Code    string
}

// PassReport says what one pass did.
type PassReport struct {
	// Leader is false when this node did not hold the lease: nothing ran.
	Leader bool
	// Deposed says the lease was lost during the pass: it stopped there.
	Deposed  bool
	Projects int
	// Evaluated counts rule grid points committed (verbatim replays included).
	Evaluated int
	// Produced counts records the producers committed (issues, incidents, jobs).
	Produced int
	// Finalized counts recording outputs completed.
	Finalized int
	// Consumed counts condition outputs applied.
	Consumed int
	// Submitted counts condition notifications decided into the outbox.
	Submitted int
	// Attempted counts deliveries handed to the sender.
	Attempted int
	// Took is the wall time of the pass.
	Took time.Duration
	// Steps is the wall time the pass spent in each step, summed over the projects it served.
	Steps StepTimes
	// StaleRetries counts the commands the pass's writers submitted again because the control
	// revision moved under them (not semantic conflicts), by writer.
	StaleRetries staleretry.Counts
	Errors       []StageError
}

// StepTimes is wall time by step of the per-project service. Evaluate and Commit are parts of Rules
// (the rule scheduling step: its listing of the project's rules, then the evaluation and the commit of
// every due grid point); Outbox is the delivery worker's RunOnce (claim, send, complete).
type StepTimes struct {
	Auth, Rules, Evaluate, Commit, Outputs, Produce, Consume, Submit, Cutover, Outbox time.Duration
}

func (s *StepTimes) add(o StepTimes) {
	s.Auth += o.Auth
	s.Rules += o.Rules
	s.Evaluate += o.Evaluate
	s.Commit += o.Commit
	s.Outputs += o.Outputs
	s.Produce += o.Produce
	s.Consume += o.Consume
	s.Submit += o.Submit
	s.Cutover += o.Cutover
	s.Outbox += o.Outbox
}

// passKind is what a pass of the workers serves: Tick does all of it in one pass over the projects;
// the runner serves the rule scheduling and the other stages apart.
type passKind uint8

const (
	passAll   passKind = iota // rule scheduling and every other stage
	passRules                 // rule scheduling only
	passWork                  // every stage but the rule scheduling
)

func (k passKind) String() string {
	switch k {
	case passRules:
		return "rules"
	case passWork:
		return "work"
	}
	return "all"
}

// Workers runs the leader-only background work of a node: rule scheduling and
// evaluation, recording outputs, condition consumption and notification
// delivery. It owns no state besides rotation cursors; everything durable is
// control state, so a pass is safe to repeat, to interrupt and to run on two
// nodes (the fence admits only the leader's effects).
type Workers struct {
	app *App
	cfg WorkerConfig

	scheduler *rules.Scheduler
	output    *rules.OutputWorker
	consumer  *conditions.Service
	outbox    *notify.Outbox
	delivery  *notify.Worker
	cutover   *notify.CutoverService
	state     *rules.StateStore

	mu          sync.Mutex // one pass over the stages beyond the rules (and Tick) at a time
	projectNext int
	acquired    replica.FenceToken // the leadership Acquirers have run for
	cursorMu    sync.Mutex
	ruleNext    map[model.ID]int // guarded by cursorMu

	ruleMu          sync.Mutex // one rule pass at a time
	ruleProjectNext int

	obsMu      sync.Mutex // Observe is called by one loop at a time
	loopErrors [2][]StageError
}

const (
	defaultWorkerInterval = 5 * time.Second
	minWorkerInterval     = 10 * time.Millisecond
	defaultMaxBackoff     = time.Minute
	defaultPassTimeout    = 2 * time.Minute
	defaultMaxProjects    = 64
	defaultMaxRules       = 32
	defaultOutputLimit    = 64
	defaultConsumeLimit   = 256
	defaultNotifyLimit    = 64
	defaultDeliveryBatch  = 16
	defaultRuleWorkers    = 4
)

func positive[T int | time.Duration](v, fallback T) T {
	if v <= 0 {
		return fallback
	}
	return v
}

// NewWorkers builds the workers over this node. Stages whose seam is nil in cfg
// are off; the rest are constructed with the leadership fence, so no
// constructor can act for a deposed leader.
func (a *App) NewWorkers(cfg WorkerConfig) (*Workers, error) {
	for _, org := range cfg.Orgs {
		if org == (model.ID{}) {
			return nil, model.Fail(model.Invalid)
		}
	}
	if cfg.Fence == nil {
		group := a.Control.ReplicaGroup()
		if group == nil {
			return nil, model.Fail(model.Unavailable)
		}
		cfg.Fence = group
	}
	if cfg.Clock == nil {
		cfg.Clock = systemWorkerClock{}
	}
	cfg.Interval = positive(cfg.Interval, defaultWorkerInterval)
	if cfg.Interval < minWorkerInterval {
		cfg.Interval = minWorkerInterval
	}
	cfg.MaxBackoff = positive(cfg.MaxBackoff, defaultMaxBackoff)
	if cfg.MaxBackoff < cfg.Interval {
		cfg.MaxBackoff = cfg.Interval
	}
	cfg.PassTimeout = positive(cfg.PassTimeout, defaultPassTimeout)
	cfg.MaxProjects = positive(cfg.MaxProjects, defaultMaxProjects)
	cfg.MaxRules = positive(cfg.MaxRules, defaultMaxRules)
	cfg.OutputLimit = positive(cfg.OutputLimit, defaultOutputLimit)
	cfg.ConsumeLimit = positive(cfg.ConsumeLimit, defaultConsumeLimit)
	cfg.NotifyLimit = positive(cfg.NotifyLimit, defaultNotifyLimit)
	cfg.DeliveryBatch = positive(cfg.DeliveryBatch, defaultDeliveryBatch)
	cfg.RuleWorkers = positive(cfg.RuleWorkers, defaultRuleWorkers)

	w := &Workers{app: a, cfg: cfg, ruleNext: map[model.ID]int{}}
	w.state = rules.NewStateStore(a.Control)
	if cfg.Rules != nil {
		options := []rules.Option{rules.WithClock(cfg.Clock), rules.WithFencer(cfg.Fence), rules.WithEvidence(rules.GapEvidence{Gaps: a.Control})}
		if cfg.Producer != nil {
			options = append(options, rules.WithProducerResolver(cfg.Producer))
		}
		evaluator := rules.NewEvaluator(a.Query, w.state, options...)
		w.scheduler = rules.NewScheduler(evaluator, rules.NewCommitter(a.Control, cfg.Fence), w.state, rules.WithSchedulerClock(cfg.Clock))
	}
	ruleOutbox := rules.NewOutboxStore(a.Control)
	if cfg.Admission != nil {
		var options []rules.OutputOption
		if cfg.Producer != nil {
			options = append(options, rules.WithProducerRefresh(cfg.Producer))
		}
		output, err := rules.NewOutputWorker(cfg.Admission, ruleOutbox, cfg.Admission, cfg.Fence, options...)
		if err != nil {
			return nil, err
		}
		w.output = output
	}
	consumer, err := conditions.New(a.Control, cfg.Fence, ruleOutbox, cfg.Clock)
	if err != nil {
		return nil, err
	}
	w.consumer = consumer
	outbox, err := notify.NewOutbox(a.Control, cfg.Fence, cfg.Clock)
	if err != nil {
		return nil, err
	}
	w.outbox = outbox
	if w.cutover, err = notify.NewCutoverService(a.Control, cfg.Clock); err != nil {
		return nil, err
	}
	if cfg.Sender != nil {
		if w.delivery, err = notify.NewWorker(outbox, cfg.Sender, cfg.Fence, notify.WithBatch(cfg.DeliveryBatch)); err != nil {
			return nil, err
		}
	}
	return w, nil
}

// RunWorkers builds the workers and runs them until ctx ends. It is the hook a
// serving process starts next to RunFences.
func (a *App) RunWorkers(ctx context.Context, cfg WorkerConfig) error {
	w, err := a.NewWorkers(cfg)
	if err != nil {
		return err
	}
	w.Run(ctx)
	return nil
}

// Run passes at the configured interval until ctx ends. The rule scheduling has a loop of its own beside
// the loop over the other stages (producers, conditions, notifications, delivery): a rule is evaluated on
// its grid at the pace of the rule loop, whatever the other stages are doing for the projects. Run returns
// only after the pass in flight of each loop has observed the cancellation. The pause of a loop grows
// exponentially (to MaxBackoff) while its passes fail and returns to the interval after a clean pass or
// while this node is not the leader.
func (w *Workers) Run(ctx context.Context) {
	var wg sync.WaitGroup
	if w.scheduler != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.loop(ctx, loopRules, w.RuleTick)
		}()
	}
	w.loop(ctx, loopWork, w.workTick)
	wg.Wait()
}

const (
	loopWork = iota
	loopRules
)

func (w *Workers) loop(ctx context.Context, which int, tick func(context.Context) PassReport) {
	name := "work"
	if which == loopRules {
		name = "rules"
	}
	timer := time.NewTimer(w.cfg.Interval)
	defer timer.Stop()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		pass, cancel := context.WithTimeout(ctx, w.cfg.PassTimeout)
		report := tick(pass)
		cancel()
		workerPassObserved(name, report)
		w.observe(which, report)
		if len(report.Errors) > 0 {
			failures++
		} else {
			failures = 0
		}
		timer.Reset(w.delay(failures))
	}
}

// observe hands the report of a pass to Observe. The errors it carries are those of the last pass of each
// loop, so a clean pass of one loop does not report a recovery while the other still fails.
func (w *Workers) observe(which int, report PassReport) {
	if w.cfg.Observe == nil {
		return
	}
	w.obsMu.Lock()
	defer w.obsMu.Unlock()
	w.loopErrors[which] = report.Errors
	report.Errors = append(append([]StageError(nil), w.loopErrors[loopWork]...), w.loopErrors[loopRules]...)
	w.cfg.Observe(report)
}

func (w *Workers) delay(failures int) time.Duration {
	d := w.cfg.Interval
	for range min(failures, 16) {
		if d >= w.cfg.MaxBackoff {
			break
		}
		d *= 2
	}
	return min(d, w.cfg.MaxBackoff)
}

// deposed reports whether err says the lease is gone.
func deposed(err error) bool {
	if errors.Is(err, replica.ErrStale) {
		return true
	}
	var f *model.Fault
	return errors.As(err, &f) && f.Code == model.Stale
}

func code(err error) string {
	var f *model.Fault
	if errors.As(err, &f) {
		return string(f.Code)
	}
	switch {
	case errors.Is(err, context.Canceled):
		return string(model.Cancelled)
	case errors.Is(err, context.DeadlineExceeded):
		return string(model.Timeout)
	}
	return string(model.Unavailable)
}

// Tick is one bounded pass. A node that is not the leader does nothing. The
// lease is taken once and re-proved between stages and by every effect; a lost
// lease ends the pass with Deposed set.
func (w *Workers) Tick(ctx context.Context) PassReport {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pass(ctx, passAll)
}

func (w *Workers) pass(ctx context.Context, kind passKind) (report PassReport) {
	begun := time.Now()
	before := staleretry.Snapshot()
	defer func() {
		report.Took = time.Since(begun)
		report.StaleRetries = staleretry.Snapshot().Since(before)
		if kind == passWork {
			report.StaleRetries.Rules = 0 // the rule loop's, not this pass's
		}
	}()
	lease, err := w.cfg.Fence.Fence(ctx)
	if err != nil {
		w.acquired = replica.FenceToken{} // the next leadership is a new acquisition
		return report
	}
	report.Leader = true
	w.acquire(ctx, lease, &report)
	orgs, err := w.orgs(ctx)
	if err != nil {
		report.Errors = append(report.Errors, StageError{Stage: StageAuth, Code: code(err)})
		return report
	}
	for _, org := range orgs {
		if ctx.Err() != nil || report.Deposed {
			break
		}
		w.serveOrg(ctx, org, lease, &report, kind)
	}
	return report
}

// workTick is one pass over every stage but the rule scheduling, which has its own loop in Run.
func (w *Workers) workTick(ctx context.Context) PassReport {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pass(ctx, passWork)
}

// RuleTick is one pass of the rule scheduling alone: the rules of the next MaxProjects projects of every
// organization, MaxRules of each, served by at most RuleWorkers projects at a time. One goroutine serves a
// project, so the rules of a project are evaluated one after the other, in their rotation, and two rule
// passes never overlap. Every effect is validated by the lease like those of Tick, whichever goroutine
// meets the loss first stops the others between projects. The other stages are not run.
func (w *Workers) RuleTick(ctx context.Context) (report PassReport) {
	if w.scheduler == nil {
		return report
	}
	w.ruleMu.Lock()
	defer w.ruleMu.Unlock()
	begun := time.Now()
	before := staleretry.Snapshot()
	defer func() {
		report.Took = time.Since(begun)
		report.StaleRetries = staleretry.Counts{Rules: staleretry.Snapshot().Rules - before.Rules} // the other loop's are its own
	}()
	lease, err := w.cfg.Fence.Fence(ctx)
	if err != nil {
		return report
	}
	report.Leader = true
	orgs, err := w.orgs(ctx)
	if err != nil {
		report.Errors = append(report.Errors, StageError{Stage: StageAuth, Code: code(err)})
		return report
	}
	for _, org := range orgs {
		if ctx.Err() != nil || report.Deposed {
			break
		}
		w.serveRuleOrg(ctx, org, lease, &report)
	}
	return report
}

func (w *Workers) serveRuleOrg(ctx context.Context, org model.ID, lease replica.FenceToken, report *PassReport) {
	projects, err := w.projects(ctx, org, &w.ruleProjectNext)
	if err != nil {
		report.Errors = append(report.Errors, StageError{Stage: StageAuth, Code: code(err)})
		return
	}
	parts := make([]PassReport, min(w.cfg.RuleWorkers, len(projects)))
	var next atomic.Int64
	var lost atomic.Bool
	var wg sync.WaitGroup
	for i := range parts {
		wg.Add(1)
		go func(part *PassReport) {
			defer wg.Done()
			for ctx.Err() == nil && !lost.Load() {
				k := int(next.Add(1)) - 1
				if k >= len(projects) {
					return
				}
				part.Projects++
				w.serveProject(ctx, org, projects[k], lease, part, passRules)
				if part.Deposed {
					lost.Store(true)
				}
			}
		}(&parts[i])
	}
	wg.Wait()
	for i := range parts {
		report.merge(parts[i])
	}
}

// merge adds the counts, the step times and the errors of one server's part of a pass.
func (r *PassReport) merge(o PassReport) {
	r.Deposed = r.Deposed || o.Deposed
	r.Projects += o.Projects
	r.Evaluated += o.Evaluated
	r.Produced += o.Produced
	r.Finalized += o.Finalized
	r.Consumed += o.Consumed
	r.Submitted += o.Submitted
	r.Attempted += o.Attempted
	r.Steps.add(o.Steps)
	r.Errors = append(r.Errors, o.Errors...)
}

// Acquirer is a Producer that keeps state in this node's memory which is a
// function of replicated state. Acquired runs once per leadership (a new term,
// or a restarted process) before the first pass serves any project, and again
// while it fails.
type Acquirer interface {
	Acquired(ctx context.Context, lease replica.FenceToken, now model.UnixNano) error
}

func (w *Workers) acquire(ctx context.Context, lease replica.FenceToken, report *PassReport) {
	if w.acquired.Group == lease.Group && w.acquired.Term == lease.Term && lease.Term != 0 {
		return
	}
	done := true
	for _, producer := range w.cfg.Producers {
		a, ok := producer.(Acquirer)
		if !ok {
			continue
		}
		if err := a.Acquired(ctx, lease, w.cfg.Clock.Now()); err != nil {
			done = false
			if deposed(err) {
				report.Deposed = true
				return
			}
			report.Errors = append(report.Errors, StageError{Stage: StageProduce, Code: code(err)})
		}
	}
	if done {
		w.acquired = lease
	}
}

// orgs is the organizations this pass serves: the configured ones, or every
// organization in control state that has not been retired, in a stable order.
func (w *Workers) orgs(ctx context.Context) ([]model.ID, error) {
	if len(w.cfg.Orgs) > 0 {
		return w.cfg.Orgs, nil
	}
	var out []model.ID
	err := w.app.Control.ViewCore(ctx, func(st model.ControlState) error {
		for key := range st.Orgs {
			if _, retired := st.RetiredOrgs[key]; retired {
				continue
			}
			id, err := model.ParseID(key)
			if err != nil {
				return model.Fail(model.Corrupt)
			}
			out = append(out, id)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, err
}

func (w *Workers) serveOrg(ctx context.Context, org model.ID, lease replica.FenceToken, report *PassReport, kind passKind) {
	projects, err := w.projects(ctx, org, &w.projectNext)
	if err != nil {
		report.Errors = append(report.Errors, StageError{Stage: StageAuth, Code: code(err)})
		return
	}
	for _, project := range projects {
		if ctx.Err() != nil || report.Deposed {
			return
		}
		report.Projects++
		w.serveProject(ctx, org, project, lease, report, kind)
	}
}

// projects returns the next MaxProjects projects of the organization in
// rotation from *cursor, in a stable order, so a large organization is served
// in full over consecutive passes.
func (w *Workers) projects(ctx context.Context, org model.ID, cursor *int) ([]model.ID, error) {
	var all []model.ID
	err := w.app.Control.ViewCore(ctx, func(st model.ControlState) error {
		o, ok := st.Orgs[org.String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		for key := range o.Projects {
			id, err := model.ParseID(key)
			if err != nil {
				return model.Fail(model.Corrupt)
			}
			all = append(all, id)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(all, func(i, j int) bool { return all[i].String() < all[j].String() })
	n := len(all)
	if n <= w.cfg.MaxProjects {
		return all, nil
	}
	start := *cursor % n
	*cursor = (start + w.cfg.MaxProjects) % n
	out := make([]model.ID, 0, w.cfg.MaxProjects)
	for i := range w.cfg.MaxProjects {
		out = append(out, all[(start+i)%n])
	}
	return out, nil
}

// stop records err for the stage and reports whether the pass must end
// (the lease is gone, or the pass's context is).
func (w *Workers) stop(ctx context.Context, project model.ID, stage string, err error, report *PassReport) bool {
	if err == nil {
		return ctx.Err() != nil
	}
	if deposed(err) {
		report.Deposed = true
		return true
	}
	report.Errors = append(report.Errors, StageError{Project: project, Stage: stage, Code: code(err)})
	return ctx.Err() != nil
}

// still re-proves the lease at the start of a project's stages, so a pass that
// lost leadership while serving an earlier project does not even authorize the
// next one. Within a project every stage's constructor validates the lease
// before each effect (and the delivery worker again immediately before each
// send), so no further checks are needed between stages.
func (w *Workers) still(ctx context.Context, lease replica.FenceToken, report *PassReport) bool {
	err := w.cfg.Fence.ValidateFence(ctx, lease)
	if err == nil {
		return true
	}
	if deposed(err) {
		report.Deposed = true
	} else {
		report.Errors = append(report.Errors, StageError{Stage: StageFence, Code: code(err)})
	}
	return false
}

func (w *Workers) serveProject(ctx context.Context, org, project model.ID, lease replica.FenceToken, report *PassReport, kind passKind) {
	begun := time.Now()
	var steps StepTimes
	defer func() {
		report.Steps.add(steps)
		workerProjectObserved(kind.String(), project, time.Since(begun), steps)
	}()
	if !w.still(ctx, lease, report) {
		return
	}
	// The scopes are derived afresh for every project of every pass: an organization
	// or project that ended, or a policy that moved, yields none from here on.
	t := time.Now()
	admin, err := w.app.Auth.AuthorizeSystem(ctx, org, []model.ID{project}, auth.OrgAdmin)
	steps.Auth += time.Since(t)
	if err != nil {
		report.Errors = append(report.Errors, StageError{Project: project, Stage: StageAuth, Code: code(err)})
		return
	}
	if kind != passWork && w.scheduler != nil {
		t = time.Now()
		end := w.rules(ctx, admin, org, project, lease, report, &steps)
		steps.Rules += time.Since(t)
		if end {
			return
		}
	}
	if kind == passRules {
		return
	}
	if w.output != nil {
		t = time.Now()
		out, err := w.output.Flush(ctx, admin, lease, w.cfg.OutputLimit)
		steps.Outputs += time.Since(t)
		report.Finalized += len(out.Finalized)
		if w.stop(ctx, project, StageOutputs, err, report) {
			return
		}
	}
	scopes := ProducerScopes{authority: w.app.Auth, org: org, project: project, clock: w.cfg.Clock}
	for _, producer := range w.cfg.Producers {
		t = time.Now()
		n, err := producer.Produce(ctx, scopes, lease)
		steps.Produce += time.Since(t)
		report.Produced += n
		if w.stop(ctx, project, StageProduce, err, report) {
			return
		}
	}
	t = time.Now()
	consumed, err := w.consumer.Consume(ctx, admin, lease, w.cfg.ConsumeLimit)
	steps.Consume += time.Since(t)
	report.Consumed += len(consumed.Applied)
	if w.stop(ctx, project, StageConsume, err, report) {
		return
	}
	if w.cfg.Routing != nil {
		t = time.Now()
		n, err := w.submitConditions(ctx, admin, project, lease, report)
		steps.Submit += time.Since(t)
		report.Submitted += n
		if w.stop(ctx, project, StageNotify, err, report) {
			return
		}
		t = time.Now()
		n, err = w.submitIncidents(ctx, admin, project, lease, report)
		steps.Submit += time.Since(t)
		report.Submitted += n
		if w.stop(ctx, project, StageNotify, err, report) {
			return
		}
	}
	t = time.Now()
	err = w.syncModes(ctx, admin, lease)
	steps.Cutover += time.Since(t)
	if w.stop(ctx, project, StageCutover, err, report) {
		return
	}
	if w.delivery != nil {
		t = time.Now()
		sent, err := w.delivery.RunOnce(ctx, admin, w.cfg.Clock.Now(), lease)
		steps.Outbox += time.Since(t)
		report.Attempted += len(sent.Accepted) + len(sent.Retried) + len(sent.Unknown) + len(sent.Failed)
		w.stop(ctx, project, StageDelivery, err, report)
		for _, e := range sent.Errors {
			report.Errors = append(report.Errors, StageError{Project: project, Stage: StageDelivery, Code: e.Code})
		}
	}
}

// rules runs the rule step of one project and reports whether the pass must end. The scope is the read
// scope of the worker principal; a refusal is a stage error of the project and the pass goes on.
func (w *Workers) rules(ctx context.Context, admin auth.Scope, org, project model.ID, lease replica.FenceToken, report *PassReport, steps *StepTimes) bool {
	read, err := w.app.Auth.AuthorizeSystem(ctx, org, []model.ID{project}, auth.Read)
	if err != nil {
		report.Errors = append(report.Errors, StageError{Project: project, Stage: StageAuth, Code: code(err)})
		return false
	}
	return w.scheduleRules(ctx, read, admin, project, lease, report, steps)
}

// scheduleRules runs the scheduler for the project's next MaxRules rules and
// reports whether the pass must end.
func (w *Workers) scheduleRules(ctx context.Context, read, admin auth.Scope, project model.ID, lease replica.FenceToken, report *PassReport, steps *StepTimes) bool {
	all, err := w.cfg.Rules.Rules(ctx, read, project)
	if w.stop(ctx, project, StageRules, err, report) {
		return true
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID.String() < all[j].ID.String() })
	n := len(all)
	if n == 0 {
		return false
	}
	count := min(n, w.cfg.MaxRules)
	w.cursorMu.Lock()
	start := w.ruleNext[project] % n
	w.ruleNext[project] = (start + count) % n
	w.cursorMu.Unlock()
	for i := range count {
		// A rule of another project is refused by the scheduler (Invalid) before any
		// read or commit: the scopes name exactly this project.
		rule := all[(start+i)%n]
		run, err := w.scheduler.RunOnce(ctx, read, admin, rule, lease)
		report.Evaluated += len(run.Committed)
		steps.Evaluate += run.Evaluate
		steps.Commit += run.Commit
		if w.stop(ctx, project, StageRules, err, report) {
			return true
		}
	}
	return false
}

// syncModes brings the project's delivery states to the mode its committed
// ownership-cutover phase requires. A project with no cutover record has no
// mode to sync.
func (w *Workers) syncModes(ctx context.Context, admin auth.Scope, lease replica.FenceToken) error {
	state, found, err := w.cutover.Cutover(ctx, admin)
	if err != nil || !found {
		return err
	}
	_, err = w.outbox.SyncModes(ctx, admin, lease, state.Phase, state.Cutover, state.Revision, w.cfg.Clock.Now())
	return err
}

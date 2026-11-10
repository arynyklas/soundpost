// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/conditions"
	"soundpost/internal/model"
	"soundpost/internal/notify"
	"soundpost/internal/replica"
	"soundpost/internal/rules"
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

// WorkerPrincipal names the organization a worker pass acts in and where it
// gets the bearer token of the principal it acts as. Committing control state
// (rule evaluations, condition state, delivery records) requires an
// organization-administrator scope, and the auth package offers no other way to
// obtain one than an organization administrator's own credential: a server token
// cannot carry org.admin (it is not a grantable permission), and there is no
// internal, privilege-minting worker scope, which this runner does not invent.
// So the principal is an administrator's session. Sessions expire (12 hours), so
// Token is asked on every pass and is where the process renews it; the principal
// must also be an organization member holding a telemetry.read grant on the
// projects served (the rule evaluator reads with the project-scoped read scope).
// The token is authenticated afresh on every pass, so revoking it stops the
// workers at once.
type WorkerPrincipal struct {
	Org   model.ID
	Token func(ctx context.Context) (string, error)
}

// RuleSource lists the active rule definitions of one project (the newest
// version of each). There is no rule catalogue in control state yet, so there is
// no production implementation: a node without a RuleSource schedules no rule.
// The scope is the project-scoped read scope of the worker principal.
type RuleSource interface {
	Rules(ctx context.Context, scope auth.Scope, project model.ID) ([]rules.Rule, error)
}

// OutputAdmission admits recording-rule batches through the data plane and looks
// receipts up again. It needs a source credential of the recording producer; no
// production implementation is wired, so without one recording outputs stay
// pending in the control outbox. Condition outputs do not need it.
type OutputAdmission interface {
	rules.Admitter
	rules.ReceiptLookup
}

// WorkerConfig configures the background workers. Every optional seam that is
// nil switches exactly that stage off; none is replaced by a stand-in.
type WorkerConfig struct {
	// Principals are the organizations to serve. Required.
	Principals []WorkerPrincipal
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
	// Finalized counts recording outputs completed.
	Finalized int
	// Consumed counts condition outputs applied.
	Consumed int
	// Submitted counts condition notifications decided into the outbox.
	Submitted int
	// Attempted counts deliveries handed to the sender.
	Attempted int
	Errors    []StageError
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

	mu          sync.Mutex
	projectNext int
	ruleNext    map[model.ID]int
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
	if len(cfg.Principals) == 0 {
		return nil, model.Fail(model.Invalid)
	}
	for _, p := range cfg.Principals {
		if p.Org == (model.ID{}) || p.Token == nil {
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

// Run passes at the configured interval until ctx ends. It starts no goroutine
// and returns only after the pass in flight has observed the cancellation. The
// pause grows exponentially (to MaxBackoff) while passes fail and returns to the
// interval after a clean pass or while this node is not the leader.
func (w *Workers) Run(ctx context.Context) {
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
		report := w.Tick(pass)
		cancel()
		if w.cfg.Observe != nil {
			w.cfg.Observe(report)
		}
		if len(report.Errors) > 0 {
			failures++
		} else {
			failures = 0
		}
		timer.Reset(w.delay(failures))
	}
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
	var report PassReport
	lease, err := w.cfg.Fence.Fence(ctx)
	if err != nil {
		return report
	}
	report.Leader = true
	for _, principal := range w.cfg.Principals {
		if ctx.Err() != nil || report.Deposed {
			break
		}
		w.servePrincipal(ctx, principal, lease, &report)
	}
	return report
}

func (w *Workers) servePrincipal(ctx context.Context, principal WorkerPrincipal, lease replica.FenceToken, report *PassReport) {
	token, err := principal.Token(ctx)
	if err != nil {
		report.Errors = append(report.Errors, StageError{Stage: StageAuth, Code: code(err)})
		return
	}
	credential, err := w.app.Auth.Authenticate(ctx, token)
	if err != nil {
		report.Errors = append(report.Errors, StageError{Stage: StageAuth, Code: code(err)})
		return
	}
	projects, err := w.projects(ctx, principal.Org)
	if err != nil {
		report.Errors = append(report.Errors, StageError{Stage: StageAuth, Code: code(err)})
		return
	}
	for _, project := range projects {
		if ctx.Err() != nil || report.Deposed {
			return
		}
		report.Projects++
		w.serveProject(ctx, credential, principal.Org, project, lease, report)
	}
}

// projects returns the next MaxProjects projects of the organization in
// rotation, in a stable order, so a large organization is served in full over
// consecutive passes.
func (w *Workers) projects(ctx context.Context, org model.ID) ([]model.ID, error) {
	var all []model.ID
	err := w.app.Control.View(ctx, func(st model.ControlState) error {
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
	start := w.projectNext % n
	w.projectNext = (start + w.cfg.MaxProjects) % n
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

func (w *Workers) serveProject(ctx context.Context, credential auth.Credential, org, project model.ID, lease replica.FenceToken, report *PassReport) {
	if !w.still(ctx, lease, report) {
		return
	}
	admin, err := w.app.Auth.Authorize(ctx, credential, org, []model.ID{project}, auth.OrgAdmin)
	if err != nil {
		report.Errors = append(report.Errors, StageError{Project: project, Stage: StageAuth, Code: code(err)})
		return
	}
	if w.scheduler != nil {
		read, err := w.app.Auth.Authorize(ctx, credential, org, []model.ID{project}, auth.Read)
		if err != nil {
			report.Errors = append(report.Errors, StageError{Project: project, Stage: StageAuth, Code: code(err)})
		} else if w.scheduleRules(ctx, read, admin, project, lease, report) {
			return
		}
	}
	if w.output != nil {
		out, err := w.output.Flush(ctx, admin, lease, w.cfg.OutputLimit)
		report.Finalized += len(out.Finalized)
		if w.stop(ctx, project, StageOutputs, err, report) {
			return
		}
	}
	consumed, err := w.consumer.Consume(ctx, admin, lease, w.cfg.ConsumeLimit)
	report.Consumed += len(consumed.Applied)
	if w.stop(ctx, project, StageConsume, err, report) {
		return
	}
	if w.cfg.Routing != nil {
		n, err := w.submitConditions(ctx, admin, project, lease, report)
		report.Submitted += n
		if w.stop(ctx, project, StageNotify, err, report) {
			return
		}
	}
	if err = w.syncModes(ctx, admin, lease); w.stop(ctx, project, StageCutover, err, report) {
		return
	}
	if w.delivery != nil {
		sent, err := w.delivery.RunOnce(ctx, admin, w.cfg.Clock.Now(), lease)
		report.Attempted += len(sent.Accepted) + len(sent.Retried) + len(sent.Unknown) + len(sent.Failed)
		w.stop(ctx, project, StageDelivery, err, report)
		for _, e := range sent.Errors {
			report.Errors = append(report.Errors, StageError{Project: project, Stage: StageDelivery, Code: e.Code})
		}
	}
}

// scheduleRules runs the scheduler for the project's next MaxRules rules and
// reports whether the pass must end.
func (w *Workers) scheduleRules(ctx context.Context, read, admin auth.Scope, project model.ID, lease replica.FenceToken, report *PassReport) bool {
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
	start := w.ruleNext[project] % n
	w.ruleNext[project] = (start + count) % n
	for i := range count {
		// A rule of another project is refused by the scheduler (Invalid) before any
		// read or commit: the scopes name exactly this project.
		rule := all[(start+i)%n]
		run, err := w.scheduler.RunOnce(ctx, read, admin, rule, lease)
		report.Evaluated += len(run.Committed)
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

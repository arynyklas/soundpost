// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/policy"
	"soundpost/internal/query/profile"
	"soundpost/internal/replica"
	"soundpost/internal/rules"
)

type ruleFile struct {
	Schema  string `json:"schema"`
	Fixture struct {
		Project string `json:"project"`
		Source  struct {
			ID     string              `json:"id"`
			Kinds  []string            `json:"kinds"`
			Labels map[string][]string `json:"labels"`
		} `json:"source"`
		MetricPoints []struct {
			Name      string            `json:"name"`
			Labels    map[string]string `json:"labels"`
			TimeNS    string            `json:"time_ns"`
			ValueBits string            `json:"value_bits"`
		} `json:"metric_points"`
		Principals []struct {
			ID     string              `json:"id"`
			Grants map[string][]string `json:"grants"`
		} `json:"principals"`
		Rules []struct {
			ID         string            `json:"id"`
			Kind       string            `json:"kind"`
			Profile    string            `json:"profile"`
			Expression string            `json:"expression"`
			IntervalNS string            `json:"interval_ns"`
			ForNS      string            `json:"for_ns"`
			HoldNS     string            `json:"recovery_hold_ns"`
			Missing    string            `json:"missing_data"`
			Severity   string            `json:"severity"`
			Version    string            `json:"version"`
			RecordName string            `json:"record_name"`
			Labels     map[string]string `json:"labels"`
		} `json:"rules"`
	} `json:"fixture"`
	Steps []struct {
		ID      string                     `json:"id"`
		NowNS   string                     `json:"now_ns"`
		Run     []string                   `json:"run"`
		RunAs   string                     `json:"run_as"`
		Scan    string                     `json:"scan"`
		Flush   string                     `json:"flush"`
		Crash   string                     `json:"crash"`
		Restart string                     `json:"restart"`
		Expect  map[string]json.RawMessage `json:"expect"`
	} `json:"steps"`
	Final struct {
		History map[string][]struct {
			Status string `json:"status"`
			Notify bool   `json:"notify"`
		} `json:"condition_history"`
	} `json:"final"`
}

type clockAt struct{ v atomic.Int64 }

func (c *clockAt) Now() model.UnixNano { return model.UnixNano(c.v.Load()) }

type admitter struct {
	e *Env
	s *Source
}

func (a admitter) Admit(ctx context.Context, b model.Batch) (model.Receipt, error) {
	grant, err := a.e.app.Ingest.ResolveSource(ctx, a.s.Cred, b)
	if err != nil {
		return model.Receipt{}, err
	}
	return a.e.app.Ingest.Admit(ctx, grant, b)
}

func (a admitter) LookupReceipt(ctx context.Context, b model.Batch) (model.Receipt, bool, error) {
	grant, err := a.e.app.Ingest.ResolveSource(ctx, a.s.Cred, b)
	if err != nil {
		return model.Receipt{}, false, err
	}
	normalized, err := policy.Normalize(grant, b)
	if err != nil {
		return model.Receipt{}, false, err
	}
	receipt, err := a.e.app.Ingest.LookupReceipt(ctx, a.s.Cred, model.ReceiptRequest{Source: b.Source, Producer: b.Producer, RouteSlot: b.RouteSlot, BatchID: b.ID, OriginalHash: normalized.Hash})
	var fault *model.Fault
	if errors.As(err, &fault) && fault.Code == model.NotFound {
		return model.Receipt{}, false, nil
	}
	return receipt, err == nil, err
}

// crashingOutbox kills the "process" after the receipt is durable but before the
// outbox learns of it.
type crashingOutbox struct {
	rules.Outbox
	crashOn string
	crashed bool
}

func (o *crashingOutbox) Settle(ctx context.Context, scope auth.Scope, lease replica.FenceToken, item control.RuleOutput, update control.RuleOutputApply) (control.Result, error) {
	if !o.crashed && update.To == o.crashOn {
		o.crashed = true
		return control.Result{}, errors.New("process crashed")
	}
	return o.Outbox.Settle(ctx, scope, lease, item, update)
}

// RunRules executes rule-smoke.json on a real node with real control.
func RunRules(ctx context.Context, dir, path string) (steps []StepResult, err error) {
	defer recoverFailure(&err)
	var file ruleFile
	check(readJSON(path, &file))
	checkf(file.Schema == "soundpost-rule-smoke/1", "unknown schema %s", file.Schema)
	env, err := NewEnv(ctx, dir)
	check(err)
	defer env.Close()
	f := file.Fixture
	env.AddProject(f.Project)
	var kinds []model.Kind
	for _, k := range f.Source.Kinds {
		kinds = append(kinds, model.Kind(k))
	}
	src := env.AddSource(SourceSpec{Name: f.Source.ID, Project: f.Project, Kinds: kinds, Labels: f.Source.Labels})
	var deviations []StepResult
	for _, p := range f.Principals {
		env.AddPerson(p.ID)
		for project, perms := range p.Grants {
			var grantable []string
			for _, perm := range perms {
				if perm == string(auth.OrgAdmin) {
					// org.admin is not a project grant in this system (the control
					// rejects it as invalid); the commit scope comes from the
					// bootstrap owner instead. Recorded, not hidden.
					deviations = append(deviations, StepResult{Name: "deviation/" + p.ID + "-org-admin-is-not-a-project-grant", Passed: true, Detail: "commit scope derived from the bootstrap owner, not from a project-scoped org.admin grant"})
					continue
				}
				grantable = append(grantable, perm)
			}
			env.Grant(p.ID, project, true, grantable...)
		}
	}
	steps = append(steps, deviations...)
	for _, pt := range f.MetricPoints {
		env.Ingest(src, env.MetricRecord(src, pt.Name, pt.Labels, mustInt(pt.TimeNS), mustHex(pt.ValueBits), nil))
	}
	project := env.Projects[f.Project]
	registry := env.registry
	built := map[string]rules.Rule{}
	for _, r := range f.Rules {
		rule := rules.Rule{ID: model.NewID(), Project: project, Version: model.Revision(mustInt(r.Version)), Kind: rules.Kind(r.Kind), Profile: r.Profile, FeatureSet: env.Features[r.Profile], Expression: r.Expression, Interval: time.Duration(mustInt(r.IntervalNS)), Severity: r.Severity, RecordName: r.RecordName, MissingData: rules.MissingData(r.Missing)}
		if r.ForNS != "" {
			rule.For = time.Duration(mustInt(r.ForNS))
		}
		if r.HoldNS != "" {
			rule.RecoveryHold = time.Duration(mustInt(r.HoldNS))
		}
		for k, v := range r.Labels {
			rule.Labels = append(rule.Labels, model.Label{Name: k, Value: v})
		}
		check(rule.Check(registry))
		built[r.ID] = rule
	}
	readName, workerName := "rule-reader", "rule-worker"
	// scopes derives the project-scoped read scope and the commit scope from the
	// file's own principals (not the bootstrap owner).
	scopes := func() (auth.Scope, auth.Scope) {
		reader := env.People[readName]
		checkf(reader != nil && env.People[workerName] != nil, "rule principals missing")
		read, err := env.app.Auth.Authorize(ctx, reader.Cred, env.org, []model.ID{project}, auth.Read)
		check(err)
		admin, err := env.app.Auth.Authorize(ctx, env.owner.Cred, env.org, []model.ID{project}, auth.OrgAdmin)
		check(err)
		return read, admin
	}
	clock := &clockAt{}
	producer := rules.ProducerIdentity{Source: src.ID, Producer: model.ID{0xee}, PolicyRevision: 1, Resource: src.Resource}
	type wiring struct {
		scheduler *rules.Scheduler
		store     rules.RuleStateReader
		evaluator *rules.Evaluator
		read      auth.Scope
		admin     auth.Scope
		lease     replica.FenceToken
	}
	wire := func() wiring {
		store := rules.NewStateStore(env.app.Control)
		group := env.app.Control.ReplicaGroup()
		evaluator := rules.NewEvaluator(env.engine, store, rules.WithClock(clock), rules.WithFencer(group), rules.WithEvidence(rules.GapEvidence{Gaps: env.app.Control}), rules.WithProducer(producer))
		committer := rules.NewCommitter(env.app.Control, group)
		read, admin := scopes()
		lease, err := group.Fence(ctx)
		check(err)
		return wiring{scheduler: rules.NewScheduler(evaluator, committer, store, rules.WithSchedulerClock(clock)), store: store, evaluator: evaluator, read: read, admin: admin, lease: lease}
	}
	w := wire()
	oldLease := w.lease
	var restarted bool
	storedCount := func(name string) int {
		n := 0
		for _, r := range distinct(env.scanMetrics(f.Project)) {
			if r.Name == name {
				n++
			}
		}
		return n
	}
	pending := func(ruleID model.ID, phase string) int {
		out, err := env.app.Control.RuleOutputs(ctx, w.admin, project, ruleID, phase, 0)
		check(err)
		return len(out)
	}
	for _, st := range file.Steps {
		result := StepResult{Name: st.ID}
		func() {
			defer func() {
				switch r := recover().(type) {
				case nil:
				case failure:
					result.Detail = r.err.Error()
				default:
					panic(r)
				}
			}()
			switch {
			case st.Restart != "":
				check(env.Restart())
				w = wire()
				checkf(w.lease.Term > oldLease.Term, "restart did not start a new leadership term: %d -> %d", oldLease.Term, w.lease.Term)
				restarted = true
				var want struct {
					Rule string `json:"rule"`
					Sch  string `json:"scheduled_ns"`
					Obs  string `json:"observed_ns"`
				}
				if raw, ok := st.Expect["committed_evaluation_returned_verbatim"]; ok {
					check(json.Unmarshal(raw, &want))
					rule := built[want.Rule]
					got, found, err := w.store.ReadEvaluation(ctx, w.read, rule.ID, rule.Version, model.UnixNano(mustInt(want.Sch)))
					check(err)
					checkf(found && int64(got.ObservedAt) == mustInt(want.Obs), "committed evaluation after restart: found=%v observed=%d want %s", found, got.ObservedAt, want.Obs)
				}
			case st.Flush != "":
				rule := built[st.Flush]
				outbox := rules.NewOutboxStore(env.app.Control)
				ad := admitter{env, src}
				if st.Crash != "" {
					crashing := &crashingOutbox{Outbox: outbox, crashOn: control.RulePhaseAdmitted}
					worker, err := rules.NewOutputWorker(ad, crashing, ad, env.app.Control.ReplicaGroup())
					check(err)
					_, err = worker.Flush(ctx, w.admin, w.lease, 10)
					checkf(err != nil && crashing.crashed, "the crash was not observed: %v", err)
				} else {
					worker, err := rules.NewOutputWorker(ad, outbox, ad, env.app.Control.ReplicaGroup())
					check(err)
					report, err := worker.Flush(ctx, w.admin, w.lease, 10)
					check(err)
					if _, ok := st.Expect["finalized_provenance"]; ok {
						done, err := env.app.Control.RuleOutputs(ctx, w.admin, project, rule.ID, control.RulePhaseFinalized, 0)
						check(err)
						checkf(len(done) == 1 && done[0].Receipt != nil && len(report.Admitted) == 1 && *done[0].Receipt == report.Admitted[0] && len(done[0].Inputs) > 0, "finalized provenance: %d outputs, receipt/inputs missing", len(done))
					}
				}
				var stored map[string]int
				if raw, ok := st.Expect["stored_samples"]; ok {
					check(json.Unmarshal(raw, &stored))
					for name, want := range stored {
						checkf(storedCount(name) == want, "stored %s = %d want %d", name, storedCount(name), want)
					}
				}
				var out struct {
					Pending   int `json:"pending"`
					Finalized int `json:"finalized"`
				}
				if raw, ok := st.Expect["outbox"]; ok {
					check(json.Unmarshal(raw, &out))
					checkf(pending(rule.ID, control.RulePhasePending) == out.Pending, "outbox pending %d want %d", pending(rule.ID, control.RulePhasePending), out.Pending)
					checkf(pending(rule.ID, control.RulePhaseFinalized) == out.Finalized, "outbox finalized %d want %d", pending(rule.ID, control.RulePhaseFinalized), out.Finalized)
				}
			case len(st.Run) > 0:
				clock.v.Store(mustInt(st.NowNS))
				switch st.Scan {
				case "unavailable":
					env.gate.setDown(true)
				case "available":
					env.gate.setDown(false)
				}
				lease := w.lease
				if st.RunAs != "" {
					checkf(restarted, "run_as names the pre-restart lease before any restart")
					lease = oldLease
				}
				for _, id := range st.Run {
					rule := built[id]
					report, err := w.scheduler.RunOnce(ctx, w.read, w.admin, rule, lease)
					if st.RunAs != "" {
						checkf(err != nil, "the deposed leader committed an evaluation")
						var want struct {
							Committed bool   `json:"committed"`
							Error     string `json:"error"`
						}
						_ = json.Unmarshal(mustRaw(st.Expect, "committed"), &want.Committed)
						checkf(!want.Committed && len(report.Committed) == 0, "deposed leader reported commits %v", report.Committed)
						continue
					}
					check(err)
					raw, ok := st.Expect[id]
					if !ok {
						continue
					}
					var want struct {
						Scheduled []string `json:"scheduled_ns"`
						Series    []struct {
							Labels map[string]string `json:"labels"`
							Phase  string            `json:"phase"`
						} `json:"series"`
						Health   string `json:"health"`
						Reason   string `json:"reason"`
						Revision *int64 `json:"state_revision"`
						Outbox   *struct {
							Pending int `json:"pending"`
						} `json:"outbox"`
					}
					check(json.Unmarshal(raw, &want))
					if want.Scheduled != nil {
						var got []string
						for _, c := range report.Committed {
							got = append(got, decimal(int64(c)))
						}
						checkf(fmt.Sprint(got) == fmt.Sprint(want.Scheduled), "%s committed %v want %v", id, got, want.Scheduled)
					}
					if rule.Kind == rules.KindAlert {
						state, err := w.store.Read(ctx, w.read, rule.ID)
						check(err)
						checkf(len(state.Series) == len(want.Series), "%s has %d series want %d", id, len(state.Series), len(want.Series))
						for i, s := range state.Series {
							_ = i
							matched := false
							for _, ws := range want.Series {
								if string(s.Phase) == ws.Phase && labelsEqual(s.Labels, ws.Labels) {
									matched = true
								}
							}
							checkf(matched, "%s series %v/%s not expected", id, s.Labels, s.Phase)
						}
						if want.Health != "" {
							checkf(string(state.Health) == want.Health, "%s health %s want %s", id, state.Health, want.Health)
						}
						if want.Reason != "" {
							checkf(string(state.Reason) == want.Reason, "%s reason %s want %s", id, state.Reason, want.Reason)
						}
						if want.Revision != nil {
							checkf(int64(state.Revision) == *want.Revision, "%s state revision %d want %d", id, state.Revision, *want.Revision)
						}
					}
					if want.Outbox != nil {
						checkf(pending(rule.ID, control.RulePhasePending) == want.Outbox.Pending, "%s pending outbox %d want %d", id, pending(rule.ID, control.RulePhasePending), want.Outbox.Pending)
					}
				}
			}
			result.Passed = true
		}()
		steps = append(steps, result)
	}
	// Final condition history: firing then resolved, nothing else.
	final := StepResult{Name: "condition-history"}
	func() {
		defer func() {
			if r := recover(); r != nil {
				f, ok := r.(failure)
				if !ok {
					panic(r)
				}
				final.Detail = f.err.Error()
			}
		}()
		for id, want := range file.Final.History {
			rule := built[id]
			outs, err := env.app.Control.RuleOutputs(ctx, w.admin, project, rule.ID, "", 0)
			check(err)
			checkf(len(outs) == len(want), "%s history has %d entries want %d", id, len(outs), len(want))
			for i, o := range outs {
				var intent rules.ConditionIntent
				check(json.Unmarshal(o.Payload, &intent))
				checkf(intent.Event.Status == want[i].Status && intent.Notify == want[i].Notify, "%s history[%d] %s notify=%v want %s notify=%v", id, i, intent.Event.Status, intent.Notify, want[i].Status, want[i].Notify)
			}
		}
		final.Passed = true
	}()
	steps = append(steps, final)
	return steps, nil
}

func mustRaw(m map[string]json.RawMessage, key string) json.RawMessage {
	if raw, ok := m[key]; ok {
		return raw
	}
	return json.RawMessage("false")
}

// labelsEqual compares series labels ignoring the reserved __name__ label: the
// file lists only the identifying labels (job), while a non-bool comparison
// keeps the metric name on its result. This is the conservative reading of the
// declarative file; the name is still required to be queue_depth by the rule.
func labelsEqual(have model.Labels, want map[string]string) bool {
	n := 0
	for _, l := range have {
		if l.Name == "__name__" {
			continue
		}
		n++
		if v, ok := want[l.Name]; !ok || v != l.Value {
			return false
		}
	}
	return n == len(want)
}

var _ = profile.Registry{}

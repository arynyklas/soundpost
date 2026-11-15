// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"github.com/arynyklas/soundpost/internal/rules"
)

const lokiProfile = "logql-loki-3.5.2"

// logsSection is the "logs" part of persisted-path.json: logs sent directly and
// through the Loki push bridge are read through the owned LogQL envelopes
// (streams with order and limit, metric queries, several projects), through
// discovery with paged cursors, through a log-based alert rule and through a
// live stream, at every persisted stage.
type logsSection struct {
	adaptersSection
	Discovery []discoverySpec `json:"discovery"`
	Rule      *logRuleSpec    `json:"rule"`
	Live      *liveSpec       `json:"live"`
}

// discoverySpec is one discovery request paged to the end. Pages is the authored
// page sequence at the stated page size.
type discoverySpec struct {
	ID    string     `json:"id"`
	Kind  string     `json:"kind"`
	Field string     `json:"field"`
	Limit uint32     `json:"limit"`
	Pages [][]string `json:"pages"`
}

// logRuleSpec is an alert rule over logs. Each stage creates the rule afresh
// (a new rule identity) and evaluates the slot at AtMS: the firing series must
// be the authored ones whatever the persisted layout the logs are read from.
type logRuleSpec struct {
	Expression string              `json:"expression"`
	AtMS       int64               `json:"at_ms"`
	Firing     []map[string]string `json:"firing"`
}

// liveSpec appends lines to a live source at each stage and requires the open
// stream of that stage to deliver exactly them.
type liveSpec struct {
	Source   string `json:"source"`
	App      string `json:"app"`
	Template string `json:"template"`
}

type logsClock struct{ v atomic.Int64 }

func (c *logsClock) Now() model.UnixNano { return model.UnixNano(c.v.Load()) }

// logsHooks admits the logs feeds and returns their hooks plus the hook of the
// envelope, discovery, rule and live checks.
func logsHooks(env *Env, sec *logsSection, profiles []string) []persistedHook {
	if len(sec.Feeds) == 0 {
		return nil
	}
	hooks := adapterHooks(env, &sec.adaptersSection, profiles, "logs")
	project := sec.Fixture.Projects[0]
	h := &logsEnvelope{env: env, sec: sec, project: project}
	hooks = append(hooks, persistedHook{name: "logs-envelopes", check: h.check})
	return hooks
}

type logsEnvelope struct {
	env     *Env
	sec     *logsSection
	project string
	// savedCursor is a discovery cursor taken at savedStage and resumed at the
	// next stage.
	savedCursor string
	savedStage  string
	savedSpec   string
	live        []string
}

func (h *logsEnvelope) discover(spec discoverySpec, cursor string) (query.DiscoveryResult, int, []byte) {
	env := h.env
	body := map[string]any{"org": env.org.String(), "projects": []string{env.Projects[h.project].String()}, "signal": "log", "kind": spec.Kind, "field": spec.Field,
		"matchers": []any{}, "time": map[string]string{"start": "0", "end": decimal(1 << 62)}, "limit": spec.Limit}
	if cursor != "" {
		body["cursor"] = cursor
	}
	code, out := env.Post(env.People["reader"], "/api/v1/discover", body)
	var d query.DiscoveryResult
	if code == 200 {
		check(json.Unmarshal(out, &d))
	}
	return d, code, out
}

func (h *logsEnvelope) check(stage string) []StepResult {
	var steps []StepResult
	add := func(name string, fn func() string) { steps = append(steps, stepOf(stage+"/logs/"+name, fn)) }
	for _, spec := range h.sec.Discovery {
		spec := spec
		add("discovery/"+spec.ID+"/pages", func() string {
			var pages [][]string
			cursor := ""
			for range 20 {
				d, code, out := h.discover(spec, cursor)
				if code != 200 {
					return fmt.Sprintf("status %d %s", code, trim(out))
				}
				if d.More != (d.NextCursor != "") || d.Freshness.Completeness != "complete" {
					return fmt.Sprintf("more=%v cursor=%q completeness=%q", d.More, d.NextCursor, d.Freshness.Completeness)
				}
				pages = append(pages, d.Items)
				if !d.More {
					if fmt.Sprint(pages) != fmt.Sprint(spec.Pages) {
						return fmt.Sprintf("pages %v, authored %v", pages, spec.Pages)
					}
					return ""
				}
				cursor = d.NextCursor
			}
			return "paging did not terminate"
		})
	}
	// A cursor taken at the previous stage continues exactly where it stopped
	// after a flush or a compaction (they move bytes, not data); after a restart
	// it either continues exactly or is refused with a typed error, and is never
	// answered with other items.
	if len(h.sec.Discovery) > 0 {
		spec := h.sec.Discovery[0]
		if h.savedCursor != "" {
			saved, savedStage := h.savedCursor, h.savedStage
			add("discovery/"+spec.ID+"/cursor-from-"+savedStage, func() string {
				d, code, out := h.discover(spec, saved)
				restarted := strings.HasPrefix(stage, "restart")
				if code != 200 {
					if !restarted {
						return fmt.Sprintf("a cursor was refused after a flush or compaction: %d %s", code, trim(out))
					}
					var f struct {
						Code string `json:"code"`
					}
					if json.Unmarshal(out, &f) != nil || f.Code == "" || code < 400 {
						return fmt.Sprintf("a cursor refusal is not typed: %d %s", code, trim(out))
					}
					return ""
				}
				want := append([]string(nil), spec.Pages[1]...)
				if fmt.Sprint(d.Items) != fmt.Sprint(want) {
					return fmt.Sprintf("a resumed cursor answered %v, the second page is %v", d.Items, want)
				}
				return ""
			})
		}
		d, code, _ := h.discover(spec, "")
		if code == 200 && d.NextCursor != "" {
			h.savedCursor, h.savedStage = d.NextCursor, stage
		}
	}
	if h.sec.Rule != nil {
		add("rule/"+"alert-over-logs", func() string { return h.ruleStage() })
	}
	if h.sec.Live != nil {
		add("live/append-is-delivered-once", func() string { return h.liveStage(stage) })
		add("live/stored-lines-equal-appended", func() string {
			src := h.env.Sources[h.sec.Live.Source]
			var got []string
			for _, r := range h.env.scanRaw(h.project, model.Log, nil) {
				if r.Source == src.ID {
					got = append(got, r.Value)
				}
			}
			sortStrings(got)
			want := append([]string(nil), h.live...)
			sortStrings(want)
			if fmt.Sprint(got) != fmt.Sprint(want) {
				return fmt.Sprintf("stored %v appended %v", got, want)
			}
			return ""
		})
	}
	return steps
}

// ruleStage evaluates a fresh alert rule over the logs and compares the firing
// series with the authored ones.
func (h *logsEnvelope) ruleStage() string {
	env, spec := h.env, h.sec.Rule
	project := env.Projects[h.project]
	src := env.Sources[h.sec.Feeds[0].Source]
	rule := rules.Rule{ID: model.NewID(), Project: project, Version: 1, Kind: rules.KindAlert, Profile: lokiProfile, FeatureSet: env.Features[lokiProfile],
		Expression: spec.Expression, Interval: time.Minute, Severity: "warning", MissingData: rules.MissingData("unknown")}
	check(rule.Check(env.registry))
	reader := env.People["reader"]
	read, err := env.app.Auth.Authorize(env.ctx, reader.Cred, env.org, []model.ID{project}, auth.Read)
	check(err)
	admin, err := env.app.Auth.Authorize(env.ctx, env.owner.Cred, env.org, []model.ID{project}, auth.OrgAdmin)
	check(err)
	clock := &logsClock{}
	anchor := h.anchor()
	clock.v.Store((anchor+spec.AtMS)*1e6 + 5e9)
	store := rules.NewStateStore(env.app.Control)
	group := env.app.Control.ReplicaGroup()
	producer := rules.ProducerIdentity{Source: src.ID, Producer: model.ID{0xee}, PolicyRevision: 1, Resource: src.Resource}
	evaluator := rules.NewEvaluator(env.engine, store, rules.WithClock(clock), rules.WithFencer(group), rules.WithEvidence(rules.GapEvidence{Gaps: env.app.Control}), rules.WithProducer(producer))
	committer := rules.NewCommitter(env.app.Control, group)
	lease, err := group.Fence(env.ctx)
	check(err)
	scheduler := rules.NewScheduler(evaluator, committer, store, rules.WithSchedulerClock(clock))
	report, err := scheduler.RunOnce(env.ctx, read, admin, rule, lease)
	check(err)
	if len(report.Committed) != 1 {
		return fmt.Sprintf("%d evaluations committed, want 1", len(report.Committed))
	}
	state, err := store.Read(env.ctx, read, rule.ID)
	check(err)
	if string(state.Health) != "ok" {
		return fmt.Sprintf("rule health %s (%s)", state.Health, state.Reason)
	}
	if len(state.Series) != len(spec.Firing) {
		return fmt.Sprintf("%d firing series, authored %d", len(state.Series), len(spec.Firing))
	}
	for _, s := range state.Series {
		matched := false
		for _, want := range spec.Firing {
			matched = matched || string(s.Phase) == "firing" && labelsEqual(s.Labels, want)
		}
		if !matched {
			return fmt.Sprintf("series %v/%s is not authored", s.Labels, s.Phase)
		}
	}
	return ""
}

func (h *logsEnvelope) anchor() int64 {
	// The anchor every feed of the section shares: the first feed's.
	return h.sec.anchorMS
}

// liveStage opens a live stream over the live source, appends one line and
// requires exactly that record, once.
func (h *logsEnvelope) liveStage(stage string) string {
	env, spec := h.env, h.sec.Live
	src := env.Sources[spec.Source]
	reader := env.People["reader"]
	body := map[string]any{"org": env.org.String(), "profile": lokiProfile, "feature_set": env.Features[lokiProfile], "expression": fmt.Sprintf(`{app=%q}`, spec.App),
		"projects": []string{env.Projects[h.project].String()}, "budget": map[string]any{"timeout_ns": "0", "memory_bytes": "0", "max_returned": "10"}}
	code, out := env.Post(reader, "/api/v1/live-tickets", body)
	if code != 200 {
		return fmt.Sprintf("ticket status %d %s", code, trim(out))
	}
	var t struct {
		Ticket string `json:"ticket"`
	}
	check(json.Unmarshal(out, &t))
	stream := env.openStream(reader, t.Ticket, "")
	defer func() { stream.cancel(); <-stream.ended }()
	if stream.status != 200 {
		return fmt.Sprintf("stream status %d", stream.status)
	}
	ev, ok := stream.next(10 * time.Second)
	if !ok || ev.Event != "open" {
		return fmt.Sprintf("first event %+v", ev)
	}
	line := fmt.Sprintf("l%d", len(h.live)+1)
	tpl := src.logTemplate
	var v model.Scalar
	check(json.Unmarshal([]byte(fmt.Sprintf("%q", line)), &v))
	env.tick++
	ts := model.UnixNano(env.tick)
	env.Ingest(src, model.Record{ID: model.NewID(), Kind: model.Log, ObservedAt: ts, Resource: src.Resource, Payload: model.Payload{Log: &model.LogRecord{
		Timestamp: &ts, TemplateID: tpl.ID, TemplateRevision: tpl.Revision, Fields: map[string]model.Scalar{tpl.Fields[0].Name: v},
		StreamLabels: model.Labels{{Name: "app", Value: spec.App}}, Metadata: map[string]model.Scalar{}}}})
	h.live = append(h.live, line)
	rendered := strings.ReplaceAll(tpl.Line, "{"+tpl.Fields[0].Name+"}", line)
	for range 4 {
		ev, ok = stream.next(10 * time.Second)
		if !ok {
			return "the stream ended or stalled before the appended record"
		}
		switch ev.Event {
		case "gap":
			if ev.Data.Gap == nil || ev.Data.Gap.Reason != "feed_catch_up" {
				return fmt.Sprintf("an unexpected gap %+v", ev.Data.Gap)
			}
		case "record":
			if ev.Data.Entry == nil || ev.Data.Entry.Line != rendered {
				return fmt.Sprintf("record %+v, want line %q", ev.Data.Entry, rendered)
			}
			if _, again := stream.silent(300 * time.Millisecond); again {
				return "the appended record was delivered more than once"
			}
			return ""
		default:
			return fmt.Sprintf("unexpected event %s", ev.Event)
		}
	}
	return "no record arrived"
}

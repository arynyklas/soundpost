// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math"
	"sort"

	"soundpost/internal/auth"
	"soundpost/internal/incidents"
	"soundpost/internal/issues"
	"soundpost/internal/model"
	"soundpost/internal/releases"
	"soundpost/internal/replica"
	"soundpost/internal/storage"
)

// The issue pipeline of a served process:
//
//	ingested error occurrences (data-plane journal)
//	  -> IssueProducer    issues.Service.ApplyThrough under the system issues.write
//	                      scope, the per-data-group checkpoint committed with the
//	                      evidence it covers
//	  -> IncidentProducer one incident per open issue episode, opened through
//	                      incidents.Service under the system org.admin scope
//
// Both are leader-only Producers of the background workers. Neither holds state:
// the source of truth is the journal (what was ingested), the control issue book
// (what was processed: issues, occurrence index, checkpoints) and the control
// incident book (which episodes already have an incident).

const (
	// issueGroupingVersion is the grouping algorithm version the producer applies.
	issueGroupingVersion uint16 = 1
	// issueProduceRows bounds the error occurrences one Produce call applies per
	// data group; a batch (one journal cursor) is never split, so a call may
	// exceed it by less than one batch. A pass resumes after the checkpoint.
	issueProduceRows = 512
	// The scan keeps at most issueKeepRows unprocessed rows per data group in
	// memory (trimmed whenever it reaches issueTrimRows); both are at least twice
	// the C03 batch limit, so one batch always fits whole.
	issueKeepRows = 2 * issueProduceRows
	issueTrimRows = 4 * issueProduceRows
	// incidentOpenLimit bounds the incidents one Produce call opens.
	incidentOpenLimit = 64
	// issueScanBytes bounds the bytes one scan may read.
	issueScanBytes = 64 << 20
)

// IssueProducer turns the error occurrences the product ingested into issues:
// per data group it resumes strictly after the committed checkpoint, groups the
// next bounded run of occurrences by fingerprint and commits them with the
// checkpoint in one control transaction (issues.Service.ApplyThrough).
func (a *App) IssueProducer() Producer { return a.IssueProducerWithClock(systemWorkerClock{}) }

// IssueProducerWithClock is IssueProducer with the clock that stamps the
// lifecycle ledger's arrival time (the data plane keeps no arrival instant).
func (a *App) IssueProducerWithClock(clock WorkerClock) Producer {
	return &issueProducer{app: a, clock: clock}
}

// IncidentProducer opens one incident for every open issue episode that has
// none: the first episode of an issue, and every regression (a reopening) after
// it. Incident, command, condition and episode IDs derive from the issue and
// its episode ordinal, so a repeated pass changes nothing.
func (a *App) IncidentProducer() Producer { return a.IncidentProducerWithClock(systemWorkerClock{}) }

// IncidentProducerWithClock is IncidentProducer with the clock that stamps the
// incident timeline.
func (a *App) IncidentProducerWithClock(clock WorkerClock) Producer {
	return &incidentProducer{app: a, clock: clock}
}

type issueProducer struct {
	app   *App
	clock WorkerClock
}

type incidentProducer struct {
	app   *App
	clock WorkerClock
}

// leaseGate re-proves the leadership lease against the control group before an
// effect; a deposed leader's effect is refused.
func (a *App) leaseGate(ctx context.Context, lease replica.FenceToken) error {
	group := a.Control.ReplicaGroup()
	if group == nil {
		return model.Fail(model.Unavailable)
	}
	return group.ValidateFence(ctx, lease)
}

// producerFence is the issues.Fence of one Produce call: it re-proves the lease
// and admits only a live (existing, not retired) organization and project.
type producerFence struct {
	app   *App
	lease replica.FenceToken
}

func (f producerFence) Admit(ctx context.Context, scope auth.Scope, project model.ID) error {
	if err := f.app.leaseGate(ctx, f.lease); err != nil {
		return err
	}
	org := scope.OrgID()
	return f.app.Control.View(ctx, func(st model.ControlState) error {
		o, ok := st.Orgs[org.String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		if _, ok = o.Projects[project.String()]; !ok {
			return model.Fail(model.NotFound)
		}
		if _, retired := st.RetiredOrgs[org.String()]; retired {
			return model.Fail(model.NotFound)
		}
		if _, retired := st.RetiredProjects[org.String()+":"+project.String()]; retired {
			return model.Fail(model.NotFound)
		}
		return nil
	})
}

// systemReleaseGraphs serves the release graph to the issue lifecycle for the
// runner's own issues.write scope (releases.Service.Graph is an administrator's
// read and would refuse it).
type systemReleaseGraphs struct{ app *App }

func (g systemReleaseGraphs) Graph(ctx context.Context, scope auth.Scope, project model.ID) (releases.Graph, error) {
	if !scope.IsSystem() || scope.Permission() != auth.IssuesWrite || !scope.AllowsProject(project) {
		return nil, model.Fail(model.Forbidden)
	}
	out := releases.Graph{}
	err := g.app.Control.View(ctx, func(st model.ControlState) error {
		if err := scope.ValidateControlState(st); err != nil {
			return err
		}
		org := scope.OrgID()
		for _, release := range st.Releases {
			if release.Org == org && release.Project == project {
				out[release.ID] = release
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// noPolicyWrite refuses the grouping migration: it needs policy.write on top of
// issues.write and is a human action; the runner never migrates.
type noPolicyWrite struct{}

func (noPolicyWrite) AuthorizePolicyWrite(context.Context, auth.Scope, model.ID) error {
	return model.Fail(model.Forbidden)
}

type issueClock struct{ c WorkerClock }

func (c issueClock) Now() model.UnixNano { return c.c.Now() }

func (p *issueProducer) service(lease replica.FenceToken) (*issues.Service, *issues.ControlStore, error) {
	store, err := issues.NewControlStore(p.app.Control)
	if err != nil {
		return nil, nil, err
	}
	svc, err := issues.New(issues.Deps{Store: store, Authorizer: p.app.Auth, Graphs: systemReleaseGraphs{p.app}, Fence: producerFence{p.app, lease},
		Policy: noPolicyWrite{}, Clock: issueClock{p.clock}, Regression: issues.RegressionPolicy{MinOccurrences: 1}})
	return svc, store, err
}

// issueRow is one scanned error occurrence. A skipped row (an occurrence the
// grouping cannot fingerprint, or one without a usable identity or time) is
// final: the checkpoint advances over it.
type issueRow struct {
	index model.Uint64
	skip  bool
	ev    issues.Evidence
}

type issueBacklog struct {
	rows    []issueRow
	trimmed bool
}

func (b *issueBacklog) sort() {
	sort.SliceStable(b.rows, func(i, j int) bool {
		if b.rows[i].index != b.rows[j].index {
			return b.rows[i].index < b.rows[j].index
		}
		return bytes.Compare(b.rows[i].ev.RecordID[:], b.rows[j].ev.RecordID[:]) < 0
	})
}

func (b *issueBacklog) add(r issueRow) {
	b.rows = append(b.rows, r)
	if len(b.rows) >= issueTrimRows {
		b.sort()
		b.rows = b.rows[:issueKeepRows]
		b.trimmed = true
	}
}

// take returns the next run: whole cursors (batches), oldest first, until
// issueProduceRows rows. After a trim the highest kept cursor may be incomplete
// (rows of it may have been dropped), so it is left for a later call unless it
// is all there is.
func (b *issueBacklog) take() []issueRow {
	b.sort()
	rows := b.rows
	if b.trimmed && len(rows) > 0 {
		last := rows[len(rows)-1].index
		j := len(rows)
		for j > 0 && rows[j-1].index == last {
			j--
		}
		if j > 0 {
			rows = rows[:j]
		}
	}
	end := 0
	for end < len(rows) && end < issueProduceRows {
		idx := rows[end].index
		for end < len(rows) && rows[end].index == idx {
			end++
		}
	}
	return rows[:end]
}

func (p *issueProducer) Produce(ctx context.Context, scopes ProducerScopes, lease replica.FenceToken) (int, error) {
	if err := p.app.leaseGate(ctx, lease); err != nil {
		return 0, err
	}
	read, err := scopes.Scope(ctx, auth.Read)
	if err != nil {
		return 0, err
	}
	write, err := scopes.Scope(ctx, auth.IssuesWrite)
	if err != nil {
		return 0, err
	}
	svc, store, err := p.service(lease)
	if err != nil {
		return 0, err
	}
	project := scopes.Project()
	state, err := store.Load(ctx, write, project)
	if err != nil {
		return 0, err
	}
	backlog, err := p.scan(ctx, read, scopes, state)
	if err != nil {
		return 0, err
	}
	groups := make([]model.ID, 0, len(backlog))
	for g := range backlog {
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool { return bytes.Compare(groups[i][:], groups[j][:]) < 0 })
	committed := 0
	for _, group := range groups {
		rows := backlog[group].take()
		if len(rows) == 0 {
			continue
		}
		seen := map[model.ID]bool{}
		var evidence []issues.Evidence
		for _, r := range rows {
			if r.skip || seen[r.ev.OccurrenceID] {
				continue
			}
			if _, known := state.Occurrences[r.ev.OccurrenceID]; known {
				continue // the same occurrence was applied from an earlier cursor
			}
			seen[r.ev.OccurrenceID] = true
			evidence = append(evidence, r.ev)
		}
		cursor := model.Cursor{Group: group, Index: rows[len(rows)-1].index}
		if err := svc.ApplyThrough(ctx, write, cursor, evidence); err != nil {
			return committed, err
		}
		committed += len(evidence)
	}
	return committed, nil
}

// scan reads the project's error occurrences under the read scope and returns,
// per data group, the unprocessed ones (above the committed checkpoint and
// within what the scan's watermark proves complete).
func (p *issueProducer) scan(ctx context.Context, read auth.Scope, scopes ProducerScopes, state issues.State) (map[model.ID]*issueBacklog, error) {
	org, project := scopes.Org(), scopes.Project()
	it, err := p.app.Storage.Scan(ctx, read, storage.ScanRequest{Projects: []model.ID{project}, Signal: model.ErrorKind, Start: math.MinInt64, End: math.MaxInt64})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	marks := map[model.ID]model.Uint64{}
	for _, m := range it.Watermarks() {
		marks[m.Group] = m.Index
	}
	out := map[model.ID]*issueBacklog{}
	var bytesRead uint64
	for {
		page, err := it.Next(ctx)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if page.Partial {
			return nil, model.Fail(model.Unavailable)
		}
		if bytesRead += page.Bytes; bytesRead > issueScanBytes {
			return nil, model.Fail(model.TooLarge)
		}
		for i := range page.IDs {
			origin := page.Origins[i]
			if origin.Group == (model.ID{}) || origin.Index <= state.Checkpoints[origin.Group] || page.Projects[i] != project {
				continue
			}
			if mark, ok := marks[origin.Group]; ok && origin.Index > mark {
				continue
			}
			b := out[origin.Group]
			if b == nil {
				b = &issueBacklog{}
				out[origin.Group] = b
			}
			b.add(p.row(org, project, page, i))
		}
	}
}

// row builds the lifecycle evidence of one scanned occurrence. Everything is
// copied out of the borrowed page.
func (p *issueProducer) row(org, project model.ID, page storage.Page, i int) issueRow {
	r := issueRow{index: page.Origins[i].Index, skip: true}
	occ := page.Values[i].Error
	if occ == nil || occ.Occurrence == (model.ID{}) || page.Times[i] <= 0 {
		return r
	}
	fingerprint, err := issues.Fingerprint(issueGroupingVersion, org, project, *occ)
	if err != nil {
		return r
	}
	arrival := p.clock.Now()
	if arrival <= 0 {
		arrival = page.Times[i]
	}
	e := issues.Evidence{OccurrenceID: occ.Occurrence, RecordID: page.IDs[i], Origin: page.Origins[i], GroupingVersion: issueGroupingVersion,
		Fingerprint: model.Hash(fingerprint), EventTime: page.Times[i], ArrivalTime: arrival, Ancestry: "unknown", Ordinal: page.Origins[i].Index, Freshness: "fresh"}
	if occ.Build != (model.ID{}) {
		build := occ.Build
		e.BuildID = &build
	}
	if occ.Release != nil && *occ.Release != (model.ID{}) {
		release := *occ.Release
		e.ReleaseID, e.Ancestry = &release, "known"
	}
	r.ev, r.skip = e, false
	return r
}

// derive is the deterministic ID of a named thing about an issue episode.
func derive(tag string, org, project, issue model.ID, ordinal uint32) model.ID {
	h := sha256.New()
	h.Write([]byte("soundpost.issue.incident." + tag + ".v1"))
	h.Write(org[:])
	h.Write(project[:])
	h.Write(issue[:])
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], ordinal)
	h.Write(n[:])
	var id model.ID
	copy(id[:], h.Sum(nil))
	return id
}

// episodeOf is the episode ordinal of an open issue (1 for the first, +1 for
// every regression since) and the occurrence that began it.
func episodeOf(rec issues.Record) (uint32, model.ID, bool) {
	ordinal := uint32(1)
	var opener model.ID
	haveOpener := false
	for _, x := range rec.Explanations {
		if x.Reopened {
			ordinal++
			opener, haveOpener = x.OccurrenceID, true
		}
	}
	if haveOpener {
		return ordinal, opener, true
	}
	first, found := issues.Evidence{}, false
	for _, e := range rec.Issue.Occurrences {
		if !found || e.EventTime < first.EventTime || e.EventTime == first.EventTime && bytes.Compare(e.OccurrenceID[:], first.OccurrenceID[:]) < 0 {
			first, found = e, true
		}
	}
	return ordinal, first.OccurrenceID, found
}

func (p *incidentProducer) Produce(ctx context.Context, scopes ProducerScopes, lease replica.FenceToken) (int, error) {
	if err := p.app.leaseGate(ctx, lease); err != nil {
		return 0, err
	}
	read, err := scopes.Scope(ctx, auth.Read)
	if err != nil {
		return 0, err
	}
	admin, err := scopes.Scope(ctx, auth.OrgAdmin)
	if err != nil {
		return 0, err
	}
	org, project := scopes.Org(), scopes.Project()
	store, err := issues.NewControlStore(p.app.Control)
	if err != nil {
		return 0, err
	}
	state, err := store.Load(ctx, read, project)
	if err != nil {
		return 0, err
	}
	existing, err := p.app.Control.Incidents(ctx, admin, project)
	if err != nil {
		return 0, err
	}
	have := make(map[model.ID]bool, len(existing))
	for _, rec := range existing {
		have[rec.ID] = true
	}
	ids := make([]model.ID, 0, len(state.Issues))
	for id, rec := range state.Issues {
		if rec.Issue.Workflow == "open" {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	opened := 0
	for _, id := range ids {
		if opened >= incidentOpenLimit {
			break
		}
		ordinal, opener, ok := episodeOf(state.Issues[id])
		incident := derive("incident", org, project, id, ordinal)
		if !ok || have[incident] {
			continue
		}
		severity, err := p.severity(ctx, read, project, state.Issues[id].Issue, opener)
		if err != nil {
			return opened, err
		}
		if err := p.app.leaseGate(ctx, lease); err != nil {
			return opened, err
		}
		_, err = p.app.Incidents.Act(ctx, admin, incidents.Action{
			CommandID: derive("command", org, project, id, ordinal),
			Type:      incidents.TypeOpen,
			Origin:    incidents.OriginSystem,
			Target:    incidents.Target{Org: org, Project: project, Incident: incident},
			Impact: &incidents.Impact{Condition: derive("condition", org, project, id, 0), Episode: derive("episode", org, project, id, ordinal),
				Severity: severity, State: incidents.ConditionFiring, Freshness: incidents.FreshnessFresh},
		}, p.clock.Now())
		if err != nil {
			return opened, err
		}
		opened++
	}
	return opened, nil
}

// severity is the impact of the occurrence that began the episode: a fatal
// error is critical, an unhandled one major, a handled one minor. An occurrence
// whose record is no longer readable (erased or expired) is minor: the incident
// still stands for the issue, with the lowest severity.
func (p *incidentProducer) severity(ctx context.Context, read auth.Scope, project model.ID, issue issues.Issue, occurrence model.ID) (incidents.Severity, error) {
	var record model.ID
	for _, list := range [][]issues.Evidence{issue.Occurrences, issue.LateHistory} {
		for _, e := range list {
			if e.OccurrenceID == occurrence {
				record = e.RecordID
			}
		}
	}
	if record == (model.ID{}) {
		return incidents.SeverityMinor, nil
	}
	it, err := p.app.Storage.Scan(ctx, read, storage.ScanRequest{Projects: []model.ID{project}, Signal: model.ErrorKind, Start: math.MinInt64, End: math.MaxInt64,
		Selectors: []storage.Matcher{idMatcher("id", record)}})
	if err != nil {
		return 0, err
	}
	defer it.Close()
	for {
		page, err := it.Next(ctx)
		if err == io.EOF {
			return incidents.SeverityMinor, nil
		}
		if err != nil {
			return 0, err
		}
		for i := range page.IDs {
			if page.IDs[i] != record || page.Values[i].Error == nil {
				continue
			}
			switch e := page.Values[i].Error; {
			case e.Fatal:
				return incidents.SeverityCritical, nil
			case !e.Handled:
				return incidents.SeverityMajor, nil
			}
			return incidents.SeverityMinor, nil
		}
	}
}

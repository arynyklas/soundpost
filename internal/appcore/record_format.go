// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// D94: rolling back past the one-way point fails closed. The records of D92 (an error issue's owner and external links,
// an incident's title, notes and external links) are members the previous release ignores and then DROPS when it stores
// the record again. The previous release refuses to start on a control-state format marker above 1 (readiness reason
// schema_newer, nothing written), so the marker is raised to model.FormatMarkerRecords BEFORE the first such record is
// written (incidents.Service and issues.Deps.RecordFormat call it), and a write whose marker cannot be written is
// refused. RecordFormatProducer repairs an installation that already holds such records without the marker (written
// by a build before this one).

// recordFormat raises the marker; idempotent, a no-op once it is up.
func (a *App) recordFormat(ctx context.Context) error {
	marked := false
	if err := a.Control.ViewCore(ctx, func(st model.ControlState) error {
		marked = st.BearerHashKeyVersion >= model.FormatMarkerRecords
		return nil
	}); err != nil || marked {
		return err
	}
	return a.Control.Update(ctx, func(st *model.ControlState) error {
		model.MarkRecordFormat(st)
		return nil
	})
}

// RecordFormatProducer is the leader-only repair: if the committed state holds a D92 record and the marker is not up, it
// raises it. After one pass that found the marker up or no record it does nothing (every later D92 write raises the
// marker itself), so the scan costs one pass of the node's life.
func (a *App) RecordFormatProducer() Producer { return &recordFormatProducer{app: a} }

type recordFormatProducer struct {
	app  *App
	done atomic.Bool
}

func (p *recordFormatProducer) Produce(ctx context.Context, _ ProducerScopes, lease replica.FenceToken) (int, error) {
	if p.done.Load() {
		return 0, nil
	}
	if err := p.app.leaseGate(ctx, lease); err != nil {
		return 0, err
	}
	marker, _, err := p.app.Control.ReadinessFacts(ctx)
	if err != nil {
		return 0, err
	}
	marked, holds := marker >= model.FormatMarkerRecords, false
	if !marked {
		if err := p.app.Control.ViewShared(ctx, func(st model.ReadOnlyControl) error {
			holds = holdsD92Records(st)
			return nil
		}); err != nil {
			return 0, err
		}
	}
	if marked || !holds {
		p.done.Store(true)
		return 0, nil
	}
	if err := p.app.recordFormat(ctx); err != nil {
		return 0, err
	}
	p.done.Store(true)
	return 1, nil
}

// holdsD92Records reports whether any issue holds an owner or an external link, or any incident a title, an external
// link or a title, note or external timeline entry. It reads the shared decode of the control state.
func holdsD92Records(st model.ReadOnlyControl) bool {
	seen := map[string]bool{}
	for _, key := range st.BookKeys(model.BookGroupingIssues, "") {
		parts := strings.SplitN(key, ":", 3)
		if len(parts) < 3 || seen[parts[0]+":"+parts[1]] {
			continue
		}
		seen[parts[0]+":"+parts[1]] = true
		org, err := model.ParseID(parts[0])
		if err != nil {
			continue
		}
		project, err := model.ParseID(parts[1])
		if err != nil {
			continue
		}
		for _, entry := range st.ProjectIssues(org, project) {
			if entry.Issue.Owner != nil || len(entry.Issue.External) > 0 {
				return true
			}
		}
	}
	for _, key := range st.BookKeys(model.BookIncidents, "") {
		raw, ok := st.BookRecord(model.BookIncidents, key)
		if !ok {
			continue
		}
		var rec struct {
			State json.RawMessage `json:"state"`
		}
		if json.Unmarshal(raw, &rec) != nil {
			continue
		}
		var inc struct {
			Title    string          `json:"title"`
			External json.RawMessage `json:"external"`
			Timeline []struct {
				Action struct {
					Type string `json:"type"`
				} `json:"action"`
			} `json:"timeline"`
		}
		if json.Unmarshal(rec.State, &inc) != nil {
			continue
		}
		if inc.Title != "" || len(inc.External) > 0 && string(inc.External) != "null" {
			return true
		}
		for _, e := range inc.Timeline {
			switch e.Action.Type {
			case "title", "note", "external_begin", "external_end", "external_adopt":
				return true
			}
		}
	}
	return false
}

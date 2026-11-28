// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// rawRow is one stored record of any signal reduced to the fields an authored
// manifest names: the input kind, the series (or stream) identity, the time and
// the value (exact float bits, the canonical native histogram, the log line or
// the condition state).
type rawRow struct {
	Source model.ID
	Kind   string
	Series string
	Time   int64
	Value  string
}

func (r rawRow) key() string {
	return r.Kind + "|" + r.Series + "|" + strconv.FormatInt(r.Time, 10) + "|" + r.Value
}

func labelString(ls model.Labels) string {
	parts := make([]string, 0, len(ls))
	for _, l := range ls {
		parts = append(parts, l.Name+"="+l.Value)
	}
	return strings.Join(parts, ",")
}

// canonHistogram renders a native histogram in one canonical JSON form so a
// stored histogram and an authored one compare byte for byte: every list is
// present (null becomes []).
func canonHistogram(h *model.NativeHistogram) string {
	raw, err := json.Marshal(h)
	check(err)
	var v any
	check(json.Unmarshal(raw, &v))
	var fix func(any) any
	fix = func(x any) any {
		switch t := x.(type) {
		case map[string]any:
			for k, e := range t {
				if e == nil {
					t[k] = []any{}
				} else {
					t[k] = fix(e)
				}
			}
		case []any:
			for i := range t {
				t[i] = fix(t[i])
			}
		}
		return x
	}
	out, err := json.Marshal(fix(v))
	check(err)
	return string(out)
}

func scalarText(s model.Scalar) string {
	raw, err := json.Marshal(s)
	check(err)
	var out string
	if json.Unmarshal(raw, &out) == nil {
		return out
	}
	return string(raw)
}

// scanRaw reads every stored record of one signal of one project on the given
// node's owner path, fenced on min.
func (e *Env) scanRaw(project string, signal model.Kind, min []model.Cursor) []rawRow {
	rows, err := e.scanRawErr(project, signal, min)
	check(err)
	return rows
}

// scanRawErr is scanRaw returning the scan's error instead of aborting, for
// the fault-injection rows that expect a typed failure.
func (e *Env) scanRawErr(project string, signal model.Kind, min []model.Cursor) ([]rawRow, error) {
	cred, err := e.app.Auth.Authenticate(e.ctx, e.owner.Session.Token)
	if err != nil {
		return nil, err
	}
	scope, err := e.app.Auth.Authorize(e.ctx, cred, e.org, []model.ID{e.Projects[project]}, auth.Read)
	if err != nil {
		return nil, err
	}
	it, err := e.app.Storage.Scan(e.ctx, scope, storage.ScanRequest{Projects: []model.ID{e.Projects[project]}, Signal: signal, Start: math.MinInt64, End: math.MaxInt64, Fence: storage.ReadFence{Min: min}})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var out []rawRow
	for {
		page, err := it.Next(e.ctx)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		for i := range page.Len() {
			v := page.Values[i]
			row := rawRow{Source: page.Sources[i], Time: int64(page.ObservedTimes[i])}
			switch {
			case v.Metric != nil:
				m := v.Metric
				row.Kind = m.SampleKind
				row.Series = m.Name + "{" + labelString(m.Labels) + "}"
				switch {
				case m.Histogram != nil:
					row.Value = canonHistogram(m.Histogram)
				case m.Value != nil:
					row.Value = fmt.Sprintf("%016x", uint64(*m.Value))
				}
			case v.Log != nil:
				l := v.Log
				row.Kind = "log"
				row.Series = "{" + labelString(l.StreamLabels) + "}"
				if f, ok := l.Fields["line"]; ok {
					row.Value = scalarText(f)
				} else {
					row.Value = l.Line
				}
			case v.Condition != nil:
				c := v.Condition
				row.Kind = "condition"
				row.Series = "seq=" + strconv.FormatUint(uint64(c.Sequence), 10)
				row.Time = int64(c.At)
				row.Value = c.Status + "|" + c.Severity + "|" + labelString(c.Labels)
			default:
				continue
			}
			out = append(out, row)
		}
	}
}

func rowKeys(rows []rawRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.key()
	}
	sort.Strings(out)
	return out
}

// diffKeys names the first difference between two sorted key multisets.
func diffKeys(got, want []string) string {
	if len(got) != len(want) {
		return fmt.Sprintf("%d stored rows, %d authored (first stored %v, first authored %v)", len(got), len(want), first(got), first(want))
	}
	for i := range got {
		if got[i] != want[i] {
			return fmt.Sprintf("row %d differs: stored %q authored %q", i, got[i], want[i])
		}
	}
	return ""
}

func first(a []string) string {
	if len(a) == 0 {
		return "-"
	}
	return a[0]
}

// maxCursors folds receipt cursors into one fence: the highest cursor per
// group.
type cursorSet struct {
	best  map[model.ID]model.Cursor
	order []model.ID
}

func (c *cursorSet) add(cur model.Cursor) {
	if c.best == nil {
		c.best = map[model.ID]model.Cursor{}
	}
	prev, seen := c.best[cur.Group]
	if !seen {
		c.order = append(c.order, cur.Group)
	}
	if !seen || cur.Index > prev.Index {
		c.best[cur.Group] = cur
	}
}

func (c *cursorSet) list() []model.Cursor {
	out := make([]model.Cursor, 0, len(c.order))
	for _, g := range c.order {
		out = append(out, c.best[g])
	}
	return out
}

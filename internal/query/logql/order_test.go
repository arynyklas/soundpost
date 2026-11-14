// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/value"
	"io"
	"testing"
)

func TestLogBoundsAndDuplicateTies(t *testing.T) {
	s := &metricSource{rows: []scan.LogRow{metricRow(2, 1000000001, "same"), metricRow(1, 1000000001, "same"), metricRow(3, 1000000002, "end")}}
	for _, order := range []LogOrder{Forward, Backward} {
		a := value.NewBoundedAccount(32 << 20)
		p := metricPlan(t, `{app="api"}`, value.Evaluation{Start: 1000000001, End: 1000000002})
		r, err := EvaluateLogs(context.Background(), p, s, order, 2, a)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Logs) != 2 || r.Logs[0].Timestamp != 1000000001 || r.Logs[1].Timestamp != 1000000001 || r.Logs[0].ID == r.Logs[1].ID {
			t.Fatalf("duplicate/end-exclusive semantics changed: %+v", r.Logs)
		}
		a.Release(value.ResultBytes(r))
		if a.Used() != 0 {
			t.Fatalf("retained charge leaked %d", a.Used())
		}
	}
}

type entryRows struct {
	rows []PipelineResult
	at   int
}

func (i *entryRows) Next(context.Context) (PipelineResult, error) {
	if i.at == len(i.rows) {
		return PipelineResult{}, io.EOF
	}
	r := i.rows[i.at]
	i.at++
	return r, nil
}
func (i *entryRows) Watermarks() []model.Cursor { return nil }
func (i *entryRows) Partial() bool              { return false }
func (i *entryRows) Close() error               { return nil }
func TestLogMergeAcrossPagesAndShards(t *testing.T) {
	for _, order := range []LogOrder{Forward, Backward} {
		a := value.NewBoundedAccount(32 << 20)
		mk := func(id byte) PipelineResult {
			r := metricRow(id, 1000000001, "same")
			return PipelineResult{Retained: true, Entry: LogEntry{ID: r.ID, Timestamp: r.Timestamp, Multiplicity: 2, Line: r.Record.Line}, Labels: r.Record.StreamLabels}
		}
		merged, err := MergeLogs(context.Background(), []EntryIterator{&entryRows{rows: []PipelineResult{mk(3), mk(1)}}, &entryRows{rows: []PipelineResult{mk(2)}}}, order, 3, a)
		if err != nil {
			t.Fatal(err)
		}
		defer merged.Close()
		var count uint64
		var ids []byte
		for {
			r, e := merged.Next(context.Background())
			if e == io.EOF {
				break
			}
			if e != nil {
				t.Fatal(e)
			}
			count += uint64(r.Entry.Multiplicity)
			ids = append(ids, r.Entry.ID[0])
			a.Release(r.Bytes)
		}
		if count != 3 || len(ids) != 2 {
			t.Fatalf("tie limit count=%d ids=%v", count, ids)
		}
		if order == Forward && ids[0] != 1 || order == Backward && ids[0] != 3 {
			t.Fatalf("direction=%s ids=%v", order, ids)
		}
		if a.Used() != 0 {
			t.Fatalf("merge leak=%d", a.Used())
		}
	}
}

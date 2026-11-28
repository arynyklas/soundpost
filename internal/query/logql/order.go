// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"bytes"
	"context"
	"errors"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
	"io"
	"math"
	"strconv"
	"strings"
)

type LogOrder string

const (
	Forward  LogOrder = "forward"
	Backward LogOrder = "backward"
)

// Next transfers ownership of PipelineResult.Bytes to the consumer. Close
// releases unread entries. Watermarks and Partial remain readable after Close.
type EntryIterator interface {
	Next(context.Context) (PipelineResult, error)
	Watermarks() []model.Cursor
	Partial() bool
	Close() error
}
type LogIterator = EntryIterator

type orderedLog struct {
	result     PipelineResult
	streamHash uint64
	labels     string
	index      int64  // scratch charged to the account for this row's ordering key
	seq        uint64 // arrival order: the last tie-break, making the order strict
}
type orderedLogs struct {
	rows       []orderedLog
	at         int
	metadata   value.Result
	account    value.Account
	indexBytes int64
	closed     bool
	// truncated reports that rows were discarded because the bound was already
	// covered by entries that precede them.
	truncated bool
}

func (i *orderedLogs) Watermarks() []model.Cursor {
	return append([]model.Cursor(nil), i.metadata.Watermarks...)
}
func (i *orderedLogs) Partial() bool { return i.metadata.Partial }
func (i *orderedLogs) Close() error {
	if i.closed {
		return nil
	}
	i.closed = true
	for j := i.at; j < len(i.rows); j++ {
		i.account.Release(i.rows[j].result.Bytes)
	}
	i.account.Release(i.indexBytes)
	i.indexBytes = 0
	i.rows = nil
	return nil
}
func (i *orderedLogs) Next(ctx context.Context) (PipelineResult, error) {
	if err := i.account.Check(ctx); err != nil {
		i.Close()
		return PipelineResult{}, boundaryErr(err)
	}
	if i.closed {
		return PipelineResult{}, io.EOF
	}
	if i.at == len(i.rows) {
		i.Close()
		return PipelineResult{}, io.EOF
	}
	r := i.rows[i.at].result
	i.rows[i.at] = orderedLog{}
	i.at++
	return r, nil
}

// discard drops a row that can no longer be part of the bounded prefix.
func (i *orderedLogs) discard(row *orderedLog) {
	i.account.Release(row.result.Bytes + row.index)
	i.indexBytes -= row.index
	i.truncated = true
}

// logBound is how much of the total order a merge must keep. units counts
// multiplicity, or rows when perRow is set; math.MaxUint64 keeps everything.
type logBound struct {
	units  uint64
	perRow bool
}

func (b logBound) bounded() bool { return b.units != math.MaxUint64 }
func (b logBound) cost(r *PipelineResult) uint64 {
	if b.perRow {
		return 1
	}
	return uint64(r.Entry.Multiplicity)
}

// MergeLogs accepts unsorted shard/page inputs. Equal text never identifies a
// record. Multiplicity is conserved and a requested limit may split a run.
// Timestamp ties between streams order by the original stream hash. A limit
// bounds the memory of the merge: only the entries that can still be among the
// first limit stay held (see mergeBounded).
func MergeLogs(ctx context.Context, inputs []EntryIterator, order LogOrder, limit uint64, account value.Account) (LogIterator, error) {
	return mergeLogs(ctx, inputs, order, limit, account, true)
}

// mergeLogs orders timestamp ties between streams by original stream hash when
// streamHash is set and otherwise, like the pinned engine whose readStreams loses
// the hash, by the label string of the streams.
func mergeLogs(ctx context.Context, inputs []EntryIterator, order LogOrder, limit uint64, account value.Account, streamHash bool) (LogIterator, error) {
	m, err := mergeBounded(ctx, inputs, order, logBound{units: limit}, account, streamHash)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// orderedBefore is the strict total order of the merge: time in the requested
// direction, then stream identity, then record identity, then arrival.
func orderedBefore(order LogOrder, left, right *orderedLog) bool {
	lt, rt := left.result.Entry.Timestamp, right.result.Entry.Timestamp
	if lt != rt {
		if order == Backward {
			return lt > rt
		}
		return lt < rt
	}
	// Equal timestamps: streams order by hash when both have one, else by label
	// string, ascending in either direction.
	if left.streamHash != 0 && right.streamHash != 0 {
		if left.streamHash != right.streamHash {
			return left.streamHash < right.streamHash
		}
		d := strings.Compare(left.labels, right.labels)
		if order == Backward {
			d = -d
		}
		if d != 0 {
			return d < 0
		}
	} else if d := strings.Compare(left.labels, right.labels); d != 0 {
		return d < 0
	}
	// Entries of one stream and timestamp keep the order they were encountered
	// in (record identity order) whichever way time is traversed; text never
	// orders them.
	if c := compareLogEncounter(left.result, right.result); c != 0 {
		return c < 0
	}
	return left.seq < right.seq
}

// The kept rows form a binary heap whose root is the row latest in the order,
// so the row that is cheapest to give up is always at hand.
func heapPush(rows *[]orderedLog, order LogOrder, row orderedLog) {
	*rows = append(*rows, row)
	h := *rows
	for i := len(h) - 1; i > 0; {
		p := (i - 1) / 2
		if !orderedBefore(order, &h[p], &h[i]) {
			break
		}
		h[p], h[i] = h[i], h[p]
		i = p
	}
}
func heapPopLatest(rows *[]orderedLog, order LogOrder) orderedLog {
	h := *rows
	latest := h[0]
	last := len(h) - 1
	h[0] = h[last]
	h[last] = orderedLog{}
	h = h[:last]
	*rows = h
	for i := 0; ; {
		c := 2*i + 1
		if c >= len(h) {
			break
		}
		if c+1 < len(h) && orderedBefore(order, &h[c], &h[c+1]) {
			c++
		}
		if !orderedBefore(order, &h[i], &h[c]) {
			break
		}
		h[i], h[c] = h[c], h[i]
		i = c
	}
	return latest
}

// mergeBounded merges unsorted inputs into the first bound.units of their total
// order. A row is given up as soon as the rows that precede it already cover the
// bound (a multiplicity run is split inside, never dropped whole, so a limit may
// cut a tied row), which keeps memory proportional to the bound, not to the
// matches. Budget failures stay errors; they never become a short result.
func mergeBounded(ctx context.Context, inputs []EntryIterator, order LogOrder, bound logBound, account value.Account, streamHash bool) (out *orderedLogs, err error) {
	defer func() { err = boundaryErr(err) }()
	if ctx == nil || account == nil || order != Forward && order != Backward {
		return nil, model.Fail(model.Invalid)
	}
	m := &orderedLogs{account: account}
	defer func() {
		for _, in := range inputs {
			if in != nil {
				closeErr := in.Close()
				if err == nil && closeErr != nil {
					err = closeErr
				}
			}
		}
		if err != nil {
			m.Close()
			out = nil
		}
	}()
	var hashBuffer []byte
	var kept, seq uint64
	for _, in := range inputs {
		if in == nil {
			return nil, model.Fail(model.Invalid)
		}
		for {
			if err = account.Check(ctx); err != nil {
				return nil, err
			}
			var r PipelineResult
			r, err = in.Next(ctx)
			if errors.Is(err, io.EOF) {
				err = nil
				break
			}
			if err != nil {
				return nil, err
			}
			if !r.Retained {
				account.Release(r.Bytes)
				continue
			}
			if r.Entry.Multiplicity == 0 {
				account.Release(r.Bytes)
				return nil, model.Fail(model.Corrupt)
			}
			if bound.units == 0 {
				// Nothing is wanted: inputs are still read to the end for their
				// partial/watermark metadata.
				account.Release(r.Bytes)
				m.truncated = true
				continue
			}
			if r.Bytes == 0 {
				r.Bytes = entryBytes(r.Entry) + int64(len(r.Labels))*64 + 128
				if err = account.Reserve(r.Bytes); err != nil {
					return nil, err
				}
				r.Entry = cloneLogEntry(r.Entry)
				r.Labels = value.CloneLabels(r.Labels)
			}
			// Stream identity as the pinned engine compares it: the Prometheus
			// label string {a="x", b="y"} of the query-visible labels.
			labels := labelString(r.Labels)
			scratch := int64(1024) + int64(len(labels))
			for _, l := range r.OriginalStreamLabels {
				scratch += int64(len(l.Name) + len(l.Value) + 2)
			}
			if err = account.Reserve(scratch); err != nil {
				account.Release(r.Bytes)
				return nil, err
			}
			m.indexBytes += scratch
			hash := uint64(0)
			if streamHash && len(r.OriginalStreamLabels) > 0 {
				hashBuffer = metricStreamHashBytes(hashBuffer, r.OriginalStreamLabels)
				hash = metricXXH64(hashBuffer)
			}
			row := orderedLog{result: r, streamHash: hash, labels: labels, index: scratch, seq: seq}
			seq++
			if !bound.bounded() {
				m.rows = append(m.rows, row)
				continue
			}
			// The kept rows already cover the bound: a row after all of them
			// cannot be among the first bound.units.
			if len(m.rows) > 0 && kept >= bound.units && !orderedBefore(order, &row, &m.rows[0]) {
				m.discard(&row)
				continue
			}
			heapPush(&m.rows, order, row)
			if kept += bound.cost(&r); kept < bound.cost(&r) {
				kept = math.MaxUint64
			}
			// Give up the latest row while the others still cover the bound. A
			// saturated total only ever under-reports, so this never drops a
			// row that is needed.
			for len(m.rows) > 0 {
				c := bound.cost(&m.rows[0].result)
				if kept < c || kept-c < bound.units {
					break
				}
				latest := heapPopLatest(&m.rows, order)
				kept -= c
				m.discard(&latest)
			}
		}
		value.InheritMetadata(&m.metadata, value.Result{Watermarks: in.Watermarks(), Partial: in.Partial()})
	}
	if err = metricSort(m.rows, func(a, b int) bool {
		return orderedBefore(order, &m.rows[a], &m.rows[b])
	}, func() error { return account.Check(ctx) }); err != nil {
		return nil, err
	}
	if err = account.Check(ctx); err != nil {
		return nil, err
	}
	keep := len(m.rows)
	if !bound.perRow {
		left := bound.units
		keep = 0
		for ; keep < len(m.rows) && left > 0; keep++ {
			r := &m.rows[keep].result
			n := uint64(r.Entry.Multiplicity)
			if n > left {
				r.Entry.Multiplicity = model.Uint64(left)
				left = 0
			} else {
				left -= n
			}
		}
		for j := keep; j < len(m.rows); j++ {
			account.Release(m.rows[j].result.Bytes)
			m.indexBytes -= m.rows[j].index
			account.Release(m.rows[j].index)
			m.truncated = true
		}
		m.rows = m.rows[:keep]
	}
	return m, nil
}

// labelString renders labels as Prometheus does: {name="value", name2="value2"}. The result is built in one
// allocation sized for the plain case; a value that needs escapes takes strconv.Quote, as it always did.
func labelString(ls model.Labels) string {
	n := 2
	for _, l := range ls {
		n += len(l.Name) + len(l.Value) + 5
	}
	var b strings.Builder
	b.Grow(n)
	b.WriteByte('{')
	for i, l := range ls {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(l.Name)
		b.WriteByte('=')
		if plainQuoted(l.Value) {
			b.WriteByte('"')
			b.WriteString(l.Value)
			b.WriteByte('"')
		} else {
			b.WriteString(strconv.Quote(l.Value))
		}
	}
	b.WriteByte('}')
	return b.String()
}

// plainQuoted reports whether strconv.Quote(v) is v between double quotes: printable ASCII without a quote or
// a backslash.
func plainQuoted(v string) bool {
	for i := range len(v) {
		if c := v[i]; c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// compareLogEncounter orders records of one stream and timestamp by identity.
func compareLogEncounter(a, b PipelineResult) int {
	if c := bytes.Compare(a.Entry.ID[:], b.Entry.ID[:]); c != 0 {
		return c
	}
	if c := bytes.Compare(a.Entry.Source[:], b.Entry.Source[:]); c != 0 {
		return c
	}
	return strings.Compare(a.Entry.Line, b.Entry.Line)
}

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
}
type orderedLogs struct {
	rows       []orderedLog
	at         int
	metadata   value.Result
	account    value.Account
	indexBytes int64
	closed     bool
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
		return PipelineResult{}, err
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

// MergeLogs accepts unsorted shard/page inputs. Equal text never identifies a
// record. Multiplicity is conserved and a requested limit may split a run.
// Timestamp ties between streams order by the original stream hash.
func MergeLogs(ctx context.Context, inputs []EntryIterator, order LogOrder, limit uint64, account value.Account) (LogIterator, error) {
	return mergeLogs(ctx, inputs, order, limit, account, true)
}

// mergeLogs orders timestamp ties between streams by original stream hash when
// streamHash is set and otherwise, like the pinned engine whose readStreams loses
// the hash, by the label string of the streams.
func mergeLogs(ctx context.Context, inputs []EntryIterator, order LogOrder, limit uint64, account value.Account, streamHash bool) (out LogIterator, err error) {
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
			m.rows = append(m.rows, orderedLog{result: r, streamHash: hash, labels: labels})
		}
		value.InheritMetadata(&m.metadata, value.Result{Watermarks: in.Watermarks(), Partial: in.Partial()})
	}
	if err = metricSort(m.rows, func(a, b int) bool {
		left, right := &m.rows[a], &m.rows[b]
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
		return compareLogEncounter(left.result, right.result) < 0
	}, func() error { return account.Check(ctx) }); err != nil {
		return nil, err
	}
	if err = account.Check(ctx); err != nil {
		return nil, err
	}
	left := limit
	keep := 0
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
	}
	m.rows = m.rows[:keep]
	return m, nil
}

// labelString renders labels as Prometheus does: {name="value", name2="value2"}.
func labelString(ls model.Labels) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, l := range ls {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(l.Name)
		b.WriteByte('=')
		b.WriteString(strconv.Quote(l.Value))
	}
	b.WriteByte('}')
	return b.String()
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

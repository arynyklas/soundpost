// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"unsafe"

	"github.com/arynyklas/soundpost/internal/model"
)

// pageFastDecode switches the typed column decoders below off, for the tests that compare them with the
// generic (reflection) decoder of encoding.go.
var pageFastDecode = true

// The generic column decoder walks every value of a page through reflection: at the Queries gate the
// decode of the pages of a metric query was 35 s of the 449 CPU seconds of a ten-query mix, and the
// allocations behind it a good part of the garbage collector's 45. The columns a scan reads on every page
// have a fixed shape, so they are decoded by typed loops that read the same bytes the encoder wrote and
// build the same values. A typed decoder takes only a column that is exactly well formed; it reports false
// for anything else (a different payload kind, a histogram, an exemplar, a truncated or overlong column),
// and the generic decoder then decodes the column, and reports its error if it has one. So the typed
// decoders can never accept what the generic one refuses nor build what it would not.

// fastDecodeColumn decodes column i of a page of n rows with its typed decoder and reports whether there
// is one that accepted the column. delta is the time column's destination (the times are rebuilt from it).
func fastDecodeColumn(i int, column []byte, n int, p *Page, delta *[]uint64) bool {
	if !pageFastDecode {
		return false
	}
	var ok bool
	switch i {
	case 0:
		p.IDs, ok = fastIDs(column, n)
	case 1:
		*delta, ok = fastUvarints(column, n)
	case 3:
		p.Values, ok = fastMetricPayloads(column, n)
		if !ok {
			p.Values, ok = fastLogPayloads(column, n)
		}
	case 4:
		p.Origins, ok = fastCursors(column, n)
	case 5:
		p.Projects, ok = fastIDs(column, n)
	case 6:
		p.Sources, ok = fastIDs(column, n)
	case 7:
		p.Loss, ok = fastUvarints(column, n)
	case 8:
		p.ObservedTimes, ok = fastTimes(column, n)
	}
	return ok
}

// columnBody is the elements of a column whose header (the count, n+1) the caller has checked.
func columnBody(column []byte) ([]byte, bool) {
	_, k := binary.Uvarint(column)
	if k <= 0 {
		return nil, false
	}
	return column[k:], true
}

func fastIDs(column []byte, n int) ([]model.ID, bool) {
	b, ok := columnBody(column)
	if !ok || len(b) != n*16 {
		return nil, false
	}
	out := make([]model.ID, n)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&out[0])), n*16), b)
	return out, true
}

func fastUvarints(column []byte, n int) ([]uint64, bool) {
	b, ok := columnBody(column)
	if !ok {
		return nil, false
	}
	out := make([]uint64, n)
	for i := range out {
		v, k := binary.Uvarint(b)
		if k <= 0 {
			return nil, false
		}
		out[i], b = v, b[k:]
	}
	return out, len(b) == 0
}

func fastTimes(column []byte, n int) ([]model.UnixNano, bool) {
	b, ok := columnBody(column)
	if !ok {
		return nil, false
	}
	out := make([]model.UnixNano, n)
	for i := range out {
		v, k := binary.Uvarint(b)
		if k <= 0 {
			return nil, false
		}
		out[i], b = model.UnixNano(int64(v>>1)^-int64(v&1)), b[k:]
	}
	return out, len(b) == 0
}

func fastCursors(column []byte, n int) ([]model.Cursor, bool) {
	b, ok := columnBody(column)
	if !ok {
		return nil, false
	}
	out := make([]model.Cursor, n)
	for i := range out {
		if len(b) < 16 {
			return nil, false
		}
		copy(out[i].Group[:], b)
		v, k := binary.Uvarint(b[16:])
		if k <= 0 {
			return nil, false
		}
		out[i].Index, b = model.Uint64(v), b[16+k:]
	}
	return out, len(b) == 0
}

// payloadReader reads the varints and the dictionary strings of one column, as columnDecoder does; a read
// that fails makes the whole column a fallback.
type payloadReader struct {
	b     []byte
	dict  []string
	arena strings.Builder // the bytes of every string of the column, in one allocation
	bad   bool
}

func (r *payloadReader) u() uint64 {
	v, k := binary.Uvarint(r.b)
	if k <= 0 {
		r.bad = true
		return 0
	}
	r.b = r.b[k:]
	return v
}

func (r *payloadReader) text() string {
	n := r.u()
	id := n >> 1
	if n&1 == 0 {
		if id >= uint64(len(r.dict)) {
			r.bad = true
			return ""
		}
		return r.dict[id]
	}
	if id != uint64(len(r.dict)) {
		r.bad = true
		return ""
	}
	size := r.u()
	if r.bad || size > uint64(len(r.b)) {
		r.bad = true
		return ""
	}
	if r.arena.Cap() == 0 {
		// The strings of a column are copies of bytes of the column: one buffer of the size of what is
		// left holds them all, and a string is a view of it (the builder never moves bytes it holds
		// while it does not outgrow its capacity, which it cannot here). A string of its own per
		// text was most of the allocations of a log page.
		r.arena.Grow(len(r.b))
	}
	at := r.arena.Len()
	r.arena.Write(r.b[:size])
	s := r.arena.String()[at:]
	r.b = r.b[size:]
	r.dict = append(r.dict, s)
	return s
}

// fastMetricPayloads decodes a payload column whose rows all carry a metric point of the plain shape: a
// float value or none, an optional start timestamp, no histogram and no exemplar.
func fastMetricPayloads(column []byte, n int) ([]model.Payload, bool) {
	r := payloadReader{b: column}
	if r.u() != uint64(n)+1 || r.bad {
		return nil, false
	}
	out := make([]model.Payload, n)
	points := make([]model.MetricPoint, n)
	floats := make([]model.FloatBits, n)
	var starts []model.UnixNano
	var labels []model.Label
	for i := range out {
		if r.u() != 1 { // Payload.Metric present
			return nil, false
		}
		mp := &points[i]
		mp.Name = r.text()
		switch c := r.u(); {
		case c == 0:
		case c-1 > uint64(len(r.b)):
			return nil, false
		default:
			size := int(c - 1)
			if size == 0 {
				mp.Labels = model.Labels{}
				break
			}
			if cap(labels)-len(labels) < size {
				labels = make([]model.Label, 0, max(size, 4*n))
			}
			start := len(labels)
			labels = labels[:start+size]
			for j := start; j < start+size; j++ {
				labels[j].Name = r.text()
				labels[j].Value = r.text()
			}
			mp.Labels = labels[start : start+size : start+size]
		}
		mp.SampleKind = r.text()
		switch r.u() { // Value
		case 0:
		case 1:
			floats[i] = model.FloatBits(r.u())
			mp.Value = &floats[i]
		default:
			return nil, false
		}
		if r.u() != 0 { // Histogram
			return nil, false
		}
		switch r.u() { // StartTimestamp
		case 0:
		case 1:
			if starts == nil {
				starts = make([]model.UnixNano, n)
			}
			v := r.u()
			starts[i] = model.UnixNano(int64(v>>1) ^ -int64(v&1))
			mp.StartTimestamp = &starts[i]
		default:
			return nil, false
		}
		mp.Unit = r.text()
		mp.Type = r.text()
		if r.u() != 0 || r.u() != 0 { // ExemplarTrace, ExemplarSpan
			return nil, false
		}
		for range 9 { // Log, Span, Error, Job, Replay, Profile, Capability, Loss, Condition
			if r.u() != 0 {
				return nil, false
			}
		}
		if r.bad {
			return nil, false
		}
		out[i].Metric = mp
	}
	return out, len(r.b) == 0
}

// fastLogPayloads decodes a payload column whose rows all carry a log record and nothing else, the shape
// every log page has. Fields and structured metadata are maps of canonical scalars; a scalar that is not
// in canonical form, a repeated map key or any other irregularity is a fallback to the generic decoder.
func fastLogPayloads(column []byte, n int) ([]model.Payload, bool) {
	r := payloadReader{b: column}
	if r.u() != uint64(n)+1 || r.bad {
		return nil, false
	}
	out := make([]model.Payload, n)
	logs := make([]model.LogRecord, n)
	var stamps []model.UnixNano
	var ids []model.ID
	var spans []model.SpanID
	var labels []model.Label
	for i := range out {
		if r.u() != 0 { // Payload.Metric absent
			return nil, false
		}
		if r.u() != 1 { // Payload.Log present
			return nil, false
		}
		l := &logs[i]
		switch r.u() { // Timestamp
		case 0:
		case 1:
			if stamps == nil {
				stamps = make([]model.UnixNano, n)
			}
			v := r.u()
			stamps[i] = model.UnixNano(int64(v>>1) ^ -int64(v&1))
			l.Timestamp = &stamps[i]
		default:
			return nil, false
		}
		l.Severity = r.text()
		l.TemplateID = r.text()
		l.TemplateRevision = model.Revision(r.u())
		var ok bool
		if l.Fields, ok = r.scalars(); !ok {
			return nil, false
		}
		l.Line = r.text()
		switch c := r.u(); { // StreamLabels
		case c == 0:
		case c-1 > uint64(len(r.b)) || c-1 > 65536:
			return nil, false
		default:
			size := int(c - 1)
			if size == 0 {
				l.StreamLabels = model.Labels{}
				break
			}
			if cap(labels)-len(labels) < size {
				labels = make([]model.Label, 0, max(size, 4*n))
			}
			start := len(labels)
			labels = labels[:start+size]
			for j := start; j < start+size; j++ {
				labels[j].Name = r.text()
				labels[j].Value = r.text()
			}
			l.StreamLabels = labels[start : start+size : start+size]
		}
		if l.Metadata, ok = r.scalars(); !ok {
			return nil, false
		}
		l.SourceClass = r.text()
		switch r.u() { // Trace
		case 0:
		case 1:
			if len(r.b) < 16 {
				return nil, false
			}
			if ids == nil {
				ids = make([]model.ID, 2*n)
			}
			copy(ids[2*i][:], r.b)
			r.b = r.b[16:]
			l.Trace = &ids[2*i]
		default:
			return nil, false
		}
		switch r.u() { // Span
		case 0:
		case 1:
			if len(r.b) < 8 {
				return nil, false
			}
			if spans == nil {
				spans = make([]model.SpanID, n)
			}
			copy(spans[i][:], r.b)
			r.b = r.b[8:]
			l.Span = &spans[i]
		default:
			return nil, false
		}
		switch r.u() { // Run
		case 0:
		case 1:
			if len(r.b) < 16 {
				return nil, false
			}
			if ids == nil {
				ids = make([]model.ID, 2*n)
			}
			copy(ids[2*i+1][:], r.b)
			r.b = r.b[16:]
			l.Run = &ids[2*i+1]
		default:
			return nil, false
		}
		for range 8 { // Span, Error, Job, Replay, Profile, Capability, Loss, Condition
			if r.u() != 0 {
				return nil, false
			}
		}
		if r.bad {
			return nil, false
		}
		out[i].Log = l
	}
	return out, len(r.b) == 0
}

// scalars reads a map of canonical scalars: 0 is a nil map, k+1 is k sorted entries.
func (r *payloadReader) scalars() (map[string]model.Scalar, bool) {
	c := r.u()
	if r.bad || c > uint64(len(r.b))+1 || c > 65537 {
		return nil, false
	}
	if c == 0 {
		return nil, true
	}
	size := int(c - 1)
	m := make(map[string]model.Scalar, size)
	for range size {
		k := r.text()
		text := r.text()
		s, ok := model.ScalarFromCanonical(text)
		if r.bad {
			return nil, false
		}
		if !ok && json.Unmarshal([]byte(text), &s) != nil { // the generic decoder's second path
			return nil, false
		}
		if _, dup := m[k]; dup {
			return nil, false
		}
		m[k] = s
	}
	return m, true
}

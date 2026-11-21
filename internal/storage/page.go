// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"encoding/binary"
	"github.com/arynyklas/soundpost/internal/model"
	"hash/crc32"
)

var pageCRC = crc32.MakeTable(crc32.Castagnoli)

const pageHeaderSize = 16 + 9*8

func encodePage(p Page) ([]byte, error) {
	if p.Len() == 0 || p.Len() > pageRows {
		return nil, model.Fail(model.Invalid)
	}
	columns := []any{p.IDs, p.Times, p.Resources, p.Values, p.Origins, p.Projects, p.Sources, p.Loss, p.ObservedTimes}
	out := make([]byte, pageHeaderSize)
	copy(out, "SPP1")
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[6:8], 9)
	binary.BigEndian.PutUint32(out[8:12], uint32(p.Len()))
	// Times use modulo-2^64 delta coding; wrap is reversible without signed overflow.
	delta := make([]uint64, len(p.Times))
	var previous uint64
	for i, t := range p.Times {
		delta[i] = uint64(t) - previous
		previous = uint64(t)
	}
	columns[1] = delta
	for i, c := range columns {
		b, err := encodeColumn(c)
		if err != nil {
			return nil, err
		}
		binary.BigEndian.PutUint32(out[16+i*8:], uint32(len(out)))
		binary.BigEndian.PutUint32(out[20+i*8:], uint32(len(b)))
		out = append(out, b...)
	}
	if len(out) > pageByteLimit {
		return nil, model.Fail(model.TooLarge)
	}
	binary.BigEndian.PutUint32(out[12:16], crc32.Checksum(out[16:], pageCRC))
	return out, nil
}
func decodePage(b []byte) (Page, error) { return decodePageColumns(b, true, true) }
func decodePageColumns(b []byte, resources, payload bool) (Page, error) {
	var p Page
	if len(b) < pageHeaderSize || len(b) > pageByteLimit || !bytes.Equal(b[:4], []byte("SPP1")) || binary.BigEndian.Uint16(b[4:6]) != 1 || binary.BigEndian.Uint16(b[6:8]) != 9 || crc32.Checksum(b[16:], pageCRC) != binary.BigEndian.Uint32(b[12:16]) {
		return p, model.Fail(model.Corrupt)
	}
	n := int(binary.BigEndian.Uint32(b[8:12]))
	if n < 1 || n > pageRows {
		return p, model.Fail(model.Corrupt)
	}
	var delta []uint64
	columns := []any{&p.IDs, &delta, &p.Resources, &p.Values, &p.Origins, &p.Projects, &p.Sources, &p.Loss, &p.ObservedTimes}
	offset := pageHeaderSize
	for i, c := range columns {
		start := int(binary.BigEndian.Uint32(b[16+i*8:]))
		size := int(binary.BigEndian.Uint32(b[20+i*8:]))
		if start != offset || size > len(b)-start || start < pageHeaderSize {
			return Page{}, model.Fail(model.Corrupt)
		}
		column := b[start : start+size]
		count, encoded := binary.Uvarint(column)
		if encoded <= 0 || count != uint64(n+1) {
			return Page{}, model.Fail(model.Corrupt)
		}
		skip := i == 2 && !resources || i == 3 && !payload
		if !skip {
			if err := decodeColumn(column, c); err != nil {
				return Page{}, err
			}
		}
		offset += size
	}
	if offset != len(b) {
		return Page{}, model.Fail(model.Corrupt)
	}
	if !resources {
		p.Resources = make([]model.Resource, n)
	}
	if !payload {
		p.Values = make([]model.Payload, n)
	}
	if len(p.IDs) != n || len(delta) != n || len(p.Resources) != n || len(p.Values) != n || len(p.Origins) != n || len(p.Projects) != n || len(p.Sources) != n || len(p.Loss) != n || len(p.ObservedTimes) != n {
		return Page{}, model.Fail(model.Corrupt)
	}
	p.Times = make([]model.UnixNano, n)
	var at uint64
	for i, d := range delta {
		at += d
		p.Times[i] = model.UnixNano(at)
	}
	p.Bytes = uint64(len(b))
	return p, nil
}
func allocatePage(capacity int) Page {
	return Page{IDs: make([]model.ID, 0, capacity), Times: make([]model.UnixNano, 0, capacity), ObservedTimes: make([]model.UnixNano, 0, capacity), Resources: make([]model.Resource, 0, capacity), Values: make([]model.Payload, 0, capacity), Origins: make([]model.Cursor, 0, capacity), Projects: make([]model.ID, 0, capacity), Sources: make([]model.ID, 0, capacity), Loss: make([]uint64, 0, capacity)}
}
func appendPageRow(dst *Page, src Page, i int) {
	if dst.IDs == nil {
		*dst = allocatePage(src.Len())
	}
	dst.IDs = append(dst.IDs, src.IDs[i])
	dst.Times = append(dst.Times, src.Times[i])
	dst.ObservedTimes = append(dst.ObservedTimes, src.ObservedTimes[i])
	dst.Resources = append(dst.Resources, src.Resources[i])
	dst.Values = append(dst.Values, src.Values[i])
	dst.Origins = append(dst.Origins, src.Origins[i])
	dst.Projects = append(dst.Projects, src.Projects[i])
	dst.Sources = append(dst.Sources, src.Sources[i])
	dst.Loss = append(dst.Loss, src.Loss[i])
}
func recordsPage(rows []model.Record, project, source model.ID, cursor model.Cursor) Page {
	p := allocatePage(len(rows))
	for _, r := range rows {
		p.IDs = append(p.IDs, r.ID)
		p.Times = append(p.Times, signalTime(r))
		p.ObservedTimes = append(p.ObservedTimes, r.ObservedAt)
		p.Resources = append(p.Resources, r.Resource)
		p.Values = append(p.Values, r.Payload)
		p.Origins = append(p.Origins, cursor)
		p.Projects = append(p.Projects, project)
		p.Sources = append(p.Sources, source)
		p.Loss = append(p.Loss, payloadLoss(&r.Payload))
	}
	return p
}
func signalTime(r model.Record) model.UnixNano {
	switch r.Kind {
	case model.Log:
		if r.Payload.Log.Timestamp != nil {
			return *r.Payload.Log.Timestamp
		}
	case model.SpanKind:
		return r.Payload.Span.Start.Wall
	case model.JobAttempt:
		return r.Payload.Job.Observed
	case model.Replay:
		return r.Payload.Replay.Clock.Wall
	case model.Profile:
		return r.Payload.Profile.Start
	case model.Loss:
		return r.Payload.Loss.Start
	case model.Condition:
		return r.Payload.Condition.At
	}
	return r.ObservedAt
}

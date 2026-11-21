// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
	"hash/crc32"
)

var signalKinds = []model.Kind{model.Metric, model.Log, model.SpanKind, model.ErrorKind, model.JobAttempt, model.Replay, model.Profile, model.CapabilityKind, model.Loss, model.Condition}

func signalCode(k model.Kind) byte {
	for i, v := range signalKinds {
		if v == k {
			return byte(i + 1)
		}
	}
	return 0
}
func namespace(org, project model.ID, k model.Kind, raw bool, source model.ID) []byte {
	p := append([]byte(nil), org[:]...)
	p = append(p, project[:]...)
	p = append(p, signalCode(k), 0)
	if raw {
		p[len(p)-1] = 1
		p = append(p, source[:]...)
	}
	return p
}
func timeKey(t model.UnixNano) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(t)^1<<63)
	return b[:]
}

type pageRef struct {
	ID             model.ID
	Org            model.ID
	Project        model.ID
	Source         model.ID
	Kind, Subject  model.Kind
	Restricted     bool
	PolicyRevision model.Revision
	Start, End     model.UnixNano
	Count          uint32
	Segment        string
	Offset         int64
	Length         uint32
	Hash           model.Hash
	RetainUntil    model.UnixNano
	Hot            []byte
}

func pageRefBytes(p pageRef) ([]byte, error) { return json.Marshal(p) }
func parsePageRef(b []byte) (pageRef, error) {
	var p pageRef
	if json.Unmarshal(b, &p) != nil || p.ID == (model.ID{}) || p.PolicyRevision == 0 || p.Count == 0 || p.Count > pageRows || p.Length > pageByteLimit || !p.Kind.Valid() || !validSubject(p.Kind, p.Subject) {
		return p, model.Fail(model.Corrupt)
	}
	return p, nil
}
func (e *Engine) indexAppliedRows(tx *bolt.Tx, b model.NormalizedBatch, receipt model.Receipt, rows []model.Record) error {
	pages, commits := tx.Bucket([]byte("scan_pages")), tx.Bucket([]byte("scan_commits"))
	if pages == nil || commits == nil || b.PolicyRevision == 0 {
		return model.Fail(model.Corrupt)
	}
	index, err := newIndexWriter(tx, "scan_time")
	if err != nil {
		return err
	}
	postings, err := newIndexWriter(tx, "scan_postings")
	if err != nil {
		return err
	}
	pageIDs := make([]committedPage, 0)
	for _, r := range rows {
		if !r.Kind.Valid() || signalCode(r.Kind) == 0 || !validSubject(r.Kind, recordSubject(r)) {
			return model.Fail(model.Corrupt)
		}
		if _, err := r.Payload.Value(r.Kind); err != nil {
			return model.Fail(model.Corrupt)
		}
	}
	for _, kind := range signalKinds {
		for _, raw := range []bool{false, true} {
			for _, subject := range storageSubjects(kind) {
				var selected []model.Record
				chunk := 0
				write := func() error {
					if len(selected) == 0 {
						return nil
					}
					p := recordsPage(selected, b.Project, b.Source, receipt.Cursor)
					data, err := encodePage(p)
					if err != nil {
						return err
					}
					identity := model.HashCanonical([]byte(fmt.Sprintf("%s:%s:%s:%s:%d:%s:%s:%t:%d", b.Org, b.Project, b.ID, receipt.Cursor.Group, receipt.Cursor.Index, kind, subject, raw, chunk)))
					var id model.ID
					copy(id[:], identity[:16])
					ref := pageRef{ID: id, Org: b.Org, Project: b.Project, Source: b.Source, Kind: kind, Subject: subject, Restricted: raw, PolicyRevision: b.PolicyRevision, Start: signalTime(selected[0]), End: signalTime(selected[0]), Count: uint32(len(selected)), Length: uint32(len(data)), Hash: model.HashCanonical(data), Hot: data}
					for _, d := range receipt.SignalDeadlines {
						if d.Kind == kind {
							ref.RetainUntil = d.RetainUntil
						}
					}
					prefix := pageNamespace(b.Org, b.Project, kind, raw, b.Source, subject)
					for i, r := range selected {
						at := signalTime(r)
						if at < ref.Start {
							ref.Start = at
						}
						if at > ref.End {
							ref.End = at
						}
						key := append(append([]byte(nil), prefix...), timeKey(at)...)
						key = append(key, r.ID[:]...)
						key = append(key, receipt.Cursor.Group[:]...)
						var tail [10]byte
						binary.BigEndian.PutUint64(tail[:8], uint64(receipt.Cursor.Index))
						binary.BigEndian.PutUint16(tail[8:], uint16(i))
						key = append(key, tail[:]...)
						value := append(append([]byte(nil), id[:]...), tail[8:]...)
						if err = index.put(key, indexValue(key, value)); err != nil {
							return err
						}
						for _, term := range recordTerms(r) {
							pk := termPrefix(prefix, term)
							pk = append(pk, key[len(prefix):]...)
							if err = postings.put(pk, indexValue(pk, value)); err != nil {
								return err
							}
						}
					}
					meta, err := pageRefBytes(ref)
					if err != nil {
						return err
					}
					if pages.Get(id[:]) != nil {
						return model.Fail(model.Corrupt)
					}
					if err = pages.Put(id[:], meta); err != nil {
						return err
					}
					pageIDs = append(pageIDs, committedPage{ID: id, Kind: kind, Subject: subject, Restricted: raw, Source: b.Source})
					selected = selected[:0]
					chunk++
					return nil
				}
				for _, r := range rows {
					restricted := r.Payload.Log != nil && r.Payload.Log.SourceClass == "restricted_raw"
					if r.Kind != kind || restricted != raw || recordSubject(r) != subject {
						continue
					}
					if selected == nil {
						selected = make([]model.Record, 0, min(pageRows, len(rows)))
					}
					selected = append(selected, r)
					if len(selected) == pageRows {
						if err = write(); err != nil {
							return err
						}
					}
				}
				if err = write(); err != nil {
					return err
				}
			}
		}
	}
	if err = index.finish(); err != nil {
		return err
	}
	if err = postings.finish(); err != nil {
		return err
	}
	raw, err := json.Marshal(pageIDs)
	if err != nil {
		return err
	}
	return commits.Put(commitKey(receipt.Cursor), raw)
}
func recordTerms(r model.Record) []string {
	terms := []string{"id=" + r.ID.String(), "service_id=" + r.Resource.Service.String(), "environment_id=" + r.Resource.Environment.String(), "build_id=" + r.Resource.Build.String()}
	labels := r.Resource.Labels
	if r.Payload.Metric != nil {
		terms = append(terms, "name="+r.Payload.Metric.Name)
		labels = r.Payload.Metric.Labels
	}
	if r.Payload.Log != nil {
		terms = append(terms, "severity="+r.Payload.Log.Severity, "template_id="+r.Payload.Log.TemplateID)
		labels = r.Payload.Log.StreamLabels
	}
	if r.Payload.Condition != nil {
		terms = append(terms, "severity="+r.Payload.Condition.Severity)
		labels = r.Payload.Condition.Labels
	}
	for _, l := range labels {
		terms = append(terms, "label:"+l.Name+"="+l.Value)
	}
	return typedRecordTerms(r, referenceTerms(r, terms))
}
func samePrefix(k, prefix []byte) bool { return bytes.HasPrefix(k, prefix) }
func termPrefix(namespace []byte, term string) []byte {
	p := append([]byte(nil), namespace...)
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(term)))
	p = append(p, size[:]...)
	return append(p, term...)
}
func postingTerm(ms []Matcher, kind model.Kind) string {
	for _, m := range ms {
		if m.Op != MatchEqual || m.Literal.Kind == LiteralString && m.Literal.String == "" {
			continue
		}
		if m.Target == MatchLabel {
			return "label:" + m.Name + "=" + m.Literal.String
		}
		if m.Literal.Kind == LiteralString {
			if isIDField(m.Name) && m.Name != "source_id" || m.Name == "span_id" {
				return m.Name + "=" + m.Literal.String
			}
			if m.Name == "name" && kind == model.Metric || m.Name == "severity" && (kind == model.Log || kind == model.Condition) || m.Name == "template_id" && kind == model.Log {
				return m.Name + "=" + m.Literal.String
			}
			if kind == model.Log && m.Name == "line" {
				if tokens := lineTokens(m.Literal.String); len(tokens) > 0 {
					return "token:" + tokens[0]
				}
				continue
			}
		}
		if nativePosting(kind, m.Name) {
			return "typed:" + m.Name + "=" + literalKey(m.Literal)
		}
		if kind == model.Log && logScalarPosting(m.Name) && m.Literal.Kind != LiteralFloatBits {
			return "field:" + m.Name + "=" + literalKey(m.Literal)
		}
	}
	return ""
}
func indexValue(key, value []byte) []byte {
	out := make([]byte, 22)
	copy(out, value)
	sum := crc32.Update(crc32.Checksum(key, pageCRC), pageCRC, out[:18])
	binary.BigEndian.PutUint32(out[18:], sum)
	return out
}
func validIndexValue(key, value []byte) bool {
	return len(value) == 22 && crc32.Update(crc32.Checksum(key, pageCRC), pageCRC, value[:18]) == binary.BigEndian.Uint32(value[18:])
}
func referenceTerms(r model.Record, terms []string) []string {
	add := func(name string, id model.ID) {
		if id != (model.ID{}) {
			terms = append(terms, name+"="+id.String())
		}
	}
	optional := func(name string, id *model.ID) {
		if id != nil {
			add(name, *id)
		}
	}
	span := func(id *model.SpanID) {
		if id != nil {
			terms = append(terms, "span_id="+spanText(*id))
		}
	}
	v := r.Payload
	if v.Span != nil {
		add("trace_id", v.Span.Trace)
		terms = append(terms, "span_id="+spanText(v.Span.ID))
		optional("job_id", v.Span.Job)
		optional("replay_id", v.Span.Replay)
		optional("profile_id", v.Span.Profile)
	}
	if v.Log != nil {
		optional("trace_id", v.Log.Trace)
		optional("run_id", v.Log.Run)
		span(v.Log.Span)
	}
	if v.Error != nil {
		add("occurrence_id", v.Error.Occurrence)
		optional("trace_id", v.Error.Trace)
		optional("run_id", v.Error.Run)
		optional("replay_id", v.Error.Replay)
		optional("profile_id", v.Error.Profile)
		optional("release_id", v.Error.Release)
		span(v.Error.Span)
	}
	if v.Job != nil {
		add("job_id", v.Job.Job)
		add("run_id", v.Job.Run)
		add("attempt_id", v.Job.Attempt)
		add("epoch_id", v.Job.Epoch)
	}
	if v.Replay != nil {
		add("replay_id", v.Replay.Replay)
		add("session_id", v.Replay.Session)
	}
	if v.Profile != nil {
		add("profile_id", v.Profile.Profile)
		add("process_id", v.Profile.Process)
		add("capability_id", v.Profile.Capability)
	}
	if v.Loss != nil {
		add("producer_id", v.Loss.Producer)
		add("epoch_id", v.Loss.Epoch)
	}
	if v.Condition != nil {
		add("condition_id", v.Condition.Condition)
		add("epoch_id", v.Condition.Epoch)
	}
	return terms
}

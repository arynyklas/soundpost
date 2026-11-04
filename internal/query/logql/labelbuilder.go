// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"slices"
	"soundpost/internal/model"
)

// Label builder: how the json, logfmt, regexp, pattern and unpack stages write
// parsed labels.
//
// A label name lives in one of three categories of an entry: stream (the
// immutable selector namespace at pipeline entry), structured metadata (owned
// by the ingest side) and parsed (written by stages). The reference reacts to a
// parser write that meets an existing name as follows, observed row by row:
//
//	plain stage (`| json`, `| logfmt`), key k, sanitized name n
//	  n is a stream name        -> the value goes to n_extracted
//	  n is structured metadata  -> the write is discarded, the metadata value stays
//	  n is parsed or free       -> the value is set; the last duplicate wins
//
//	expression stage (`| json x="p"`, `| logfmt x="p"`), requested label x
//	  x is a stream name, key present  -> the value goes to x_extracted
//	  x is a stream name, key absent   -> nothing at all (no x, no x_extracted)
//	  x is metadata or parsed or free  -> the value replaces it (metadata is
//	                                      taken over by the parsed category)
//	  key absent, x not a stream name  -> x is set to "" by logfmt; by json only
//	                                      when no category holds x already
//	  logfmt only: the first value of a renamed label wins, and a second write to
//	  an already-parsed x_extracted ends the scan of the line with no further
//	  extraction and no strict-mode error for the unread rest. json reports
//	  the first match of each path by construction.
//
// The stream namespace is the one captured when the pipeline started, so a
// later stage that removes a stream label does not change what collides.

// stageLabels is the label builder of ONE parser stage on one entry. Writes
// are collected per stage and merged into the sorted parsed category once, by
// flush, so a stage that writes n labels costs O(n log n) instead of n sorted
// insertions. Membership tests against the categories that exist before the
// stage use a linear scan for small slices and a lazily built hash set for
// large ones. Every stage that creates a builder defers flush, so labels read
// before a scanner error are kept exactly as with in-place writes.
type stageLabels struct {
	e        *LogEntry
	stream   nameSet
	parsed   nameSet // parsed labels from EARLIER stages
	meta     nameSet
	pending  map[string]string   // this stage's writes (final names)
	metaGone map[string]struct{} // metadata names taken over by this stage
}

const nameSetLinear = 32

// nameSet is a membership test over a label slice that is not modified while the set is used.
type nameSet struct {
	ls model.Labels
	m  map[string]struct{}
}

func (s *nameSet) has(n string) bool {
	if len(s.ls) <= nameSetLinear {
		return labelPresent(s.ls, n)
	}
	if s.m == nil {
		s.m = make(map[string]struct{}, len(s.ls))
		for _, l := range s.ls {
			s.m[l.Name] = struct{}{}
		}
	}
	_, ok := s.m[n]
	return ok
}

func newStageLabels(e *LogEntry) *stageLabels {
	base := e.baseStream
	if base == nil {
		base = e.StreamLabels
	}
	return &stageLabels{e: e, stream: nameSet{ls: base}, parsed: nameSet{ls: e.ParsedLabels}, meta: nameSet{ls: e.StructuredMetadata}}
}

// streamHas reports whether n is a stream-namespace name.
func (w *stageLabels) streamHas(n string) bool { return w.stream.has(n) }

// extractedName returns the parsed-category name a write for n lands on.
func (w *stageLabels) extractedName(n string) string {
	if w.streamHas(n) {
		n += "_extracted"
	}
	return n
}

func (w *stageLabels) hasParsed(n string) bool {
	if _, ok := w.pending[n]; ok {
		return true
	}
	return w.parsed.has(n)
}

func (w *stageLabels) hasMeta(n string) bool {
	if _, gone := w.metaGone[n]; gone {
		return false
	}
	return w.meta.has(n)
}

// has reports whether any category holds n.
func (w *stageLabels) has(n string) bool {
	return w.hasParsed(n) || w.hasMeta(n) || w.streamHas(n)
}

// shadowedKey is the name a line key takes in expression mode. A key naming an
// existing structured-metadata or parsed label is renamed key_extracted before
// request paths are matched, unless the stage itself requests a label of that
// name (that label takes the key over). A request path equal to the plain key
// therefore no longer finds it. Stream names do not shadow: a path naming a
// stream label still finds the key.
func (w *stageLabels) shadowedKey(k string, requested map[string]bool) string {
	if requested[k] {
		return k
	}
	if w.hasMeta(k) || w.hasParsed(k) {
		return k + "_extracted"
	}
	return k
}

func (w *stageLabels) set(n, v string) {
	if w.pending == nil {
		w.pending = make(map[string]string)
	}
	w.pending[n] = v
}

// putExtracted is the plain-stage write: a name owned by structured metadata is
// left alone.
func (w *stageLabels) putExtracted(n, v string) {
	n = w.extractedName(n)
	if w.hasMeta(n) && !w.hasParsed(n) {
		return
	}
	w.set(n, v)
}

// putRequested is the expression-stage write to an already resolved name: the
// parsed category takes the name over from structured metadata.
func (w *stageLabels) putRequested(n, v string) {
	if w.hasMeta(n) {
		if w.metaGone == nil {
			w.metaGone = make(map[string]struct{})
		}
		w.metaGone[n] = struct{}{}
	}
	w.set(n, v)
}

// capture is the write of the capture stages (`| regexp`, `| pattern`,
// `| unpack`), whose labels come from named captures or object members rather
// than from a line scan with its own duplicate handling:
//
//	capture stage, name n
//	  n is a stream name           -> the value goes to n_extracted
//	  the final name is parsed by
//	  an EARLIER stage             -> the write is discarded, that value stays
//	  the final name is structured
//	  metadata (not taken over)    -> the write is discarded, the metadata stays
//	  otherwise                    -> the value is set (an empty value included);
//	                                  a later write of the same stage replaces it
//
// The refusal of a name an earlier stage parsed is observed for chained regexp
// stages (`| regexp "(?P<a>..)" | regexp "(?P<a>..)"` keeps the first a and
// writes no a_extracted) and for a regexp after logfmt. A stage never refuses its
// own earlier write, as in the json stage where the last duplicate wins.
func (w *stageLabels) capture(n, v string) {
	n = w.extractedName(n)
	if _, mine := w.pending[n]; !mine && (w.parsed.has(n) || w.hasMeta(n)) {
		return
	}
	w.set(n, v)
}

// flush merges this stage's writes into the entry: the parsed category stays
// sorted by name and a name written by the stage replaces the earlier value.
func (w *stageLabels) flush() {
	e := w.e
	if len(w.metaGone) > 0 {
		kept := make(model.Labels, 0, len(e.StructuredMetadata))
		for _, l := range e.StructuredMetadata {
			if _, gone := w.metaGone[l.Name]; !gone {
				kept = append(kept, l)
			}
		}
		e.StructuredMetadata = kept
		w.metaGone = nil
	}
	if len(w.pending) == 0 {
		return
	}
	names := make([]string, 0, len(w.pending))
	for n := range w.pending {
		names = append(names, n)
	}
	slices.Sort(names)
	old := e.ParsedLabels
	out := make(model.Labels, 0, len(old)+len(names))
	i, j := 0, 0
	for i < len(old) || j < len(names) {
		switch {
		case j == len(names) || i < len(old) && old[i].Name < names[j]:
			out = append(out, old[i])
			i++
		case i == len(old) || names[j] < old[i].Name:
			out = append(out, model.Label{Name: names[j], Value: w.pending[names[j]]})
			j++
		default:
			out = append(out, model.Label{Name: names[j], Value: w.pending[names[j]]})
			i++
			j++
		}
	}
	e.ParsedLabels = out
	w.pending = nil
	w.parsed = nameSet{ls: out}
}

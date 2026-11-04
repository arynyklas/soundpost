// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

// Label builder: how the json and logfmt stages write parsed labels.
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

// streamHas reports whether n is a stream-namespace name.
func (e *LogEntry) streamHas(n string) bool {
	base := e.baseStream
	if base == nil {
		base = e.StreamLabels
	}
	return labelPresent(base, n)
}

// extractedName returns the parsed-category name a write for n lands on.
func (e *LogEntry) extractedName(n string) string {
	if e.streamHas(n) {
		n += "_extracted"
	}
	return n
}

// shadowedKey is the name a line key takes in expression mode. A key naming an
// existing structured-metadata or parsed label is renamed key_extracted before
// request paths are matched, unless the stage itself requests a label of that
// name (that label takes the key over). A request path equal to the plain key
// therefore no longer finds it. Stream names do not shadow: a path naming a
// stream label still finds the key.
func (e *LogEntry) shadowedKey(k string, requested map[string]bool) string {
	if requested[k] {
		return k
	}
	if labelPresent(e.StructuredMetadata, k) || labelPresent(e.ParsedLabels, k) {
		return k + "_extracted"
	}
	return k
}

// putExtracted is the plain-stage write: a name owned by structured metadata is
// left alone.
func (e *LogEntry) putExtracted(n, v string) {
	n = e.extractedName(n)
	if labelPresent(e.StructuredMetadata, n) && !labelPresent(e.ParsedLabels, n) {
		return
	}
	e.ParsedLabels = setLabel(e.ParsedLabels, n, v)
}

// putRequested is the expression-stage write to an already resolved name: the
// parsed category takes the name over from structured metadata.
func (e *LogEntry) putRequested(n, v string) {
	e.StructuredMetadata = removeLabel(e.StructuredMetadata, n)
	e.ParsedLabels = setLabel(e.ParsedLabels, n, v)
}

// extract is the write for the stages outside this model (regexp, pattern,
// unpack): stream names rename, nothing else is protected.
func (e *LogEntry) extract(n, v string) {
	e.ParsedLabels = setLabel(e.ParsedLabels, e.extractedName(n), v)
}

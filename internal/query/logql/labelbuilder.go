// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

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

// captureWriter is the write of the capture stages (`| regexp`, `| pattern`,
// `| unpack`), whose labels come from named captures or object members rather
// than from a line scan with its own duplicate handling. One writer serves one
// stage on one entry:
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
type captureWriter struct {
	e       *LogEntry
	written []string
}

func (w *captureWriter) put(n, v string) {
	n = w.e.extractedName(n)
	mine := false
	for _, s := range w.written {
		if s == n {
			mine = true
			break
		}
	}
	if !mine {
		if labelPresent(w.e.ParsedLabels, n) || labelPresent(w.e.StructuredMetadata, n) {
			return
		}
		w.written = append(w.written, n)
	}
	w.e.ParsedLabels = setLabel(w.e.ParsedLabels, n, v)
}

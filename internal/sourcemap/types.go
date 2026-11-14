// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Package sourcemap decodes owned, inert source-map v3 documents. It never opens sources.
package sourcemap

import "errors"

const maxBytes = 32 << 20
const maxFiles = 1024
const maxDepth = 8
const maxSegments = 1 << 20

var ErrInvalid = errors.New("invalid source map")
var ErrLimit = errors.New("source map limit exceeded")
var ErrPosition = errors.New("invalid generated position")

// Limits can tighten, never raise, C07 ceilings. Zero selects the ceiling.
// MaxSegments additionally bounds indexing work and memory independently of JSON size.
type Limits struct {
	MaxBytes    int64
	MaxFiles    int
	MaxDepth    int
	MaxSegments int
}

// Position contains only safe project-relative identity and optional symbol name.
// Lines are one-based; columns are zero-based UTF-16 code-unit offsets.
type Position struct {
	SourceID string
	Name     string
	Line     uint32
	Column   uint32
}
type segment struct {
	line, column uint32
	position     Position
	mapped       bool
}
type section struct {
	line, column uint32
	child        *Map
}
type Map struct {
	segments []segment
	sections []section
}

func ceilings(l Limits) (Limits, error) {
	if l.MaxBytes < 0 || l.MaxFiles < 0 || l.MaxDepth < 0 || l.MaxSegments < 0 {
		return l, ErrLimit
	}
	if l.MaxBytes == 0 || l.MaxBytes > maxBytes {
		l.MaxBytes = maxBytes
	}
	if l.MaxFiles == 0 || l.MaxFiles > maxFiles {
		l.MaxFiles = maxFiles
	}
	if l.MaxDepth == 0 || l.MaxDepth > maxDepth {
		l.MaxDepth = maxDepth
	}
	if l.MaxSegments == 0 || l.MaxSegments > maxSegments {
		l.MaxSegments = maxSegments
	}
	return l, nil
}

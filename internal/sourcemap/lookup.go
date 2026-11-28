// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sourcemap

import "sort"

// Lookup uses greatest-lower-bound segments on the same generated line. It
// never interpolates source columns, carries mappings across lines, or guesses
// a missing function name. A miss leaves the caller's sanitized frame unchanged.
func (m *Map) Lookup(generatedLine, generatedColumn uint32) (Position, bool, error) {
	if generatedLine == 0 {
		return Position{}, false, ErrPosition
	}
	if m == nil {
		return Position{}, false, ErrInvalid
	}
	return m.lookup(generatedLine-1, generatedColumn)
}
func (m *Map) lookup(line, column uint32) (Position, bool, error) {
	if len(m.sections) > 0 {
		i := sort.Search(len(m.sections), func(i int) bool { s := m.sections[i]; return less(line, column, s.line, s.column) }) - 1
		if i < 0 {
			return Position{}, false, nil
		}
		s := m.sections[i]
		line -= s.line
		if line == 0 {
			column -= s.column
		}
		return s.child.lookup(line, column)
	}
	i := sort.Search(len(m.segments), func(i int) bool { s := m.segments[i]; return less(line, column, s.line, s.column) }) - 1
	if i < 0 {
		return Position{}, false, nil
	}
	s := m.segments[i]
	if s.line != line || !s.mapped {
		return Position{}, false, nil
	}
	return s.position, true, nil
}

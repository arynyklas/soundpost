// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sourcemap

func less(al, ac, bl, bc uint32) bool { return al < bl || al == bl && ac < bc }
func offset(line, column, childLine, childColumn uint32) (uint32, uint32, error) {
	l := uint64(line) + uint64(childLine)
	c := uint64(childColumn)
	if childLine == 0 {
		c += uint64(column)
	}
	if l >= 0xffffffff || c > 0xffffffff {
		return 0, 0, ErrInvalid
	}
	return uint32(l), uint32(c), nil
}
func (m *Map) last() (uint32, uint32, bool) {
	if len(m.sections) > 0 {
		for i := len(m.sections) - 1; i >= 0; i-- {
			s := m.sections[i]
			if l, c, ok := s.child.last(); ok {
				l, c, e := offset(s.line, s.column, l, c)
				return l, c, e == nil
			}
		}
		return 0, 0, false
	}
	if len(m.segments) == 0 {
		return 0, 0, false
	}
	s := m.segments[len(m.segments)-1]
	return s.line, s.column, true
}
func (b *budget) mappings(m *Map, text string, sources, names []string) error {
	var line uint32
	var column, source, originalLine, originalColumn, name int64
	at := 0
	newLine := true
	for at < len(text) {
		if text[at] == ';' {
			if line == 0xfffffffe {
				return ErrInvalid
			}
			line++
			column = 0
			newLine = true
			at++
			continue
		}
		if text[at] == ',' {
			return ErrInvalid
		}
		var fields [5]int64
		n := 0
		for at < len(text) && text[at] != ',' && text[at] != ';' {
			if n == len(fields) {
				return ErrInvalid
			}
			v, e := vlq(text, &at)
			if e != nil {
				return e
			}
			fields[n] = v
			n++
		}
		if n != 1 && n != 4 && n != 5 {
			return ErrInvalid
		}
		next, e := delta(column, fields[0])
		if e != nil || !newLine && next <= column {
			return ErrInvalid
		}
		column = next
		newLine = false
		s := segment{line: line, column: uint32(column)}
		if n > 1 {
			source, e = delta(source, fields[1])
			if e != nil || source >= int64(len(sources)) {
				return ErrInvalid
			}
			originalLine, e = delta(originalLine, fields[2])
			if e != nil || originalLine == 0xffffffff {
				return ErrInvalid
			}
			originalColumn, e = delta(originalColumn, fields[3])
			if e != nil {
				return ErrInvalid
			}
			s.mapped = true
			s.position = Position{SourceID: sources[source], Line: uint32(originalLine) + 1, Column: uint32(originalColumn)}
			if n == 5 {
				name, e = delta(name, fields[4])
				if e != nil || name >= int64(len(names)) {
					return ErrInvalid
				}
				s.position.Name = names[name]
			}
		}
		b.segments++
		if b.segments > b.limits.MaxSegments {
			return ErrLimit
		}
		m.segments = append(m.segments, s)
		if at < len(text) && text[at] == ',' {
			at++
			if at == len(text) || text[at] == ';' {
				return ErrInvalid
			}
		}
	}
	return nil
}

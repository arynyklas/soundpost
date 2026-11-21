// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package regexcompat

import (
	"context"
	"strings"
)

// regexMeta is the byte set regexp.QuoteMeta escapes. The PromQL references
// treat a label-matcher pattern as a literal alternative only when it holds none.
const regexMeta = `\.+*?()|[]{}^$`

// literalAlternatives splits pattern on '|' and reports the alternatives when
// every one is free of regexp metacharacters. The PromQL references (3.1.0 and
// 3.13.5 alike, observed) match such a label pattern by byte equality against the
// alternatives and never compile it, so it may hold bytes that are not UTF-8.
func literalAlternatives(pattern string) ([]string, bool) {
	set := strings.Split(pattern, "|")
	for _, alt := range set {
		if strings.ContainsAny(alt, regexMeta) {
			return nil, false
		}
	}
	return set, true
}

// literalEngine matches the whole input against a set of literal alternatives.
// It exists only for label-matcher patterns (whole-value anchored, no groups);
// replacement is not defined for them and leaves the input unchanged.
type literalEngine struct{ set []string }

func (e literalEngine) MatchString(s string) bool {
	for _, alt := range e.set {
		if alt == s {
			return true
		}
	}
	return false
}
func (e literalEngine) FindStringSubmatchIndex(s string) []int {
	if e.MatchString(s) {
		return []int{0, len(s)}
	}
	return nil
}
func (e literalEngine) FindAllStringSubmatchIndex(s string, n int) [][]int {
	if n == 0 {
		return nil
	}
	if m := e.FindStringSubmatchIndex(s); m != nil {
		return [][]int{m}
	}
	return nil
}
func (e literalEngine) ReplaceAllString(s, _ string) string { return s }
func (e literalEngine) ExpandString(dst []byte, _, _ string, _ []int) []byte {
	return dst
}
func (e literalEngine) SubexpNames() []string { return []string{""} }
func (e literalEngine) NumSubexp() int        { return 0 }
func (e literalEngine) ProgramSize() uint64 {
	var n uint64 = 1
	for _, alt := range e.set {
		n += uint64(len(alt)) + 1
	}
	return n
}
func (e literalEngine) CaptureSlots() int { return 2 }
func (e literalEngine) ExecuteContext(ctx context.Context, s string, start, slots int) ([]int, error) {
	// The pattern is anchored at both ends, so only a search from 0 can match.
	if start != 0 {
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !e.MatchString(s) {
		return nil, nil
	}
	if slots == 0 {
		return []int{}, nil
	}
	return []int{0, len(s)}, nil
}

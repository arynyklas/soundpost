// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package regexcompat

import (
	"context"
	"errors"
	"strings"
	"sync"
	"unicode/utf8"

	"soundpost/internal/query/profile"
)

type Mode uint8

const (
	Search Mode = iota
	Label
)

// Limits are operational query budgets, not additional regex syntax rules.
// All are required positive values. Work is a conservative admission charge:
// compilation reserves 1000 units per source byte (the pinned repeat bound),
// and matching reserves (input bytes+1)*compiled program units per scan.
// CachePatternBytes bounds retained source, ProgramUnits bounds retained compiled
// instructions/runes. No match results, input text or tenant data are cached.
type Limits struct {
	CacheEntries      int
	CachePatternBytes uint64
	ProgramUnits      uint64
	PatternBytes      uint64
	InputBytes        uint64
	Work              uint64
	Matches           int
	OutputBytes       uint64
}

type cacheKey struct {
	pattern string
	mode    Mode
}
type Scope struct {
	mu                                    sync.Mutex
	p                                     profile.Profile
	limits                                Limits
	cache                                 map[cacheKey]*Regexp
	patternBytes, programUnits, remaining uint64
}

// NewScope is called once per owned query context, never globally or per tenant.
// A scope cannot be rebound to another resolved profile/feature/configuration.
func NewScope(p profile.Profile, l Limits) (*Scope, error) {
	if _, err := selectEdition(p); err != nil {
		return nil, err
	}
	if p.Identity == "" || p.ConfigurationHash == "" {
		return nil, ErrProfile
	}
	if l.CacheEntries <= 0 || l.CachePatternBytes == 0 || l.ProgramUnits == 0 || l.PatternBytes == 0 || l.InputBytes == 0 || l.Work == 0 || l.Matches <= 0 || l.OutputBytes == 0 {
		return nil, errors.New("invalid query regex limits")
	}
	// Only immutable identity fields are needed after construction; do not retain
	// caller-owned mutable manifest maps/slices.
	frozen := profile.Profile{ID: p.ID, Commit: p.Commit, Identity: p.Identity, ConfigurationHash: p.ConfigurationHash}
	return &Scope{p: frozen, limits: l, remaining: l.Work, cache: make(map[cacheKey]*Regexp)}, nil
}
func (s *Scope) charge(n uint64) error {
	if n > s.remaining {
		return ErrBudget
	}
	s.remaining -= n
	return nil
}
func product(a, b uint64) (uint64, bool) {
	if a != 0 && b > ^uint64(0)/a {
		return 0, false
	}
	return a * b, true
}
func (s *Scope) Compile(ctx context.Context, pattern string, mode Mode) (*Regexp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := cacheKey{pattern, mode}
	if re := s.cache[key]; re != nil {
		return re, nil
	}
	size := uint64(len(pattern))
	if size > s.limits.PatternBytes || len(s.cache) >= s.limits.CacheEntries || size > s.limits.CachePatternBytes-s.patternBytes {
		return nil, ErrBudget
	}
	cost, ok := product(size+1, 1000)
	if !ok {
		return nil, ErrBudget
	}
	if err := s.charge(cost); err != nil {
		return nil, err
	}
	// Clone only on a cache miss: a tiny substring must not retain a large query.
	owned := strings.Clone(pattern)
	key.pattern = owned
	re, err := compile(s.p, owned, mode)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	units := re.units
	if units > s.limits.ProgramUnits-s.programUnits {
		return nil, ErrBudget
	}
	re.owner = s
	s.cache[key] = re
	s.patternBytes += size
	s.programUnits += units
	return re, nil
}
func (s *Scope) admit(ctx context.Context, re *Regexp, input string, scans uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if re == nil || re.owner != s {
		return ErrScope
	}
	if uint64(len(input)) > s.limits.InputBytes {
		return ErrBudget
	}
	cost, ok := product(uint64(len(input))+1, re.units)
	if !ok {
		return ErrBudget
	}
	cost, ok = product(cost, scans)
	if !ok {
		return ErrBudget
	}
	return s.charge(cost)
}
func (s *Scope) MatchString(ctx context.Context, re *Regexp, input string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.admit(ctx, re, input, 1); err != nil {
		return false, err
	}
	matches, err := re.engine.ExecuteContext(ctx, input, 0, 0)
	return matches != nil, err
}
func (s *Scope) FindStringSubmatchIndex(ctx context.Context, re *Regexp, input string) ([]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.admit(ctx, re, input, 1); err != nil {
		return nil, err
	}
	if uint64(re.engine.CaptureSlots()) > s.limits.OutputBytes/8 {
		return nil, ErrBudget
	}
	return re.engine.ExecuteContext(ctx, input, 0, re.engine.CaptureSlots())
}
func (s *Scope) FindAllStringSubmatchIndex(ctx context.Context, re *Regexp, input string, n int) ([][]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.findAll(ctx, re, input, n)
}
func (s *Scope) findAll(ctx context.Context, re *Regexp, input string, n int) ([][]int, error) {
	if err := s.admit(ctx, re, input, 0); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	if uint64(re.engine.CaptureSlots()) > s.limits.OutputBytes/8 {
		return nil, ErrBudget
	}
	var out [][]int
	pos, lastEnd := 0, -1
	for pos <= len(input) && (n < 0 || len(out) < n) {
		if err := s.admit(ctx, re, input, 1); err != nil {
			return nil, err
		}
		match, err := re.engine.ExecuteContext(ctx, input, pos, re.engine.CaptureSlots())
		if err != nil {
			return nil, err
		}
		if match == nil {
			break
		}
		end := match[1]
		accept := true
		if end == pos {
			accept = match[0] != lastEnd
			if pos == len(input) {
				pos++
			} else {
				_, width := utf8.DecodeRuneInString(input[pos:])
				pos += width
			}
		} else {
			pos = end
		}
		lastEnd = end
		if accept {
			if len(out) >= s.limits.Matches {
				return nil, ErrBudget
			}
			// Result capture storage itself is bounded, not only the number of matches.
			bytes, ok := product(uint64(len(out)+1), uint64(len(match))*8)
			if !ok || bytes > s.limits.OutputBytes {
				return nil, ErrBudget
			}
			out = append(out, match)
		}
	}
	return out, nil
}
func (s *Scope) ReplaceAllString(ctx context.Context, re *Regexp, input, replacement string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.admit(ctx, re, input, 0); err != nil {
		return "", err
	}
	if uint64(len(replacement)) > s.limits.OutputBytes {
		return "", ErrBudget
	}
	matches, err := s.findAll(ctx, re, input, -1)
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		if uint64(len(input)) > s.limits.OutputBytes {
			return "", ErrBudget
		}
		return input, nil
	}
	// Expansion may repeat a capture as many times as there are template bytes.
	// Admit that upper bound before allocating, including unmatched source bytes.
	per, ok := product(uint64(len(input))+1, uint64(len(replacement))+1)
	if !ok {
		return "", ErrBudget
	}
	expanded, ok := product(per, uint64(len(matches)))
	if !ok || expanded > s.limits.OutputBytes || uint64(len(input)) > s.limits.OutputBytes-expanded {
		return "", ErrBudget
	}
	var dst []byte
	end := 0
	for _, m := range matches {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		dst = append(dst, input[end:m[0]]...)
		dst = re.engine.ExpandString(dst, replacement, input, m)
		end = m[1]
	}
	dst = append(dst, input[end:]...)
	return string(dst), ctx.Err()
}

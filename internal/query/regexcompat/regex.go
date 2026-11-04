// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package regexcompat owns query-language regex primitives, not a query engine.
// Compile performs ordinary unanchored search; CompileLabel separately applies
// the pinned label normalization, whole-label anchoring and DotNL behavior.
// Compiled values expose no mutation or environment/file/network capabilities.
// Evaluators use Scope for per-query cache, work, result and cancellation bounds.
package regexcompat

import (
	"context"
	"errors"
	"strings"

	"soundpost/internal/query/profile"
	syn123 "soundpost/third_party/regex/go123/forksyntax"
	re123 "soundpost/third_party/regex/go123/regexp"
	std123 "soundpost/third_party/regex/go123/stdsyntax"
	u123 "soundpost/third_party/regex/go123/unicode"
	syn124 "soundpost/third_party/regex/go124/forksyntax"
	re124 "soundpost/third_party/regex/go124/regexp"
	std124 "soundpost/third_party/regex/go124/stdsyntax"
	u124 "soundpost/third_party/regex/go124/unicode"
	syn126 "soundpost/third_party/regex/go126/forksyntax"
	re126 "soundpost/third_party/regex/go126/regexp"
	std126 "soundpost/third_party/regex/go126/stdsyntax"
	u126 "soundpost/third_party/regex/go126/unicode"
)

var (
	ErrProfile = errors.New("unsupported or unresolved pinned regex profile")
	ErrBudget  = errors.New("query regex budget exhausted")
	ErrScope   = errors.New("compiled regex belongs to a different query scope")
)

type edition uint8

func selectEdition(p profile.Profile) (edition, error) {
	switch p.ID {
	case "promql-prometheus-3.1.0":
		if p.Commit == "7086161a93b262aa0949dbf2aba15a5a7b13e0a3" {
			return 1, nil
		}
	case "logql-loki-3.5.2":
		if p.Commit == "257d2f62bf8a81b44dea6fe88968d1d28c8e01e7" {
			return 2, nil
		}
	case "promql-prometheus-3.13.5":
		if p.Commit == "f497435984d1ca1d84cda5ed309387ac2eb1f8f6" {
			return 3, nil
		}
	}
	return 0, ErrProfile
}

type engine interface {
	MatchString(string) bool
	FindStringSubmatchIndex(string) []int
	FindAllStringSubmatchIndex(string, int) [][]int
	ReplaceAllString(string, string) string
	ExpandString([]byte, string, string, []int) []byte
	SubexpNames() []string
	NumSubexp() int
	ProgramSize() uint64
	CaptureSlots() int
	ExecuteContext(context.Context, string, int, int) ([]int, error)
}

// Regexp is immutable. No raw engine pointer or mutable syntax tree escapes.
// The direct helpers preserve the primitive API for bounded frontend use;
// evaluation of untrusted records must instead go through a query Scope.
type Regexp struct {
	engine  engine
	owner   *Scope
	pattern string
	units   uint64
}

func Compile(p profile.Profile, pattern string) (*Regexp, error) { return compile(p, pattern, Search) }
func CompileLabel(p profile.Profile, pattern string) (*Regexp, error) {
	return compile(p, pattern, Label)
}
func compile(p profile.Profile, pattern string, mode Mode) (*Regexp, error) {
	e, err := selectEdition(p)
	if err != nil {
		return nil, err
	}
	original := pattern
	if mode != Search && mode != Label {
		return nil, errors.New("invalid regex matching mode")
	}
	var impl engine
	switch e {
	case 1:
		if mode == Label {
			tree, err := syn123.Parse(pattern, syn123.Perl|syn123.DotNL)
			if err != nil {
				return nil, err
			}
			pattern = "^(?s:" + tree.Simplify().String() + ")$"
		}
		impl, err = re123.Compile(pattern)
	case 2:
		if mode == Label {
			tree, err := syn124.Parse(pattern, syn124.Perl|syn124.DotNL)
			if err != nil {
				return nil, err
			}
			pattern = "^(?s:" + tree.Simplify().String() + ")$"
		}
		impl, err = re124.Compile(pattern)
	case 3:
		if mode == Label {
			tree, err := syn126.Parse(pattern, syn126.Perl|syn126.DotNL)
			if err != nil {
				return nil, err
			}
			pattern = "^(?s:" + tree.Simplify().String() + ")$"
		}
		impl, err = re126.Compile(pattern)
	}
	if err != nil {
		return nil, err
	}
	return &Regexp{engine: impl, pattern: original, units: impl.ProgramSize()}, nil
}
func (r *Regexp) String() string                         { return r.pattern }
func (r *Regexp) MatchString(s string) bool              { return r.engine.MatchString(s) }
func (r *Regexp) FindStringSubmatchIndex(s string) []int { return r.engine.FindStringSubmatchIndex(s) }
func (r *Regexp) FindAllStringSubmatchIndex(s string, n int) [][]int {
	return r.engine.FindAllStringSubmatchIndex(s, n)
}
func (r *Regexp) ReplaceAllString(s, replacement string) string {
	return r.engine.ReplaceAllString(s, replacement)
}
func (r *Regexp) SubexpNames() []string { return append([]string(nil), r.engine.SubexpNames()...) }
func (r *Regexp) NumSubexp() int        { return r.engine.NumSubexp() }

// Case helpers use the actual compiler's Unicode edition, including unassigned
// code points, rather than normalizing or borrowing the host's Unicode tables.
func ToUpper(p profile.Profile, s string) (string, error) {
	e, err := selectEdition(p)
	if err != nil {
		return "", err
	}
	switch e {
	case 1:
		return strings.Map(u123.ToUpper, s), nil
	case 2:
		return strings.Map(u124.ToUpper, s), nil
	case 3:
		return strings.Map(u126.ToUpper, s), nil
	}
	panic("unreachable edition")
}
func ToLower(p profile.Profile, s string) (string, error) {
	e, err := selectEdition(p)
	if err != nil {
		return "", err
	}
	switch e {
	case 1:
		return strings.Map(u123.ToLower, s), nil
	case 2:
		return strings.Map(u124.ToLower, s), nil
	case 3:
		return strings.Map(u126.ToLower, s), nil
	}
	panic("unreachable edition")
}
func SimpleFold(p profile.Profile, r rune) (rune, error) {
	e, err := selectEdition(p)
	if err != nil {
		return 0, err
	}
	switch e {
	case 1:
		return u123.SimpleFold(r), nil
	case 2:
		return u124.SimpleFold(r), nil
	case 3:
		return u126.SimpleFold(r), nil
	}
	panic("unreachable edition")
}

// PatternErrorCode preserves the primitive parser's semantic error code while
// allowing callers to attach their own source range and safe public message.
func PatternErrorCode(err error) (string, bool) {
	switch e := err.(type) {
	case *syn123.Error:
		return string(e.Code), true
	case *syn124.Error:
		return string(e.Code), true
	case *syn126.Error:
		return string(e.Code), true
	case *std123.Error:
		return string(e.Code), true
	case *std124.Error:
		return string(e.Code), true
	case *std126.Error:
		return string(e.Code), true
	}
	return "", false
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package syntax

// Diagnostic contains only safe static language messages, never raw query text.
//
// Key is the de-duplication identity of an annotation: two diagnostics that
// carry the same non-empty Key are one annotation, as in the pinned engines,
// which key annotations by their rendered text (metric name, value, operator,
// aggregation name) and keep a single entry whatever the source range. Key
// never leaves the engine; an empty Key means "distinct per source range".
type Diagnostic struct {
	Category    string
	Range       SourceRange
	SafeMessage string
	Key         string
}

// Code identifies an owned semantic error family at its production origin.
// Empty means unclassified; adapters must not derive it from SafeMessage.
type LanguageError struct {
	Code        string
	Category    string
	Range       SourceRange
	SafeMessage string
}

func (e *LanguageError) Error() string { return e.Category + ": " + e.SafeMessage }

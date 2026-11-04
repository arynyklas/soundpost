// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package syntax

// Diagnostic contains only safe static language messages, never raw query text.
type Diagnostic struct {
	Category    string
	Range       SourceRange
	SafeMessage string
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

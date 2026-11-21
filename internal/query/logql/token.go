// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import "github.com/arynyklas/soundpost/internal/query/syntax"

type token struct {
	kind, text, value string
	span              syntax.SourceRange
	// dur is the parsed interval of a "range" token.
	dur int64
}

func languageError(category, message string, r syntax.SourceRange) error {
	if category == "parse" {
		category = "syntax"
	}
	code := "type.expression-invalid"
	switch category {
	case "syntax":
		code = "syntax.unexpected-token"
	case "profile":
		code = "profile.unknown"
	}
	return &syntax.LanguageError{Code: code, Category: category, SafeMessage: message, Range: r}
}
func languageErrorCode(code, category, message string, r syntax.SourceRange) error {
	return &syntax.LanguageError{Code: code, Category: category, SafeMessage: message, Range: r}
}

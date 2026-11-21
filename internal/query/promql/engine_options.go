// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"encoding/json"

	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// engineOption reads a boolean engine switch from the profile configuration.
// Both pinned references enable the @ modifier and negative offsets by default,
// so an absent or unreadable switch means enabled.
func engineOption(p profile.Profile, key string) bool {
	raw, ok := p.Configuration[key]
	if !ok {
		return true
	}
	var option struct {
		Default string `json:"default"`
	}
	if json.Unmarshal(raw, &option) != nil {
		return true
	}
	return option.Default != "false"
}

// validateEngineOptions is the engine validation stage that runs after parsing,
// separately from the parser's feature gates: a disabled @ modifier or negative
// offset rejects the whole query before any evaluation.
func validateEngineOptions(expr Expr, p profile.Profile, ev value.Evaluation) error {
	atEnabled := engineOption(p, "engine.enable-at-modifier")
	negativeEnabled := engineOption(p, "engine.enable-negative-offset")
	if atEnabled && negativeEnabled {
		return nil
	}
	var failure error
	Walk(expr, func(e Expr) bool {
		if failure != nil {
			return false
		}
		n := e.(*Node)
		if !atEnabled && n.At != "" {
			failure = &syntax.LanguageError{Code: "engine.at-modifier-disabled", Category: "plan", Range: n.Range, SafeMessage: "@ modifier is disabled"}
			return false
		}
		if !negativeEnabled && (n.OffsetExpr != nil || n.Offset != "") {
			if offset, err := durationNS(n.OffsetExpr, n.Offset, ev); err == nil && offset < 0 {
				failure = &syntax.LanguageError{Code: "engine.negative-offset-disabled", Category: "plan", Range: n.Range, SafeMessage: "negative offset is disabled"}
				return false
			}
		}
		return true
	})
	return failure
}

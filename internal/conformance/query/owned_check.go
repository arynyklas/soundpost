// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"errors"
	"fmt"

	"soundpost/internal/query/logql"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/promql"
	"soundpost/internal/query/syntax"
)

// OwnedOutcome is the owned parser and type checker's verdict on an expression.
type OwnedOutcome struct {
	Accepted bool
	Type     string
	Category string
}

// CheckOwned parses and type-checks an expression with the owned engine for
// the resolved profile. An error return is an unexpected failure (not a
// language error); a language error is a normal rejected outcome.
func CheckOwned(language, expression string, p profile.Profile) (OwnedOutcome, error) {
	var err error
	var kind string
	switch language {
	case "promql":
		var tree promql.Expr
		if tree, err = promql.Parse(expression, p); err == nil {
			var typed promql.TypedExpr
			if typed, _, err = promql.Check(tree, p); err == nil {
				kind = string(typed.Type)
			}
		}
	case "logql":
		var tree logql.Expr
		if tree, err = logql.Parse(expression, p); err == nil {
			var typed logql.TypedExpr
			if typed, _, err = logql.Check(tree, p); err == nil {
				kind = fmt.Sprint(typed.Type)
			}
		}
	default:
		return OwnedOutcome{}, fmt.Errorf("unknown language %s", language)
	}
	if err == nil {
		return OwnedOutcome{Accepted: true, Type: kind}, nil
	}
	var language2 *syntax.LanguageError
	if errors.As(err, &language2) {
		return OwnedOutcome{Category: language2.Category}, nil
	}
	return OwnedOutcome{}, fmt.Errorf("unexpected owned failure: %w", err)
}

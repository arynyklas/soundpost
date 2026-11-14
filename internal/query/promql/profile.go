// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/syntax"
)

func validateProfile(p profile.Profile) error {
	commit := ""
	switch p.ID {
	case "promql-prometheus-3.1.0":
		commit = "7086161a93b262aa0949dbf2aba15a5a7b13e0a3"
	case "promql-prometheus-3.13.5":
		commit = "f497435984d1ca1d84cda5ed309387ac2eb1f8f6"
	}
	if commit == "" || p.Commit != commit {
		return &syntax.LanguageError{Category: "profile", SafeMessage: "unsupported pinned PromQL profile"}
	}
	return nil
}

//go:build !soundpost_faults

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
)

// gateStamp, gateBegin, gateCommitted and gateQueried are the released binary's: empty inline
// functions the compiler removes, so a normal build observes nothing and pays nothing.
type gateStamp struct{}

func gateBegin() gateStamp { return gateStamp{} }

func gateCommitted(Evaluation, gateStamp) {}

func gateQueried(Rule, model.UnixNano, query.Result, error) {}

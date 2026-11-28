//go:build !soundpost_faults

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package appcore

import (
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// workerPassObserved and workerProjectObserved are the released binary's: empty inline functions the
// compiler removes, so a normal build observes nothing and pays nothing.
func workerPassObserved(string, PassReport) {}

func workerProjectObserved(string, model.ID, time.Duration, StepTimes) {}

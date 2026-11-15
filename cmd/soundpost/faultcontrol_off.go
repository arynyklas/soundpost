//go:build !soundpost_faults

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"

	"github.com/arynyklas/soundpost/internal/appcore"
)

// startFaultControl is the released binary's: there is no way to remove a shard from outside.
func startFaultControl(context.Context, *appcore.App) {}

//go:build !soundpost_faults

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"
)

// gateScanRoute and gateScanner are the released binary's: they return their argument unchanged,
// so a normal build counts nothing and wraps nothing.
func gateScanRoute(_ string, next http.HandlerFunc) http.HandlerFunc { return next }

func gateScanner(_ context.Context, inner SpanScanner) SpanScanner { return inner }

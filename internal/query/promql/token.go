// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

// token retains raw source byte boundaries and separately decoded string values.
type token struct {
	text, value string
	start, end  int
	kind        string
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import "sort"

// metricSort checks authorization/cancellation throughout comparison-heavy work.
// A failed check poisons the result: the interrupted permutation never escapes.
func metricSort[T any](items []T, less func(int, int) bool, check func() error) error {
	var failure error
	comparisons := 0
	sort.SliceStable(items, func(i, j int) bool {
		if failure != nil {
			return false
		}
		comparisons++
		if comparisons%1024 == 1 && check != nil {
			failure = check()
			if failure != nil {
				return false
			}
		}
		return less(i, j)
	})
	if failure == nil && check != nil {
		failure = check()
	}
	return failure
}
func metricCheck(checks []func() error) error {
	if len(checks) > 0 && checks[0] != nil {
		return checks[0]()
	}
	return nil
}

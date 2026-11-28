// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// callErrors counts the errors the handlers of the calls answered with, by the name of the call and the error (the first 80
// characters of its text): what a diagnostic build reports of the calls a leader refused (Stats).
var callErrors sync.Map // string -> *atomic.Uint64

func noteCallError(name string, err error) {
	text := err.Error()
	if len(text) > 80 {
		text = text[:80]
	}
	counter, _ := callErrors.LoadOrStore(fmt.Sprintf("%s: %T %s", name, err, text), new(atomic.Uint64))
	counter.(*atomic.Uint64).Add(1)
}

func callErrorCounts() map[string]any {
	out := map[string]any{}
	callErrors.Range(func(k, v any) bool {
		out[k.(string)] = v.(*atomic.Uint64).Load()
		return true
	})
	return out
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import "time"

// SetLiveWriteTimeoutForTest shortens the per-frame write deadline of live
// streams and returns the function that restores the default.
func SetLiveWriteTimeoutForTest(d time.Duration) (restore func()) {
	liveWriteTimeoutNS.Store(int64(d))
	return func() { liveWriteTimeoutNS.Store(0) }
}

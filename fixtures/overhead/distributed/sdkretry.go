// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// How the generator answers a refusal: the way the SDKs' delivery queues do (packages/core/src/queue.ts retryDelay,
// packages/core/src/transport.ts retryAfter; sdk/python/src/soundpost/queue.py and transport.py are the same rules).
//
//   - 200 with a receipt ends the batch.
//   - 429 and 503 are retryable and may carry a Retry-After; the next attempt waits the larger of that and sdkRetryDelay.
//   - Every other status is final for the batch (the SDK drops it as terminal_rejected or denied): it is not sent again.
//   - A failed or timed-out attempt (no answer) is retried after sdkRetryDelay. The SDK first asks for the receipt of the batch
//     (POST /ingest/v1/receipts, which needs the hash the SDK computed); the generator sends the identical batch again to the
//     next member instead, which the product answers with the same receipt.
//
// The attempt counter counts every failed attempt of the batch.
const (
	sdkRetryFloor = 250 * time.Millisecond
	sdkRetryCeil  = 30 * time.Second
)

// sdkRetryDelay is queue.ts retryDelay: 250 ms * 2^min(attempt, 7), at most 30 s, times 0.5 + 0.5 * u (u in 0..1), held to 250 ms .. 30 s.
func sdkRetryDelay(attempt int, u float64) time.Duration {
	cap := min(sdkRetryCeil, sdkRetryFloor<<min(attempt, 7))
	u = max(0, min(1, u))
	return max(sdkRetryFloor, min(sdkRetryCeil, time.Duration(float64(cap)*(0.5+0.5*u))))
}

// sdkRetryAfter is transport.ts retryAfter: whole seconds or an HTTP date, held to 250 ms .. 30 s; ok is false for a missing or
// unreadable value.
func sdkRetryAfter(value string, now time.Time) (d time.Duration, ok bool) {
	if value == "" {
		return 0, false
	}
	if allDigits(value) {
		n, err := strconv.ParseUint(value, 10, 63)
		if err != nil || n > uint64(sdkRetryCeil/time.Second) {
			return sdkRetryCeil, true
		}
		return max(sdkRetryFloor, time.Duration(n)*time.Second), true
	}
	at, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	return max(sdkRetryFloor, min(sdkRetryCeil, at.Sub(now))), true
}

func allDigits(s string) bool {
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// sdkWait is how long the SDK waits after the attempt-th failed attempt of a batch whose answer carried retryAfter (the header, "" if none).
func sdkWait(attempt int, retryAfter string) time.Duration {
	wait := sdkRetryDelay(attempt, rand.Float64())
	if d, ok := sdkRetryAfter(retryAfter, time.Now()); ok {
		wait = max(wait, d)
	}
	return wait
}

// retriable says whether the SDK sends the batch again after this answer (0 = no answer: transport failure or timeout).
func retriable(status int) bool {
	return status == 0 || status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable
}

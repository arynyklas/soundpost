// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// The generator answers 429 and 503 the way the SDKs' delivery queues do (packages/core/src/queue.ts retryDelay and
// transport.ts retryAfter; sdk/python/src/soundpost/queue.py and transport.py say the same): the wait before the next attempt
// is the larger of the Retry-After the product sent (seconds or an HTTP date, held to 250 ms .. 30 s) and an exponential
// delay with jitter, 250 ms * 2^attempt (attempt capped at 7, delay capped at 30 s) times a factor between 0.5 and 1, never
// below 250 ms. Any other status that is not a receipt is final for the batch (the SDK drops it as terminal_rejected): the
// generator does not send it again.
func TestRetryDelayIsTheSDKs(t *testing.T) {
	for _, c := range []struct {
		attempt int
		u       float64
		want    time.Duration
	}{
		{0, 0, 250 * time.Millisecond}, {0, 1, 250 * time.Millisecond},
		{1, 0, 250 * time.Millisecond}, {1, 1, 500 * time.Millisecond},
		{3, 0, time.Second}, {3, 1, 2 * time.Second}, {3, 0.5, 1500 * time.Millisecond},
		{6, 1, 16 * time.Second}, {7, 0, 15 * time.Second}, {7, 1, 30 * time.Second}, {40, 1, 30 * time.Second}, {40, 0, 15 * time.Second},
	} {
		if got := sdkRetryDelay(c.attempt, c.u); got != c.want {
			t.Errorf("attempt %d, jitter %.1f: %v, want %v", c.attempt, c.u, got, c.want)
		}
	}
}

func TestRetryAfterIsTheSDKs(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, c := range []struct {
		value string
		want  time.Duration
		ok    bool
	}{
		{"", 0, false}, {"soon", 0, false}, {"-3", 0, false},
		{"0", 250 * time.Millisecond, true}, {"1", time.Second, true}, {"12", 12 * time.Second, true}, {"9999", 30 * time.Second, true},
		{now.Add(5 * time.Second).UTC().Format(http.TimeFormat), 5 * time.Second, true},
		{now.Add(-time.Hour).UTC().Format(http.TimeFormat), 250 * time.Millisecond, true},
		{now.Add(time.Hour).UTC().Format(http.TimeFormat), 30 * time.Second, true},
	} {
		got, ok := sdkRetryAfter(c.value, now)
		if ok != c.ok || got != c.want {
			t.Errorf("Retry-After %q: %v %v, want %v %v", c.value, got, ok, c.want, c.ok)
		}
	}
}

// rig is a loader that talks to one fake member.
type rig struct {
	l      *loader
	mu     sync.Mutex
	at     []time.Time
	paths  []string
	bodies [][]byte
	rows   strings.Builder
}

func newRig(t *testing.T, answer func(n int, w http.ResponseWriter, id model.ID)) *rig {
	t.Helper()
	r := &rig{}
	var id model.ID
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.at = append(r.at, time.Now())
		r.paths = append(r.paths, req.URL.Path)
		r.bodies = append(r.bodies, body)
		n := len(r.at)
		r.mu.Unlock()
		answer(n, w, id)
	}))
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "https://")
	r.l = &loader{plan: &Plan{Nodes: []PlanNode{{Addr: addr}}}, client: srv.Client(), t0: time.Now(), rowsBuf: bufio.NewWriter(&r.rows), ledger: bufio.NewWriter(io.Discard)}
	return r
}

func (r *rig) send(t *testing.T, id model.ID) {
	t.Helper()
	body, err := json.Marshal(model.Batch{Version: 1, Project: model.ID{1}, Source: model.ID{2}, Producer: model.ID{3}, ID: id, PolicyRevision: 1, RouteSlot: 5})
	if err != nil {
		t.Fatal(err)
	}
	r.l.wg.Add(1)
	r.l.send(Prepared{Project: 0, Slot: 5, ID: id, Body: body, Records: []RecMeta{{Kind: 'm'}}}, time.Now(), "credential")
	r.l.rowsBuf.Flush()
}

func receipt(w http.ResponseWriter, id model.ID) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(model.Receipt{Version: 1, BatchID: id, Cursor: model.Cursor{Group: model.NewID(), Index: 1}})
}

func TestA429WithRetryAfterIsNotAnsweredBeforeThatTime(t *testing.T) {
	id := model.NewID()
	r := newRig(t, func(n int, w http.ResponseWriter, _ model.ID) {
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		receipt(w, id)
	})
	r.send(t, id)
	if len(r.at) != 2 {
		t.Fatalf("%d attempts, want 2", len(r.at))
	}
	if gap := r.at[1].Sub(r.at[0]); gap < time.Second {
		t.Fatalf("the retry came %v after a 429 that said Retry-After: 1", gap)
	}
	if r.l.ok.Load() != 1 || r.l.ackedBatches.Load() != 1 || r.l.refused.Load() != 0 || r.l.transport.Load() != 0 {
		t.Fatalf("ok %d acked %d refused %d transport %d", r.l.ok.Load(), r.l.ackedBatches.Load(), r.l.refused.Load(), r.l.transport.Load())
	}
}

func TestA503WithoutRetryAfterWaitsTheBackoffOfTheSDK(t *testing.T) {
	id := model.NewID()
	r := newRig(t, func(n int, w http.ResponseWriter, _ model.ID) {
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		receipt(w, id)
	})
	r.send(t, id)
	if len(r.at) != 2 {
		t.Fatalf("%d attempts, want 2", len(r.at))
	}
	if gap := r.at[1].Sub(r.at[0]); gap < 250*time.Millisecond {
		t.Fatalf("the retry came %v after a 503 (the SDK waits at least 250 ms)", gap)
	}
}

func TestAnAnswerThatIsNotARetryableOneIsFinal(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusBadGateway, http.StatusConflict, http.StatusNotFound, http.StatusUnprocessableEntity, http.StatusForbidden} {
		r := newRig(t, func(n int, w http.ResponseWriter, _ model.ID) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			w.Write([]byte(`{"code":"unavailable","retryable":true}`))
		})
		r.send(t, model.NewID())
		if len(r.at) != 1 {
			t.Errorf("%d answered: %d attempts, want 1 (the SDK drops the batch)", status, len(r.at))
		}
		if r.l.refused.Load() != 1 || r.l.ok.Load() != 0 {
			t.Errorf("%d answered: refused %d ok %d", status, r.l.refused.Load(), r.l.ok.Load())
		}
	}
}

// After an attempt that ended without an answer the SDK does not send the batch again: it asks for the receipt of the batch (POST
// /ingest/v1/receipts with the batch's identity and the hash of its canonical form, packages/core/src/queue.ts flush: the attempt
// is marked ambiguous before it is sent and stays so), and sends it again only when the product answers 404, or when the send was
// refused outright (429/503). The generator did the other thing: it sent the identical batch to the next member.

// lookupReceipt answers a receipt lookup with the receipt of the batch it names, the hash it asked for included.
func lookupReceipt(r *rig, n int, w http.ResponseWriter, id model.ID) {
	r.mu.Lock()
	raw := r.bodies[n-1]
	r.mu.Unlock()
	var q model.ReceiptRequest
	if err := json.Unmarshal(raw, &q); err != nil || q.BatchID != id {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(model.Receipt{Version: 1, BatchID: id, Hash: q.OriginalHash, Cursor: model.Cursor{Group: model.NewID(), Index: 1}})
}

func TestAnAttemptWithoutAnAnswerIsFollowedByALookupOfTheReceiptNotAResend(t *testing.T) {
	id := model.NewID()
	var r *rig
	r = newRig(t, func(n int, w http.ResponseWriter, _ model.ID) {
		if n == 1 {
			time.Sleep(1500 * time.Millisecond) // the send is not answered within the attempt's timeout
			return
		}
		lookupReceipt(r, n, w, id)
	})
	r.l.attemptTo = 300 * time.Millisecond
	r.send(t, id)
	if want := []string{"/ingest/v1/batches", "/ingest/v1/receipts"}; len(r.paths) != 2 || r.paths[0] != want[0] || r.paths[1] != want[1] {
		t.Fatalf("requests %v, want %v: a batch whose send was not answered is looked up, not sent again", r.paths, want)
	}
	var q model.ReceiptRequest
	if err := json.Unmarshal(r.bodies[1], &q); err != nil || q.BatchID != id || q.Source != (model.ID{2}) || q.Producer != (model.ID{3}) || q.RouteSlot != 5 || q.OriginalHash == (model.Hash{}) {
		t.Fatalf("the lookup asks %s (%v)", r.bodies[1], err)
	}
	if r.l.ok.Load() != 1 || r.l.ackedBatches.Load() != 1 || r.l.lookups.Load() != 1 || r.l.lookupHits.Load() != 1 || r.l.refused.Load() != 0 || r.l.transport.Load() != 0 {
		t.Fatalf("ok %d acked %d lookups %d found %d refused %d transport %d", r.l.ok.Load(), r.l.ackedBatches.Load(), r.l.lookups.Load(), r.l.lookupHits.Load(), r.l.refused.Load(), r.l.transport.Load())
	}
	if gap := r.at[1].Sub(r.at[0]); gap < 250*time.Millisecond {
		t.Fatalf("the lookup came %v after the attempt that was not answered", gap)
	}
}

func TestALookupThatFindsNoBatchIsFollowedByTheSendAndALookupThatIsRefusedIsAskedAgain(t *testing.T) {
	id := model.NewID()
	var r *rig
	r = newRig(t, func(n int, w http.ResponseWriter, _ model.ID) {
		switch n {
		case 1:
			time.Sleep(1500 * time.Millisecond) // not answered
		case 2:
			w.WriteHeader(http.StatusServiceUnavailable) // the lookup is refused: it is asked again, the batch is not sent
		case 3:
			w.WriteHeader(http.StatusNotFound) // the product holds no such batch
		case 4:
			receipt(w, id) // the send, again
		}
	})
	r.l.attemptTo = 300 * time.Millisecond
	r.send(t, id)
	want := []string{"/ingest/v1/batches", "/ingest/v1/receipts", "/ingest/v1/receipts", "/ingest/v1/batches"}
	if len(r.paths) != len(want) {
		t.Fatalf("requests %v, want %v", r.paths, want)
	}
	for i := range want {
		if r.paths[i] != want[i] {
			t.Fatalf("requests %v, want %v", r.paths, want)
		}
	}
	if r.l.ok.Load() != 1 || r.l.lookups.Load() != 2 || r.l.lookupHits.Load() != 0 || r.l.lookupMisses.Load() != 1 {
		t.Fatalf("ok %d lookups %d found %d not found %d", r.l.ok.Load(), r.l.lookups.Load(), r.l.lookupHits.Load(), r.l.lookupMisses.Load())
	}
}

func TestASendThatWasRefusedIsSentAgainNotLookedUp(t *testing.T) {
	id := model.NewID()
	r := newRig(t, func(n int, w http.ResponseWriter, _ model.ID) {
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		receipt(w, id)
	})
	r.send(t, id)
	if len(r.paths) != 2 || r.paths[1] != "/ingest/v1/batches" || r.l.lookups.Load() != 0 {
		t.Fatalf("requests %v, lookups %d: a send the product refused outright appended nothing and is sent again", r.paths, r.l.lookups.Load())
	}
}

// A receipt that names another hash than the batch's is not the batch's receipt.
func TestALookupAnsweredWithAnotherHashIsNotAnAck(t *testing.T) {
	id := model.NewID()
	r := newRig(t, func(n int, w http.ResponseWriter, _ model.ID) {
		if n == 1 {
			time.Sleep(1500 * time.Millisecond)
			return
		}
		receipt(w, id) // names the zero hash
	})
	r.l.attemptTo = 300 * time.Millisecond
	r.send(t, id)
	if r.l.ok.Load() != 0 || r.l.refused.Load() != 1 {
		t.Fatalf("ok %d refused %d", r.l.ok.Load(), r.l.refused.Load())
	}
}

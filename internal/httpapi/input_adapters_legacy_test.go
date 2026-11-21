// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

// previousRelease mounts the bridge the way the releases before request.v2
// behaved, on the same receipt ledger and the same credentials as the current
// bridge of the environment.
func (e *adapterEnv) previousRelease(t *testing.T, cfg httpapi.InputAdapterConfig) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterPreviousReleaseInputRoutesForTest(mux, e.app.Auth, e.adm, cfg)
	}).Handler)
	t.Cleanup(srv.Close)
	return srv
}

// postVia sends one request to another bridge of the same environment.
func (e *adapterEnv) postVia(t *testing.T, srv *httptest.Server, path, credential string, header map[string]string, body []byte) adapterReply {
	t.Helper()
	current := e.srv
	e.srv = srv
	defer func() { e.srv = current }()
	return e.post(t, path, credential, header, body)
}

// Batch and record identifiers moved to request.v2 (resource, unit and mapping
// are in them). A request that the previous release admitted, retried after the
// upgrade, must be answered with its original receipts and must store nothing
// again: log lines at one nanosecond are distinct records, so a retry under a new
// identity would double them. A request the previous release never saw is a new
// one, recorded under the current identity.
func TestRetryOfARequestTheOldIdentityAdmittedIsAnsweredFromTheLedger(t *testing.T) {
	e := newAdapterEnv(t, httpapi.InputAdapterConfig{})
	old := e.previousRelease(t, httpapi.InputAdapterConfig{})
	now := time.Now().UnixNano() - int64(time.Minute)
	body := lokiJSON(t, e.shards, now, "alpha", "alpha", "beta")
	const entries = 80 * 3

	first := e.postVia(t, old, "/adapters/v1/loki/push", e.s1.Credential, lokiHeaders(), body)
	if first.Status != 200 || first.Failed != 0 || len(first.Children) < 3 {
		t.Fatalf("the previous release's admission: %d %s", first.Status, first.Body)
	}
	if got := e.count(t, e.p1, model.Log); got != entries {
		t.Fatalf("%d logs after the first admission, want %d", got, entries)
	}

	retry := e.post(t, "/adapters/v1/loki/push", e.s1.Credential, lokiHeaders(), body)
	if retry.Status != 200 || retry.Failed != 0 || retry.Admitted != len(first.Children) {
		t.Fatalf("the retry must be ACKed with every original receipt: %d %s", retry.Status, retry.Body)
	}
	if fmt.Sprint(retry.ids()) != fmt.Sprint(first.ids()) {
		t.Fatalf("the retry became a new request:\n first %v\n retry %v", first.ids(), retry.ids())
	}
	for i, c := range retry.Children {
		r0 := first.Children[i].Receipt
		if c.Receipt == nil || r0 == nil || c.Receipt.Cursor.Group != r0.Cursor.Group || fmt.Sprint(c.Receipt.Cursor.Index) != fmt.Sprint(r0.Cursor.Index) {
			t.Fatalf("child %d was answered with a new durable position instead of its original receipt: %s vs %s", i, first.Body, retry.Body)
		}
	}
	if got := e.count(t, e.p1, model.Log); got != entries {
		t.Fatalf("the retry stored the lines again: %d logs, want %d", got, entries)
	}

	// Metrics: the ledger answer is the same receipts (the points themselves collapse by value).
	nowMS := time.Now().UnixMilli() - 60000
	rw := snappyBlock(remoteWriteV1([]string{"legacy_up"}, nowMS, 1))
	metricFirst := e.postVia(t, old, "/adapters/v1/prometheus/write", e.s1.Credential, rwHeaders(false), rw)
	metricRetry := e.post(t, "/adapters/v1/prometheus/write", e.s1.Credential, rwHeaders(false), rw)
	if metricFirst.Status != 200 || metricRetry.Status != 200 || fmt.Sprint(metricRetry.ids()) != fmt.Sprint(metricFirst.ids()) {
		t.Fatalf("remote write retry across the upgrade: %d %v, first %d %v", metricRetry.Status, metricRetry.ids(), metricFirst.Status, metricFirst.ids())
	}
}

// A request that the previous release admitted only in part (a child durable
// whose response was lost) is carried on under the same identifiers: the missing
// children are appended, the durable ones answered from the ledger.
func TestRetryOfAPartlyAdmittedOldRequestCompletesItWithoutDuplicates(t *testing.T) {
	e := newAdapterEnv(t, httpapi.InputAdapterConfig{})
	old := e.previousRelease(t, httpapi.InputAdapterConfig{})
	now := time.Now().UnixNano() - int64(time.Minute)
	body := lokiJSON(t, e.shards, now, "alpha", "alpha", "beta")
	const entries = 80 * 3

	e.adm.arm(2)
	first := e.postVia(t, old, "/adapters/v1/loki/push", e.s1.Credential, lokiHeaders(), body)
	if first.Status != 503 || first.Failed != 1 {
		t.Fatalf("setup: the previous release's attempt must lose one response: %d %s", first.Status, first.Body)
	}
	e.adm.arm()
	retry := e.post(t, "/adapters/v1/loki/push", e.s1.Credential, lokiHeaders(), body)
	if retry.Status != 200 || retry.Failed != 0 || fmt.Sprint(retry.ids()) != fmt.Sprint(first.ids()) {
		t.Fatalf("the retry must complete the request under its own identifiers: %d\n first %v\n retry %v", retry.Status, first.ids(), retry.ids())
	}
	if got := e.count(t, e.p1, model.Log); got != entries {
		t.Fatalf("%d logs after the completed retry, want %d", got, entries)
	}
}

// The lookup of the previous identity ends with the receipt dedup window: past
// LegacyIdentityUntil a retry is a request under the current identity.
func TestLegacyIdentityLookupEndsAtItsWindow(t *testing.T) {
	expired := httpapi.InputAdapterConfig{LegacyIdentityUntil: time.Now().Add(-time.Hour)}
	e := newAdapterEnv(t, expired)
	old := e.previousRelease(t, httpapi.InputAdapterConfig{})
	body := lokiJSON(t, e.shards[:1], time.Now().UnixNano()-int64(time.Minute), "alpha")
	first := e.postVia(t, old, "/adapters/v1/loki/push", e.s1.Credential, lokiHeaders(), body)
	retry := e.post(t, "/adapters/v1/loki/push", e.s1.Credential, lokiHeaders(), body)
	if first.Status != 200 || retry.Status != 200 {
		t.Fatalf("%d %s / %d %s", first.Status, first.Body, retry.Status, retry.Body)
	}
	if fmt.Sprint(retry.ids()) == fmt.Sprint(first.ids()) {
		t.Fatal("the lookup of the previous identity ran after its window")
	}
}

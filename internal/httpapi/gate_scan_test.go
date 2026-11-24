//go:build soundpost_faults

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// gateScanLine is the harness's ScanLine, field for field.
type gateScanLine struct {
	Req     string `json:"req"`
	Route   string `json:"route"`
	Pages   uint64 `json:"pages"`
	Rows    uint64 `json:"rows"`
	Bytes   uint64 `json:"bytes"`
	MS      int64  `json:"ms"`
	Partial bool   `json:"partial"`
}

func gateScans(t *testing.T, dir string) []gateScanLine {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "scans.jsonl"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []gateScanLine
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var l gateScanLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("not a scan line: %v: %s", err, sc.Text())
		}
		out = append(out, l)
	}
	return out
}

func gateHeader(id string) func(*http.Request) {
	return func(r *http.Request) {
		if id != "" {
			r.Header.Set("X-Gate-Request", id)
		}
	}
}

// A trace view carrying X-Gate-Request writes one scan line with the pages, rows and bytes the span
// scan read; a request without a well-formed id writes nothing.
func TestGateScanTraceViewCountsItsScan(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SOUNDPOST_FAULT_DIR", dir)
	trace := model.NewID()
	a, b, c := tSpan(trace, 1, 0, 0, 100), tSpan(trace, 2, 1, 0, 70), tSpan(trace, 3, 1, 0, 40)
	first, second := pageOf(false, &a, &b), pageOf(true, &c)
	first.Bytes, second.Bytes = 1000, 234
	e := newTrEnv(t, httpapi.NewStorageSpanSource(&fakeScanner{pages: []storage.Page{first, second}}))
	project := model.NewID()
	org := e.org("gate trace", project)
	reader := e.user(org, "gate-trace-reader@example.test")
	e.grant(org, reader, project, true, auth.Read)
	post := func(id string) (int, []byte) {
		return (&evEnv{isoEnv: e.isoEnv, srv: e.srv}).post(reader, "/api/v1/traces/view", traceBody(org, project, trace), gateHeader(id))
	}

	for _, id := range []string{"", "0123456789ABCDEF", "0123456789abcde", "0123456789abcdef0", "0123456789abcdeg"} {
		if status, raw := post(id); status != 200 {
			t.Fatalf("id %q: %d %s", id, status, raw)
		}
	}
	if got := gateScans(t, dir); len(got) != 0 {
		t.Fatalf("a request without a well-formed id was counted: %+v", got)
	}

	status, raw := post("0123456789abcdef")
	if status != 200 {
		t.Fatalf("%d %s", status, raw)
	}
	if v := decodeTrace(t, raw); !v.Partial {
		t.Fatalf("the second page said partial: %s", raw)
	}
	got := gateScans(t, dir)
	if len(got) != 1 {
		t.Fatalf("scan lines: %+v", got)
	}
	// The loss and error reads of the view go through the same scanner but serve no page here, so the line is the span scan's.
	if l := got[0]; l.Req != "0123456789abcdef" || l.Route != "trace_view" || l.Pages != 2 || l.Rows != 3 || l.Bytes != 1234 || !l.Partial || l.MS < 0 {
		t.Fatalf("scan line: %+v", l)
	}

	// An error answer is accounted too.
	status, _ = (&evEnv{isoEnv: e.isoEnv, srv: e.srv}).post(reader, "/api/v1/traces/view", traceBody(org, model.NewID(), trace), gateHeader("fedcba9876543210"))
	if status != 404 {
		t.Fatalf("guessed project: %d", status)
	}
	if got = gateScans(t, dir); len(got) != 2 || got[1].Req != "fedcba9876543210" || got[1].Pages != 0 || got[1].Partial {
		t.Fatalf("scan lines after the refused request: %+v", got)
	}
}

// A RED request over real stored spans writes one scan line with non-zero pages, rows and bytes.
func TestGateScanServiceREDCountsItsScan(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SOUNDPOST_FAULT_DIR", dir)
	r := newREDRig(t)
	for i := range 3 {
		r.span(spanSpec{at: r.start.Add(time.Duration(i) * time.Second), kind: "server", status: "ok", duration: 10 * time.Millisecond})
	}
	body := clBody{"org": r.org.String(), "projects": []string{r.project.String()}, "service": r.ids.Service.String(),
		"window": map[string]any{"start": strconv.FormatInt(r.start.UnixNano(), 10), "end": strconv.FormatInt(r.start.Add(10*time.Minute).UnixNano(), 10)}, "step_seconds": 60}
	post := func(id string) (int, []byte) {
		return (&evEnv{isoEnv: r.isoEnv, srv: r.srv}).post(r.reader, "/api/v1/services/red", body, gateHeader(id))
	}

	if status, raw := post(""); status != 200 {
		t.Fatalf("%d %s", status, raw)
	}
	if got := gateScans(t, dir); len(got) != 0 {
		t.Fatalf("a request without an id was counted: %+v", got)
	}
	status, raw := post("00112233445566ff")
	v := decodeRED(t, status, raw)
	if v.Requests == nil || *v.Requests != 3 {
		t.Fatalf("answer: %s", raw)
	}
	got := gateScans(t, dir)
	if len(got) != 1 {
		t.Fatalf("scan lines: %+v", got)
	}
	if l := got[0]; l.Req != "00112233445566ff" || l.Route != "service_red" || l.Pages == 0 || l.Rows < 3 || l.Bytes == 0 || l.Partial {
		t.Fatalf("scan line: %+v", l)
	}
}

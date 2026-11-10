// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"soundpost/internal/model"
)

func classifyOne(t *testing.T, p SourcePolicy, msg string) (model.LogRecord, string) {
	t.Helper()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	ct, err := compileTemplates(p)
	if err != nil {
		t.Fatal(err)
	}
	return p.classify(ct, []byte(msg), 0, p.modelPolicy())
}

func TestSourceTemplateClassification(t *testing.T) {
	p := baseFilePolicy(t, filepath.Join(t.TempDir(), "x.log"))
	good := map[string]struct {
		template, line string
		field, value   string
	}{
		"service started unit alpha": {"svc.started", "service started unit alpha", "unit", "alpha"},
		"request status 503":         {"http.status", "request status 503", "status", "503"},
	}
	for msg, want := range good {
		rec, drop := classifyOne(t, p, msg)
		if drop != "" || rec.TemplateID != want.template || rec.Line != want.line || rec.Fields[want.field].Text() != want.value ||
			rec.SourceClass != ClassStructured || !reflect.DeepEqual(rec.StreamLabels, model.Labels{{Name: "source", Value: "app"}}) {
			t.Fatalf("%q: drop %q record %+v", msg, drop, rec)
		}
	}
	drops := map[string]string{
		"service started unit gamma":                     DropUnapprovedValue, // structure registered, value not approved
		"request status 999":                             DropUnapprovedValue,
		"request status 0503":                            DropUnknownTemplate, // not a canonical integer
		"request status 5030000000000000000000":          DropUnknownTemplate,
		"request status -503":                            DropUnapprovedValue,
		"request status ":                                DropUnknownTemplate,
		"service started unit alpha now":                 DropUnapprovedValue, // the lazy string capture swallows more than an approved value
		" service started unit alpha":                    DropUnknownTemplate,
		"service started unit alpha\x00":                 DropUnapprovedValue,
		"":                                               DropUnknownTemplate,
		"service started unit \xff\xfe":                  DropInvalidUTF8,
		"Service started unit alpha":                     DropUnknownTemplate,
		"service started unit alpha\nrequest status 200": DropOversizeValue, // (?s): one message, never two; the capture exceeds the field bound
	}
	for msg, want := range drops {
		if rec, drop := classifyOne(t, p, msg); drop != want {
			t.Errorf("%q: drop %q (record %+v), want %q", msg, drop, rec, want)
		}
	}
}

func TestSourceMostSpecificTemplateWins(t *testing.T) {
	p := baseFilePolicy(t, filepath.Join(t.TempDir(), "x.log"))
	p.Class = ClassRestrictedRaw
	p.Raw = &RawGrant{Owner: model.ID{0x41}, Rationale: "diagnosis of the catch-all template choice", Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), MaxBytes: 64}
	// declared FIRST so declaration order alone would choose it
	p.Templates = append([]model.LogTemplate{{ID: "catch.all", Revision: 1, Line: "{message}", Severity: "info", Fields: []model.TemplateField{
		{Name: "message", Type: "string", MaxBytes: 64, Sensitivity: "restricted_raw"},
	}}}, p.Templates...)
	rec, drop := classifyOne(t, p, "service started unit beta")
	if drop != "" || rec.TemplateID != "svc.started" || rec.Fields["unit"].Text() != "beta" || rec.SourceClass != ClassRestrictedRaw {
		t.Fatalf("catch-all shadowed the registered template: %q %+v", drop, rec)
	}
	rec, drop = classifyOne(t, p, "anything else")
	if drop != "" || rec.TemplateID != "catch.all" || rec.Fields["message"].Text() != "anything else" {
		t.Fatalf("catch-all not applied to the rest: %q %+v", drop, rec)
	}
}

func TestSourceFileTimeLayoutAndUnparsedTimestamp(t *testing.T) {
	file := filepath.Join(t.TempDir(), "app.log")
	appendLines(t, file,
		"2026-11-10T10:00:00Z service started unit alpha",
		"garbage request status 200",
		"2026-11-10T10:00:01.5Z request status 503",
	)
	p := baseFilePolicy(t, file)
	p.File.TimeLayout = time.RFC3339Nano
	store, _ := mustStore(t)
	server := newRecorder()
	drain(t, newPump(t, p, store, server))
	recs := server.kinds(model.Log)
	if len(recs) != 2 {
		t.Fatalf("records %d", len(recs))
	}
	if got := *recs[0].Payload.Log.Timestamp; got != model.UnixNano(time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC).UnixNano()) {
		t.Fatalf("timestamp %d", got)
	}
	if got := *recs[1].Payload.Log.Timestamp; got != model.UnixNano(time.Date(2026, 11, 10, 10, 0, 1, 500_000_000, time.UTC).UnixNano()) {
		t.Fatalf("fractional timestamp %d", got)
	}
	if recs[0].ObservedAt != *recs[0].Payload.Log.Timestamp {
		t.Fatalf("observed time is not the source time: %d", recs[0].ObservedAt)
	}
	cp, _ := store.Load("app")
	if cp.Counters[DropBadTimestamp] != 1 {
		t.Fatalf("counters %+v", cp.Counters)
	}
}

func syslogPolicy(t testing.TB, path string, now time.Time) SourcePolicy {
	return SourcePolicy{
		Name: "syslog", Kind: KindSyslog, Class: ClassStructured, Revision: 1, Resource: testResource(),
		Labels: model.Labels{{Name: "source", Value: "app"}}, Templates: testTemplates(t),
		Syslog: &SyslogSpec{Path: path, Tags: []string{"myapp"}, StartAt: StartBeginning},
		clock:  func() time.Time { return now },
	}
}

func TestSourceSyslogFramingTagsAndTimestamps(t *testing.T) {
	// one line per supported framing, an unapproved tag, an unknown message and
	// a line that is not syslog at all
	raw, err := os.ReadFile(filepath.Join("..", "..", "tools", "fixtures", "host", "sources", "syslog-formats.log"))
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "syslog")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 10, 13, 0, 0, 0, time.UTC)
	p := syslogPolicy(t, file, now)
	store, _ := mustStore(t)
	server := newRecorder()
	drain(t, newPump(t, p, store, server))
	want := []string{"service started unit alpha", "request status 503", "service started unit beta", "request status 200"}
	if got := server.lines(); !reflect.DeepEqual(got, want) {
		t.Fatalf("lines %q, want %q", got, want)
	}
	recs := server.kinds(model.Log)
	wantTS := []time.Time{
		time.Date(2026, 11, 10, 12, 0, 1, 0, time.UTC),
		time.Date(2026, 11, 10, 12, 0, 2, 250_000_000, time.UTC),
		time.Date(2026, 11, 10, 12, 0, 3, 0, time.UTC),
		time.Date(2026, 11, 10, 12, 0, 4, 0, time.UTC),
	}
	for i, r := range recs {
		if r.Payload.Log.Timestamp == nil || *r.Payload.Log.Timestamp != model.UnixNano(wantTS[i].UnixNano()) {
			t.Fatalf("record %d timestamp %v, want %v", i, r.Payload.Log.Timestamp, wantTS[i])
		}
	}
	cp, _ := store.Load("syslog")
	if cp.Counters[DropUnapprovedSource] != 1 || cp.Counters[DropUnknownTemplate] != 1 || cp.Counters[DropBadFrame] != 1 {
		t.Fatalf("counters %+v", cp.Counters)
	}
	// a December line read in January belongs to the previous year
	jan := syslogPolicy(t, file, time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC))
	dec := filepath.Join(t.TempDir(), "dec")
	appendLines(t, dec, "Dec 31 23:59:59 h myapp: request status 200")
	jan.Syslog.Path = dec
	store2, _ := mustStore(t)
	server2 := newRecorder()
	drain(t, newPump(t, jan, store2, server2))
	if r := server2.kinds(model.Log); len(r) != 1 || *r[0].Payload.Log.Timestamp != model.UnixNano(time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC).UnixNano()) {
		t.Fatalf("year inference: %+v", r)
	}
}

func TestSourcePolicyValidationBoundaries(t *testing.T) {
	file := filepath.Join(t.TempDir(), "x.log")
	ok := func() SourcePolicy { return baseFilePolicy(t, file) }
	if err := ok().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*SourcePolicy){
		"bad name":           func(p *SourcePolicy) { p.Name = "App Log" },
		"zero revision":      func(p *SourcePolicy) { p.Revision = 0 },
		"no templates":       func(p *SourcePolicy) { p.Templates = nil },
		"two specs":          func(p *SourcePolicy) { p.Journal = &JournalSpec{Identifiers: []string{"x"}} },
		"relative path":      func(p *SourcePolicy) { p.File.Path = "app.log" },
		"unsorted labels":    func(p *SourcePolicy) { p.Labels = model.Labels{{Name: "b", Value: "1"}, {Name: "a", Value: "1"}} },
		"max records":        func(p *SourcePolicy) { p.MaxRecords = 513 },
		"tiny line":          func(p *SourcePolicy) { p.MaxLineBytes = 8 },
		"bad layout":         func(p *SourcePolicy) { p.File.TimeLayout = "not a layout" },
		"unknown class":      func(p *SourcePolicy) { p.Class = "raw" },
		"kind spec mismatch": func(p *SourcePolicy) { p.Kind = KindSyslog },
		"unregistered field": func(p *SourcePolicy) { p.Templates[0].Line = "service started unit {nope}" },
	} {
		p := ok()
		mutate(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSourceReadIsPureAndDeterministicForAPendingRange(t *testing.T) {
	file := filepath.Join(t.TempDir(), "app.log")
	appendLines(t, file, "service started unit alpha", "unknown line", "request status 200")
	p := baseFilePolicy(t, file)
	recs, next, err := Read(context.Background(), p, Checkpoint{Version: 1, Source: "app"})
	if err != nil || len(recs) != 2 {
		t.Fatalf("%v %d", err, len(recs))
	}
	// more lines arrive before the retry; the pending range must not grow
	appendLines(t, file, "request status 503")
	again, next2, err := Read(context.Background(), p, next)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(recs, again) || !reflect.DeepEqual(next, next2) {
		t.Fatalf("re-reading the pending range changed it:\n%+v\n%+v", next.Pending, next2.Pending)
	}
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

const (
	canaryBody = "authentication failure for dave password=hunter2-BODY-CANARY"
	canaryCmd  = "CMDLINE-CANARY"
)

func everyByteUnder(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		b.Write(raw)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// An unknown journal message is never copied into the export queue, the
// checkpoint or an error. Registered messages become typed approved fields.
func TestJournalUnknownMessageNotRaw(t *testing.T) {
	fj := newFakeJournal(t)
	fj.add("service started unit alpha")
	fj.add(canaryBody)
	fj.add("request status 503")
	fj.raw(`{"__CURSOR":"s=fake;i=ff","__REALTIME_TIMESTAMP":"1700000000000099","MESSAGE":[104,117,110,116,101,114,50],"SYSLOG_IDENTIFIER":"myapp","_SYSTEMD_UNIT":"myapp.service"}`) // binary message
	fj.add("service started unit beta")
	// an entry the journal should never have delivered (other unit and
	// identifier) is refused by the adapter even if its text is registered
	fj.raw(`{"__CURSOR":"s=fake;i=fe","__REALTIME_TIMESTAMP":"1700000000000098","MESSAGE":"service started unit alpha","SYSLOG_IDENTIFIER":"other","_SYSTEMD_UNIT":"other.service"}`)
	p := journalPolicy(t, fj.Command)
	store, dir := mustStore(t)
	server := newRecorder()
	pump := newPump(t, p, store, server)

	var errs []string
	for range 8 {
		res, err := pump.Cycle(context.Background())
		if err != nil {
			errs = append(errs, err.Error())
			break
		}
		if res.Scanned == 0 && !res.Advanced {
			break
		}
	}
	if len(errs) != 0 {
		t.Fatalf("cycle failed: %v", errs)
	}
	want := []string{"service started unit alpha", "request status 503", "service started unit beta"}
	if got := server.lines(); !reflect.DeepEqual(got, want) {
		t.Fatalf("exported lines %q, want exactly the registered ones %q", got, want)
	}
	// typed approved fields only
	recs := server.kinds(model.Log)
	l := recs[0].Payload.Log
	if l.TemplateID != "svc.started" || l.TemplateRevision != 1 || l.Severity != "info" || l.SourceClass != ClassStructured ||
		len(l.Fields) != 1 || l.Fields["unit"].Text() != "alpha" || len(l.Metadata) != 0 {
		t.Fatalf("typed fields wrong: %+v", l)
	}
	if l.Timestamp == nil || *l.Timestamp != model.UnixNano(1700000000000001*1000) {
		t.Fatalf("journal realtime timestamp not carried: %+v", l.Timestamp)
	}
	if l2 := recs[1].Payload.Log; l2.TemplateID != "http.status" || l2.Fields["status"].Text() != "503" || l2.Severity != "warn" {
		t.Fatalf("second record wrong: %+v", l2)
	}
	cp, _ := store.Load("journal")
	if cp.Counters[DropUnknownTemplate] != 1 || cp.Counters[DropNonTextMessage] != 1 || cp.Counters[DropUnapprovedSource] != 1 {
		t.Fatalf("drops not counted by reason: %+v", cp.Counters)
	}
	// nothing the journal said that was not approved appears anywhere that is
	// exported, persisted or reported
	var wire strings.Builder
	for _, b := range server.batches {
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		wire.Write(raw)
	}
	for place, text := range map[string]string{
		"export queue": wire.String(),
		"state dir":    everyByteUnder(t, dir),
		"argv":         joinLines(flatten(fj.argvs())),
	} {
		for _, secret := range []string{"hunter2", "BODY-CANARY", "authentication failure", canaryCmd, "--token", "dave"} {
			if strings.Contains(text, secret) {
				t.Fatalf("%s contains %q", place, secret)
			}
		}
	}
}

func flatten(in [][]string) []string {
	var out []string
	for _, a := range in {
		out = append(out, a...)
	}
	return out
}

func TestSourceStructuredPolicyCannotCarryRawField(t *testing.T) {
	file := filepath.Join(t.TempDir(), "app.log")
	p := baseFilePolicy(t, file)
	p.Templates = append(p.Templates, model.LogTemplate{ID: "free.text", Revision: 1, Line: "{message}", Severity: "info", Fields: []model.TemplateField{
		{Name: "message", Type: "string", MaxBytes: 256, Sensitivity: "restricted_raw"},
	}})
	if err := p.Validate(); err == nil {
		t.Fatal("a structured source accepted a restricted_raw template field")
	}
	// ... and a raw class without the explicit grant is invalid too
	p.Class = ClassRestrictedRaw
	if err := p.Validate(); err == nil {
		t.Fatal("restricted_raw accepted without owner, rationale, expiry and size")
	}
}

func rawPolicy(t testing.TB, path string, expires model.UnixNano) SourcePolicy {
	p := baseFilePolicy(t, path)
	p.Class = ClassRestrictedRaw
	p.Raw = &RawGrant{Owner: model.ID{0x41}, Rationale: "temporary incident diagnosis of the app log", Expires: expires, MaxBytes: 64}
	p.Templates = append(p.Templates, model.LogTemplate{ID: "free.text", Revision: 1, Line: "raw {message}", Severity: "info", Fields: []model.TemplateField{
		{Name: "message", Type: "string", MaxBytes: 64, Sensitivity: "restricted_raw"},
	}})
	return p
}

func TestSourceRestrictedRawIsExplicitBoundedAndExpiring(t *testing.T) {
	ctx := context.Background()
	file := filepath.Join(t.TempDir(), "app.log")
	appendLines(t, file, "raw disk almost full on volume 3", "raw "+strings.Repeat("y", 200), "service started unit alpha", "something else entirely")
	future := model.UnixNano(time.Now().Add(time.Hour).UnixNano())
	p := rawPolicy(t, file, future)
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	store, dir := mustStore(t)
	server := newRecorder()
	pump := newPump(t, p, store, server)
	drain(t, pump)
	want := []string{"raw disk almost full on volume 3", "service started unit alpha"}
	if got := server.lines(); !reflect.DeepEqual(got, want) {
		t.Fatalf("lines %q, want %q", got, want)
	}
	recs := server.kinds(model.Log)
	if recs[0].Payload.Log.SourceClass != ClassRestrictedRaw || recs[0].Payload.Log.Fields["message"].Text() != "disk almost full on volume 3" {
		t.Fatalf("raw record not marked/typed: %+v", recs[0].Payload.Log)
	}
	cp, _ := store.Load("app")
	if cp.Counters[DropOversizeValue] != 1 || cp.Counters[DropUnknownTemplate] != 1 {
		t.Fatalf("drops %+v", cp.Counters)
	}
	// raw content is only in the export queue, never in the durable state
	if s := everyByteUnder(t, dir); strings.Contains(s, "disk almost full") || strings.Contains(s, "yyyy") {
		t.Fatal("restricted raw content was persisted in the checkpoint directory")
	}

	// an expired grant reads nothing, whatever the source holds
	expired := rawPolicy(t, file, model.UnixNano(time.Now().Add(-time.Minute).UnixNano()))
	store2, _ := mustStore(t)
	server2 := newRecorder()
	_, err := newPump(t, expired, store2, server2).Cycle(ctx)
	if se, ok := AsError(err); !ok || se.Status != StatusDenied || se.Reason != ReasonRawExpired {
		t.Fatalf("got %v, want denied/raw_grant_expired", err)
	}
	if len(server2.lines()) != 0 || server2.calls != 0 {
		t.Fatal("expired raw policy still exported")
	}
}

// A batch the server refuses is not spooled: neither the pending intent nor any
// error holds the rejected content, and the source stays blocked at its
// position instead of skipping.
func TestSourceRejectedRawContentIsNeverPersisted(t *testing.T) {
	file := filepath.Join(t.TempDir(), "app.log")
	appendLines(t, file, "raw "+canaryBody)
	p := rawPolicy(t, file, model.UnixNano(time.Now().Add(time.Hour).UnixNano()))
	store, dir := mustStore(t)
	server := newRecorder()
	server.failBefore = true
	_, err := newPump(t, p, store, server).Cycle(context.Background())
	if err == nil {
		t.Fatal("rejected batch reported success")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error carries content: %v", err)
	}
	if s := everyByteUnder(t, dir); strings.Contains(s, "hunter2") || strings.Contains(s, "authentication") {
		t.Fatal("rejected raw content persisted in the state directory")
	}
	cp, _ := store.Load("app")
	if cp.Position != (Position{}) || cp.Admitted != 0 || cp.Pending == nil {
		t.Fatalf("source skipped past a rejected batch: %+v", cp)
	}
}

// The acquisition buffers that held unregistered bytes are overwritten, not
// just dropped, once the message has been classified.
func TestSourceAcquisitionBuffersAreZeroedAfterClassification(t *testing.T) {
	p := baseFilePolicy(t, filepath.Join(t.TempDir(), "x.log"))
	templates, err := compileTemplates(p)
	if err != nil {
		t.Fatal(err)
	}
	unknown := []byte(canaryBody)
	registered := []byte("service started unit alpha")
	rawKeep := [][]byte{unknown, registered}
	entries := []entry{{msg: unknown}, {msg: registered}}
	recs, dropped := classifyEntries(p, templates, entries, time.Unix(1_700_000_000, 0))
	if len(recs) != 1 || dropped[DropUnknownTemplate] != 1 {
		t.Fatalf("records %d dropped %v", len(recs), dropped)
	}
	for i, b := range rawKeep {
		for _, c := range b {
			if c != 0 {
				t.Fatalf("buffer %d still holds source bytes after classification", i)
			}
		}
	}
	for i := range entries {
		if entries[i].msg != nil {
			t.Fatalf("entry %d still references its buffer", i)
		}
	}
}

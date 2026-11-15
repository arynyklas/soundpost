// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// fakeJournal is a real executable standing in for journalctl: it honours
// --cursor / --after-cursor over an entries file, records the argv of every invocation and
// can be switched to the insufficient-permission behaviour of journalctl. The
// entries deliberately carry fields (_CMDLINE) the adapter must never export.
type fakeJournal struct {
	t       *testing.T
	dir     string
	Command string
	n       int
}

func newFakeJournal(t *testing.T) *fakeJournal {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake journalctl is a POSIX shell script")
	}
	dir := t.TempDir()
	script := `#!/bin/sh
d=$(dirname "$0")
n=$(ls "$d" | grep -c '^argv\.')
printf '%s\n' "$@" > "$d/argv.$n"
if [ -f "$d/mode" ]; then
  case "$(cat "$d/mode")" in
    denied) echo "No journal files were opened due to insufficient permissions." >&2; exit 0;;
    broken) echo "boom" >&2; exit 1;;
  esac
fi
after=""
cur=""
lines=""
for a in "$@"; do
  case "$a" in
    --after-cursor=*) after="${a#--after-cursor=}";;
    --cursor=*) cur="${a#--cursor=}";;
    --lines=*) lines="${a#--lines=}";;
  esac
done
# --cursor starts AT the cursor entry, --after-cursor just after it. A cursor
# that is no longer in the journal (vacuumed) seeks to the nearest surviving
# entry, like the real journalctl (checked against systemd 257: --after-cursor
# silently returns every survivor; --cursor's first line differs from the cursor).
out=$(awk -v after="$after" -v cur="$cur" 'BEGIN{emit=(after==""&&cur=="")} { if (emit) {print; next} if (cur!="" && index($0, "\"__CURSOR\":\"" cur "\"")>0) {emit=1; print} else if (after!="" && index($0, "\"__CURSOR\":\"" after "\"")>0) emit=1 }' "$d/entries.jsonl")
for c in "$cur" "$after"; do
  if [ -n "$c" ] && ! grep -qF "\"__CURSOR\":\"$c\"" "$d/entries.jsonl"; then
    out=$(cat "$d/entries.jsonl")
  fi
done
if [ -n "$lines" ]; then
  [ -n "$out" ] && printf '%s\n' "$out" | tail -n "$lines"
else
  [ -n "$out" ] && printf '%s\n' "$out"
fi
exit 0
`
	cmd := filepath.Join(dir, "journalctl")
	if err := os.WriteFile(cmd, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "entries.jsonl"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	return &fakeJournal{t: t, dir: dir, Command: cmd}
}

func (f *fakeJournal) add(message string) {
	f.t.Helper()
	f.n++
	f.raw(fmt.Sprintf(`{"__CURSOR":"s=fake;i=%x","__REALTIME_TIMESTAMP":"%d","_BOOT_ID":"b","MESSAGE":%q,"PRIORITY":"6","SYSLOG_IDENTIFIER":"myapp","_SYSTEMD_UNIT":"myapp.service","_CMDLINE":"/usr/bin/myapp --token=CMDLINE-CANARY"}`, f.n, 1700000000000000+int64(f.n), message))
}

func (f *fakeJournal) raw(line string) {
	f.t.Helper()
	appendLines(f.t, filepath.Join(f.dir, "entries.jsonl"), line)
}

func (f *fakeJournal) setMode(m string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "mode"), []byte(m), 0600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeJournal) argvs() [][]string {
	f.t.Helper()
	var out [][]string
	for i := 0; ; i++ {
		raw, err := os.ReadFile(filepath.Join(f.dir, fmt.Sprintf("argv.%d", i)))
		if err != nil {
			return out
		}
		out = append(out, strings.Split(strings.TrimRight(string(raw), "\n"), "\n"))
	}
}

func journalPolicy(t testing.TB, command string) SourcePolicy {
	return SourcePolicy{
		Name: "journal", Kind: KindJournal, Class: ClassStructured, Revision: 1, Resource: testResource(),
		Labels:    model.Labels{{Name: "source", Value: "app"}},
		Templates: testTemplates(t),
		Journal:   &JournalSpec{Command: command, Identifiers: []string{"myapp"}, Units: []string{"myapp.service"}, StartAt: StartBeginning},
	}
}

func TestJournalCursorContinuationAndApprovedMatches(t *testing.T) {
	fj := newFakeJournal(t)
	for _, m := range []string{"service started unit alpha", "request status 503", "service started unit beta", "request status 200"} {
		fj.add(m)
	}
	p := journalPolicy(t, fj.Command)
	p.MaxRecords = 3
	store, _ := mustStore(t)
	server := newRecorder()
	pump := newPump(t, p, store, server)
	drain(t, pump)
	want := []string{"service started unit alpha", "request status 503", "service started unit beta", "request status 200"}
	if got := server.lines(); !reflect.DeepEqual(got, want) {
		t.Fatalf("lines %q, want %q", got, want)
	}
	fj.add("service started unit alpha")
	drain(t, pump)
	if got := server.lines(); len(got) != 5 || got[4] != "service started unit alpha" {
		t.Fatalf("lines after a later entry %q", got)
	}
	for id, n := range server.ids() {
		if n != 1 {
			t.Fatalf("record %s admitted %d times", id, n)
		}
	}
	if l := server.kinds(model.Loss); len(l) != 0 {
		t.Fatalf("a journal whose cursor entry still exists reported a gap: %+v", l)
	}
	argvs := fj.argvs()
	if len(argvs) < 3 {
		t.Fatalf("expected several journalctl invocations, got %d", len(argvs))
	}
	// the first read has no cursor; the one after the first batch resumes after
	// the third entry (MaxRecords=3), and the journal is only ever asked for
	// the approved identifier and unit, with a fixed field list
	hasPrefix := func(argv []string, prefix string) bool {
		for _, a := range argv {
			if strings.HasPrefix(a, prefix) {
				return true
			}
		}
		return false
	}
	if hasPrefix(argvs[0], "--cursor") || hasPrefix(argvs[0], "--after-cursor") {
		t.Fatalf("first read already has a cursor: %q", argvs[0])
	}
	if !hasPrefix(argvs[1], "--cursor=s=fake;i=3") {
		t.Fatalf("second read does not resume at entry 3 (inclusive, to prove it still exists): %q", argvs[1])
	}
	for _, argv := range argvs {
		if !containsString(argv, "SYSLOG_IDENTIFIER=myapp") || !containsString(argv, "_SYSTEMD_UNIT=myapp.service") || !containsString(argv, "+") {
			t.Fatalf("approved matches missing: %q", argv)
		}
		if !containsString(argv, "--output=json") || !hasPrefix(argv, "--output-fields=MESSAGE,") || !containsString(argv, "--no-pager") {
			t.Fatalf("output restriction missing: %q", argv)
		}
		for _, a := range argv {
			if strings.Contains(a, "CANARY") {
				t.Fatalf("argv carries content: %q", a)
			}
		}
	}
}

func TestJournalPermissionDeniedAndMissingBinary(t *testing.T) {
	fj := newFakeJournal(t)
	fj.add("service started unit alpha")
	p := journalPolicy(t, fj.Command)
	store, _ := mustStore(t)
	server := newRecorder()
	pump := newPump(t, p, store, server)
	fj.setMode("denied")
	_, err := pump.Cycle(context.Background())
	se, ok := AsError(err)
	if !ok || se.Status != StatusDenied || se.Reason != ReasonPermission {
		t.Fatalf("got %v, want denied/permission_denied", err)
	}
	if cp, _ := store.Load("journal"); cp.Health.Status != StatusDenied || cp.Position != (Position{}) || cp.Pending != nil {
		t.Fatalf("denial state wrong: %+v", cp)
	}
	if len(server.lines()) != 0 {
		t.Fatal("a denied journal exported records")
	}
	os.Remove(filepath.Join(fj.dir, "mode"))
	drain(t, pump)
	if got := server.lines(); !reflect.DeepEqual(got, []string{"service started unit alpha"}) {
		t.Fatalf("after access returned: %q", got)
	}

	// journalctl failing for another reason is a typed read failure, not empty
	fj.setMode("broken")
	_, err = pump.Cycle(context.Background())
	if se, ok := AsError(err); !ok || se.Status != StatusUnknown || se.Reason != ReasonJournalFailed {
		t.Fatalf("got %v, want unknown/journal_failed", err)
	}

	missing := journalPolicy(t, filepath.Join(t.TempDir(), "no-such-journalctl"))
	store2, _ := mustStore(t)
	_, err = newPump(t, missing, store2, server).Cycle(context.Background())
	if se, ok := AsError(err); !ok || se.Status != StatusUnsupported || se.Reason != ReasonNotPresent {
		t.Fatalf("got %v, want unsupported/not_present", err)
	}
}

func TestJournalPolicyRefusesUnscopedOrInjectedMatches(t *testing.T) {
	for name, mutate := range map[string]func(*JournalSpec){
		"no approved match":  func(j *JournalSpec) { j.Identifiers, j.Units = nil, nil },
		"option injection":   func(j *JournalSpec) { j.Identifiers = []string{"--output=export"} },
		"dash-led option":    func(j *JournalSpec) { j.Identifiers = []string{"--all"} },
		"short option":       func(j *JournalSpec) { j.Units = []string{"-f"} },
		"match with space":   func(j *JournalSpec) { j.Units = []string{"a b"} },
		"plus separator":     func(j *JournalSpec) { j.Identifiers = []string{"+"} },
		"relative command":   func(j *JournalSpec) { j.Command = "journalctl" },
		"newline identifier": func(j *JournalSpec) { j.Identifiers = []string{"a\nb"} },
		"bad start":          func(j *JournalSpec) { j.StartAt = "yesterday" },
	} {
		p := journalPolicy(t, filepath.Join(t.TempDir(), "journalctl"))
		mutate(p.Journal)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: policy accepted", name)
		}
	}
	p := journalPolicy(t, filepath.Join(t.TempDir(), "journalctl"))
	if err := p.Validate(); err != nil {
		t.Fatalf("baseline policy rejected: %v", err)
	}
}

// Entries shaped like real journalctl JSON (including a field the adapter must
// never export and a binary MESSAGE) from the fixture directory.
func TestJournalFixtureEntries(t *testing.T) {
	fj := newFakeJournal(t)
	raw, err := os.ReadFile(filepath.Join("..", "..", "tools", "fixtures", "host", "sources", "journal-entries.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fj.dir, "entries.jsonl"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	store, dir := mustStore(t)
	server := newRecorder()
	drain(t, newPump(t, journalPolicy(t, fj.Command), store, server))
	if got := server.lines(); !reflect.DeepEqual(got, []string{"service started unit alpha"}) {
		t.Fatalf("lines %q", got)
	}
	cp, _ := store.Load("journal")
	if cp.Counters[DropUnknownTemplate] != 1 || cp.Counters[DropNonTextMessage] != 1 || cp.Position.Cursor != "s=fixture;i=3" {
		t.Fatalf("checkpoint %+v", cp)
	}
	wire, _ := json.Marshal(server.batches)
	for place, text := range map[string]string{"wire": string(wire), "state": everyByteUnder(t, dir)} {
		for _, secret := range []string{"CMDLINE-CANARY", "BODY-CANARY", "hunter2", "dave"} {
			if strings.Contains(text, secret) {
				t.Fatalf("%s contains %q", place, secret)
			}
		}
	}
}

// vacuum removes the oldest n entries of the fake journal, as journald does when
// its size or age limit is reached.
func (f *fakeJournal) vacuum(n int) {
	f.t.Helper()
	path := filepath.Join(f.dir, "entries.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		f.t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	rest := ""
	if n < len(lines) {
		rest = strings.Join(lines[n:], "\n") + "\n"
	}
	if err := os.WriteFile(path, []byte(rest), 0600); err != nil {
		f.t.Fatal(err)
	}
}

func lossesOf(s *recorder) []model.LossReport {
	var out []model.LossReport
	for _, r := range s.kinds(model.Loss) {
		out = append(out, *r.Payload.Loss)
	}
	return out
}

// A vacuumed journal no longer contains the committed cursor. journalctl
// silently seeks to what is left, so the entries between the cursor and the
// oldest survivor would vanish without a trace. The adapter exposes the loss as
// a typed loss record, keeps the surviving entries, and reports the gap once.
func TestJournalVacuumedCursorIsATypedGap(t *testing.T) {
	fj := newFakeJournal(t)
	for _, m := range []string{"service started unit alpha", "request status 503", "service started unit beta"} {
		fj.add(m)
	}
	store, dir := mustStore(t)
	server := newRecorder()
	pump := newPump(t, journalPolicy(t, fj.Command), store, server)
	drain(t, pump)
	if cp, _ := store.Load("journal"); cp.Position.Cursor != "s=fake;i=3" || len(lossesOf(server)) != 0 {
		t.Fatalf("baseline: %+v, losses %+v", cp.Position, lossesOf(server))
	}

	// entry 4 is written but never read; then journald vacuums entries 1-4,
	// including the committed cursor, and entries 5 and 6 arrive
	fj.add("service started unit gamma-never-read")
	fj.vacuum(4)
	fj.add("request status 200")
	fj.add("service started unit alpha")
	drain(t, pump)

	want := []string{"service started unit alpha", "request status 503", "service started unit beta", "request status 200", "service started unit alpha"}
	if got := server.lines(); !reflect.DeepEqual(got, want) {
		t.Fatalf("lines %q, want %q", got, want)
	}
	losses := lossesOf(server)
	if len(losses) != 1 {
		t.Fatalf("a vacuumed cursor must be exposed as exactly one loss record, got %+v", losses)
	}
	l := losses[0]
	id := testIdentity()
	if l.Reason != "truncated" || l.Signal != model.Log || l.Count < 1 || l.End < l.Start || l.Source != id.Source || l.Producer != id.Producer || l.Epoch != id.Epoch {
		t.Fatalf("loss record %+v", l)
	}
	if cp, _ := store.Load("journal"); cp.Position.Cursor != "s=fake;i=6" || cp.Pending != nil {
		t.Fatalf("checkpoint after the gap: %+v", cp)
	}

	// the gap is reported once: an idle cycle and a later entry add no second one
	drain(t, pump)
	fj.add("service started unit beta")
	drain(t, pump)
	if got := server.lines(); len(got) != 6 || got[5] != "service started unit beta" {
		t.Fatalf("lines after the gap %q", got)
	}
	if len(lossesOf(server)) != 1 {
		t.Fatalf("the gap was reported again: %+v", lossesOf(server))
	}
	for rid, n := range server.ids() {
		if n != 1 {
			t.Fatalf("record %s admitted %d times", rid, n)
		}
	}
	wire, _ := json.Marshal(server.batches)
	for place, text := range map[string]string{"wire": string(wire), "state": everyByteUnder(t, dir)} {
		for _, secret := range []string{"CMDLINE-CANARY", "gamma-never-read"} {
			if strings.Contains(text, secret) {
				t.Fatalf("%s contains %q", place, secret)
			}
		}
	}
}

// Everything vacuumed: journalctl returns nothing for the lost cursor. That is
// a gap too (never "no new entries"), it moves the position to the present so
// it is not repeated every cycle, and a later entry is read exactly once.
func TestJournalFullyVacuumedIsAGapNotAnEmptyRead(t *testing.T) {
	fj := newFakeJournal(t)
	fj.add("service started unit alpha")
	fj.add("request status 503")
	store, _ := mustStore(t)
	server := newRecorder()
	pump := newPump(t, journalPolicy(t, fj.Command), store, server)
	drain(t, pump)
	fj.vacuum(2)
	drain(t, pump)
	if got := lossesOf(server); len(got) != 1 || got[0].Reason != "truncated" || got[0].Signal != model.Log {
		t.Fatalf("losses %+v", got)
	}
	cp, _ := store.Load("journal")
	if cp.Position.Cursor != "" || cp.Position.Since <= 0 || !cp.Position.Started || cp.Pending != nil {
		t.Fatalf("position after the gap: %+v", cp)
	}
	drain(t, pump)
	fj.add("service started unit beta")
	drain(t, pump)
	if got := server.lines(); !reflect.DeepEqual(got, []string{"service started unit alpha", "request status 503", "service started unit beta"}) {
		t.Fatalf("lines %q", got)
	}
	if len(lossesOf(server)) != 1 {
		t.Fatalf("losses %+v", lossesOf(server))
	}
}

// A lost acknowledgement or a restart rebuilds the pending range of a gap
// byte-identically: the same group, no counted rebuild, the same batch IDs.
func TestJournalGapRangeIsRebuiltIdentically(t *testing.T) {
	for name, survivors := range map[string]bool{"with surviving entries": true, "nothing survives": false} {
		t.Run(name, func(t *testing.T) {
			fj := newFakeJournal(t)
			fj.add("service started unit alpha")
			p := journalPolicy(t, fj.Command)
			store, _ := mustStore(t)
			pump := newPump(t, p, store, newRecorder())
			drain(t, pump)
			fj.add("request status 503")
			fj.vacuum(2)
			if survivors {
				fj.add("service started unit beta")
			}
			cp, _ := store.Load("journal")
			recs, next, err := Read(context.Background(), p, cp)
			if err != nil || next.Pending == nil || len(next.Pending.Gaps) != 1 {
				t.Fatalf("first read: %+v %v", next.Pending, err)
			}
			if err := store.Prepare(next); err != nil {
				t.Fatal(err)
			}
			// the acknowledgement is lost: the next read starts from the stored intent
			stored, _ := store.Load("journal")
			recs2, again, err := Read(context.Background(), p, stored)
			if err != nil || again.Pending == nil {
				t.Fatalf("second read: %v", err)
			}
			if again.Pending.Group != next.Pending.Group || again.Pending.Dropped[DropRebuilt] != 0 || again.Pending.Supersedes != nil || len(recs2) != len(recs) {
				t.Fatalf("the gap range was not reproduced: first %+v, again %+v", next.Pending, again.Pending)
			}
			b1, err1 := BuildBatches(testIdentity(), p, next, recs)
			b2, err2 := BuildBatches(testIdentity(), p, again, recs2)
			if err1 != nil || err2 != nil || !reflect.DeepEqual(b1, b2) || len(b1) == 0 {
				t.Fatalf("batches differ: %v %v", err1, err2)
			}
		})
	}
}

// The line that journalctl returns instead of the lost cursor entry is an
// ordinary entry: a gap read still honours MaxRecords, and the next read
// continues from the last entry it consumed, losing and repeating nothing.
func TestJournalGapReadHonoursTheRecordLimit(t *testing.T) {
	fj := newFakeJournal(t)
	fj.add("service started unit alpha")
	p := journalPolicy(t, fj.Command)
	p.MaxRecords = 2
	store, _ := mustStore(t)
	server := newRecorder()
	pump := newPump(t, p, store, server)
	drain(t, pump)
	fj.vacuum(1)
	for _, m := range []string{"request status 200", "request status 503", "service started unit beta", "service started unit alpha"} {
		fj.add(m)
	}
	cp, _ := store.Load("journal")
	_, next, err := Read(context.Background(), p, cp)
	if err != nil || next.Pending == nil || next.Pending.Scanned != 2 || len(next.Pending.Gaps) != 1 || next.Pending.To.Cursor != "s=fake;i=3" {
		t.Fatalf("a gap read must stop at MaxRecords=2: %+v (%v)", next.Pending, err)
	}
	drain(t, pump)
	want := []string{"service started unit alpha", "request status 200", "request status 503", "service started unit beta", "service started unit alpha"}
	if got := server.lines(); !reflect.DeepEqual(got, want) {
		t.Fatalf("lines %q, want %q", got, want)
	}
	if len(lossesOf(server)) != 1 {
		t.Fatalf("losses %+v", lossesOf(server))
	}
}

// The committed entry that a resumed read starts with does not count against
// MaxRecords: a cursor that still exists yields MaxRecords new entries.
func TestJournalResumedReadHonoursTheRecordLimit(t *testing.T) {
	fj := newFakeJournal(t)
	fj.add("service started unit alpha")
	p := journalPolicy(t, fj.Command)
	p.MaxRecords = 2
	store, _ := mustStore(t)
	pump := newPump(t, p, store, newRecorder())
	drain(t, pump)
	for _, m := range []string{"request status 200", "request status 503", "service started unit beta"} {
		fj.add(m)
	}
	cp, _ := store.Load("journal")
	_, next, err := Read(context.Background(), p, cp)
	if err != nil || next.Pending == nil || next.Pending.Scanned != 2 || len(next.Pending.Gaps) != 0 || next.Pending.To.Cursor != "s=fake;i=3" {
		t.Fatalf("a resumed read must yield MaxRecords=2 new entries and no gap: %+v (%v)", next.Pending, err)
	}
}

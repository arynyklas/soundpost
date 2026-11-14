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
// --after-cursor over an entries file, records the argv of every invocation and
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
lines=""
for a in "$@"; do
  case "$a" in
    --after-cursor=*) after="${a#--after-cursor=}";;
    --lines=*) lines="${a#--lines=}";;
  esac
done
out=$(awk -v after="$after" 'BEGIN{emit=(after=="")} { if (emit) print; else if (index($0, "\"__CURSOR\":\"" after "\"")>0) emit=1 }' "$d/entries.jsonl")
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
	if hasPrefix(argvs[0], "--after-cursor") {
		t.Fatalf("first read already has a cursor: %q", argvs[0])
	}
	if !hasPrefix(argvs[1], "--after-cursor=s=fake;i=3") {
		t.Fatalf("second read does not resume after entry 3: %q", argvs[1])
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

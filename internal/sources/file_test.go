// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// drain runs cycles until nothing more is read or hopped.
func drain(t *testing.T, p *Pump) {
	t.Helper()
	for i := range 16 {
		res, err := p.Cycle(context.Background())
		if err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
		if res.Scanned == 0 && !res.Advanced {
			return
		}
	}
	t.Fatal("source never became idle")
}

type rotationFixture struct {
	t      *testing.T
	path   string
	rotate string
	server *recorder
	pump   *Pump
	store  *Store
}

func newRotationFixture(t *testing.T) *rotationFixture {
	t.Helper()
	dir := t.TempDir()
	f := &rotationFixture{t: t, path: filepath.Join(dir, "app.log"), rotate: filepath.Join(dir, "app.log.1"), server: newRecorder()}
	p := baseFilePolicy(t, f.path)
	p.File.Rotated = []string{f.rotate}
	f.store, _ = mustStore(t)
	f.pump = newPump(t, p, f.store, f.server)
	return f
}

func (f *rotationFixture) lossRecords() []model.LossReport {
	var out []model.LossReport
	for _, r := range f.server.kinds(model.Loss) {
		out = append(out, *r.Payload.Loss)
	}
	return out
}

func TestRotatedFileAndDuplicateTail(t *testing.T) {
	t.Run("rename rotation finishes the predecessor before the successor", func(t *testing.T) {
		f := newRotationFixture(t)
		appendLines(t, f.path, "service started unit alpha", "request status 200", "service started unit beta")
		drain(t, f.pump)
		// two lines land after the last read, then logrotate renames and a new
		// file starts; the agent was not running during the rotation
		appendLines(t, f.path, "request status 503", "service started unit alpha")
		if err := os.Rename(f.path, f.rotate); err != nil {
			t.Fatal(err)
		}
		appendLines(t, f.path, "request status 200", "service started unit beta")
		drain(t, f.pump)
		want := []string{
			"service started unit alpha", "request status 200", "service started unit beta",
			"request status 503", "service started unit alpha",
			"request status 200", "service started unit beta",
		}
		if got := f.server.lines(); !reflect.DeepEqual(got, want) {
			t.Fatalf("lines %q, want %q", got, want)
		}
		if l := f.lossRecords(); len(l) != 0 {
			t.Fatalf("a complete rotation reported a gap: %+v", l)
		}
		for id, n := range f.server.ids() {
			if n != 1 {
				t.Fatalf("record %s admitted %d times", id, n)
			}
		}
		// later appends to the new live file keep flowing without duplicates
		appendLines(t, f.path, "request status 503")
		drain(t, f.pump)
		if got := f.server.lines(); len(got) != len(want)+1 || got[len(got)-1] != "request status 503" {
			t.Fatalf("append after rotation: %q", got)
		}
	})

	t.Run("a predecessor that vanished exposes a truncation gap", func(t *testing.T) {
		f := newRotationFixture(t)
		appendLines(t, f.path, "service started unit alpha", "request status 200")
		drain(t, f.pump)
		appendLines(t, f.path, "request status 503", "request status 503") // never read
		if err := os.Rename(f.path, f.rotate); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(f.rotate); err != nil { // compressed away / deleted
			t.Fatal(err)
		}
		appendLines(t, f.path, "service started unit beta")
		drain(t, f.pump)
		want := []string{"service started unit alpha", "request status 200", "service started unit beta"}
		if got := f.server.lines(); !reflect.DeepEqual(got, want) {
			t.Fatalf("lines %q, want %q (the two unread lines are lost, not invented)", got, want)
		}
		losses := f.lossRecords()
		if len(losses) != 1 || losses[0].Reason != "truncated" || losses[0].Signal != model.Log || losses[0].Count < 1 {
			t.Fatalf("gap not exposed: %+v", losses)
		}
		if losses[0].Source != testIdentity().Source || losses[0].Producer != testIdentity().Producer || losses[0].Epoch != testIdentity().Epoch || losses[0].End < losses[0].Start {
			t.Fatalf("loss identity/interval wrong: %+v", losses[0])
		}
	})

	t.Run("copytruncate continues in the copy by its tail and never duplicates", func(t *testing.T) {
		f := newRotationFixture(t)
		appendLines(t, f.path, "service started unit alpha", "request status 200", "service started unit beta")
		drain(t, f.pump)
		appendLines(t, f.path, "request status 503", "service started unit alpha") // unread
		raw, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.rotate, raw, 0600); err != nil { // the copy holds all five lines
			t.Fatal(err)
		}
		if err := os.Truncate(f.path, 0); err != nil {
			t.Fatal(err)
		}
		appendLines(t, f.path, "request status 200")
		drain(t, f.pump)
		want := []string{
			"service started unit alpha", "request status 200", "service started unit beta",
			"request status 503", "service started unit alpha",
			"request status 200",
		}
		if got := f.server.lines(); !reflect.DeepEqual(got, want) {
			t.Fatalf("lines %q, want %q", got, want)
		}
		if l := f.lossRecords(); len(l) != 0 {
			t.Fatalf("copytruncate with a complete copy reported a gap: %+v", l)
		}
	})

	t.Run("in-place replacement is detected by the tail and re-read with a gap", func(t *testing.T) {
		f := newRotationFixture(t)
		appendLines(t, f.path, "service started unit alpha", "request status 200", "service started unit beta")
		drain(t, f.pump)
		// same path, same inode, longer than the committed offset, different bytes
		replacement := "request status 503\nrequest status 503\nrequest status 503\nrequest status 200\n"
		if err := os.WriteFile(f.path, []byte(replacement), 0600); err != nil {
			t.Fatal(err)
		}
		drain(t, f.pump)
		want := []string{
			"service started unit alpha", "request status 200", "service started unit beta",
			"request status 503", "request status 503", "request status 503", "request status 200",
		}
		if got := f.server.lines(); !reflect.DeepEqual(got, want) {
			t.Fatalf("lines %q, want %q", got, want)
		}
		if l := f.lossRecords(); len(l) != 1 || l[0].Reason != "truncated" {
			t.Fatalf("replacement not exposed as a gap: %+v", l)
		}
	})

	t.Run("a truncated file whose copy is missing exposes a gap", func(t *testing.T) {
		f := newRotationFixture(t)
		appendLines(t, f.path, "service started unit alpha", "request status 200")
		drain(t, f.pump)
		if err := os.Truncate(f.path, 0); err != nil {
			t.Fatal(err)
		}
		appendLines(t, f.path, "service started unit beta")
		drain(t, f.pump)
		want := []string{"service started unit alpha", "request status 200", "service started unit beta"}
		if got := f.server.lines(); !reflect.DeepEqual(got, want) {
			t.Fatalf("lines %q, want %q", got, want)
		}
		if l := f.lossRecords(); len(l) != 1 || l[0].Reason != "truncated" {
			t.Fatalf("truncation not exposed as a gap: %+v", l)
		}
	})

	t.Run("permission denial is a typed reason, never an empty source", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("file permission denial cannot be produced here (windows or root)")
		}
		f := newRotationFixture(t)
		appendLines(t, f.path, "service started unit alpha")
		drain(t, f.pump)
		before, _ := f.store.Load("app")
		if err := os.Chmod(f.path, 0); err != nil {
			t.Fatal(err)
		}
		_, err := f.pump.Cycle(context.Background())
		se, ok := AsError(err)
		if !ok || se.Status != StatusDenied || se.Reason != ReasonPermission || se.Source != "app" {
			t.Fatalf("got %v, want denied/permission_denied", err)
		}
		if strings.Contains(err.Error(), f.path) || strings.Contains(err.Error(), "app.log") {
			t.Fatalf("error leaks the path: %v", err)
		}
		after, _ := f.store.Load("app")
		if after.Position != before.Position || after.Pending != nil || after.Health.Status != StatusDenied || after.Health.Reason != ReasonPermission {
			t.Fatalf("denial changed the position or was not recorded: before %+v after %+v", before, after)
		}
		// access returns: the lines written meanwhile are read, nothing lost
		if err := os.Chmod(f.path, 0600); err != nil {
			t.Fatal(err)
		}
		appendLines(t, f.path, "request status 503")
		drain(t, f.pump)
		want := []string{"service started unit alpha", "request status 503"}
		if got := f.server.lines(); !reflect.DeepEqual(got, want) {
			t.Fatalf("lines %q, want %q", got, want)
		}
		if l := f.lossRecords(); len(l) != 0 {
			t.Fatalf("denial reported as loss: %+v", l)
		}
		if cp, _ := f.store.Load("app"); cp.Health.Status != StatusSupported {
			t.Fatalf("health not restored: %+v", cp.Health)
		}
	})

	t.Run("permission denial before the first read is denied, not missing", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("file permission denial cannot be produced here (windows or root)")
		}
		f := newRotationFixture(t)
		appendLines(t, f.path, "service started unit alpha")
		if err := os.Chmod(f.path, 0); err != nil {
			t.Fatal(err)
		}
		_, err := f.pump.Cycle(context.Background())
		se, ok := AsError(err)
		if !ok || se.Status != StatusDenied || se.Reason != ReasonPermission {
			t.Fatalf("got %v, want denied/permission_denied", err)
		}
		if cp, _ := f.store.Load("app"); cp.Health.Status != StatusDenied || cp.Position != (Position{}) {
			t.Fatalf("state %+v", cp)
		}
	})

	t.Run("a missing file is unknown, not an empty source", func(t *testing.T) {
		f := newRotationFixture(t)
		_, err := f.pump.Cycle(context.Background())
		se, ok := AsError(err)
		if !ok || se.Status != StatusUnknown || se.Reason != ReasonNotPresent {
			t.Fatalf("got %v, want unknown/not_present", err)
		}
		if cp, _ := f.store.Load("app"); cp.Position != (Position{}) || cp.Admitted != 0 {
			t.Fatalf("missing file invented a position: %+v", cp)
		}
	})

	t.Run("only complete lines are consumed", func(t *testing.T) {
		f := newRotationFixture(t)
		if err := os.WriteFile(f.path, []byte("service started unit al"), 0600); err != nil {
			t.Fatal(err)
		}
		drain(t, f.pump)
		if got := f.server.lines(); len(got) != 0 {
			t.Fatalf("a partial line was exported: %q", got)
		}
		fh, err := os.OpenFile(f.path, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		fh.WriteString("pha\nrequest status 200\n")
		fh.Close()
		drain(t, f.pump)
		want := []string{"service started unit alpha", "request status 200"}
		if got := f.server.lines(); !reflect.DeepEqual(got, want) {
			t.Fatalf("lines %q, want %q", got, want)
		}
	})

	t.Run("an over-long line is dropped by count and bounded memory, then reading resumes", func(t *testing.T) {
		f := newRotationFixture(t)
		f.pump.Policy.MaxLineBytes = 128
		long := strings.Repeat("x", 1<<20)
		appendLines(t, f.path, "service started unit alpha", long, "request status 200")
		drain(t, f.pump)
		want := []string{"service started unit alpha", "request status 200"}
		if got := f.server.lines(); !reflect.DeepEqual(got, want) {
			t.Fatalf("lines %q, want %q", got, want)
		}
		cp, _ := f.store.Load("app")
		if cp.Counters[DropOversizeLine] != 1 {
			t.Fatalf("counters %+v", cp.Counters)
		}
	})

	t.Run("default start is the current end: history is not swept in", func(t *testing.T) {
		f := newRotationFixture(t)
		f.pump.Policy.File.StartAt = ""
		appendLines(t, f.path, "service started unit alpha", "request status 200")
		drain(t, f.pump)
		if got := f.server.lines(); len(got) != 0 {
			t.Fatalf("history was exported: %q", got)
		}
		appendLines(t, f.path, "request status 503")
		drain(t, f.pump)
		if got := f.server.lines(); !reflect.DeepEqual(got, []string{"request status 503"}) {
			t.Fatalf("lines %q", got)
		}
	})
}

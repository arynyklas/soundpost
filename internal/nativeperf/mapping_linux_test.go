//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSymbolPolicyMapsRejectPathsAndBudgets(t *testing.T) {
	good := []byte("1000-2000 r-xp 00001000 08:01 42 /home/PRIVATE_CANARY/module\n2000-3000 rw-p 00002000 08:01 42 /home/PRIVATE_CANARY/module\n")
	rows, e := parseExecutableMaps(good, 4096, 8)
	if e != nil || len(rows) != 1 || rows[0].offset != 4096 || rows[0].inode != 42 {
		t.Fatal(rows, e)
	}
	for _, bad := range []string{"2000-1000 r-xp 0 08:01 42 /x\n", "1000-2000 r-xp 0 08:01 42 /home/../secret\n", "1000-2000 r-xp 0 08:01 42 /x\\777\n", "1000-2000 r-xp ffffffffffffffff 08:01 42 /x\n"} {
		if _, e := parseExecutableMaps([]byte(bad), 4096, 8); e == nil || strings.Contains(e.Error(), "secret") {
			t.Fatal("unsafe maps accepted or echoed")
		}
	}
	if _, e := parseExecutableMaps(bytes.Repeat(good, 10), 32, 8); e != ErrResourceBudget {
		t.Fatal(e)
	}
	many := []byte("1000-2000 r-xp 0 08:01 42 /x\n2000-3000 r-xp 0 08:01 42 /x\n3000-4000 r-xp 0 08:01 42 /x\n")
	if _, e := parseExecutableMaps(many, 4096, 2); e != ErrResourceBudget {
		t.Fatal(e)
	}
}
func TestSymbolPolicyMappingExportHasNoAbsoluteAddress(t *testing.T) {
	table := MappingTable{process: ProcessKey{BootID: "boot", PIDNamespace: 1, TGID: 7, ProcessStart: 1, Generation: 2}, entries: []mappingEntry{{start: 0x70000000, end: 0x70001000, offset: 0x1000, module: SafeModule{ID: moduleIdentity("ab12"), BuildID: "ab12"}}}}
	out, e := json.Marshal(table.Modules())
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(out, []byte("1879048192")) || bytes.Contains(out, []byte("home")) || bytes.Contains(out, []byte("start")) {
		t.Fatal("transient mapping escaped")
	}
	// The table itself must not serialize transient addresses either.
	raw, _ := json.Marshal(table)
	if string(raw) != "{}" {
		t.Fatal(string(raw))
	}
	safe, _ := json.Marshal(table.Mappings())
	if bytes.Contains(safe, []byte("1879048192")) || bytes.Contains(safe, []byte("home")) {
		t.Fatal("safe mapping exposed acquisition address")
	}
}
func TestSymbolPolicyNoSymlinkOrNonregularRead(t *testing.T) {
	root := t.TempDir()
	if e := os.WriteFile(filepath.Join(root, "module"), []byte("secret"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("module", filepath.Join(root, "link")); e != nil {
		t.Fatal(e)
	}
	dir, e := os.Open(root)
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	for _, p := range []string{"/link", "/../module", "/./module", "//module"} {
		if f, e := openMappedPath(int(dir.Fd()), p); e == nil {
			f.Close()
			t.Fatal("unsafe path accepted")
		}
	}
	f, e := openMappedPath(int(dir.Fd()), "/module")
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
}
func TestSymbolPolicyDeletedAndAnonymousMappingsRemainUnknown(t *testing.T) {
	rows, e := parseExecutableMaps([]byte("1000-2000 r-xp 0 00:00 0 [vdso]\n2000-3000 r-xp 0 08:01 42 /private/module (deleted)\n"), 4096, 8)
	if e != nil || len(rows) != 2 || rows[0].reason != FrameJITMissing || rows[1].reason != FrameDeleted {
		t.Fatal(rows, e)
	}
}

func TestSymbolPolicyChangedELFAndDeletedExecutableIdentity(t *testing.T) {
	f := symbolFixture(t, "hot_loop")
	before, e := fileIdentity(f)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(f.Name(), []byte("not an ELF any longer"), 0600); e != nil {
		t.Fatal(e)
	}
	after, e := fileIdentity(f)
	if e != nil || before == after || before.inode != after.inode {
		t.Fatal("same-inode replacement not detectable", e)
	}
	if _, e := readELFSymbols(context.Background(), f, 1024, 128); e == nil {
		t.Fatal("modified artifact accepted")
	}
	if e = os.Remove(f.Name()); e != nil {
		t.Fatal(e)
	}
	// A pinned FD still exists, but deleted files are never a live proc-exe
	// authorization. The live reader checks the kernel exe link on every guard.
	if _, e := fileIdentity(f); e != nil {
		t.Fatal("fixture FD unexpectedly invalid", e)
	}
}
func TestMappingReadCallerCancellationWinsIdentityFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := &MappingReader{}
	if _, e := reader.Read(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal("mapping API detached caller cancellation", e)
	}
}

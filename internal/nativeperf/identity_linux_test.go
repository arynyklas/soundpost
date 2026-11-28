//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"os"
	"testing"
)

// A reused TID/start or namespace must never reproduce the prior identity.
func TestPIDReuseIdentityIncludesThreadStart(t *testing.T) {
	a := taskIdentityDigest(7, 8, 9, 10, 11, 12, 13)
	for _, b := range []uint64{taskIdentityDigest(7, 8, 9, 10, 11, 12, 14), taskIdentityDigest(7, 8, 9, 10, 15, 12, 13), taskIdentityDigest(17, 8, 9, 10, 11, 12, 13)} {
		if a == b || b == 0 {
			t.Fatal("reused task identity joined")
		}
	}
}
func TestNamespaceResolveChecksActualTask(t *testing.T) {
	f, e := os.Open("/proc/self/ns/pid")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	ns, e := namespaceInode(f)
	if e != nil {
		t.Fatal(e)
	}
	k, e := resolveTask(os.Getpid(), NamespaceID(ns))
	if e != nil {
		t.Fatal(e)
	}
	if k.TGID != uint32(os.Getpid()) || k.TID != uint32(os.Getpid()) || k.ProcessStart == 0 || k.Generation == 0 {
		t.Fatal("incomplete checked identity")
	}
	if _, e = resolveTask(os.Getpid(), NamespaceID(ns+1)); e == nil {
		t.Fatal("foreign namespace accepted")
	}
}
func TestPIDReuseBoundedStatParser(t *testing.T) {
	// Field22 is 123 ticks; comm may itself contain parentheses and spaces.
	b := []byte("7 (private ) command) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 123 0\n")
	start, e := parseTaskStart(b, 7)
	if e != nil || start != 123 {
		t.Fatal(start, e)
	}
	for _, bad := range [][]byte{bytes.Repeat([]byte("x"), 4097), []byte("8 (secret) R 1"), bytes.Replace(b, []byte("123"), []byte("18446744073709551615"), 1)} {
		if _, e := parseTaskStart(bad, 7); e == nil {
			t.Fatal("invalid stat accepted")
		}
	}
	if _, e := resolveTask(-1, 1); e == nil {
		t.Fatal("negative task accepted")
	}
	if _, e := resolveTask(os.Getpid(), 0); e == nil {
		t.Fatal("missing namespace accepted")
	}
}
func TestExecMappingGuardRejectsInvalidation(t *testing.T) {
	// Same-inode exec requires the real perf COMM_EXEC control: metadata alone
	// cannot prove it. Invalidation must make every in-flight guard unusable.
	g := identityEpoch{generation: 1}
	before := g.generation
	if e := g.invalidate(2); e != nil {
		t.Fatal(e)
	}
	if e := g.check(before); e == nil {
		t.Fatal("delayed pre-exec read accepted")
	}
	if e := g.invalidate(2); e == nil {
		t.Fatal("generation reused")
	}
}

//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package nativeperf

import (
	"errors"
	"os"
	"testing"
)

func TestProcViewIsOwnHoldsWhereProcBelongsToThePIDNamespace(t *testing.T) {
	if _, err := os.Readlink("/proc/self"); err != nil {
		t.Skip("NOT run: /proc/self unreadable")
	}
	if err := procViewIsOwn(); err != nil {
		t.Fatalf("this process's /proc is its own PID namespace's, got %v", err)
	}
	if _, err := ResolveLocalTarget(os.Getpid()); errors.Is(err, ErrPIDNamespaceUnproven) {
		t.Fatalf("ResolveLocalTarget refused the process itself: %v", err)
	}
}

func TestPIDNamespaceUnprovenIsATargetIdentityError(t *testing.T) {
	if !errors.Is(ErrPIDNamespaceUnproven, ErrTargetIdentity) {
		t.Fatal("an unproven PID namespace must end a session like any identity loss")
	}
	if code := helperErrorCode(ErrPIDNamespaceUnproven); code != "generation_changed" {
		t.Fatalf("the closed wire code of an unproven PID namespace is %q, want generation_changed", code)
	}
}

func TestNSpidOfReadsTheKernelsChain(t *testing.T) {
	cases := []struct {
		status string
		want   []uint32
	}{
		{"Name:\tx\nNSpid:\t4242\t1\nTgid:\t4242\n", []uint32{4242, 1}},
		{"NSpid:\t77\n", []uint32{77}},
		{"Tgid:\t77\n", nil},
		{"NSpid:\t77\tzero\n", nil},
		{"NSpid:\t0\n", nil},
		{"NSpid:\t77\t0\n", nil},
		{"NSpid:\n", nil},
	}
	for _, c := range cases {
		got := nspidOf([]byte(c.status))
		if len(got) != len(c.want) {
			t.Errorf("nspidOf(%q) = %v, want %v", c.status, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("nspidOf(%q) = %v, want %v", c.status, got, c.want)
			}
		}
	}
}

// The two kernel facts about a target (ns/pid link and NSpid chain) must agree: one entry exactly when the target is in the
// reader's own PID namespace, more when it is in a descendant one, and the chain starts with the number the reader was given.
func TestNSpidProvesTheNamespaceRelation(t *testing.T) {
	const own, nested = 4026531836, 4026532292
	cases := []struct {
		name     string
		nspid    []uint32
		tgid     uint32
		targetNS uint64
		want     bool
	}{
		{"own namespace, one entry", []uint32{4242}, 4242, own, true},
		{"nested namespace, two entries", []uint32{4242, 1}, 4242, nested, true},
		{"two levels deep", []uint32{4242, 17, 1}, 4242, nested, true},
		{"no NSpid line", nil, 4242, own, false},
		{"chain starts with another number than the one read", []uint32{4243, 1}, 4242, nested, false},
		{"own namespace but a nested chain", []uint32{4242, 1}, 4242, own, false},
		{"foreign namespace but a single entry", []uint32{4242}, 4242, nested, false},
	}
	for _, c := range cases {
		if got := nspidProves(c.nspid, c.tgid, c.targetNS, own); got != c.want {
			t.Errorf("%s: nspidProves(%v, %d, %d, %d) = %v, want %v", c.name, c.nspid, c.tgid, c.targetNS, own, got, c.want)
		}
	}
}

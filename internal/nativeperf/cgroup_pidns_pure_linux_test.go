//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// 04.02-C16 mutation battery re-run (mut0402): the cgroup-v2 root discovery and the PID-namespace proof that the target
// identity rests on (cgroup_linux.go, pidns_linux.go), and the streamed identity error, pinned by their pure parts. The parts
// that read kernel files are in cgroup_root_linux_test.go and pidns_proc_linux_test.go (namespace children).

func TestParseCgroup2MountsKeepsOnlyRootedCgroup2Mounts(t *testing.T) {
	info := strings.Join([]string{
		"30 23 0:26 / /sys/fs/cgroup rw,nosuid - cgroup2 cgroup2 rw",
		"31 23 0:27 /sub /sys/fs/cgroup/sub rw - cgroup2 cgroup2 rw", // the root of its hierarchy is a sub-cgroup
		"32 23 0:28 / /sys/fs/cgroup/v1 rw - cgroup cgroup rw,cpu",
		"33 23 0:29 / /run/x rw - tmpfs tmpfs rw",
		"no separator at all",
		"30 23 0:26 / - cgroup2 cgroup2 rw", // too few fields before the separator
		"34 23 0:30 / /mnt/a\\040b rw - cgroup2",
		"35 23 0:31 / /mnt/nothing rw - ",
		"",
	}, "\n")
	want := []string{"/sys/fs/cgroup", "/mnt/a b"}
	if got := parseCgroup2Mounts([]byte(info)); !reflect.DeepEqual(got, want) {
		t.Errorf("mounts %q, want %q", got, want)
	}
	if got := parseCgroup2Mounts(nil); len(got) != 0 {
		t.Errorf("no mountinfo: %q", got)
	}
}

func TestUnescapeMountFieldDecodesOctalEscapesAndNothingElse(t *testing.T) {
	for in, want := range map[string]string{
		"plain":       "plain",
		"":            "",
		"a\\040b":     "a b",
		"a\\134b":     "a\\b",
		"x\\012y":     "x\ny",
		"\\011":       "\t",
		"a\\777":      "a\\777", // 511 is not a byte
		"a\\400":      "a\\400", // 256 is not a byte
		"a\\377":      "a\xff",
		"a\\0":        "a\\0", // truncated escape
		"\\04":        "\\04",
		"a\\08x":      "a\\08x", // not octal
		"\\0400":      " 0",
		"\\040\\040":  "  ",
		"trailing\\":  "trailing\\",
		"\\040after":  " after",
		"before\\040": "before ",
	} {
		if got := unescapeMountField(in); got != want {
			t.Errorf("unescapeMountField(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCgroup2MountOrderPrefersPureV2ThenHybridThenMountinfoOrder(t *testing.T) {
	in := []string{"/mnt/z", "/sys/fs/cgroup/unified", "/sys/fs/cgroup", "/mnt/y", "/sys/fs/cgroup", "/sys/fs/cgroup/unified"}
	want := []string{"/sys/fs/cgroup", "/sys/fs/cgroup", "/sys/fs/cgroup/unified", "/sys/fs/cgroup/unified", "/mnt/z", "/mnt/y"}
	if got := cgroup2MountOrder(in); !reflect.DeepEqual(got, want) {
		t.Errorf("order %q, want %q", got, want)
	}
	if got := cgroup2MountOrder(nil); len(got) != 0 {
		t.Errorf("no mounts: %q", got)
	}
}

func TestNSpidOfParsesTheChainAndRefusesWhatItCannotRead(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status string
		want   []uint32
	}{
		{"one level", "Name:\tx\nNSpid:\t12\n", []uint32{12}},
		{"two levels, not the first line", "Name:\tx\nTgid:\t12\nNSpid:\t12\t1\nPPid:\t1\n", []uint32{12, 1}},
		{"the first line", "NSpid:\t7 3 1\n", []uint32{7, 3, 1}},
		{"no NSpid line", "Name:\tx\nTgid:\t12\n", nil},
		{"empty", "", nil},
		{"a zero entry", "NSpid:\t0\n", nil},
		{"a zero entry behind a good one", "NSpid:\t5\t0\n", nil},
		{"not a number", "NSpid:\tx\n", nil},
		{"the largest pid", "NSpid:\t4294967295\n", []uint32{4294967295}},
		{"one past 32 bits", "NSpid:\t4294967296\n", nil},
		{"32 levels", "NSpid:" + strings.Repeat("\t1", 32) + "\n", func() []uint32 {
			out := make([]uint32, 32)
			for i := range out {
				out[i] = 1
			}
			return out
		}()},
		{"33 levels", "NSpid:" + strings.Repeat("\t1", 33) + "\n", nil},
		{"a negative entry", "NSpid:\t-1\n", nil},
	} {
		if got := nspidOf([]byte(tc.status)); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestNSpidProvesOnlyWhenTheChainAndTheNamespaceLinkAgree(t *testing.T) {
	for _, tc := range []struct {
		name        string
		nspid       []uint32
		tgid        uint32
		target, own uint64
		want        bool
	}{
		{"own namespace, one level", []uint32{5}, 5, 100, 100, true},
		{"own namespace, but the chain has a second level", []uint32{5, 1}, 5, 100, 100, false},
		{"a descendant namespace, two levels", []uint32{5, 1}, 5, 200, 100, true},
		{"a descendant namespace, one level", []uint32{5}, 5, 200, 100, false},
		{"a deep descendant", []uint32{5, 3, 1}, 5, 200, 100, true},
		{"the chain starts with another pid", []uint32{6}, 5, 100, 100, false},
		{"the chain starts with another pid in a descendant", []uint32{6, 1}, 5, 200, 100, false},
		{"no chain", nil, 5, 100, 100, false},
		{"an empty chain", []uint32{}, 5, 200, 100, false},
	} {
		if got := nspidProves(tc.nspid, tc.tgid, tc.target, tc.own); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCheckNSpidAnswersUnprovenUnlessTheKernelsTwoStatementsAgree(t *testing.T) {
	st, err := os.Stat("/proc/self/ns/pid")
	if err != nil {
		t.Skip(err)
	}
	own := st.Sys().(*syscall.Stat_t).Ino
	status := func(chain string) []byte { return []byte("Name:\tx\nNSpid:\t" + chain + "\n") }
	if e := checkNSpid(status("100"), 100, own); e != nil {
		t.Errorf("a target of this namespace: %v", e)
	}
	if e := checkNSpid(status("100\t1"), 100, own+1); e != nil {
		t.Errorf("a target of a descendant namespace: %v", e)
	}
	for name, tc := range map[string]struct {
		status []byte
		tgid   uint32
		target uint64
	}{
		"the link names another namespace but the chain has one level": {status("100"), 100, own + 1},
		"the chain has two levels but the link names this namespace":   {status("100\t1"), 100, own},
		"the chain starts with another pid":                            {status("101"), 100, own},
		"no NSpid line":                                                {[]byte("Name:\tx\n"), 100, own},
	} {
		if e := checkNSpid(tc.status, tc.tgid, tc.target); !errors.Is(e, ErrPIDNamespaceUnproven) || !errors.Is(e, ErrTargetIdentity) {
			t.Errorf("%s: %v, want ErrPIDNamespaceUnproven (an ErrTargetIdentity)", name, e)
		}
	}
}

func TestProcViewIsOwnOnAHostThatMountsItsOwnProc(t *testing.T) {
	if got, e := os.Readlink("/proc/self"); e != nil || got != strconv.Itoa(os.Getpid()) {
		t.Skipf("this process does not see its own /proc (%q, %v)", got, e)
	}
	if e := procViewIsOwn(); e != nil {
		t.Errorf("the host's own /proc: %v", e)
	}
}

func TestResolveCgroupIDRefusesWhatIsNotAProcessOfThisHost(t *testing.T) {
	for _, pid := range []int{0, -1, -1 << 40, 1 << 33, 1 << 30} { // none, negative, beyond 32 bits, a pid that does not exist
		if id, e := ResolveCgroupID(pid); !errors.Is(e, ErrInvalid) || id != 0 {
			t.Errorf("pid %d: %d %v, want 0 and ErrInvalid", pid, id, e)
		}
	}
	if id, e := ResolveCgroupID(os.Getpid()); e != nil && !errors.Is(e, ErrAuthorization) {
		t.Errorf("own pid: %d %v", id, e)
	} else if e == nil && id == 0 {
		t.Error("own pid resolved to the cgroup inode 0")
	}
}

func TestHelperReplyErrorKeepsTheProvenInstantOnlyOfIdentityErrors(t *testing.T) {
	for _, tc := range []struct {
		code     string
		proven   int64
		identity bool
		is       error
	}{
		{"generation_changed", 77, true, ErrTargetIdentity},
		{"thread_coverage_changed", 77, true, ErrThreadCoverageChanged},
		{"topology_changed", 77, true, ErrTopologyChanged},
		{"generation_changed", 0, false, ErrTargetIdentity},
		{"loss", 77, false, ErrRingOverwrite},
		{"resource_limit", 77, false, ErrResources},
		{"authorization_denied", 77, false, ErrAuthorization},
	} {
		e := helperReplyError(helperReply{Error: tc.code, ProvenThrough: model.MonoNano(tc.proven)})
		if !errors.Is(e, tc.is) {
			t.Errorf("%s: %v, want %v", tc.code, e, tc.is)
		}
		var identity *IdentityError
		if got := errors.As(e, &identity); got != tc.identity {
			t.Errorf("%s with proven %d: wrapped as IdentityError = %v, want %v", tc.code, tc.proven, got, tc.identity)
		} else if got && int64(identity.ProvenThrough) != tc.proven {
			t.Errorf("%s: proven through %d, want %d", tc.code, identity.ProvenThrough, tc.proven)
		}
	}
}

//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// 04.02-C16 mutation battery re-run (mut0402, G019-G037): Ring.exited is one zero-timeout ppoll on the ring's own
// descriptor that reports only POLLHUP (a task-scoped perf event hangs up when its task exits). Pipes give the kernel's
// three answers without a perf event: a read end whose writer is gone hangs up, a read end whose writer lives reports
// nothing, and a write end whose reader is gone reports POLLERR (a descriptor that is ready, with an error, but did not
// hang up: that is not an exit). The ppoll itself failing is reachable by lowering RLIMIT_NOFILE under the one descriptor
// polled (EINVAL), in a child process.

func TestRingExitedReportsOnlyAHangUp(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	ring := &Ring{fd: r}
	if exited, e := ring.exited(); e != nil || exited {
		t.Fatalf("a live task: %v, %v", exited, e)
	}
	w.Close()
	if exited, e := ring.exited(); e != nil || !exited {
		t.Fatalf("a task that exited (the read end hung up): %v, %v", exited, e)
	}

	r2, w2, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	r2.Close()
	if exited, e := (&Ring{fd: w2}).exited(); e != nil || exited {
		t.Fatalf("a descriptor that reports POLLERR without hanging up is not an exit: %v, %v", exited, e)
	}
}

func TestRingExitedOfAClosedOrDescriptorlessRingIsClosedAndNeverExited(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	w.Close() // a hung-up descriptor: if the guard let it through, the answer would be "exited"
	for name, ring := range map[string]*Ring{
		"closed ring that still names a descriptor": {fd: r, closed: true},
		"open ring without a descriptor":            {},
	} {
		if exited, e := ring.exited(); !errors.Is(e, ErrAcquisitionClosed) || exited {
			t.Errorf("%s: %v, %v, want false and ErrAcquisitionClosed", name, exited, e)
		}
	}
	ring := &Ring{}
	ring.Close()
	if exited, e := ring.exited(); !errors.Is(e, ErrAcquisitionClosed) || exited {
		t.Errorf("a ring closed by Close: %v, %v", exited, e)
	}
}

const ringExitedChildEnv = "MUT0402_RING_EXITED_CHILD"

func TestRingExitedReportsAFailedPollAsAFailedAcquisition(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestRingExitedPollFailureChild$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), ringExitedChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	text := string(out)
	if strings.Contains(text, "RINGEXITED SKIP") {
		t.Skipf("SKIPPED: %s", text[strings.Index(text, "RINGEXITED SKIP"):])
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "RINGEXITED FAIL") {
			t.Error(line)
		}
	}
	if !strings.Contains(text, "RINGEXITED DONE") {
		t.Fatalf("the child did not finish (%v):\n%s", err, text)
	}
}

func TestRingExitedPollFailureChild(t *testing.T) {
	if os.Getenv(ringExitedChildEnv) == "" {
		t.Skip("helper of TestRingExitedReportsAFailedPollAsAFailedAcquisition")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Close() // hung up: a poll that did not fail would answer "exited"
	var limit syscall.Rlimit
	if err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		fmt.Println("RINGEXITED SKIP:", err)
		return
	}
	// ppoll refuses with EINVAL when the number of descriptors polled exceeds RLIMIT_NOFILE.
	if err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{Cur: 0, Max: limit.Max}); err != nil {
		fmt.Println("RINGEXITED SKIP: cannot lower RLIMIT_NOFILE:", err)
		return
	}
	exited, e := (&Ring{fd: r}).exited()
	if !errors.Is(e, ErrAcquisitionFailed) || exited {
		fmt.Printf("RINGEXITED FAIL a ppoll that fails answered %v, %v; want false and ErrAcquisitionFailed\n", exited, e)
	}
	fmt.Println("RINGEXITED DONE")
}

// Ring.viewAt is called with an offset inside [tail, head) by consume and by the sideband sweep. It has to measure what
// is available from the offset it is given (head - at, not head + at: the two agree only at offset zero), and refuse a
// header that is not all there.
func TestRingViewAtMeasuresTheBytesAvailableFromItsOffset(t *testing.T) {
	header := func(data []byte, at, size int) {
		binary.LittleEndian.PutUint16(data[at%len(data)+6:], uint16(size))
	}
	// 16 bytes outstanding from offset 16: a record of 16 is whole, one of 24 is not, and 8 bytes is just a header.
	data := make([]byte, 64)
	r := ringWithMeta(data, 16, 32)
	header(data, 16, 16)
	if v, size, e := r.viewAt(16, 32); e != nil || size != 16 || v.len() != 16 {
		t.Errorf("a record that is all there: size %d len %d %v", size, v.len(), e)
	}
	header(data, 16, 24)
	if _, _, e := r.viewAt(16, 32); !errors.Is(e, ErrRingMalformed) {
		t.Errorf("a record of 24 bytes with 16 outstanding from offset 16: %v, want ErrRingMalformed", e)
	}
	// fewer than a header's 8 bytes outstanding is malformed whatever the stale bytes there say
	header(data, 16, 8)
	for _, head := range []uint64{17, 20, 23} {
		if _, size, e := r.viewAt(16, head); !errors.Is(e, ErrRingMalformed) || size != 0 {
			t.Errorf("%d bytes outstanding: size %d, %v, want ErrRingMalformed", head-16, size, e)
		}
	}
	if _, _, e := r.viewAt(16, 24); e != nil {
		t.Errorf("exactly a header outstanding: %v", e)
	}
	// the same far into the ring, past one lap of the data area
	r = ringWithMeta(data, 3*64+56, 3*64+60)
	if _, _, e := r.viewAt(3*64+56, 3*64+60); !errors.Is(e, ErrRingMalformed) {
		t.Errorf("4 bytes outstanding at the end of the data area: %v", e)
	}
}

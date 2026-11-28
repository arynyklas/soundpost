//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// 04.02-C16 mutation battery re-run (mut0402): the helper's admission path (peer credential, request framing, resident
// size, descriptor and CPU census, control channel) and its kernel-file readers. Every refusal answers exactly once and
// starts nothing; the readers refuse what they cannot prove. Kernel files that the tests cannot write are replaced inside a
// private mount namespace (child process, root), as in the other namespace tests of the package.

// ---- the in-process rig -------------------------------------------------------------------------------------------

type helperRig struct {
	t        *testing.T
	helper   *Helper
	request  CaptureRequest
	acquired atomic.Int32
	ctxSeen  atomic.Pointer[context.Context]
	source   EventSource
	acquire  error
}

func newHelperRig(t *testing.T) *helperRig {
	t.Helper()
	fx := startTargetFixture(t, "/usr/bin/sleep")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	uid := uint32(os.Getuid())
	cfg := DefaultConfig(1)
	grant, e := SignStart(StartAuthorization{Installation: "fixture", UID: uid, Revision: 1, Expires: time.Now().Add(time.Hour).Unix(), Targets: []Target{fx.target}, Config: cfg, Mode: ModeCPU}, priv)
	if e != nil {
		t.Fatal(e)
	}
	r := &helperRig{t: t, request: CaptureRequest{Authorization: grant, Targets: []Target{fx.target}, Config: cfg, Mode: ModeCPU}, acquire: ErrAcquisitionPending}
	r.helper = &Helper{
		Policy: OperatorPolicy{Installation: "fixture", PublicKey: pub, UID: uid, Revision: 1, Allowlist: []Target{fx.target}},
		Budget: NewResourceBudget(),
		rss:    func(int) (uint64, error) { return 8 << 20, nil },
	}
	r.helper.Acquire = func(ctx context.Context, _ AuthorizedTargets, _ Config, _ *Reservation) (EventSource, error) {
		r.acquired.Add(1)
		r.ctxSeen.Store(&ctx)
		if r.acquire != nil {
			return nil, r.acquire
		}
		return r.source, nil
	}
	return r
}

// serve runs one connection through serveConnection and returns every reply the client received before the end of the
// stream. send writes the request side; it may keep the connection open (hold) and is told the server side.
func (r *helperRig) serve(send func(client *net.UnixConn)) (replies []helperReply) {
	r.t.Helper()
	client, server := cpuSocketPair(r.t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.helper.serveConnection(context.Background(), server)
		server.Close()
	}()
	send(client)
	got := make(chan []helperReply, 1)
	go func() {
		var all []helperReply
		for {
			var reply helperReply
			if readMessage(client, &reply) != nil {
				break
			}
			all = append(all, reply)
		}
		got <- all
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		r.t.Fatal("serveConnection did not return")
	}
	replies = <-got // the server side is closed: the reader ends at EOF
	client.Close()
	return replies
}

func (r *helperRig) expectOneRefusal(name, code string, replies []helperReply) {
	r.t.Helper()
	if len(replies) != 1 || replies[0].Error != code {
		r.t.Errorf("%s: replies %+v, want exactly one error %q", name, replies, code)
	}
	if r.acquired.Load() != 0 {
		r.t.Errorf("%s: an acquisition started behind a refusal", name)
	}
	if reasons, _ := r.helper.ClosedReasons(); !reflect.DeepEqual(reasons, map[string]uint64{code: 1}) {
		r.t.Errorf("%s: closed reasons %v, want %s once", name, reasons, code)
	}
	if b := r.helper.Budget; b.memory != 0 || b.fds != 0 {
		r.t.Errorf("%s: the refusal left %d bytes and %d descriptors charged", name, b.memory, b.fds)
	}
}

func TestHelperAnswersEachRefusalOnceAndStartsNothing(t *testing.T) {
	// a frame that is not a request
	r := newHelperRig(t)
	r.expectOneRefusal("a frame of no bytes", "authorization_denied", r.serve(func(c *net.UnixConn) { c.Write([]byte{0, 0, 0, 0}) }))
	r = newHelperRig(t)
	r.expectOneRefusal("a frame that is not JSON", "authorization_denied", r.serve(func(c *net.UnixConn) {
		c.Write([]byte{0, 0, 0, 3, 'n', 'o', 'p'})
	}))
	// a request the policy does not authorize (the grant is for another mode)
	r = newHelperRig(t)
	bad := r.request
	bad.Mode = ModeCPUOffCPU
	r.expectOneRefusal("a mode the grant does not carry", "authorization_denied", r.serve(func(c *net.UnixConn) { writeMessage(c, bad) }))
	// a resident size the helper cannot read: the capture is refused, not charged as zero
	r = newHelperRig(t)
	r.helper.rss = func(int) (uint64, error) { return 0, errors.New("no statm") }
	r.expectOneRefusal("an unreadable resident size", "resource_limit", r.serve(func(c *net.UnixConn) { writeMessage(c, r.request) }))
	// a resident size that leaves no room
	r = newHelperRig(t)
	r.helper.rss = func(int) (uint64, error) { return MaxMemoryBytes, nil }
	r.expectOneRefusal("a resident size that fills the budget", "resource_limit", r.serve(func(c *net.UnixConn) { writeMessage(c, r.request) }))
	// the acquisition refuses: one answer, and the context handed to it is over once the connection is
	r = newHelperRig(t)
	replies := r.serve(func(c *net.UnixConn) { writeMessage(c, r.request) })
	if len(replies) != 1 || replies[0].Error != "event_unavailable" || r.acquired.Load() != 1 {
		t.Fatalf("a refused acquisition: %+v acquired %d", replies, r.acquired.Load())
	}
	if ctx := r.ctxSeen.Load(); ctx == nil || (*ctx).Err() == nil {
		t.Error("the capture context outlived the connection that was refused (cancel not deferred)")
	}
	if b := r.helper.Budget; b.memory != 0 || b.fds != 0 {
		t.Errorf("the lease was not released: %d bytes, %d descriptors", b.memory, b.fds)
	}
}

// The connection closes while the helper is admitting it: the capture context cannot be bound to the socket and the helper
// refuses instead of starting an acquisition on a dead connection.
func TestHelperRefusesToAcquireOnAConnectionThatWentAway(t *testing.T) {
	r := newHelperRig(t)
	client, server := cpuSocketPair(t)
	r.helper.rss = func(int) (uint64, error) { server.Close(); return 8 << 20, nil }
	done := make(chan struct{})
	go func() { defer close(done); r.helper.serveConnection(context.Background(), server) }()
	if e := writeMessage(client, r.request); e != nil {
		t.Fatal(e)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("serveConnection did not return")
	}
	if r.acquired.Load() != 0 {
		t.Error("an acquisition started on a connection that was already closed")
	}
	if reasons, _ := r.helper.ClosedReasons(); reasons["acquisition_failed"] != 1 {
		t.Errorf("closed reasons %v, want acquisition_failed once", reasons)
	}
	if b := r.helper.Budget; b.memory != 0 || b.fds != 0 {
		t.Errorf("the lease was not released: %d bytes, %d descriptors", b.memory, b.fds)
	}
	// the same refusal, on its own
	if ctx, cancel, e := helperCaptureContext(context.Background(), server, time.Now().Add(time.Minute)); !errors.Is(e, ErrAcquisitionFailed) || ctx != nil || cancel != nil {
		t.Errorf("a closed connection: %v %v %v", ctx, cancel != nil, e)
	}
}

// ---- the control channel ------------------------------------------------------------------------------------------

type stopFake struct {
	stops   atomic.Int32
	stopErr error
}

func (s *stopFake) Next(ctx context.Context) (SanitizedEvent, error) {
	<-ctx.Done()
	return SanitizedEvent{}, ctx.Err()
}
func (s *stopFake) Close() error { return nil }
func (s *stopFake) Stop() error  { s.stops.Add(1); return s.stopErr }

func TestHelperControlChannelCarriesOnlyAStopRequest(t *testing.T) {
	// {"stop":true} reaches the source's Stop exactly once; the stream ends when the client hangs up
	r := newHelperRig(t)
	fake := &stopFake{}
	r.source, r.acquire = fake, nil
	replies := r.serve(func(c *net.UnixConn) {
		writeMessage(c, r.request)
		var ready helperReply
		if e := readMessage(c, &ready); e != nil || !ready.Ready {
			t.Errorf("ready: %+v %v", ready, e)
		}
		writeMessage(c, struct {
			Stop bool `json:"stop"`
		}{true})
		for deadline := time.Now().Add(5 * time.Second); fake.stops.Load() == 0 && time.Now().Before(deadline); {
			time.Sleep(5 * time.Millisecond)
		}
		c.CloseWrite()
	})
	if fake.stops.Load() != 1 {
		t.Errorf("Stop called %d times by a stop request, want 1 (replies %+v)", fake.stops.Load(), replies)
	}

	// anything else ends the capture without calling Stop
	for name, payload := range map[string]any{"stop false": struct {
		Stop bool `json:"stop"`
	}{false}, "unknown command": map[string]string{"command": "id"}} {
		r = newHelperRig(t)
		fake = &stopFake{}
		r.source, r.acquire = fake, nil
		r.serve(func(c *net.UnixConn) {
			writeMessage(c, r.request)
			var ready helperReply
			readMessage(c, &ready)
			writeMessage(c, payload)
		})
		if fake.stops.Load() != 0 {
			t.Errorf("%s: Stop called", name)
		}
	}

	// a Stop that fails leaves the capture running: the stream is not cancelled when the client then hangs up
	r = newHelperRig(t)
	fake = &stopFake{stopErr: errors.New("stop failed")}
	r.source, r.acquire = fake, nil
	parent, cancelParent := context.WithCancel(context.Background())
	client, server := cpuSocketPair(t)
	done := make(chan struct{})
	go func() { defer close(done); r.helper.serveConnection(parent, server); server.Close() }()
	writeMessage(client, r.request)
	var ready helperReply
	readMessage(client, &ready)
	writeMessage(client, struct {
		Stop bool `json:"stop"`
	}{true})
	for deadline := time.Now().Add(5 * time.Second); fake.stops.Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	client.Close()
	time.Sleep(300 * time.Millisecond)
	if ctx := r.ctxSeen.Load(); ctx == nil || (*ctx).Err() != nil {
		t.Error("a failed Stop was followed by the end of the capture")
	}
	cancelParent()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("serveConnection did not return")
	}
}

// ---- peer credential, resident size ---------------------------------------------------------------------------------

func TestPeerCredentialIsThePeerProcess(t *testing.T) {
	client, server := cpuSocketPair(t)
	got, e := peerCredential(server)
	if e != nil || got.UID != uint32(os.Getuid()) || got.PID != int32(os.Getpid()) {
		t.Fatalf("peer %+v %v, want uid %d pid %d", got, e, os.Getuid(), os.Getpid())
	}
	_ = client
	server.Close()
	if got, e = peerCredential(server); e == nil {
		t.Errorf("a closed connection has a peer: %+v", got)
	}
	if got, e = peerCredential(&net.UnixConn{}); e == nil {
		t.Errorf("an unopened connection has a peer: %+v", got)
	}
}

func TestChargeableMemoryChargesEachProcessOnce(t *testing.T) {
	sizes := map[int]uint64{10: 11 << 20, 20: 22 << 20}
	read := func(pid int) (uint64, error) {
		if n, ok := sizes[pid]; ok {
			return n, nil
		}
		return 0, errors.New("no such process")
	}
	if got, e := chargeableMemory(10, 20, read); e != nil || got != (MemoryUsage{HelperRSS: 11 << 20, ExportRSS: 22 << 20}) {
		t.Errorf("two processes: %+v %v", got, e)
	}
	if got, e := chargeableMemory(10, 10, read); e != nil || got != (MemoryUsage{HelperRSS: 11 << 20}) {
		t.Errorf("one process embedding the helper is charged once: %+v %v", got, e)
	}
	if _, e := chargeableMemory(99, 20, read); e == nil {
		t.Error("an unreadable helper size was charged as zero")
	}
	if got, e := chargeableMemory(10, 99, read); e == nil {
		t.Errorf("an unreadable peer size was charged as zero: %+v", got)
	}
}

func TestProcessRSSIsTheResidentSetOfTheProcessAndRefusesAnUnknownOne(t *testing.T) {
	if n, e := processRSS(os.Getpid()); e != nil || n == 0 || n%uint64(os.Getpagesize()) != 0 {
		t.Errorf("own resident size %d %v", n, e)
	}
	if n, e := processRSS(1 << 30); e == nil {
		t.Errorf("a process that does not exist has a resident size: %d", n)
	}
}

// ---- kernel files, in a private mount namespace -----------------------------------------------------------------------

const helperFilesChildEnv = "MUT0402_HELPER_FILES_CHILD"

func TestHelperKernelFileReadersRefuseWhatTheyCannotProve(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("SKIPPED: a private mount namespace needs root")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestHelperKernelFilesChild$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), helperFilesChildEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
	out, err := cmd.CombinedOutput()
	text := string(out)
	if strings.Contains(text, "HELPERFILES SKIP") {
		t.Skipf("SKIPPED: %s", text[strings.Index(text, "HELPERFILES SKIP"):])
	}
	failed := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "HELPERFILES FAIL") {
			t.Error(line)
			failed++
		}
	}
	if !strings.Contains(text, "HELPERFILES DONE") {
		t.Fatalf("the namespace child did not finish (%v):\n%s", err, text)
	}
	if err != nil && failed == 0 {
		t.Fatalf("the namespace child failed: %v\n%s", err, text)
	}
}

func TestHelperKernelFilesChild(t *testing.T) {
	if os.Getenv(helperFilesChildEnv) == "" {
		t.Skip("helper of TestHelperKernelFileReadersRefuseWhatTheyCannotProve")
	}
	if err := syscall.Mount("none", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		fmt.Println("HELPERFILES SKIP: cannot make the mount tree private:", err)
		return
	}
	dir := t.TempDir()
	fail := func(format string, args ...any) { fmt.Printf("HELPERFILES FAIL "+format+"\n", args...) }
	n := 0
	bind := func(path, content string) func() {
		n++
		file := filepath.Join(dir, fmt.Sprintf("f%d", n))
		if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mount(file, path, "", syscall.MS_BIND, ""); err != nil {
			fmt.Println("HELPERFILES SKIP: cannot bind a file over", path+":", err)
			os.Exit(0)
		}
		return func() { syscall.Unmount(path, syscall.MNT_DETACH) }
	}

	// processRSS: the second field of statm, in pages, up to the 64 MiB budget and not a page more
	page := uint64(os.Getpagesize())
	statm := "/proc/" + fmt.Sprint(os.Getpid()) + "/statm"
	rss := func(content string) (uint64, error) {
		defer bind(statm, content)()
		return processRSS(os.Getpid())
	}
	if got, e := rss("1000 7 3 0 0 0 0\n"); e != nil || got != 7*page {
		fail("statm \"1000 7 3\": %d %v, want %d (the resident field, not size or shared)", got, e, 7*page)
	}
	if got, e := rss("1000\n"); !errors.Is(e, ErrResources) {
		fail("statm with one field: %d %v, want ErrResources", got, e)
	}
	if got, e := rss("1000 many\n"); !errors.Is(e, ErrResources) {
		fail("statm with a resident field that is not a number: %d %v", got, e)
	}
	limit := MaxMemoryBytes / page
	if got, e := rss(fmt.Sprintf("1000 %d 0\n", limit)); e != nil || got != MaxMemoryBytes {
		fail("a resident set of exactly the budget: %d %v", got, e)
	}
	if got, e := rss(fmt.Sprintf("1000 %d 0\n", limit+1)); !errors.Is(e, ErrResources) {
		fail("a resident set one page over the budget: %d %v", got, e)
	}

	// OnlineCPUs: the kernel's list, strictly ascending and bounded
	online := func(content string) ([]int, error) {
		defer bind("/sys/devices/system/cpu/online", content)()
		return OnlineCPUs()
	}
	span := func(a, b int) []int {
		var out []int
		for i := a; i <= b; i++ {
			out = append(out, i)
		}
		return out
	}
	for _, tc := range []struct {
		content string
		want    []int // nil: refused
	}{
		{"0\n", []int{0}},
		{"0-3\n", span(0, 3)},
		{"0-3,8-9\n", []int{0, 1, 2, 3, 8, 9}},
		{"0-255\n", span(0, 255)},
		{"1048576\n", []int{1048576}},
		{"0-3,2-5\n", nil},
		{"3,1\n", nil},
		{"2,2\n", nil},
		{"0-3,3\n", nil},
		{"5-3\n", nil},
		{"0,5-3\n", nil},
		{"0-x\n", nil},
		{"5-x\n", nil},
		{"-1\n", nil},
		{"x\n", nil},
		{"\n", nil},
		{"0-1-2\n", nil},
		{"0-256\n", nil},
		{"0-255,300\n", nil},
		{"1048577\n", nil},
		{"0," + "\n", nil},
		{"0-3" + strings.Repeat("\n", 4096-3), span(0, 3)},
		{"0-3" + strings.Repeat("\n", 4097-3), nil},
		{"0-3" + strings.Repeat(" ", 5000), nil},
	} {
		got, e := online(tc.content)
		switch {
		case tc.want == nil && (e == nil || !errors.Is(e, ErrResources)):
			fail("online %.20q: %v %v, want ErrResources", tc.content, got, e)
		case tc.want != nil && (e != nil || !reflect.DeepEqual(got, tc.want)):
			fail("online %.20q: got %v %v", tc.content, len(got), e)
		}
	}

	// ListenHelper: a private 0700 directory of the helper's own user, no symlink, no existing socket
	if err := syscall.Mount("tmpfs", "/run", "tmpfs", 0, "mode=0755"); err != nil {
		fmt.Println("HELPERFILES SKIP: cannot mount a private /run:", err)
		os.Exit(0)
	}
	home := "/run/soundpost-perf"
	listen := func(setup func()) (*net.UnixListener, error) {
		os.RemoveAll(home)
		setup()
		return ListenHelper()
	}
	mkdir := func(mode os.FileMode, uid int) func() {
		return func() {
			os.Mkdir(home, 0o700)
			os.Chmod(home, mode)
			os.Chown(home, uid, uid)
		}
	}
	refused := func(name string, setup func()) {
		l, e := listen(setup)
		if l != nil {
			l.Close()
		}
		if !errors.Is(e, ErrAuthorization) || l != nil {
			fail("ListenHelper with %s: %v %v, want ErrAuthorization", name, l != nil, e)
		}
	}
	refused("no directory", func() {})
	refused("a 0755 directory", mkdir(0o755, os.Geteuid()))
	refused("a 0770 directory", mkdir(0o770, os.Geteuid()))
	refused("a 0750 directory", mkdir(0o750, os.Geteuid()))
	refused("a directory of another user", mkdir(0o700, 4242))
	refused("a regular file", func() { os.WriteFile(home, nil, 0o700) })
	refused("a symlink to a private directory", func() {
		os.Mkdir("/run/elsewhere", 0o700)
		os.Symlink("/run/elsewhere", home)
	})
	refused("a socket already there", func() {
		mkdir(0o700, os.Geteuid())()
		os.WriteFile(HelperSocket, nil, 0o600)
	})
	before := syscall.Umask(0o022)
	l, e := listen(mkdir(0o700, os.Geteuid()))
	if e != nil || l == nil {
		fail("ListenHelper on a private directory: %v", e)
	} else {
		if st, err := os.Lstat(HelperSocket); err != nil || st.Mode().Perm()&0o077 != 0 {
			fail("the socket is reachable by group or others: %v %v", st, err)
		}
		l.Close()
	}
	if got := syscall.Umask(before); got != 0o022 {
		fail("ListenHelper left umask %o, want 022", got)
	}

	// serveConnection: a host whose online CPU set cannot be read refuses the capture once and starts nothing
	r := newHelperRig(t)
	defer bind("/sys/devices/system/cpu/online", "garbage\n")()
	replies := r.serve(func(c *net.UnixConn) { writeMessage(c, r.request) })
	if len(replies) != 1 || replies[0].Error != "resource_limit" || r.acquired.Load() != 0 {
		fail("an unreadable CPU set: replies %+v acquired %d, want one resource_limit and no acquisition", replies, r.acquired.Load())
	}

	// OnlineCPUs on a process that cannot open one more file
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err == nil {
		if err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{Cur: 0, Max: rl.Max}); err == nil {
			if got, e := OnlineCPUs(); e == nil || len(got) != 0 {
				fmt.Printf("HELPERFILES FAIL OnlineCPUs without a descriptor to read with: %v %v\n", got, e)
			}
			syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rl)
		}
	}
	fmt.Println("HELPERFILES DONE")
}

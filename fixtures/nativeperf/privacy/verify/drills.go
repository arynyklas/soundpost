//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// runPeer is the sacrificial socket peer of the peer-death drill. It authenticates
// to the helper with a signed request, reads a few sanitized frames, announces
// "streaming" and then waits to be SIGKILLed. It prints no frame content.
func runPeer(o options) (int, error) {
	raw, e := os.ReadFile(o.requestFile)
	if e != nil {
		return exitUsage, errors.New("request file unreadable")
	}
	conn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: o.socket, Net: "unix"})
	if e != nil {
		return exitFail, errors.New("helper unreachable")
	}
	defer conn.Close()
	var length [4]byte
	putLen := func(n int) {
		length[0], length[1], length[2], length[3] = byte(n>>24), byte(n>>16), byte(n>>8), byte(n)
	}
	putLen(len(raw))
	if _, e = conn.Write(length[:]); e != nil {
		return exitFail, e
	}
	if _, e = conn.Write(raw); e != nil {
		return exitFail, e
	}
	events := 0
	for events < 4 {
		if _, e = io.ReadFull(conn, length[:]); e != nil {
			return exitFail, errors.New("helper stream ended before streaming")
		}
		n := int(length[0])<<24 | int(length[1])<<16 | int(length[2])<<8 | int(length[3])
		if n <= 0 || n > 64<<10 {
			return exitFail, errors.New("invalid frame")
		}
		payload := make([]byte, n)
		if _, e = io.ReadFull(conn, payload); e != nil {
			return exitFail, e
		}
		var reply struct {
			Error string `json:"error"`
			Ready bool   `json:"ready"`
			Event any    `json:"event"`
		}
		if json.Unmarshal(payload, &reply) != nil || reply.Error != "" {
			return exitFail, errors.New("helper refused")
		}
		if reply.Event != nil {
			events++
		}
	}
	fmt.Println("streaming")
	// Keep the connection open and do not read: the parent kills this process.
	time.Sleep(10 * time.Minute)
	return exitOK, nil
}

// operatorFile is the helper process's operator policy (public material only).
type operatorFile struct {
	PublicKey string            `json:"public_key"`
	Target    nativeperf.Target `json:"target"`
}

// runHelperProcess runs the real Helper in its own process for the helper-crash
// drill, on the private socket given by --socket.
func runHelperProcess(o options) (int, error) {
	raw, e := os.ReadFile(o.policyBlob)
	if e != nil {
		return exitUsage, errors.New("operator file unreadable")
	}
	var op operatorFile
	if e = json.Unmarshal(raw, &op); e != nil {
		return exitUsage, errors.New("operator file invalid")
	}
	public, e := hex.DecodeString(op.PublicKey)
	if e != nil || len(public) != ed25519.PublicKeySize {
		return exitUsage, errors.New("operator key invalid")
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: o.socket, Net: "unix"})
	if e != nil {
		return exitFail, errors.New("socket unavailable")
	}
	os.Chmod(o.socket, 0o600)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	helper := nativeperf.Helper{Policy: nativeperf.OperatorPolicy{Installation: "privacy-fixture", UID: uint32(os.Getuid()), Revision: 1, PublicKey: public, Allowlist: []nativeperf.Target{op.Target}}, Budget: nativeperf.NewResourceBudget(), Acquire: nativeperf.NewCPUAcquisition}
	fmt.Println("listening")
	helper.Serve(ctx, listener)
	return exitOK, nil
}

// waitPerfFDs polls until this process holds the baseline number of perf FDs.
func waitPerfFDs(baseline int, limit time.Duration) (time.Duration, bool) {
	start := time.Now()
	for time.Since(start) < limit {
		if perfFDs() == baseline {
			return time.Since(start), true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return time.Since(start), false
}

func readLine(r io.Reader, d time.Duration) (string, error) {
	ch := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(r).ReadString('\n')
		ch <- line
	}()
	select {
	case line := <-ch:
		return strings.TrimSpace(line), nil
	case <-time.After(d):
		return "", errors.New("timeout")
	}
}

// runPeerDeath: a real peer process SIGKILLed mid-capture. The in-process helper
// must stop acquisition, release every perf FD/mapping, and serve the next peer.
func runPeerDeath(env *fixtureEnv, w *workload, o options, rep *report) {
	rep.PeerDeath.Requested = true
	fail := func(format string, args ...any) {
		rep.PeerDeath.Result = "FAILED"
		rep.PeerDeath.Detail = fmt.Sprintf(format, args...)
		rep.Failures = append(rep.Failures, "peer death: "+rep.PeerDeath.Detail)
	}
	h, e := newOperator(w, nativeperf.ModeCPU)
	if e != nil {
		fail("%v", e)
		return
	}
	defer h.stop()
	if e = h.start(env, helperCPU, false); e != nil {
		fail("%v", e)
		return
	}
	baseline := perfFDs()
	request, e := h.request(2 * time.Minute)
	if e != nil {
		fail("%v", e)
		return
	}
	raw, _ := json.Marshal(request)
	requestFile := filepath.Join(h.dir, "request.json")
	if e = os.WriteFile(requestFile, raw, 0o600); e != nil {
		fail("%v", e)
		return
	}
	self, e := os.Executable()
	if e != nil {
		fail("%v", e)
		return
	}
	peer := exec.Command(self, "--role=peer", "--socket", h.sock, "--request-file", requestFile)
	stdout, e := peer.StdoutPipe()
	if e != nil {
		fail("%v", e)
		return
	}
	if e = peer.Start(); e != nil {
		fail("%v", e)
		return
	}
	defer func() { peer.Process.Kill(); peer.Wait() }()
	line, e := readLine(stdout, 20*time.Second)
	if e != nil || line != "streaming" {
		fail("peer never reached streaming (%q %v)", line, e)
		return
	}
	held := perfFDs()
	if held <= baseline {
		fail("premise: the helper held no perf FDs while streaming (%d vs %d)", held, baseline)
		return
	}
	peer.Process.Kill()
	peer.Wait()
	took, ok := waitPerfFDs(baseline, 5*time.Second)
	if !ok {
		fail("perf FDs still held %v after peer death (%d held, baseline %d)", took, perfFDs(), baseline)
		return
	}
	rep.PeerDeath.ReleasedWithin = took.Milliseconds()
	// The helper must have survived and still serve a fresh authorized peer.
	conn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: h.sock, Net: "unix"})
	if e != nil {
		fail("helper did not survive peer death: %v", e)
		return
	}
	request, _ = h.request(time.Minute)
	if e = writeFrame(conn, request); e != nil {
		conn.Close()
		fail("%v", e)
		return
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	ready, e := env.readFrame(conn)
	got := 0
	for e == nil && ready.Error == "" && got == 0 {
		var next wireReply
		next, e = env.readFrame(conn)
		if e == nil && next.Event != nil {
			got++
		}
	}
	conn.Close()
	if e != nil || !ready.Ready || got == 0 {
		fail("released resources could not be reacquired (%v ready=%v events=%d)", e, ready.Ready, got)
		return
	}
	if _, ok = waitPerfFDs(baseline, 5*time.Second); !ok {
		fail("second session leaked perf FDs")
		return
	}
	rep.PeerDeath.Result = "peer SIGKILLed mid-stream: acquisition stopped, perf FDs released, helper served the next peer"
}

// runHelperCrash: the real helper in its own process is SIGKILLed mid-capture.
// The client must see a failed stream (never a success marker), the helper process
// must be gone, and no perf.data/core/stack dump may exist afterwards.
func runHelperCrash(env *fixtureEnv, w *workload, o options, rep *report) {
	rep.HelperCrash.Requested = true
	fail := func(format string, args ...any) {
		rep.HelperCrash.Result = "FAILED"
		rep.HelperCrash.Detail = fmt.Sprintf(format, args...)
		rep.Failures = append(rep.Failures, "helper crash: "+rep.HelperCrash.Detail)
	}
	h, e := newOperator(w, nativeperf.ModeCPU)
	if e != nil {
		fail("%v", e)
		return
	}
	dir, e := os.MkdirTemp("", "soundpost-privacy-crash-")
	if e != nil {
		fail("%v", e)
		return
	}
	defer os.RemoveAll(dir)
	h.dir, h.sock = dir, filepath.Join(dir, "acquire.sock")
	opRaw, _ := json.Marshal(operatorFile{PublicKey: hex.EncodeToString(h.public), Target: w.target})
	opFile := filepath.Join(dir, "operator.json")
	if e = os.WriteFile(opFile, opRaw, 0o600); e != nil {
		fail("%v", e)
		return
	}
	self, e := os.Executable()
	if e != nil {
		fail("%v", e)
		return
	}
	proc := exec.Command(self, "--role=helper", "--socket", h.sock, "--operator-file", opFile)
	stdout, e := proc.StdoutPipe()
	if e != nil {
		fail("%v", e)
		return
	}
	if e = proc.Start(); e != nil {
		fail("%v", e)
		return
	}
	defer func() { proc.Process.Kill(); proc.Wait() }()
	if line, err := readLine(stdout, 20*time.Second); err != nil || line != "listening" {
		fail("helper process did not start (%q %v)", line, err)
		return
	}
	before := len(dumpFiles(env))
	request, e := h.request(2 * time.Minute)
	if e != nil {
		fail("%v", e)
		return
	}
	conn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: h.sock, Net: "unix"})
	if e != nil {
		fail("%v", e)
		return
	}
	defer conn.Close()
	if e = writeFrame(conn, request); e != nil {
		fail("%v", e)
		return
	}
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	ready, e := env.readFrame(conn)
	if e != nil || !ready.Ready {
		fail("separate helper process refused the signed request: %v %q", e, ready.Error)
		return
	}
	events := 0
	for events < 3 {
		reply, err := env.readFrame(conn)
		if err != nil || reply.Error != "" {
			fail("stream failed before the crash: %v %q", err, reply.Error)
			return
		}
		if reply.Event != nil {
			events++
		}
	}
	proc.Process.Kill()
	proc.Wait()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var terminal error
	for terminal == nil {
		var reply wireReply
		reply, terminal = env.readFrame(conn)
		if terminal == nil && (reply.Complete || reply.Error == "" && reply.Event == nil && reply.Proof == nil) {
			fail("crash was reported as a clean completion")
			return
		}
	}
	if !errors.Is(terminal, io.EOF) && !errors.Is(terminal, syscall.ECONNRESET) && !errors.Is(terminal, io.ErrUnexpectedEOF) {
		fail("stream ended with an unexpected error class: %v", terminal)
		return
	}
	if _, e = os.Stat(fmt.Sprintf("/proc/%d", proc.Process.Pid)); e == nil {
		fail("killed helper process still exists")
		return
	}
	if after := len(dumpFiles(env)); after != before {
		fail("%d new perf.data/core artifact(s) after the crash", after-before)
		return
	}
	rep.HelperCrash.Result = "helper process SIGKILLed mid-capture: client saw a failed stream (not a success), process gone, no dump files; the kernel releases its perf FDs with the process"
}

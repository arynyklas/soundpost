//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const HelperSocket = "/run/soundpost-perf/acquire.sock"
const maxHelperMessage = 64 << 10

type AcquisitionFactory func(context.Context, AuthorizedTargets, Config, *Reservation) (EventSource, error)
type Helper struct {
	Policy  OperatorPolicy
	Budget  *ResourceBudget
	Acquire AcquisitionFactory
}
type helperReply struct {
	Error    string            `json:"error,omitempty"`
	Event    *SanitizedEvent   `json:"event,omitempty"`
	Ready    bool              `json:"ready,omitempty"`
	Proof    *AcquisitionProof `json:"proof,omitempty"`
	Complete bool              `json:"complete,omitempty"`
}

func writeMessage(w io.Writer, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if len(b) > maxHelperMessage {
		return ErrInvalid
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	if _, e = w.Write(n[:]); e != nil {
		return e
	}
	_, e = w.Write(b)
	return e
}
func readMessage(r io.Reader, v any) error {
	var n [4]byte
	if _, e := io.ReadFull(r, n[:]); e != nil {
		return e
	}
	size := binary.BigEndian.Uint32(n[:])
	if size == 0 || size > maxHelperMessage {
		return ErrInvalid
	}
	b := make([]byte, size)
	if _, e := io.ReadFull(r, b); e != nil {
		return e
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func peerCredential(c *net.UnixConn) (PeerCredential, error) {
	raw, e := c.SyscallConn()
	if e != nil {
		return PeerCredential{}, e
	}
	var cred *syscall.Ucred
	var inner error
	e = raw.Control(func(fd uintptr) {
		cred, inner = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if e != nil {
		return PeerCredential{}, e
	}
	if inner != nil {
		return PeerCredential{}, inner
	}
	return PeerCredential{UID: cred.Uid, PID: cred.Pid}, nil
}

// Serve accepts an already private Unix listener; it never binds an IP address.
func (h *Helper) Serve(ctx context.Context, l *net.UnixListener) error {
	if h.Budget == nil {
		return ErrResources
	}
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	// One active connection bounds protocol queues and prevents concurrent baseline races.
	for {
		c, e := l.AcceptUnix()
		if e != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return e
		}
		h.serveConnection(ctx, c)
		c.Close()
	}
}
func (h *Helper) serveConnection(parent context.Context, c *net.UnixConn) {
	c.SetReadBuffer(maxHelperMessage)
	c.SetWriteBuffer(maxHelperMessage)
	c.SetDeadline(time.Now().Add(5 * time.Second))
	deny := func(e error) { writeMessage(c, helperReply{Error: helperErrorCode(e)}) }
	peer, e := peerCredential(c)
	if e != nil {
		deny(ErrAuthorization)
		return
	}
	var req CaptureRequest
	if readMessage(c, &req) != nil {
		deny(ErrAuthorization)
		return
	}
	a, e := authorizeLocal(peer, req, h.Policy)
	if e != nil {
		deny(e)
		return
	}
	// Read actual peer RSS, never trust the request's baseline assertion.
	helperRSS, e := processRSS(os.Getpid())
	if e != nil {
		deny(ErrResources)
		return
	}
	exportRSS, e := processRSS(int(peer.PID))
	if e != nil {
		deny(ErrResources)
		return
	}
	var limit syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit) != nil {
		deny(ErrResources)
		return
	}
	fds, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		deny(ErrResources)
		return
	}
	cpus, e := OnlineCPUs()
	if e != nil {
		deny(ErrResources)
		return
	}
	lease, e := h.Budget.Reserve(a, req.Config, Topology{CPUs: uint64(len(cpus)), FDLimit: limit.Cur, OpenFDs: uint64(len(fds)), PageBytes: uint64(os.Getpagesize())}, MemoryUsage{HelperRSS: helperRSS, ExportRSS: exportRSS})
	if e != nil {
		deny(e)
		return
	}
	defer lease.Close()
	for _, t := range a.targets {
		target, e := openCheckedTarget(t)
		if e != nil {
			deny(e)
			return
		}
		if e = lease.Own(target); e != nil {
			deny(e)
			return
		}
	}
	if h.Acquire == nil {
		deny(ErrAcquisitionPending)
		return
	}
	ctx, cancel, e := helperCaptureContext(parent, c, time.Unix(req.Authorization.Expires, 0))
	if e != nil {
		deny(e)
		return
	}
	defer cancel()
	source, e := h.Acquire(ctx, a, req.Config, lease)
	if e != nil {
		deny(e)
		return
	}
	defer source.Close()
	// No arbitrary control command: one bounded fixed stop message, then EOF.
	go func() {
		var control struct {
			Stop bool `json:"stop"`
		}
		if readMessage(c, &control) != nil || !control.Stop {
			cancel()
			return
		}
		stopper, ok := source.(interface{ Stop() error })
		if !ok {
			cancel()
			return
		}
		if stopper.Stop() != nil {
			return
		}
		var extra [1]byte
		c.Read(extra[:])
		cancel()
	}()
	streamHelperEvents(ctx, c, source)
}

// The signed grant bounds both acquisition and blocked socket operations. A
// peer that stops reading/writing cannot keep the single active lease forever.
func helperCaptureContext(parent context.Context, c *net.UnixConn, expires time.Time) (context.Context, context.CancelFunc, error) {
	ctx, cancel := context.WithDeadline(parent, expires)
	deadline, _ := ctx.Deadline()
	if c.SetDeadline(deadline) != nil {
		cancel()
		return nil, nil, ErrAcquisitionFailed
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	release := func() { cancel(); stop(); c.Close() }
	return ctx, release, nil
}
func processRSS(pid int) (uint64, error) {
	b, e := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/statm")
	if e != nil {
		return 0, e
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return 0, ErrResources
	}
	n, e := strconv.ParseUint(f[1], 10, 64)
	page := uint64(os.Getpagesize())
	if e != nil || n > MaxMemoryBytes/page {
		return 0, ErrResources
	}
	return n * page, nil
}

// ListenHelper refuses symlinked/non-private parent directories and existing sockets.
func ListenHelper() (*net.UnixListener, error) {
	st, e := os.Lstat("/run/soundpost-perf")
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return nil, ErrAuthorization
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != uint32(os.Geteuid()) {
		return nil, ErrAuthorization
	}
	if _, e = os.Lstat(HelperSocket); !os.IsNotExist(e) {
		return nil, ErrAuthorization
	}
	old := syscall.Umask(0077)
	defer syscall.Umask(old)
	return net.ListenUnix("unix", &net.UnixAddr{Name: HelperSocket, Net: "unix"})
}

// OnlineCPUs uses the full kernel topology, not scheduler affinity or a capped subset.
func OnlineCPUs() ([]int, error) {
	f, e := os.Open("/sys/devices/system/cpu/online")
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil || len(b) > 4096 {
		return nil, ErrResources
	}
	var out []int
	previous := -1
	for _, part := range strings.Split(strings.TrimSpace(string(b)), ",") {
		pieces := strings.Split(part, "-")
		if len(pieces) > 2 {
			return nil, ErrResources
		}
		first, e := strconv.Atoi(pieces[0])
		if e != nil || first < 0 || first <= previous {
			return nil, ErrResources
		}
		last := first
		if len(pieces) == 2 {
			last, e = strconv.Atoi(pieces[1])
			if e != nil || last < first {
				return nil, ErrResources
			}
		}
		if last > 1<<20 || last-first >= 256 || len(out)+last-first+1 > 256 {
			return nil, ErrResources
		}
		for n := first; n <= last; n++ {
			out = append(out, n)
		}
		previous = last
	}
	if len(out) == 0 {
		return nil, ErrResources
	}
	return out, nil
}

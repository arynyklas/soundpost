//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/arynyklas/soundpost/internal/nativeperf"
	"io"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

func run() error {
	pid := flag.Uint("target-pid", 0, "operator-authorized process leader")
	scenarios := flag.String("scenario", "authorized,denied,expired,fd-cap,cancel", "comma separated scenarios")
	requestPath := flag.String("request", "/run/soundpost-perf/smoke-request.json", "operator-signed baseline request")
	expiredPath := flag.String("expired-request", "", "separately operator-signed expired request (required for expired scenario)")
	budgetPath := flag.String("fd-cap-request", "", "unmodified operator-signed request for a separately FD-limited disposable helper")
	budgetPID := flag.Int("fd-cap-helper-pid", 0, "PID of separately FD-limited disposable helper; peer identity and numeric FD ceiling must match")
	flag.Parse()
	if *pid == 0 {
		return errors.New("target-pid is required")
	}
	var base nativeperf.CaptureRequest
	if e := readJSONFixture(*requestPath, &base); e != nil {
		return e
	}
	if len(base.Targets) != 1 || base.Targets[0].TGID != uint32(*pid) {
		return errors.New("fixture request target mismatch")
	}
	if e := settleRuntimeDescriptors(); e != nil {
		return e
	}
	failed := false
	for _, scenario := range strings.Split(*scenarios, ",") {
		r := base
		ctx, cancel := context.WithCancel(context.Background())
		switch scenario {
		case "authorized":
		case "denied":
			r, _ = requestFor(scenario, base, "")
		case "expired", "fd-cap":
			path := *expiredPath
			if scenario == "fd-cap" {
				path = *budgetPath
			}
			if path == "" {
				cancel()
				return errors.New("expired/fd-cap scenario requires its separately signed request fixture; no mutation qualifies")
			}
			var policy nativeperf.OperatorPolicy
			if e := readOperatorPolicy(&policy); e != nil {
				cancel()
				return e
			}
			loaded, e := requestFor(scenario, base, path)
			if e != nil {
				cancel()
				return e
			}
			r = loaded
			if e := validateSignedCase(scenario, r, base, policy, time.Now()); e != nil {
				cancel()
				return e
			}
			if scenario == "fd-cap" {
				if e := requireHelperFDCeiling(*budgetPID, len(r.Targets)); e != nil {
					cancel()
					return e
				}
			}
		case "capture":
			// the baseline request; the scenario reads real CPU samples for a short while before closing.
		case "cancel":
			cancel()
		default:
			cancel()
			return errors.New("unknown fixed scenario")
		}
		before, e := countFDs("/proc/self/fd")
		if e != nil {
			cancel()
			return e
		}
		session, e := nativeperf.OpenAuthorized(ctx, r)
		var samples uint64
		if session != nil {
			if scenario == "capture" {
				var readErr error
				samples, readErr = countSamples(ctx, session, 3*time.Second)
				if readErr != nil {
					e = readErr
				}
			}
			session.Close()
		}
		cancel()
		after, countErr := countFDs("/proc/self/fd")
		if countErr != nil {
			return countErr
		}
		status := "denied"
		if e == nil {
			status = "opened"
		}
		var capability *nativeperf.CapabilityError
		if errors.As(e, &capability) {
			status = string(capability.Status)
		}
		if errors.Is(e, nativeperf.ErrResources) {
			status = "resource_limit"
		}
		if errors.Is(e, nativeperf.ErrAcquisitionFailed) {
			status = "acquisition_failed"
		}
		if errors.Is(e, context.Canceled) {
			status = "cancelled"
		}
		ok := before == after
		switch scenario {
		case "authorized":
			ok = ok && e == nil
		case "capture":
			ok = ok && e == nil && samples > 0
		case "denied", "expired":
			ok = ok && errors.Is(e, nativeperf.ErrAuthorization)
		case "fd-cap":
			ok = ok && errors.Is(e, nativeperf.ErrResources)
		case "cancel":
			ok = ok && errors.Is(e, context.Canceled)
		}
		line := map[string]any{"scenario": scenario, "status": status, "fd_before": before, "fd_after": after, "passed": ok, "samples_claimed": 0}
		if e != nil {
			line["error"] = e.Error() // nativeperf errors are closed codes; none carries content
		}
		if scenario == "capture" {
			line["samples_claimed"] = samples
		}
		if encodeErr := json.NewEncoder(os.Stdout).Encode(line); encodeErr != nil {
			return encodeErr
		}
		failed = failed || !ok
	}
	if failed {
		return errors.New("helper smoke did not meet requested scenario outcomes")
	}
	return nil
}

func decodeFixture(reader io.Reader, v any) error {
	b, e := io.ReadAll(io.LimitReader(reader, 65537))
	if e != nil || len(b) > 65536 {
		return errors.New("operator fixture exceeds bounded JSON input")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("operator fixture is not one strict bounded JSON value")
	}
	return nil
}
func readJSONFixture(path string, v any) error {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return errors.New("required private operator fixture could not be read")
	}
	file := os.NewFile(uintptr(fd), "operator fixture")
	defer file.Close()
	st, e := file.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return errors.New("request fixture must be an owner-private regular file")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("request fixture owner mismatch")
	}
	return decodeFixture(file, v)
}
func readOperatorPolicy(policy *nativeperf.OperatorPolicy) error {
	fd, e := syscall.Open("/etc/soundpost/perf-policy.json", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return errors.New("installed helper public-key policy unavailable")
	}
	file := os.NewFile(uintptr(fd), "operator policy")
	defer file.Close()
	st, e := file.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 {
		return errors.New("installed public-key policy permissions invalid")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return errors.New("installed public-key policy is not root-owned")
	}
	return decodeFixture(file, policy)
}
func countFDs(path string) (int, error) {
	entries, e := os.ReadDir(path)
	if e != nil {
		return 0, errors.New("FD observation failed; no cleanup qualification claimed")
	}
	return len(entries), nil
}

// Verify the public-key signature before accepting an external denial fixture.
// The helper never needs nor receives the operator signing key.
func validateSignedCase(scenario string, r, base nativeperf.CaptureRequest, p nativeperf.OperatorPolicy, now time.Time) error {
	a := r.Authorization
	signature := a.Signature
	a.Signature = nil
	message, e := json.Marshal(a)
	if e != nil || len(p.PublicKey) != ed25519.PublicKeySize || !ed25519.Verify(p.PublicKey, message, signature) || a.Installation != p.Installation || a.UID != p.UID || p.UID != uint32(os.Getuid()) || a.Revision != p.Revision || uint64(r.Config.PolicyRevision) != p.Revision || !reflect.DeepEqual(r.Targets, base.Targets) || !reflect.DeepEqual(r.Targets, a.Targets) || r.Mode != a.Mode || r.Mode != base.Mode || r.Config != a.Config || r.Config.Validate() != nil {
		return errors.New("negative fixture must be independently signed with matching authorized targets/mode/config")
	}
	allowed := false
	for _, t := range p.Allowlist {
		if len(r.Targets) == 1 && reflect.DeepEqual(t, r.Targets[0]) {
			allowed = true
		}
	}
	if !allowed {
		return errors.New("negative fixture is not in operator allowlist")
	}
	switch scenario {
	case "expired":
		if a.Expires > now.Unix() {
			return errors.New("expired fixture is not expired")
		}
	case "fd-cap":
		if a.Expires <= now.Unix() || a.Expires > now.Add(24*time.Hour).Unix() || r.Config != base.Config {
			return errors.New("FD fixture must be unexpired and keep baseline valid config; deny via the disposable helper FD ceiling, not config or memory inflation")
		}
	default:
		return errors.New("not a signed negative scenario")
	}
	return nil
}

func requireHelperFDCeiling(pid, targets int) error {
	if pid <= 0 {
		return errors.New("fd-cap requires a separately FD-limited disposable helper PID")
	}
	probe, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: nativeperf.HelperSocket, Net: "unix"})
	if e != nil {
		return errors.New("could not bind FD evidence to helper peer")
	}
	raw, e := probe.SyscallConn()
	if e != nil {
		probe.Close()
		return errors.New("helper peer credential unavailable")
	}
	var credential *syscall.Ucred
	var inner error
	e = raw.Control(func(fd uintptr) {
		credential, inner = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	probe.Close()
	if e != nil || inner != nil || credential == nil || int(credential.Pid) != pid || credential.Uid != uint32(os.Geteuid()) {
		return errors.New("FD evidence PID does not match dedicated helper peer")
	}
	base := "/proc/" + strconv.Itoa(pid)
	file, e := os.Open(base + "/limits")
	if e != nil {
		return errors.New("helper FD limit evidence unavailable")
	}
	b, e := io.ReadAll(io.LimitReader(file, 16385))
	file.Close()
	if e != nil || len(b) > 16384 {
		return errors.New("helper FD limit evidence invalid")
	}
	limit := uint64(0)
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Max open files") {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				return errors.New("helper FD limit evidence malformed")
			}
			limit, e = strconv.ParseUint(fields[3], 10, 64)
			if e != nil {
				return errors.New("helper needs a finite independently configured FD ceiling")
			}
			break
		}
	}
	count, e := countFDs(base + "/fd")
	if e != nil {
		return e
	}
	// Ignore two potentially transient probe/metadata descriptors conservatively.
	// Admission charges one baseline CPU ring + three target pins, plus sockets.
	if limit == 0 || count < 2 || limit >= uint64(32+count-2+4*targets+2) {
		return errors.New("observed helper FD ceiling does not independently force admission refusal")
	}
	return nil
}

// settleRuntimeDescriptors makes the Go runtime open its network poller now (an epoll descriptor and an eventfd, created
// on the first pollable descriptor) so no scenario is charged for descriptors the runtime, not the helper session,
// owns. A leak of a session's own descriptor still changes the count of the scenario that leaked it.
func settleRuntimeDescriptors() error {
	r, w, e := os.Pipe()
	if e != nil {
		return e
	}
	r.Close()
	return w.Close()
}

// countSamples reads real CPU samples from an open session for d, then stops it. The client's own end of the capture
// surfaces as a closed read, which is not an error.
func countSamples(ctx context.Context, session *nativeperf.Session, d time.Duration) (uint64, error) {
	var ending atomic.Bool
	stop := time.AfterFunc(d, func() {
		ending.Store(true)
		session.Stop()
		session.Close()
	})
	defer stop.Stop()
	var n uint64
	for {
		item, e := session.NextItem(ctx)
		if e != nil {
			if ending.Load() || errors.Is(e, nativeperf.ErrSourceComplete) {
				return n, nil
			}
			return n, e
		}
		if item.Proof == nil && item.Event.CPUEvent != nil {
			n++
		}
	}
}

// requestFor returns the request one scenario sends and never modifies base. "denied" is the baseline without its
// signature; "expired" and "fd-cap" are separately signed fixtures read from path. A fixture is decoded into a fresh
// value: decoding into a copy of base would write through the slices the copy shares with base (Targets,
// AllowedBuildIDs) and corrupt the baseline for every later scenario ("expired" followed by "authorized" was denied
// by the real helper).
func requestFor(scenario string, base nativeperf.CaptureRequest, path string) (nativeperf.CaptureRequest, error) {
	switch scenario {
	case "denied":
		r := base
		r.Authorization.Signature = nil
		return r, nil
	case "expired", "fd-cap":
		var loaded nativeperf.CaptureRequest
		if e := readJSONFixture(path, &loaded); e != nil {
			return nativeperf.CaptureRequest{}, e
		}
		return loaded, nil
	}
	return base, nil
}

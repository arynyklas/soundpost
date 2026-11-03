//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"soundpost/internal/nativeperf"
	"strings"
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
	workload := flag.String("workload", "fixtures/nativeperf/cpu/loop", "controlled CPU workload")
	seconds := flag.Int("seconds", 10, "real capture duration")
	hz := flag.Int("hz", 99, "fixed requested rate")
	cycles := flag.Bool("cycles", false, "explicit hardware cycle opt-in")
	flag.Parse()
	if *seconds < 1 || *seconds > 60 || *hz != 99 {
		return errors.New("requires 1..60 seconds and fixed 99 Hz")
	}
	child := exec.Command(*workload)
	stdout, e := child.StdoutPipe()
	if e != nil {
		return e
	}
	if e = child.Start(); e != nil {
		return e
	}
	defer func() { child.Process.Signal(syscall.SIGTERM); child.Wait() }()
	if ready, e := bufio.NewReader(stdout).ReadString('\n'); e != nil || ready != "ready\n" {
		return errors.New("workload did not become ready")
	}
	target, e := nativeperf.ResolveLocalTarget(child.Process.Pid)
	if e != nil {
		return e
	}
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", child.Process.Pid))
	if e != nil {
		return e
	}
	group := ""
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "0::/") {
			group = strings.TrimPrefix(line, "0::")
			break
		}
	}
	if group == "" {
		return errors.New("cgroup v2 identity unavailable")
	}
	for _, part := range strings.Split(group, "/") {
		if part == ".." {
			return errors.New("cgroup namespace path not visible")
		}
	}
	st, e := os.Stat(filepath.Join("/sys/fs/cgroup", group))
	if e != nil {
		return e
	}
	target.CgroupID = st.Sys().(*syscall.Stat_t).Ino
	executable, e := elf.Open(*workload)
	if e != nil {
		return e
	}
	defer executable.Close()
	note := executable.Section(".note.gnu.build-id")
	if note == nil {
		return errors.New("GNU build ID required")
	}
	notes, e := note.Data()
	if e != nil || len(notes) < 16 {
		return errors.New("invalid build ID note")
	}
	nameSize := binary.LittleEndian.Uint32(notes)
	descSize := binary.LittleEndian.Uint32(notes[4:])
	start := 12 + (nameSize+3)&^3
	if descSize == 0 || uint64(start)+uint64(descSize) > uint64(len(notes)) {
		return errors.New("invalid build ID note bounds")
	}
	target.AllowedBuildIDs = []string{hex.EncodeToString(notes[start : start+descSize])}
	hotStart, hotEnd := uint64(0), uint64(0)
	symbols, e := executable.Symbols()
	if e != nil {
		return e
	}
	for _, symbol := range symbols {
		if symbol.Name == "soundpost_hot_loop" {
			hotStart = symbol.Value
			hotEnd = symbol.Value + symbol.Size
		}
	}
	if executable.Type != elf.ET_EXEC || hotStart == 0 || hotEnd <= hotStart {
		return errors.New("compile fixture with -fno-pie -no-pie and symbols")
	}
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	cfg := nativeperf.DefaultConfig(1)
	targets := []nativeperf.Target{target}
	grant, e := nativeperf.SignStart(nativeperf.StartAuthorization{Installation: "public-cpu-fixture", UID: uint32(os.Getuid()), Revision: 1, Expires: time.Now().Add(time.Minute).Unix(), Targets: targets, Config: cfg, Mode: nativeperf.ModeCPU}, private)
	if e != nil {
		return e
	}
	dir, e := os.MkdirTemp("", "soundpost-cpu-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dir)
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "acquire.sock"), Net: "unix"})
	if e != nil {
		return e
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	acquire := nativeperf.NewCPUAcquisition
	if *cycles {
		acquire = nativeperf.NewCyclesAcquisition
	}
	helper := nativeperf.Helper{Policy: nativeperf.OperatorPolicy{Installation: "public-cpu-fixture", UID: uint32(os.Getuid()), Revision: 1, PublicKey: public, Allowlist: targets}, Budget: nativeperf.NewResourceBudget(), Acquire: acquire}
	helperDone := make(chan error, 1)
	go func() { helperDone <- helper.Serve(ctx, listener) }()
	// Exercise the real signed/peer-credential helper protocol on a private,
	// fixture-only socket. No production socket/policy or host privilege changes.
	conn, e := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if e != nil {
		return e
	}
	defer conn.Close()
	request := nativeperf.CaptureRequest{Authorization: grant, Targets: targets, Config: cfg, Mode: nativeperf.ModeCPU}
	payload, e := json.Marshal(request)
	if e != nil {
		return e
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	if _, e = conn.Write(length[:]); e != nil {
		return e
	}
	if _, e = conn.Write(payload); e != nil {
		return e
	}
	startTime := time.Now()
	deadline := startTime.Add(time.Duration(*seconds) * time.Second)
	conn.SetReadDeadline(deadline)
	samples, lost, hot, throttle := uint64(0), uint64(0), uint64(0), uint64(0)
	threads := map[uint32]bool{}
	ready := false
	for {
		if _, e = io.ReadFull(conn, length[:]); e != nil {
			if timeout, ok := e.(net.Error); ok && timeout.Timeout() && ready {
				break
			}
			return e
		}
		size := binary.BigEndian.Uint32(length[:])
		if size == 0 || size > 64<<10 {
			return errors.New("invalid helper frame")
		}
		payload = make([]byte, size)
		if _, e = io.ReadFull(conn, payload); e != nil {
			return e
		}
		for _, canary := range []string{"SOUNDPOST_CPU_LOCAL_CANARY_2026", "SOUNDPOST_CPU_HEAP_CANARY_2026"} {
			if bytes.Contains(payload, []byte(canary)) {
				return errors.New("canary leaked")
			}
		}
		var reply struct {
			Error string
			Ready bool
			Event *nativeperf.SanitizedEvent
		}
		if e = json.Unmarshal(payload, &reply); e != nil {
			return e
		}
		if reply.Error != "" {
			return fmt.Errorf("real acquisition refused: %s", reply.Error)
		}
		if reply.Ready {
			ready = true
			continue
		}
		if reply.Event == nil {
			return errors.New("missing event")
		}
		event := reply.Event
		if e = event.Validate(); e != nil {
			return e
		}
		if event.CPUEvent != nil {
			samples++
			threads[event.Task.TID] = true
			if event.CPUEvent.IP >= hotStart && event.CPUEvent.IP < hotEnd {
				hot++
			}
			for _, frame := range event.CPUEvent.Callchain {
				if frame.IP >= 1<<56 {
					return errors.New("unsafe address exported")
				}
			}
		}
		if event.Loss != nil {
			lost += event.Loss.Count
			if event.Loss.Throttle != nil {
				throttle++
			}
		}
	}
	conn.Close()
	cancel()
	<-helperDone
	result := struct {
		Samples, Lost, HotFunctionSamples, ThrottleRecords uint64
		ObservedThreads                                    int
		ElapsedSeconds, AchievedSamplesPerSecond           float64
		RequestedHz                                        int
		Method                                             string
		CanaryLeaks                                        int
	}{samples, lost, hot, throttle, len(threads), time.Since(startTime).Seconds(), float64(samples) / time.Since(startTime).Seconds(), *hz, string(nativeperf.MethodSoftwareCPUClock), 0}
	if *cycles {
		result.Method = string(nativeperf.MethodHardwareCycles)
	}
	if e = json.NewEncoder(os.Stdout).Encode(result); e != nil {
		return e
	}
	if samples == 0 || hot == 0 || len(threads) != 2 {
		return errors.New("require real samples, known hot function and both existing workload threads")
	}
	return nil
}

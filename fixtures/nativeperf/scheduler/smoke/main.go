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
	"soundpost/internal/model"
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
	workload := flag.String("workload", "fixtures/nativeperf/scheduler/switch-wake", "real workload")
	seconds := flag.Int("seconds", 10, "capture seconds")
	flag.Parse()
	if *seconds < 1 || *seconds > 60 {
		return errors.New("seconds must be 1..60")
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
	line, e := bufio.NewReader(stdout).ReadString('\n')
	if e != nil {
		return e
	}
	var foreign int
	if _, e = fmt.Sscanf(line, "ready %d\n", &foreign); e != nil || foreign <= 0 {
		return errors.New("real foreign waker missing")
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
		}
	}
	if group == "" {
		return errors.New("visible cgroup v2 required")
	}
	for _, p := range strings.Split(group, "/") {
		if p == ".." {
			return errors.New("cgroup namespace not visible")
		}
	}
	st, e := os.Stat(filepath.Join("/sys/fs/cgroup", group))
	if e != nil {
		return e
	}
	target.CgroupID = model.Uint64(st.Sys().(*syscall.Stat_t).Ino)
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
		return errors.New("build ID note invalid")
	}
	n, d := binary.LittleEndian.Uint32(notes), binary.LittleEndian.Uint32(notes[4:])
	start := 12 + (n+3)&^3
	if d == 0 || uint64(start)+uint64(d) > uint64(len(notes)) {
		return errors.New("build ID bounds")
	}
	target.AllowedBuildIDs = []string{hex.EncodeToString(notes[start : start+d])}
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	cfg := nativeperf.DefaultConfig(1)
	targets := []nativeperf.Target{target}
	grant, e := nativeperf.SignStart(nativeperf.StartAuthorization{Installation: "public-scheduler-fixture", UID: uint32(os.Getuid()), Revision: 1, Expires: time.Now().Add(2 * time.Minute).Unix(), Targets: targets, Config: cfg, Mode: nativeperf.ModeCPUOffCPU}, private)
	if e != nil {
		return e
	}
	dir, e := os.MkdirTemp("", "soundpost-scheduler-")
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
	helper := nativeperf.Helper{Policy: nativeperf.OperatorPolicy{Installation: "public-scheduler-fixture", UID: uint32(os.Getuid()), Revision: 1, PublicKey: public, Allowlist: targets}, Budget: nativeperf.NewResourceBudget(), Acquire: nativeperf.NewNativeAcquisition}
	go helper.Serve(ctx, listener)
	conn, e := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if e != nil {
		return e
	}
	defer conn.Close()
	write := func(v any) error {
		b, e := json.Marshal(v)
		if e != nil {
			return e
		}
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		if _, e = conn.Write(n[:]); e != nil {
			return e
		}
		_, e = conn.Write(b)
		return e
	}
	if e = write(nativeperf.CaptureRequest{Authorization: grant, Targets: targets, Config: cfg, Mode: nativeperf.ModeCPUOffCPU}); e != nil {
		return e
	}
	conn.SetDeadline(time.Now().Add(time.Duration(*seconds+20) * time.Second))
	timer := time.AfterFunc(time.Duration(*seconds)*time.Second, func() {
		write(struct {
			Stop bool `json:"stop"`
		}{true})
	})
	defer timer.Stop()
	var switches, wakes, missing uint64
	topology, final := false, false
	for {
		var n [4]byte
		if _, e = io.ReadFull(conn, n[:]); e != nil {
			return e
		}
		size := binary.BigEndian.Uint32(n[:])
		if size == 0 || size > 65536 {
			return errors.New("bad protocol size")
		}
		payload := make([]byte, size)
		if _, e = io.ReadFull(conn, payload); e != nil {
			return e
		}
		for _, secret := range [][]byte{[]byte("SECRET_WAKER"), []byte("SECRET_SLEEPER")} {
			if bytes.Contains(payload, secret) {
				return errors.New("command canary leaked on sanitized socket")
			}
		}
		var reply struct {
			Ready    bool                         `json:"ready"`
			Error    string                       `json:"error"`
			Event    *nativeperf.SanitizedEvent   `json:"event"`
			Proof    *nativeperf.AcquisitionProof `json:"proof"`
			Complete bool                         `json:"complete"`
		}
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if e = decoder.Decode(&reply); e != nil {
			return e
		}
		if reply.Error != "" {
			return fmt.Errorf("explicit scheduler denial/failure: %s (no scheduler qualification)", reply.Error)
		}
		if reply.Proof != nil {
			if reply.Proof.Final {
				final = true
			} else {
				topology = true
			}
		}
		if reply.Complete {
			if !topology || !final || switches == 0 || wakes == 0 {
				return errors.New("missing actual switch/wake/final drain evidence")
			}
			break
		}
		if reply.Event == nil {
			continue
		}
		ev := reply.Event
		if e = ev.Validate(); e != nil {
			return e
		}
		check := func(k *nativeperf.TaskKey) error {
			if k != nil && (k.TGID != uint32(child.Process.Pid) || k.TID == uint32(foreign)) {
				return errors.New("foreign identity exported")
			}
			return nil
		}
		if ev.Switch != nil {
			switches++
			if e = check(ev.Switch.Previous); e != nil {
				return e
			}
			if e = check(ev.Switch.Next); e != nil {
				return e
			}
			if ev.Switch.MissingCallchain != "" {
				missing++
			}
		}
		if ev.Wakeup != nil {
			wakes++
			if e = check(&ev.Wakeup.Target); e != nil {
				return e
			}
		}
	}
	fmt.Printf("real scheduler switches=%d wakeups=%d missing_switch_callchain=%d topology=%t stopped_fully_drained=%t foreign_identity_excluded=true sanitized_socket_canaries_absent=true\n", switches, wakes, missing, topology, final)
	return nil
}

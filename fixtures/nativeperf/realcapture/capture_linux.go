//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package realcapture

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// BuildWorkload compiles the controlled workload source (fixtures/nativeperf/cpu/loop.c) into dir with the flags its target identity needs
// (no PIE, symbols, frame pointers, a GNU build ID) and returns the executable's path.
func BuildWorkload(ctx context.Context, source, dir string) (string, error) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		return "", cannot("no C compiler (cc) to build the workload")
	}
	out := filepath.Join(dir, "native-loop")
	if b, err := exec.CommandContext(ctx, cc, "-O2", "-g", "-fno-pie", "-no-pie", "-fno-omit-frame-pointer", "-pthread", "-Wl,--build-id", "-o", out, source).CombinedOutput(); err != nil {
		return "", fmt.Errorf("compile %s: %w: %s", source, err, b)
	}
	return out, nil
}

func monoNow() (model.MonoNano, error) {
	var ts syscall.Timespec
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 1, uintptr(unsafe.Pointer(&ts)), 0)
	if errno != 0 || ts.Sec < 0 || ts.Nsec < 0 {
		return 0, errors.New("monotonic clock unavailable")
	}
	return model.MonoNano(uint64(ts.Sec)*1000000000 + uint64(ts.Nsec)), nil
}

func frameRead(c *net.UnixConn, v any) error {
	var length [4]byte
	if _, e := io.ReadFull(c, length[:]); e != nil {
		return e
	}
	n := binary.BigEndian.Uint32(length[:])
	if n == 0 || n > 64<<10 {
		return errors.New("invalid helper frame")
	}
	payload := make([]byte, n)
	if _, e := io.ReadFull(c, payload); e != nil {
		return e
	}
	return json.Unmarshal(payload, v)
}

func frameWrite(c *net.UnixConn, v any) error {
	payload, e := json.Marshal(v)
	if e != nil {
		return e
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	if _, e = c.Write(length[:]); e != nil {
		return e
	}
	_, e = c.Write(payload)
	return e
}

// targetOf is the workload as one authorized target: its resolved task identity, its cgroup and the GNU build ID of its executable, plus the
// address range of its `hot` symbol.
func targetOf(child *os.Process, workload, hot string) (nativeperf.Target, uint64, uint64, error) {
	target, e := nativeperf.ResolveLocalTarget(child.Pid)
	if e != nil {
		return target, 0, 0, cannot("the workload's identity cannot be resolved: %v", e)
	}
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", child.Pid))
	if e != nil {
		return target, 0, 0, e
	}
	group := ""
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "0::/") {
			group = strings.TrimPrefix(line, "0::")
			break
		}
	}
	if group == "" {
		return target, 0, 0, cannot("cgroup v2 identity unavailable")
	}
	id, e := nativeperf.ResolveCgroupID(child.Pid)
	if e != nil {
		return target, 0, 0, cannot("cgroup %q not visible: %v", group, e)
	}
	target.CgroupID = model.Uint64(id)
	executable, e := elf.Open(workload)
	if e != nil {
		return target, 0, 0, e
	}
	defer executable.Close()
	note := executable.Section(".note.gnu.build-id")
	if note == nil {
		return target, 0, 0, errors.New("the workload needs a GNU build ID (link with -Wl,--build-id)")
	}
	notes, e := note.Data()
	if e != nil || len(notes) < 16 {
		return target, 0, 0, errors.New("invalid build ID note")
	}
	nameSize := binary.LittleEndian.Uint32(notes)
	descSize := binary.LittleEndian.Uint32(notes[4:])
	start := 12 + (nameSize+3)&^3
	if descSize == 0 || uint64(start)+uint64(descSize) > uint64(len(notes)) {
		return target, 0, 0, errors.New("invalid build ID note bounds")
	}
	target.AllowedBuildIDs = []string{hex.EncodeToString(notes[start : start+descSize])}
	var hotStart, hotEnd uint64
	symbols, e := executable.Symbols()
	if e != nil {
		return target, 0, 0, e
	}
	for _, symbol := range symbols {
		// The compiler may clone the function (burn.isra.0, burn.constprop.0): the clone is the same code.
		if symbol.Name == hot || strings.HasPrefix(symbol.Name, hot+".") {
			hotStart, hotEnd = symbol.Value, symbol.Value+symbol.Size
		}
	}
	if executable.Type != elf.ET_EXEC || hotStart == 0 || hotEnd <= hotStart {
		return target, 0, 0, errors.New("compile the workload with -fno-pie -no-pie and symbols")
	}
	return target, hotStart, hotEnd, nil
}

// Capture runs the workload, captures its CPU samples through the in-process native helper and returns the sanitized events with the
// probe's capabilities. It returns *CannotCapture when the host cannot take the capture and a plain error when the capture itself failed.
func Capture(ctx context.Context, req Request) (Result, error) {
	var res Result
	if req.Workload == "" || req.Seconds < 1 || req.Seconds > 60 {
		return res, errors.New("a workload and 1..60 seconds are required")
	}
	child := exec.Command(req.Workload)
	stdout, e := child.StdoutPipe()
	if e != nil {
		return res, e
	}
	if e = child.Start(); e != nil {
		return res, e
	}
	defer func() { child.Process.Signal(syscall.SIGTERM); child.Wait() }()
	if ready, e := bufio.NewReader(stdout).ReadString('\n'); e != nil || ready != "ready\n" {
		return res, errors.New("the workload did not become ready")
	}
	hot := req.HotSymbol
	if hot == "" {
		hot = "soundpost_hot_loop"
	}
	target, hotStart, hotEnd, e := targetOf(child.Process, req.Workload, hot)
	if e != nil {
		return res, e
	}
	probeTarget := target
	probeTarget.CgroupID = 0
	caps, probeErr := nativeperf.Probe(ctx, []nativeperf.Target{probeTarget})
	if caps.CPU != nativeperf.Supported {
		return res, cannot("cpu=%s reasons=%v permissions=%+v probe error=%v", caps.CPU, caps.Reasons, caps.Permissions, probeErr)
	}
	if req.Scheduler && caps.OffCPU != nativeperf.Supported {
		return res, cannot("scheduler capture: off_cpu=%s runqueue_split=%s reasons=%v permissions=%+v probe error=%v", caps.OffCPU, caps.RunqueueSplit, caps.Reasons, caps.Permissions, probeErr)
	}
	res.Capabilities = caps

	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return res, e
	}
	cfg := nativeperf.DefaultConfig(1)
	mode := nativeperf.ModeCPU
	if req.Scheduler {
		mode = nativeperf.ModeCPUOffCPU
	}
	targets := []nativeperf.Target{target}
	signed, e := nativeperf.SignStart(nativeperf.StartAuthorization{Installation: "public-real-capture-fixture", UID: uint32(os.Getuid()), Revision: 1, Expires: time.Now().Add(2 * time.Minute).Unix(), Targets: targets, Config: cfg, Mode: mode}, private)
	if e != nil {
		return res, e
	}
	dir, e := os.MkdirTemp("", "soundpost-realcapture-")
	if e != nil {
		return res, e
	}
	defer os.RemoveAll(dir)
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "acquire.sock"), Net: "unix"})
	if e != nil {
		return res, e
	}
	if e = os.Chmod(listener.Addr().String(), 0600); e != nil {
		listener.Close()
		return res, e
	}
	helperCtx, stop := context.WithCancel(ctx)
	active := make(chan *nativeperf.ProfileSource, 1)
	helper := nativeperf.Helper{Policy: nativeperf.OperatorPolicy{Installation: "public-real-capture-fixture", UID: uint32(os.Getuid()), Revision: 1, PublicKey: public, Allowlist: targets}, Budget: nativeperf.NewResourceBudget(), Acquire: func(ctx context.Context, a nativeperf.AuthorizedTargets, c nativeperf.Config, r *nativeperf.Reservation) (nativeperf.EventSource, error) {
		p := nativeperf.DefaultSymbolPolicy(uint64(c.PolicyRevision))
		p.AllowMappedELF = true
		s, e := nativeperf.NewProfileAcquisition(ctx, a, c, r, p)
		if e != nil {
			return nil, e
		}
		active <- s
		return s, nil
	}}
	helperDone := make(chan struct{})
	go func() { helper.Serve(helperCtx, listener); close(helperDone) }()
	defer func() { stop(); listener.Close(); <-helperDone }()
	conn, e := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if e != nil {
		return res, e
	}
	defer conn.Close()

	if res.FirstMono, e = monoNow(); e != nil {
		return res, e
	}
	if e = frameWrite(conn, nativeperf.CaptureRequest{Authorization: signed, Targets: targets, Config: cfg, Mode: mode}); e != nil {
		return res, e
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var ready struct {
		Ready bool   `json:"ready"`
		Error string `json:"error"`
	}
	if e = frameRead(conn, &ready); e != nil || !ready.Ready || ready.Error != "" {
		return res, fmt.Errorf("the helper refused the capture: %q (%v)", ready.Error, e)
	}
	var source *nativeperf.ProfileSource
	select {
	case source = <-active:
	case <-ctx.Done():
		return res, errors.New("the profile acquisition never started")
	}
	if req.Scheduler {
		if e = readScheduler(conn, cfg, source, req.Seconds, &res); e != nil {
			return res, e
		}
	} else {
		conn.SetReadDeadline(time.Now().Add(time.Duration(req.Seconds) * time.Second))
		for len(res.Events) < MaxEvents {
			var reply struct {
				Event *nativeperf.SanitizedEvent `json:"event"`
				Error string                     `json:"error"`
			}
			if e = frameRead(conn, &reply); e != nil {
				if n, ok := e.(net.Error); ok && n.Timeout() {
					break
				}
				return res, fmt.Errorf("capture transport: %w", e)
			}
			if reply.Error != "" || reply.Event == nil || reply.Event.Validate() != nil {
				return res, fmt.Errorf("capture refused or invalid event: %q", reply.Error)
			}
			res.Events = append(res.Events, *reply.Event)
		}
		if len(res.Events) == 0 {
			return res, errors.New("no genuine CPU observation arrived")
		}
		res.Mappings = source.FramesMappings()
	}
	threads := map[uint32]bool{}
	for _, ev := range res.Events {
		if ev.CPUEvent != nil {
			res.CPUSamples++
			threads[ev.Task.TID] = true
			res.Period = uint64(ev.CPUEvent.Period)
			if uint64(ev.CPUEvent.IP) >= hotStart && uint64(ev.CPUEvent.IP) < hotEnd {
				res.HotSamples++
			}
		}
		if ev.Loss != nil {
			res.Loss += uint64(ev.Loss.Count)
		}
	}
	res.Threads = len(threads)
	if res.HotSamples == 0 {
		return res, errors.New("no sample landed in the workload's hot loop: the capture is not of the target")
	}
	return res, nil
}

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
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const privatePathCanary = "SOUNDPOST_PRIVATE_HOME_PATH_CANARY"

type setup struct {
	reader *nativeperf.MappingReader
	table  nativeperf.MappingTable
}
type guardedSource struct {
	nativeperf.EventSource
	reader *nativeperf.MappingReader
}

func (s *guardedSource) Next(ctx context.Context) (nativeperf.SanitizedEvent, error) {
	if e := s.reader.Guard(); e != nil {
		return nativeperf.SanitizedEvent{}, e
	}
	event, e := s.EventSource.Next(ctx)
	if e != nil {
		if errors.Is(e, nativeperf.ErrTargetIdentity) || errors.Is(e, nativeperf.ErrThreadCoverageChanged) {
			_ = s.reader.Invalidate(2)
		}
		return nativeperf.SanitizedEvent{}, e
	}
	if e = s.reader.Guard(); e != nil {
		return nativeperf.SanitizedEvent{}, e
	}
	return event, nil
}
func (s *guardedSource) Close() error { e := s.EventSource.Close(); s.reader.Close(); return e }
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	scenarios := flag.String("scenario", "exit,exec,pid-reuse,namespaces,no-frame-pointers", "comma-separated real scenarios; extra, never in the default list (root, cc and namespace creation needed; a host without them fails): ns-nested-target, ns-nested-helper, ns-transitions, ns-layers, ns-container (all of them)")
	workload := flag.String("workload", "fixtures/nativeperf/identity/reuse", "frame-pointer controlled ELF")
	execWorkload := flag.String("exec-workload", "fixtures/nativeperf/identity/exec", "same-file exec controlled ELF")
	noFP := flag.String("no-fp-workload", "fixtures/nativeperf/identity/reuse-no-fp", "frame-pointer-disabled controlled ELF")
	attempts := flag.Int("reuse-attempts", 4096, "maximum real PID allocation attempts; no pid_max/ns_last_pid writes unless -steer-ns-last-pid")
	steer := flag.Bool("steer-ns-last-pid", false, "pid-reuse only: inside a DISPOSABLE PID namespace (unshare --pid --fork --mount-proc, as root) write the previous child's PID minus one to /proc/sys/kernel/ns_last_pid before each start, so the kernel really hands the same number to a new process; refused in the initial PID namespace")
	attachExe := flag.String("attach-exe", "", "ns-attach only: the exact executable path (as /proc/<pid>/exe shows it) of an already running target in this PID namespace's /proc")
	flag.Parse()
	if *attempts < 2 || *attempts > 16384 {
		return errors.New("invalid_reuse_attempt_budget")
	}
	for _, scenario := range strings.Split(*scenarios, ",") {
		var e error
		switch scenario {
		case "exit", "namespaces":
			e = capture(*workload, scenario, false)
		case "exec":
			e = capture(*execWorkload, scenario, false)
		case "no-frame-pointers":
			e = capture(*noFP, scenario, true)
		case "pid-reuse":
			e = realPIDReuse(*workload, *attempts, *steer)
		case "ns-attach":
			e = nsAttach(*attachExe)
		case "ns-nested-target", "ns-nested-helper", "ns-transitions", "ns-layers", "ns-container":
			e = nsScenario(scenario)
		default:
			return errors.New("unknown_identity_scenario")
		}
		if e != nil {
			return fmt.Errorf("%s: %w", scenario, e)
		}
	}
	return nil
}
func copyWorkload(input string) (string, func(), error) {
	directory, e := os.MkdirTemp("", privatePathCanary+"-")
	if e != nil {
		return "", nil, errors.New("fixture_directory_unavailable")
	}
	cleanup := func() { os.RemoveAll(directory) }
	in, e := os.Open(input)
	if e != nil {
		cleanup()
		return "", nil, errors.New("fixture_binary_unavailable")
	}
	defer in.Close()
	output := filepath.Join(directory, "workload")
	out, e := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if e != nil {
		cleanup()
		return "", nil, errors.New("fixture_copy_unavailable")
	}
	n, e := io.Copy(out, io.LimitReader(in, 32<<20+1))
	closeErr := out.Close()
	if e != nil || closeErr != nil || n > 32<<20 {
		cleanup()
		return "", nil, errors.New("fixture_copy_budget")
	}
	return output, cleanup, nil
}
func targetFor(pid int, workload string) (nativeperf.Target, error) {
	target, e := nativeperf.ResolveLocalTarget(pid)
	if e != nil {
		return target, errors.New("target_identity_unavailable")
	}
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if e != nil || len(b) > 65536 {
		return target, errors.New("cgroup_unavailable")
	}
	group := ""
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "0::/") {
			group = strings.TrimPrefix(line, "0::")
			break
		}
	}
	if group == "" {
		return target, errors.New("cgroup_v2_required")
	}
	for _, part := range strings.Split(group, "/") {
		if part == ".." {
			return target, errors.New("cgroup_namespace_unavailable")
		}
	}
	id, e := nativeperf.ResolveCgroupID(pid)
	if e != nil {
		return target, errors.New("cgroup_identity_unavailable")
	}
	target.CgroupID = model.Uint64(id)
	object, e := elf.Open(workload)
	if e != nil {
		return target, errors.New("fixture_elf_unavailable")
	}
	defer object.Close()
	note := object.Section(".note.gnu.build-id")
	if note == nil || note.Size > 65536 {
		return target, errors.New("fixture_gnu_build_id_required")
	}
	data, e := note.Data()
	if e != nil || len(data) < 16 {
		return target, errors.New("fixture_build_note_invalid")
	}
	names, desc := binary.LittleEndian.Uint32(data), binary.LittleEndian.Uint32(data[4:])
	start := uint64(12) + (uint64(names)+3)&^3
	if names != 4 || desc == 0 || desc > 64 || start+uint64(desc) > uint64(len(data)) || !bytes.Equal(data[12:16], []byte{'G', 'N', 'U', 0}) {
		return target, errors.New("fixture_build_note_invalid")
	}
	target.AllowedBuildIDs = []string{hex.EncodeToString(data[start : start+uint64(desc)])}
	return target, nil
}
func capture(input, scenario string, noFP bool) error {
	workload, cleanup, e := copyWorkload(input)
	if e != nil {
		return e
	}
	defer cleanup()
	child := exec.Command(workload)
	stdout, e := child.StdoutPipe()
	if e != nil {
		return errors.New("fixture_pipe_unavailable")
	}
	stdin, e := child.StdinPipe()
	if e != nil {
		return errors.New("fixture_pipe_unavailable")
	}
	if e = child.Start(); e != nil {
		return errors.New("fixture_start_failed")
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	lines := bufio.NewReader(stdout)
	if line, e := lines.ReadString('\n'); e != nil || line != "ready\n" {
		return errors.New("fixture_not_ready")
	}
	target, e := targetFor(child.Process.Pid, workload)
	if e != nil {
		return e
	}
	checked, e := nativeperf.ResolveTask(child.Process.Pid, nativeperf.NamespaceID(target.PIDNamespace))
	if e != nil || checked.ProcessStart != target.ProcessStart {
		return errors.New("checked_task_mismatch")
	}
	if scenario == "namespaces" {
		own, e := nativeperf.ResolveLocalTarget(os.Getpid())
		if e != nil || own.PIDNamespace != target.PIDNamespace {
			return errors.New("already_authorized_local_namespace_required")
		}
		if _, e = nativeperf.ResolveTask(child.Process.Pid, nativeperf.NamespaceID(target.PIDNamespace+1)); e == nil {
			return errors.New("foreign_namespace_accepted")
		}
	}
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return errors.New("fixture_key_unavailable")
	}
	cfg := nativeperf.DefaultConfig(1)
	targets := []nativeperf.Target{target}
	grant, e := nativeperf.SignStart(nativeperf.StartAuthorization{Installation: "public-identity-fixture", UID: uint32(os.Getuid()), Revision: 1, Expires: time.Now().Add(time.Minute).Unix(), Targets: targets, Config: cfg, Mode: nativeperf.ModeCPU}, private)
	if e != nil {
		return e
	}
	directory, e := os.MkdirTemp("", "soundpost-identity-socket-")
	if e != nil {
		return errors.New("fixture_socket_directory_unavailable")
	}
	defer os.RemoveAll(directory)
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(directory, "acquire.sock"), Net: "unix"})
	if e != nil {
		return errors.New("fixture_listener_unavailable")
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	state := make(chan setup, 1)
	helper := nativeperf.Helper{Policy: nativeperf.OperatorPolicy{Installation: "public-identity-fixture", UID: uint32(os.Getuid()), Revision: 1, PublicKey: public, Allowlist: targets}, Budget: nativeperf.NewResourceBudget(), Acquire: func(ctx context.Context, a nativeperf.AuthorizedTargets, c nativeperf.Config, r *nativeperf.Reservation) (nativeperf.EventSource, error) {
		policy := nativeperf.DefaultSymbolPolicy(uint64(c.PolicyRevision))
		policy.AllowMappedELF = true
		policy.FramePointersAbsent = noFP
		reader, e := nativeperf.NewMappingReader(a, target, 1, policy)
		if e != nil {
			return nil, e
		}
		table, e := reader.Read(ctx)
		if e != nil {
			reader.Close()
			return nil, e
		}
		source, e := nativeperf.NewCPUAcquisition(ctx, a, c, r)
		if e != nil {
			reader.Close()
			return nil, e
		}
		state <- setup{reader, table}
		return &guardedSource{source, reader}, nil
	}}
	go helper.Serve(ctx, listener)
	conn, e := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if e != nil {
		return errors.New("fixture_connect_failed")
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	request, e := json.Marshal(nativeperf.CaptureRequest{Authorization: grant, Targets: targets, Config: cfg, Mode: nativeperf.ModeCPU})
	if e != nil {
		return e
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(request)))
	if _, e = conn.Write(length[:]); e != nil {
		return errors.New("fixture_request_failed")
	}
	if _, e = conn.Write(request); e != nil {
		return errors.New("fixture_request_failed")
	}
	var active setup
	ready := false
	samples := 0
	relative := 0
	transition := false
	var final nativeperf.CPUObservation
	for {
		if _, e = io.ReadFull(conn, length[:]); e != nil {
			return errors.New("real_capture_incomplete")
		}
		size := binary.BigEndian.Uint32(length[:])
		if size == 0 || size > 64<<10 {
			return errors.New("invalid_helper_frame")
		}
		payload := make([]byte, size)
		if _, e = io.ReadFull(conn, payload); e != nil {
			return errors.New("real_capture_incomplete")
		}
		if bytes.Contains(payload, []byte(privatePathCanary)) {
			return errors.New("private_path_leaked_to_acquisition_socket")
		}
		var reply struct {
			Ready bool
			Error string
			Event *nativeperf.SanitizedEvent
		}
		if json.Unmarshal(payload, &reply) != nil {
			return errors.New("invalid_helper_reply")
		}
		if reply.Error != "" {
			if ready && transition && (reply.Error == "generation_changed" || reply.Error == "thread_coverage_changed") {
				if active.reader.Guard() == nil {
					return errors.New("old_identity_guard_still_live")
				}
				delayed, e := nativeperf.ResolveFrames(ctx, []nativeperf.AddressFrame{{Task: nativeperf.TaskKey{BootID: active.table.Process().BootID, PIDNamespace: target.PIDNamespace, TGID: target.TGID, TID: target.TGID, ProcessStart: target.ProcessStart, Generation: 2}, IP: 1}}, active.table, nil)
				if e != nil || len(delayed) != 1 || delayed[0].Reason != nativeperf.FrameGeneration {
					return errors.New("cross_generation_frame_join")
				}
				break
			}
			return fmt.Errorf("real_acquisition_refused_%s", reply.Error)
		}
		if reply.Ready {
			if ready {
				return errors.New("duplicate_ready")
			}
			ready = true
			select {
			case active = <-state:
			case <-ctx.Done():
				return errors.New("mapping_setup_missing")
			}
			continue
		}
		if !ready || reply.Event == nil || reply.Event.Validate() != nil {
			return errors.New("invalid_native_observation")
		}
		if reply.Event.CPUEvent == nil {
			continue
		}
		if transition {
			continue
		} // Queued pre-control samples are not relabeled after transition.
		observation, e := nativeperf.ResolveCPUObservation(ctx, reply.Event.Task, *reply.Event.CPUEvent, active.table, nil)
		if e != nil || observation.Period == 0 || len(observation.Frames) == 0 {
			return errors.New("native_sample_discarded")
		}
		exported, e := json.Marshal(observation)
		if e != nil || bytes.Contains(exported, []byte(privatePathCanary)) || bytes.Contains(exported, []byte(workload)) {
			return errors.New("private_path_exported")
		}
		for _, frame := range observation.Frames {
			if frame.Module != nil {
				relative++
			}
		}
		samples++
		final = observation
		if samples < 5 || relative == 0 {
			continue
		}
		if noFP && observation.Coverage != nativeperf.FrameMissing {
			return errors.New("missing_frame_pointers_hidden")
		}
		switch scenario {
		case "exit":
			transition = true
			if child.Process.Kill() != nil {
				return errors.New("fixture_exit_failed")
			}
		case "exec":
			transition = true
			if _, e = stdin.Write([]byte{'e'}); e != nil {
				return errors.New("fixture_exec_request_failed")
			}
			if line, e := lines.ReadString('\n'); e != nil || line != "ready\n" {
				return errors.New("fixture_exec_failed")
			}
		default:
			goto complete
		}
	}
complete:
	if samples == 0 || relative == 0 {
		return errors.New("no_genuine_approved_samples")
	}
	result := struct {
		Scenario               string                    `json:"scenario"`
		Samples                int                       `json:"genuine_cpu_samples"`
		Modules                []nativeperf.SafeModule   `json:"modules"`
		Observation            nativeperf.CPUObservation `json:"observation"`
		NamespaceQualification string                    `json:"namespace_qualification,omitempty"`
	}{Scenario: scenario, Samples: samples, Modules: active.table.Modules(), Observation: final}
	if scenario == "namespaces" {
		result.NamespaceQualification = "existing_authorized_local_namespace_only"
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

// initPIDNamespaceInode is PROC_PID_INIT_INO.
const initPIDNamespaceInode = 0xEFFFFFFC

// steerNsLastPID makes the kernel's next PID allocation in this PID namespace start right after pid. It only ever
// runs inside a non-initial PID namespace: the write is local to that namespace and disappears with it.
func steerNsLastPID(pid int) error {
	return os.WriteFile("/proc/sys/kernel/ns_last_pid", []byte(fmt.Sprintf("%d\n", pid-1)), 0)
}

func realPIDReuse(input string, attempts int, steer bool) error {
	if steer {
		info, e := os.Stat("/proc/self/ns/pid")
		if e != nil {
			return errors.New("pid_namespace_unreadable")
		}
		if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Ino == initPIDNamespaceInode {
			return errors.New("ns_last_pid_steering_requires_a_disposable_pid_namespace")
		}
	}
	workload, cleanup, e := copyWorkload(input)
	if e != nil {
		return e
	}
	defer cleanup()
	seen := make(map[int]nativeperf.TaskKey)
	last := 0
	for attempt := range attempts {
		if steer && last > 0 {
			// /proc/<pid>/stat start times have a 10 ms resolution: a steered reuse inside the same tick, of the same
			// executable, would be identical by construction. A real wrap-around never is.
			time.Sleep(25 * time.Millisecond)
			if e := steerNsLastPID(last); e != nil {
				return errors.New("ns_last_pid_write_failed")
			}
		}
		child := exec.Command(workload)
		stdout, e := child.StdoutPipe()
		if e != nil {
			return errors.New("reuse_pipe_failed")
		}
		if child.Start() != nil {
			return errors.New("reuse_start_failed")
		}
		line, e := bufio.NewReader(stdout).ReadString('\n')
		if e != nil || line != "ready\n" {
			child.Process.Kill()
			child.Wait()
			return errors.New("reuse_fixture_not_ready")
		}
		target, e := nativeperf.ResolveLocalTarget(child.Process.Pid)
		if e != nil {
			child.Process.Kill()
			child.Wait()
			return errors.New("reuse_target_unavailable")
		}
		key, e := nativeperf.ResolveTask(child.Process.Pid, nativeperf.NamespaceID(target.PIDNamespace))
		pid := child.Process.Pid
		last = pid
		child.Process.Kill()
		child.Wait()
		if e != nil {
			return errors.New("reuse_checked_identity_unavailable")
		}
		if old, ok := seen[pid]; ok {
			if old == key {
				return errors.New("real_pid_reuse_joined")
			}
			return json.NewEncoder(os.Stdout).Encode(struct {
				Scenario      string `json:"scenario"`
				ObservedReuse bool   `json:"actual_numeric_pid_reuse"`
				Steered       bool   `json:"ns_last_pid_steered"`
				PID           int    `json:"reused_pid"`
				Attempt       int    `json:"attempt"`
				SameProcess   bool   `json:"same_process_start"`
				SameGen       bool   `json:"same_generation"`
			}{"pid-reuse", true, steer, pid, attempt + 1, old.ProcessStart == key.ProcessStart, old.Generation == key.Generation})
		}
		seen[pid] = key
	}
	// An allocation loop is not proof of actual PID reuse. Without -steer-ns-last-pid nothing is written to pid_max or
	// ns_last_pid; with it the write is confined to a disposable PID namespace the caller created.
	return errors.New("actual_numeric_pid_reuse_not_observed_within_budget")
}

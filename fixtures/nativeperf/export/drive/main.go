//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0

// Command drive is the operator side of the native export fixture. The export
// fixture (../main.go) needs a dedicated, stopped backend, a running authorized
// target and a private 0600 config naming both; drive builds them on a throwaway
// directory and runs the fixture against them:
//
//	cc -O2 -g -pthread -fno-omit-frame-pointer -fno-optimize-sibling-calls -Wl,--build-id \
//	   -o /tmp/cpu_wait fixtures/nativeperf/export/workloads/cpu_wait.c
//	go build -o /tmp/export ./fixtures/nativeperf/export
//	sudo go run ./fixtures/nativeperf/export/drive --workload /tmp/cpu_wait --export /tmp/export -- \
//	    --scheduler --verify-scope-denial --verify-revocation --require-http-profile-read \
//	    --verify-historical-policy-delete --probe-receipts-http
//
// It starts the workload, provisions a real node (organization, project, source,
// a profiles.read reader, a foreign reader, an owner) with the product's own admin
// commands, closes it, writes the config and execs the fixture, whose exit code
// it returns. No credential is printed.
package main

import (
	"bufio"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/privacy/privnode"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

type config struct {
	BackendDir         string            `json:"backend_dir"`
	SourceCredential   string            `json:"source_credential"`
	ReaderToken        string            `json:"reader_token"`
	ForeignReaderToken string            `json:"foreign_reader_token"`
	AdminToken         string            `json:"admin_token"`
	Org                model.ID          `json:"org_id"`
	Project            model.ID          `json:"project_id"`
	ForeignOrg         model.ID          `json:"foreign_org_id"`
	ForeignProject     model.ID          `json:"foreign_project_id"`
	Source             model.ID          `json:"source_id"`
	Producer           model.ID          `json:"producer_id"`
	Resource           model.Resource    `json:"resource"`
	Revision           model.Revision    `json:"policy_revision"`
	Target             nativeperf.Target `json:"target"`
}

func main() {
	code, e := run()
	if e != nil {
		fmt.Fprintln(os.Stderr, "drive:", e)
	}
	os.Exit(code)
}

func run() (int, error) {
	workload := flag.String("workload", "", "compiled workloads/cpu_wait")
	exportBin := flag.String("export", "", "compiled fixtures/nativeperf/export")
	work := flag.String("work", "", "work directory (default: a new temporary directory, removed afterwards)")
	flag.Parse()
	if *workload == "" || *exportBin == "" {
		return 2, errors.New("--workload and --export are required; flags after -- go to the export fixture")
	}
	dir := *work
	if dir == "" {
		d, e := os.MkdirTemp("", "soundpost-native-export-drive-")
		if e != nil {
			return 1, e
		}
		defer os.RemoveAll(d)
		dir = d
	}
	cmd := exec.Command(*workload)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		return 1, e
	}
	if e = cmd.Start(); e != nil {
		return 1, errors.New("workload did not start")
	}
	defer func() {
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
	}()
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- strings.TrimSpace(line)
	}()
	select {
	case line := <-ready:
		if line != "ready" {
			return 1, errors.New("workload did not report ready")
		}
	case <-time.After(15 * time.Second):
		return 1, errors.New("workload readiness timeout")
	}
	target, e := resolveTarget(cmd.Process.Pid, *workload)
	if e != nil {
		return 1, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cfg, e := provision(ctx, filepath.Join(dir, "backend"), target)
	if e != nil {
		return 1, e
	}
	raw, e := json.Marshal(cfg)
	if e != nil {
		return 1, e
	}
	path := filepath.Join(dir, "export-config.json")
	if e = os.WriteFile(path, raw, 0o600); e != nil {
		return 1, e
	}
	args := append([]string{"--target-pid", fmt.Sprint(cmd.Process.Pid)}, flag.Args()...)
	child := exec.Command(*exportBin, args...)
	child.Env = append(os.Environ(), "SOUNDPOST_NATIVE_EXPORT_CONFIG="+path)
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if e = child.Run(); e != nil {
		var exit *exec.ExitError
		if errors.As(e, &exit) {
			return exit.ExitCode(), nil
		}
		return 1, e
	}
	return 0, nil
}

func resolveTarget(pid int, exe string) (nativeperf.Target, error) {
	target, e := nativeperf.ResolveLocalTarget(pid)
	if e != nil {
		return target, e
	}
	id, e := nativeperf.ResolveCgroupID(pid)
	if e != nil {
		return target, errors.New("cgroup identity not visible")
	}
	target.CgroupID = model.Uint64(id)
	f, e := elf.Open(exe)
	if e != nil {
		return target, e
	}
	defer f.Close()
	note := f.Section(".note.gnu.build-id")
	if note == nil {
		return target, errors.New("GNU build ID required")
	}
	notes, e := note.Data()
	if e != nil || len(notes) < 16 {
		return target, errors.New("invalid build ID note")
	}
	nameSize, descSize := binary.LittleEndian.Uint32(notes), binary.LittleEndian.Uint32(notes[4:])
	start := 12 + (nameSize+3)&^3
	if descSize == 0 || uint64(start)+uint64(descSize) > uint64(len(notes)) {
		return target, errors.New("invalid build ID note bounds")
	}
	target.AllowedBuildIDs = []string{hex.EncodeToString(notes[start : start+descSize])}
	return target, nil
}

// provision builds the real node the fixture opens: the same identities the
// privacy verifier's node has, plus the reader/foreign-reader/owner tokens.
func provision(ctx context.Context, backend string, target nativeperf.Target) (config, error) {
	n, e := privnode.Start(ctx, backend)
	if e != nil {
		return config{}, e
	}
	defer n.Close()
	reader, e := n.IssueReaderToken(ctx)
	if e != nil {
		return config{}, errors.New("reader token refused")
	}
	foreign, foreignOrg, foreignProject, e := n.ForeignReaderToken(ctx)
	if e != nil {
		return config{}, e
	}
	return config{BackendDir: backend, SourceCredential: n.SourceKey, ReaderToken: reader.Token, ForeignReaderToken: foreign, AdminToken: n.OwnerToken, Org: n.Org, Project: n.Project, ForeignOrg: foreignOrg, ForeignProject: foreignProject, Source: n.Source, Producer: n.Producer, Resource: n.Resource, Revision: 1, Target: target}, nil
}

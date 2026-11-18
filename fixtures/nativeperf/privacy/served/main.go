//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0

// Command served runs the 04.08 privacy verifier against a REAL served node: the
// `soundpost serve` binary in its own process, over verified TLS (a private CA),
// instead of the verifier's in-process node. Plan 04.08's smoke names this node
// through --endpoint-env SOUNDPOST_FIXTURE_API.
//
//	go build -o /tmp/soundpost ./cmd/soundpost
//	go build -o /tmp/verify ./fixtures/nativeperf/privacy/verify
//	cc -O2 -pthread -fno-omit-frame-pointer -g -o /tmp/canary fixtures/nativeperf/privacy/canary.c
//	sudo go run ./fixtures/nativeperf/privacy/served --soundpost /tmp/soundpost --verify /tmp/verify \
//	    --workload /tmp/canary --policy fixtures/nativeperf/privacy/policy.json -- --audit-syscalls --inject-peer-death
//
// It provisions the node's identities with the product's own admin commands on a
// throwaway data directory (through the same in-process composition the verifier's
// own node uses), copies that directory while nothing runs (the verifier needs a
// source grant, which only exists inside an auth service, and opens the copy for
// that and nothing else), starts the real server on the original through the SDK
// estate's launcher, writes the verifier's private node description and runs the
// verifier with SOUNDPOST_FIXTURE_API/SOUNDPOST_FIXTURE_NODE set. The verifier's
// exit code is this command's. No credential is printed.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/privacy/privnode"
	"github.com/arynyklas/soundpost/fixtures/sdk/estate"
)

func main() {
	code, e := run()
	if e != nil {
		fmt.Fprintln(os.Stderr, "served:", e)
	}
	os.Exit(code)
}

func run() (int, error) {
	binary := flag.String("soundpost", "", "linux soundpost binary (go build ./cmd/soundpost)")
	verify := flag.String("verify", "", "compiled fixtures/nativeperf/privacy/verify")
	workload := flag.String("workload", "", "compiled fixtures/nativeperf/privacy/canary")
	policy := flag.String("policy", "fixtures/nativeperf/privacy/policy.json", "privacy policy file")
	work := flag.String("work", "", "work directory (default: a new temporary directory, removed afterwards)")
	flag.Parse()
	if *binary == "" || *verify == "" || *workload == "" {
		return 2, errors.New("--soundpost, --verify and --workload are required; flags after -- go to the verifier")
	}
	dir := *work
	if dir == "" {
		d, e := os.MkdirTemp("", "soundpost-privacy-served-")
		if e != nil {
			return 1, e
		}
		defer os.RemoveAll(d)
		dir = d
	}
	data, grant := filepath.Join(dir, "data"), filepath.Join(dir, "grant")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	n, e := privnode.Start(ctx, data)
	if e != nil {
		return 1, e
	}
	reader, e := n.IssueReaderToken(ctx)
	if e != nil {
		n.Close()
		return 1, errors.New("reader token refused")
	}
	description := map[string]any{
		"source_credential": n.SourceKey, "reader_token": reader.Token,
		"org_id": n.Org, "project_id": n.Project, "source_id": n.Source, "producer_id": n.Producer,
		"resource": n.Resource, "policy_revision": n.PolicyRevision, "data_dir": data, "grant_dir": grant,
	}
	n.Close()
	if out, e := exec.Command("cp", "-a", data, grant).CombinedOutput(); e != nil {
		return 1, fmt.Errorf("grant copy: %v: %s", e, estate.Tail(string(out)))
	}
	est := estate.New(estate.Options{Binary: *binary, Work: dir, Name: "privacy-served"})
	est.DataDir = data
	est.Start()
	description["ca_file"] = est.CA
	raw, e := json.Marshal(description)
	if e != nil {
		return 1, e
	}
	path := filepath.Join(dir, "node.json")
	if e = os.WriteFile(path, raw, 0o600); e != nil {
		return 1, e
	}
	version, _ := estate.RunOut(*binary, "version")
	fmt.Fprintf(os.Stderr, "served: real soundpost serve on %s (%s)\n", est.Addr, version)
	args := append([]string{"--workload", *workload, "--policy", *policy}, flag.Args()...)
	child := exec.Command(*verify, args...)
	child.Env = append(os.Environ(), "SOUNDPOST_FIXTURE_API=https://"+est.Addr, "SOUNDPOST_FIXTURE_NODE="+path)
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	code := 0
	if e = child.Run(); e != nil {
		var exit *exec.ExitError
		if !errors.As(e, &exit) {
			est.Close()
			return 1, e
		}
		code = exit.ExitCode()
	}
	est.Close()
	return code, nil
}

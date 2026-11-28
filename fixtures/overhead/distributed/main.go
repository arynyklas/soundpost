// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Command distributed is the load harness of design section 13's distributed row (07.06 criterion 11): three REAL `soundpost serve
// --mode=distributed` voters on three hosts (each in the D90 cgroup v2 scope of 8 CPUs / 16 GiB, mutual TLS between them), the same
// estate as the single-host row (10 organizations, 100 projects, 100,000 active metric series), 5,000 mixed records/s open loop for
// one hour from several generator hosts, the node that leads most Raft groups killed with SIGKILL in the middle of the hour and
// restarted. Roles:
//
//	prepare    provisions the estate on a throw-away single installation, exports the cluster seed, makes the mutual-TLS PKI and the
//	           per-node files (internal/config renders them) and writes the plan the other roles read
//	node       runs on each voter host: starts the product in its scope, samples it (/proc, cgroup, NIC), answers a control endpoint
//	           (leadership count, kill -9 + restart, bundle)
//	load       one generator shard: drives its share of the projects open loop through all three members with the SDK's own retry of
//	           an identical batch; the shard that carries --kill-at also decides and performs the kill
//	verify     reads back one generator shard's ACK ledger from ONE member (receipts, metrics, logs, spans) and digests what it read
//	summarize  folds the raw series into the result file the qualify runner `overhead_distributed` validates
//
// README.md in this directory states the commands.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: distributed prepare|node|load|verify|summarize [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "prepare":
		runPrepare(os.Args[2:])
	case "node":
		runNode(os.Args[2:])
	case "load":
		runLoad(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
	case "summarize":
		runSummarize(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "distributed: unknown role %q\n", os.Args[1])
		os.Exit(2)
	}
}

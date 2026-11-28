// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Command singlehost is the load harness of design section 13's single-host row (07.06 criterion 11): 10 organizations, 100 projects,
// 100,000 active metric series, 2,000 mixed records/s for one hour against a REAL `soundpost serve` that runs on another host. It has
// four roles:
//
//	server     starts the product pinned to a CPU set, provisions the estate through the product's admin routes, samples the server
//	           process (/proc) and answers a small control endpoint used for the restarts
//	load       drives the estate open loop and records, per request, the latency to the product's durable receipt
//	verify     after a restart, reads back through the product's authenticated routes what the ACKs said was durable
//	summarize  folds the raw series into the result file the qualify runner `overhead_single_host` validates
//
// See README.md in this directory for the exact commands and the stated workload shape.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: singlehost server|load|verify|summarize [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "load":
		runLoad(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
	case "summarize":
		runSummarize(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "singlehost: unknown role %q\n", os.Args[1])
		os.Exit(2)
	}
}

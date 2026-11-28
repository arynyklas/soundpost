// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Command pcut is the load, journal, prober and verifier of the real hypervisor power-cut drill (07.07#7): a three-voter
// cluster on three machines, one of them powered off by the hypervisor under load and started again.
//
//	pcut bootstrap  one-time bootstrap of the single installation the cluster seed is made from; writes the fixture
//	pcut gen        continuous ingest with a durable ACK journal
//	pcut probe      per-second readiness and read probe of every voter, from a host that is not cut
//	pcut verify     after the cut: recovery, read-back of every acknowledged record from every voter, digests, outage availability
//
// See docs/operations/drills.md ("A real hypervisor power cut").
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: pcut bootstrap|gen|probe|verify [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "bootstrap":
		err = runBootstrap(os.Args[2:])
	case "gen":
		err = runGen(os.Args[2:])
	case "probe":
		err = runProbe(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pcut:", err)
		os.Exit(1)
	}
}

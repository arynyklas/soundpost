// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"net"
	"os"
	"testing"
)

// A node whose peer port was taken must say so: the generic classification
// reports every network failure as "transport", which hid this cause behind an
// unexplained startup flake.
func TestChildReportsARefusedPeerPortPrecisely(t *testing.T) {
	holder, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	_, refused := net.Listen("tcp", holder.Addr().String())
	if refused == nil {
		t.Fatal("the same loopback address bound twice")
	}
	if got := clusterChildFailureCode(refused); got != "address_in_use" {
		t.Fatalf("refused peer port classified as %q", got)
	}
	_, missing := os.ReadFile("/nonexistent/soundpost-cluster-config")
	if got, want := clusterChildFailureCode(missing), classifySmokeError(missing); got != want || got != "not_found" {
		t.Fatalf("an unrelated failure changed classification: %q want %q", got, want)
	}
}

// Node ports are chosen together, never repeat, and never alias a relay listener
// (those are held for the whole scenario), and each is free the moment it is
// handed out so the owning process can bind it.
func TestReservedClusterAddressesAreDistinctFreeAndNeverRelayPorts(t *testing.T) {
	relays, err := newClusterRelays(1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer relays.close()
	held := map[string]bool{}
	for _, listener := range relays.listeners {
		held[listener.Addr().String()] = true
	}
	for round := range 200 {
		addresses, err := reserveClusterAddresses(8)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, address := range addresses {
			if seen[address] || held[address] {
				t.Fatalf("round %d: address %s repeated or aliases a relay listener", round, address)
			}
			seen[address] = true
			listener, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatalf("round %d: reserved address %s was not free: %v", round, address, err)
			}
			listener.Close()
		}
	}
}

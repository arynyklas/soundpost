// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smokecluster

import (
	"net"
	"testing"
)

// Node ports are chosen together, never repeat, and never alias a relay listener
// (those are held for the whole scenario), and each is free the moment it is
// handed out so the owning process can bind it.
func TestReservedClusterAddressesAreDistinctFreeAndNeverRelayPorts(t *testing.T) {
	relays, err := NewRelays(1, 2, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer relays.Close()
	held := map[string]bool{}
	for _, address := range relays.Addresses() {
		held[address] = true
	}
	for round := range 200 {
		addresses, err := ReserveAddresses(8)
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

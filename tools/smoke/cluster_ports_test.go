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

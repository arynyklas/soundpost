//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package nativeperf

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// UseResidentSizeReader is the one seam a harness has to keep a race-instrumented process off the 64 MiB admission: the reader it
// installs decides admission (an over-budget size is refused as resource_limit, a reader error too, a small size passes the
// budget and reaches the acquisition), it is asked about the helper's own process once when the exporting peer is that same
// process (one address space is charged once), and nil puts the real /proc reader back.
func TestUseResidentSizeReaderDecidesAdmission(t *testing.T) {
	fx := startTargetFixture(t, "/usr/bin/sleep")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	uid := uint32(os.Getuid())
	cfg := DefaultConfig(1)
	grant, e := SignStart(StartAuthorization{Installation: "fixture", UID: uid, Revision: 1, Expires: time.Now().Add(time.Minute).Unix(), Targets: []Target{fx.target}, Config: cfg, Mode: ModeCPU}, priv)
	if e != nil {
		t.Fatal(e)
	}
	request := CaptureRequest{Authorization: grant, Targets: []Target{fx.target}, Config: cfg, Mode: ModeCPU}
	helper := &Helper{Policy: OperatorPolicy{Installation: "fixture", PublicKey: pub, UID: uid, Revision: 1, Allowlist: []Target{fx.target}}, Budget: NewResourceBudget()}
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	var asked []int
	reading := func(size uint64, err error) func(int) (uint64, error) {
		return func(pid int) (uint64, error) {
			mu.Lock()
			asked = append(asked, pid)
			mu.Unlock()
			return size, err
		}
	}
	// the first connection of each row is answered before the helper is told about the next reader: Serve handles one at a time
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { defer close(served); helper.Serve(ctx, listener) }()
	defer func() { cancel(); <-served }()
	reply := func() string {
		c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		if e = writeMessage(c, request); e != nil {
			t.Fatal(e)
		}
		var r helperReply
		if e = readMessage(c, &r); e != nil {
			t.Fatal(e)
		}
		return r.Error
	}
	cases := []struct {
		name   string
		reader func(int) (uint64, error)
		want   string
	}{
		{"size above the budget", reading(MaxMemoryBytes, nil), "resource_limit"},
		{"reader error", reading(0, errors.New("no such process")), "resource_limit"},
		{"size inside the budget reaches the (absent) acquisition", reading(8<<20, nil), "event_unavailable"},
	}
	for _, c := range cases {
		// no connection is open between rows, so installing the next reader cannot race the helper's read of it
		helper.UseResidentSizeReader(c.reader)
		mu.Lock()
		asked = nil
		mu.Unlock()
		if got := reply(); got != c.want {
			t.Errorf("%s: reply %q, want %q", c.name, got, c.want)
		}
		mu.Lock()
		if len(asked) != 1 || asked[0] != os.Getpid() {
			t.Errorf("%s: reader asked about %v, want exactly this process once (the peer is the helper's own process)", c.name, asked)
		}
		mu.Unlock()
	}
	// nil restores the real reader: the stand-in is not consulted again
	helper.UseResidentSizeReader(reading(8<<20, nil))
	helper.UseResidentSizeReader(nil)
	mu.Lock()
	asked = nil
	mu.Unlock()
	reply()
	mu.Lock()
	defer mu.Unlock()
	if len(asked) != 0 {
		t.Errorf("the stand-in reader was still asked about %v after UseResidentSizeReader(nil)", asked)
	}
}

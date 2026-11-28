//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type closeCountingSource struct {
	closedItemSource
	closed *atomic.Int32
}

func (s closeCountingSource) Close() error { s.closed.Add(1); return nil }

// 04.08-W5 (battery survivor R4): the helper closes the event source when a stream ends, so its rings and
// descriptors are released with the connection and not at process exit.
func TestHelperClosesTheSourceWhenTheStreamEnds(t *testing.T) {
	fx := startTargetFixture(t, "/usr/bin/sleep")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	uid := uint32(os.Getuid())
	cfg := DefaultConfig(1)
	grant, e := SignStart(StartAuthorization{Installation: "fixture", UID: uid, Revision: 1, Expires: time.Now().Add(time.Minute).Unix(), Targets: []Target{fx.target}, Config: cfg, Mode: ModeCPU}, priv)
	if e != nil {
		t.Fatal(e)
	}
	request := CaptureRequest{Authorization: grant, Targets: []Target{fx.target}, Config: cfg, Mode: ModeCPU}
	var closed atomic.Int32
	helper := &Helper{
		Policy: OperatorPolicy{Installation: "fixture", PublicKey: pub, UID: uid, Revision: 1, Allowlist: []Target{fx.target}},
		Budget: NewResourceBudget(),
		rss:    func(int) (uint64, error) { return 8 << 20, nil },
		Acquire: func(context.Context, AuthorizedTargets, Config, *Reservation) (EventSource, error) {
			return closeCountingSource{closedItemSource{closedFakeSource{err: ErrSourceComplete}}, &closed}, nil
		},
	}
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { defer close(served); helper.Serve(ctx, listener) }()
	defer func() { cancel(); <-served }()
	c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if e = writeMessage(c, request); e != nil {
		t.Fatal(e)
	}
	var ready, done helperReply
	if e = readMessage(c, &ready); e != nil || !ready.Ready {
		t.Fatalf("ready %+v %v", ready, e)
	}
	if e = readMessage(c, &done); e != nil || !done.Complete {
		t.Fatalf("complete %+v %v", done, e)
	}
	deadline := time.Now().Add(5 * time.Second)
	for closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if closed.Load() != 1 {
		t.Fatalf("source closed %d times after its stream ended, want 1", closed.Load())
	}
}

// 04.08-W5 (battery survivor D4): a zero-length frame is refused as invalid by the size rule itself, not by
// whatever the JSON decoder then says about empty input.
func TestReadMessageRefusesAZeroLengthFrameAsInvalid(t *testing.T) {
	var v helperReply
	if err := readMessage(bytes.NewReader([]byte{0, 0, 0, 0}), &v); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero-length frame: %v, want ErrInvalid", err)
	}
}

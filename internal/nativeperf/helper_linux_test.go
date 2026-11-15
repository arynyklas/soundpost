//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestHelperProtocolRejectsUnknownAndOversize(t *testing.T) {
	for _, payload := range []string{`{"Targets":[],"command":"id"}`, `{} {}`} {
		var b bytes.Buffer
		binary.Write(&b, binary.BigEndian, uint32(len(payload)))
		b.WriteString(payload)
		var r CaptureRequest
		if readMessage(&b, &r) == nil {
			t.Fatal("accepted non-fixed request")
		}
	}
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint32(maxHelperMessage+1))
	var r CaptureRequest
	if readMessage(&b, &r) == nil {
		t.Fatal("accepted oversized request")
	}
}

// One active connection at a time: a second connection that arrives while the first holds the helper is not served (and cannot
// start a second acquisition) until the first ends, then it is served normally.
func TestHelperServesOneConnectionAtATime(t *testing.T) {
	fx := startTargetFixture(t, "/usr/bin/sleep")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	uid := uint32(os.Getuid())
	cfg := DefaultConfig(1)
	grant, e := SignStart(StartAuthorization{Installation: "fixture", UID: uid, Revision: 1, Expires: time.Now().Add(time.Minute).Unix(), Targets: []Target{fx.target}, Config: cfg, Mode: ModeCPU}, priv)
	if e != nil {
		t.Fatal(e)
	}
	request := CaptureRequest{Authorization: grant, Targets: []Target{fx.target}, Config: cfg, Mode: ModeCPU}
	var running, peak, started atomic.Int32
	release := make(chan struct{}, 2)
	entered := make(chan struct{}, 2)
	helper := &Helper{
		Policy: OperatorPolicy{Installation: "fixture", PublicKey: pub, UID: uid, Revision: 1, Allowlist: []Target{fx.target}},
		Budget: NewResourceBudget(),
		Acquire: func(ctx context.Context, _ AuthorizedTargets, _ Config, _ *Reservation) (EventSource, error) {
			started.Add(1)
			now := running.Add(1)
			for {
				p := peak.Load()
				if now <= p || peak.CompareAndSwap(p, now) {
					break
				}
			}
			entered <- struct{}{}
			<-release
			running.Add(-1)
			return nil, ErrAcquisitionPending
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
	dial := func() (*net.UnixConn, chan helperReply) {
		c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if e != nil {
			t.Fatal(e)
		}
		if e = writeMessage(c, request); e != nil {
			t.Fatal(e)
		}
		reply := make(chan helperReply, 1)
		go func() {
			var r helperReply
			readMessage(c, &r)
			reply <- r
		}()
		return c, reply
	}
	first, firstReply := dial()
	defer first.Close()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first connection never reached acquisition")
	}
	second, secondReply := dial()
	defer second.Close()
	select {
	case <-entered:
		t.Fatal("a second acquisition started while the first connection was active")
	case r := <-secondReply:
		t.Fatalf("second connection was answered while the first was active: %+v", r)
	case <-time.After(400 * time.Millisecond):
	}
	if started.Load() != 1 {
		t.Fatalf("acquisitions started while one connection was active: %d", started.Load())
	}
	release <- struct{}{}
	if r := <-firstReply; r.Error != "event_unavailable" {
		t.Fatalf("first connection reply %+v", r)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("second connection was never served after the first ended")
	}
	release <- struct{}{}
	if r := <-secondReply; r.Error != "event_unavailable" {
		t.Fatalf("second connection reply %+v", r)
	}
	if peak.Load() != 1 {
		t.Fatalf("peak concurrent acquisitions %d", peak.Load())
	}
}

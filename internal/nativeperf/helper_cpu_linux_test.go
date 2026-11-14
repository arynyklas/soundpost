//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func cpuSocketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "helper.sock"), Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { listener.Close() })
	client, e := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if e != nil {
		t.Fatal(e)
	}
	server, e := listener.AcceptUnix()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}
func TestCPUHelperDisconnectIsNotSuccessfulEOF(t *testing.T) {
	for _, partial := range []bool{false, true} {
		client, server := cpuSocketPair(t)
		if partial {
			server.Write([]byte{0, 0})
		}
		server.Close()
		source := &socketSource{conn: client}
		_, e := source.Next(context.Background())
		if e == nil || errors.Is(e, io.EOF) || errors.Is(e, io.ErrUnexpectedEOF) {
			t.Fatal("invalid acquisition became successful EOF", e)
		}
	}
}
func TestCPUHelperExplicitUnavailableAndPermission(t *testing.T) {
	for _, tc := range []struct {
		code   string
		status Status
		reason Reason
	}{{"event_unavailable", Unsupported, ReasonEvent}, {"permission_denied", Denied, ReasonPermission}} {
		client, server := cpuSocketPair(t)
		if e := writeMessage(server, helperReply{Error: tc.code}); e != nil {
			t.Fatal(e)
		}
		_, e := (&socketSource{conn: client}).Next(context.Background())
		var capability *CapabilityError
		if !errors.As(e, &capability) || capability.Status != tc.status || capability.Reason != tc.reason {
			t.Fatal("capability reason collapsed", e)
		}
	}
}
func TestCPUHelperStreamsActualRingFailure(t *testing.T) {
	execRecord := make([]byte, 64)
	binary.LittleEndian.PutUint32(execRecord, 3)
	binary.LittleEndian.PutUint16(execRecord[4:], 1<<13)
	binary.LittleEndian.PutUint16(execRecord[6:], 64)
	forkRecord := make([]byte, 56)
	binary.LittleEndian.PutUint32(forkRecord, 7)
	binary.LittleEndian.PutUint16(forkRecord[6:], 56)
	for _, tc := range []struct {
		record []byte
		want   error
	}{{make([]byte, 8), ErrAcquisitionFailed}, {execRecord, ErrTargetIdentity}, {forkRecord, ErrThreadCoverageChanged}, {make([]byte, 129), ErrRingOverwrite}} {
		client, server := cpuSocketPair(t)
		source := &cpuSource{done: make(chan struct{}), lastCheck: time.Now(), rings: []*Ring{testRing(make([]byte, 128), 0, tc.record)}}
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer source.Close()
			streamHelperEvents(context.Background(), server, source)
			server.Close()
		}()
		var ready helperReply
		if e := readMessage(client, &ready); e != nil || !ready.Ready {
			t.Fatal("missing ready", e)
		}
		_, e := (&socketSource{conn: client}).Next(context.Background())
		if !errors.Is(e, tc.want) {
			t.Fatalf("terminal failure lost: got %v want %v", e, tc.want)
		}
		<-done
	}
}
func TestCPUHelperLocalCancelAndCloseRemainDistinct(t *testing.T) {
	client, _ := cpuSocketPair(t)
	source := &socketSource{conn: client}
	source.Close()
	if _, e := source.Next(context.Background()); !errors.Is(e, ErrAcquisitionClosed) {
		t.Fatal(e)
	}
	client, _ = cpuSocketPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	source = newSocketSource(ctx, client)
	cancel()
	if _, e := source.Next(context.Background()); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	source.Close()
}

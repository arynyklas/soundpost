//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

type closedFakeSource struct{ err error }

func (s closedFakeSource) Next(context.Context) (SanitizedEvent, error) {
	return SanitizedEvent{}, s.err
}
func (s closedFakeSource) Close() error { return nil }

// closedItemSource is a proof-carrying source (NextItem), the only kind that can end with ErrSourceComplete.
type closedItemSource struct{ closedFakeSource }

func (s closedItemSource) NextItem(context.Context) (AcquisitionItem, error) {
	return AcquisitionItem{}, s.err
}

// 04.08-W1: every way a helper connection ends is counted under a closed reason; the counters carry no content.
func TestHelperCountsClosedReasons(t *testing.T) {
	fx := startTargetFixture(t, "/usr/bin/sleep")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	uid := uint32(os.Getuid())
	cfg := DefaultConfig(1)
	grant, e := SignStart(StartAuthorization{Installation: "fixture", UID: uid, Revision: 1, Expires: time.Now().Add(time.Minute).Unix(), Targets: []Target{fx.target}, Config: cfg, Mode: ModeCPU}, priv)
	if e != nil {
		t.Fatal(e)
	}
	request := CaptureRequest{Authorization: grant, Targets: []Target{fx.target}, Config: cfg, Mode: ModeCPU}
	var complete atomic.Bool
	helper := &Helper{
		Policy: OperatorPolicy{Installation: "fixture", PublicKey: pub, UID: uid, Revision: 1, Allowlist: []Target{fx.target}},
		Budget: NewResourceBudget(),
		rss:    func(int) (uint64, error) { return 8 << 20, nil },
		Acquire: func(context.Context, AuthorizedTargets, Config, *Reservation) (EventSource, error) {
			if complete.Load() {
				return closedItemSource{closedFakeSource{err: ErrSourceComplete}}, nil
			}
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
	roundTrip := func(send func(*net.UnixConn)) helperReply {
		c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		send(c)
		var r helperReply
		readMessage(c, &r)
		return r
	}
	// A request whose mode differs from the signed grant is refused.
	if r := roundTrip(func(c *net.UnixConn) {
		bad := request
		bad.Mode = ModeCPUOffCPU
		writeMessage(c, bad)
	}); r.Error != "authorization_denied" {
		t.Fatalf("reply %+v", r)
	}
	if r := roundTrip(func(c *net.UnixConn) { writeMessage(c, request) }); r.Error != "event_unavailable" {
		t.Fatalf("reply %+v", r)
	}
	got, names := helper.ClosedReasons()
	want := map[string]uint64{"authorization_denied": 1, "event_unavailable": 1}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(names, []string{"authorization_denied", "event_unavailable"}) {
		t.Fatalf("closed reasons %v %v", got, names)
	}
	// A stream that completes is counted by the helper itself, under its literal closed name.
	complete.Store(true)
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
	for {
		got, _ = helper.ClosedReasons()
		if got["stream_complete"] == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stream completion never counted: %v", got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// 04.08-W1: every way an authenticated stream ends maps to one closed reason.
func TestStreamHelperEventsReturnsClosedReason(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		cancel bool
		item   bool
		want   string
	}{
		"complete":    {err: ErrSourceComplete, item: true, want: "stream_complete"},
		"item error":  {err: ErrRingOverwrite, item: true, want: "loss"},
		"overwrite":   {err: ErrRingOverwrite, want: "loss"},
		"topology":    {err: ErrTopologyChanged, want: "topology_changed"},
		"canceled":    {err: context.Canceled, cancel: true, want: "stream_canceled"},
		"item cancel": {err: context.Canceled, cancel: true, item: true, want: "stream_canceled"},
	} {
		t.Run(name, func(t *testing.T) {
			client, server := cpuSocketPair(t)
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			var source EventSource = closedFakeSource{err: tc.err}
			if tc.item {
				source = closedItemSource{closedFakeSource{err: tc.err}}
			}
			if got := streamHelperEvents(ctx, server, source); got != tc.want {
				t.Fatalf("reason %q, want %q", got, tc.want)
			}
		})
	}
	client, server := cpuSocketPair(t)
	client.Close()
	for range 8 {
		if got := streamHelperEvents(context.Background(), server, closedFakeSource{err: ErrSourceComplete}); got == closedWriteFailed {
			return
		}
	}
	t.Fatal("a closed peer never produced stream_write_failed")
}

//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
)

type socketSource struct {
	conn     *net.UnixConn
	once     sync.Once
	next     sync.Mutex
	stopMu   sync.Mutex
	stop     func() bool
	parent   context.Context
	closed   atomic.Bool
	closeErr error
	terminal error
}

func newSocketSource(ctx context.Context, c *net.UnixConn) *socketSource {
	s := &socketSource{conn: c, parent: ctx}
	s.stopMu.Lock()
	s.stop = context.AfterFunc(ctx, func() { s.Close() })
	s.stopMu.Unlock()
	return s
}
func (s *socketSource) Close() error {
	s.once.Do(func() {
		s.closed.Store(true)
		s.stopMu.Lock()
		if s.stop != nil {
			s.stop()
		}
		s.stopMu.Unlock()
		s.closeErr = s.conn.Close()
	})
	return s.closeErr
}
func (s *socketSource) readFailure(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if s.parent != nil {
		if e := s.parent.Err(); e != nil {
			return e
		}
	}
	if s.closed.Load() {
		return ErrAcquisitionClosed
	}
	return ErrAcquisitionFailed
}
func (s *socketSource) Next(ctx context.Context) (SanitizedEvent, error) {
	s.next.Lock()
	defer s.next.Unlock()
	if e := ctx.Err(); e != nil {
		return SanitizedEvent{}, e
	}
	if s.parent != nil {
		if e := s.parent.Err(); e != nil {
			return SanitizedEvent{}, e
		}
	}
	if s.terminal != nil {
		return SanitizedEvent{}, s.terminal
	}
	if s.closed.Load() {
		return SanitizedEvent{}, ErrAcquisitionClosed
	}
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	var reply helperReply
	if e := readMessage(s.conn, &reply); e != nil {
		failure := s.readFailure(ctx)
		if failure == ErrAcquisitionFailed {
			s.terminal = failure
		}
		s.Close()
		return SanitizedEvent{}, failure
	}
	if reply.Error != "" && reply.Event == nil && !reply.Ready {
		s.terminal = helperCodeError(reply.Error)
		s.Close()
		return SanitizedEvent{}, s.terminal
	}
	if reply.Event == nil || reply.Error != "" || reply.Ready || reply.Event.Validate() != nil {
		s.terminal = ErrAcquisitionFailed
		s.Close()
		return SanitizedEvent{}, s.terminal
	}
	return *reply.Event, nil
}

// OpenAuthorized sends one immutable signed request to the fixed local helper.
func OpenAuthorized(ctx context.Context, r CaptureRequest) (*Session, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	info, e := os.Lstat(HelperSocket)
	if e != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0077 != 0 {
		return nil, ErrAuthorization
	}
	d := net.Dialer{}
	conn, e := d.DialContext(ctx, "unix", HelperSocket)
	if e != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrAcquisitionFailed
	}
	c := conn.(*net.UnixConn)
	peer, e := peerCredential(c)
	if e != nil || peer.UID != uint32(os.Geteuid()) {
		c.Close()
		return nil, ErrAuthorization
	}
	source := newSocketSource(ctx, c)
	if e = writeMessage(c, r); e != nil {
		failure := source.readFailure(ctx)
		source.Close()
		return nil, failure
	}
	var reply helperReply
	if e = readMessage(c, &reply); e != nil {
		failure := source.readFailure(ctx)
		source.Close()
		return nil, failure
	}
	if reply.Error != "" && reply.Event == nil && !reply.Ready {
		source.Close()
		return nil, helperCodeError(reply.Error)
	}
	if !reply.Ready || reply.Error != "" || reply.Event != nil {
		source.Close()
		return nil, ErrAcquisitionFailed
	}
	return &Session{source: source}, nil
}

// C10's fixed call shape loads an operator-issued request from a private local file.
// Ingest credentials are neither read nor accepted by this protocol.
func openLocalSession(ctx context.Context, targets []Target, cfg Config) (*Session, error) {
	fd, e := syscall.Open("/run/soundpost-perf/start.json", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, ErrAuthorization
	}
	f := os.NewFile(uintptr(fd), "start authorization")
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, ErrAuthorization
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, ErrAuthorization
	}
	var req CaptureRequest
	d := json.NewDecoder(io.LimitReader(f, maxHelperMessage+1))
	d.DisallowUnknownFields()
	if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF {
		return nil, ErrAuthorization
	}
	if !reflect.DeepEqual(req.Targets, targets) {
		return nil, ErrAuthorization
	}
	req.Config = cfg
	return OpenAuthorized(ctx, req)
}

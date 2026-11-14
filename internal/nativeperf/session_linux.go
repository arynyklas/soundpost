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
	conn         *net.UnixConn
	once         sync.Once
	next         sync.Mutex
	stopMu       sync.Mutex
	stop         func() bool
	parent       context.Context
	closed       atomic.Bool
	closeErr     error
	terminal     error
	pending      *AcquisitionProof
	finalSeen    bool
	topologySeen bool
	writeMu      sync.Mutex
	stopSent     bool
	initialProof *AcquisitionProof
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
	item, e := s.NextItem(ctx)
	if e != nil {
		return SanitizedEvent{}, e
	}
	if item.Proof != nil {
		s.next.Lock()
		s.pending = item.Proof
		s.next.Unlock()
		return SanitizedEvent{}, ErrProgressRequired
	}
	return *item.Event, nil
}
func (s *socketSource) NextItem(ctx context.Context) (AcquisitionItem, error) {
	s.next.Lock()
	defer s.next.Unlock()
	if e := ctx.Err(); e != nil {
		return AcquisitionItem{}, e
	}
	if s.pending != nil {
		p := s.pending
		s.pending = nil
		return AcquisitionItem{Proof: p}, nil
	}
	if s.terminal != nil {
		return AcquisitionItem{}, s.terminal
	}
	if s.closed.Load() {
		return AcquisitionItem{}, s.readFailure(ctx)
	}
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	var reply helperReply
	fail := func(e error) (AcquisitionItem, error) { s.terminal = e; s.Close(); return AcquisitionItem{}, e }
	if readMessage(s.conn, &reply) != nil {
		return fail(s.readFailure(ctx))
	}
	count := 0
	for _, v := range []bool{reply.Error != "", reply.Event != nil, reply.Proof != nil, reply.Complete, reply.Ready} {
		if v {
			count++
		}
	}
	if count != 1 || reply.Ready {
		return fail(ErrAcquisitionFailed)
	}
	if reply.Error != "" {
		return fail(helperCodeError(reply.Error))
	}
	if reply.Complete {
		if !s.finalSeen {
			return fail(ErrAcquisitionFailed)
		}
		return fail(ErrSourceComplete)
	}
	if reply.Proof != nil {
		p := reply.Proof
		if !p.valid() || s.finalSeen || p.Final && !s.topologySeen || !p.Final && s.topologySeen {
			return fail(ErrAcquisitionFailed)
		}
		if p.Final {
			if s.initialProof == nil || p.Domain != s.initialProof.Domain || !reflect.DeepEqual(p.CPUs, s.initialProof.CPUs) || p.Through < s.initialProof.Through {
				return fail(ErrAcquisitionFailed)
			}
			s.finalSeen = true
		} else {
			s.topologySeen = true
			copyProof := *p
			copyProof.CPUs = append([]uint32(nil), p.CPUs...)
			s.initialProof = &copyProof
		}
		return AcquisitionItem{Proof: p}, nil
	}
	if s.finalSeen || reply.Event.Validate() != nil {
		return fail(ErrAcquisitionFailed)
	}
	return AcquisitionItem{Event: reply.Event}, nil
}
func (s *socketSource) Stop() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.closed.Load() {
		return ErrAcquisitionClosed
	}
	if s.stopSent {
		return nil
	}
	if e := writeMessage(s.conn, struct {
		Stop bool `json:"stop"`
	}{true}); e != nil {
		return e
	}
	s.stopSent = true
	return nil
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
	if reply.Error != "" && reply.Event == nil && !reply.Ready && reply.Proof == nil && !reply.Complete {
		source.Close()
		return nil, helperCodeError(reply.Error)
	}
	if !reply.Ready || reply.Error != "" || reply.Event != nil || reply.Proof != nil || reply.Complete {
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

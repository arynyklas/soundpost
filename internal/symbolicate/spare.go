// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// spareMaxAge is how long an unused pre-started worker may wait. The worker's
// own five-second process timer is the hard stop; the spare is discarded long
// before it so the request that takes it keeps nearly the whole budget.
var spareMaxAge = 2 * time.Second

// spareState is the opt-in warm pool of an OCI service (Config.WarmSpare): at
// most one worker that already passed the full launch handshake (image
// provenance, container start, sandbox installed, executable identity checked)
// and waits for its one request. It is never reused: the request that takes it
// is the only one it ever serves, and the worker is then removed like any
// one-shot worker, so no byte of one request reaches another request's process.
// A replacement is started in the background after each request.
type spareState struct {
	mu      sync.Mutex
	spare   *spareWorker
	pending bool
	// started lets tests wait for background starts.
	started sync.WaitGroup
}

type spareWorker struct {
	p     *workerProcess
	timer *time.Timer
}

// startWorker launches one worker and completes its handshake. The returned
// process is running, has installed its sandbox and proved its executable
// identity; its stdin is waiting for the request. On failure nothing is left
// running or registered.
func (s *Service) startWorker(ctx context.Context) (*workerProcess, Reason) {
	p, e := s.launch(ctx, false)
	if e != nil {
		return nil, SandboxUnavailable
	}
	if e = p.cmd.Start(); e != nil {
		p.cleanup()
		return nil, SandboxUnavailable
	}
	fail := func(r Reason) (*workerProcess, Reason) {
		p.cmd.Process.Kill()
		p.cmd.Wait()
		p.cleanup()
		return nil, r
	}
	if e = p.attach(); e != nil {
		return fail(SandboxUnavailable)
	}
	if _, e = p.input.Write([]byte{'A'}); e != nil {
		return fail(SandboxUnavailable)
	}
	ready := make(chan error, 1)
	go func() {
		var b [33]byte
		_, e := io.ReadFull(p.output, b[:1])
		if e == nil && b[0] != 'R' {
			e = errors.New("sandbox unavailable")
		}
		if e == nil {
			_, e = io.ReadFull(p.output, b[1:])
			if e == nil && model.Hash(b[1:]) != s.config.WorkerSHA256 {
				e = errors.New("worker identity")
			}
		}
		ready <- e
	}()
	select {
	case e = <-ready:
		if e != nil {
			return fail(SandboxUnavailable)
		}
	case <-ctx.Done():
		return fail(Deadline)
	}
	return p, ""
}

// takeSpare hands out the waiting worker, if there is one that has not expired.
func (s *Service) takeSpare() *workerProcess {
	if !s.config.WarmSpare {
		return nil
	}
	s.spares.mu.Lock()
	defer s.spares.mu.Unlock()
	w := s.spares.spare
	if w == nil || !w.timer.Stop() {
		return nil
	}
	s.spares.spare = nil
	return w.p
}

// refillSpare starts the replacement spare in the background, off the
// request's slot and clock. Nothing but a worker that completed its handshake is
// ever kept.
func (s *Service) refillSpare() {
	if !s.config.WarmSpare {
		return
	}
	st := &s.spares
	st.mu.Lock()
	if st.spare != nil || st.pending {
		st.mu.Unlock()
		return
	}
	st.pending = true
	st.mu.Unlock()
	st.started.Add(1)
	go func() {
		defer st.started.Done()
		ctx, cancel := context.WithTimeout(context.Background(), ProcessTimeout)
		p, reason := s.startWorker(ctx)
		st.mu.Lock()
		st.pending = false
		if reason != "" {
			st.mu.Unlock()
			cancel()
			return
		}
		inner := p.cleanup
		p.cleanup = func() { inner(); cancel() }
		w := &spareWorker{p: p}
		w.timer = time.AfterFunc(spareMaxAge, func() { s.expireSpare(w) })
		st.spare = w
		st.mu.Unlock()
	}()
}

// expireSpare discards a spare nobody took in time.
func (s *Service) expireSpare(w *spareWorker) {
	s.spares.mu.Lock()
	if s.spares.spare != w {
		s.spares.mu.Unlock()
		return
	}
	s.spares.spare = nil
	s.spares.mu.Unlock()
	w.p.cmd.Process.Kill()
	w.p.cleanup()
	w.p.cmd.Wait()
}

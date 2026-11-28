// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import "context"

// SetFakeWorker replaces the sandboxed worker launch with a deterministic fake
// that answers each position independently.
func (s *Service) SetFakeWorker(f func(context.Context, []byte, uint32, uint32) (Reason, *CodeIdentity)) {
	s.runner = func(ctx context.Context, in workerInput) []workerOutput {
		out := make([]workerOutput, len(in.Positions))
		for i, p := range in.Positions {
			r, pos := f(ctx, in.Map, p.Line, p.Column)
			out[i] = workerOutput{Reason: r, Position: pos}
		}
		return out
	}
}

// SetFakeBatchWorker replaces the launch with a fake that sees each whole
// batch: it receives the map and the (line, column) positions of one launch.
func (s *Service) SetFakeBatchWorker(f func(ctx context.Context, mapBytes []byte, positions [][2]uint32) []Reason) {
	s.runner = func(ctx context.Context, in workerInput) []workerOutput {
		ps := make([][2]uint32, len(in.Positions))
		for i, p := range in.Positions {
			ps[i] = [2]uint32{p.Line, p.Column}
		}
		rs := f(ctx, in.Map, ps)
		out := make([]workerOutput, len(rs))
		for i, r := range rs {
			out[i] = workerOutput{Reason: r}
			if r == Resolved {
				out[i].Position = &CodeIdentity{Source: "a.ts", Line: ps[i][0], Column: ps[i][1]}
			}
		}
		return out
	}
}

// runOne runs a single-position batch and returns its answer.
func (s *Service) runOne(ctx context.Context, in workerInput) workerOutput {
	return s.run(ctx, in)[0]
}

// resolveOne resolves the first position of in.
func resolveOne(in workerInput) workerOutput { return resolveBatch(in)[0] }

// CachedEntries reports how many warm map entries the service holds.
func (s *Service) CachedEntries() int {
	s.cache.mu.Lock()
	defer s.cache.mu.Unlock()
	return s.cache.order.Len()
}

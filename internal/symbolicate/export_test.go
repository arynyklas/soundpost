// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import "context"

// SetFakeWorker replaces the sandboxed worker launch with a deterministic fake.
func (s *Service) SetFakeWorker(f func(context.Context, []byte, uint32, uint32) (Reason, *CodeIdentity)) {
	s.runner = func(ctx context.Context, in workerInput) workerOutput {
		r, p := f(ctx, in.Map, in.Line, in.Column)
		return workerOutput{Reason: r, Position: p}
	}
}

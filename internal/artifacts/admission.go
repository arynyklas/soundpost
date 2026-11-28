// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"github.com/arynyklas/soundpost/internal/model"
	"sync"
)

// An upload holds roughly uploadPeakFactor times its declared size in memory
// while it is buffered, parsed and re-encoded (measured at about 3x; see
// docs/artifacts and upload_memory_test.go). Admission charges that cost.
const (
	uploadPeakFactor            = 4
	defaultUploadGlobalBytes    = 256 << 20
	defaultUploadPrincipalBytes = 128 << 20
)

// uploadBudget bounds the memory in flight across concurrent uploads, globally
// and per principal. It never queues: a request that does not fit is refused
// at once with a retryable quota fault, so waiting work is bounded by zero.
type uploadBudget struct {
	mu        sync.Mutex
	global    uint64
	principal uint64
	used      uint64
	perUser   map[model.ID]uint64
}

func newUploadBudget(global, principal uint64) *uploadBudget {
	return &uploadBudget{global: global, principal: principal, perUser: map[model.ID]uint64{}}
}

// acquire reserves cost bytes for who; the returned release is idempotent.
func (b *uploadBudget) acquire(who model.ID, cost uint64) (func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if cost > b.global || cost > b.principal || b.used+cost > b.global || b.perUser[who]+cost > b.principal {
		f := model.Fail(model.Quota)
		f.Retryable = true
		return nil, f
	}
	b.used += cost
	b.perUser[who] += cost
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			b.used -= cost
			if left := b.perUser[who] - cost; left == 0 {
				delete(b.perUser, who)
			} else {
				b.perUser[who] = left
			}
		})
	}, nil
}

// LimitUploads replaces the in-flight upload memory budget (global and per
// principal, in bytes of estimated peak memory). It must be called before the
// service handles requests.
func (s *Service) LimitUploads(global, principal uint64) {
	s.uploads = newUploadBudget(global, principal)
}

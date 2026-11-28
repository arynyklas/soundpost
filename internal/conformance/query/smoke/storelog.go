// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/query"
)

// storeLog is the engine's result cache with a record of every value the engine
// stored. The lookup side refuses a failed or partial entry, so the answers alone
// cannot show whether one was ever stored; the record can.
type storeLog struct {
	inner query.ResultCache
	mu    sync.Mutex
	vals  [][]byte
}

func (s *storeLog) Lookup(ctx context.Context, scope auth.Scope, profile, q, params string) (auth.CacheResult, error) {
	return s.inner.Lookup(ctx, scope, profile, q, params)
}

func (s *storeLog) Store(ctx context.Context, scope auth.Scope, fill auth.CacheFill, value []byte, negative bool) error {
	s.mu.Lock()
	s.vals = append(s.vals, append([]byte(nil), value...))
	s.mu.Unlock()
	return s.inner.Store(ctx, scope, fill, value, negative)
}

// mark is the number of stores so far.
func (s *storeLog) mark() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.vals)
}

// failedSince reports a stored query result since mark that holds a failed,
// value-less or non-complete project ("" when there is none).
func (s *storeLog) failedSince(mark int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.vals[mark:] {
		var res query.Result
		if json.Unmarshal(v, &res) != nil {
			continue
		}
		for _, p := range res.Projects {
			if p.Failure != nil || p.Completeness != query.CompletenessComplete {
				return fmt.Sprintf("a failed or partial project result was stored in the cache: %s", trim(v))
			}
		}
	}
	return ""
}

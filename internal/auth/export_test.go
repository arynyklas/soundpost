// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import "time"

// Test-only views of the cache's bookkeeping, so tests can prove memory is
// bounded by the structures themselves rather than by what lookups happen to see.
func (c *Cache) OrderLen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
func (c *Cache) EntryLen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
func (c *Cache) LatestEntryExpiry() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	var latest time.Time
	for el := c.order.Front(); el != nil; el = el.Next() {
		if e := el.Value.(*cacheEntry); e.expires.After(latest) {
			latest = e.expires
		}
	}
	return latest
}

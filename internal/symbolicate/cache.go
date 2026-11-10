// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"bytes"
	"container/list"
	"soundpost/internal/model"
	"sync"
)

// cacheKey binds warm bytes to everything that can revoke them: the exact
// reference (Root, Hash), the caller's effective visibility and policy epoch, and
// the organization's delete generation at the time they were read.
type cacheKey struct {
	Org, Project, Source, Build, Root model.ID
	Visibility                        string
	Epoch                             uint64
	Generation                        uint64
	Hash                              model.Hash
}
type cacheEntry struct {
	key  cacheKey
	data []byte
}
type boundedCache struct {
	mu        sync.Mutex
	max, used int
	items     map[cacheKey]*list.Element
	order     *list.List
}

func newCache(max int) *boundedCache {
	return &boundedCache{max: max, items: make(map[cacheKey]*list.Element), order: list.New()}
}
func (c *boundedCache) get(k cacheKey) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.items[k]
	if e == nil {
		return nil
	}
	c.order.MoveToFront(e)
	return bytes.Clone(e.Value.(cacheEntry).data)
}
func (c *boundedCache) put(k cacheKey, b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.max <= 0 || len(b) > c.max {
		return
	}
	b = bytes.Clone(b)
	if e := c.items[k]; e != nil {
		c.order.MoveToFront(e)
		return
	}
	for c.used+len(b) > c.max || c.order.Len() >= 16 {
		e := c.order.Back()
		v := e.Value.(cacheEntry)
		c.used -= len(v.data)
		delete(c.items, v.key)
		c.order.Remove(e)
	}
	c.items[k] = c.order.PushFront(cacheEntry{k, b})
	c.used += len(b)
}
func (c *boundedCache) remove(k cacheKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.items[k]; e != nil {
		c.used -= len(e.Value.(cacheEntry).data)
		delete(c.items, k)
		c.order.Remove(e)
	}
}

// dropBefore discards every entry of org that was read under an older delete
// generation. Such an entry can never be served again, so its bytes (which may
// derive from data a deletion just removed) must not linger in memory.
func (c *boundedCache) dropBefore(org model.ID, generation uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for e := c.order.Front(); e != nil; {
		next := e.Next()
		if v := e.Value.(cacheEntry); v.key.Org == org && v.key.Generation < generation {
			c.used -= len(v.data)
			delete(c.items, v.key)
			c.order.Remove(e)
		}
		e = next
	}
}

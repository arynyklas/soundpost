// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"bytes"
	"container/list"
	"context"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
	"sort"
	"sync"
)

// Window selects the bytes of an artifact to release: Length bytes from Offset,
// or everything from Offset when Length is zero. A window outside the artifact
// is Invalid (after the caller has been authorized, never before).
type Window struct{ Offset, Length uint64 }

// ArtifactReader streams one window. Every Read is a new release: it revalidates
// the exact published reference, the caller's scope and grants, the org delete
// generation and the reference state before it may return a byte.
type ArtifactReader interface {
	io.ReadCloser
	Size() uint64 // bytes in the window
}

// CacheStats describes the visibility-bound fragment cache.
type CacheStats struct{ Hits, Misses, Entries, Bytes uint64 }

// readGate is what a Lifecycle installs on its Service so that every read path
// applies the same current generation and reference-state fences.
type readGate struct {
	deletes auth.DeleteGenerations
	state   StateStore
	cache   *fragmentCache
}

func (g *readGate) generation(ctx context.Context, scope auth.Scope) (uint64, error) {
	return g.deletes.DeleteGeneration(ctx, scope.OrgID(), scope.ProjectIDs())
}

// referenceState refuses a GC-fenced artifact (indistinguishable from absent) and
// fails closed on a reference ledger that does not verify.
func (g *readGate) referenceState(ctx context.Context, org, project, root model.ID) error {
	return g.state.View(ctx, func(st model.ControlState) error {
		led, err := loadLedger(settingsOf(st, org), project, root)
		if err != nil {
			return err
		}
		if led != nil && led.Retired {
			return model.Fail(model.NotFound)
		}
		return nil
	})
}

// ReadAuthorized opens the retained map for a window of its bytes.
func (s *Service) ReadAuthorized(ctx context.Context, scope auth.Scope, id ArtifactID, w Window) (ArtifactReader, error) {
	return s.openWindow(ctx, scope, id, false, w)
}

// ReadSourcesAuthorized opens the private source content; it additionally needs
// raw.read and a named source-reader grant, rechecked on every Read.
func (s *Service) ReadSourcesAuthorized(ctx context.Context, scope auth.Scope, id ArtifactID, w Window) (ArtifactReader, error) {
	return s.openWindow(ctx, scope, id, true, w)
}

func (s *Service) selectReceipt(artifact Artifact, private bool) (model.BlobReceipt, error) {
	if !private {
		return artifact.Map, nil
	}
	if artifact.Sources == nil {
		return model.BlobReceipt{}, model.Fail(model.NotFound)
	}
	return *artifact.Sources, nil
}

func (s *Service) openWindow(ctx context.Context, scope auth.Scope, id ArtifactID, private bool, w Window) (ArtifactReader, error) {
	artifact, err := s.Lookup(ctx, scope, id)
	if err != nil {
		return nil, err
	}
	receipt, err := s.selectReceipt(artifact, private)
	if err != nil {
		return nil, err
	}
	if err = scope.RevalidateArtifact(ctx, receipt.Manifest, false); err != nil {
		return nil, err
	}
	if err = s.blobs.VerifyBlob(ctx, receipt); err != nil {
		return nil, model.Fail(model.Unavailable)
	}
	r := &windowReader{service: s, gate: s.gate.Load(), ctx: ctx, scope: scope, id: id, private: private, receipt: receipt, ordinal: -1}
	if r.gate != nil {
		if r.generation, err = r.gate.generation(ctx, scope); err != nil {
			return nil, err
		}
		if err = r.gate.referenceState(ctx, receipt.Manifest.Org, receipt.Manifest.Project, receipt.Manifest.Root); err != nil {
			return nil, err
		}
	}
	var total uint64
	r.starts = make([]uint64, 0, len(receipt.Fragments)+1)
	for _, f := range receipt.Fragments {
		r.starts = append(r.starts, total)
		total += uint64(f.Size)
	}
	r.starts = append(r.starts, total)
	if total != uint64(receipt.Manifest.Size) {
		return nil, model.Fail(model.Corrupt)
	}
	if w.Offset > total || w.Length > total-w.Offset {
		return nil, model.Fail(model.Invalid)
	}
	length := w.Length
	if length == 0 {
		length = total - w.Offset
	}
	r.pos, r.end = w.Offset, w.Offset+length
	r.size = length
	return r, nil
}

type windowReader struct {
	service    *Service
	gate       *readGate
	ctx        context.Context
	scope      auth.Scope
	id         ArtifactID
	private    bool
	receipt    model.BlobReceipt
	generation uint64
	starts     []uint64
	pos, end   uint64
	size       uint64
	ordinal    int
	cur        []byte // at most one fragment is ever held
	closed     bool
}

func (r *windowReader) Size() uint64 { return r.size }

// fence is the whole release check. Nothing below it runs for a caller whose
// authority, reference, generation or reference state changed.
func (r *windowReader) fence() error {
	artifact, err := r.service.Lookup(r.ctx, r.scope, r.id)
	if err != nil {
		return err
	}
	current, err := r.service.selectReceipt(artifact, r.private)
	if err != nil {
		return err
	}
	a, _ := model.CanonicalJSON(current)
	b, _ := model.CanonicalJSON(r.receipt)
	if !bytes.Equal(a, b) {
		return model.Fail(model.NotFound)
	}
	return r.revalidate()
}

// revalidate is the cheaper re-check after bytes were fetched.
func (r *windowReader) revalidate() error {
	if err := r.scope.RevalidateArtifact(r.ctx, r.receipt.Manifest, false); err != nil {
		return err
	}
	if r.gate == nil {
		return nil
	}
	gen, err := r.gate.generation(r.ctx, r.scope)
	if err != nil {
		return err
	}
	if gen != r.generation {
		return model.Fail(model.NotFound)
	}
	m := r.receipt.Manifest
	return r.gate.referenceState(r.ctx, m.Org, m.Project, m.Root)
}

func (r *windowReader) key(ordinal int) (cacheKey, bool) {
	fp := r.scope.VisibilityFingerprint()
	if r.gate == nil || fp == "" {
		return cacheKey{}, false
	}
	m := r.receipt.Manifest
	return cacheKey{Org: m.Org, Project: m.Project, Root: m.Root, Hash: r.receipt.Hash, Private: r.private, Ordinal: uint32(ordinal), Fingerprint: fp, Epoch: r.scope.PolicyEpoch(), Generation: r.generation}, true
}

func (r *windowReader) fragment(ordinal int) ([]byte, error) {
	key, cacheable := r.key(ordinal)
	if cacheable {
		if data, ok := r.gate.cache.get(key); ok {
			return data, nil
		}
	}
	data, err := r.service.blobs.ReadBlobFragment(r.ctx, r.scope, r.receipt, uint32(ordinal))
	if err != nil {
		return nil, err
	}
	if len(data) != int(r.receipt.Fragments[ordinal].Size) {
		return nil, model.Fail(model.Corrupt)
	}
	// Bytes fetched while a revocation was landing are discarded, never cached.
	if err = r.revalidate(); err != nil {
		return nil, err
	}
	if cacheable {
		r.gate.cache.put(key, data)
	}
	return data, nil
}

func (r *windowReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.pos >= r.end {
		return 0, io.EOF
	}
	if err := r.fence(); err != nil {
		r.drop()
		return 0, err
	}
	i := sort.Search(len(r.starts)-1, func(i int) bool { return r.starts[i+1] > r.pos })
	if r.ordinal != i {
		data, err := r.fragment(i)
		if err != nil {
			r.drop()
			return 0, err
		}
		r.cur, r.ordinal = data, i
	}
	chunk := r.cur[r.pos-r.starts[i]:]
	if rest := r.end - r.pos; uint64(len(chunk)) > rest {
		chunk = chunk[:rest]
	}
	n := copy(p, chunk)
	r.pos += uint64(n)
	return n, nil
}

func (r *windowReader) drop() { r.cur, r.ordinal = nil, -1 }
func (r *windowReader) Close() error {
	r.closed = true
	r.drop()
	return nil
}

// cacheKey binds warm fragment bytes to everything that can revoke them: the
// exact reference (root and receipt hash), public versus private content, the
// caller's full visibility fingerprint (principal, session and every named
// source grant), the policy epoch and the org delete generation.
type cacheKey struct {
	Org, Project, Root model.ID
	Hash               model.Hash
	Private            bool
	Ordinal            uint32
	Fingerprint        string
	Epoch              uint64
	Generation         uint64
}
type cacheEntry struct {
	key  cacheKey
	data []byte
}

// fragmentCache is a byte-bounded LRU. Entries are immutable once stored.
type fragmentCache struct {
	mu           sync.Mutex
	max, used    int
	items        map[cacheKey]*list.Element
	order        *list.List
	hits, misses uint64
}

func newFragmentCache(max int) *fragmentCache {
	return &fragmentCache{max: max, items: map[cacheKey]*list.Element{}, order: list.New()}
}
func (c *fragmentCache) get(k cacheKey) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.items[k]; e != nil {
		c.hits++
		c.order.MoveToFront(e)
		return e.Value.(cacheEntry).data, true
	}
	c.misses++
	return nil, false
}
func (c *fragmentCache) put(k cacheKey, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.max <= 0 || len(data) > c.max || c.items[k] != nil {
		return
	}
	// A newer generation makes every older entry of the org dead weight.
	for e := c.order.Front(); e != nil; {
		next := e.Next()
		if v := e.Value.(cacheEntry); v.key.Org == k.Org && v.key.Generation < k.Generation {
			c.remove(e)
		}
		e = next
	}
	for c.used+len(data) > c.max {
		c.remove(c.order.Back())
	}
	c.items[k] = c.order.PushFront(cacheEntry{k, data})
	c.used += len(data)
}
func (c *fragmentCache) remove(e *list.Element) {
	v := e.Value.(cacheEntry)
	c.used -= len(v.data)
	delete(c.items, v.key)
	c.order.Remove(e)
}
func (c *fragmentCache) stats() CacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return CacheStats{Hits: c.hits, Misses: c.misses, Entries: uint64(c.order.Len()), Bytes: uint64(c.used)}
}

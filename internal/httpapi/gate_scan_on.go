//go:build soundpost_faults

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// A harness that runs a soundpost_faults build can ask what the storage scan of one trace view or
// service RED request cost: it sends an X-Gate-Request header of 16 lowercase hex characters, and
// when the handler finishes the pages, rows and bytes the scan read are appended to
// <SOUNDPOST_FAULT_DIR>/scans.jsonl. Without the variable or without a well-formed header nothing
// is counted and nothing is wrapped. A failed write is dropped; it never changes an answer.

// gateRequestHeader names the request whose scan is accounted.
const gateRequestHeader = "X-Gate-Request"

// gateScanLine mirrors the harness's ScanLine field for field (the product does not import the
// harness): the JSON names are the contract.
type gateScanLine struct {
	Req     string `json:"req"`
	Route   string `json:"route"`
	Pages   uint64 `json:"pages"`
	Rows    uint64 `json:"rows"`
	Bytes   uint64 `json:"bytes"`
	MS      int64  `json:"ms"`
	Partial bool   `json:"partial"`
}

// gateScanKey carries the per-request counters through the context; nothing is shared between requests.
type gateScanKey struct{}

type gateScanCount struct {
	pages, rows, bytes atomic.Uint64
	partial            atomic.Bool
}

// gateScanMu serializes the appends of one process (each line is opened, written whole and closed,
// so it is on disk when the handler returns).
var gateScanMu sync.Mutex

func gateRequestID(id string) bool {
	if len(id) != 16 {
		return false
	}
	for i := range len(id) {
		if c := id[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// gateScanRoute wraps a handler: for a request that asks for it, the handler's context carries a
// counter every scan made through gateScanner adds to, and the line is written when it returns
// (also when the answer is an error; partial is true when any page the scan read said so).
func gateScanRoute(route string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dir, id := os.Getenv("SOUNDPOST_FAULT_DIR"), r.Header.Get(gateRequestHeader)
		if dir == "" || !gateRequestID(id) {
			next(w, r)
			return
		}
		count, started := &gateScanCount{}, time.Now()
		defer func() {
			raw, err := json.Marshal(gateScanLine{Req: id, Route: route, Pages: count.pages.Load(), Rows: count.rows.Load(), Bytes: count.bytes.Load(), MS: time.Since(started).Milliseconds(), Partial: count.partial.Load()})
			if err != nil {
				return
			}
			raw = append(raw, '\n')
			gateScanMu.Lock()
			defer gateScanMu.Unlock()
			f, err := os.OpenFile(filepath.Join(dir, "scans.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				return
			}
			_, _ = f.Write(raw)
			_ = f.Close()
		}()
		next(w, r.WithContext(context.WithValue(r.Context(), gateScanKey{}, count)))
	}
}

// gateScanner wraps the scanner of a request that is being accounted; any other request keeps its scanner.
func gateScanner(ctx context.Context, inner SpanScanner) SpanScanner {
	count, ok := ctx.Value(gateScanKey{}).(*gateScanCount)
	if !ok || inner == nil {
		return inner
	}
	return gateScan{inner: inner, count: count}
}

type gateScan struct {
	inner SpanScanner
	count *gateScanCount
}

func (g gateScan) Scan(ctx context.Context, scope auth.Scope, req storage.ScanRequest) (storage.RowIterator, error) {
	rows, err := g.inner.Scan(ctx, scope, req)
	if err != nil || rows == nil {
		return rows, err
	}
	return gateRows{inner: rows, count: g.count}, nil
}

// gateRows counts the pages the way the query engine's tracked iterator does.
type gateRows struct {
	inner storage.RowIterator
	count *gateScanCount
}

func (r gateRows) Next(ctx context.Context) (storage.Page, error) {
	page, err := r.inner.Next(ctx)
	if err == nil {
		r.count.pages.Add(1)
		r.count.rows.Add(uint64(page.Len()))
		r.count.bytes.Add(page.Bytes)
		if page.Partial {
			r.count.partial.Store(true)
		}
	}
	return page, err
}
func (r gateRows) Watermarks() []model.Cursor { return r.inner.Watermarks() }
func (r gateRows) Close() error               { return r.inner.Close() }

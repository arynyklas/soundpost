// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"time"
)

// CursorTTL is how long a pagination cursor stays valid.
const CursorTTL = 15 * time.Minute

// maxCursorPosition bounds the position a cursor carries, so a hostile name or
// label value cannot make a cursor unissuable or unbounded.
const maxCursorPosition = 4096

// cursorState is the authenticated payload of a cursor. The token around it
// (see auth.Cache) already binds org, effective visibility fingerprint, every
// named-source grant, policy epoch, delete generation and expiry; the state adds
// the operation and a digest of the request parameters, so a cursor can only
// continue the very query that produced it.
type cursorState struct {
	Version int             `json:"v"`
	Op      string          `json:"o"`
	Params  [32]byte        `json:"p"`
	After   json.RawMessage `json:"a"`
}

// paramsDigest binds a cursor to its request without the cursor itself.
func paramsDigest(op string, params any) ([32]byte, error) {
	raw, err := json.Marshal(params)
	if err != nil {
		return [32]byte{}, model.Fail(model.Invalid)
	}
	h := sha256.New()
	h.Write([]byte(op))
	h.Write([]byte{0})
	h.Write(raw)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

func cursorSubject(d [32]byte) model.ID {
	var id model.ID
	copy(id[:], d[:16])
	if id == (model.ID{}) {
		id[15] = 1
	}
	return id
}

func cursorKind(op string) string { return "q-" + op }

// issueCursor mints the cursor for the position after the last returned item.
func (e *Engine) issueCursor(ctx context.Context, scope auth.Scope, op string, digest [32]byte, after any) (string, error) {
	if e.tickets == nil {
		return "", model.Fail(model.Unsupported)
	}
	raw, err := json.Marshal(after)
	if err != nil || len(raw) > maxCursorPosition {
		return "", model.Fail(model.TooLarge)
	}
	state, err := json.Marshal(cursorState{Version: 1, Op: op, Params: digest, After: raw})
	if err != nil {
		return "", model.Fail(model.Unavailable)
	}
	return e.tickets.IssueTicket(ctx, scope, cursorKind(op), cursorSubject(digest), state, CursorTTL)
}

// openCursor validates a presented cursor and decodes its position into after.
// Scope validity, tampering, another org, project set, principal or named-source
// grant, a changed policy epoch or delete generation and expiry are all one
// NotFound; a valid cursor from this scope used for different parameters is
// Invalid.
func (e *Engine) openCursor(ctx context.Context, scope auth.Scope, op string, digest [32]byte, token string, after any) error {
	if e.tickets == nil {
		return model.Fail(model.Unsupported)
	}
	subject, raw, err := e.tickets.OpenTicket(ctx, scope, cursorKind(op), token)
	if err != nil {
		return err
	}
	var st cursorState
	if json.Unmarshal(raw, &st) != nil || st.Version != 1 || st.Op != op || subject != cursorSubject(digest) || st.Params != digest {
		return model.Fail(model.Invalid)
	}
	if json.Unmarshal(st.After, after) != nil {
		return model.Fail(model.Invalid)
	}
	return nil
}

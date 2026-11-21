// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/arynyklas/soundpost/internal/model"
)

// FailReason is the closed vocabulary a fail-stop is reported in. It carries no text of the
// underlying error: that can name paths or credentials.
type FailReason string

const (
	// FailJournal: writing or syncing the Ready journal (entries, HardState, snapshot) failed.
	FailJournal FailReason = "journal_write_failed"
	// FailState: updating the in-memory log or the rebuilt command identities after a journal
	// write failed.
	FailState FailReason = "state_update_failed"
	// FailApply: the machine could not apply a committed command.
	FailApply FailReason = "apply_failed"
	// FailMaintenance: a journal rewrite (redaction, compaction) or a snapshot cut failed.
	FailMaintenance FailReason = "maintenance_failed"
	// FailEngine: the storage engine reported itself failed outside any command.
	FailEngine FailReason = "engine_failed"
	// FailBehind: a leader committed beyond the end of this node's journal, so the journal holds
	// less than this node acknowledged (a rolled-back or replaced disk). The member must not
	// rejoin as a voter under this identity.
	FailBehind FailReason = "journal_behind_acknowledged"
)

// ReasonJournalBehind is the closed reason `serve` prints when a node refuses to rejoin because
// its journal is behind what it acknowledged (FailBehind, ErrJournalBehind).
const ReasonJournalBehind = string(FailBehind)

// FailStop names the first failure of a FailDomain: the group that hit it and why.
type FailStop struct {
	Group  model.ID
	Reason FailReason
}

// FailDomain is the set of groups that share one node's storage and therefore one fate. A fsync
// that fails in one group means the page cache state of the whole device is unknown, and the
// storage engine of the node is one engine for all its data groups: a node whose storage failed
// can no longer persist or apply for ANY group. If only the group that noticed stopped, the node
// would keep answering Raft heartbeats, and so keep the leadership, of every group that has not
// itself tried to write yet; the two healthy voters would never elect a replacement leader while
// every proposal that reaches the failed leader is refused before it is persisted.
//
// When any group of the domain fails closed because its storage failed, every group of the
// domain fails closed too: it stops ticking (no heartbeat, no campaign), stops answering steps
// (no vote, no append acknowledgement) and refuses proposals and reads, so each healthy voter's
// election timeout runs out and the survivors elect a leader among themselves.
type FailDomain struct {
	mu      sync.Mutex
	groups  []*Group
	failed  bool
	failure FailStop
	done    chan struct{}
}

// NewFailDomain returns an empty domain. Every group of one node is opened with the same one
// (Config.Domain).
func NewFailDomain() *FailDomain { return &FailDomain{done: make(chan struct{})} }

// Done is closed when a group of the domain failed closed because of its storage.
func (d *FailDomain) Done() <-chan struct{} { return d.done }

// Failure is the first failure of the domain; false while the domain is healthy.
func (d *FailDomain) Failure() (FailStop, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.failure, d.failed
}

// Cause returns the error the caller should report for err once this domain may have failed: when the
// domain failed because a journal is behind what this node acknowledged, that is ErrJournalBehind (the
// node must not rejoin under this identity), whatever symptom err shows (a startup read answering
// unavailable or stale after every group failed closed). Any other err, or a healthy domain, is returned
// unchanged; nil stays nil.
func (d *FailDomain) Cause(err error) error {
	if err == nil || d == nil || errors.Is(err, ErrJournalBehind) {
		return err
	}
	if f, failed := d.Failure(); failed && f.Reason == FailBehind {
		return fmt.Errorf("%w (after: %w)", ErrJournalBehind, err)
	}
	return err
}

// add registers g; a domain that already failed admits no new group.
func (d *FailDomain) add(g *Group) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failed {
		return ErrUnavailable
	}
	d.groups = append(d.groups, g)
	return nil
}

// stop fails every group of the domain but origin, which already failed. It takes the other
// groups' locks one at a time and never while any group lock is held by the caller.
func (d *FailDomain) stop(origin *Group, reason FailReason) {
	d.mu.Lock()
	if !d.failed {
		d.failed = true
		d.failure = FailStop{Group: origin.group, Reason: reason}
		close(d.done)
	}
	groups := slices.Clone(d.groups)
	d.mu.Unlock()
	for _, g := range groups {
		if g == origin {
			continue
		}
		g.mu.Lock()
		if !g.failed && !g.closed {
			g.fail()
		}
		g.mu.Unlock()
	}
}

// failStop fails this group closed because its storage failed and, from another goroutine
// (g.mu is held by the caller), fails every other group of its domain.
func (g *Group) failStop(reason FailReason) {
	first := !g.failed
	g.fail()
	if first && !g.closed && g.domain != nil {
		go g.domain.stop(g, reason)
	}
}

// FailStop is failStop for a caller outside the group, the storage engine that failed outside
// any command. It is safe to call from any goroutine that holds no group lock. A group opened
// without a FailDomain has no node to stop with it: the call does nothing.
func (g *Group) FailStop(reason FailReason) {
	if g.domain == nil {
		return
	}
	g.mu.Lock()
	g.failStop(reason)
	g.mu.Unlock()
}

// recoverBehind is deferred by Step (g.mu held). Raft panics when a leader's heartbeat or append
// commits beyond the end of this node's log: the journal holds less than this node acknowledged,
// which a rolled-back or replaced disk does. That becomes a typed fail-stop of the whole node
// (reason journal_behind_acknowledged), never a crash of the serving goroutine; any other panic
// is not ours and continues.
func (g *Group) recoverBehind(err *error) {
	r := recover()
	if r == nil {
		return
	}
	text := fmt.Sprint(r)
	if !strings.Contains(text, "tocommit(") || !strings.Contains(text, "is out of range") {
		panic(r)
	}
	g.failStop(FailBehind)
	*err = ErrJournalBehind
}

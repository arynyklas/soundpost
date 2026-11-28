//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"errors"
	"net"
	"sort"
	"sync"
)

// Closed reasons are a fixed, content-free vocabulary: every helperErrorCode value plus the stream-end reasons below.
// The helper counts how many connections ended for each reason; no path, pid, target or error text is ever recorded.
const (
	closedComplete      = "stream_complete"
	closedCanceled      = "stream_canceled"
	closedWriteFailed   = "stream_write_failed"
	closedInvalidSource = "stream_invalid_item"
)

type closedReasons struct {
	mu sync.Mutex
	n  map[string]uint64
}

func (r *closedReasons) add(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.n == nil {
		r.n = map[string]uint64{}
	}
	r.n[reason]++
}

// ClosedReasons returns a copy of the per-reason connection-close counters, and the sorted reason names.
func (h *Helper) ClosedReasons() (map[string]uint64, []string) {
	h.closed.mu.Lock()
	defer h.closed.mu.Unlock()
	out := make(map[string]uint64, len(h.closed.n))
	names := make([]string, 0, len(h.closed.n))
	for k, v := range h.closed.n {
		out[k] = v
		names = append(names, k)
	}
	sort.Strings(names)
	return out, names
}

// The helper never serializes err.Error(): neither paths nor syscall/config
// details are part of its closed control protocol.
func helperErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrAuthorization):
		return "authorization_denied"
	case errors.Is(err, ErrTopologyChanged):
		return "topology_changed"
	case errors.Is(err, context.Canceled):
		return "source_canceled"
	case errors.Is(err, ErrResources):
		return "resource_limit"
	case errors.Is(err, ErrThreadCoverageChanged):
		return "thread_coverage_changed"
	case errors.Is(err, ErrTargetIdentity):
		return "generation_changed"
	case errors.Is(err, ErrRingOverwrite):
		return "loss"
	case errors.Is(err, ErrAcquisitionPending):
		return "event_unavailable"
	}
	var capability *CapabilityError
	if errors.As(err, &capability) {
		switch capability.Status {
		case Denied:
			return "permission_denied"
		case Unsupported:
			return "event_unavailable"
		}
	}
	return "acquisition_failed"
}
func helperCodeError(code string) error {
	switch code {
	case "authorization_denied":
		return ErrAuthorization
	case "topology_changed":
		return ErrTopologyChanged
	case "source_canceled":
		return context.Canceled
	case "resource_limit":
		return ErrResources
	case "permission_denied":
		return &CapabilityError{Denied, ReasonPermission}
	case "event_unavailable":
		return &CapabilityError{Unsupported, ReasonEvent}
	case "generation_changed":
		return ErrTargetIdentity
	case "thread_coverage_changed":
		return ErrThreadCoverageChanged
	case "loss":
		return ErrRingOverwrite
	default:
		return ErrAcquisitionFailed
	}
}

// helperReplyError is helperCodeError for a streamed error reply: an identity error keeps the instant the helper last proved
// the identity (IdentityError), so the consumer revokes [ProvenThrough, end) rather than everything.
func helperReplyError(r helperReply) error {
	e := helperCodeError(r.Error)
	if r.ProvenThrough != 0 && (errors.Is(e, ErrTargetIdentity) || errors.Is(e, ErrThreadCoverageChanged) || errors.Is(e, ErrTopologyChanged)) {
		return &IdentityError{Err: e, ProvenThrough: r.ProvenThrough}
	}
	return e
}

// This is the real post-authorization stream, also exercised against actual
// malformed/generation-change ring sources in tests. There is no EOF success.
func streamHelperEvents(ctx context.Context, c *net.UnixConn, source EventSource) string {
	if writeMessage(c, helperReply{Ready: true}) != nil {
		return closedWriteFailed
	}
	for {
		if proofSource, ok := source.(interface {
			NextItem(context.Context) (AcquisitionItem, error)
		}); ok {
			item, e := proofSource.NextItem(ctx)
			if e != nil {
				if errors.Is(e, ErrSourceComplete) {
					writeMessage(c, helperReply{Complete: true})
					return closedComplete
				}
				if ctx.Err() == nil {
					writeMessage(c, helperReply{Error: helperErrorCode(e), ProvenThrough: ProvenThroughOf(e)})
					return helperErrorCode(e)
				}
				return closedCanceled
			}
			if (item.Event == nil) == (item.Proof == nil) || item.Event != nil && item.Event.Validate() != nil || item.Proof != nil && !item.Proof.valid() {
				writeMessage(c, helperReply{Error: "acquisition_failed"})
				return closedInvalidSource
			}
			if writeMessage(c, helperReply{Event: item.Event, Proof: item.Proof}) != nil {
				return closedWriteFailed
			}
			continue
		}
		event, e := source.Next(ctx)
		if e != nil {
			if ctx.Err() == nil {
				writeMessage(c, helperReply{Error: helperErrorCode(e), ProvenThrough: ProvenThroughOf(e)})
				return helperErrorCode(e)
			}
			return closedCanceled
		}
		if event.Validate() != nil {
			writeMessage(c, helperReply{Error: "acquisition_failed"})
			return closedInvalidSource
		}
		if writeMessage(c, helperReply{Event: &event}) != nil {
			return closedWriteFailed
		}
	}
}

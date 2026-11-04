//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"errors"
	"net"
)

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

// This is the real post-authorization stream, also exercised against actual
// malformed/generation-change ring sources in tests. There is no EOF success.
func streamHelperEvents(ctx context.Context, c *net.UnixConn, source EventSource) {
	if writeMessage(c, helperReply{Ready: true}) != nil {
		return
	}
	for {
		if proofSource, ok := source.(interface {
			NextItem(context.Context) (AcquisitionItem, error)
		}); ok {
			item, e := proofSource.NextItem(ctx)
			if e != nil {
				if errors.Is(e, ErrSourceComplete) {
					writeMessage(c, helperReply{Complete: true})
				} else if ctx.Err() == nil {
					writeMessage(c, helperReply{Error: helperErrorCode(e)})
				}
				return
			}
			if (item.Event == nil) == (item.Proof == nil) || item.Event != nil && item.Event.Validate() != nil || item.Proof != nil && !item.Proof.valid() {
				writeMessage(c, helperReply{Error: "acquisition_failed"})
				return
			}
			if writeMessage(c, helperReply{Event: item.Event, Proof: item.Proof}) != nil {
				return
			}
			continue
		}
		event, e := source.Next(ctx)
		if e != nil {
			if ctx.Err() == nil {
				writeMessage(c, helperReply{Error: helperErrorCode(e)})
			}
			return
		}
		if event.Validate() != nil {
			writeMessage(c, helperReply{Error: "acquisition_failed"})
			return
		}
		if writeMessage(c, helperReply{Event: &event}) != nil {
			return
		}
	}
}

//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"time"
)

type CaptureMode string

const (
	ModeCPU       CaptureMode = "cpu"
	ModeCPUOffCPU CaptureMode = "cpu_offcpu"
)

var ErrAuthorization = errors.New("native profiling: local operator authorization denied")
var ErrResources = ErrResourceBudget

type PeerCredential struct {
	UID uint32
	PID int32
}
type StartAuthorization struct {
	Installation string
	UID          uint32
	Revision     uint64
	Expires      int64
	Targets      []Target
	Config       Config
	Mode         CaptureMode
	Signature    []byte
}

func (a StartAuthorization) message() []byte { a.Signature = nil; b, _ := json.Marshal(a); return b }

// SignStart is an operator-side operation; the helper never loads a signing key.
func SignStart(a StartAuthorization, key ed25519.PrivateKey) (StartAuthorization, error) {
	if len(key) != ed25519.PrivateKeySize {
		return a, ErrAuthorization
	}
	a.Signature = ed25519.Sign(key, a.message())
	return a, nil
}

type CaptureRequest struct {
	Authorization StartAuthorization
	Targets       []Target
	Config        Config
	Mode          CaptureMode
}
type OperatorPolicy struct {
	Installation string
	PublicKey    ed25519.PublicKey
	UID          uint32
	Revision     uint64
	Allowlist    []Target
}
type AuthorizedTargets struct {
	targets []Target
	mode    CaptureMode
}

func (a AuthorizedTargets) Targets() []Target {
	out := append([]Target(nil), a.targets...)
	for i := range out {
		out[i].AllowedBuildIDs = append([]string(nil), out[i].AllowedBuildIDs...)
	}
	return out
}
func (a AuthorizedTargets) Mode() CaptureMode { return a.mode }
func authorizeLocal(peer PeerCredential, r CaptureRequest, p OperatorPolicy) (AuthorizedTargets, error) {
	a := r.Authorization
	if len(p.PublicKey) != ed25519.PublicKeySize || p.Installation == "" || a.Installation != p.Installation || peer.UID != p.UID || a.UID != peer.UID || a.Revision != p.Revision || uint64(r.Config.PolicyRevision) != p.Revision || a.Expires <= time.Now().Unix() || a.Expires > time.Now().Add(24*time.Hour).Unix() || !ed25519.Verify(p.PublicKey, a.message(), a.Signature) || validateTargets(r.Targets) != nil || r.Config.Validate() != nil || (r.Mode != ModeCPU && r.Mode != ModeCPUOffCPU) || r.Mode != a.Mode || !reflect.DeepEqual(r.Targets, a.Targets) {
		return AuthorizedTargets{}, ErrAuthorization
	}
	// Config is signed as an upper bound, not an extensible event selector.
	c, m := r.Config, a.Config
	if m.Validate() != nil || c.CPUHz > m.CPUHz || c.MaxFrames > m.MaxFrames || c.RingBytes > m.RingBytes || c.MaxMemory > m.MaxMemory || c.ReorderWindow != m.ReorderWindow {
		return AuthorizedTargets{}, ErrAuthorization
	}
	for _, t := range r.Targets {
		if t.CgroupID == 0 || len(t.AllowedBuildIDs) == 0 {
			return AuthorizedTargets{}, ErrAuthorization
		}
		found := false
		for _, allowed := range p.Allowlist {
			if reflect.DeepEqual(t, allowed) {
				found = true
				break
			}
		}
		if !found {
			return AuthorizedTargets{}, ErrAuthorization
		}
	}
	return AuthorizedTargets{targets: append([]Target(nil), r.Targets...), mode: r.Mode}, nil
}

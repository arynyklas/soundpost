// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
	"time"
)

// FrameReason is separate from acquisition Reason: symbol/coverage failure must
// not change a genuine CPU observation into an empty or zero-valued measurement.
type FrameReason string

const (
	FrameUnresolved          FrameReason = "frame_unresolved"
	FrameMissing             FrameReason = "missing_frame_pointer_or_callchain"
	FrameTruncated           FrameReason = "callchain_truncated"
	FrameUnapproved          FrameReason = "build_not_approved"
	FrameDeleted             FrameReason = "deleted_executable"
	FrameGeneration          FrameReason = "generation_changed"
	FrameJITMissing          FrameReason = "jit_or_anonymous_map_unavailable"
	FrameJITExpired          FrameReason = "jit_map_expired"
	FrameArtifactUnavailable FrameReason = "artifact_unavailable"
	FrameArtifactDenied      FrameReason = "artifact_denied"
	FrameInvalidELF          FrameReason = "invalid_elf_artifact"
)

func (r FrameReason) valid() bool {
	switch r {
	case "", FrameUnresolved, FrameMissing, FrameTruncated, FrameUnapproved, FrameDeleted, FrameGeneration, FrameJITMissing, FrameJITExpired, FrameArtifactUnavailable, FrameArtifactDenied, FrameInvalidELF:
		return true
	}
	return false
}

// SafeModule has no pathname or load address. ID is a domain-separated hash of
// an approved build identity, not a hash of a potentially private pathname.
type SafeModule struct {
	ID      string `json:"id"`
	BuildID string `json:"build_id"`
}

func moduleIdentity(build string) string {
	sum := sha256.Sum256([]byte("soundpost-native-module-v1\x00" + build))
	return hex.EncodeToString(sum[:])
}

// SymbolPolicy is trusted local operator configuration, never a capture-request
// extension. The app must bind Revision to the signed C10 policy revision.
// No source paths, source contents, runtime URLs or perf-map files are read.
type SymbolPolicy struct {
	Revision            uint64
	AllowMappedELF      bool
	FramePointersAbsent bool // explicit approved-build coverage fact, never inferred from zero samples
	MaxMapsBytes        uint64
	MaxMappings         uint32
	MaxELFBytes         uint64
	MaxSymbols          uint32
	MinReadInterval     time.Duration
	ArtifactScope       auth.Scope
	ProjectID           model.ID
	Artifacts           map[string]model.ID // approved GNU build-ID -> C07 artifact identity
}

func DefaultSymbolPolicy(revision uint64) SymbolPolicy {
	return SymbolPolicy{Revision: revision, MaxMapsBytes: 1 << 20, MaxMappings: 4096, MaxELFBytes: 32 << 20, MaxSymbols: 65536, MinReadInterval: 100 * time.Millisecond}
}
func (p SymbolPolicy) validate() error {
	if p.Revision == 0 || p.MaxMapsBytes == 0 || p.MaxMapsBytes > 1<<20 || p.MaxMappings == 0 || p.MaxMappings > 4096 || p.MaxELFBytes == 0 || p.MaxELFBytes > 32<<20 || p.MaxSymbols == 0 || p.MaxSymbols > 65536 || p.MinReadInterval < 100*time.Millisecond || len(p.Artifacts) > 256 {
		return ErrInvalid
	}
	for build, id := range p.Artifacts {
		if !validBuild(build) || id == (model.ID{}) {
			return ErrInvalid
		}
	}
	return nil
}

// ArtifactReference includes authorization identity, not just a content hash.
// C07's adapter independently revalidates scope, project, build association,
// deletion generation, retention and artifact-read policy on every scoped read.
type ArtifactReference struct {
	Scope      auth.Scope
	ProjectID  model.ID
	BuildID    string
	ArtifactID model.ID
}
type ArtifactResolver interface {
	ScopedRead(context.Context, ArtifactReference) (io.ReadCloser, error)
}

// AddressFrame and MappingTable are transient acquisition data. JSON cannot
// serialize absolute addresses; only ResolvedFrame is intended for persistence.
type AddressFrame struct {
	Task   TaskKey     `json:"-"`
	IP     uint64      `json:"-"`
	Reason FrameReason `json:"-"`
}
type mappingEntry struct {
	start, end, offset uint64
	module             SafeModule
	reason             FrameReason
}
type MappingTable struct {
	process ProcessKey
	entries []mappingEntry
	policy  SymbolPolicy
}

func (m MappingTable) Process() ProcessKey { return m.process }
func (m MappingTable) Modules() []SafeModule {
	out := make([]SafeModule, 0, len(m.entries))
	seen := make(map[string]bool)
	for _, entry := range m.entries {
		if entry.module.ID != "" && !seen[entry.module.ID] {
			seen[entry.module.ID] = true
			out = append(out, entry.module)
		}
	}
	return out
}

// SafeMapping describes only approved file-relative code and its process epoch.
// Unapproved/anonymous ranges never become public address-shaped metadata.
type SafeMapping struct {
	Process    ProcessKey   `json:"process"`
	Module     SafeModule   `json:"module"`
	FileOffset model.Uint64 `json:"relative_code_offset"`
	CodeBytes  model.Uint64 `json:"code_bytes"`
}

func (m MappingTable) Mappings() []SafeMapping {
	out := make([]SafeMapping, 0, len(m.entries))
	for _, entry := range m.entries {
		if entry.reason != "" || entry.module.ID == "" || !validBuild(entry.module.BuildID) || entry.start >= entry.end || entry.offset > ^uint64(0)-(entry.end-entry.start) {
			continue
		}
		out = append(out, SafeMapping{Process: m.process, Module: entry.module, FileOffset: model.Uint64(entry.offset), CodeBytes: model.Uint64(entry.end - entry.start)})
	}
	return out
}

type ResolvedFrame struct {
	Module *SafeModule  `json:"module,omitempty"`
	Offset model.Uint64 `json:"relative_code_offset,omitempty"` // ELF file-relative code offset, never process IP
	Symbol string       `json:"symbol,omitempty"`
	Reason FrameReason  `json:"reason,omitempty"`
}

func sameFrameProcess(k TaskKey, p ProcessKey) bool {
	return k.BootID == p.BootID && k.PIDNamespace == p.PIDNamespace && k.TGID == p.TGID && k.ProcessStart == p.ProcessStart && k.Generation == p.Generation
}

// ResolveFrames never falls back to the host filesystem or a runtime URL when
// C07 is absent/denies. Each failure still leaves a nonempty safe observation.
func ResolveFrames(ctx context.Context, samples []AddressFrame, mappings MappingTable, artifacts ArtifactResolver) ([]ResolvedFrame, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	caller := ctx
	if len(samples) > 128 {
		return nil, ErrResourceBudget
	}
	var previousEnd uint64
	for _, entry := range mappings.entries {
		if entry.start >= entry.end || entry.start < previousEnd || entry.offset > ^uint64(0)-(entry.end-entry.start) {
			return nil, ErrInvalid
		}
		previousEnd = entry.end
	}
	if len(samples) == 0 {
		return []ResolvedFrame{{Reason: FrameMissing}}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out := make([]ResolvedFrame, 0, len(samples))
	// Cache only within this bounded scope-bound operation, never across reads,
	// revocation checks or mapping epochs. One reusable input buffer avoids
	// per-frame copies and aggregate artifact bytes/symbols have fixed ceilings.
	cache := make(map[string]frameArtifact)
	var scratch []byte
	var artifactBytes uint64
	var symbolCount uint32
	for _, sample := range samples {
		if e := caller.Err(); e != nil {
			return nil, e
		}
		if !sample.Reason.valid() {
			return nil, ErrInvalid
		}
		frame := ResolvedFrame{Reason: FrameUnresolved}
		if sample.Reason != "" {
			frame.Reason = sample.Reason
			out = append(out, frame)
			continue
		}
		if !sameFrameProcess(sample.Task, mappings.process) {
			frame.Reason = FrameGeneration
			out = append(out, frame)
			continue
		}
		for _, entry := range mappings.entries {
			if sample.IP < entry.start || sample.IP >= entry.end {
				continue
			}
			if entry.reason != "" {
				frame.Reason = entry.reason
				break
			}
			if entry.module.ID == "" || !validBuild(entry.module.BuildID) {
				frame.Reason = FrameUnapproved
				break
			}
			module := entry.module
			frame.Module = &module
			frame.Offset = model.Uint64(entry.offset + (sample.IP - entry.start))
			frame.Reason = FrameArtifactUnavailable
			if artifacts == nil {
				break
			}
			if ctx.Err() != nil {
				break
			}
			policy := mappings.policy
			id, ok := policy.Artifacts[module.BuildID]
			if !ok {
				break
			}
			if policy.validate() != nil || policy.ArtifactScope.OrgID() == (model.ID{}) || !policy.ArtifactScope.AllowsProject(policy.ProjectID) || policy.ArtifactScope.Permission() != auth.ArtifactRead {
				frame.Reason = FrameArtifactDenied
				break
			}
			resolved, exists := cache[module.BuildID]
			if !exists {
				if artifactBytes >= policy.MaxELFBytes || symbolCount >= policy.MaxSymbols {
					resolved.reason = FrameArtifactUnavailable
				} else {
					if scratch == nil {
						scratch = make([]byte, int(policy.MaxELFBytes)+1)
					}
					var artifactErr error
					resolved, artifactErr = readFrameArtifact(caller, ctx, artifacts, ArtifactReference{Scope: policy.ArtifactScope, ProjectID: policy.ProjectID, BuildID: module.BuildID, ArtifactID: id}, scratch, policy.MaxELFBytes-artifactBytes, policy.MaxELFBytes, policy.MaxSymbols-symbolCount)
					if artifactErr != nil {
						return nil, artifactErr
					}
					artifactBytes += resolved.bytes
					symbolCount += uint32(len(resolved.info.symbols))
				}
				cache[module.BuildID] = resolved
			}
			frame.Reason = resolved.reason
			if frame.Reason == "" {
				frame.Reason = FrameUnresolved
				if name, ok := resolved.info.lookup(uint64(frame.Offset)); ok {
					frame.Symbol = name
					frame.Reason = ""
				}
			}
			break
		}
		out = append(out, frame)
	}
	if e := caller.Err(); e != nil {
		return nil, e
	}
	return out, nil
}

type frameArtifact struct {
	info   elfSymbolInfo
	reason FrameReason
	bytes  uint64
}

func readFrameArtifact(caller, bounded context.Context, resolver ArtifactResolver, reference ArtifactReference, scratch []byte, remaining, maxBytes uint64, maxSymbols uint32) (frameArtifact, error) {
	if e := caller.Err(); e != nil {
		return frameArtifact{}, e
	}
	ctx, cancel := context.WithTimeout(bounded, 100*time.Millisecond)
	defer cancel()
	unavailable := func(n uint64) (frameArtifact, error) {
		return frameArtifact{reason: FrameArtifactUnavailable, bytes: min(n, remaining)}, nil
	}
	reader, e := resolver.ScopedRead(ctx, reference)
	if e != nil || reader == nil {
		if reader != nil {
			reader.Close()
		}
		if err := caller.Err(); err != nil {
			return frameArtifact{}, err
		}
		if ctx.Err() != nil {
			return unavailable(0)
		}
		var denied *model.Fault
		if errors.As(e, &denied) && (denied.Code == model.Forbidden || denied.Code == model.Unauthenticated) {
			return frameArtifact{reason: FrameArtifactDenied}, nil
		}
		return unavailable(0)
	}
	n, readErr := io.ReadFull(reader, scratch[:int(remaining)+1])
	closeErr := reader.Close()
	if err := caller.Err(); err != nil {
		return frameArtifact{}, err
	}
	if ctx.Err() != nil || readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF || closeErr != nil || uint64(n) > remaining {
		return unavailable(uint64(n))
	}
	info, parseErr := readELFSymbols(ctx, newImageReader(scratch[:n]), maxBytes, maxSymbols)
	if err := caller.Err(); err != nil {
		return frameArtifact{}, err
	}
	if ctx.Err() != nil || errors.Is(parseErr, ErrResourceBudget) {
		return unavailable(uint64(n))
	}
	if parseErr != nil || info.buildID != reference.BuildID {
		return frameArtifact{reason: FrameInvalidELF, bytes: uint64(n)}, nil
	}
	return frameArtifact{info: info, bytes: uint64(n)}, nil
}

type CPUObservation struct {
	Task                TaskKey           `json:"task"`
	Method              SamplingMethod    `json:"method"`
	Unit                Unit              `json:"unit"`
	RequestedHz         uint32            `json:"requested_hz"`
	Period              model.Uint64      `json:"period"`
	Frames              []ResolvedFrame   `json:"frames"`
	Coverage            FrameReason       `json:"coverage,omitempty"`
	AcquisitionCoverage Reason            `json:"acquisition_coverage,omitempty"`
	Throttle            *ThrottleEvidence `json:"throttle,omitempty"`
}

func ResolveCPUObservation(ctx context.Context, task TaskKey, sample CPUSample, mappings MappingTable, artifacts ArtifactResolver) (CPUObservation, error) {
	if e := ctx.Err(); e != nil {
		return CPUObservation{}, e
	}
	if !sample.valid() || !safeIdentity(task.BootID) || !task.valid(ClockDomain{BootID: task.BootID}) {
		return CPUObservation{}, ErrInvalid
	}
	frames := make([]AddressFrame, 0, min(len(sample.Callchain)+1, 128))
	frames = append(frames, AddressFrame{Task: task, IP: uint64(sample.IP)})
	chainContext := ContextUser
	filtered, truncated := false, false
	for _, entry := range sample.Callchain {
		if entry.Context != "" {
			chainContext = entry.Context
			continue
		}
		if chainContext != ContextUser {
			filtered = true
			continue
		}
		if entry.IP == sample.IP {
			continue
		}
		if len(frames) == 128 {
			truncated = true
			break
		}
		frames = append(frames, AddressFrame{Task: task, IP: uint64(entry.IP)})
	}
	resolved, e := ResolveFrames(ctx, frames, mappings, artifacts)
	if e != nil {
		return CPUObservation{}, e
	}
	out := CPUObservation{Task: task, Method: sample.Method, Unit: sample.Unit, RequestedHz: sample.RequestedHz, Period: sample.Period, Frames: resolved, AcquisitionCoverage: sample.Truncated}
	if sample.Throttle != nil {
		copy := *sample.Throttle
		out.Throttle = &copy
	}
	switch sample.Truncated {
	case ReasonTruncated:
		out.Coverage = FrameTruncated
	case ReasonMissingCallchain:
		out.Coverage = FrameMissing
	case ReasonUnresolved:
		out.Coverage = FrameUnresolved
	}
	if filtered && out.Coverage == "" {
		out.Coverage = FrameUnresolved
	}
	if mappings.policy.FramePointersAbsent {
		out.Coverage = FrameMissing
	}
	if len(sample.Callchain) == 0 && out.Coverage == "" {
		out.Coverage = FrameMissing
	}
	if truncated {
		out.Coverage = FrameTruncated
	}
	return out, nil
}

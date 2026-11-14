// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Package symbolicate resolves exact owned source-map identities in OS-isolated workers.
package symbolicate

import (
	"context"
	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
)

type BuildID = model.ID
type Reason string

const (
	Resolved           Reason = "resolved"
	IdentityMismatch   Reason = "identity_mismatch"
	Unavailable        Reason = "artifact_unavailable"
	CorruptArtifact    Reason = "artifact_corrupt"
	InvalidMap         Reason = "invalid_map"
	ResourceLimit      Reason = "resource_limit"
	Deadline           Reason = "deadline"
	SandboxUnavailable Reason = "sandbox_unavailable"
	WorkerFailure      Reason = "worker_failure"
	Unmapped           Reason = "unmapped"
	SourceDenied       Reason = "source_context_denied"
	FrameLimit         Reason = "frame_limit"
)

type CodeIdentity struct {
	Source   string `json:"source"`
	Function string `json:"function,omitempty"`
	Line     uint32 `json:"line"`
	Column   uint32 `json:"column"`
}
type SymbolicatedFrame struct {
	Original      model.Frame   `json:"original"`
	Resolved      *CodeIdentity `json:"resolved,omitempty"`
	Build         model.ID      `json:"build"`
	MapSHA256     model.Hash    `json:"map_sha256"`
	Reason        Reason        `json:"reason"`
	SourceContext *string       `json:"source_context,omitempty"`
}
type Options struct{ IncludeSources bool }

// Lookup returns the actual scoped immutable reference, including the complete
// build/debug/generated/map/path manifest, not an unauthenticated content hash.
type ArtifactReader interface {
	Lookup(context.Context, auth.Scope, model.ID) (artifacts.Artifact, error)
	Get(context.Context, auth.Scope, model.ID) (io.ReadCloser, error)
	GetSources(context.Context, auth.Scope, model.ID) (io.ReadCloser, error)
}

// Config is trusted operator configuration; it is never decoded from requests.
// Mode must be explicitly selected. Native never falls back to OCI.
type Config struct {
	Mode         string     `json:"mode"`
	WorkerPath   string     `json:"worker_path,omitempty"`
	WorkerSHA256 model.Hash `json:"worker_sha256"`
	CgroupRoot   string     `json:"cgroup_root,omitempty"`
	OCIRuntime   string     `json:"oci_runtime,omitempty"`
	OCIImage     string     `json:"oci_image,omitempty"`
	CacheBytes   int        `json:"cache_bytes,omitempty"`
}

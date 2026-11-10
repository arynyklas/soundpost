// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package host

import (
	"context"
	"errors"
	"io/fs"
	"math"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"soundpost/internal/model"
)

const maxFilesystems = 16

var aliasPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// FilesystemTarget names one filesystem to measure. Alias is the only
// identifier ever emitted; Path is used for the OS call and never leaves it.
type FilesystemTarget struct {
	Alias string
	Path  string
}

// HostPolicy is the operator-approved set of metric groups and filesystems.
type HostPolicy struct {
	Allow       []Group
	Filesystems []FilesystemTarget
}

// Validate rejects unknown or duplicate groups and unsafe filesystem targets.
func (p HostPolicy) Validate() error {
	known := map[Group]bool{}
	for _, g := range AllGroups() {
		known[g] = true
	}
	seen := map[Group]bool{}
	for _, g := range p.Allow {
		if !known[g] || seen[g] {
			return model.Fail(model.Invalid)
		}
		seen[g] = true
	}
	if len(p.Filesystems) > maxFilesystems {
		return model.Fail(model.Invalid)
	}
	aliases := map[string]bool{}
	for _, t := range p.Filesystems {
		if !aliasPattern.MatchString(t.Alias) || aliases[t.Alias] || !absolutePath(t.Path) {
			return model.Fail(model.Invalid)
		}
		aliases[t.Alias] = true
	}
	return nil
}

// absolutePath requires a non-empty, NUL-free absolute path; on Windows it must
// be drive-absolute (X:\ or X:/), UNC and drive-relative forms are rejected.
func absolutePath(p string) bool {
	if p == "" || len(p) > 4096 || strings.ContainsRune(p, 0) {
		return false
	}
	if runtime.GOOS == "windows" {
		if len(p) < 3 || !(p[0] >= 'a' && p[0] <= 'z' || p[0] >= 'A' && p[0] <= 'Z') || p[1] != ':' {
			return false
		}
		return p[2] == '\\' || p[2] == '/'
	}
	return p[0] == '/'
}

// Sample is one host measurement before it is wrapped in a model record.
type Sample struct {
	Name   string
	Labels model.Labels
	Value  float64
	Unit   string
	Type   string
}

// HostBatch is one coherent collection pass.
type HostBatch struct {
	At      model.UnixNano
	Samples []Sample
}

// fsStat is the portable result of a filesystem statistics call, already in bytes.
type fsStat struct {
	Size, Free, Avail uint64
	Files, FilesFree  uint64
}

type groupResult struct {
	caps    []Capability
	samples []Sample
}

// collector holds every injectable OS dependency so the Linux parsing can run
// against fixtures as well as the real /proc.
type collector struct {
	procRoot string
	sysRoot  string
	statfs   func(path string) (fsStat, error)
	// isCgroup2 reports whether dir is a cgroup2 filesystem mount.
	isCgroup2 func(dir string) (bool, error)
	// exempt reports whether the agent can see every process despite a
	// hidepid /proc mount; gid is the mount's gid= option when hasGID.
	exempt   func(gid int, hasGID bool) bool
	now      func() time.Time
	fsMethod string
	read     func(c *collector, g Group, p HostPolicy) groupResult
}

// Collect gathers the allowed groups. The error is only for an invalid policy
// or a cancelled context; every group failure becomes a Capability and a
// missing source never becomes a zero sample.
func Collect(ctx context.Context, p HostPolicy) (HostBatch, Capabilities, error) {
	if err := p.Validate(); err != nil {
		return HostBatch{}, nil, err
	}
	return newCollector().collect(ctx, p)
}

func (c *collector) collect(ctx context.Context, p HostPolicy) (HostBatch, Capabilities, error) {
	allowed := map[Group]bool{}
	for _, g := range p.Allow {
		allowed[g] = true
	}
	batch := HostBatch{At: model.UnixNano(c.now().UnixNano())}
	var caps Capabilities
	for _, g := range AllGroups() {
		if ctx.Err() != nil {
			return HostBatch{}, nil, model.Fail(model.Cancelled)
		}
		if !allowed[g] {
			caps = append(caps, Capability{Group: g, Status: StatusDenied, Reason: ReasonPolicy, Method: "policy"})
			continue
		}
		r := c.read(c, g, p)
		if ctx.Err() != nil {
			return HostBatch{}, nil, model.Fail(model.Cancelled)
		}
		caps = append(caps, r.caps...)
		batch.Samples = append(batch.Samples, r.samples...)
	}
	return batch, caps, nil
}

func statusFor(err error) (Status, Reason) {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return StatusDenied, ReasonPermission
	case errors.Is(err, fs.ErrNotExist):
		return StatusUnknown, ReasonNotPresent
	}
	return StatusUnknown, ReasonReadFailed
}

func failure(g Group, method string, s Status, r Reason) groupResult {
	return groupResult{caps: []Capability{{Group: g, Status: s, Reason: r, Method: method}}}
}

func supported(g Group, method string, samples ...Sample) groupResult {
	return groupResult{caps: []Capability{{Group: g, Status: StatusSupported, Method: method}}, samples: samples}
}

func osUnsupported(g Group, method string) groupResult {
	return failure(g, method, StatusUnsupported, ReasonOSUnsupported)
}

func sample(name, unit, typ string, v float64, labels ...string) Sample {
	l := make(model.Labels, 0, len(labels)/2)
	for i := 0; i+1 < len(labels); i += 2 {
		l = append(l, model.Label{Name: labels[i], Value: labels[i+1]})
	}
	sort.Slice(l, func(i, j int) bool { return l[i].Name < l[j].Name })
	return Sample{Name: name, Labels: l, Value: v, Unit: unit, Type: typ}
}

// readFilesystem is shared by every OS that can stat a path; the alias is the
// only identifier that reaches samples or capabilities.
func (c *collector) readFilesystem(p HostPolicy) groupResult {
	if len(p.Filesystems) == 0 {
		return failure(GroupFilesystem, c.fsMethod, StatusDenied, ReasonNoTarget)
	}
	var out groupResult
	for _, t := range p.Filesystems {
		st, err := c.statfs(t.Path)
		if err != nil {
			s, r := statusFor(err)
			out.caps = append(out.caps, Capability{Group: GroupFilesystem, Scope: t.Alias, Status: s, Reason: r, Method: c.fsMethod})
			continue
		}
		out.caps = append(out.caps, Capability{Group: GroupFilesystem, Scope: t.Alias, Status: StatusSupported, Method: c.fsMethod})
		out.samples = append(out.samples,
			sample("host_filesystem_bytes", "bytes", "gauge", float64(st.Size), "mount", t.Alias, "state", "size"),
			sample("host_filesystem_bytes", "bytes", "gauge", float64(st.Free), "mount", t.Alias, "state", "free"),
			sample("host_filesystem_bytes", "bytes", "gauge", float64(st.Avail), "mount", t.Alias, "state", "available"))
		if st.Files != 0 {
			out.samples = append(out.samples,
				sample("host_filesystem_inodes", "1", "gauge", float64(st.Files), "mount", t.Alias, "state", "total"),
				sample("host_filesystem_inodes", "1", "gauge", float64(st.FilesFree), "mount", t.Alias, "state", "free"))
		}
	}
	return out
}

// Records converts samples into float metric records with fresh identities.
func (b HostBatch) Records(res model.Resource) ([]model.Record, error) {
	out := make([]model.Record, 0, len(b.Samples))
	for _, s := range b.Samples {
		if s.Name == "" || s.Labels.Validate() != nil || math.IsNaN(s.Value) || math.IsInf(s.Value, 0) {
			return nil, model.Fail(model.Invalid)
		}
		bits := model.FloatBits(math.Float64bits(s.Value))
		out = append(out, model.Record{
			ID:         model.NewID(),
			Kind:       model.Metric,
			ObservedAt: b.At,
			Resource:   res,
			Payload: model.Payload{Metric: &model.MetricPoint{
				Name: s.Name, Labels: s.Labels, SampleKind: "float", Value: &bits, Unit: s.Unit, Type: s.Type,
			}},
		})
	}
	return out, nil
}

// Records emits one capability record per group. The wire capability has no
// group field, so its Method is "<group>:<method>" (for example
// "cpu:procfs_stat" or "cgroup:policy"): the group is part of the record. The wire capability has no
// scope, so a group with several filesystem scopes is reported as supported
// only when every scope is; otherwise the first non-supported scope speaks
// for the group.
func (c Capabilities) Records(res model.Resource, at model.UnixNano, ttl time.Duration, domain model.ClockDomain, build string) ([]model.Record, error) {
	if ttl <= 0 || build == "" {
		return nil, model.Fail(model.Invalid)
	}
	var out []model.Record
	for _, g := range AllGroups() {
		var rep *Capability
		for i := range c {
			if c[i].Group != g {
				continue
			}
			if rep == nil || rep.Status == StatusSupported && c[i].Status != StatusSupported {
				rep = &c[i]
			}
		}
		if rep == nil {
			continue
		}
		status, reason, complete := string(rep.Status), string(rep.Reason), "unknown"
		switch rep.Status {
		case StatusSupported:
			complete = "complete"
			if reason == "" {
				reason = "ok"
			}
		case StatusUnknown:
			status = "error"
		}
		if reason == "" {
			reason = "unknown"
		}
		out = append(out, model.Record{
			ID:         model.NewID(),
			Kind:       model.CapabilityKind,
			ObservedAt: at,
			Resource:   res,
			Payload: model.Payload{Capability: &model.Capability{
				Runtime: "soundpost-agent", Version: "1", Build: build,
				OS: runtime.GOOS, Arch: runtime.GOARCH,
				Signal: model.Metric, Method: string(g) + ":" + rep.Method, Status: status, Reason: reason,
				Coverage: model.Coverage{Frames: complete, Threads: complete, Workers: complete, Tasks: complete},
				Clock:    domain,
				Expires:  at + model.UnixNano(ttl),
			}},
		})
	}
	return out, nil
}

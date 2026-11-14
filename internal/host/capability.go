// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package host collects policy-bound CPU, memory, load, filesystem,
// process-count and cgroup metrics from OS primitives. It never reads command
// lines, environments, process names or paths with identities.
package host

// Group is one independently allowed collection group.
type Group string

const (
	GroupCPU          Group = "cpu"
	GroupMemory       Group = "memory"
	GroupLoad         Group = "load"
	GroupFilesystem   Group = "filesystem"
	GroupProcessCount Group = "process_count"
	GroupCgroup       Group = "cgroup"
)

// AllGroups returns every group in the fixed reporting order.
func AllGroups() []Group {
	return []Group{GroupCPU, GroupMemory, GroupLoad, GroupFilesystem, GroupProcessCount, GroupCgroup}
}

// Status is the observed state of one group (or filesystem scope).
type Status string

const (
	StatusSupported   Status = "supported"
	StatusUnsupported Status = "unsupported"
	StatusDenied      Status = "denied"
	StatusUnknown     Status = "unknown"
)

// Reason is a closed lowercase vocabulary compatible with the model's safe codes.
type Reason string

const (
	ReasonNone              Reason = ""
	ReasonPolicy            Reason = "policy"
	ReasonPermission        Reason = "permission_denied"
	ReasonNotPresent        Reason = "not_present"
	ReasonReadFailed        Reason = "read_failed"
	ReasonParseFailed       Reason = "parse_failed"
	ReasonOSUnsupported     Reason = "os_unsupported"
	ReasonCgroupV2Required  Reason = "cgroup_v2_required"
	ReasonProcessVisibility Reason = "process_visibility_restricted"
	ReasonNoTarget          Reason = "no_target_configured"
	ReasonCancelled         Reason = "cancelled"
	ReasonRequiresCgo       Reason = "requires_cgo"
)

// Capability reports what one group (or one filesystem alias) can deliver.
type Capability struct {
	Group  Group
	Scope  string // filesystem alias; "" otherwise
	Status Status
	Reason Reason
	Method string
}

// Capabilities is ordered by AllGroups(), filesystem scopes in policy order.
type Capabilities []Capability

// Find returns the capability for a group and scope.
func (c Capabilities) Find(g Group, scope string) (Capability, bool) {
	for _, x := range c {
		if x.Group == g && x.Scope == scope {
			return x, true
		}
	}
	return Capability{}, false
}

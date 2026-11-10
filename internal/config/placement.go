// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path"
	"strings"

	"soundpost/internal/appcore"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

// validatePlacement rejects every way three nodes can silently be fewer than three: a shared
// member identity, volume, disk device, failure-domain attestation, listener or data tree, a
// missing or surplus voter, or a replication factor the engine does not implement. The final
// call is the engine's own replica.ValidateMembers, so this check can only be stricter than
// startup, never looser.
func validatePlacement(c InstallConfig) error {
	ids := map[uint64]bool{}
	names := map[string]bool{}
	domains := map[string]bool{}
	addresses := map[string]bool{}
	devices := map[string]bool{}
	volumes := map[string]bool{}
	for i, n := range c.Nodes {
		field := fmt.Sprintf("nodes[%d]", i)
		switch {
		case n.ID == 0 || ids[n.ID]:
			return invalid(field+".id", "must_be_nonzero_and_unique")
		case !identityName.MatchString(n.Identity) || names[n.Identity]:
			return invalid(field+".identity", "must_be_a_unique_dns_label")
		case n.FailureDomain == "" || domains[n.FailureDomain]:
			return invalid(field+".failure_domain", "must_be_set_and_unique_per_voter")
		}
		ids[n.ID], names[n.Identity], domains[n.FailureDomain] = true, true, true
		address, err := url.Parse(n.PeerAddress.Reveal())
		if err != nil || address.Scheme != "https" || address.Host == "" || address.User != nil || address.RawQuery != "" || address.Fragment != "" || address.Path != "" && address.Path != "/" || addresses[address.Host] {
			return invalid(field+".peer_address", "must_be_a_unique_https_host_port")
		}
		addresses[address.Host] = true
		if _, port, err := net.SplitHostPort(n.PeerListen); err != nil || port == "" {
			return invalid(field+".peer_listen", "must_be_host_port")
		}
		if n.Disk.ID == "" || devices[n.Disk.ID] {
			return invalid(field+".disk.id", "must_be_set_and_unique")
		}
		if n.Disk.Volume == "" || volumes[n.Disk.Volume] {
			return invalid(field+".disk.volume", "must_be_set_and_unique")
		}
		devices[n.Disk.ID], volumes[n.Disk.Volume] = true, true
		if !path.IsAbs(n.Disk.Path) || path.Clean(n.Disk.Path) != n.Disk.Path {
			return invalid(field+".disk.path", "must_be_a_clean_absolute_path")
		}
		if n.Disk.CapacityBytes == 0 {
			return invalid(field+".disk.capacity_bytes", "must_be_positive")
		}
		for j := range i {
			if nested(c.Nodes[j].Disk.Path, n.Disk.Path) {
				return invalid(field+".disk.path", "data_trees_must_not_contain_each_other")
			}
		}
	}
	if c.Mode != ModeDistributed {
		return nil
	}
	if len(c.Nodes) != ReplicationFactor {
		return invalid("nodes", "distributed_needs_exactly_three_voters")
	}
	for i, n := range c.Nodes {
		if n.Learner {
			return invalid(fmt.Sprintf("nodes[%d].learner", i), "initial_members_are_voters")
		}
	}
	return replica.ValidateMembers(members(c))
}

// nested reports whether exactly one of two different paths contains the other. Equal paths
// are legitimate: every container sees its own volume at the same mount point.
func nested(a, b string) bool {
	return a != b && (strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/"))
}

// validateTrust requires mTLS trust material: a CA, one certificate and one private key per
// member (never shared), a seed, and a bootstrap leader that is a voter.
func validateTrust(c InstallConfig) error {
	if c.Mode != ModeDistributed {
		return nil
	}
	if !path.IsAbs(c.Cluster.CA) {
		return invalid("cluster.ca", "must_be_an_absolute_path")
	}
	if _, ok := c.Cluster.Seed.FilePath(); !ok {
		return invalid("cluster.seed", "must_be_a_file_reference")
	}
	if c.Cluster.Revision == 0 {
		return invalid("cluster.members_revision", "must_be_positive")
	}
	leader := false
	certificates := map[string]bool{}
	keys := map[string]bool{}
	for i, n := range c.Nodes {
		field := fmt.Sprintf("nodes[%d]", i)
		if !path.IsAbs(n.Certificate) || certificates[n.Certificate] {
			return invalid(field+".certificate", "must_be_an_absolute_path_unique_per_member")
		}
		certificates[n.Certificate] = true
		key, ok := n.PrivateKey.FilePath()
		if !ok || keys[key] {
			return invalid(field+".private_key", "must_be_a_file_reference_unique_per_member")
		}
		keys[key] = true
		leader = leader || n.ID == c.Cluster.InitialLeader && !n.Learner
	}
	if !leader {
		return invalid("cluster.initial_leader", "must_be_a_voter")
	}
	return nil
}

// members is the replica membership the validated configuration describes.
func members(c InstallConfig) replica.Members {
	m := replica.Members{Revision: model.Revision(c.Cluster.Revision)}
	for _, n := range c.Nodes {
		m.Nodes = append(m.Nodes, replica.Member{ID: n.ID, Address: n.PeerAddress.Reveal(), NodeIdentity: n.Identity, FailureDomain: n.FailureDomain, Learner: n.Learner})
	}
	return m
}

// NodeConfigs returns, per raft node id, the JSON file `soundpost serve --mode distributed
// --cluster-config` reads for that node. It marshals appcore.NodeConfig itself, so the schema
// cannot drift from the loader, and it refuses any configuration Validate refuses.
func NodeConfigs(c InstallConfig) (map[uint64][]byte, error) {
	if c.Mode != ModeDistributed {
		return nil, invalid("mode", "node_files_exist_only_for_distributed")
	}
	if err := Validate(c); err != nil {
		return nil, err
	}
	seed, _ := c.Cluster.Seed.FilePath()
	out := make(map[uint64][]byte, len(c.Nodes))
	for _, n := range c.Nodes {
		key, _ := n.PrivateKey.FilePath()
		raw, err := json.MarshalIndent(appcore.NodeConfig{
			NodeID: n.ID, PeerListen: n.PeerListen, Certificate: n.Certificate, PrivateKey: key,
			CA: c.Cluster.CA, Seed: seed, Members: members(c), InitialLeader: c.Cluster.InitialLeader,
		}, "", "  ")
		if err != nil {
			return nil, err
		}
		out[n.ID] = append(raw, '\n')
	}
	return out, nil
}

// Qualification states what a configuration does and does not prove about failure domains.
func Qualification(c InstallConfig) string {
	switch {
	case c.Mode == ModeSingle:
		return "single voter: not highly available; a host or disk loss is a restore from backup"
	case c.Cluster.Placement == PlacementSimulated:
		return "simulated placement: distinct volumes or directories on shared hardware are process and disk simulations, not three physical failure domains"
	default:
		return "operator-attested physical placement: independent hosts, storage, power and network are asserted by the operator and not verified here"
	}
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package config is the typed installation configuration. It does not invent a second
// cluster description: for a distributed installation it GENERATES the exact per-node JSON
// that `soundpost serve --mode distributed --cluster-config` reads (appcore.NodeConfig, with
// replica.Members) and it validates placement with the same replica.ValidateMembers the
// engine runs at startup, plus the checks an operator needs before the engine is started
// (shared identity, shared volume, shared failure domain, missing voter, trust material and
// the C12 restore-authority capabilities of an off-host backup).
//
// Nothing here reads a secret. Secrets are named by SecretRef and are redacted by every
// formatter, encoder and slog value this package provides.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Mode is the installation shape.
type Mode string

const (
	// ModeSingle is one voter. It is not highly available.
	ModeSingle Mode = "single"
	// ModeDistributed is exactly three voters (replication factor 3).
	ModeDistributed Mode = "distributed"
)

// Placement says what the operator attests about the failure domains of the nodes.
type Placement string

const (
	// PlacementSimulated marks process/disk simulations on one host (Compose volumes, three
	// directories). They are not three physical failure domains.
	PlacementSimulated Placement = "simulated"
	// PlacementPhysical is an operator attestation of independent hosts and storage. It is
	// not verified by this package.
	PlacementPhysical Placement = "physical"
)

// ReplicationFactor is the number of voters the distributed engine implements: replica
// accepts one or three voters, and appcore.OpenDistributed requires at least three nodes.
const ReplicationFactor = 3

// InstallConfig is the typed installation file.
type InstallConfig struct {
	Mode              Mode             `yaml:"mode"`
	ReplicationFactor int              `yaml:"replication_factor"`
	Cluster           Cluster          `yaml:"cluster"`
	Nodes             []Node           `yaml:"nodes"`
	Listen            Listen           `yaml:"listen"`
	Sources           []SourcePolicy   `yaml:"sources"`
	Quotas            Quotas           `yaml:"quotas"`
	Retention         Retention        `yaml:"retention"`
	Backup            Backup           `yaml:"backup"`
	CollectorGrants   []CollectorGrant `yaml:"collector_grants,omitempty"`
}

// Cluster carries the trust material and bootstrap choices of a distributed installation.
type Cluster struct {
	Placement     Placement `yaml:"placement"`
	CA            string    `yaml:"ca"`             // path of the cluster CA certificate (public)
	Seed          SecretRef `yaml:"seed"`           // file: reference to the installation seed
	InitialLeader uint64    `yaml:"initial_leader"` // node id of an initial voter
	Revision      uint64    `yaml:"members_revision"`
}

// Node is one member.
type Node struct {
	ID            uint64    `yaml:"id"`
	Identity      string    `yaml:"identity"`       // durable member identity; cert URI spiffe://soundpost/node/<identity>
	FailureDomain string    `yaml:"failure_domain"` // operator-attested domain
	Learner       bool      `yaml:"learner,omitempty"`
	PeerAddress   Endpoint  `yaml:"peer_address"` // https URL other members dial
	PeerListen    string    `yaml:"peer_listen"`  // host:port the member binds
	Disk          Disk      `yaml:"disk"`
	Certificate   string    `yaml:"certificate"`
	PrivateKey    SecretRef `yaml:"private_key"` // file: reference
}

// Disk names the durable volume of a member.
type Disk struct {
	ID            string `yaml:"id"`     // attested device identity
	Volume        string `yaml:"volume"` // named volume / PVC / directory
	Path          string `yaml:"path"`   // mount path inside the member
	CapacityBytes uint64 `yaml:"capacity_bytes"`
}

// Listen is the public HTTPS surface.
type Listen struct {
	Address       string   `yaml:"address"`
	PublicOrigins []string `yaml:"public_origins"`
}

// SourcePolicy declares one class of telemetry source.
type SourcePolicy struct {
	ID      string   `yaml:"id"`
	Class   string   `yaml:"class"` // private | browser
	Origins []string `yaml:"origins,omitempty"`
}

// Quotas bound every source.
type Quotas struct {
	MaxBytesPerSource  uint64 `yaml:"max_bytes_per_source"`
	MaxSeriesPerSource uint64 `yaml:"max_series_per_source"`
}

// Retention is days per signal kind (model.Kind names).
type Retention struct {
	Days map[string]uint32 `yaml:"days"`
}

// CollectorGrant lets a named collector write to one declared source policy.
type CollectorGrant struct {
	Collector string   `yaml:"collector"`
	Source    string   `yaml:"source"`
	Kinds     []string `yaml:"kinds"`
}

// BackupMode is where a backup goes.
type BackupMode string

const (
	BackupNone    BackupMode = "none"
	BackupLocal   BackupMode = "local"
	BackupOffhost BackupMode = "offhost"
)

// Backup is the backup and C12 restore-authority declaration.
type Backup struct {
	Mode          BackupMode  `yaml:"mode"`
	Local         LocalBackup `yaml:"local,omitempty"`
	Destination   Store       `yaml:"destination,omitempty"`
	Authority     Authority   `yaml:"authority,omitempty"`
	DataKEKID     string      `yaml:"data_kek_id,omitempty"`
	SecretKEKID   string      `yaml:"secret_kek_id,omitempty"`
	RetentionDays uint32      `yaml:"retention_days,omitempty"`
}

// LocalBackup is a recovery copy beside the installation. It never carries the deletion authority.
type LocalBackup struct {
	Dir string `yaml:"dir"`
}

// Store is an object destination: an HTTPS S3-compatible bucket, or a directory on a device
// attested to be different from every node disk.
type Store struct {
	Kind      string    `yaml:"kind"` // s3 | dir
	Endpoint  Endpoint  `yaml:"endpoint,omitempty"`
	Bucket    string    `yaml:"bucket,omitempty"`
	Prefix    string    `yaml:"prefix,omitempty"`
	AccessKey SecretRef `yaml:"access_key,omitempty"`
	SecretKey SecretRef `yaml:"secret_key,omitempty"`
	Path      string    `yaml:"path,omitempty"`
	DeviceID  string    `yaml:"device_id,omitempty"`
}

// Authority is the C12 restore authority: a journal on a Destination that is not the data
// volume and not the backup destination, with its own keys.
type Authority struct {
	Store          Store        `yaml:"store"`
	Keys           SecretRef    `yaml:"keys"`            // full keys, only on SigningNode
	RestrictedKeys SecretRef    `yaml:"restricted_keys"` // read/verify only, for the restore operator
	SigningNode    string       `yaml:"signing_node"`    // node identity that checkpoints deletions
	ID             string       `yaml:"id,omitempty"`    // expected authority id once initialised
	Capabilities   Capabilities `yaml:"capabilities"`
}

// Capabilities are the operator's statement of what the authority store provides; they are
// necessary but never sufficient: readiness additionally proves them with a probe.
type Capabilities struct {
	ConditionalCreate bool `yaml:"conditional_create"` // create-if-absent (If-None-Match: *)
	FreshHead         bool `yaml:"fresh_head"`         // strong read-after-write/list consistency
	RestrictedRestore bool `yaml:"restricted_restore"` // restore uses read-only keys
}

// Parse reads one strict YAML document (unknown fields and extra documents are errors).
func Parse(raw []byte) (InstallConfig, error) {
	var c InstallConfig
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return InstallConfig{}, &ValidationError{Field: "document", Rule: "not_valid_installconfig_yaml"}
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		return InstallConfig{}, &ValidationError{Field: "document", Rule: "more_than_one_document"}
	}
	return c, nil
}

// ValidationError names the field and the rule. It never carries the offending value: values
// may be credentials.
type ValidationError struct{ Field, Rule string }

func (e *ValidationError) Error() string { return "config: " + e.Field + ": " + e.Rule }

// Validate checks everything that can be decided without contacting an authority store.
// It returns the first violation in a fixed order so the message is stable.
func Validate(c InstallConfig) error {
	var checks = []func(InstallConfig) error{validateShape, validatePlacement, validateTrust, validatePublic, validateSources, validateBackup}
	for _, check := range checks {
		if err := check(c); err != nil {
			return err
		}
	}
	return nil
}

func invalid(field, rule string) error { return &ValidationError{Field: field, Rule: rule} }

var (
	identityName   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	sourceID       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	kekID          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	retentionKinds = map[string]bool{"metric": true, "log": true, "span": true, "error": true, "job_attempt": true, "replay_chunk": true, "profile_chunk": true}
)

func validateShape(c InstallConfig) error {
	switch c.Mode {
	case ModeSingle:
		if c.ReplicationFactor != 1 {
			return invalid("replication_factor", "single_mode_is_exactly_one")
		}
		if len(c.Nodes) != 1 || c.Nodes[0].Learner {
			return invalid("nodes", "single_mode_needs_exactly_one_voter")
		}
	case ModeDistributed:
		if c.ReplicationFactor != ReplicationFactor {
			return invalid("replication_factor", "must_be_3")
		}
		if c.Cluster.Placement != PlacementSimulated && c.Cluster.Placement != PlacementPhysical {
			return invalid("cluster.placement", "must_be_simulated_or_physical")
		}
	default:
		return invalid("mode", "must_be_single_or_distributed")
	}
	return nil
}

func validatePublic(c InstallConfig) error {
	if _, _, err := net.SplitHostPort(c.Listen.Address); err != nil {
		return invalid("listen.address", "must_be_host_port")
	}
	if len(c.Listen.PublicOrigins) == 0 {
		return invalid("listen.public_origins", "at_least_one_origin_required")
	}
	for i, o := range c.Listen.PublicOrigins {
		if !exactHTTPSOrigin(o) {
			return invalid(fmt.Sprintf("listen.public_origins[%d]", i), "must_be_an_exact_https_origin")
		}
	}
	return nil
}

// exactHTTPSOrigin accepts scheme://host[:port] and nothing else: no wildcard, userinfo,
// path, query or fragment.
func exactHTTPSOrigin(o string) bool {
	u, err := url.Parse(o)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && !strings.ContainsAny(u.Host, "*") && u.Opaque == ""
}

func validateSources(c InstallConfig) error {
	seen := map[string]bool{}
	for i, s := range c.Sources {
		field := fmt.Sprintf("sources[%d]", i)
		if !sourceID.MatchString(s.ID) || seen[s.ID] {
			return invalid(field+".id", "must_be_unique_and_well_formed")
		}
		seen[s.ID] = true
		switch s.Class {
		case "private":
			if len(s.Origins) != 0 {
				return invalid(field+".origins", "private_source_has_no_browser_origin")
			}
		case "browser":
			if len(s.Origins) == 0 {
				return invalid(field+".origins", "browser_source_needs_exact_origins")
			}
			for j, o := range s.Origins {
				if !exactHTTPSOrigin(o) {
					return invalid(fmt.Sprintf("%s.origins[%d]", field, j), "must_be_an_exact_https_origin")
				}
			}
		default:
			return invalid(field+".class", "must_be_private_or_browser")
		}
	}
	if c.Quotas.MaxBytesPerSource == 0 || c.Quotas.MaxSeriesPerSource == 0 {
		return invalid("quotas", "limits_must_be_positive")
	}
	if len(c.Retention.Days) == 0 {
		return invalid("retention.days", "at_least_one_signal_required")
	}
	kinds := make([]string, 0, len(c.Retention.Days))
	for k := range c.Retention.Days {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		if !retentionKinds[k] || c.Retention.Days[k] == 0 || c.Retention.Days[k] > 3650 {
			return invalid("retention.days."+sanitizeKey(k), "unknown_signal_or_days_outside_1_to_3650")
		}
	}
	for i, g := range c.CollectorGrants {
		field := fmt.Sprintf("collector_grants[%d]", i)
		if !sourceID.MatchString(g.Collector) || !seen[g.Source] || len(g.Kinds) == 0 {
			return invalid(field, "needs_a_collector_a_declared_source_and_kinds")
		}
		for _, k := range g.Kinds {
			if !retentionKinds[k] {
				return invalid(field+".kinds", "unknown_signal")
			}
		}
	}
	return nil
}

// sanitizeKey keeps a map key out of an error message unless it is a plain token.
func sanitizeKey(k string) string {
	if sourceID.MatchString(k) || identityName.MatchString(k) {
		return k
	}
	return "?"
}

// ---- redaction ----

// Endpoint is a URL whose userinfo and query never appear in any encoded or formatted form.
type Endpoint string

func (e Endpoint) redacted() string {
	u, err := url.Parse(string(e))
	if err != nil || u.Host == "" {
		if e == "" {
			return ""
		}
		return "[redacted]"
	}
	return u.Scheme + "://" + u.Host + u.EscapedPath()
}

func (e Endpoint) String() string               { return e.redacted() }
func (e Endpoint) GoString() string             { return fmt.Sprintf("%q", e.redacted()) }
func (e Endpoint) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, e.redacted()) }
func (e Endpoint) MarshalText() ([]byte, error) { return []byte(e.redacted()), nil }
func (e Endpoint) MarshalJSON() ([]byte, error) { return []byte(fmt.Sprintf("%q", e.redacted())), nil }
func (e Endpoint) MarshalYAML() (any, error)    { return e.redacted(), nil }
func (e Endpoint) LogValue() slog.Value         { return slog.StringValue(e.redacted()) }
func (e *Endpoint) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	*e = Endpoint(s)
	return nil
}

// Reveal returns the endpoint exactly as configured (for dialing only; never log it).
func (e Endpoint) Reveal() string { return string(e) }

// SecretRef names a secret (env:NAME, file:/absolute/path or k8s:secret/key). The reference,
// not just the secret, is treated as sensitive: it is redacted everywhere.
type SecretRef struct{ ref string }

// NewSecretRef wraps a reference string.
func NewSecretRef(ref string) SecretRef { return SecretRef{ref: ref} }

const redactedText = "[redacted]"

func (r SecretRef) String() string               { return redactedText }
func (r SecretRef) GoString() string             { return `config.SecretRef("` + redactedText + `")` }
func (r SecretRef) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, redactedText) }
func (r SecretRef) MarshalText() ([]byte, error) { return []byte(redactedText), nil }
func (r SecretRef) MarshalJSON() ([]byte, error) { return []byte(`"` + redactedText + `"`), nil }
func (r SecretRef) MarshalYAML() (any, error) {
	if r.ref == "" {
		return "", nil
	}
	return redactedText, nil
}
func (r SecretRef) LogValue() slog.Value { return slog.StringValue(redactedText) }
func (r *SecretRef) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	r.ref = s
	return nil
}

// IsSet reports whether a reference was configured.
func (r SecretRef) IsSet() bool { return r.ref != "" }

// Reveal returns the reference text; callers resolve it and must never log it.
func (r SecretRef) Reveal() string { return r.ref }

var (
	envRefName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
	k8sRefName = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?/[A-Za-z0-9._-]{1,253}$`)
)

// valid reports whether the reference has one of the three shapes. A raw credential pasted
// where a reference belongs has none of them.
func (r SecretRef) valid() bool {
	scheme, target, ok := strings.Cut(r.ref, ":")
	if !ok {
		return false
	}
	switch scheme {
	case "env":
		return envRefName.MatchString(target)
	case "file":
		return strings.HasPrefix(target, "/") && !strings.Contains(target, "..") && !strings.ContainsAny(target, "\x00\n")
	case "k8s":
		return k8sRefName.MatchString(target)
	}
	return false
}

// FilePath returns the path of a file: reference.
func (r SecretRef) FilePath() (string, bool) {
	target, ok := strings.CutPrefix(r.ref, "file:")
	return target, ok && r.valid()
}

// Summary is the safe, loggable view of an installation.
func (c InstallConfig) Summary() string {
	identities := make([]string, 0, len(c.Nodes))
	for _, n := range c.Nodes {
		identities = append(identities, n.Identity)
	}
	return fmt.Sprintf("mode=%s rf=%d placement=%s nodes=%s backup=%s", c.Mode, c.ReplicationFactor, c.Cluster.Placement, strings.Join(identities, ","), c.Backup.Mode)
}

// Format prints the summary for every verb: %v, %+v and %#v of a whole configuration can
// never print a credential.
func (c InstallConfig) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.Summary()) }

// LogValue implements slog.LogValuer.
func (c InstallConfig) LogValue() slog.Value { return slog.StringValue(c.Summary()) }

// Marshal returns redacted YAML (secret references and URL credentials are replaced).
func (c InstallConfig) Marshal() ([]byte, error) { return yaml.Marshal(c) }

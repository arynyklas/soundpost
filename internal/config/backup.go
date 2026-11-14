// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"errors"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/backup"
)

// BackupLabel is the only honest name of what a configured backup is. A copy on the
// installation's own host, or any off-host copy whose deletion authority has not been proven
// right now, is never a deletion-safe disaster backup: restoring it can resurrect data whose
// deletion was already acknowledged (docs/operations/backup-restore.md).
type BackupLabel string

const (
	LabelNone                       BackupLabel = "none"
	LabelLocalRecoveryCopy          BackupLabel = "local-recovery-copy"
	LabelDeletionSafeDisasterBackup BackupLabel = "deletion-safe-disaster-backup"
)

// Reason is a closed set; it never carries an error text (store errors can name endpoints).
type Reason string

const (
	ReasonInvalidConfig           Reason = "invalid_config"
	ReasonConditionalCreateFailed Reason = "conditional_create_failed"
	ReasonHeadUnavailable         Reason = "head_unavailable"
	ReasonHeadStale               Reason = "head_stale"
	ReasonForeignAuthority        Reason = "foreign_authority"
	ReasonAuthorityRolledBack     Reason = "authority_rolled_back"
)

// ErrNotReady matches every NotReadyError.
var ErrNotReady = errors.New("config: backup authority not ready")

// NotReadyError says why an off-host backup may not be used or labelled.
type NotReadyError struct{ Reason Reason }

func (e *NotReadyError) Error() string {
	return "config: backup authority not ready: " + string(e.Reason)
}
func (e *NotReadyError) Is(t error) bool { return t == ErrNotReady }

func notReady(r Reason) error { return &NotReadyError{Reason: r} }

// AuthorityHead is one verified position of the C12 restore authority's journal.
type AuthorityHead struct {
	Authority  string
	Sequence   uint64
	Generation uint64
	Digest     string
	// ReadAt is when this verified read happened. A head observed earlier and cached must
	// carry its earlier time; it is then too old to be a fresh head.
	ReadAt time.Time
}

// AuthorityProbe is the narrow view of internal/backup the readiness decision needs.
// NewBackupProbe adapts the real package; tests and the smoke supply real or fake stores.
type AuthorityProbe interface {
	// VerifyConditionalCreate proves create-if-absent semantics on the authority store:
	// the first create succeeds, a second create of the same name is refused, and the first
	// bytes read back. A last-writer-wins store fails here.
	VerifyConditionalCreate(ctx context.Context) error
	// CurrentHead performs one fresh, fully verified read of the journal and returns its head.
	CurrentHead(ctx context.Context) (AuthorityHead, error)
}

// NewBackupProbe adapts the real authority of internal/backup (without editing it).
func NewBackupProbe(dest backup.Destination, keys backup.AuthorityKeys, now func() time.Time) (AuthorityProbe, error) {
	authority, err := backup.NewAuthority(dest, keys, now)
	if err != nil {
		return nil, err
	}
	return &backupProbe{dest: dest, authority: authority, now: now}, nil
}

type backupProbe struct {
	dest      backup.Destination
	authority *backup.Authority
	now       func() time.Time
}

func (p *backupProbe) VerifyConditionalCreate(ctx context.Context) error {
	return backup.VerifyConditionalCreate(ctx, p.dest)
}

func (p *backupProbe) CurrentHead(ctx context.Context) (AuthorityHead, error) {
	current, err := p.authority.Current(ctx)
	if err != nil {
		return AuthorityHead{}, err
	}
	h := current.Head
	return AuthorityHead{Authority: h.Authority.String(), Sequence: h.Sequence, Generation: h.Generation, Digest: h.Digest.String(), ReadAt: p.now()}, nil
}

// BackupStatus is the outcome of Check: the label an operator may show, and the head it rests on.
type BackupStatus struct {
	Label BackupLabel
	Head  AuthorityHead
}

// BackupChecker decides whether the configured backup may be used and what it may be called.
// It remembers the highest authority sequence it has seen so a rolled-back journal is caught.
type BackupChecker struct {
	Probe      AuthorityProbe
	Now        func() time.Time
	MaxHeadAge time.Duration // default one minute

	mu    sync.Mutex
	floor uint64
}

const defaultHeadAge = time.Minute

// futureSkew is how far ahead of the local clock a head's read time may be.
const futureSkew = 5 * time.Second

// Check never returns the deletion-safe label unless the configuration is complete AND the
// authority store proves conditional create AND a fresh verified head names the expected
// authority at or above every sequence seen before. Every other off-host outcome is a typed
// not-ready error; the local modes can only ever be labelled as what they are.
func (c *BackupChecker) Check(ctx context.Context, cfg InstallConfig) (BackupStatus, error) {
	if err := Validate(cfg); err != nil {
		return BackupStatus{Label: LabelNone}, notReady(ReasonInvalidConfig)
	}
	switch cfg.Backup.Mode {
	case BackupNone:
		return BackupStatus{Label: LabelNone}, nil
	case BackupLocal:
		return BackupStatus{Label: LabelLocalRecoveryCopy}, nil
	}
	if c.Probe == nil || c.Now == nil {
		return BackupStatus{Label: LabelNone}, notReady(ReasonConditionalCreateFailed)
	}
	if err := c.Probe.VerifyConditionalCreate(ctx); err != nil {
		return BackupStatus{Label: LabelNone}, notReady(ReasonConditionalCreateFailed)
	}
	head, err := c.Probe.CurrentHead(ctx)
	if err != nil || head.Authority == "" {
		return BackupStatus{Label: LabelNone}, notReady(ReasonHeadUnavailable)
	}
	limit := c.MaxHeadAge
	if limit <= 0 {
		limit = defaultHeadAge
	}
	if age := c.Now().Sub(head.ReadAt); age > limit || age < -futureSkew {
		return BackupStatus{Label: LabelNone}, notReady(ReasonHeadStale)
	}
	if want := cfg.Backup.Authority.ID; want != "" && want != head.Authority {
		return BackupStatus{Label: LabelNone}, notReady(ReasonForeignAuthority)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if head.Sequence < c.floor {
		return BackupStatus{Label: LabelNone}, notReady(ReasonAuthorityRolledBack)
	}
	c.floor = head.Sequence
	return BackupStatus{Label: LabelDeletionSafeDisasterBackup, Head: head}, nil
}

// maxBackupRetentionDays is the manifest lifetime backup.Config enforces.
const maxBackupRetentionDays = 30

func validateBackup(c InstallConfig) error {
	b := c.Backup
	switch b.Mode {
	case BackupNone:
		return nil
	case BackupLocal:
		if !path.IsAbs(b.Local.Dir) || path.Clean(b.Local.Dir) != b.Local.Dir {
			return invalid("backup.local.dir", "must_be_a_clean_absolute_path")
		}
		if b.RetentionDays > maxBackupRetentionDays {
			return invalid("backup.retention_days", "at_most_30")
		}
		return nil
	case BackupOffhost:
	default:
		return invalid("backup.mode", "must_be_none_local_or_offhost")
	}

	if err := validateStore("backup.destination", b.Destination, c); err != nil {
		return err
	}
	a := b.Authority
	if err := validateStore("backup.authority.store", a.Store, c); err != nil {
		return err
	}
	if sameStore(b.Destination, a.Store) {
		return invalid("backup.authority.store", "must_not_be_the_backup_destination")
	}
	if a.Store.Kind == "s3" {
		if a.Store.AccessKey.Reveal() == b.Destination.AccessKey.Reveal() {
			return invalid("backup.authority.store.access_key", "must_not_share_credentials_with_the_backup_destination")
		}
		if a.Store.SecretKey.Reveal() == b.Destination.SecretKey.Reveal() {
			return invalid("backup.authority.store.secret_key", "must_not_share_credentials_with_the_backup_destination")
		}
	}
	if !a.Keys.valid() {
		return invalid("backup.authority.keys", "must_be_a_secret_reference")
	}
	if !a.RestrictedKeys.valid() || a.RestrictedKeys.Reveal() == a.Keys.Reveal() {
		return invalid("backup.authority.restricted_keys", "must_be_a_separate_secret_reference")
	}
	signer := false
	for _, n := range c.Nodes {
		signer = signer || n.Identity == a.SigningNode
	}
	if !signer {
		return invalid("backup.authority.signing_node", "must_be_a_member_identity")
	}
	if !a.Capabilities.ConditionalCreate {
		return invalid("backup.authority.capabilities.conditional_create", "must_be_declared")
	}
	if !a.Capabilities.FreshHead {
		return invalid("backup.authority.capabilities.fresh_head", "must_be_declared")
	}
	if !a.Capabilities.RestrictedRestore {
		return invalid("backup.authority.capabilities.restricted_restore", "must_be_declared")
	}
	if !kekID.MatchString(b.DataKEKID) {
		return invalid("backup.data_kek_id", "must_be_an_identifier")
	}
	if !kekID.MatchString(b.SecretKEKID) || b.SecretKEKID == b.DataKEKID {
		return invalid("backup.secret_kek_id", "must_be_an_identifier_different_from_the_data_kek")
	}
	if b.RetentionDays == 0 || b.RetentionDays > maxBackupRetentionDays {
		return invalid("backup.retention_days", "between_1_and_30")
	}
	return nil
}

// validateStore checks an off-host destination: an HTTPS S3-compatible bucket with its own
// credential references, or a directory on a device attested to differ from every node disk.
func validateStore(field string, s Store, c InstallConfig) error {
	switch s.Kind {
	case "s3":
		u, err := url.Parse(s.Endpoint.Reveal())
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
			return invalid(field+".endpoint", "must_be_an_https_endpoint_without_credentials")
		}
		if s.Bucket == "" || strings.ContainsAny(s.Bucket, "/\\ ") {
			return invalid(field+".bucket", "must_be_a_bucket_name")
		}
		if s.Prefix != "" && (strings.HasPrefix(s.Prefix, "/") || strings.Contains(s.Prefix, "..") || strings.Contains(s.Prefix, "\\")) {
			return invalid(field+".prefix", "must_be_a_relative_prefix")
		}
		if !s.AccessKey.valid() {
			return invalid(field+".access_key", "must_be_a_secret_reference")
		}
		if !s.SecretKey.valid() {
			return invalid(field+".secret_key", "must_be_a_secret_reference")
		}
	case "dir":
		if s.DeviceID == "" {
			return invalid(field+".device_id", "must_name_the_backing_device")
		}
		for _, n := range c.Nodes {
			if n.Disk.ID == s.DeviceID {
				return invalid(field+".device_id", "must_differ_from_every_node_disk")
			}
		}
		if !path.IsAbs(s.Path) || path.Clean(s.Path) != s.Path {
			return invalid(field+".path", "must_be_a_clean_absolute_path")
		}
		for _, n := range c.Nodes {
			if s.Path == n.Disk.Path || strings.HasPrefix(s.Path, n.Disk.Path+"/") || strings.HasPrefix(n.Disk.Path, s.Path+"/") {
				return invalid(field+".path", "must_not_overlap_a_node_data_path")
			}
		}
	default:
		return invalid(field+".kind", "must_be_s3_or_dir")
	}
	return nil
}

// sameStore reports whether two stores can be one failure domain: the same bucket (or nested
// prefixes of it) on one endpoint, the same or nested directory, or one backing device.
func sameStore(a, b Store) bool {
	if a.Kind != b.Kind {
		return false
	}
	if a.Kind == "dir" {
		return a.DeviceID == b.DeviceID || a.Path == b.Path || strings.HasPrefix(a.Path, b.Path+"/") || strings.HasPrefix(b.Path, a.Path+"/")
	}
	ua, errA := url.Parse(a.Endpoint.Reveal())
	ub, errB := url.Parse(b.Endpoint.Reveal())
	if errA != nil || errB != nil || !strings.EqualFold(ua.Host, ub.Host) || a.Bucket != b.Bucket {
		return false
	}
	pa, pb := strings.Trim(a.Prefix, "/"), strings.Trim(b.Prefix, "/")
	return pa == "" || pb == "" || pa == pb || strings.HasPrefix(pa, pb+"/") || strings.HasPrefix(pb, pa+"/")
}

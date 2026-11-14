// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/durablefs"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/retention"
	"github.com/arynyklas/soundpost/internal/storage"
)

// MaxRetention is the design's upper bound on backup lifetime (C12/§12).
const MaxRetention = 30 * 24 * time.Hour

// ---- narrow interfaces the backup service consumes ---------------------------------

// ControlSource is the control view a backup needs. *control.Store satisfies
// it. View is the linearizable (ReadIndex) fence; the cut C is derived only from
// the seed ReplicationSeed returns, so the control state stored in the backup and
// the cut handed to the data plane are one revision by construction.
type ControlSource interface {
	View(ctx context.Context, fn func(model.ControlState) error) error
	ReplicationSeed() ([]byte, uint64, error)
}

// PlaneSession is the in-progress pinned backup of the data groups.
type PlaneSession interface {
	Seal(ctx context.Context, gaps []storage.DeclaredGap) (storage.SealedBackup, error)
	Abort()
}

// DataPlane is what the backup needs from the data groups. EngineDataPlane
// adapts *storage.Engine.
type DataPlane interface {
	Applied() []model.Cursor // application cursor per data group, slot order
	Begin(ctx context.Context, cut storage.ControlCut) (PlaneSession, error)
}

type enginePlane struct{ e *storage.Engine }

// EngineDataPlane adapts the real storage engine.
func EngineDataPlane(e *storage.Engine) DataPlane { return enginePlane{e} }

func (p enginePlane) Applied() []model.Cursor {
	groups := p.e.ReplicaGroups()
	out := make([]model.Cursor, 0, len(groups))
	for _, g := range groups {
		s := g.Status()
		out = append(out, model.Cursor{Group: s.Group, Index: s.ApplicationCursor.Index})
	}
	return out
}

func (p enginePlane) Begin(ctx context.Context, cut storage.ControlCut) (PlaneSession, error) {
	b, err := p.e.BeginBackup(ctx, cut)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Processed reports the highest application index of a data group whose
// lifecycle evidence a projection has fully processed (the C12 highwater H).
type Processed interface {
	Processed(ctx context.Context, group model.ID) (uint64, error)
}

type appliedProcessed struct{ plane DataPlane }

// AppliedProcessed reports every group's current applied cursor as processed.
// It is correct only for a build that has no lifecycle projection (nothing
// consumes evidence, so nothing needs replaying after restore); an installation
// with projections must supply their real checkpoints instead.
func AppliedProcessed(p DataPlane) Processed { return appliedProcessed{p} }

func (a appliedProcessed) Processed(ctx context.Context, group model.ID) (uint64, error) {
	for _, c := range a.plane.Applied() {
		if c.Group == group {
			return uint64(c.Index), nil
		}
	}
	return 0, model.Fail(model.NotFound)
}

// InstanceAuthorizer re-validates the InstanceScope an installation-wide
// operation runs under. *auth.Service satisfies it.
type InstanceAuthorizer interface {
	RevalidateInstance(ctx context.Context, scope auth.Scope) error
}

// Pin is one durable journal pin as a PinReaper reports it.
type Pin struct {
	ID    string
	Group string
}

// PinReaper is the consumer-owned view of durable journal pins (IMP-1): a backup
// that died between BeginBackup and Seal/Abort leaves pins nothing else lists or
// drops. The parent adapts the replica group pin accessors to it.
//
// A Pin carries no owner, so Service.Reap cannot tell the pins of a dead attempt
// from those of a backup running now: when any attempt is incomplete it drops
// every pin Pins reports. Call Reap only before a backup of the installation
// can be in flight (process start; `backup create` opens the installation
// exclusively). Stamping the attempt ID into each pin and filtering Pins by it is
// what would make a scheduled in-process reap safe.
type PinReaper interface {
	Pins() ([]Pin, error)
	DropPin(id string) error
}

// Attempt is the durable marker of a backup that has begun.
type Attempt struct {
	ID              model.ID
	StartedAt       model.UnixNano
	ControlRevision model.Revision
}

// AttemptLog records attempts durably BEFORE BeginBackup, so a startup reaper
// can find the pins of an attempt that never completed.
type AttemptLog interface {
	Begin(ctx context.Context, a Attempt) error
	Finish(ctx context.Context, id model.ID, outcome string) error
	Incomplete(ctx context.Context) ([]Attempt, error)
}

// DirAttempts keeps attempt markers as fsynced files in a private directory.
type DirAttempts string

type attemptFile struct {
	ID              model.ID       `json:"id"`
	StartedAt       model.UnixNano `json:"started_at_ns"`
	ControlRevision model.Revision `json:"control_revision"`
}

func (d DirAttempts) Begin(ctx context.Context, a Attempt) error {
	if a.ID == (model.ID{}) {
		return model.Fail(model.Invalid)
	}
	if err := durablefs.MkdirAll(string(d)); err != nil {
		return err
	}
	raw, err := json.Marshal(attemptFile{a.ID, a.StartedAt, a.ControlRevision})
	if err != nil {
		return err
	}
	return durablefs.Exclusive(filepath.Join(string(d), a.ID.String()+".begin"), raw)
}

func (d DirAttempts) Finish(ctx context.Context, id model.ID, outcome string) error {
	switch outcome {
	case "completed", "aborted", "reaped":
	default:
		return model.Fail(model.Invalid)
	}
	if id == (model.ID{}) {
		return model.Fail(model.Invalid)
	}
	err := durablefs.Exclusive(filepath.Join(string(d), id.String()+".done"), []byte(outcome))
	if os.IsExist(err) {
		return nil
	}
	return err
}

func (d DirAttempts) Incomplete(ctx context.Context) ([]Attempt, error) {
	entries, err := os.ReadDir(string(d))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	done := map[string]bool{}
	for _, e := range entries {
		if name := e.Name(); filepath.Ext(name) == ".done" {
			done[name[:len(name)-len(".done")]] = true
		}
	}
	var out []Attempt
	for _, e := range entries {
		name := e.Name()
		if filepath.Ext(name) != ".begin" || done[name[:len(name)-len(".begin")]] {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(string(d), name))
		var f attemptFile
		if err != nil || json.Unmarshal(raw, &f) != nil || f.ID.String() != name[:len(name)-len(".begin")] {
			return nil, model.Fail(model.Corrupt)
		}
		out = append(out, Attempt{ID: f.ID, StartedAt: f.StartedAt, ControlRevision: f.ControlRevision})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt < out[j].StartedAt })
	return out, nil
}

// ---- backup service ---------------------------------------------------------------------

// SnapshotSet is a sealed, verified set ready to export: the control seed
// captured at C, the sealed data bundle with its 64 verified snapshots, the
// committed control facts that explain the bundle's gaps and the authority head
// the backup is bound to.
type SnapshotSet struct {
	ControlSeed []byte
	Sealed      storage.SealedBackup
	Gaps        []GapAttestation
	Authority   CurrentDeletion
	CreatedAt   time.Time
}

// Config wires a backup Service.
type Config struct {
	Control    ControlSource
	Data       DataPlane
	Processed  Processed
	Authority  DeletionLedger // required: backups without a verifiable deletion authority are refused
	Authorizer InstanceAuthorizer
	Keys       KeyProvider
	DataKEK    string // wraps the data key (snapshots, bundle, control state) and authenticates the manifest
	SecretKEK  string // wraps the key-material key (control envelope keys); must differ from DataKEK
	Attempts   AttemptLog
	Pins       PinReaper // optional; without it Reap cannot clean a dead attempt
	Clock      func() time.Time
	Retention  time.Duration // backup lifetime; default and maximum 30 days
}

// Service takes encrypted installation backups.
type Service struct {
	cfg     Config
	mu      sync.Mutex
	running bool
}

func New(cfg Config) (*Service, error) {
	if cfg.Control == nil || cfg.Data == nil || cfg.Processed == nil || cfg.Authority == nil || cfg.Authorizer == nil || cfg.Keys == nil || cfg.Attempts == nil {
		return nil, model.Fail(model.Invalid)
	}
	if !keyID.MatchString(cfg.DataKEK) || !keyID.MatchString(cfg.SecretKEK) || cfg.DataKEK == cfg.SecretKEK {
		return nil, model.Fail(model.Invalid)
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Retention <= 0 {
		cfg.Retention = MaxRetention
	}
	if cfg.Retention > MaxRetention {
		return nil, model.Fail(model.Invalid)
	}
	return &Service{cfg: cfg}, nil
}

// errRestart marks a seal that failed because privacy deletion touched pinned
// evidence: the backup restarts from a new cut.
var errRestart = errors.New("backup restarts after deletion")

// Run takes one complete backup of the installation into dest: control cut C and
// processed highwaters H, pinned post-H journal, sealed data cut D with
// replay-or-gap and reservation certificates, encrypted objects and the
// authenticated manifest (written last). It always seals or aborts: the pins are
// released on every path, including a panic. A privacy deletion that touches
// pinned evidence restarts the backup from a new cut.
func (s *Service) Run(ctx context.Context, scope auth.Scope, dest Destination) (BackupManifest, error) {
	if dest == nil {
		return BackupManifest{}, model.Fail(model.Invalid)
	}
	if err := s.cfg.Authorizer.RevalidateInstance(ctx, scope); err != nil {
		return BackupManifest{}, err
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return BackupManifest{}, model.Fail(model.Conflict)
	}
	s.running = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.running = false; s.mu.Unlock() }()
	for range 3 {
		m, err := s.once(ctx, scope, dest)
		if errors.Is(err, errRestart) {
			continue
		}
		return m, err
	}
	return BackupManifest{}, model.Fail(model.Conflict)
}

func parseSeed(raw []byte) (map[string]json.RawMessage, model.ControlState, error) {
	var parts map[string]json.RawMessage
	var st model.ControlState
	if json.Unmarshal(raw, &parts) != nil || len(parts) != 3 || parts["state"] == nil || parts["keys"] == nil || parts["metadata"] == nil || json.Unmarshal(parts["state"], &st) != nil || st.Installation == (model.ID{}) {
		return nil, model.ControlState{}, model.Fail(model.Corrupt)
	}
	return parts, st, nil
}

func (s *Service) once(ctx context.Context, scope auth.Scope, dest Destination) (manifest BackupManifest, err error) {
	started := s.cfg.Clock()
	if err = s.cfg.Control.View(ctx, func(model.ControlState) error { return nil }); err != nil {
		return BackupManifest{}, err
	}
	seed, revision, err := s.cfg.Control.ReplicationSeed()
	if err != nil {
		return BackupManifest{}, err
	}
	_, state, err := parseSeed(seed)
	if err != nil || uint64(state.Revision) != revision {
		return BackupManifest{}, model.Fail(model.Corrupt)
	}
	current, err := s.cfg.Authority.Current(ctx)
	if err != nil {
		return BackupManifest{}, model.Fail(model.Unavailable)
	}
	if err = checkAuthorityCoversControl(state, current); err != nil {
		return BackupManifest{}, err
	}
	applied := s.cfg.Data.Applied()
	if len(applied) != 64 {
		return BackupManifest{}, model.Fail(model.Unavailable)
	}
	groups := map[model.ID]bool{}
	cut := storage.ControlCut{Revision: state.Revision, Reservations: map[string]model.AdmissionReservation{}}
	for _, c := range applied {
		h, err := s.cfg.Processed.Processed(ctx, c.Group)
		if err != nil {
			return BackupManifest{}, err
		}
		groups[c.Group] = true
		cut.Processed = append(cut.Processed, model.Cursor{Group: c.Group, Index: model.Uint64(h)})
	}
	for id, r := range state.Reservations {
		cut.Reservations[id] = r
	}
	declared, facts, err := committedGaps(state, groups)
	if err != nil {
		return BackupManifest{}, err
	}
	attempt := Attempt{ID: model.NewID(), StartedAt: model.UnixNano(started.UnixNano()), ControlRevision: state.Revision}
	if err = s.cfg.Attempts.Begin(ctx, attempt); err != nil { // durable BEFORE BeginBackup
		return BackupManifest{}, err
	}
	success := false
	defer func() {
		outcome := "aborted" // also the outcome of a panic: the deferred Abort below ran
		if success {
			outcome = "completed"
		}
		_ = s.cfg.Attempts.Finish(context.WithoutCancel(ctx), attempt.ID, outcome)
	}()
	session, err := s.cfg.Data.Begin(ctx, cut)
	if err != nil {
		return BackupManifest{}, err
	}
	sealedOK := false
	defer func() {
		if !sealedOK {
			session.Abort() // Seal-or-Abort on every path, panics included
		}
	}()
	sealed, err := session.Seal(ctx, declared)
	if err != nil {
		var fault *model.Fault
		if errors.As(err, &fault) && fault.Code == model.Conflict {
			return BackupManifest{}, errRestart
		}
		return BackupManifest{}, err
	}
	sealedOK = true
	attested, err := attestations(sealed.Bundle.Replay.Intervals, facts, state.Revision)
	if err != nil {
		return BackupManifest{}, err
	}
	manifest, err = s.Backup(ctx, scope, SnapshotSet{ControlSeed: seed, Sealed: sealed, Gaps: attested, Authority: current, CreatedAt: started}, dest)
	success = err == nil
	return manifest, err
}

// checkAuthorityCoversControl proves the authority this backup will bind has not
// been rolled back or forked relative to what control already recorded: every
// completed deletion's authority receipt must be a record of the verified chain.
func checkAuthorityCoversControl(st model.ControlState, cur CurrentDeletion) error {
	if cur.Installation != st.Installation {
		return model.Fail(model.Conflict)
	}
	chain := make(map[model.Hash]bool, len(cur.Chain)+1)
	chain[cur.Root] = true
	for _, h := range cur.Chain {
		chain[h] = true
	}
	for _, op := range st.Deletions {
		if op.Phase != model.DeletePhaseComplete || op.Authority == nil {
			continue
		}
		if !chain[op.Authority.Head] || uint64(op.Authority.Generation) > cur.Head.Generation {
			return model.Fail(model.Corrupt)
		}
	}
	return nil
}

type committedFact struct {
	gap  storage.DeclaredGap
	fact model.EvidenceGap
}

// committedGaps lists the evidence gaps control has committed (RecordEvidenceGap)
// at or before the cut: the only gaps the backup may declare. A fact naming a
// group the installation does not own makes the control state untrustworthy.
func committedGaps(st model.ControlState, groups map[model.ID]bool) ([]storage.DeclaredGap, []committedFact, error) {
	var facts []committedFact
	for key, g := range st.EvidenceGaps {
		if g.ID.String() != key || !groups[g.Group] || g.Through <= g.After || g.Reason == "" {
			return nil, nil, model.Fail(model.Corrupt)
		}
		facts = append(facts, committedFact{gap: storage.DeclaredGap{Group: g.Group, After: g.After, Through: g.Through, Reason: g.Reason}, fact: g})
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].fact.ID.String() < facts[j].fact.ID.String() })
	declared := make([]storage.DeclaredGap, len(facts))
	for i, f := range facts {
		declared[i] = f.gap
	}
	return declared, facts, nil
}

// attestations keeps only the facts the sealed certificate actually used.
func attestations(intervals []storage.ReplayInterval, facts []committedFact, revision model.Revision) ([]GapAttestation, error) {
	var out []GapAttestation
	for _, in := range intervals {
		if in.Mode != "gap" {
			continue
		}
		found := false
		for _, f := range facts {
			if f.gap.Group == in.Group && f.gap.After == in.After && f.gap.Through == in.Through && f.gap.Reason == in.Reason {
				out = append(out, GapAttestation{Fact: f.fact.ID, Group: in.Group, After: in.After, Through: in.Through, Reason: in.Reason, ControlRevision: revision, Digest: GapDigest(f.fact)})
				found = true
				break
			}
		}
		if !found {
			return nil, model.Fail(model.Corrupt)
		}
	}
	return out, nil
}

// Reap drops the journal pins of backup attempts that never completed (the
// process died between BeginBackup and Seal/Abort). Run it once at startup,
// before any backup. Pins with no incomplete attempt are reported, not dropped:
// nothing proves they are abandoned. A pin that cannot be dropped keeps its
// attempt open and fails loudly.
type ReapReport struct {
	Attempts int // incomplete attempts closed
	Dropped  int // pins dropped
	Unowned  int // pins present with no incomplete attempt (left alone)
}

func (s *Service) Reap(ctx context.Context) (ReapReport, error) {
	open, err := s.cfg.Attempts.Incomplete(ctx)
	if err != nil {
		return ReapReport{}, err
	}
	var pins []Pin
	if s.cfg.Pins != nil {
		if pins, err = s.cfg.Pins.Pins(); err != nil {
			return ReapReport{}, err
		}
	}
	if len(open) == 0 {
		return ReapReport{Unowned: len(pins)}, nil
	}
	if s.cfg.Pins == nil {
		return ReapReport{}, model.Fail(model.Unavailable) // cannot drop pins: the attempts stay open
	}
	report := ReapReport{}
	for _, p := range pins {
		if err = s.cfg.Pins.DropPin(p.ID); err != nil {
			return report, model.Fail(model.Unavailable)
		}
		report.Dropped++
	}
	for _, a := range open {
		if err = s.cfg.Attempts.Finish(ctx, a.ID, "reaped"); err != nil {
			return report, err
		}
		report.Attempts++
	}
	return report, nil
}

func objectAAD(id model.ID, name, class string) []byte {
	return []byte("soundpost/backup/object/v1\x00" + id.String() + "\x00" + name + "\x00" + class)
}
func keyAAD(id model.ID, keyID, purpose string) []byte {
	return []byte("soundpost/backup/dek\x00" + id.String() + "\x00" + keyID + "\x00" + purpose)
}

type wrappedKey struct {
	Version int    `json:"version"`
	KeyID   string `json:"key_id"`
	KEK     string `json:"kek"`
	Wrapped []byte `json:"wrapped"`
}

// Backup encrypts and uploads a sealed SnapshotSet to dest and writes the
// authenticated manifest last, so a backup exists only once every object does.
// Every object is read back from the destination and verified before the
// manifest is published. Uploading never touches the local replicas.
func (s *Service) Backup(ctx context.Context, scope auth.Scope, set SnapshotSet, dest Destination) (BackupManifest, error) {
	if err := s.cfg.Authorizer.RevalidateInstance(ctx, scope); err != nil {
		return BackupManifest{}, err
	}
	parts, state, err := parseSeed(set.ControlSeed)
	if err != nil {
		return BackupManifest{}, err
	}
	bundle := set.Sealed.Bundle
	if bundle.Version != 1 || len(set.Sealed.Snapshots) != 64 || len(bundle.Snapshots) != 64 || bundle.Cut.Revision != state.Revision {
		return BackupManifest{}, model.Fail(model.Invalid)
	}
	reservations, err := canonicalReservations(state.Reservations)
	if err != nil {
		return BackupManifest{}, model.Fail(model.Corrupt)
	}
	cutReservations, err := canonicalReservations(bundle.Cut.Reservations)
	if err != nil || !bytes.Equal(reservations, cutReservations) {
		return BackupManifest{}, model.Fail(model.Corrupt) // the cut and the stored control state must be one revision
	}
	dataKEK, err := s.cfg.Keys.Key(ctx, s.cfg.DataKEK)
	if err != nil {
		return BackupManifest{}, err
	}
	secretKEK, err := s.cfg.Keys.Key(ctx, s.cfg.SecretKEK)
	if err != nil {
		return BackupManifest{}, err
	}
	id := model.NewID()
	out := &export{s: s, ctx: ctx, id: id, dest: dest, deks: map[string][]byte{}}
	defer out.wipe()
	manifest := BackupManifest{Version: ManifestVersion, ID: id, CreatedAt: model.UnixNano(set.CreatedAt.UnixNano())}
	manifest.ExpiresAt = manifest.CreatedAt + model.UnixNano(s.cfg.Retention)
	for _, k := range []struct {
		purpose string
		kek     Key
	}{{ClassData, dataKEK}, {ClassKeys, secretKEK}} {
		ref, err := out.newKey(k.purpose, k.kek)
		if err != nil {
			return BackupManifest{}, err
		}
		manifest.Encryption.Keys = append(manifest.Encryption.Keys, ref)
	}
	manifest.Encryption.Algorithm, manifest.Encryption.ChunkSize = AlgorithmAES256GCM, chunkSize
	// The control state travels without its envelope key files; those go into a
	// separate object under the separate key. It also travels without the
	// quarantine stash of the restore that built THIS installation, if any: that
	// is bookkeeping of the source's own restore, not installation data, and a
	// restore of this backup starts its own (installControl).
	stateRaw := parts["state"]
	if auth.DiscardRestoreStash(&state) {
		if stateRaw, err = json.Marshal(state); err != nil {
			return BackupManifest{}, model.Fail(model.Corrupt)
		}
	}
	keysRaw := parts["keys"]
	stateSeed, err := json.Marshal(map[string]json.RawMessage{"state": stateRaw, "keys": json.RawMessage(`{}`), "metadata": parts["metadata"]})
	if err != nil {
		return BackupManifest{}, err
	}
	bundleRaw, err := json.Marshal(bundle)
	if err != nil {
		return BackupManifest{}, err
	}
	uploads := []struct {
		name, class string
		data        []byte
	}{{BundleObject, ClassData, bundleRaw}, {ControlStateObject, ClassData, stateSeed}, {ControlKeysObject, ClassKeys, keysRaw}}
	for _, u := range uploads {
		ref, err := out.put(u.name, u.class, bytes.NewReader(u.data), int64(len(u.data)))
		if err != nil {
			return BackupManifest{}, err
		}
		manifest.Objects = append(manifest.Objects, ref)
	}
	for slot, snapshot := range set.Sealed.Snapshots {
		var size int64
		for _, f := range snapshot.Manifest.Files {
			size += int64(f.Size)
		}
		pr, pw := io.Pipe()
		go func() { _, err := snapshot.WriteTo(pw); pw.CloseWithError(err) }()
		ref, err := out.put(SlotObject(slot), ClassData, pr, size)
		pr.Close()
		if err != nil {
			return BackupManifest{}, err
		}
		manifest.Objects = append(manifest.Objects, ref)
	}
	manifest.Control = ControlBinding{Installation: state.Installation, Revision: state.Revision, StateSHA256: model.HashCanonical(stateSeed), ReservationsSHA256: model.HashCanonical(reservations)}
	applied := make([]model.Cursor, len(bundle.Snapshots))
	for i, sm := range bundle.Snapshots {
		applied[i] = sm.Cursor
	}
	manifest.Data = DataBinding{Identity: bundle.Identity, BundleDigest: bundle.Digest, Generation: model.Uint64(bundle.Generation), Applied: applied, Processed: append([]model.Cursor(nil), bundle.Cut.Processed...), ReplayDigest: bundle.Replay.Digest, QuotaDigest: bundle.Quota.Digest}
	policies, err := model.CanonicalJSON(state.RetentionPolicies)
	if err != nil {
		return BackupManifest{}, model.Fail(model.Corrupt)
	}
	var versions uint64
	for _, v := range state.RetentionPolicies {
		versions += uint64(len(v))
	}
	manifest.Retention = RetentionBinding{PolicyDigest: model.HashCanonical(policies), Versions: model.Uint64(versions)}
	if manifest.Deletion, err = bindingOf(set.Authority); err != nil {
		return BackupManifest{}, err
	}
	manifest.Gaps = append([]GapAttestation{}, set.Gaps...)
	manifest.CompletedAt = model.UnixNano(s.cfg.Clock().UnixNano())
	// The backup must be restorable before it is published: re-verify what it asserts.
	if err = verifyGaps(manifest, bundle.Replay.Intervals, state); err != nil {
		return BackupManifest{}, err
	}
	if err = manifest.Sign(dataKEK); err != nil {
		return BackupManifest{}, err
	}
	raw, err := manifest.Encode()
	if err != nil {
		return BackupManifest{}, err
	}
	if _, err = ParseManifest(raw); err != nil {
		return BackupManifest{}, err
	}
	if err = dest.Create(ctx, ManifestName(id), bytes.NewReader(raw), int64(len(raw))); err != nil {
		return BackupManifest{}, model.Fail(model.Unavailable)
	}
	stored, err := readObject(ctx, dest, ManifestName(id), 4<<20)
	if err != nil || !bytes.Equal(stored, raw) {
		return BackupManifest{}, model.Fail(model.Unavailable)
	}
	return manifest, nil
}

func readObject(ctx context.Context, d Destination, name string, limit int64) ([]byte, error) {
	r, err := d.Open(ctx, name)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, model.Fail(model.Unavailable)
		}
		return nil, err
	}
	defer r.Close()
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, model.Fail(model.Unavailable)
	}
	if int64(len(raw)) > limit {
		return nil, model.Fail(model.TooLarge)
	}
	return raw, nil
}

type export struct {
	s    *Service
	ctx  context.Context
	id   model.ID
	dest Destination
	deks map[string][]byte // class -> data key
}

func (e *export) wipe() {
	for _, k := range e.deks {
		clear(k)
	}
}

func (e *export) newKey(purpose string, kek Key) (KeyRef, error) {
	dek, err := newDataKey()
	if err != nil {
		return KeyRef{}, err
	}
	e.deks[purpose] = dek
	keyName := e.id.String() + "-" + purpose
	wrapped, err := wrapKey(kek, dek, keyAAD(e.id, keyName, purpose))
	if err != nil {
		return KeyRef{}, err
	}
	raw, err := json.Marshal(wrappedKey{Version: 1, KeyID: keyName, KEK: kek.ID(), Wrapped: wrapped})
	if err != nil {
		return KeyRef{}, err
	}
	object := KeyName(e.id, keyName)
	if err = e.dest.Create(e.ctx, object, bytes.NewReader(raw), int64(len(raw))); err != nil {
		return KeyRef{}, model.Fail(model.Unavailable)
	}
	return KeyRef{ID: keyName, Purpose: purpose, KEK: kek.ID(), Object: object, ObjectSHA256: digestOf(raw)}, nil
}

// put encrypts src (size plaintext bytes) into one object, then reads the stored
// ciphertext back and checks its hash and length.
func (e *export) put(name, class string, src io.Reader, size int64) (ObjectRef, error) {
	dek := e.deks[class]
	pr, pw := io.Pipe()
	type outcome struct {
		res streamResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := encryptStream(dek, objectAAD(e.id, name, class), src, pw)
		pw.CloseWithError(err)
		done <- outcome{res, err}
	}()
	object := ObjectName(e.id, name)
	createErr := e.dest.Create(e.ctx, object, pr, encryptedSize(size))
	pr.Close()
	res := <-done
	if res.err != nil {
		return ObjectRef{}, res.err
	}
	if createErr != nil {
		return ObjectRef{}, model.Fail(model.Unavailable)
	}
	if res.res.Plain != size {
		return ObjectRef{}, model.Fail(model.Corrupt) // the source changed length while it was copied
	}
	rc, err := e.dest.Open(e.ctx, object)
	if err != nil {
		return ObjectRef{}, model.Fail(model.Unavailable)
	}
	h := sha256.New()
	n, err := io.Copy(h, rc)
	rc.Close()
	var sum model.Hash
	copy(sum[:], h.Sum(nil))
	if err != nil || n != res.res.Cipher || sum != res.res.CipherSum {
		return ObjectRef{}, model.Fail(model.Unavailable) // the destination did not store what was sent
	}
	return ObjectRef{Name: name, Class: class, Size: model.Uint64(res.res.Plain), SHA256: res.res.PlainSum, CipherSize: model.Uint64(res.res.Cipher), CipherSHA256: res.res.CipherSum}, nil
}

// ---- restore ---------------------------------------------------------------------------------

// DestinationRoot is the clean storage root a restore builds (the directory
// appcore.Open later starts from). It must not exist or must be empty; restore
// builds a sibling staging directory and renames it into place only when every
// verification passed, so a failed restore leaves nothing behind.
type DestinationRoot string

type RestoreConfig struct {
	Keys   KeyProvider
	Source Destination
	Clock  func() time.Time
}

type Restorer struct{ cfg RestoreConfig }

func NewRestorer(cfg RestoreConfig) (*Restorer, error) {
	if cfg.Keys == nil || cfg.Source == nil {
		return nil, model.Fail(model.Invalid)
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Restorer{cfg}, nil
}

// LoadManifest reads and authenticates a backup's manifest. The key-encryption
// key is named by the manifest and supplied by keys; a wrong key, an edited
// manifest and a missing manifest all fail.
func LoadManifest(ctx context.Context, src Destination, id model.ID, keys KeyProvider) (BackupManifest, error) {
	raw, err := readObject(ctx, src, ManifestName(id), 4<<20)
	if err != nil {
		return BackupManifest{}, err
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return BackupManifest{}, err
	}
	if m.ID != id {
		return BackupManifest{}, model.Fail(model.Corrupt)
	}
	return m, authenticate(ctx, m, keys)
}

func authenticate(ctx context.Context, m BackupManifest, keys KeyProvider) error {
	name, ok := m.kekFor(ClassData)
	if !ok {
		return model.Fail(model.Corrupt)
	}
	kek, err := keys.Key(ctx, name)
	if err != nil {
		return err
	}
	return m.VerifyMAC(kek)
}

// denyAll revalidates nothing: the offline engine used to install a restore
// never serves a scope.
type denyAll struct{}

func (denyAll) Revalidate(context.Context, auth.Scope) error { return model.Fail(model.Unavailable) }

type RestoreReport struct {
	BackupID            model.ID
	ControlRevision     model.Revision
	AuthoritySequence   uint64
	AuthorityGeneration uint64
	Tombstones          int
	Objects             int
	GapsVerified        int
	QuotaCertificate    model.Hash
	Quarantined         auth.RestoreSummary
}

type restoreState struct {
	Version int                         `json:"version"`
	Backup  model.ID                    `json:"backup"`
	Control model.Revision              `json:"control_revision"`
	Cert    storage.QuotaReconciliation `json:"quota_certificate"`
	// Deletion is the authority position Restore verified (activation refuses any
	// journal that is not at or beyond it, with that head in its chain).
	Deletion       AuthorityBinding `json:"deletion"`
	Installation   model.ID         `json:"installation"`
	At             model.UnixNano   `json:"at_ns"`
	QuotaStarted   model.UnixNano   `json:"quota_started_ns,omitempty"`
	QuotaCommitted model.UnixNano   `json:"quota_committed_ns,omitempty"`
	Activated      model.UnixNano   `json:"activated_ns,omitempty"`
}

const restoreStateFile = "restore.json"

// IsRestoredRoot reports whether dir was built by Restore (it carries the restore's
// bookkeeping file). A process that starts on such a root must not log the root's
// one-time recovery bootstrap secret.
func IsRestoredRoot(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, restoreStateFile))
	return err == nil && info.Mode().IsRegular()
}

// checkAuthority is the single place a restore decides an authority is the
// current, unrolled-back authority of this backup's installation. It runs
// before any backup data is read and again at activation.
func checkAuthority(cur CurrentDeletion, b AuthorityBinding, installation model.ID) error {
	if cur.Head.Authority != b.Authority || cur.Installation != installation || cur.Head.Sequence < uint64(b.Sequence) || cur.Head.Generation < uint64(b.Generation) || uint64(len(cur.Tombstones)) < uint64(b.Tombstones) {
		return model.Fail(model.Conflict)
	}
	if b.Sequence == 0 {
		if cur.Root != b.Head {
			return model.Fail(model.Conflict)
		}
	} else if uint64(len(cur.Chain)) < uint64(b.Sequence) || cur.Chain[uint64(b.Sequence)-1] != b.Head {
		return model.Fail(model.Conflict) // the head this backup was taken under is not in the authority's history
	}
	return nil
}

// canonicalReservations is the canonical encoding of a reservation set. A control
// state that never admitted a batch carries no reservation map at all while the
// data cut carries an empty one; both are "no reservations" and encode alike.
func canonicalReservations(r map[string]model.AdmissionReservation) ([]byte, error) {
	if r == nil {
		r = map[string]model.AdmissionReservation{}
	}
	return model.CanonicalJSON(r)
}

// bindingOf is the authority position one verified read stands at.
func bindingOf(cur CurrentDeletion) (AuthorityBinding, error) {
	ledger, err := model.CanonicalJSON(cur.Ledger)
	if err != nil {
		return AuthorityBinding{}, model.Fail(model.Corrupt)
	}
	return AuthorityBinding{Authority: cur.Head.Authority, Sequence: model.Uint64(cur.Head.Sequence), Generation: model.Uint64(cur.Head.Generation), Head: cur.Head.Digest, Tombstones: model.Uint64(len(cur.Tombstones)), LedgerDigest: model.HashCanonical(ledger)}, nil
}

func expectedObjects() map[string]string {
	out := map[string]string{BundleObject: ClassData, ControlStateObject: ClassData, ControlKeysObject: ClassKeys}
	for slot := range 64 {
		out[SlotObject(slot)] = ClassData
	}
	return out
}

func randomSuffix() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// Restore verifies and installs backup m into the clean root, bootstrap-only.
//
// Order is the contract: (1) the manifest authenticates under the data
// key-encryption key; (2) the CURRENT deletion ledger is obtained from the
// independent authority and verified against the head the backup was taken
// under, failing closed if it is unavailable, unverifiable, from another
// installation or behind the backup, all before any backup data is read;
// (3) the wrapped data keys are unwrapped; (4) the snapshot generation fence is
// armed in the staging store; (5) every object is fetched, decrypted and
// verified against the manifest, the bundle certificates, the control state and
// every gap; (6) the data groups are installed (intake closed until the quota
// certificate and deletion ledger are applied); (7) the control state is
// installed through the real replicated update, quarantined (every old user,
// session, token, source and sender inactive, fresh keys and a fresh recovery
// bootstrap) and its quota reconciled; (8) the staged tree is renamed to root.
// Old decryption keys decrypt data and confer no authority.
func (r *Restorer) Restore(ctx context.Context, m BackupManifest, root DestinationRoot, ledger DeletionLedger) (report RestoreReport, err error) {
	if ledger == nil || root == "" {
		return RestoreReport{}, model.Fail(model.Unavailable)
	}
	target, err := filepath.Abs(string(root))
	if err != nil {
		return RestoreReport{}, err
	}
	if entries, err := os.ReadDir(target); err == nil && len(entries) != 0 {
		return RestoreReport{}, model.Fail(model.Conflict)
	} else if err != nil && !os.IsNotExist(err) {
		return RestoreReport{}, model.Fail(model.Unavailable)
	}
	if err = m.validate(); err != nil {
		return RestoreReport{}, err
	}
	if err = authenticate(ctx, m, r.cfg.Keys); err != nil {
		return RestoreReport{}, err
	}
	if !r.cfg.Clock().Before(time.Unix(0, int64(m.ExpiresAt))) {
		return RestoreReport{}, model.Fail(model.Stale) // backups expire; an expired one is never restored
	}
	current, err := ledger.Current(ctx)
	if err != nil {
		return RestoreReport{}, model.Fail(model.Unavailable)
	}
	if err = checkAuthority(current, m.Deletion, m.Control.Installation); err != nil {
		return RestoreReport{}, err
	}
	deks, err := r.unwrap(ctx, m)
	if err != nil {
		return RestoreReport{}, err
	}
	defer func() {
		for _, k := range deks {
			clear(k)
		}
	}()
	if err = durablefs.MkdirAll(filepath.Dir(target)); err != nil {
		return RestoreReport{}, err
	}
	stage := target + ".restore-" + randomSuffix()
	if err = durablefs.MkdirAll(stage); err != nil {
		return RestoreReport{}, err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(stage)
		}
	}()
	raftData := filepath.Join(stage, "raft", "data")
	// Armed before any data is read: no snapshot older than the backup's own
	// generation may ever be selected in this root.
	if err = armGeneration(raftData, m); err != nil {
		return RestoreReport{}, err
	}
	staged, err := r.fetch(ctx, m, deks, filepath.Join(stage, ".objects"))
	if err != nil {
		return RestoreReport{}, err
	}
	var bundle storage.BackupBundle
	if err = json.Unmarshal(staged.bundle, &bundle); err != nil {
		return RestoreReport{}, model.Fail(model.Corrupt)
	}
	cert, err := verifyBundle(m, bundle)
	if err != nil {
		return RestoreReport{}, err
	}
	if model.HashCanonical(staged.controlState) != m.Control.StateSHA256 {
		return RestoreReport{}, model.Fail(model.Corrupt) // the manifest names another control state than the one it carries
	}
	seed, state, err := reassembleSeed(staged.controlState, staged.controlKeys)
	if err != nil {
		return RestoreReport{}, err
	}
	if err = verifyControl(m, bundle, state); err != nil {
		return RestoreReport{}, err
	}
	if err = verifyGaps(m, bundle.Replay.Intervals, state); err != nil {
		return RestoreReport{}, err
	}
	created, err := r.installData(ctx, stage, raftData, bundle, cert, staged.objects)
	if err != nil {
		return RestoreReport{}, err
	}
	summary, err := installControl(ctx, stage, seed, cert, created, bundle.Quota.Consumed, m.ID, r.cfg.Clock())
	if err != nil {
		return RestoreReport{}, err
	}
	_ = os.RemoveAll(filepath.Join(stage, ".objects")) // no plaintext duplicates of the installed data
	// Activation is bound to the authority position THIS restore verified (not only to the older
	// head the backup was taken under): a journal rolled back or forked below it is refused.
	observed, err := bindingOf(current)
	if err != nil {
		return RestoreReport{}, err
	}
	state2 := restoreState{Version: 1, Backup: m.ID, Control: m.Control.Revision, Cert: cert, Deletion: observed, Installation: m.Control.Installation, At: model.UnixNano(r.cfg.Clock().UnixNano())}
	raw, err := json.Marshal(state2)
	if err != nil {
		return RestoreReport{}, err
	}
	if err = durablefs.Exclusive(filepath.Join(stage, restoreStateFile), raw); err != nil {
		return RestoreReport{}, err
	}
	if err = durablefs.SyncDir(stage); err != nil {
		return RestoreReport{}, err
	}
	if err = os.Remove(target); err != nil && !os.IsNotExist(err) {
		return RestoreReport{}, err
	}
	if err = durablefs.Rename(stage, target); err != nil {
		return RestoreReport{}, err
	}
	return RestoreReport{BackupID: m.ID, ControlRevision: m.Control.Revision, AuthoritySequence: current.Head.Sequence, AuthorityGeneration: current.Head.Generation, Tombstones: len(current.Tombstones), Objects: len(m.Objects), GapsVerified: len(m.Gaps), QuotaCertificate: cert.Digest, Quarantined: summary}, nil
}

func (r *Restorer) unwrap(ctx context.Context, m BackupManifest) (map[string][]byte, error) {
	deks := map[string][]byte{}
	for _, ref := range m.Encryption.Keys {
		kek, err := r.cfg.Keys.Key(ctx, ref.KEK)
		if err != nil {
			return nil, err
		}
		raw, err := readObject(ctx, r.cfg.Source, ref.Object, 1<<16)
		if err != nil || digestOf(raw) != ref.ObjectSHA256 {
			return nil, model.Fail(model.Corrupt)
		}
		var w wrappedKey
		if model.StrictJSON(raw, &w) != nil || w.Version != 1 || w.KeyID != ref.ID || w.KEK != ref.KEK {
			return nil, model.Fail(model.Corrupt)
		}
		dek, err := unwrapKey(kek, w.Wrapped, keyAAD(m.ID, ref.ID, ref.Purpose))
		if err != nil {
			return nil, err
		}
		deks[ref.Purpose] = dek
	}
	return deks, nil
}

func armGeneration(raftData string, m BackupManifest) error {
	for slot := range 64 {
		store, err := replica.OpenSnapshotStore(storage.SlotDirectory(raftData, uint16(slot)), m.Data.Applied[slot].Group, nil)
		if err != nil {
			return model.Fail(model.Unavailable)
		}
		if err = store.RequireGeneration(uint64(m.Data.Generation)); err != nil {
			return model.Fail(model.Stale)
		}
	}
	return nil
}

type stagedObjects struct {
	bundle, controlState, controlKeys []byte
	objects                           string // directory with slot-NN files
}

// fetch downloads, decrypts and verifies every object of the backup into dir.
func (r *Restorer) fetch(ctx context.Context, m BackupManifest, deks map[string][]byte, dir string) (stagedObjects, error) {
	want := expectedObjects()
	if len(m.Objects) != len(want) {
		return stagedObjects{}, model.Fail(model.Corrupt)
	}
	if err := durablefs.MkdirAll(dir); err != nil {
		return stagedObjects{}, err
	}
	out := stagedObjects{objects: dir}
	for _, ref := range m.Objects {
		if want[ref.Name] != ref.Class {
			return stagedObjects{}, model.Fail(model.Corrupt)
		}
		delete(want, ref.Name)
		rc, err := r.cfg.Source.Open(ctx, ObjectName(m.ID, ref.Name))
		if err != nil {
			return stagedObjects{}, model.Fail(model.Unavailable) // a missing object is never silently omitted
		}
		path := filepath.Join(dir, ref.Name)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			rc.Close()
			return stagedObjects{}, err
		}
		res, err := decryptStream(deks[ref.Class], objectAAD(m.ID, ref.Name, ref.Class), rc, f)
		rc.Close()
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return stagedObjects{}, err
		}
		if uint64(res.Plain) != uint64(ref.Size) || res.PlainSum != ref.SHA256 || uint64(res.Cipher) != uint64(ref.CipherSize) || res.CipherSum != ref.CipherSHA256 {
			return stagedObjects{}, model.Fail(model.Corrupt)
		}
		switch ref.Name {
		case BundleObject, ControlStateObject, ControlKeysObject:
			raw, err := os.ReadFile(path)
			if err != nil {
				return stagedObjects{}, err
			}
			if err = os.Remove(path); err != nil {
				return stagedObjects{}, err
			}
			switch ref.Name {
			case BundleObject:
				out.bundle = raw
			case ControlStateObject:
				out.controlState = raw
			default:
				out.controlKeys = raw
			}
		}
	}
	if len(want) != 0 || out.bundle == nil || out.controlState == nil || out.controlKeys == nil {
		return stagedObjects{}, model.Fail(model.Corrupt)
	}
	return out, nil
}

// verifyBundle binds the decrypted bundle to the manifest and verifies its
// certificates (storage.ReconcileQuota authenticates the bundle digest and the
// reservation evidence and returns the quota certificate).
func verifyBundle(m BackupManifest, b storage.BackupBundle) (storage.QuotaReconciliation, error) {
	if b.Version != 1 || len(b.Snapshots) != 64 || len(b.Cut.Processed) != 64 || b.Identity != m.Data.Identity || b.Digest != m.Data.BundleDigest || uint64(b.Generation) != uint64(m.Data.Generation) || b.Replay.Digest != m.Data.ReplayDigest || b.Quota.Digest != m.Data.QuotaDigest || b.Cut.Revision != m.Control.Revision {
		return storage.QuotaReconciliation{}, model.Fail(model.Corrupt)
	}
	for i := range 64 {
		if b.Snapshots[i].Cursor != m.Data.Applied[i] || b.Cut.Processed[i] != m.Data.Processed[i] {
			return storage.QuotaReconciliation{}, model.Fail(model.Corrupt)
		}
	}
	cert, err := storage.ReconcileQuota(b)
	if err != nil {
		return storage.QuotaReconciliation{}, err
	}
	return cert, nil
}

// reassembleSeed rebuilds the control seed from its two objects (state and
// envelope key files), dropping any bootstrap token file the old installation
// carried: a restore arms a fresh recovery bootstrap, never the old one.
func reassembleSeed(stateObject, keysObject []byte) ([]byte, model.ControlState, error) {
	var parts map[string]json.RawMessage
	var keys map[string]json.RawMessage
	if json.Unmarshal(stateObject, &parts) != nil || json.Unmarshal(keysObject, &keys) != nil || parts["state"] == nil || parts["metadata"] == nil {
		return nil, model.ControlState{}, model.Fail(model.Corrupt)
	}
	delete(keys, "bootstrap.token")
	rawKeys, err := json.Marshal(keys)
	if err != nil {
		return nil, model.ControlState{}, model.Fail(model.Corrupt)
	}
	seed, err := json.Marshal(map[string]json.RawMessage{"state": parts["state"], "keys": rawKeys, "metadata": parts["metadata"]})
	if err != nil {
		return nil, model.ControlState{}, model.Fail(model.Corrupt)
	}
	var st model.ControlState
	if json.Unmarshal(parts["state"], &st) != nil || st.Installation == (model.ID{}) {
		return nil, model.ControlState{}, model.Fail(model.Corrupt)
	}
	return seed, st, nil
}

func verifyControl(m BackupManifest, b storage.BackupBundle, st model.ControlState) error {
	reservations, err := canonicalReservations(st.Reservations)
	cut, err2 := canonicalReservations(b.Cut.Reservations)
	policies, err3 := model.CanonicalJSON(st.RetentionPolicies)
	if err != nil || err2 != nil || err3 != nil || st.Installation != m.Control.Installation || st.Revision != m.Control.Revision || st.Revision != b.Cut.Revision || model.HashCanonical(reservations) != m.Control.ReservationsSHA256 || !bytes.Equal(reservations, cut) || model.HashCanonical(policies) != m.Retention.PolicyDigest {
		return model.Fail(model.Corrupt)
	}
	return nil
}

// installData installs the 64 snapshots into the staged data root and returns
// the full reservations of batches admitted after the control cut.
func (r *Restorer) installData(ctx context.Context, stage, raftData string, b storage.BackupBundle, cert storage.QuotaReconciliation, objects string) (map[model.ID]model.AdmissionReservation, error) {
	engine, err := storage.Open(filepath.Join(stage, "data"), denyAll{})
	if err != nil {
		return nil, err
	}
	defer engine.Close()
	if err = engine.InstallReplicationIdentity(b.Identity); err != nil {
		return nil, err
	}
	open := func(slot uint16) (io.ReadCloser, error) {
		return os.Open(filepath.Join(objects, SlotObject(int(slot))))
	}
	if err = engine.InstallBackup(ctx, raftData, b, open); err != nil {
		return nil, err
	}
	want := map[model.ID]bool{}
	for _, id := range cert.AddedAfterCut {
		want[id] = true
	}
	created := map[model.ID]model.AdmissionReservation{}
	if len(want) == 0 {
		return created, nil
	}
	for slot := range 64 {
		store, err := replica.OpenSnapshotStore(storage.SlotDirectory(raftData, uint16(slot)), b.Snapshots[slot].Group, nil)
		if err != nil {
			return nil, model.Fail(model.Unavailable)
		}
		snapshot, ok := store.Current()
		if !ok {
			return nil, model.Fail(model.Corrupt)
		}
		found, err := slotReservations(snapshot)
		if err != nil {
			return nil, err
		}
		for id, res := range found {
			if want[id] {
				created[id] = res
			}
		}
	}
	return created, nil
}

// installControl installs the restored control state through the real
// replicated control path and applies, in one transaction, the quarantine and
// the quota reconciliation. The envelope key is rotated first, so everything
// sealed from now on uses a fresh key (old keys stay decrypt-only).
func installControl(ctx context.Context, stage string, seed []byte, cert storage.QuotaReconciliation, created map[model.ID]model.AdmissionReservation, evidence []storage.ReservationEvidence, backupID model.ID, at time.Time) (auth.RestoreSummary, error) {
	store, err := control.OpenSeed(stage, seed)
	if err != nil {
		return auth.RestoreSummary{}, err
	}
	defer store.Close()
	if err = store.EnableSingle(ctx, filepath.Join(stage, "raft", "control")); err != nil {
		return auth.RestoreSummary{}, err
	}
	if _, err = store.RotateSecretKey(); err != nil {
		return auth.RestoreSummary{}, err
	}
	sealed, err := auth.SealedBearerKey(store.Seal)
	if err != nil {
		return auth.RestoreSummary{}, err
	}
	token, hash := auth.NewRecoveryBootstrap()
	var summary auth.RestoreSummary
	err = store.Update(ctx, func(st *model.ControlState) error {
		// A backup of an installation that was itself restored (and one taken by an
		// older build) can still carry that restore's stash. It is bookkeeping of the
		// earlier restore: this generation quarantines what is active in the state it
		// restores and replaces it.
		auth.DiscardRestoreStash(st)
		var e error
		if summary, e = auth.QuarantineRestoredState(st, auth.RestoreInput{Generation: model.NewID(), Backup: backupID, BootstrapHash: hash, SealedBearerKey: sealed, At: at}); e != nil {
			return e
		}
		return applyQuotaReconciliation(st, cert, created, evidence)
	})
	if err != nil {
		return auth.RestoreSummary{}, err
	}
	if err = durablefs.Exclusive(filepath.Join(stage, "bootstrap.token"), []byte(token)); err != nil {
		return auth.RestoreSummary{}, err
	}
	return summary, nil
}

// ---- activation -------------------------------------------------------------------------------

// Activation is the opened restored installation as Activate needs it.
// *storage.Engine supplies CommitQuotaReconciliation and RestoreReady;
// RestoreDeletions is retention.Service.Restore.
type Activation interface {
	CommitQuotaReconciliation(ctx context.Context, cert storage.QuotaReconciliation) error
	RestoreDeletions(ctx context.Context, authority retention.Authority) error
	RestoreReady() error
}

type ActivationReport struct {
	AuthorityGeneration uint64
	Tombstones          int
}

// Activate finishes a restore on an opened restored installation: it commits
// the verified quota certificate, then re-reads the CURRENT deletion ledger (a
// deletion may have completed since Restore), verifies it against the backup's
// binding, applies exactly that head (control import and a tombstone barrier in
// every data group) and only then lets the engine open. Until Activate succeeds
// the engine serves no read and admits no write.
func (r *Restorer) Activate(ctx context.Context, root DestinationRoot, target Activation, ledger DeletionLedger) (ActivationReport, error) {
	return Activate(ctx, root, target, ledger, r.cfg.Clock)
}

// Activate is Restorer.Activate for callers that hold no backup keys or source:
// activation needs only the restored root, the opened installation and the
// authority.
func Activate(ctx context.Context, root DestinationRoot, target Activation, ledger DeletionLedger, now func() time.Time) (ActivationReport, error) {
	if now == nil {
		now = time.Now
	}
	if ledger == nil || target == nil {
		return ActivationReport{}, model.Fail(model.Unavailable)
	}
	path := filepath.Join(string(root), restoreStateFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		return ActivationReport{}, model.Fail(model.NotFound)
	}
	var state restoreState
	if model.StrictJSON(raw, &state) != nil || state.Version != 1 {
		return ActivationReport{}, model.Fail(model.Corrupt)
	}
	resumed := state.QuotaStarted != 0 // a previous activation got as far as starting the quota commit
	var cur CurrentDeletion
	for range 3 { // re-read until two consecutive reads agree: narrows the window to a deletion completing mid-activation
		first, err := ledger.Current(ctx)
		if err != nil {
			return ActivationReport{}, model.Fail(model.Unavailable)
		}
		if err = checkAuthority(first, state.Deletion, state.Installation); err != nil {
			return ActivationReport{}, err
		}
		second, err := ledger.Current(ctx)
		if err != nil {
			return ActivationReport{}, model.Fail(model.Unavailable)
		}
		if first.Head.Digest == second.Head.Digest {
			cur = second
			break
		}
	}
	if cur.Head.Authority == (model.ID{}) {
		return ActivationReport{}, model.Fail(model.Unavailable)
	}
	if state.QuotaCommitted == 0 {
		// The intent is recorded first: CommitQuotaReconciliation answers Conflict
		// when its pending marker is already gone, which after a crash between its
		// own persist and our bookkeeping means it had completed.
		if state.QuotaStarted == 0 {
			state.QuotaStarted = model.UnixNano(now().UnixNano())
			if err = rewriteState(path, state); err != nil {
				return ActivationReport{}, err
			}
		}
		if err = target.CommitQuotaReconciliation(ctx, state.Cert); err != nil && !(faultIs(err, model.Conflict) && state.QuotaStarted != 0 && state.QuotaCommitted == 0 && resumed) {
			return ActivationReport{}, err
		}
		state.QuotaCommitted = model.UnixNano(now().UnixNano())
		if err = rewriteState(path, state); err != nil {
			return ActivationReport{}, err
		}
	}
	if err = target.RestoreDeletions(ctx, cur.AsAuthority()); err != nil {
		return ActivationReport{}, err
	}
	if err = target.RestoreReady(); err != nil {
		return ActivationReport{}, err
	}
	state.Activated = model.UnixNano(now().UnixNano())
	if err = rewriteState(path, state); err != nil {
		return ActivationReport{}, err
	}
	return ActivationReport{AuthorityGeneration: cur.Head.Generation, Tombstones: len(cur.Tombstones)}, nil
}

func rewriteState(path string, state restoreState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err = durablefs.Remove(tmp); err != nil {
		return err
	}
	if err = durablefs.Exclusive(tmp, raw); err != nil {
		return err
	}
	return durablefs.Rename(tmp, path)
}

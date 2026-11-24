// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"context"
	"errors"
	"github.com/arynyklas/soundpost/internal/artifacts/refledger"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
	"math"
)

// retainedForever is what LatestReference answers while something outside the
// reference ledger (a snapshot pin, or the absence of the GC fence at the final
// check) forbids physical removal.
const retainedForever = model.UnixNano(math.MaxInt64)

// GCDecision is the durable fence a successful GC took.
type GCDecision struct{ Seq uint64 }

// GC fences an artifact for physical removal. It succeeds only when nothing
// retains the map (upload deadline and every unreleased reference are over),
// the reference ledger verifies completely, no tombstone covers the root (a
// deletion takes precedence and is erased by its own saga), and no snapshot pin
// holds it. Once taken, no reference can be added and no read is released. GC
// never consults backup upload state: a local authoritative replica is released
// only by the erasure that follows this fence, never because a copy exists
// elsewhere. Idempotent.
func (l *Lifecycle) GC(ctx context.Context, scope auth.Scope, id ArtifactID) (GCDecision, error) {
	if scope.Permission() != auth.ArtifactWrite || len(scope.ProjectIDs()) != 1 {
		return GCDecision{}, model.Fail(model.NotFound)
	}
	var out GCDecision
	org, project := scope.OrgID(), scope.ProjectIDs()[0]
	err := l.run(ctx, org, true, one(org, project, id, func(st model.ControlState, in model.ArtifactReferenceIntent) error {
		return scope.ValidateArtifactCleanup(st, in.Map.Manifest)
	}, func(m model.ArtifactManifest, led *refledger.Ledger, now model.UnixNano) (bool, error) {
		if led.Retired {
			out = GCDecision{Seq: led.Seq}
			return false, nil
		}
		if max(m.RetainUntil, led.Latest()) > now {
			return false, model.Fail(model.Conflict)
		}
		pinned, err := l.cfg.Pins.Pinned(ctx, m.Org, m.Project, id)
		if err != nil {
			return false, model.Fail(model.Unavailable)
		}
		if pinned {
			return false, model.Fail(model.Conflict)
		}
		led.Retired = true
		out = GCDecision{Seq: led.Seq + 1}
		return true, nil
	}))
	return out, err
}

// LatestReference implements retention.References for artifact roots: the
// latest deadline at which anything retained still needs the candidate, zero
// when nothing does. When nothing does it takes the GC fence in the same
// transaction as the last check, so a reference racing the erasure either was
// seen here or is refused afterwards. A candidate under a deletion answers zero
// (deletion takes precedence); a ledger that fails verification is an error, so
// the pass fails closed. Records are never held by a map.
func (l *Lifecycle) LatestReference(ctx context.Context, c storage.EraseCandidate) (model.UnixNano, error) {
	if c.Blob == nil {
		return 0, nil
	}
	m := *c.Blob
	now := model.UnixNano(l.cfg.Now().UnixNano())
	var latest model.UnixNano
	var covered, retired, present bool
	err := l.view(ctx, false, model.ID{}, model.ID{}, func(st model.ControlState) error {
		if covered = deletionCovers(st, m); covered {
			return nil
		}
		intent, ok := st.ArtifactIntents[m.Org.String()+":"+m.Project.String()+":"+m.Root.String()]
		present = ok
		led, err := refledger.Load(settingsOf(st, m.Org), m.Project, m.Root)
		if err != nil {
			return err
		}
		retired = led != nil && led.Retired
		if ok && intent.State == intentRetired && !retired {
			return model.Fail(model.Corrupt) // the fence wrote both: the ledger was removed or rolled back
		}
		latest = max(m.RetainUntil, led.Latest())
		return nil
	})
	switch {
	case err != nil:
		return 0, err
	case covered || retired:
		return 0, nil
	case latest > now:
		return latest, nil
	case c.Final:
		return retainedForever, nil // the fence was not taken at scan time
	case !present:
		return 0, nil // no published reference exists to fence
	}
	out := retainedForever
	err = l.run(ctx, m.Org, true, one(m.Org, m.Project, m.Root, nil, func(mf model.ArtifactManifest, led *refledger.Ledger, at model.UnixNano) (bool, error) {
		if led.Retired {
			out = 0
			return false, nil
		}
		if v := max(mf.RetainUntil, led.Latest()); v > at {
			out = v
			return false, nil
		}
		pinned, perr := l.cfg.Pins.Pinned(ctx, m.Org, m.Project, m.Root)
		if perr != nil {
			return false, model.Fail(model.Unavailable)
		}
		if pinned {
			out = retainedForever
			return false, nil
		}
		led.Retired = true
		out = 0
		return true, nil
	}))
	if isNotFound(err) { // deleted between the check and the fence
		return 0, nil
	}
	return out, err
}

// EffectiveRetention is when the map stops being retained: the later of the
// upload's own deadline and every unreleased reference. It is the deadline the
// read gate enforces (D-new C07, see Lifecycle): auth.Scope.ValidateArtifactState
// computes it with the same code over the same verified ledger
// (refledger.EffectiveRetention), so a read is refused exactly when this has elapsed.
// NotFound for a GC-fenced, deleted or already elapsed artifact (its readers are
// refused alike) and for any artifact outside the caller's scope.
func (l *Lifecycle) EffectiveRetention(ctx context.Context, scope auth.Scope, id ArtifactID) (model.UnixNano, error) {
	artifact, err := l.service.Lookup(ctx, scope, id)
	if err != nil {
		return 0, err
	}
	var out model.UnixNano
	err = l.view(ctx, false, model.ID{}, model.ID{}, func(st model.ControlState) error {
		until, retired, e := refledger.EffectiveRetention(st, artifact.Map.Manifest)
		if e != nil {
			return e
		}
		if retired {
			return model.Fail(model.NotFound)
		}
		out = until
		return nil
	})
	return out, err
}

// CacheStats reports the visibility-bound fragment cache.
func (l *Lifecycle) CacheStats() CacheStats { return l.gate.cache.stats() }

func isNotFound(err error) bool {
	var fault *model.Fault
	return errors.As(err, &fault) && fault.Code == model.NotFound
}

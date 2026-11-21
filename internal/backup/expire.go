// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// DefaultAbandonedAfter is how long an upload may run before its objects, which never got a
// manifest, are treated as abandoned.
const DefaultAbandonedAfter = 24 * time.Hour

// startedName is the stamp an upload writes before its first object. It holds no secret.
func startedName(id model.ID) string { return "backups/" + id.String() + "/started" }

type startedStamp struct {
	Version   int            `json:"version"`
	StartedAt model.UnixNano `json:"started_ns"`
}

func putStarted(ctx context.Context, dest Destination, id model.ID, at time.Time) error {
	raw, err := json.Marshal(startedStamp{Version: 1, StartedAt: model.UnixNano(at.UnixNano())})
	if err != nil {
		return err
	}
	if err = dest.Create(ctx, startedName(id), bytes.NewReader(raw), int64(len(raw))); err != nil {
		return model.Fail(model.Unavailable)
	}
	return nil
}

// ExpireOptions configures ExpireBackups.
type ExpireOptions struct {
	Keys KeyProvider // verifies manifests under the data key-encryption key each one names
	Now  func() time.Time
	// AbandonedAfter bounds an upload: the objects of a backup with no manifest are deleted only when
	// its start stamp is older than this (default DefaultAbandonedAfter; keep it above the longest
	// upload). There is no other way to tell an upload in flight from one that died.
	AbandonedAfter time.Duration
}

// ExpireReport counts backups by what ExpireBackups did with them.
type ExpireReport struct {
	Expired   int // authenticated manifest past its expiry: every object deleted
	Abandoned int // no manifest and a start stamp older than AbandonedAfter: every object deleted
	Kept      int // within expiry, or an upload that may still be running
	Untrusted int // left alone: a manifest that does not authenticate under a key we hold, or objects with neither manifest nor start stamp
	Deleted   int // objects deleted
}

// ExpireBackups deletes the objects of backups whose manifest expired and of uploads that were
// abandoned. Restore already refuses an expired backup; this is what frees the storage, which a
// 30-day retention promises. A manifest is trusted only when it authenticates, so an object
// that merely looks like one cannot make a live backup disappear. The manifest goes first: a delete
// interrupted half-way leaves a backup that is no longer restorable (rather than one that looks
// restorable and is missing objects), and the next run removes the rest. The authority journal is not
// under backups/ and is never touched. Local retained replicas are not touched either.
func ExpireBackups(ctx context.Context, dest Destination, opts ExpireOptions) (ExpireReport, error) {
	deleter, ok := dest.(Deleter)
	if !ok || opts.Keys == nil {
		return ExpireReport{}, model.Fail(model.Unsupported)
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	if opts.AbandonedAfter <= 0 {
		opts.AbandonedAfter = DefaultAbandonedAfter
	}
	names, err := dest.List(ctx, "backups/")
	if err != nil {
		return ExpireReport{}, err
	}
	byID := map[string][]string{}
	for _, name := range names {
		parts := strings.SplitN(name, "/", 3)
		if len(parts) == 3 {
			byID[parts[1]] = append(byID[parts[1]], name)
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var report ExpireReport
	for _, text := range ids {
		id, err := model.ParseID(text)
		if err != nil {
			report.Untrusted++
			continue
		}
		verdict, err := judge(ctx, dest, opts, id, byID[text], now())
		if err != nil {
			return report, err
		}
		switch verdict {
		case "keep":
			report.Kept++
			continue
		case "untrusted":
			report.Untrusted++
			continue
		case "expired":
			report.Expired++
		case "abandoned":
			report.Abandoned++
		}
		// manifest first, start stamp last: whatever is left after a crash is still recognisable.
		members := append([]string(nil), byID[text]...)
		sort.SliceStable(members, func(i, j int) bool { return deleteRank(id, members[i]) < deleteRank(id, members[j]) })
		for _, name := range members {
			if err = deleter.Delete(ctx, name); err != nil {
				return report, err
			}
			report.Deleted++
		}
	}
	return report, nil
}

func deleteRank(id model.ID, name string) int {
	switch name {
	case ManifestName(id):
		return 0
	case startedName(id):
		return 2
	}
	return 1
}

// judge decides what to do with one backup prefix: "expired", "abandoned", "keep" or "untrusted".
func judge(ctx context.Context, dest Destination, opts ExpireOptions, id model.ID, members []string, now time.Time) (string, error) {
	hasManifest, hasStamp := false, false
	for _, name := range members {
		hasManifest = hasManifest || name == ManifestName(id)
		hasStamp = hasStamp || name == startedName(id)
	}
	if hasManifest {
		m, err := LoadManifest(ctx, dest, id, opts.Keys)
		if err != nil {
			var fault *model.Fault
			if errors.As(err, &fault) && fault.Code == model.Unavailable {
				return "", err // the destination is failing: say so rather than guess
			}
			return "untrusted", nil // forged, edited or signed under a key we do not hold
		}
		if now.Before(time.Unix(0, int64(m.ExpiresAt))) {
			return "keep", nil
		}
		return "expired", nil
	}
	if !hasStamp {
		return "untrusted", nil
	}
	raw, err := readObject(ctx, dest, startedName(id), 1<<10)
	var stamp startedStamp
	if err != nil || model.StrictJSON(raw, &stamp) != nil || stamp.Version != 1 {
		return "untrusted", nil
	}
	if now.Sub(time.Unix(0, int64(stamp.StartedAt))) < opts.AbandonedAfter {
		return "keep", nil
	}
	return "abandoned", nil
}

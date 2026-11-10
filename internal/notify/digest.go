// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sync"
	"time"

	"soundpost/internal/model"
	timezone "soundpost/third_party/timezone/go124"
)

// DigestHour is the local hour of the daily digest: 09:00 in the recipient's
// zone.
const DigestHour = 9

// NextDigest returns the first 09:00 in the IANA zone strictly after the
// given instant. An empty zone is UTC (the fallback for a recipient and an
// installation without a zone). An unknown or unsafe zone is a typed
// ReasonInvalidZone refusal; the zone is never guessed.
//
// Zone rules come from the repository's pinned reference dataset
// (third_party/timezone/go124, SHA-256 58b3770b...cd43d0), never from the
// host, the environment or time.Local, so every node resolves DST
// identically.
//
// Daylight saving rules, deterministic and independent of the host:
//   - A local 09:00 that exists once is that instant.
//   - A local time that occurs twice (a fall-back fold) resolves to its
//     first, earlier occurrence, so a digest is never sent twice a day.
//   - A local time that does not exist (a spring-forward gap) resolves to the
//     instant of the transition, the first moment after the gap, provided
//     that moment is still on the same civil date.
//   - A civil date that does not exist at all (for instance 2011-12-30 in
//     Pacific/Apia) has no digest; the next existing date's 09:00 is used.
//
// A result that does not fit in a UnixNano is a typed ReasonTimeRange
// refusal, never a wrapped value.
func NextDigest(after model.UnixNano, zone string) (model.UnixNano, error) {
	loc, err := location(zone)
	if err != nil {
		return 0, err
	}
	return nextLocal(after, loc, DigestHour, 0)
}

// nextLocal is NextDigest for any local time of day, so the gap and fold
// rules can be exercised with times that real zones change at.
func nextLocal(after model.UnixNano, loc *time.Location, hour, minute int) (model.UnixNano, error) {
	t := time.Unix(0, int64(after)).In(loc)
	y, m, d := t.Date()
	// Eight days cover every real skipped date.
	for i := range 8 {
		day := time.Date(y, m, d+i, 0, 0, 0, 0, time.UTC)
		inst, ok := resolveLocal(loc, day.Year(), day.Month(), day.Day(), hour, minute)
		if !ok {
			continue
		}
		n, ok := nanoOf(inst)
		if !ok {
			return 0, refuse(model.Invalid, ReasonTimeRange)
		}
		if n > after {
			return n, nil
		}
	}
	return 0, refuse(model.Invalid, ReasonTimeRange)
}

// LocalDate returns the civil date of an instant in the zone as yyyymmdd.
func LocalDate(at model.UnixNano, zone string) (uint32, error) {
	loc, err := location(zone)
	if err != nil {
		return 0, err
	}
	return localDate(at, loc), nil
}

func localDate(at model.UnixNano, loc *time.Location) uint32 {
	y, m, d := time.Unix(0, int64(at)).In(loc).Date()
	if y < 0 {
		y = 0
	}
	return uint32(y)*10000 + uint32(m)*100 + uint32(d)
}

// DigestID is the one digest identity per recipient, local date and policy
// revision. A restart or a replayed timer reproduces it; a new policy
// revision or a new local date is a new digest.
func DigestID(org, policy, recipient model.ID, localDate uint32, revision model.Revision) model.ID {
	h := sha256.New()
	h.Write([]byte("soundpost.notify.digest.v1\x00"))
	h.Write(org[:])
	h.Write(policy[:])
	h.Write(recipient[:])
	var n [12]byte
	binary.BigEndian.PutUint32(n[:4], localDate)
	binary.BigEndian.PutUint64(n[4:], uint64(revision))
	h.Write(n[:])
	return idFrom(h.Sum(nil))
}

func idFrom(sum []byte) model.ID {
	var id model.ID
	copy(id[:], sum)
	if id == (model.ID{}) {
		id[15] = 1
	}
	return id
}

// resolveLocal resolves a civil local time in loc per the NextDigest rules.
// ok is false when the civil date does not exist.
func resolveLocal(loc *time.Location, y int, m time.Month, d, hour, minute int) (time.Time, bool) {
	wall := time.Date(y, m, d, hour, minute, 0, 0, time.UTC)
	var first time.Time
	found := false
	// The offset in force a day before and after the wall time brackets any
	// single transition, so each side proposes the instant for its offset.
	for _, probe := range [...]time.Duration{-24 * time.Hour, 0, 24 * time.Hour} {
		_, off := wall.Add(probe).In(loc).Zone()
		inst := wall.Add(-time.Duration(off) * time.Second)
		l := inst.In(loc)
		if l.Year() != y || l.Month() != m || l.Day() != d || l.Hour() != hour || l.Minute() != minute {
			continue
		}
		if !found || inst.Before(first) {
			first, found = inst, true
		}
	}
	if found {
		return first, true
	}
	// Gap: the pre-transition offset puts the wall time after the transition;
	// the zone period containing it starts at the transition instant.
	_, pre := wall.Add(-24 * time.Hour).In(loc).Zone()
	start, _ := wall.Add(-time.Duration(pre) * time.Second).In(loc).ZoneBounds()
	if start.IsZero() {
		return time.Time{}, false
	}
	l := start.In(loc)
	if l.Year() != y || l.Month() != m || l.Day() != d {
		return time.Time{}, false
	}
	return start, true
}

var (
	minInstant = time.Unix(0, math.MinInt64)
	maxInstant = time.Unix(0, math.MaxInt64)
)

// nanoOf converts an instant when it fits a UnixNano exactly.
func nanoOf(t time.Time) (model.UnixNano, bool) {
	if t.Before(minInstant) || t.After(maxInstant) {
		return 0, false
	}
	return model.UnixNano(t.UnixNano()), true
}

// zoneCache holds immutable public zone data parsed from the pinned dataset,
// keyed by validated name; it is never keyed by tenant data and is bounded by
// the dataset's size.
var zoneCache sync.Map

// location loads a zone from the pinned dataset. Empty is UTC.
func location(name string) (*time.Location, error) {
	if name == "" || name == "UTC" {
		return time.UTC, nil
	}
	if !safeZone(name) {
		return nil, refuse(model.Invalid, ReasonInvalidZone)
	}
	if v, ok := zoneCache.Load(name); ok {
		return v.(*time.Location), nil
	}
	loc, err := timezone.LoadLocation(name)
	if err != nil {
		return nil, refuse(model.Invalid, ReasonInvalidZone)
	}
	zoneCache.Store(name, loc)
	return loc, nil
}

// safeZone is the same bounded-name check internal/jobs applies to schedule
// zones: no path tricks, no Local, only letters, digits and _-+/.
func safeZone(z string) bool {
	if z == "" || len(z) > 64 || z == "Local" {
		return false
	}
	for i := range len(z) {
		c := z[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '+' || c == '/') {
			return false
		}
	}
	return z[0] != '/'
}

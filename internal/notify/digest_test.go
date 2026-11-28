// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package notify

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

func utc(y int, m time.Month, d, hh, mm, ss, ns int) model.UnixNano {
	return model.UnixNano(time.Date(y, m, d, hh, mm, ss, ns, time.UTC).UnixNano())
}

func show(n model.UnixNano) string { return time.Unix(0, int64(n)).UTC().Format(time.RFC3339Nano) }

func TestDigestNextAcrossZones(t *testing.T) {
	cases := []struct {
		name  string
		after model.UnixNano
		zone  string
		want  model.UnixNano
	}{
		{"UTC before 09:00 is today", utc(2026, 3, 10, 8, 59, 59, 999999999), "UTC", utc(2026, 3, 10, 9, 0, 0, 0)},
		{"UTC exactly 09:00 is strictly after: tomorrow", utc(2026, 3, 10, 9, 0, 0, 0), "UTC", utc(2026, 3, 11, 9, 0, 0, 0)},
		{"UTC one nanosecond after 09:00", utc(2026, 3, 10, 9, 0, 0, 1), "UTC", utc(2026, 3, 11, 9, 0, 0, 0)},
		{"empty zone is the UTC fallback", utc(2026, 3, 10, 12, 0, 0, 0), "", utc(2026, 3, 11, 9, 0, 0, 0)},
		{"Etc/UTC", utc(2026, 3, 10, 12, 0, 0, 0), "Etc/UTC", utc(2026, 3, 11, 9, 0, 0, 0)},
		// Half-hour and 45-minute offsets.
		{"India +05:30", utc(2026, 1, 1, 3, 30, 0, 0), "Asia/Kolkata", utc(2026, 1, 2, 3, 30, 0, 0)},
		{"India before the minute", utc(2026, 1, 1, 3, 29, 59, 0), "Asia/Kolkata", utc(2026, 1, 1, 3, 30, 0, 0)},
		{"Nepal +05:45", utc(2026, 1, 1, 0, 0, 0, 0), "Asia/Kathmandu", utc(2026, 1, 1, 3, 15, 0, 0)},
		{"Adelaide +10:30 in January", utc(2026, 1, 10, 0, 0, 0, 0), "Australia/Adelaide", utc(2026, 1, 10, 22, 30, 0, 0)},
		{"Adelaide +09:30 in July", utc(2026, 7, 10, 0, 0, 0, 0), "Australia/Adelaide", utc(2026, 7, 10, 23, 30, 0, 0)},
		{"Lord Howe +11:00 in January", utc(2026, 1, 10, 0, 0, 0, 0), "Australia/Lord_Howe", utc(2026, 1, 10, 22, 0, 0, 0)},
		{"Lord Howe +10:30 in July", utc(2026, 7, 1, 0, 0, 0, 0), "Australia/Lord_Howe", utc(2026, 7, 1, 22, 30, 0, 0)},
		// Zones whose local date differs from the UTC date.
		{"Kiritimati +14:00", utc(2026, 1, 1, 0, 0, 0, 0), "Pacific/Kiritimati", utc(2026, 1, 1, 19, 0, 0, 0)},
		{"Pago Pago -11:00", utc(2026, 1, 1, 0, 0, 0, 0), "Pacific/Pago_Pago", utc(2026, 1, 1, 20, 0, 0, 0)},
		// DST: the digest stays at 09:00 local, so the UTC distance is 23 or 25 hours.
		{"New York spring forward: 23 hours later", utc(2025, 3, 8, 14, 0, 0, 0), "America/New_York", utc(2025, 3, 9, 13, 0, 0, 0)},
		{"New York fall back: 25 hours later", utc(2025, 11, 1, 13, 0, 0, 0), "America/New_York", utc(2025, 11, 2, 14, 0, 0, 0)},
		{"Berlin spring forward", utc(2026, 3, 28, 8, 0, 0, 0), "Europe/Berlin", utc(2026, 3, 29, 7, 0, 0, 0)},
		{"Berlin fall back", utc(2026, 10, 24, 7, 0, 0, 0), "Europe/Berlin", utc(2026, 10, 25, 8, 0, 0, 0)},
		{"Sydney October DST start: 23 hours later", utc(2026, 10, 2, 23, 0, 0, 0), "Australia/Sydney", utc(2026, 10, 3, 22, 0, 0, 0)},
		// Leap and short months.
		{"leap day exists", utc(2028, 2, 28, 9, 0, 0, 0), "UTC", utc(2028, 2, 29, 9, 0, 0, 0)},
		{"after the leap day", utc(2028, 2, 29, 9, 0, 0, 0), "UTC", utc(2028, 3, 1, 9, 0, 0, 0)},
		{"no leap day in a common year", utc(2026, 2, 28, 9, 0, 0, 0), "UTC", utc(2026, 3, 1, 9, 0, 0, 0)},
		{"century is not leap", utc(2100, 2, 28, 12, 0, 0, 0), "UTC", utc(2100, 3, 1, 9, 0, 0, 0)},
		{"30-day month", utc(2026, 4, 30, 12, 0, 0, 0), "UTC", utc(2026, 5, 1, 9, 0, 0, 0)},
		{"year end", utc(2026, 12, 31, 12, 0, 0, 0), "UTC", utc(2027, 1, 1, 9, 0, 0, 0)},
		{"leap day in New York", utc(2028, 2, 29, 14, 0, 0, 0), "America/New_York", utc(2028, 3, 1, 14, 0, 0, 0)},
		// A civil date that does not exist has no digest.
		{"Apia skips 2011-12-30", utc(2011, 12, 29, 19, 0, 0, 0), "Pacific/Apia", utc(2011, 12, 30, 19, 0, 0, 0)},
		{"Apia after the skip", utc(2011, 12, 30, 19, 0, 0, 0), "Pacific/Apia", utc(2011, 12, 31, 19, 0, 0, 0)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := NextDigest(c.after, c.zone)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("NextDigest(%s, %q) = %s, want %s", show(c.after), c.zone, show(got), show(c.want))
			}
		})
	}
}

func TestDigestNextLocalGapsAndFolds(t *testing.T) {
	ny := mustLoad(t, "America/New_York")
	lord := mustLoad(t, "Australia/Lord_Howe")
	cases := []struct {
		name         string
		loc          *time.Location
		after        model.UnixNano
		hour, minute int
		want         model.UnixNano
	}{
		// 2025-03-09 02:00 EST jumps to 03:00 EDT: 02:30 does not exist and
		// resolves to the transition instant (07:00Z).
		{"New York gap", ny, utc(2025, 3, 8, 12, 0, 0, 0), 2, 30, utc(2025, 3, 9, 7, 0, 0, 0)},
		// The day before the gap is untouched.
		{"New York normal day before the gap", ny, utc(2025, 3, 7, 12, 0, 0, 0), 2, 30, utc(2025, 3, 8, 7, 30, 0, 0)},
		{"New York day after the gap", ny, utc(2025, 3, 9, 7, 0, 0, 0), 2, 30, utc(2025, 3, 10, 6, 30, 0, 0)},
		// 2025-11-02 02:00 EDT falls back to 01:00 EST: 01:30 occurs twice,
		// 05:30Z (EDT) then 06:30Z (EST); the first is chosen.
		{"New York fold chooses the first", ny, utc(2025, 11, 1, 12, 0, 0, 0), 1, 30, utc(2025, 11, 2, 5, 30, 0, 0)},
		{"New York fold is never visited twice", ny, utc(2025, 11, 2, 5, 30, 0, 0), 1, 30, utc(2025, 11, 3, 6, 30, 0, 0)},
		{"New York between the two folded instants", ny, utc(2025, 11, 2, 5, 45, 0, 0), 1, 30, utc(2025, 11, 3, 6, 30, 0, 0)},
		// Lord Howe has a 30-minute shift: 02:00 LHST (+10:30) -> 02:30 LHDT (+11:00)
		// at 2025-10-04T15:30Z. 02:00-02:29 do not exist; 02:30 is the transition.
		{"Lord Howe 30-minute gap", lord, utc(2025, 10, 4, 0, 0, 0, 0), 2, 15, utc(2025, 10, 4, 15, 30, 0, 0)},
		{"Lord Howe gap lower edge does not exist", lord, utc(2025, 10, 4, 0, 0, 0, 0), 2, 0, utc(2025, 10, 4, 15, 30, 0, 0)},
		{"Lord Howe gap upper edge is the transition", lord, utc(2025, 10, 4, 0, 0, 0, 0), 2, 30, utc(2025, 10, 4, 15, 30, 0, 0)},
		{"Lord Howe gap is strictly after", lord, utc(2025, 10, 4, 15, 30, 0, 0), 2, 15, utc(2025, 10, 5, 15, 15, 0, 0)},
		// 2025-04-06 02:00 LHDT (+11:00) -> 01:30 LHST (+10:30).
		{"Lord Howe 30-minute fold chooses the first", lord, utc(2025, 4, 5, 12, 0, 0, 0), 1, 45, utc(2025, 4, 5, 14, 45, 0, 0)},
		{"Lord Howe fold boundary: 02:00 happens once", lord, utc(2025, 4, 5, 12, 0, 0, 0), 2, 0, utc(2025, 4, 5, 15, 30, 0, 0)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := nextLocal(c.after, c.loc, c.hour, c.minute)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("got %s want %s", show(got), show(c.want))
			}
		})
	}
	// The result is always at or after the transition and a real local time:
	// a local time strictly inside a gap never resolves into the gap.
	for m := 0; m < 60; m += 5 {
		got, err := nextLocal(utc(2025, 3, 8, 12, 0, 0, 0), ny, 2, m)
		if err != nil {
			t.Fatal(err)
		}
		if got != utc(2025, 3, 9, 7, 0, 0, 0) {
			t.Fatalf("02:%02d resolved to %s", m, show(got))
		}
	}
}

func mustLoad(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := location(name)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return loc
}

func TestDigestScheduleInvariantsAcrossZonesAndYears(t *testing.T) {
	zones := []string{
		"UTC", "America/New_York", "America/Los_Angeles", "America/Sao_Paulo", "America/St_Johns", "Europe/London", "Europe/Berlin",
		"Europe/Moscow", "Africa/Cairo", "Asia/Tehran", "Asia/Kolkata", "Asia/Kathmandu", "Asia/Tokyo", "Australia/Adelaide",
		"Australia/Lord_Howe", "Pacific/Auckland", "Pacific/Chatham", "Pacific/Apia", "Pacific/Kiritimati", "Pacific/Pago_Pago",
	}
	for _, zone := range zones {
		t.Run(zone, func(t *testing.T) {
			loc := mustLoad(t, zone)
			after := utc(2024, 1, 1, 0, 0, 0, 0)
			var prevDate uint32
			for range 800 {
				next, err := NextDigest(after, zone)
				if err != nil {
					t.Fatal(err)
				}
				if next <= after {
					t.Fatalf("not strictly after: %s <= %s", show(next), show(after))
				}
				if gap := next - after; gap > model.UnixNano(49*time.Hour) {
					// Only a vanished civil date may stretch beyond two days.
					t.Fatalf("gap of %v after %s", time.Duration(gap), show(after))
				}
				local := time.Unix(0, int64(next)).In(loc)
				date := localDate(next, loc)
				if local.Hour() != DigestHour || local.Minute() != 0 {
					// A gap at 09:00 would resolve to the transition; real zones
					// do not change at 09:00, so this must not happen here.
					t.Fatalf("digest at %s local %s", show(next), local)
				}
				if date <= prevDate {
					t.Fatalf("two digests on local date %d", date)
				}
				prevDate, after = date, next
			}
		})
	}
}

func TestDigestZoneErrorsAreTyped(t *testing.T) {
	for _, zone := range []string{"Mars/Olympus", "america/new_york", "../etc/passwd", "/etc/localtime", "Local", "UTC ", "Europe/Berlin\x00", strings.Repeat("A", 65), "..", "America//New_York", "Europe/Ber lin", "America/New_York.zip"} {
		t.Run(zone, func(t *testing.T) {
			got, err := NextDigest(utc(2026, 1, 1, 0, 0, 0, 0), zone)
			var typed *Error
			if !errors.As(err, &typed) || typed.Reason != ReasonInvalidZone || typed.Code != model.Invalid || got != 0 {
				t.Fatalf("zone %q: got %v, %v", zone, got, err)
			}
			if _, err := LocalDate(utc(2026, 1, 1, 0, 0, 0, 0), zone); !errors.Is(err, &Error{Reason: ReasonInvalidZone}) {
				t.Fatalf("LocalDate(%q): %v", zone, err)
			}
			var f *model.Fault
			if !errors.As(err, &f) || f.Code != model.Invalid {
				t.Fatalf("typed error must unwrap to the shared fault: %v", err)
			}
		})
	}
}

func TestDigestDoesNotDependOnTheHost(t *testing.T) {
	// The pinned dataset is used, never the host's: poisoning every host
	// lookup must not change a result.
	want, err := NextDigest(utc(2025, 3, 8, 14, 0, 0, 0), "America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ZONEINFO", "/nonexistent/zoneinfo.zip")
	t.Setenv("TZ", "Asia/Tokyo")
	zoneCache.Clear()
	got, err := NextDigest(utc(2025, 3, 8, 14, 0, 0, 0), "America/New_York")
	if err != nil || got != want {
		t.Fatalf("got %v %v want %v", got, err, want)
	}
	if got != utc(2025, 3, 9, 13, 0, 0, 0) {
		t.Fatalf("unexpected %s", show(got))
	}
}

func TestDigestTimeArithmeticOverflow(t *testing.T) {
	max := model.UnixNano(math.MaxInt64)
	// The last representable instant is 2262-04-11T23:47:16.854775807Z.
	cases := []struct {
		name  string
		after model.UnixNano
		zone  string
		ok    bool
		want  model.UnixNano
	}{
		{"at the end of time", max, "UTC", false, 0},
		{"just before the end of time", max - 1, "UTC", false, 0},
		{"the last digest that fits", utc(2262, 4, 10, 10, 0, 0, 0), "UTC", true, utc(2262, 4, 11, 9, 0, 0, 0)},
		{"the next digest does not fit", utc(2262, 4, 11, 10, 0, 0, 0), "UTC", false, 0},
		{"a zone east of UTC near the end", utc(2262, 4, 11, 20, 0, 0, 0), "Pacific/Kiritimati", false, 0},
		{"the first representable instant", model.UnixNano(math.MinInt64), "UTC", true, utc(1677, 9, 21, 9, 0, 0, 0)},
		{"before the epoch", utc(1900, 6, 1, 10, 0, 0, 0), "UTC", true, utc(1900, 6, 2, 9, 0, 0, 0)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := NextDigest(c.after, c.zone)
			if c.ok {
				if err != nil || got != c.want {
					t.Fatalf("got %s %v want %s", show(got), err, show(c.want))
				}
				return
			}
			var typed *Error
			if !errors.As(err, &typed) || typed.Reason != ReasonTimeRange || got != 0 {
				t.Fatalf("must be a typed range error, got %d %v", got, err)
			}
		})
	}
	if got := mulOK(t, 3, 4); got != 12 {
		t.Fatal(got)
	}
	if _, ok := mulNano(math.MaxInt64, 2); ok {
		t.Fatal("multiplication overflow went undetected")
	}
	if _, ok := mulNano(math.MaxInt64, math.MaxInt64); ok {
		t.Fatal("a product past 64 bits went undetected")
	}
	if _, ok := mulNano(1<<32, 1<<32); ok {
		t.Fatal("a product of exactly 2^64 went undetected")
	}
	if _, ok := mulNano(-1, 2); ok {
		t.Fatal("negative operand accepted")
	}
	if _, ok := addNano(math.MaxInt64, 1); ok {
		t.Fatal("addition overflow went undetected")
	}
	if _, ok := addNano(math.MinInt64, -1); ok {
		t.Fatal("negative overflow went undetected")
	}
	if v, ok := addNano(math.MaxInt64-1, 1); !ok || v != math.MaxInt64 {
		t.Fatal("the largest sum must be accepted")
	}
}

func mulOK(t *testing.T, a, k model.UnixNano) model.UnixNano {
	t.Helper()
	v, ok := mulNano(a, k)
	if !ok {
		t.Fatal("mulNano")
	}
	return v
}

func TestDigestLocalDate(t *testing.T) {
	cases := []struct {
		at   model.UnixNano
		zone string
		want uint32
	}{
		{utc(2026, 3, 10, 23, 59, 59, 0), "UTC", 20260310},
		{utc(2026, 3, 10, 23, 59, 59, 0), "Asia/Kolkata", 20260311},
		{utc(2026, 3, 10, 0, 0, 0, 0), "America/New_York", 20260309},
		{utc(2028, 2, 29, 12, 0, 0, 0), "", 20280229},
	}
	for _, c := range cases {
		got, err := LocalDate(c.at, c.zone)
		if err != nil || got != c.want {
			t.Fatalf("LocalDate(%s,%q) = %d %v, want %d", show(c.at), c.zone, got, err, c.want)
		}
	}
}

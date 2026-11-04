// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"soundpost/internal/query/profile"
	timezone "soundpost/third_party/timezone/go124"
)

// Named locations must come from the exact selected compiler dataset, never the
// operating system database or this executable's compiler's embedded database.
func loadLogQLLocation(name string, p profile.Profile) (*time.Location, string, error) {
	if name == "" || name == "UTC" {
		return time.UTC, "", nil
	}
	raw, actual, err := logQLTimezoneDataset(p)
	if err != nil {
		return nil, "", err
	}
	z, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, "", err
	}
	for _, f := range z.File {
		if f.Name != name {
			continue
		}
		r, e := f.Open()
		if e != nil {
			return nil, "", e
		}
		data, e := io.ReadAll(io.LimitReader(r, (1<<20)+1))
		closeErr := r.Close()
		if e != nil {
			return nil, "", e
		}
		if closeErr != nil {
			return nil, "", closeErr
		}
		if len(data) > 1<<20 {
			return nil, "", fmt.Errorf("timezone entry exceeds bound")
		}
		loc, e := time.LoadLocationFromTZData(name, data)
		return loc, actual, e
	}
	return nil, "", fmt.Errorf("timezone absent from pinned dataset: %s", name)
}
func logQLTimezoneDataset(p profile.Profile) ([]byte, string, error) {
	var path, want string
	if json.Unmarshal(p.Configuration["timezone_dataset_path"], &path) != nil || json.Unmarshal(p.Configuration["timezone_dataset_sha256"], &want) != nil || path == "" || len(want) != 64 {
		return nil, "", fmt.Errorf("explicit pinned Go1.24.5 timezone dataset required")
	}
	clean := filepath.Clean(path)
	if filepath.IsAbs(path) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, "", fmt.Errorf("timezone dataset path must be repository-relative")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, "", e
	}
	sum := sha256.Sum256(raw)
	actual := hex.EncodeToString(sum[:])
	if actual != want || timezone.DatasetDigest() != want {
		return nil, "", fmt.Errorf("actual selected/embedded timezone bytes differ from profile")
	}
	return raw, actual, nil
}
func clockBounds(o LogQLObservation) (time.Time, time.Time, error) {
	start, e := strconv.ParseInt(o.ClockStart, 10, 64)
	if e != nil {
		return time.Time{}, time.Time{}, e
	}
	end, e := strconv.ParseInt(o.ClockEnd, 10, 64)
	if e != nil || end < start {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid actual wall-clock bracket")
	}
	return time.Unix(0, start), time.Unix(0, end), nil
}
func compareLogQLClock(c LogQLCase, a, b LogQLObservation) error {
	return compareLogQLClockAt(c, a, b, time.UTC)
}
func compareLogQLClockAt(c LogQLCase, a, b LogQLObservation, loc *time.Location) error {
	if c.Clock == nil {
		return fmt.Errorf("undeclared clock observation")
	}
	check := func(o LogQLObservation) (string, string, error) {
		lo, hi, e := clockBounds(o)
		if e != nil {
			return "", "", e
		}
		switch c.Clock.Kind {
		case "unix", "unix-seconds":
			n, e := strconv.ParseInt(o.Output, 10, 64)
			if e != nil || n < lo.Unix() || n > hi.Unix() {
				return "", "", fmt.Errorf("now observation outside actual process wall bracket")
			}
			return "", "", nil
		case "calendar":
			if c.Clock.Layout == "" {
				return "", "", fmt.Errorf("calendar observation requires layout")
			}
			left, right := lo.In(loc).Format(c.Clock.Layout), hi.In(loc).Format(c.Clock.Layout)
			// Only qualify intervals that do not cross the declared observation unit.
			// A crossing boundary is not permission to accept arbitrary intermediate text.
			if o.Output != left && o.Output != right {
				return "", "", fmt.Errorf("calendar now outside declared wall-clock/layout bracket")
			}
			if hi.Sub(lo) > time.Second {
				return "", "", fmt.Errorf("calendar wall-clock bracket too wide to qualify endpoints")
			}
			return left, right, nil
		default:
			return "", "", fmt.Errorf("unsupported declared clock observation %q", c.Clock.Kind)
		}
	}
	al, ah, e := check(a)
	if e != nil {
		return e
	}
	bl, bh, e := check(b)
	if e != nil {
		return e
	}
	if c.Clock.Kind == "calendar" && al == ah && bl == bh && al == bl && a.Output != b.Output {
		return fmt.Errorf("calendar outputs differ inside same declared unit")
	}
	return nil
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package issues

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"path"
	"soundpost/internal/model"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Fingerprint consumes already-admitted safe code identities, newest/innermost
// frame first. It does not resolve artifacts, authorize callers, read exception
// graphs, or inspect values/messages. Callers must supply C02-authorized scope
// and C04-admitted code/template identities, never arbitrary exception text.
func Fingerprint(version uint16, org, project model.ID, occurrence model.ErrorOccurrence) ([32]byte, error) {
	if version == 0 || org == (model.ID{}) || project == (model.ID{}) || !safeIdentity(occurrence.Class, 256) || len(occurrence.Frames) > 128 {
		return [32]byte{}, model.Fail(model.Invalid)
	}
	if occurrence.Code != nil && !safeIdentity(*occurrence.Code, 256) {
		return [32]byte{}, model.Fail(model.Invalid)
	}
	h := sha256.New()
	writePart(h, "soundpost.error-grouping")
	h.Write(org[:])
	h.Write(project[:])
	var v [2]byte
	binary.BigEndian.PutUint16(v[:], version)
	h.Write(v[:])
	writePart(h, occurrence.Class)
	count := 0
	for _, frame := range occurrence.Frames {
		if !frame.InApp {
			continue
		}
		if count == 8 {
			break
		}
		if !safeIdentity(frame.Module, 256) || !safeIdentity(frame.Function, 256) || !safeArtifact(frame.Artifact) {
			return [32]byte{}, model.Fail(model.Invalid)
		}
		count++
	}
	h.Write([]byte{byte(count)})
	if count > 0 {
		used := 0
		for _, frame := range occurrence.Frames {
			if !frame.InApp {
				continue
			}
			if used == count {
				break
			}
			used++
			writePart(h, frame.Module)
			writePart(h, frame.Artifact)
			writePart(h, frame.Function)
		}
	} else {
		if !safeIdentity(occurrence.Mechanism, 256) {
			return [32]byte{}, model.Fail(model.Invalid)
		}
		writePart(h, occurrence.Mechanism)
		if occurrence.Template == nil {
			h.Write([]byte{0})
		} else {
			if !safeIdentity(*occurrence.Template, 256) {
				return [32]byte{}, model.Fail(model.Invalid)
			}
			h.Write([]byte{1})
			writePart(h, *occurrence.Template)
		}
	}
	if occurrence.Code == nil {
		h.Write([]byte{0})
	} else {
		h.Write([]byte{1})
		writePart(h, *occurrence.Code)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out, nil
}
func writePart(h hash.Hash, value string) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(value)))
	h.Write(n[:])
	h.Write([]byte(value))
}
func safeIdentity(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.:/<>-+ $", c)) {
			return false
		}
	}
	return true
}
func safeArtifact(value string) bool {
	if value == "" || len(value) > 512 || !utf8.ValidString(value) || strings.ContainsAny(value, "\\:?#\x00") || strings.HasPrefix(value, "/") || path.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

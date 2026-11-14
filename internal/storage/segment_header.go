// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"encoding/binary"
	"github.com/arynyklas/soundpost/internal/model"
	"hash/crc32"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

const segmentHeaderSize = 112
const dayNanos = int64(24*60*60) * 1_000_000_000

func segmentDay(at model.UnixNano) string {
	n := int64(at)
	day := n / dayNanos
	if n < 0 && n%dayNanos != 0 {
		day--
	}
	return strconv.FormatInt(day, 10)
}
func segmentName(org, project model.ID, signal model.Kind, start model.UnixNano, id model.ID) string {
	return path.Join(org.String(), project.String(), string(signal), segmentDay(start), id.String()+".sps")
}
func segmentPath(dir, name string) (string, error) {
	if name == "" || path.Clean(name) != name || strings.Contains(name, "\\") || path.IsAbs(name) {
		return "", model.Fail(model.Corrupt)
	}
	parts := strings.Split(name, "/")
	if len(parts) != 5 || !model.Kind(parts[2]).Valid() {
		return "", model.Fail(model.Corrupt)
	}
	for _, p := range parts[:2] {
		if _, err := model.ParseID(p); err != nil {
			return "", model.Fail(model.Corrupt)
		}
	}
	day, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || strconv.FormatInt(day, 10) != parts[3] {
		return "", model.Fail(model.Corrupt)
	}
	if path.Ext(parts[4]) != ".sps" {
		return "", model.Fail(model.Corrupt)
	}
	if _, err = model.ParseID(strings.TrimSuffix(parts[4], ".sps")); err != nil {
		return "", model.Fail(model.Corrupt)
	}
	return filepath.Join(dir, "segments", filepath.FromSlash(name)), nil
}
func sameSegmentNamespace(a, b pageRef) bool {
	return a.Org == b.Org && a.Project == b.Project && a.Source == b.Source && a.Kind == b.Kind && a.Subject == b.Subject && a.Restricted == b.Restricted && a.PolicyRevision == b.PolicyRevision && segmentDay(a.Start) == segmentDay(b.Start)
}
func segmentHeader(ref pageRef, start, end model.UnixNano, rows uint64) []byte {
	h := make([]byte, segmentHeaderSize)
	copy(h, "SPS1")
	binary.BigEndian.PutUint16(h[4:6], 1)
	binary.BigEndian.PutUint16(h[6:8], segmentHeaderSize)
	copy(h[8:24], ref.Org[:])
	copy(h[24:40], ref.Project[:])
	copy(h[40:56], ref.Source[:])
	h[56] = signalCode(ref.Kind)
	if ref.Restricted {
		h[57] = 1
	}
	binary.BigEndian.PutUint16(h[58:60], 1)
	binary.BigEndian.PutUint64(h[60:68], uint64(ref.PolicyRevision))
	binary.BigEndian.PutUint64(h[68:76], uint64(start))
	binary.BigEndian.PutUint64(h[76:84], uint64(end))
	binary.BigEndian.PutUint64(h[84:92], rows)
	h[92] = signalCode(ref.Subject)
	binary.BigEndian.PutUint32(h[108:112], crc32.Checksum(h[:108], pageCRC))
	return h
}
func checkSegmentHeader(h []byte, ref pageRef) error {
	if len(h) != segmentHeaderSize || !bytes.Equal(h[:4], []byte("SPS1")) || binary.BigEndian.Uint16(h[4:6]) != 1 || binary.BigEndian.Uint16(h[6:8]) != segmentHeaderSize || binary.BigEndian.Uint16(h[58:60]) != 1 || binary.BigEndian.Uint64(h[60:68]) != uint64(ref.PolicyRevision) || crc32.Checksum(h[:108], pageCRC) != binary.BigEndian.Uint32(h[108:]) {
		return model.Fail(model.Corrupt)
	}
	raw := byte(0)
	if ref.Restricted {
		raw = 1
	}
	if !bytes.Equal(h[8:24], ref.Org[:]) || !bytes.Equal(h[24:40], ref.Project[:]) || !bytes.Equal(h[40:56], ref.Source[:]) || h[56] != signalCode(ref.Kind) || h[57] != raw || h[92] != signalCode(ref.Subject) || !bytes.Equal(h[93:108], make([]byte, 15)) {
		return model.Fail(model.Corrupt)
	}
	start, end := model.UnixNano(binary.BigEndian.Uint64(h[68:76])), model.UnixNano(binary.BigEndian.Uint64(h[76:84]))
	if start > end || ref.Start < start || ref.End > end || binary.BigEndian.Uint64(h[84:92]) < uint64(ref.Count) || segmentDay(start) != segmentDay(ref.Start) {
		return model.Fail(model.Corrupt)
	}
	// File namespace and immutable header namespace must agree before page bytes.
	id, err := model.ParseID(strings.TrimSuffix(path.Base(ref.Segment), ".sps"))
	if err != nil || ref.Segment != segmentName(ref.Org, ref.Project, ref.Kind, start, id) {
		return model.Fail(model.Corrupt)
	}
	return nil
}
func verifySegmentFileHeader(filePath string, s SegmentManifest) error {
	f, err := os.Open(filePath)
	if err != nil {
		return model.Fail(model.Corrupt)
	}
	defer f.Close()
	var h [segmentHeaderSize]byte
	if _, err = io.ReadFull(f, h[:]); err != nil {
		return model.Fail(model.Corrupt)
	}
	ref := pageRef{Org: s.Org, Project: s.Project, Source: s.Source, Kind: s.Signal, Subject: s.Subject, Restricted: s.Restricted, PolicyRevision: s.PolicyRevision}
	if !bytes.Equal(h[:], segmentHeader(ref, s.Start, s.End, s.Rows)) {
		return model.Fail(model.Corrupt)
	}
	return nil
}

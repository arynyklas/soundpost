// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"github.com/arynyklas/soundpost/internal/durablefs"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
	"os"
	"path"
	"path/filepath"
)

func (e *Engine) readPage(ref pageRef) (Page, error) { return e.readPageColumns(ref, true, true) }
func (e *Engine) readPageColumns(ref pageRef, resources, payload bool) (Page, error) {
	var data []byte
	if ref.Segment == "" {
		data = ref.Hot
		if len(data) == 0 {
			return Page{}, model.Fail(model.Corrupt)
		}
	} else {
		path, err := segmentPath(e.dir, ref.Segment)
		if err != nil {
			return Page{}, err
		}
		f, err := os.Open(path)
		if err != nil {
			return Page{}, model.Fail(model.Corrupt)
		}
		defer f.Close()
		var h [segmentHeaderSize]byte
		if _, err = io.ReadFull(f, h[:]); err != nil {
			return Page{}, model.Fail(model.Corrupt)
		}
		if err = checkSegmentHeader(h[:], ref); err != nil {
			return Page{}, err
		}
		if ref.Offset < segmentHeaderSize || ref.Length < pageHeaderSize || ref.Length > pageByteLimit {
			return Page{}, model.Fail(model.Corrupt)
		}
		data = make([]byte, int(ref.Length))
		if _, err = f.ReadAt(data, ref.Offset); err != nil {
			return Page{}, model.Fail(model.Corrupt)
		}
	}
	if uint32(len(data)) != ref.Length || model.HashCanonical(data) != ref.Hash {
		return Page{}, model.Fail(model.Corrupt)
	}
	p, err := decodePageColumns(data, resources, payload)
	if err != nil {
		return Page{}, err
	}
	if p.Len() != int(ref.Count) {
		return Page{}, model.Fail(model.Corrupt)
	}
	for i := range p.IDs {
		if p.Projects[i] != ref.Project || p.Sources[i] != ref.Source {
			return Page{}, model.Fail(model.Corrupt)
		}
		if payload {
			if _, err = p.Values[i].Value(ref.Kind); err != nil {
				return Page{}, model.Fail(model.Corrupt)
			}
			if payloadSubject(&p.Values[i]) != ref.Subject {
				return Page{}, model.Fail(model.Corrupt)
			}
			if p.Values[i].Log != nil && (p.Values[i].Log.SourceClass == "restricted_raw") != ref.Restricted {
				return Page{}, model.Fail(model.Corrupt)
			}
		}
	}
	e.storageStats.PagesRead++
	e.storageStats.BytesRead += uint64(len(data))
	return p, nil
}
func (e *Engine) writeSegment(ctx context.Context, refs []pageRef) ([]pageRef, SegmentManifest, error) {
	if len(refs) == 0 {
		return nil, SegmentManifest{}, model.Fail(model.Invalid)
	}
	if ctx.Err() != nil {
		return nil, SegmentManifest{}, model.Fail(model.Cancelled)
	}
	first := refs[0]
	start, end := first.Start, first.End
	var rows uint64
	for _, ref := range refs {
		if !sameSegmentNamespace(first, ref) {
			return nil, SegmentManifest{}, model.Fail(model.Invalid)
		}
		if ref.Start < start {
			start = ref.Start
		}
		if ref.End > end {
			end = ref.End
		}
		rows += uint64(ref.Count)
	}
	id := model.NewID()
	name := segmentName(first.Org, first.Project, first.Kind, start, id)
	dir := filepath.Join(e.dir, "segments", filepath.FromSlash(path.Dir(name)))
	if err := durablefs.MkdirAll(dir); err != nil {
		return nil, SegmentManifest{}, err
	}
	filePath, err := segmentPath(e.dir, name)
	if err != nil {
		return nil, SegmentManifest{}, err
	}
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, SegmentManifest{}, err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = durablefs.Remove(filePath)
		}
	}()
	header := segmentHeader(first, start, end, rows)
	if n, err := f.Write(header); err != nil {
		return nil, SegmentManifest{}, err
	} else if n != len(header) {
		return nil, SegmentManifest{}, io.ErrShortWrite
	}
	offset := int64(len(header))
	out := make([]pageRef, 0, len(refs))
	manifest := SegmentManifest{ID: id, File: name, Org: first.Org, Project: first.Project, Source: first.Source, Signal: first.Kind, Subject: first.Subject, Restricted: first.Restricted, PolicyRevision: first.PolicyRevision, Format: 1, Start: start, End: end, RetainUntil: first.RetainUntil, Rows: rows}
	for _, metadata := range refs {
		if ctx.Err() != nil {
			return nil, SegmentManifest{}, model.Fail(model.Cancelled)
		}
		ref, err := e.loadRefLocked(metadata.ID)
		if err != nil {
			return nil, SegmentManifest{}, err
		}
		if !sameSegmentNamespace(ref, first) {
			return nil, SegmentManifest{}, model.Fail(model.Invalid)
		}
		p, err := e.readPage(ref)
		if err != nil {
			return nil, SegmentManifest{}, err
		}
		b, err := encodePage(p)
		if err != nil {
			return nil, SegmentManifest{}, err
		}
		if n, err := f.Write(b); err != nil {
			return nil, SegmentManifest{}, err
		} else if n != len(b) {
			return nil, SegmentManifest{}, io.ErrShortWrite
		}
		ref.Offset = offset
		ref.Length = uint32(len(b))
		ref.Hash = model.HashCanonical(b)
		ref.Segment = name
		ref.Hot = nil
		out = append(out, ref)
		manifest.Pages = append(manifest.Pages, ref.ID)
		offset += int64(len(b))
		if ref.Start < manifest.Start {
			manifest.Start = ref.Start
		}
		if ref.End > manifest.End {
			manifest.End = ref.End
		}
		if ref.RetainUntil > manifest.RetainUntil {
			manifest.RetainUntil = ref.RetainUntil
		}
	}
	if ctx.Err() != nil {
		return nil, SegmentManifest{}, model.Fail(model.Cancelled)
	}
	if err = e.trip("segment_sync"); err != nil {
		return nil, SegmentManifest{}, err
	}
	if err = f.Sync(); err != nil {
		return nil, SegmentManifest{}, err
	}
	if err = f.Close(); err != nil {
		return nil, SegmentManifest{}, err
	}
	if err = durablefs.SyncDir(dir); err != nil {
		return nil, SegmentManifest{}, err
	}
	manifest.Bytes = uint64(offset)
	hash, err := hashFile(filePath)
	if err != nil {
		return nil, SegmentManifest{}, err
	}
	manifest.Checksum = hash
	ok = true
	return out, manifest, nil
}
func hashFile(path string) (model.Hash, error) {
	f, err := os.Open(path)
	if err != nil {
		return model.Hash{}, err
	}
	defer f.Close()
	h := newFileHash()
	if _, err = io.Copy(h, f); err != nil {
		return model.Hash{}, err
	}
	var out model.Hash
	copy(out[:], h.Sum(nil))
	return out, nil
}

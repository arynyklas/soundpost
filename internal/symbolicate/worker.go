// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/sourcemap"
	"io"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
	"unicode/utf8"
)

type workerInput struct {
	Version        uint16     `json:"version"`
	Map            []byte     `json:"map"`
	MapHash        model.Hash `json:"map_hash"`
	Line           uint32     `json:"line"`
	Column         uint32     `json:"column"`
	IncludeSources bool       `json:"include_sources"`
	Sources        []byte     `json:"sources,omitempty"`
	SourcesHash    model.Hash `json:"sources_hash"`
}
type workerOutput struct {
	Reason        Reason        `json:"reason"`
	Position      *CodeIdentity `json:"position,omitempty"`
	SourceContext *string       `json:"source_context,omitempty"`
}

func resolveInput(in workerInput) workerOutput {
	if in.Version != 1 || in.Line == 0 {
		return workerOutput{Reason: InvalidMap}
	}
	if len(in.Map) == 0 || len(in.Map)+len(in.Sources) > MaxMapBytes {
		return workerOutput{Reason: ResourceLimit}
	}
	if model.HashCanonical(in.Map) != in.MapHash || len(in.Sources) > 0 && model.HashCanonical(in.Sources) != in.SourcesHash {
		return workerOutput{Reason: CorruptArtifact}
	}
	decoded, e := sourcemap.Decode(bytes.NewReader(in.Map), sourcemap.Limits{MaxBytes: MaxMapBytes, MaxFiles: 1024, MaxDepth: 8})
	if e != nil {
		if errors.Is(e, sourcemap.ErrLimit) {
			return workerOutput{Reason: ResourceLimit}
		}
		return workerOutput{Reason: InvalidMap}
	}
	p, ok, e := decoded.Lookup(in.Line, in.Column)
	if e != nil {
		return workerOutput{Reason: InvalidMap}
	}
	if !ok {
		return workerOutput{Reason: Unmapped}
	}
	out := workerOutput{Reason: Resolved, Position: &CodeIdentity{Source: p.SourceID, Function: p.Name, Line: p.Line, Column: p.Column}}
	if in.IncludeSources {
		if len(in.Sources) == 0 {
			return workerOutput{Reason: SourceDenied}
		}
		var doc sourceDocument
		if json.Unmarshal(in.Sources, &doc) != nil {
			return workerOutput{Reason: CorruptArtifact}
		}
		out.SourceContext = doc.context(in.Line-1, in.Column, p.SourceID, p.Line, 1)
	}
	return out
}

type sourceDocument struct {
	Sources  []string  `json:"sources"`
	Root     string    `json:"sourceRoot"`
	Content  []*string `json:"sourcesContent"`
	Sections []struct {
		Offset struct {
			Line   uint32 `json:"line"`
			Column uint32 `json:"column"`
		} `json:"offset"`
		Map json.RawMessage `json:"map"`
	} `json:"sections"`
}

func (d sourceDocument) context(line, column uint32, id string, sourceLine uint32, depth int) *string {
	if depth > 8 {
		return nil
	}
	if len(d.Sections) > 0 {
		selected := -1
		for i, s := range d.Sections {
			if s.Offset.Line < line || s.Offset.Line == line && s.Offset.Column <= column {
				selected = i
			}
		}
		if selected < 0 {
			return nil
		}
		s := d.Sections[selected]
		line -= s.Offset.Line
		if line == 0 {
			column -= s.Offset.Column
		}
		var child sourceDocument
		if json.Unmarshal(s.Map, &child) != nil {
			return nil
		}
		return child.context(line, column, id, sourceLine, depth+1)
	}
	selected := -1
	for i, s := range d.Sources {
		r, e := url.PathUnescape(d.Root)
		if e != nil {
			return nil
		}
		v, e := url.PathUnescape(s)
		if e != nil {
			return nil
		}
		if path.Clean(path.Join(r, v)) == id {
			if selected >= 0 {
				return nil
			}
			selected = i
		}
	}
	if selected < 0 || selected >= len(d.Content) || d.Content[selected] == nil || sourceLine == 0 {
		return nil
	}
	text := *d.Content[selected]
	for n := uint32(1); n < sourceLine; n++ {
		i := strings.IndexByte(text, '\n')
		if i < 0 {
			return nil
		}
		text = text[i+1:]
	}
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		text = text[:i]
	}
	text = strings.TrimSuffix(text, "\r")
	if len(text) > 4096 {
		text = text[:4096]
		for !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
	}
	return &text
}

// WorkerMain is the fixed executable entry. Only pipes are read; neither map
// identity nor source names are ever opened. Sandbox installation precedes DTO
// decoding. Failure never runs the decoder unconstrained.
func WorkerMain() int {
	processTimer := time.AfterFunc(ProcessTimeout, func() { os.Exit(124) })
	defer processTimer.Stop()
	digest, e := executableHash()
	if e != nil {
		return 70
	}
	var ack [1]byte
	if _, e = io.ReadFull(os.Stdin, ack[:]); e != nil || ack[0] != 'A' {
		return 70
	}
	if e = installSandbox(); e != nil {
		os.Stdout.Write([]byte{'U'})
		return 71
	}
	if _, e = os.Stdout.Write(append([]byte{'R'}, digest[:]...)); e != nil {
		return 70
	}
	frameTimer := time.AfterFunc(FrameTimeout, func() { os.Exit(124) })
	defer frameTimer.Stop()
	var in workerInput
	if e = decodeClosed(os.Stdin, &in, MaxInputBytes); e != nil {
		return 72
	}
	out := resolveInput(in)
	if e = json.NewEncoder(os.Stdout).Encode(out); e != nil {
		return 70
	}
	return 0
}
func executableHash() (model.Hash, error) {
	var h model.Hash
	name, e := os.Executable()
	if e != nil {
		return h, e
	}
	f, e := os.Open(name)
	if e != nil {
		return h, e
	}
	defer f.Close()
	sum := sha256.New()
	if _, e = io.Copy(sum, f); e != nil {
		return h, e
	}
	copy(h[:], sum.Sum(nil))
	return h, nil
}

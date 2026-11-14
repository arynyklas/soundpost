// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"

	"github.com/arynyklas/soundpost/internal/model"
)

// entry is one transient acquired message. Its bytes are zeroed as soon as it
// has been classified; nothing keeps them.
type entry struct {
	msg []byte
	at  model.UnixNano // source timestamp, zero when the source gave none
	tag string         // journal identifier/unit, empty for files
}

// acquired is what one acquisition produced: the transient entries, the
// position just after them, and the gaps/drops found on the way.
type acquired struct {
	entries []entry
	to      Position
	scanned uint32
	gaps    []Gap
	dropped map[string]uint64
}

const (
	tailBytes = 64
	readChunk = 64 << 10
)

type candidate struct {
	f    *os.File
	id   string
	size int64
	live bool
}

type candidateSet struct {
	live          *candidate
	rotated       []*candidate
	liveDenied    bool
	rotatedDenied bool
}

func (c *candidateSet) all() []*candidate {
	var out []*candidate
	if c.live != nil {
		out = append(out, c.live)
	}
	return append(out, c.rotated...)
}

func (c *candidateSet) close() {
	for _, x := range c.all() {
		x.f.Close()
	}
}

// openCandidate opens a regular file. A FIFO or device is refused before it is
// opened, because opening it could block forever.
func openCandidate(path string, live bool) (*candidate, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errNotRegular
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err = f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, errNotRegular
	}
	id, err := fileID(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &candidate{f: f, id: id, size: st.Size(), live: live}, nil
}

var errNotRegular = errors.New("not a regular file")

// openCandidates opens the live file and every present rotated path. Errors
// are folded into the set's flags; no OS error text survives.
func openCandidates(path string, rotated []string) (*candidateSet, error) {
	set := &candidateSet{}
	live, err := openCandidate(path, true)
	switch {
	case err == nil:
		set.live = live
	case errors.Is(err, fs.ErrNotExist):
	case errors.Is(err, fs.ErrPermission):
		set.liveDenied = true
	default:
		return nil, errReadFailed
	}
	for _, r := range rotated {
		c, err := openCandidate(r, false)
		switch {
		case err == nil:
			set.rotated = append(set.rotated, c)
		case errors.Is(err, fs.ErrNotExist):
		case errors.Is(err, fs.ErrPermission):
			set.rotatedDenied = true
		default:
			set.close()
			return nil, errReadFailed
		}
	}
	return set, nil
}

var errReadFailed = errors.New("read failed")

// tailHash hashes up to the 64 bytes before offset. Empty for offset zero.
func tailHash(f *os.File, offset int64) (string, error) {
	if offset <= 0 {
		return "", nil
	}
	n := int64(tailBytes)
	if offset < n {
		n = offset
	}
	buf := make([]byte, n)
	defer clear(buf)
	if _, err := f.ReadAt(buf, offset-n); err != nil {
		return "", err
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:16]), nil
}

func verifyTail(f *os.File, size, offset int64, want string) bool {
	if offset == 0 {
		return want == ""
	}
	if size < offset || want == "" {
		return false
	}
	got, err := tailHash(f, offset)
	return err == nil && got == want
}

type locateStatus int

const (
	locateOK locateStatus = iota
	locateGap
	locateDenied
	locateMissing
)

// locate finds where the committed position continues: the same file (same
// identity and tail), a rotated predecessor, or a copy of the file whose bytes
// before the offset match the committed tail. If nothing continues it, unread
// bytes were lost: the answer is a gap and a restart at the live file's start.
func (c *candidateSet) locate(pos Position) (*candidate, int64, locateStatus) {
	var byID *candidate
	for _, x := range c.all() {
		if x.id == pos.File {
			byID = x
			break
		}
	}
	if byID != nil && verifyTail(byID.f, byID.size, pos.Offset, pos.Tail) {
		return byID, pos.Offset, locateOK
	}
	if pos.Tail != "" {
		for _, x := range c.all() {
			if x != byID && verifyTail(x.f, x.size, pos.Offset, pos.Tail) {
				return x, pos.Offset, locateOK
			}
		}
	}
	if byID == nil && c.rotatedDenied {
		return nil, 0, locateDenied
	}
	if c.live == nil {
		if c.liveDenied {
			return nil, 0, locateDenied
		}
		return nil, 0, locateMissing
	}
	return c.live, 0, locateGap
}

// acquireFile reads up to limit lines of one file (or its rotated chain) from
// the committed position of cp. It never moves the committed position itself.
func acquireFile(ctx context.Context, p SourcePolicy, path string, rotated []string, startAt string, cp Checkpoint, limit int) (acquired, error) {
	acq := acquired{dropped: map[string]uint64{}}
	cands, err := openCandidates(path, rotated)
	if err != nil {
		return acq, newError(p.Name, StatusUnknown, ReasonReadFailed)
	}
	defer cands.close()
	missing := func() error {
		if cands.liveDenied {
			return newError(p.Name, StatusDenied, ReasonPermission)
		}
		return newError(p.Name, StatusUnknown, ReasonNotPresent)
	}
	pos := cp.Position
	var cont *candidate
	var offset int64
	skip := pos.Skip
	gap := false
	switch {
	case !pos.Started:
		if cands.live == nil {
			return acq, missing()
		}
		if startAt != StartBeginning {
			tail, err := tailHash(cands.live.f, cands.live.size)
			if err != nil {
				return acq, newError(p.Name, StatusUnknown, ReasonReadFailed)
			}
			acq.to = Position{Started: true, File: cands.live.id, Offset: cands.live.size, Tail: tail}
			return acq, nil
		}
		cont, offset, skip = cands.live, 0, false
	case pos.Final:
		if cands.live == nil {
			return acq, missing()
		}
		cont, offset, skip = cands.live, 0, false
	default:
		var st locateStatus
		cont, offset, st = cands.locate(pos)
		switch st {
		case locateDenied:
			return acq, newError(p.Name, StatusDenied, ReasonPermission)
		case locateMissing:
			return acq, missing()
		case locateGap:
			gap, skip = true, false
		}
		if st == locateOK && cont != nil && cont.id != pos.File {
			skip = pos.Skip
		}
	}
	if err := ctx.Err(); err != nil {
		return acq, newError(p.Name, StatusUnknown, ReasonCancelled)
	}
	res, err := readLines(cont.f, offset, skip, limit, p.maxLine(), !cont.live)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return acq, newError(p.Name, StatusDenied, ReasonPermission)
		}
		return acq, newError(p.Name, StatusUnknown, ReasonReadFailed)
	}
	acq.entries, acq.scanned = res.entries, uint32(res.scanned)
	if res.oversize > 0 {
		acq.dropped[DropOversizeLine] += res.oversize
	}
	tail, err := tailHash(cont.f, res.offset)
	if err != nil {
		return acq, newError(p.Name, StatusUnknown, ReasonReadFailed)
	}
	acq.to = Position{Started: true, File: cont.id, Offset: res.offset, Tail: tail, Skip: res.skip, Final: !cont.live && res.exhausted}
	if gap {
		now := model.UnixNano(p.now().UnixNano())
		start := cp.LastRead
		if start == 0 || start > now {
			start = now
		}
		acq.gaps = append(acq.gaps, Gap{Reason: "truncated", Count: 1, Start: start, End: now})
	}
	return acq, nil
}

type lineResult struct {
	entries   []entry
	offset    int64
	skip      bool
	exhausted bool
	scanned   int
	oversize  uint64
}

// readLines splits complete lines out of f starting at offset. Only
// newline-terminated lines are consumed, except at the end of a rotated
// predecessor (final), where the last unterminated line is complete by
// definition. A line longer than maxLine is counted once and skipped to its
// newline without being buffered. The chunk buffer is zeroed on return.
func readLines(f *os.File, offset int64, skip bool, limit, maxLine int, final bool) (lineResult, error) {
	buf := make([]byte, readChunk)
	defer clear(buf)
	var carry []byte
	defer func() { clear(carry) }()
	res := lineResult{offset: offset, skip: skip}
	committed := offset
	pos := offset
	for res.scanned < limit {
		n, err := f.ReadAt(buf, pos)
		if err != nil && !errors.Is(err, io.EOF) {
			return res, err
		}
		chunk := buf[:n]
		start := 0
		for start < len(chunk) && res.scanned < limit {
			nl := bytes.IndexByte(chunk[start:], '\n')
			if nl < 0 {
				seg := chunk[start:]
				start = len(chunk)
				switch {
				case res.skip:
					committed = pos + int64(len(chunk))
				case len(carry)+len(seg) > maxLine:
					clear(carry)
					carry = carry[:0]
					res.oversize++
					res.scanned++
					res.skip = true
					committed = pos + int64(len(chunk))
				default:
					carry = append(carry, seg...)
				}
				break
			}
			seg := chunk[start : start+nl]
			lineEnd := pos + int64(start+nl) + 1
			start += nl + 1
			switch {
			case res.skip:
				res.skip = false
			case len(carry)+len(seg) > maxLine:
				res.oversize++
				res.scanned++
			default:
				line := make([]byte, 0, len(carry)+len(seg))
				line = append(line, carry...)
				line = append(line, seg...)
				if k := len(line); k > 0 && line[k-1] == '\r' {
					line = line[:k-1]
				}
				res.entries = append(res.entries, entry{msg: line})
				res.scanned++
			}
			clear(carry)
			carry = carry[:0]
			committed = lineEnd
		}
		pos += int64(n)
		if start < len(chunk) {
			break // the limit stopped us inside this chunk
		}
		if errors.Is(err, io.EOF) || n == 0 {
			res.exhausted = true
			break
		}
	}
	if res.exhausted && final && !res.skip && len(carry) > 0 && res.scanned < limit {
		line := append([]byte(nil), carry...)
		if k := len(line); k > 0 && line[k-1] == '\r' {
			line = line[:k-1]
		}
		res.entries = append(res.entries, entry{msg: line})
		res.scanned++
		committed = pos
	}
	if res.exhausted && res.scanned >= limit && len(carry) > 0 && final {
		res.exhausted = false // the unterminated final line is still unread
	}
	res.offset = committed
	return res, nil
}

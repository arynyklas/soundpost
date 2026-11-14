// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os/exec"
	"strconv"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
)

const (
	journalFields    = "MESSAGE,PRIORITY,SYSLOG_IDENTIFIER,_SYSTEMD_UNIT"
	journalLineLimit = 256 << 10
	journalStderrCap = 4 << 10
)

// journalEntry decodes only what the adapter may use. journalctl is asked for
// exactly these fields (--output-fields); anything else a journalctl emits is
// skipped by the decoder and never copied.
type journalEntry struct {
	Message  json.RawMessage `json:"MESSAGE"`
	Ident    json.RawMessage `json:"SYSLOG_IDENTIFIER"`
	Unit     json.RawMessage `json:"_SYSTEMD_UNIT"`
	Cursor   json.RawMessage `json:"__CURSOR"`
	Realtime json.RawMessage `json:"__REALTIME_TIMESTAMP"`
}

// journalArgs is the complete argument vector. The journal itself filters to
// the approved identifiers and units, so entries of other units are never
// delivered to the agent. Matches are validated at policy time (no leading
// dash, closed character set), and the process is not run through a shell.
func journalArgs(j *JournalSpec, pos Position, lines int) []string {
	args := []string{"--no-pager", "--quiet", "--output=json", "--output-fields=" + journalFields}
	switch {
	case pos.Cursor != "":
		args = append(args, "--after-cursor="+pos.Cursor)
	case pos.Since > 0:
		args = append(args, "--since=@"+strconv.FormatInt(pos.Since, 10))
	}
	if lines > 0 {
		args = append(args, "--lines="+strconv.Itoa(lines))
	}
	for _, id := range j.Identifiers {
		args = append(args, "SYSLOG_IDENTIFIER="+id)
	}
	if len(j.Identifiers) > 0 && len(j.Units) > 0 {
		args = append(args, "+")
	}
	for _, u := range j.Units {
		args = append(args, "_SYSTEMD_UNIT="+u)
	}
	return args
}

// runJournal runs journalctl and hands at most max stdout lines to emit, then
// stops it. The child gets a three-variable environment, never the agent's.
func runJournal(ctx context.Context, command string, args []string, max int, emit func(line []byte) error) (stderr string, exitErr, err error) {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Env = []string{"LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER="}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", nil, err
	}
	var errBuf limitedBuffer
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		return "", nil, err
	}
	rd := bufio.NewReaderSize(out, 64<<10)
	got := 0
	var emitErr error
	for got < max {
		line, rerr := readBoundedLine(rd, journalLineLimit)
		if len(line) > 0 {
			emitErr = emit(line)
			clear(line)
			got++
			if emitErr != nil {
				break
			}
		}
		if rerr != nil {
			if !errors.Is(rerr, io.EOF) {
				emitErr = rerr
			}
			break
		}
	}
	stopped := got >= max || emitErr != nil
	if stopped {
		cmd.Process.Kill()
	}
	io.Copy(io.Discard, out)
	waitErr := cmd.Wait()
	if stopped {
		waitErr = nil // the exit status of a process we stopped says nothing
	}
	return errBuf.String(), waitErr, emitErr
}

var errJournalLine = errors.New("journal line unusable")

// readBoundedLine reads one newline-terminated line of at most limit bytes into
// a fresh buffer, or fails: the journal JSON protocol cannot resynchronize
// inside a truncated line. The bufio buffer is zeroed as it is consumed.
func readBoundedLine(rd *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := rd.ReadSlice('\n')
		line = append(line, chunk...)
		clear(chunk)
		if len(line) > limit {
			clear(line)
			return nil, errJournalLine
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return bytes.TrimRight(line, "\n"), err
	}
}

type limitedBuffer struct{ b []byte }

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := journalStderrCap - len(l.b); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		l.b = append(l.b, p[:room]...)
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string { return string(l.b) }

// journalDenied recognizes journalctl's permission diagnostics. The text is
// never kept: it can quote units and messages.
func journalDenied(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "insufficient permissions") || strings.Contains(s, "not seeing messages from other users and the system") || strings.Contains(s, "permission denied")
}

func jsonText(raw json.RawMessage) (string, bool) {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func (p SourcePolicy) journalCommand() (string, error) {
	if p.Journal.Command != "" {
		return p.Journal.Command, nil
	}
	path, err := exec.LookPath("journalctl")
	if err != nil {
		return "", newError(p.Name, StatusUnsupported, ReasonNotPresent)
	}
	return path, nil
}

// journalFailure maps a failed journalctl run to its typed error.
func journalFailure(p SourcePolicy, stderr string, exitErr, err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return newError(p.Name, StatusUnknown, ReasonCancelled)
	case errors.Is(err, exec.ErrNotFound), errors.Is(err, fs.ErrNotExist):
		return newError(p.Name, StatusUnsupported, ReasonNotPresent)
	case errors.Is(err, fs.ErrPermission):
		return newError(p.Name, StatusDenied, ReasonPermission)
	case err != nil:
		return newError(p.Name, StatusUnknown, ReasonJournalFailed)
	}
	if journalDenied(stderr) {
		return newError(p.Name, StatusDenied, ReasonPermission)
	}
	if exitErr != nil {
		return newError(p.Name, StatusUnknown, ReasonJournalFailed)
	}
	return nil
}

// acquireJournal reads up to limit entries after the committed cursor.
func acquireJournal(ctx context.Context, p SourcePolicy, cp Checkpoint, limit int) (acquired, error) {
	acq := acquired{dropped: map[string]uint64{}}
	j := p.Journal
	command, err := p.journalCommand()
	if err != nil {
		return acq, err
	}
	pos := cp.Position
	if !pos.Started {
		if j.StartAt == StartBeginning {
			pos = Position{Started: true}
		} else {
			return acquireJournalEnd(ctx, p, command)
		}
	}
	var lastCursor string
	scanned := 0
	stderr, exitErr, err := runJournal(ctx, command, journalArgs(j, pos, 0), limit, func(line []byte) error {
		var e journalEntry
		if json.Unmarshal(line, &e) != nil {
			return errJournalLine
		}
		cursor, ok := jsonText(e.Cursor)
		if !ok || cursor == "" || len(cursor) > 512 {
			return errJournalLine
		}
		lastCursor = cursor
		scanned++
		ident, _ := jsonText(e.Ident)
		unit, _ := jsonText(e.Unit)
		if !(containsString(j.Identifiers, ident) || containsString(j.Units, unit)) {
			acq.dropped[DropUnapprovedSource]++
			return nil
		}
		msg, isText := jsonText(e.Message)
		switch {
		case !isText && bytes.Equal(bytes.TrimSpace(e.Message), []byte("null")):
			acq.dropped[DropOversizeLine]++ // journalctl nulls fields over 4 KiB
		case !isText:
			acq.dropped[DropNonTextMessage]++
		case len(msg) > p.maxLine():
			acq.dropped[DropOversizeLine]++
		default:
			var at model.UnixNano
			if rt, ok := jsonText(e.Realtime); ok {
				if us, err := strconv.ParseInt(rt, 10, 64); err == nil && us > 0 && us < 1<<53 {
					at = model.UnixNano(us * 1000)
				}
			}
			acq.entries = append(acq.entries, entry{msg: []byte(msg), at: at, tag: ident})
		}
		return nil
	})
	fail := journalFailure(p, stderr, exitErr, err)
	if fail != nil {
		for i := range acq.entries {
			clear(acq.entries[i].msg)
		}
		return acquired{dropped: map[string]uint64{}}, fail
	}
	acq.scanned = uint32(scanned)
	acq.to = pos
	if lastCursor != "" {
		acq.to.Cursor, acq.to.Since = lastCursor, 0
	}
	return acq, nil
}

// acquireJournalEnd takes the "start at the current end" decision: it records
// the cursor of the newest matching entry (nothing is read), or, for a journal
// with no matching entry yet, the current second.
func acquireJournalEnd(ctx context.Context, p SourcePolicy, command string) (acquired, error) {
	acq := acquired{dropped: map[string]uint64{}}
	var last string
	stderr, exitErr, err := runJournal(ctx, command, journalArgs(p.Journal, Position{}, 1), 1, func(line []byte) error {
		var e journalEntry
		if json.Unmarshal(line, &e) != nil {
			return errJournalLine
		}
		last, _ = jsonText(e.Cursor)
		return nil
	})
	if fail := journalFailure(p, stderr, exitErr, err); fail != nil {
		return acq, fail
	}
	acq.to = Position{Started: true, Cursor: last}
	if last == "" {
		acq.to.Since = p.now().Unix()
	}
	return acq, nil
}

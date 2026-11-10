// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"bytes"
	"time"

	"soundpost/internal/model"
)

// parseSyslog frames one syslog line written by a local syslog daemon: RFC 3164
// ("Mmm dd hh:mm:ss host tag[pid]: msg"), the RFC 3339-timestamp file format
// of rsyslog, or RFC 5424, each optionally with a leading <PRI>. It returns the
// tag (application name), the message and the source time (zero when the line
// has none). The host name, process id, message id and structured data are
// read only to be skipped; none of them is ever returned.
func parseSyslog(line []byte, now time.Time) (tag string, msg []byte, ts model.UnixNano, ok bool) {
	s := line
	if len(s) > 0 && s[0] == '<' {
		end := bytes.IndexByte(s, '>')
		if end < 2 || end > 4 || !allDigits(s[1:end]) {
			return "", nil, 0, false
		}
		s = s[end+1:]
	}
	switch {
	case len(s) >= 2 && s[0] == '1' && s[1] == ' ':
		return parse5424(s[2:])
	case len(s) >= 11 && allDigits(s[:4]) && s[4] == '-':
		return parseRFC3339Line(s)
	default:
		return parseBSD(s, now)
	}
}

func allDigits(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func nextToken(s []byte) (tok, rest []byte, ok bool) {
	i := bytes.IndexByte(s, ' ')
	if i <= 0 {
		return nil, nil, false
	}
	return s[:i], s[i+1:], true
}

func parse5424(s []byte) (string, []byte, model.UnixNano, bool) {
	var toks [5][]byte
	for i := range toks {
		t, rest, ok := nextToken(s)
		if !ok {
			return "", nil, 0, false
		}
		toks[i], s = t, rest
	}
	var ts model.UnixNano
	if string(toks[0]) != "-" {
		t, err := time.Parse(time.RFC3339Nano, string(toks[0]))
		if err != nil {
			return "", nil, 0, false
		}
		ts = model.UnixNano(t.UnixNano())
	}
	// structured data: "-" or one or more [ ... ] elements with \] escapes
	switch {
	case len(s) > 0 && s[0] == '-':
		s = s[1:]
	case len(s) > 0 && s[0] == '[':
		for len(s) > 0 && s[0] == '[' {
			i := 1
			for i < len(s) && s[i] != ']' {
				if s[i] == '\\' {
					i++
				}
				i++
			}
			if i >= len(s) {
				return "", nil, 0, false
			}
			s = s[i+1:]
		}
	default:
		return "", nil, 0, false
	}
	if len(s) > 0 && s[0] == ' ' {
		s = s[1:]
	}
	s = bytes.TrimPrefix(s, []byte{0xEF, 0xBB, 0xBF})
	app := toks[2]
	if string(app) == "-" {
		app = nil
	}
	return string(app), s, ts, true
}

func parseRFC3339Line(s []byte) (string, []byte, model.UnixNano, bool) {
	tsTok, rest, ok := nextToken(s)
	if !ok {
		return "", nil, 0, false
	}
	t, err := time.Parse(time.RFC3339Nano, string(tsTok))
	if err != nil {
		return "", nil, 0, false
	}
	_, rest, ok = nextToken(rest) // host name: skipped
	if !ok {
		return "", nil, 0, false
	}
	tag, msg, ok := splitTag(rest)
	return tag, msg, model.UnixNano(t.UnixNano()), ok
}

func parseBSD(s []byte, now time.Time) (string, []byte, model.UnixNano, bool) {
	if len(s) < 17 || s[15] != ' ' {
		return "", nil, 0, false
	}
	t, err := time.ParseInLocation("Jan _2 15:04:05", string(s[:15]), now.Location())
	if err != nil {
		return "", nil, 0, false
	}
	t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, now.Location())
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	_, rest, ok := nextToken(s[16:]) // host name: skipped
	if !ok {
		return "", nil, 0, false
	}
	tag, msg, ok := splitTag(rest)
	return tag, msg, model.UnixNano(t.UnixNano()), ok
}

// splitTag splits "tag[pid]: message" or "tag: message".
func splitTag(s []byte) (string, []byte, bool) {
	i := 0
	for i < len(s) && s[i] != '[' && s[i] != ':' && s[i] != ' ' {
		i++
	}
	if i == 0 || i >= len(s) {
		return "", nil, false
	}
	tag := string(s[:i])
	if s[i] == '[' {
		j := bytes.IndexByte(s[i:], ']')
		if j < 0 || !allDigits(s[i+1:i+j]) {
			return "", nil, false
		}
		i += j + 1
	}
	if i >= len(s) || s[i] != ':' {
		return "", nil, false
	}
	i++
	if i < len(s) && s[i] == ' ' {
		i++
	}
	return tag, s[i:], true
}

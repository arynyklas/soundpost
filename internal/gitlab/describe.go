// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package gitlab

import (
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/arynyklas/soundpost/internal/model"
)

// Entity kinds a GitLab issue can be created for.
const (
	KindIncident = "incident"
	KindIssue    = "issue"
)

// Ref names one structured entity an incident or issue is linked to.
type Ref struct {
	Kind string
	ID   model.ID
}

// Facts are the only things a description ever states: identifiers, severity,
// status and linked entity IDs. There is no field for a title, a note, a message,
// a log or any telemetry, so none can reach GitLab or a copied task text.
type Facts struct {
	Kind     string
	ID       model.ID
	Project  model.ID
	Severity string // "" when the entity has none (an error issue)
	Status   string
	Related  []Ref
}

const maxRelated = 16

// Short is the short form of an ID used in default titles.
func Short(id model.ID) string { return id.String()[:8] }

// DefaultTitle is the title a GitLab issue gets unless the caller supplies one.
func DefaultTitle(kind string, id model.ID) string {
	return "Soundpost " + kind + " " + Short(id)
}

// ValidTitle checks a caller-supplied title: 1..255 bytes, valid UTF-8, no control
// characters, not blank.
func ValidTitle(s string) bool {
	if len(s) == 0 || len(s) > 255 || !utf8.ValidString(s) || strings.TrimSpace(s) == "" {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// ValidDescription checks a caller-supplied description: valid UTF-8, bounded,
// only \n and \t as control characters, and no Soundpost reference marker (a marker
// is written by the server alone, so a caller cannot make a lookup match another
// entity's issue).
func ValidDescription(s string) bool {
	if len(s) == 0 || len(s) > 8000 || !utf8.ValidString(s) || strings.Contains(strings.ToLower(s), markerPrefix) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return false
		}
	}
	return true
}

// ValidLabels checks caller-supplied labels: at most 10, each 1..50 bytes of valid
// UTF-8 without control characters or a comma.
func ValidLabels(labels []string) bool {
	if len(labels) > 10 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 50 || !utf8.ValidString(l) || strings.ContainsRune(l, ',') || strings.TrimSpace(l) == "" {
			return false
		}
		for _, r := range l {
			if unicode.IsControl(r) {
				return false
			}
		}
	}
	return true
}

const markerPrefix = "soundpost-ref-"

// escapes are the Markdown characters that are escaped in user text.
const escapes = "\\`*_{}[]()<>#+-.!|~&"

// Line makes user text safe for one Markdown line: control characters and
// newlines become spaces and every character that could start markup, a link, a
// table cell or raw HTML is backslash-escaped.
func Line(s string) string {
	var b strings.Builder
	b.Grow(len(s) + len(s)/4)
	for _, r := range defuse(strings.ToValidUTF8(s, "\uFFFD")) {
		switch {
		case r == '\n' || r == '\r' || r == '\t' || unicode.IsControl(r):
			b.WriteByte(' ')
		case r < utf8.RuneSelf && strings.IndexByte(escapes, byte(r)) >= 0:
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Quote renders multi-line user text as a Markdown block quote: every line is
// escaped by Line and prefixed, so no line can leave the quote.
func Quote(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(s, "\n")
	var b strings.Builder
	for i, l := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString("> ")
		b.WriteString(Line(l))
	}
	return b.String()
}

// Code renders an identifier or time as an inline code span. Backticks and
// control characters are dropped, so nothing can close the span.
func Code(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r != '`' && !unicode.IsControl(r) {
			b.WriteRune(r)
		}
	}
	return "`" + b.String() + "`"
}

// NormalizeOrigin returns the https origin without a trailing slash; ok is false
// for an empty or unusable origin (links are then not available).
func NormalizeOrigin(origin string) (string, bool) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	return "https://" + u.Host, true
}

// Link is the console link of an entity, in the hash form notifications use. It
// carries identifiers only. ok is false without a usable public origin.
func Link(origin string, org model.ID, kind string, project, id model.ID) (string, bool) {
	o, ok := NormalizeOrigin(origin)
	if !ok {
		return "", false
	}
	view, param := "incidents", "incident"
	if kind == KindIssue {
		view, param = "issues", "target"
	}
	return o + "/#view=" + view + "&org=" + org.String() + "&projects=" + project.String() + "&" + param + "=" + project.String() + ":" + id.String(), true
}

// Description is the task text of an entity: identifiers, severity, status,
// linked entity IDs and the console link (when link is not empty).
func Description(f Facts, link string) string {
	var b strings.Builder
	b.WriteString("Soundpost " + Line(f.Kind) + " " + Code(Short(f.ID)) + "\n\n")
	b.WriteString("- ID: " + Code(f.ID.String()) + "\n")
	b.WriteString("- Project: " + Code(f.Project.String()) + "\n")
	if f.Severity != "" {
		b.WriteString("- Severity: " + Code(f.Severity) + "\n")
	}
	if f.Status != "" {
		b.WriteString("- Status: " + Code(f.Status) + "\n")
	}
	for i, r := range f.Related {
		if i == maxRelated {
			break
		}
		b.WriteString("- Linked " + Line(r.Kind) + ": " + Code(r.ID.String()) + "\n")
	}
	if link != "" {
		b.WriteString("\n[Open in Soundpost](" + strings.NewReplacer("(", "%28", ")", "%29", " ", "%20", "<", "%3C", ">", "%3E").Replace(link) + ")\n")
	}
	return b.String()
}

// WithMarker appends the reference marker line GitLab lookups match on.
func WithMarker(description, marker string) string {
	return strings.TrimRight(description, "\n") + "\n\nSoundpost reference: " + marker + "\n"
}

// zwsp breaks every GitLab reference, mention and autolink without changing what
// a person reads.
const zwsp = "\u200b"

// triggers are the characters GitLab turns into mentions or references when a
// name, number or label follows: @user, #1, !1, &1, %milestone, ~label, $snippet.
const triggers = "@#!&%~$"

// defuse inserts U+200B after every trigger character, after the scheme colon of a
// URL and after "www.", inside [[wiki]] brackets, after the fourth character of a
// 7..40 hex run (a commit SHA) and before a leading "/" (a quick action). Together
// with the backslash escapes of Line, pasted text cannot ping, cross-link or run a
// command in GitLab.
func defuse(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 16)
	if strings.HasPrefix(s, "/") {
		b.WriteString(zwsp)
	}
	for i := 0; i < len(s); {
		c := s[i]
		if isAlnum(c) {
			j := i
			hex := true
			for j < len(s) && isAlnum(s[j]) {
				hex = hex && (c2h(s[j]))
				j++
			}
			run := s[i:j]
			if hex && len(run) >= 7 && len(run) <= 40 {
				run = run[:4] + zwsp + run[4:]
			}
			b.WriteString(run)
			i = j
			continue
		}
		b.WriteByte(c)
		switch {
		case strings.IndexByte(triggers, c) >= 0, c == '[' && i+1 < len(s) && s[i+1] == '[':
			b.WriteString(zwsp)
		case c == ':' && strings.HasPrefix(s[i:], "://"):
			b.WriteString(zwsp)
		}
		i++
	}
	return strings.ReplaceAll(b.String(), "www.", "www."+zwsp)
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func c2h(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

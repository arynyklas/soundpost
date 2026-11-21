// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package sources acquires system log sources (journal, syslog files, plain
// files) and OpenMetrics scrape targets for the Soundpost agent. It PRODUCES
// batches for the C03 ingest route; it is not a second ingestion engine.
//
// The default source class is structured: a source line is only ever exported
// as a registered template revision with typed, individually approved fields.
// A line that matches no registered template is counted by reason and dropped:
// its bytes exist only in a bounded, zeroed acquisition buffer and are never
// copied into a record, a checkpoint, an error or a log. Raw text needs an
// explicit restricted_raw source policy with owner, rationale, expiry and size.
package sources

import (
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/arynyklas/soundpost/internal/model"
)

// Kind selects the acquisition adapter.
type Kind string

const (
	KindFile    Kind = "file"
	KindJournal Kind = "journal"
	KindSyslog  Kind = "syslog"
)

// Source classes mirror model.SourcePolicy.Class.
const (
	ClassStructured    = "structured"
	ClassRestrictedRaw = "restricted_raw"
)

// StartAt says where a source with no checkpoint begins. The default is the
// current end: history that predates the installation of the agent is not
// silently swept in.
const (
	StartEnd       = "end"
	StartBeginning = "beginning"
)

// Closed vocabulary of per-reason drop counters. A counter never holds content.
const (
	DropUnknownTemplate  = "unknown_template"
	DropUnapprovedValue  = "unapproved_value"
	DropOversizeValue    = "oversize_value"
	DropOversizeLine     = "oversize_line"
	DropInvalidUTF8      = "invalid_utf8"
	DropUnapprovedSource = "unapproved_source"
	DropBadTimestamp     = "bad_timestamp"
	DropNonTextMessage   = "non_text_message"
	DropBadFrame         = "bad_frame"
)

// RawGrant is the explicit restricted_raw authorization copied from the
// installation's source policy. Only a restricted_raw source carries one.
type RawGrant struct {
	Owner     model.ID       `json:"owner"`
	Rationale string         `json:"rationale"`
	Expires   model.UnixNano `json:"expires_ns"`
	MaxBytes  uint32         `json:"max_bytes"`
}

// FileSpec reads one append-only text file. Rotated lists the paths a rotation
// tool may move the file to; a rotated predecessor is finished before its
// successor is read, so a rotation neither skips nor duplicates lines.
type FileSpec struct {
	Path       string   `json:"path"`
	Rotated    []string `json:"rotated,omitempty"`
	StartAt    string   `json:"start_at,omitempty"`
	TimeLayout string   `json:"time_layout,omitempty"`
}

// JournalSpec reads the systemd journal through journalctl, restricted by the
// journal itself to the listed identifiers and units: other entries are never
// delivered to the agent. At least one approved match is required.
type JournalSpec struct {
	Command     string   `json:"command,omitempty"`
	Identifiers []string `json:"identifiers,omitempty"`
	Units       []string `json:"units,omitempty"`
	StartAt     string   `json:"start_at,omitempty"`
}

// SyslogSpec reads syslog-framed messages (RFC 3164, RFC 3339-timestamp or RFC
// 5424, each with an optional <PRI>) either from a file written by the local
// syslog daemon (Path, Rotated, StartAt) or from the network (Listen,
// BufferRecords): exactly one of the two. Only messages whose tag is listed
// are classified; the host name and process id are never read into a record.
type SyslogSpec struct {
	Path          string         `json:"path,omitempty"`
	Rotated       []string       `json:"rotated,omitempty"`
	Listen        []SyslogListen `json:"listen,omitempty"`
	BufferRecords int            `json:"buffer_records,omitempty"`
	Tags          []string       `json:"tags"`
	StartAt       string         `json:"start_at,omitempty"`
}

// SyslogListen is one network listener of a network syslog source: UDP (one
// message per datagram, RFC 5426), TCP (octet counting or newline framing, RFC
// 6587) or TLS (RFC 5425; the same framing). Address is "IP:port" with an IP
// literal (no name is resolved). A TLS listener needs a certificate and key;
// ClientCAFile additionally requires and verifies a client certificate.
type SyslogListen struct {
	Network      string `json:"network"`
	Address      string `json:"address"`
	CertFile     string `json:"cert_file,omitempty"`
	KeyFile      string `json:"key_file,omitempty"`
	ClientCAFile string `json:"client_ca_file,omitempty"`
}

// SourcePolicy is the local, operator-approved description of one log source.
// Templates are the registered revisions of the installation's source policy
// (their Line is also the pattern a source line must match); the server
// validates every record again on admission.
type SourcePolicy struct {
	Name         string              `json:"name"`
	Kind         Kind                `json:"kind"`
	Class        string              `json:"class"`
	Revision     model.Revision      `json:"-"` // supplied by the caller (the agent sets it from its top-level configuration)
	Resource     model.Resource      `json:"-"` // likewise: never part of a per-source configuration
	Labels       model.Labels        `json:"stream_labels"`
	Templates    []model.LogTemplate `json:"templates"`
	Raw          *RawGrant           `json:"raw,omitempty"`
	MaxRecords   int                 `json:"max_records,omitempty"`
	MaxLineBytes int                 `json:"max_line_bytes,omitempty"`
	File         *FileSpec           `json:"file,omitempty"`
	Journal      *JournalSpec        `json:"journal,omitempty"`
	Syslog       *SyslogSpec         `json:"syslog,omitempty"`

	clock func() time.Time // test seam
}

const (
	defaultMaxRecords   = 256
	defaultMaxLineBytes = 8192
	maxSpecs            = 64
)

var (
	nameRE  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,47}$`)
	matchRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@_.:\\-]{0,127}$`)
	tagRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./@:-]{0,63}$`)
)

func (p SourcePolicy) now() time.Time {
	if p.clock != nil {
		return p.clock()
	}
	return time.Now()
}

func (p SourcePolicy) maxRecords() int {
	if p.MaxRecords == 0 {
		return defaultMaxRecords
	}
	return p.MaxRecords
}

func (p SourcePolicy) maxLine() int {
	if p.MaxLineBytes == 0 {
		return defaultMaxLineBytes
	}
	return p.MaxLineBytes
}

// modelPolicy is the subset of the installation policy that decides whether a
// log record is admissible. The same model.ValidateRecord the server runs is
// applied locally, so what is exported is what the server would accept.
func (p SourcePolicy) modelPolicy() model.SourcePolicy {
	labels := map[string][]string{}
	add := func(l model.Labels) {
		for _, v := range l {
			if !containsString(labels[v.Name], v.Value) {
				labels[v.Name] = append(labels[v.Name], v.Value)
			}
		}
	}
	add(p.Labels)
	add(p.Resource.Labels)
	mp := model.SourcePolicy{
		Revision: p.Revision, Enabled: true, Class: p.Class, Kinds: []model.Kind{model.Log},
		Templates: p.Templates, Labels: labels, MaxBytes: 1, MaxSeries: 1,
		RetentionDays: map[model.Kind]uint32{model.Log: 1},
		Resources: model.ResourceRegistry{
			Services: []model.ID{p.Resource.Service}, Environments: []model.ID{p.Resource.Environment},
			Builds: []model.ID{p.Resource.Build}, Instances: []string{p.Resource.Instance},
		},
	}
	if p.Raw != nil {
		owner := p.Raw.Owner
		mp.RawOwner, mp.RawRationale, mp.RawMaxBytes, mp.Expires = &owner, p.Raw.Rationale, p.Raw.MaxBytes, p.Raw.Expires
	}
	return mp
}

// Validate checks the policy before any source byte is touched.
func (p SourcePolicy) Validate() error {
	bad := func() error { return newError(p.Name, StatusUnknown, ReasonInvalidPolicy) }
	if !nameRE.MatchString(p.Name) || p.Revision == 0 || len(p.Templates) == 0 || len(p.Templates) > maxSpecs {
		return bad()
	}
	if p.MaxRecords < 0 || p.MaxRecords > 512 || p.MaxLineBytes < 0 || (p.MaxLineBytes != 0 && (p.MaxLineBytes < 64 || p.MaxLineBytes > 65536)) {
		return bad()
	}
	if p.Labels.Validate() != nil || len(p.Labels) > 16 {
		return bad()
	}
	switch p.Class {
	case ClassStructured:
		if p.Raw != nil {
			return bad()
		}
	case ClassRestrictedRaw:
		if p.Raw == nil || p.Raw.Owner == (model.ID{}) || p.Raw.Rationale == "" || len(p.Raw.Rationale) > 512 || p.Raw.Expires <= 0 || p.Raw.MaxBytes == 0 || p.Raw.MaxBytes > 65536 {
			return bad()
		}
	default:
		return bad()
	}
	if model.ValidateSourcePolicy(p.modelPolicy()) != nil {
		return bad()
	}
	specs := 0
	if p.File != nil {
		specs++
	}
	if p.Journal != nil {
		specs++
	}
	if p.Syslog != nil {
		specs++
	}
	if specs != 1 {
		return bad()
	}
	switch p.Kind {
	case KindFile:
		if p.File == nil || !validPath(p.File.Path) || !validPaths(p.File.Rotated) || !validStart(p.File.StartAt) || !validLayout(p.File.TimeLayout) {
			return bad()
		}
	case KindSyslog:
		if p.Syslog == nil || !validSyslogSource(p.Syslog) || len(p.Syslog.Tags) == 0 || len(p.Syslog.Tags) > maxSpecs {
			return bad()
		}
		for _, t := range p.Syslog.Tags {
			if !tagRE.MatchString(t) {
				return bad()
			}
		}
	case KindJournal:
		j := p.Journal
		if j == nil || !validStart(j.StartAt) || len(j.Identifiers)+len(j.Units) == 0 || len(j.Identifiers) > maxSpecs || len(j.Units) > maxSpecs {
			return bad()
		}
		if j.Command != "" && !validPath(j.Command) {
			return bad()
		}
		for _, m := range append(append([]string{}, j.Identifiers...), j.Units...) {
			if !matchRE.MatchString(m) {
				return bad()
			}
		}
	default:
		return bad()
	}
	return nil
}

func validPath(s string) bool {
	return s != "" && len(s) <= 1024 && !strings.ContainsRune(s, 0) && isAbs(s)
}

func validPaths(l []string) bool {
	if len(l) > 8 {
		return false
	}
	for _, s := range l {
		if !validPath(s) {
			return false
		}
	}
	return true
}

func validStart(s string) bool { return s == "" || s == StartEnd || s == StartBeginning }

// validSyslogSource checks the file-or-network choice of a syslog source: a
// file source has a path (and maybe rotated paths, a start) and no listener; a
// network source has listeners and a buffer size, no path, and no start
// position (a network stream has no history to start from).
func validSyslogSource(s *SyslogSpec) bool {
	if (s.Path != "") == (len(s.Listen) > 0) {
		return false
	}
	if s.Path != "" {
		return validPath(s.Path) && validPaths(s.Rotated) && validStart(s.StartAt) && s.BufferRecords == 0
	}
	if len(s.Rotated) != 0 || len(s.Listen) > maxListeners || s.StartAt != "" && s.StartAt != StartBeginning ||
		s.BufferRecords < 0 || s.BufferRecords > maxNetBuffer || s.BufferRecords != 0 && s.BufferRecords < 16 {
		return false
	}
	seen := map[string]bool{}
	for _, l := range s.Listen {
		if !validListen(l) {
			return false
		}
		if !strings.HasSuffix(l.Address, ":0") {
			key := l.Network + "|" + l.Address
			if l.Network == netTLS {
				key = netTCP + "|" + l.Address // TLS and TCP share a port space
			}
			if seen[key] {
				return false
			}
			seen[key] = true
		}
	}
	return true
}

func validListen(l SyslogListen) bool {
	host, port, err := net.SplitHostPort(l.Address)
	if err != nil || len(l.Address) > 64 {
		return false
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return false
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return false
	}
	switch l.Network {
	case netUDP, netTCP:
		return l.CertFile == "" && l.KeyFile == "" && l.ClientCAFile == ""
	case netTLS:
		return validPath(l.CertFile) && validPath(l.KeyFile) && (l.ClientCAFile == "" || validPath(l.ClientCAFile))
	}
	return false
}

func validLayout(layout string) bool {
	if layout == "" {
		return true
	}
	ref := time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC)
	got, err := time.Parse(layout, ref.Format(layout))
	return err == nil && got.Equal(ref) && len(layout) <= 64
}

// ---- template matching ----

type compiledTemplate struct {
	tpl     model.LogTemplate
	re      *regexp.Regexp
	names   []string
	literal int
}

var placeholderRE = regexp.MustCompile(`\{([^{}]+)\}`)

// compileTemplates turns every registered Line into an anchored matcher.
// Placeholders match by their declared type; when several templates match one
// message the one with the most literal text wins, then declaration order, so
// the choice is deterministic and never depends on map iteration.
func compileTemplates(p SourcePolicy) ([]compiledTemplate, error) {
	out := make([]compiledTemplate, 0, len(p.Templates))
	for _, t := range p.Templates {
		types := map[string]string{}
		for _, f := range t.Fields {
			types[f.Name] = f.Type
		}
		var re strings.Builder
		re.WriteString(`^`)
		var names []string
		literal := 0
		rest := t.Line
		for _, m := range placeholderRE.FindAllStringSubmatchIndex(t.Line, -1) {
			lit := t.Line[len(t.Line)-len(rest) : m[0]]
			re.WriteString(regexp.QuoteMeta(lit))
			literal += len(lit)
			name := t.Line[m[2]:m[3]]
			names = append(names, name)
			switch types[name] {
			case "int64":
				re.WriteString(`(0|-?[1-9][0-9]{0,18})`)
			case "bool":
				re.WriteString(`(true|false)`)
			case "null":
				re.WriteString(`(null)`)
			default:
				re.WriteString(`(.*?)`)
			}
			rest = t.Line[m[1]:]
		}
		re.WriteString(regexp.QuoteMeta(rest))
		literal += len(rest)
		re.WriteString(`$`)
		c, err := regexp.Compile("(?s)" + re.String())
		if err != nil {
			return nil, newError(p.Name, StatusUnknown, ReasonInvalidPolicy)
		}
		out = append(out, compiledTemplate{tpl: t, re: c, names: names, literal: literal})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].literal > out[j].literal })
	return out, nil
}

// classify maps one message to a typed record or to a drop reason. The message
// is only read; the caller owns (and zeroes) it. No error or reason carries any
// of its bytes.
func (p SourcePolicy) classify(templates []compiledTemplate, msg []byte, ts model.UnixNano, mp model.SourcePolicy) (model.LogRecord, string) {
	if !utf8.Valid(msg) {
		return model.LogRecord{}, DropInvalidUTF8
	}
	if len(msg) > 65536 {
		return model.LogRecord{}, DropOversizeLine
	}
	for _, c := range templates {
		m := c.re.FindSubmatch(msg)
		if m == nil {
			continue
		}
		fields := make(map[string]model.Scalar, len(c.names))
		types, maxBytes := map[string]string{}, map[string]uint32{}
		for _, f := range c.tpl.Fields {
			types[f.Name], maxBytes[f.Name] = f.Type, f.MaxBytes
		}
		for i, name := range c.names {
			if len(m[i+1]) > int(maxBytes[name]) {
				return model.LogRecord{}, DropOversizeValue
			}
			s, ok := scalarOf(types[name], m[i+1])
			if !ok {
				return model.LogRecord{}, DropUnapprovedValue
			}
			fields[name] = s
		}
		rec := model.LogRecord{
			TemplateID: c.tpl.ID, TemplateRevision: c.tpl.Revision, Fields: fields,
			StreamLabels: append(model.Labels(nil), p.Labels...), Metadata: map[string]model.Scalar{},
		}
		if ts != 0 {
			v := ts
			rec.Timestamp = &v
		}
		r := model.Record{ID: model.ID{1}, Kind: model.Log, Resource: p.Resource, Payload: model.Payload{Log: &rec}}
		if err := model.ValidateRecord(&r, mp); err != nil {
			if f, ok := err.(*model.Fault); ok && f.Code == model.TooLarge {
				return model.LogRecord{}, DropOversizeValue
			}
			return model.LogRecord{}, DropUnapprovedValue
		}
		return *r.Payload.Log, ""
	}
	return model.LogRecord{}, DropUnknownTemplate
}

// scalarOf builds the canonical typed scalar for a captured value. Text is
// copied, never aliased: the acquisition buffer is zeroed afterwards.
func scalarOf(kind string, raw []byte) (model.Scalar, bool) {
	var v model.Scalar
	var lit string
	switch kind {
	case "int64":
		n, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil {
			return v, false
		}
		lit = strconv.FormatInt(n, 10)
	case "bool":
		lit = string(raw)
	case "null":
		lit = "null"
	default:
		b, err := jsonString(raw)
		if err != nil {
			return v, false
		}
		lit = b
	}
	if err := v.UnmarshalJSON([]byte(lit)); err != nil {
		return v, false
	}
	return v, true
}

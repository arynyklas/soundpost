// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package scan is the fixture-only canary matcher shared by the 04.08 privacy
// test and verifier. It is not a content logger: a Hit names the sentinel kind,
// the encoding that matched and a byte offset, never the surrounding bytes.
// Production packages must not import it (enforced by the nativeperf test).
package scan

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Kind is one sentinel family placed by the canary workload.
type Kind struct {
	ID        string `json:"id"`
	Token     string `json:"token"`
	Placement string `json:"placement"`
	MaxLen    int    `json:"max_len,omitempty"`
}

// PerfAttrRule is the closed perf_event_open attribute policy for one capture kind.
type PerfAttrRule struct {
	Types      []string `json:"types"`
	SampleType []string `json:"sample_type"`
	MustBeOne  []string `json:"must_be_one_fields"`
}

// PerfOpenPolicy constrains every perf_event_open attribute observed in a run.
type PerfOpenPolicy struct {
	CPU       PerfAttrRule `json:"cpu"`
	Scheduler PerfAttrRule `json:"scheduler"`
	MustZero  []string     `json:"must_be_zero_fields"`
}

// SourceNumbers lists numeric raw syscall arguments the acquisition sources may use.
type SourceNumbers struct {
	Comment string `json:"comment"`
	Numbers []int  `json:"numbers"`
}

// SyscallPolicy is the forbidden/allowed syscall and configuration audit policy.
type SyscallPolicy struct {
	Forbidden           []string       `json:"forbidden"`
	ForbiddenOpenPath   []string       `json:"forbidden_open_path_regex"`
	ForbiddenOpenName   []string       `json:"forbidden_open_name_regex"`
	PerfEventOpen       PerfOpenPolicy `json:"perf_event_open"`
	IoctlAllow          []string       `json:"ioctl_allow"`
	SourceNumbers       SourceNumbers  `json:"source_allowed_syscall_numbers"`
	SourceConstants     []string       `json:"source_allowed_syscall_constants"`
	SourceIoctl         []int          `json:"source_allowed_ioctl_requests"`
	SourceSymbolRegex   string         `json:"source_allowed_syscall_symbol_regex"`
	SourceForbiddenID   []string       `json:"source_forbidden_identifiers"`
	SourceForbiddenText []string       `json:"source_forbidden_string_regex"`
	SourceForbiddenImp  []string       `json:"source_forbidden_imports"`
}

// DumpPolicy is the packaging-side no-emergency-dump policy.
type DumpPolicy struct {
	SystemdUnit       string            `json:"systemd_unit"`
	RequiredDirective map[string]string `json:"required_directives"`
	ForbiddenFilter   []string          `json:"forbidden_syscall_filter_tokens"`
}

// Policy is the complete fixtures/nativeperf/privacy/policy.json document.
type Policy struct {
	Version         int           `json:"version"`
	Comment         string        `json:"comment"`
	Marker          string        `json:"marker"`
	SentinelPattern string        `json:"sentinel_pattern"`
	NonceHexLen     int           `json:"nonce_hex_len"`
	Kinds           []Kind        `json:"kinds"`
	Stages          []string      `json:"stages"`
	Syscalls        SyscallPolicy `json:"syscalls"`
	Dump            DumpPolicy    `json:"dump_policy"`
	ReasonVocab     []string      `json:"reason_vocabulary"`
}

// LoadPolicy strictly decodes the policy file: unknown fields are rejected.
func LoadPolicy(path string) (Policy, error) {
	var p Policy
	raw, e := os.ReadFile(path)
	if e != nil {
		return p, e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e = d.Decode(&p); e != nil {
		return p, e
	}
	if d.Decode(new(any)) != io.EOF {
		return p, errors.New("trailing policy data")
	}
	if p.Version != 1 || p.Marker == "" || p.NonceHexLen < 6 || len(p.Kinds) == 0 || !strings.Contains(p.SentinelPattern, "%s-%s") {
		return p, errors.New("invalid privacy policy")
	}
	seen := map[string]bool{}
	for _, k := range p.Kinds {
		if k.ID == "" || k.Token == "" || seen[k.ID] {
			return p, errors.New("invalid or duplicate sentinel kind")
		}
		seen[k.ID] = true
		if v := fmt.Sprintf(p.SentinelPattern, k.Token, strings.Repeat("0", p.NonceHexLen)); !strings.HasPrefix(v, p.Marker) || (k.MaxLen > 0 && len(v) > k.MaxLen) {
			return p, fmt.Errorf("sentinel kind %s violates marker or length", k.ID)
		}
	}
	return p, nil
}

// Sentinel returns the per-run value for a kind. Only the verifier calls this.
func (p Policy) Sentinel(kind, nonce string) (string, error) {
	if len(nonce) != p.NonceHexLen {
		return "", errors.New("nonce length")
	}
	if _, e := hex.DecodeString(nonce); e != nil {
		return "", errors.New("nonce must be hex")
	}
	for _, k := range p.Kinds {
		if k.ID == kind {
			return fmt.Sprintf(p.SentinelPattern, k.Token, nonce), nil
		}
	}
	return "", errors.New("unknown sentinel kind")
}

// Hit is a content-free detection record.
type Hit struct {
	Kind     string
	Encoding string
	Offset   int
}

func (h Hit) String() string {
	return "canary kind=" + h.Kind + " encoding=" + h.Encoding + " offset=" + strconv.Itoa(h.Offset)
}

type pattern struct {
	kind, encoding string
	needle         []byte
	fold           bool
}

// Detector matches every sentinel for one run in raw, case-folded, reversed,
// hex, base64 (all three alignments, standard and URL alphabets), UTF-16LE,
// JSON-escaped and packed 8-byte-word (decimal/hex, both endians) encodings, plus
// the generic marker prefix so truncated copies are caught too.
type Detector struct {
	patterns []pattern
}

func foldASCII(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// NewDetector builds the matcher for one run's nonce.
func NewDetector(p Policy, nonce string) (*Detector, error) {
	d := &Detector{}
	add := func(kind, encoding string, needle []byte, fold bool) {
		if len(needle) == 0 {
			return
		}
		if fold {
			needle = foldASCII(needle)
		}
		d.patterns = append(d.patterns, pattern{kind, encoding, append([]byte(nil), needle...), fold})
	}
	add("marker", "marker_fold", []byte(p.Marker), true)
	add("marker", "marker_reversed", reverse([]byte(p.Marker)), true)
	add("marker", "marker_hex", []byte(hex.EncodeToString([]byte(p.Marker))), true)
	for _, k := range p.Kinds {
		v, e := p.Sentinel(k.ID, nonce)
		if e != nil {
			return nil, e
		}
		raw := []byte(v)
		add(k.ID, "raw_fold", raw, true)
		add(k.ID, "reversed", reverse(raw), true)
		add(k.ID, "hex", []byte(hex.EncodeToString(raw)), true)
		for shift := range 3 {
			// A leaked copy may start at any alignment of a base64 stream. Encode the
			// value behind 0..2 filler bytes and keep only the characters fully
			// determined by the value (drop the filler head and the unaligned tail).
			padded := append(bytes.Repeat([]byte{'#'}, shift), raw...)
			for _, enc := range []struct {
				name string
				e    *base64.Encoding
			}{{"base64_std", base64.RawStdEncoding}, {"base64_url", base64.RawURLEncoding}} {
				s := enc.e.EncodeToString(padded)
				skip := (shift*8 + 5) / 6
				if skip+4 < len(s)-2 {
					add(k.ID, enc.name+"_"+strconv.Itoa(shift), []byte(s[skip:len(s)-2]), false)
				}
			}
		}
		u16 := make([]byte, 0, 2*len(raw))
		for _, c := range raw {
			u16 = append(u16, c, 0)
		}
		add(k.ID, "utf16le", u16, false)
		jsonEscaped, _ := json.Marshal(v)
		add(k.ID, "json", jsonEscaped[1:len(jsonEscaped)-1], false)
		// Raw substrings of at least 12 bytes (a leak of only part of a value).
		for i := 0; i+12 <= len(raw); i++ {
			add(k.ID, "raw_window", raw[i:i+12], true)
		}
		// Packed words: a collector that copies stack/heap/comm bytes into numeric
		// fields (addresses, periods) serializes them as decimal or hex integers.
		// Windows of 6-8 bytes at every offset, both byte orders.
		for width := 6; width <= 8; width++ {
			for i := 0; i+width <= len(raw); i++ {
				var le, be uint64
				for j := range width {
					le |= uint64(raw[i+j]) << (8 * j)
					be = be<<8 | uint64(raw[i+j])
				}
				for _, order := range []struct {
					name string
					v    uint64
				}{{"le", le}, {"be", be}} {
					add(k.ID, "word_dec_"+order.name, []byte(strconv.FormatUint(order.v, 10)), false)
					add(k.ID, "word_hex_"+order.name, []byte(strconv.FormatUint(order.v, 16)), true)
				}
			}
		}
	}
	// Different kinds may share a leading word ("SPCNRY-S"/"SPCNRY-H" do not, but
	// "SPCNRY-" alone is covered by the marker); keep patterns deterministic.
	sort.SliceStable(d.patterns, func(i, j int) bool {
		if d.patterns[i].kind != d.patterns[j].kind {
			return d.patterns[i].kind < d.patterns[j].kind
		}
		return d.patterns[i].encoding < d.patterns[j].encoding
	})
	return d, nil
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[len(b)-1-i] = c
	}
	return out
}

// Scan returns one hit per matching pattern (first occurrence). It never keeps
// or returns input bytes.
func (d *Detector) Scan(b []byte) []Hit {
	var folded []byte
	var hits []Hit
	for _, p := range d.patterns {
		hay := b
		if p.fold {
			if folded == nil {
				folded = foldASCII(b)
			}
			hay = folded
		}
		if at := bytes.Index(hay, p.needle); at >= 0 {
			hits = append(hits, Hit{Kind: p.kind, Encoding: p.encoding, Offset: at})
		}
	}
	return hits
}

// PatternCount reports how many encodings are armed, for self-tests.
func (d *Detector) PatternCount() int { return len(d.patterns) }

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/arynyklas/soundpost/internal/durablefs"
	"github.com/arynyklas/soundpost/internal/model"
)

// The carried-series set of a scrape target (what its stale markers are
// computed against) lives in a private directory of the node, one file per
// target alias. The rule the Scraper follows, in the order of one cycle:
//
//  1. Before the cycle's first batch is submitted, the file holds
//     (previous set ∪ the cycle's own set). A crash from here on carries a
//     superset of everything that could have been admitted: a series first
//     seen in this cycle that vanishes right after the restart still gets its
//     marker, and a series whose marker was in flight gets it (again).
//  2. Only after EVERY batch of the cycle has its receipt does the file become
//     exactly the cycle's own set.
//
// A restart therefore never skips a marker. It can re-emit a marker whose batch
// had in fact been admitted but whose receipt, or the second write, was lost;
// that duplicate is a stale marker of the same series at the first scrape time
// after the restart: a distinct batch (the identity binds the scrape time) of
// the same series and the same stale value, a no-op for every query. The same
// at-least-once rule already holds inside one process (a refused cycle marks
// again on the next one).
//
// The file is written atomically (temporary file, fsync, rename, directory
// fsync) and carries a SHA-256 of its content. A file that cannot be trusted is
// an error, never "nothing seen": that would hide a gap.

// ScrapeStateReason is the closed set of typed scrape-state failures. The values
// are also the per-target health reasons (ScrapeReason).
type ScrapeStateReason string

const (
	// ScrapeStateCorrupt: the state file exists but cannot be trusted (not
	// parseable, checksum, version or alias mismatch, invalid series).
	ScrapeStateCorrupt ScrapeStateReason = "state_corrupt"
	// ScrapeStateUnavailable: the state directory or file could not be read or written.
	ScrapeStateUnavailable ScrapeStateReason = "state_unavailable"
	// ScrapeStateTooLarge: the carried set exceeds the bound, twice the target's
	// series limit (the previous committed set plus one cycle's own set).
	ScrapeStateTooLarge ScrapeStateReason = "state_too_large"
)

// ScrapeStateError is the only error the scrape state returns. Its text is
// static: no path, no alias, no OS error text.
type ScrapeStateError struct{ Reason ScrapeStateReason }

func (e *ScrapeStateError) Error() string { return "sources: scrape state: " + string(e.Reason) }

func scrapeStateFail(r ScrapeStateReason) error { return &ScrapeStateError{Reason: r} }

const (
	scrapeStateVersion = 1
	// scrapeStateMaxBytes bounds a state file (read and written) whatever the
	// series count: series names and labels are bounded per series by the decoder,
	// not in total.
	scrapeStateMaxBytes = 64 << 20
)

// ScrapeStateStore persists the carried-series set of each scrape target in one
// directory. A single node process owns the directory.
type ScrapeStateStore struct {
	mu  sync.Mutex
	dir string

	// beforeWrite is a test seam: when set it is called with the series about to
	// be written and a returned error fails that write. It is nil in production.
	beforeWrite func(series []SeriesRef) error
	// writes counts the successful writes (test observation).
	writes int
}

// OpenScrapeStateStore creates (if needed) and opens the state directory. A new
// directory is private (0700) like every directory the node creates.
func OpenScrapeStateStore(dir string) (*ScrapeStateStore, error) {
	if dir == "" || !isAbs(dir) {
		return nil, scrapeStateFail(ScrapeStateUnavailable)
	}
	if err := durablefs.MkdirAll(dir); err != nil {
		return nil, scrapeStateFail(ScrapeStateUnavailable)
	}
	return &ScrapeStateStore{dir: filepath.Clean(dir)}, nil
}

func (s *ScrapeStateStore) path(alias string) (string, error) {
	if !scrapeAliasRE.MatchString(alias) {
		return "", scrapeInvalid("scrape alias")
	}
	return filepath.Join(s.dir, alias+".scrape-state.json"), nil
}

type scrapeStateSeries struct {
	Name   string       `json:"name"`
	Labels model.Labels `json:"labels,omitempty"`
}

type scrapeStateDoc struct {
	Version int    `json:"version"`
	Alias   string `json:"alias"`
	// Identity is the hex SHA-256 of the target identity (scrapeStateIdentity)
	// the series were carried under.
	Identity string              `json:"identity"`
	Series   []scrapeStateSeries `json:"series"`
}

type scrapeStateFile struct {
	State  json.RawMessage `json:"state"`
	SHA256 string          `json:"sha256"`
}

// encodeScrapeState renders the checksummed file content of a document.
func encodeScrapeState(doc scrapeStateDoc) ([]byte, error) {
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	return json.Marshal(scrapeStateFile{State: body, SHA256: hex.EncodeToString(sum[:])})
}

// load returns the series carried for the target under the given identity.
// A target that has no file is a fresh target (no series). A file written under
// another identity (the target's configuration changed) is not inherited: no
// series, and inSync false, which makes the next write replace it whatever it
// holds. A file that cannot be trusted is an error. inSync reports that the file
// holds exactly the returned set (an absent file holds the empty set).
func (s *ScrapeStateStore) load(alias string, identity [32]byte, limit int) (series []SeriesRef, inSync bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.path(alias)
	if err != nil {
		return nil, false, err
	}
	f, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, scrapeStateFail(ScrapeStateUnavailable)
	}
	raw, err := io.ReadAll(io.LimitReader(f, scrapeStateMaxBytes+1))
	f.Close()
	if err != nil {
		return nil, false, scrapeStateFail(ScrapeStateUnavailable)
	}
	corrupt := scrapeStateFail(ScrapeStateCorrupt)
	var file scrapeStateFile
	if len(raw) > scrapeStateMaxBytes || json.Unmarshal(raw, &file) != nil {
		return nil, false, corrupt
	}
	sum := sha256.Sum256(file.State)
	if file.SHA256 != hex.EncodeToString(sum[:]) {
		return nil, false, corrupt
	}
	var doc scrapeStateDoc
	d := json.NewDecoder(bytes.NewReader(file.State))
	d.DisallowUnknownFields()
	if d.Decode(&doc) != nil || doc.Version != scrapeStateVersion || doc.Alias != alias {
		return nil, false, corrupt
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return nil, false, corrupt
	}
	if id, err := hex.DecodeString(doc.Identity); err != nil || len(id) != len(identity) {
		return nil, false, corrupt
	} else if !bytes.Equal(id, identity[:]) {
		return nil, false, nil // another target configuration: its series are not ours
	}
	if len(doc.Series) > limit {
		return nil, false, scrapeStateFail(ScrapeStateTooLarge)
	}
	out := make([]SeriesRef, 0, len(doc.Series))
	for _, x := range doc.Series {
		if x.Name == "" || x.Labels.Validate() != nil {
			return nil, false, corrupt
		}
		out = append(out, SeriesRef{Name: x.Name, Labels: x.Labels})
	}
	return scrapeDedupe(out), true, nil
}

// save atomically replaces the state of the target by series, which must not
// exceed limit.
func (s *ScrapeStateStore) save(alias string, identity [32]byte, series []SeriesRef, limit int) error {
	series = scrapeDedupe(series)
	if len(series) > limit {
		return scrapeStateFail(ScrapeStateTooLarge)
	}
	doc := scrapeStateDoc{Version: scrapeStateVersion, Alias: alias, Identity: hex.EncodeToString(identity[:]), Series: make([]scrapeStateSeries, 0, len(series))}
	for _, x := range series {
		doc.Series = append(doc.Series, scrapeStateSeries{Name: x.Name, Labels: x.Labels})
	}
	raw, err := encodeScrapeState(doc)
	if err != nil {
		return scrapeStateFail(ScrapeStateUnavailable)
	}
	if len(raw) > scrapeStateMaxBytes {
		return scrapeStateFail(ScrapeStateTooLarge)
	}
	p, err := s.path(alias)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.beforeWrite != nil {
		if err := s.beforeWrite(series); err != nil {
			return scrapeStateFail(ScrapeStateUnavailable)
		}
	}
	if writeFileAtomic(p, raw) != nil {
		return scrapeStateFail(ScrapeStateUnavailable)
	}
	s.writes++
	return nil
}

// scrapeStateIdentity is the identity a target's carried series belong to: the
// alias (the identifier its batch and record identifiers already bind), the URL
// it is read from, the organization (from the grant), project, source and
// producer it admits as, the resource every sample is attributed to, and the
// stale policy that consumes the set. A series carried under one identity is
// never marked under another: a stale marker names the series of one resource of
// one project, so another target (or the same alias after its configuration
// changed) must not inherit them. The source policy revision and the schedule
// are not identity: a policy change or a new interval keeps the carried series.
func scrapeStateIdentity(org model.ID, t ScrapeTarget) [32]byte {
	h := sha256.New()
	put := func(b []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	put([]byte("soundpost.sources.scrape.state.v1"))
	put([]byte(t.Alias))
	put([]byte(t.URL))
	put(org[:])
	p := t.Profile
	for _, id := range []model.ID{p.Project, p.Source, p.Producer, p.Resource.Service, p.Resource.Environment, p.Resource.Build} {
		put(id[:])
	}
	put([]byte(p.Resource.Instance))
	labels := scrapeSortedLabels(p.Resource.Labels)
	put(scrapeU64(uint64(len(labels))))
	for _, l := range labels {
		put([]byte(l.Name))
		put([]byte(l.Value))
	}
	flags := []byte{0, 0}
	if t.Stale.OnDisappear {
		flags[0] = 1
	}
	if t.Stale.OnFailure {
		flags[1] = 1
	}
	put(flags)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// scrapeUnion is the deduplicated, sorted union of two series sets.
func scrapeUnion(a, b []SeriesRef) []SeriesRef {
	all := make([]SeriesRef, 0, len(a)+len(b))
	all = append(all, a...)
	return scrapeDedupe(append(all, b...))
}

// scrapeSetDigest fingerprints a sorted, deduplicated series set, to tell
// whether a write would change the file.
func scrapeSetDigest(series []SeriesRef) [32]byte {
	h := sha256.New()
	for _, x := range series {
		k := scrapeSeriesKey(x.Name, x.Labels)
		h.Write(scrapeU64(uint64(len(k))))
		h.Write([]byte(k))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/arynyklas/soundpost/internal/artifacts/refledger"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

// The real-binary scenarios of the two-phase layout of the artifact ledger index and the replay pins
// (decision D70): the new binary keeps the previous release's per-project values current (expand) until
// `soundpost upgrade contract-indexes` drops them (contract). This file holds what those scenarios share:
// reading a node's stored control state, the structural rules of both phases, and the HTTP drivers that make
// a REAL binary write a ledger (an uploaded map named by an error occurrence, held by the issue producer)
// and a replay (an ingested replay chunk) and read them back (the artifact read and the replay stream).

// ---- the stored control state ----

// findDataFile is the first file called name below dir.
func findDataFile(dir, name string) string {
	var path string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && info.Name() == name && path == "" {
			path = p
		}
		return nil
	})
	return path
}

// copyForRead copies a database the voter holds open to a private file and opens the copy read-only.
func copyForRead(src string) (*bolt.DB, func(), error) {
	in, err := os.Open(src)
	if err != nil {
		return nil, nil, err
	}
	defer in.Close()
	tmp, err := os.CreateTemp("", "soundpost-mixed-db-")
	if err != nil {
		return nil, nil, err
	}
	if _, err = io.Copy(tmp, in); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, nil, err
	}
	tmp.Close()
	db, err := bolt.Open(tmp.Name(), 0o600, &bolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	if err != nil {
		os.Remove(tmp.Name())
		return nil, nil, err
	}
	return db, func() { db.Close(); os.Remove(tmp.Name()) }, nil
}

// readControlState is the stored control state and its seal of a voter (read from a copy of control.db; the
// seal check proves the copy was not torn).
func readControlState(dir string) (state, seal []byte, err error) {
	path := findDataFile(dir, "control.db")
	if path == "" {
		return nil, nil, errors.New("no control.db")
	}
	for range 5 {
		var db *bolt.DB
		var closeDB func()
		if db, closeDB, err = copyForRead(path); err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		err = db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("control"))
			if b == nil {
				return errors.New("no control bucket")
			}
			state, seal = bytes.Clone(b.Get([]byte("state"))), bytes.Clone(b.Get([]byte("state_seal")))
			return nil
		})
		closeDB()
		if err == nil {
			sum := sha256.Sum256(state)
			if bytes.Equal(sum[:], seal) {
				return state, seal, nil
			}
			err = errors.New("state seal does not match the copy")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, nil, err
}

// readOrgSettings is the Settings map of one organization in the stored control state of the data directory.
func readOrgSettings(dir string, org model.ID) (map[string]json.RawMessage, error) {
	state, _, err := readControlState(dir)
	if err != nil {
		return nil, err
	}
	var st struct {
		Orgs map[string]struct {
			Settings map[string]json.RawMessage
		}
	}
	if err = json.Unmarshal(state, &st); err != nil {
		return nil, err
	}
	o, ok := st.Orgs[org.String()]
	if !ok {
		return nil, errors.New("the stored state has no such organization")
	}
	return o.Settings, nil
}

// ---- the stored layout of the ledger index and the replay pins ----

type storedPin struct {
	Seq         uint64
	Head        model.Hash
	RetainUntil model.UnixNano
}

type storedGroup struct {
	Seq  uint64
	Head model.Hash
}

type storedAnchor struct {
	Version int
	Roots   int
	Index   model.Hash
}

// storedLayout is every value of the artifact ledger index and the replay pins that one project keeps in its
// organization's Settings, by family.
type storedLayout struct {
	Project      model.ID
	Ledgers      map[string]json.RawMessage // root -> ledger
	LegacyIndex  json.RawMessage            // artifact_refs_index:<project> (the previous release's whole-project index)
	LegacyAnchor json.RawMessage            // artifact_refs_index:anchor:<project>
	Shards       map[string]json.RawMessage // <xx> -> shard index
	ShardAnchors map[string]json.RawMessage
	LegacyPins   json.RawMessage            // replay_pins:<project> (the previous release's pin map)
	OwnPins      map[string]json.RawMessage // replay -> its own pin
	Groups       map[string]json.RawMessage // replay -> its checkpoint index
	Contracted   bool
	// Digest is a hash over every value of the families (all projects): equal digests mean no write touched them.
	Digest string
}

// layoutFamilies are the Settings key prefixes the layout digest covers.
var layoutFamilies = []string{model.ArtifactLedgerKeyPrefix, model.ArtifactLedgerIndexKeyPrefix, model.ReplayIndexKeyPrefix, model.ReplayPinKeyPrefix}

func parseLayout(settings map[string]json.RawMessage, project model.ID) storedLayout {
	p := project.String()
	l := storedLayout{Project: project, Ledgers: map[string]json.RawMessage{}, Shards: map[string]json.RawMessage{}, ShardAnchors: map[string]json.RawMessage{}, OwnPins: map[string]json.RawMessage{}, Groups: map[string]json.RawMessage{}}
	h := sha256.New()
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := settings[k]
		for _, f := range layoutFamilies {
			if strings.HasPrefix(k, f) {
				h.Write([]byte(k))
				h.Write([]byte{0})
				h.Write(v)
				h.Write([]byte{0})
				break
			}
		}
		switch {
		case k == model.IndexesContractedKey:
			l.Contracted = true
		case k == refledger.LegacyIndexKey(project):
			l.LegacyIndex = v
		case k == refledger.LegacyAnchorKey(project):
			l.LegacyAnchor = v
		case strings.HasPrefix(k, model.ArtifactLedgerKeyPrefix+p+":"):
			l.Ledgers[strings.TrimPrefix(k, model.ArtifactLedgerKeyPrefix+p+":")] = v
		case strings.HasPrefix(k, model.ArtifactLedgerIndexKeyPrefix+"shard:"+p+":"):
			l.Shards[strings.TrimPrefix(k, model.ArtifactLedgerIndexKeyPrefix+"shard:"+p+":")] = v
		case strings.HasPrefix(k, model.ArtifactLedgerIndexKeyPrefix+"shardanchor:"+p+":"):
			l.ShardAnchors[strings.TrimPrefix(k, model.ArtifactLedgerIndexKeyPrefix+"shardanchor:"+p+":")] = v
		case k == model.ReplayPinKeyPrefix+p:
			l.LegacyPins = v
		case strings.HasPrefix(k, model.ReplayPinKeyPrefix+p+":"):
			l.OwnPins[strings.TrimPrefix(k, model.ReplayPinKeyPrefix+p+":")] = v
		case strings.HasPrefix(k, model.ReplayIndexKeyPrefix+p+":"):
			l.Groups[strings.TrimPrefix(k, model.ReplayIndexKeyPrefix+p+":")] = v
		}
	}
	l.Digest = hex.EncodeToString(h.Sum(nil)[:12])
	return l
}

func readStoredLayout(dir string, org, project model.ID) (storedLayout, error) {
	settings, err := readOrgSettings(dir, org)
	if err != nil {
		return storedLayout{}, err
	}
	return parseLayout(settings, project), nil
}

// perProjectKeys names the exact per-project values of the previous release that are present.
func (l storedLayout) perProjectKeys() []string {
	var out []string
	if l.LegacyIndex != nil {
		out = append(out, refledger.LegacyIndexKey(l.Project))
	}
	if l.LegacyAnchor != nil {
		out = append(out, refledger.LegacyAnchorKey(l.Project))
	}
	if l.LegacyPins != nil {
		out = append(out, model.ReplayPinKeyPrefix+l.Project.String())
	}
	return out
}

func (l storedLayout) summary() string {
	return fmt.Sprintf("ledgers=%d groups=%d shards=%d own_pins=%d per_project=%v contracted=%t digest=%s", len(l.Ledgers), len(l.Groups), len(l.Shards), len(l.OwnPins), l.perProjectKeys(), l.Contracted, l.Digest)
}

// verifyIndexValue decodes one index value with its anchor (the rule of refledger.verifyIndex, independently).
func verifyIndexValue(raw, rawAnchor json.RawMessage) (map[string]refledger.IndexEntry, string) {
	var idx map[string]refledger.IndexEntry
	if json.Unmarshal(raw, &idx) != nil || idx == nil {
		return nil, "the index does not decode"
	}
	var a storedAnchor
	if rawAnchor == nil {
		return nil, "the index has no anchor"
	}
	if json.Unmarshal(rawAnchor, &a) != nil || a.Version != refledger.Version || a.Roots != len(idx) || a.Index != model.HashCanonical(raw) {
		return nil, "the anchor does not pin the index"
	}
	return idx, ""
}

// problems is what the stored values say is wrong in the phase: expand (contracted false) or contracted.
//
//	expand:     no contracted marker; the whole-project index (and its anchor) names exactly the stored ledgers with
//	            their (Seq, Head); every replay's checkpoint index is pinned (Seq, Head) in the whole-project pin map;
//	            every shard that exists is anchored.
//	contracted: the marker; none of the three per-project values; the shards together name exactly the stored
//	            ledgers; every replay has a pin of its own that pins its checkpoint index.
func (l storedLayout) problems(contracted bool) []string {
	var out []string
	add := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }
	ledgers := map[string]refledger.IndexEntry{}
	for root, raw := range l.Ledgers {
		var led refledger.Ledger
		if json.Unmarshal(raw, &led) != nil || led.Root.String() != root || led.Project != l.Project {
			add("ledger %s does not decode as the ledger of that root", root)
			continue
		}
		ledgers[root] = refledger.IndexEntry{Seq: led.Seq, Head: led.Head}
	}
	same := func(what string, idx map[string]refledger.IndexEntry) {
		for root, e := range ledgers {
			got, ok := idx[root]
			switch {
			case !ok:
				add("%s has no entry for the ledger %s", what, root)
			case got != e:
				add("%s pins (Seq %d) for the ledger %s, the ledger is at Seq %d", what, got.Seq, root, e.Seq)
			}
		}
		for root := range idx {
			if _, ok := ledgers[root]; !ok {
				add("%s names the root %s, which has no ledger", what, root)
			}
		}
	}
	if contracted != l.Contracted {
		add("contracted marker present=%t, want %t", l.Contracted, contracted)
	}
	shardUnion := map[string]refledger.IndexEntry{}
	for shard, raw := range l.Shards {
		idx, why := verifyIndexValue(raw, l.ShardAnchors[shard])
		if why != "" {
			add("shard %s: %s", shard, why)
			continue
		}
		for k, v := range idx {
			shardUnion[k] = v
		}
	}
	for shard := range l.ShardAnchors {
		if _, ok := l.Shards[shard]; !ok {
			add("shard anchor %s has no shard", shard)
		}
	}
	pins := map[string]storedPin{}
	if l.LegacyPins != nil {
		if json.Unmarshal(l.LegacyPins, &pins) != nil {
			add("the whole-project pin map does not decode")
		}
	}
	own := map[string]storedPin{}
	for replay, raw := range l.OwnPins {
		var p storedPin
		if json.Unmarshal(raw, &p) != nil {
			add("the pin of replay %s does not decode", replay)
			continue
		}
		own[replay] = p
	}
	groups := map[string]storedGroup{}
	for replay, raw := range l.Groups {
		var g storedGroup
		if json.Unmarshal(raw, &g) != nil {
			add("the checkpoint index of replay %s does not decode", replay)
			continue
		}
		groups[replay] = g
	}
	if contracted {
		for _, k := range l.perProjectKeys() {
			add("the per-project value %s is still stored", k)
		}
		same("the shards", shardUnion)
		for replay, g := range groups {
			if p, ok := own[replay]; !ok || p.Seq != g.Seq || p.Head != g.Head {
				add("replay %s has no pin of its own that pins its checkpoint index (Seq %d)", replay, g.Seq)
			}
		}
		return out
	}
	if len(ledgers) > 0 || l.LegacyIndex != nil || l.LegacyAnchor != nil {
		if l.LegacyIndex == nil {
			add("no whole-project index %s although ledgers are stored", refledger.LegacyIndexKey(l.Project))
		} else if idx, why := verifyIndexValue(l.LegacyIndex, l.LegacyAnchor); why != "" {
			add("whole-project index: %s", why)
		} else {
			same("the whole-project index", idx)
		}
	}
	if len(groups) > 0 {
		if l.LegacyPins == nil {
			add("no whole-project pin map although replays are stored")
		}
		for replay, g := range groups {
			if p, ok := pins[replay]; !ok || p.Seq != g.Seq || p.Head != g.Head {
				add("the whole-project pin map does not pin the checkpoint index of replay %s (Seq %d)", replay, g.Seq)
			}
		}
	}
	return out
}

// requireExpanded requires the shape of the expand phase after a NEW binary wrote: the problems list is
// empty and the shards, per-replay pins and the three per-project values are all present.
func (l storedLayout) requireExpanded(needShards, needPins bool) []string {
	out := l.problems(false)
	if len(l.perProjectKeys()) != 3 && (len(l.Ledgers) > 0 || len(l.Groups) > 0) {
		out = append(out, fmt.Sprintf("the per-project values present: %v (want the index, its anchor and the pin map)", l.perProjectKeys()))
	}
	if needShards && len(l.Shards) == 0 {
		out = append(out, "no shard of the sharded index is stored")
	}
	if needPins && len(l.OwnPins) == 0 {
		out = append(out, "no per-replay pin is stored")
	}
	return out
}

// waitStored polls the stored state of dir until cond holds on the project's layout.
func waitStored(dir string, org, project model.ID, limit time.Duration, what string, cond func(storedLayout) bool) (storedLayout, error) {
	deadline := time.Now().Add(limit)
	var last storedLayout
	var lastErr error
	for time.Now().Before(deadline) {
		if l, err := readStoredLayout(dir, org, project); err == nil {
			last = l
			if cond(l) {
				return l, nil
			}
		} else {
			lastErr = err
		}
		time.Sleep(300 * time.Millisecond)
	}
	return last, fmt.Errorf("stored state never showed %s within %s (last: %s, read error %v)", what, limit, last.summary(), lastErr)
}

// ---- users and admin commands ----

// expandUser is one account with its own cookie jar.
type expandUser struct {
	email, password string
	id              model.ID
	jar             http.CookieJar
	session         auth.Session
}

var expandStale int

// on is a copy of site (its address and its pinned certificate) whose client carries the user's cookies.
func (u *expandUser) on(site *installSite) *installSite {
	cp := *site
	cp.client = &http.Client{Transport: site.client.Transport, Jar: u.jar, Timeout: site.client.Timeout, CheckRedirect: site.client.CheckRedirect}
	return &cp
}

func newExpandUser(_ *installSite, email, password string) *expandUser {
	jar, _ := cookiejar.New(nil)
	return &expandUser{email: email, password: password, jar: jar}
}

// login opens a new session on the node site addresses (a restart, or another binary, needs one again).
func (u *expandUser) login(site *installSite) error {
	s := u.on(site)
	status, raw, err := postRetryStale(s, "/api/v1/login", map[string]string{"Email": u.email, "Password": u.password, "Code": ""}, "", "", &expandStale)
	if err = requireSmokeResponse("expand_login", status, 200, raw, err); err != nil {
		return err
	}
	return json.Unmarshal(raw, &u.session)
}

// expandAdmin is one admin command of org as the owner, repeated while the control revision it read moved.
func expandAdmin(owner *expandUser, site *installSite, org model.ID, kind string, p auth.AdminPayload) error {
	s := owner.on(site)
	p.Reason = "expand/contract smoke"
	payload, _ := json.Marshal(p)
	for attempt := 0; ; attempt++ {
		status, raw, err := s.post("/api/v1/admin/read", struct {
			Kind string `json:"kind"`
		}{"organizations"}, owner.session.CSRF, "")
		if err = requireSmokeResponse("expand_admin_read", status, 200, raw, err); err != nil {
			return err
		}
		var view auth.AdminView
		if err = json.Unmarshal(raw, &view); err != nil {
			return err
		}
		status, raw, err = s.post("/api/v1/admin/commands", auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: view.Revision, OrgID: org, Kind: kind, Payload: payload}, owner.session.CSRF, "")
		if err == nil && (status == 400 || status == 409) && (bytes.Contains(raw, []byte(`"stale"`)) || bytes.Contains(raw, []byte(`"conflict"`))) && attempt < 40 {
			expandStale++
			time.Sleep(250 * time.Millisecond)
			continue
		}
		return requireSmokeResponse("expand_admin_"+kind, status, 200, raw, err)
	}
}

// provisionAnalyst creates the reader-and-artifact account the scenarios read with (telemetry, artifacts and
// replays) and logs it in on site. owner is the installation's system administrator, logged in on site.
func provisionAnalyst(owner *expandUser, site *installSite, fx *installFixture) (*expandUser, error) {
	u := newExpandUser(site, "analyst@expand-smoke.invalid", "expand smoke analyst password 2026")
	u.id = model.NewID()
	for _, step := range []struct {
		kind string
		p    auth.AdminPayload
	}{
		{"create_user", auth.AdminPayload{ID: u.id, Email: u.email, Password: u.password}},
		{"membership", auth.AdminPayload{UserID: u.id, Enabled: true}},
		{"grant", auth.AdminPayload{UserID: u.id, ProjectID: fx.project, Enabled: true, Permissions: []string{string(auth.Read), string(auth.ArtifactRead), string(auth.ArtifactWrite), string(httpapi.ReplayRead)}}},
	} {
		if err := expandAdmin(owner, site, fx.org, step.kind, step.p); err != nil {
			return nil, err
		}
	}
	return u, u.login(site)
}

// loginOwner logs the installation's system administrator in on a client of its own.
func loginOwner(site *installSite, fx *installFixture) (*expandUser, error) {
	o := newExpandUser(site, "owner@install-smoke.invalid", fx.password)
	return o, o.login(site)
}

// ---- real writes and reads ----

// expandArtifact is one uploaded source map.
type expandArtifact struct {
	label   string
	receipt model.ArtifactReferenceIntent
}

func (a expandArtifact) root() model.ID { return a.receipt.ID }

func expandMap(salt string) []byte {
	return []byte(`{"version":3,"file":"` + salt + `.js","sources":["` + salt + `.ts"],"names":[],"mappings":"AAAA,CAAC;AACA"}`)
}

// tryUploadArtifact is one attempt to publish a source map (POST /api/v1/artifacts, multipart) as the analyst:
// the status (0 when the node did not answer), the receipt of a 200 and the start of any other body.
func tryUploadArtifact(site *installSite, u *expandUser, fx *installFixture, salt string) (int, expandArtifact, string, error) {
	content := expandMap(salt)
	mapHash := sha256.Sum256(content)
	generated := sha256.Sum256([]byte("generated " + salt))
	manifest := model.ArtifactManifest{Version: 1, Org: fx.org, Project: fx.project, Source: fx.source, Build: fx.build, DebugID: "expand-" + salt, GeneratedSHA256: generated, MapSHA256: mapHash, Path: salt + ".js.map", Size: model.Uint64(len(content)), RetainUntil: model.UnixNano(time.Now().Add(2 * time.Hour).UnixNano())}
	s := u.on(site)
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, _ := w.CreateFormField("manifest")
	encoded, _ := json.Marshal(manifest)
	part.Write(encoded)
	part, _ = w.CreateFormFile("file", "artifact.map")
	part.Write(content)
	w.Close()
	req, err := http.NewRequest("POST", s.base+"/api/v1/artifacts", &body)
	if err != nil {
		return 0, expandArtifact{}, "", err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Origin", s.base)
	req.Header.Set("X-CSRF-Token", u.session.CSRF)
	status, raw, _, err := s.do(req)
	if err != nil || status != http.StatusOK {
		return status, expandArtifact{}, trunc(string(raw), 160), err
	}
	var published model.ArtifactReferenceIntent
	if model.StrictJSON(raw, &published) != nil {
		return status, expandArtifact{}, "receipt does not decode", errors.New("receipt does not decode")
	}
	return status, expandArtifact{label: salt, receipt: published}, "", nil
}

// uploadArtifact publishes a source map, repeating a retryable answer (a 503, or the typed stale fault of a
// control write that lost its index race).
func uploadArtifact(site *installSite, u *expandUser, fx *installFixture, salt string) (expandArtifact, error) {
	var last string
	for range 40 {
		status, a, detail, err := tryUploadArtifact(site, u, fx, salt)
		if err == nil && status == http.StatusOK {
			return a, nil
		}
		last = fmt.Sprintf("status %d err %v body %s", status, err, detail)
		if err == nil && status != 503 && !(status == 400 && strings.Contains(detail, `"stale"`)) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "upload %s refused: %s\n", salt, last)
	return expandArtifact{}, &smokeFailure{Stage: "expand_upload_" + salt, Code: "upload_refused"}
}

// readArtifact reads the retained map back as the analyst: status and whether the bytes are the retained ones.
func readArtifact(site *installSite, u *expandUser, fx *installFixture, a expandArtifact) (int, bool, string, error) {
	status, body, err := u.on(site).post("/api/v1/artifacts", httpapi.ArtifactReadRequest{Operation: "read", Org: fx.org, Project: fx.project, ID: a.root()}, u.session.CSRF, "")
	if err != nil {
		return 0, false, "", err
	}
	if status != http.StatusOK {
		return status, false, trunc(string(body), 160), nil
	}
	return status, model.HashCanonical(body) == a.receipt.Map.Hash && uint64(len(body)) == retainedBytes(a.receipt.Map), "", nil
}

// requireArtifactRead requires a 200 with the retained bytes.
func requireArtifactRead(site *installSite, u *expandUser, fx *installFixture, a expandArtifact, who string) error {
	var status int
	var intact bool
	var detail string
	var err error
	for range 20 {
		if status, intact, detail, err = readArtifact(site, u, fx, a); err == nil && status == 200 && intact {
			return nil
		}
		if err == nil && status != 503 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "%s: artifact %s (%s): status %d intact=%t err=%v %s\n", who, a.label, a.root(), status, intact, err, detail)
	code := "artifact_read_failed"
	if bytes.Contains([]byte(detail), []byte("corrupt")) {
		code = "artifact_read_corrupt"
	}
	return &smokeFailure{Stage: "expand_read_artifact_" + who, Code: code, Actual: status, Expected: 200}
}

// namingRecord is one error occurrence whose frame names the artifact: the issue producer then holds the map
// for the occurrence's issue, which is a ledger write (refledger.Store) in the node that leads the producers.
func namingRecord(fx *installFixture, root model.ID) model.Record {
	resource := model.Resource{Service: fx.service, Environment: fx.environment, Build: fx.build, Instance: "instance", Labels: model.Labels{}}
	col := uint32(1)
	return model.Record{ID: model.NewID(), Kind: model.ErrorKind, ObservedAt: model.UnixNano(time.Now().Add(-time.Second).UnixNano()), Resource: resource, Payload: model.Payload{Error: &model.ErrorOccurrence{
		Occurrence: model.NewID(), Class: "ExpandError", Mechanism: "manual", Build: fx.build, Handled: true,
		Frames: []model.Frame{{Module: "app", Function: "run", Artifact: root.String(), Line: 1, Column: &col, InApp: true}}}}}
}

// replayRecord is one NEW replay: a checkpoint chunk (checkpoint sequence = sequence).
func replayRecord(fx *installFixture) (model.Record, model.ID) {
	now := time.Now().UnixNano()
	resource := model.Resource{Service: fx.service, Environment: fx.environment, Build: fx.build, Instance: "instance", Labels: model.Labels{}}
	clock := model.TraceClock{Wall: model.UnixNano(now), Mono: 1000, Domain: model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}}
	chunk := model.ReplayChunk{Replay: model.NewID(), Session: model.NewID(), Recorder: "1", Sequence: 1, CheckpointSequence: 1, PolicyRevision: fx.policy(), Clock: clock}
	return model.Record{ID: model.NewID(), Kind: model.Replay, ObservedAt: clock.Wall, Resource: resource, Payload: model.Payload{Replay: &chunk}}, chunk.Replay
}

func batchOf(fx *installFixture, rec model.Record) (model.Batch, error) {
	batch := model.Batch{Version: 1, Project: fx.project, Source: fx.source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: fx.policy(), Records: []model.Record{rec}}
	var err error
	batch.RouteSlot, err = model.OwnerSlot(fx.org, fx.project, fx.source, batch.Producer, rec)
	return batch, err
}

// policy is the source policy revision the fixture's batches carry.
func (fx *installFixture) policy() model.Revision {
	if fx.policyRevision == 0 {
		return 1
	}
	return fx.policyRevision
}

// tryIngestRecord is one attempt: whether the node acknowledged the record (status 200 and a receipt).
func tryIngestRecord(site *installSite, fx *installFixture, rec model.Record) bool {
	batch, err := batchOf(fx, rec)
	if err != nil {
		return false
	}
	status, raw, err := site.ingest(batch, fx.credential)
	var receipt model.Receipt
	return err == nil && status == 200 && json.Unmarshal(raw, &receipt) == nil && receipt.Cursor.Index != 0
}

func ingestRecord(site *installSite, fx *installFixture, rec model.Record, stage string) error {
	batch, err := batchOf(fx, rec)
	if err != nil {
		return err
	}
	status, raw, _, err := retryIngest(site, batch, fx.credential, 120*time.Second)
	if err != nil || status != 200 {
		fmt.Fprintf(os.Stderr, "%s: ingest status %d err %v body %s\n", stage, status, err, trunc(string(raw), 160))
		return httpSmokeFailure(stage, status, 200, raw)
	}
	var receipt model.Receipt
	if json.Unmarshal(raw, &receipt) != nil || receipt.Cursor.Index == 0 {
		return &smokeFailure{Stage: stage, Code: "receipt_decode"}
	}
	return nil
}

func ingestNaming(site *installSite, fx *installFixture, root model.ID) error {
	return ingestRecord(site, fx, namingRecord(fx, root), "expand_error_"+root.String()[:8])
}

// ingestReplay records one NEW replay and returns its ID.
func ingestReplay(site *installSite, fx *installFixture) (model.ID, error) {
	rec, id := replayRecord(fx)
	return id, ingestRecord(site, fx, rec, "expand_replay_"+id.String()[:8])
}

// streamReplay reads the replay back through POST /api/v1/replays/stream as the analyst. It requires an
// open line, the checkpoint at sequence 1 and the end line, and no error, revoke or truncated line; the shape
// of the stream is returned.
func streamReplay(site *installSite, u *expandUser, fx *installFixture, replay model.ID) (string, error) {
	raw, _ := json.Marshal(httpapi.ReplayBody{ScopeFields: httpapi.ScopeFields{Org: fx.org}, Project: fx.project, Replay: replay})
	s := u.on(site)
	var shape, detail string
	for range 20 {
		req, err := http.NewRequest("POST", s.base+"/api/v1/replays/stream", bytes.NewReader(raw))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", s.base)
		req.Header.Set("X-CSRF-Token", u.session.CSRF)
		resp, err := s.client.Do(req)
		if err != nil {
			detail = err.Error()
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if resp.StatusCode != 200 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			detail = fmt.Sprintf("status %d %s", resp.StatusCode, trunc(string(b), 160))
			if resp.StatusCode == 503 {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			break
		}
		var lines []httpapi.ReplayLine
		br := bufio.NewReaderSize(resp.Body, 64<<10)
		for len(lines) < 1000 {
			line, rerr := br.ReadBytes('\n')
			if len(line) > 0 {
				var l httpapi.ReplayLine
				if json.Unmarshal(line, &l) == nil {
					lines = append(lines, l)
				}
			}
			if rerr != nil {
				break
			}
		}
		resp.Body.Close()
		shape = evidenceShape(lines)
		good := len(lines) >= 3 && lines[0].Type == "open" && lines[len(lines)-1].Type == "end"
		checkpoint := false
		for _, l := range lines {
			switch l.Type {
			case "error", "revoke", "truncated", "not_available", "unsupported":
				good = false
				detail = fmt.Sprintf("line %s code %q reason %q", l.Type, l.Code, l.Reason)
			case "checkpoint":
				checkpoint = checkpoint || l.Sequence != nil && uint64(*l.Sequence) == 1
			}
		}
		if good && checkpoint {
			return shape, nil
		}
		if detail == "" {
			detail = "shape " + shape
		}
		break
	}
	fmt.Fprintf(os.Stderr, "replay %s stream refused: %s (shape %s)\n", replay, detail, shape)
	code := "replay_stream_failed"
	if strings.Contains(detail, "corrupt") {
		code = "replay_stream_corrupt"
	}
	return shape, &smokeFailure{Stage: "expand_read_replay", Code: code}
}

// ---- the operator step ----

// runContractCLI runs `soundpost upgrade contract-indexes` (the binary of the candidate) against base as the
// installation's administrator and returns its combined output and exit status.
func runContractCLI(bin, base, caFile, email, password string) (string, int, error) {
	dir, err := os.MkdirTemp("", "soundpost-contract-")
	if err != nil {
		return "", 0, err
	}
	defer os.RemoveAll(dir)
	pf := filepath.Join(dir, "password")
	if err = os.WriteFile(pf, []byte(password+"\n"), 0o600); err != nil {
		return "", 0, err
	}
	cmd := exec.Command(bin, "upgrade", "contract-indexes", "--url", base, "--email", email, "--password-file", pf, "--reason", "expand/contract smoke", "--ca", caFile)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return strings.TrimSpace(string(out)), 0, nil
	case errors.As(err, &exit):
		return strings.TrimSpace(string(out)), exit.ExitCode(), nil
	}
	return strings.TrimSpace(string(out)), -1, err
}

// ---- one ledger write and one replay write, by whoever runs the node ----

// expandWrite is what one real write round put in the installation.
type expandWrite struct {
	artifact expandArtifact
	replay   model.ID
}

// writeLedgerAndReplay uploads a map, ingests an error naming it and a new replay through site, and waits until
// the node's stored state at dir holds the map's ledger and the replay's checkpoint index.
func writeLedgerAndReplay(site *installSite, u *expandUser, fx *installFixture, dir, salt string) (expandWrite, error) {
	var w expandWrite
	var err error
	if w.artifact, err = uploadArtifact(site, u, fx, salt); err != nil {
		return w, err
	}
	if err = ingestNaming(site, fx, w.artifact.root()); err != nil {
		return w, err
	}
	if w.replay, err = ingestReplay(site, fx); err != nil {
		return w, err
	}
	root, replay := w.artifact.root().String(), w.replay.String()
	_, err = waitStored(dir, fx.org, fx.project, 180*time.Second, "the ledger of "+salt+" and the replay", func(l storedLayout) bool {
		_, ledger := l.Ledgers[root]
		_, group := l.Groups[replay]
		return ledger && group
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return w, &smokeFailure{Stage: "expand_write_" + salt, Code: "ledger_or_replay_not_stored"}
	}
	return w, nil
}

// requireReads reads every write back through the node site addresses.
func requireReads(site *installSite, u *expandUser, fx *installFixture, who string, writes []expandWrite) error {
	for _, w := range writes {
		if w.artifact.root() != (model.ID{}) {
			if err := requireArtifactRead(site, u, fx, w.artifact, who); err != nil {
				return err
			}
		}
		if w.replay == (model.ID{}) {
			continue
		}
		if _, err := streamReplay(site, u, fx, w.replay); err != nil {
			fmt.Fprintf(os.Stderr, "%s could not read replay %s\n", who, w.replay)
			return annotateSmokeFailure("expand", "expand_read_replay_"+who, model.ID{}, err)
		}
	}
	return nil
}

func expandProblem(stage, code string, problems []string) error {
	for _, p := range problems {
		fmt.Fprintf(os.Stderr, "%s: %s\n", stage, p)
	}
	return &smokeFailure{Stage: stage, Code: code}
}

// ---- the single-node stage of RunUpgradeRollback ----

// startOn starts the host's binary on the data directory and waits until it serves, with the site pointed at it.
func startOn(h *binaryHost, site *installSite, label string) (installRun, error) {
	r, err := h.start()
	if err != nil {
		return nil, err
	}
	if _, err = r.waitCertificate(); err != nil {
		r.kill()
		return nil, err
	}
	site.base = r.url()
	if err = r.release(); err != nil {
		r.kill()
		return nil, err
	}
	if err = r.waitReady(90 * time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "%s did not become ready; log tail:\n%s\n", label, trunc(lastLines(h.logs.String(), 6), 800))
		r.kill()
		return nil, &smokeFailure{Stage: "expand_" + label + "_ready", Code: "not_ready"}
	}
	return r, nil
}

// runExpandContractStage is the part of the upgrade/rollback test that exercises the two-phase layout (D70).
// The data directory is the installation of RunUpgradeRollback (made by the previous release); oldHost and newHost
// are the previous release's and the candidate's binaries on it.
//
//  1. new:  writes a ledger (an uploaded map named by an error occurrence) and two replays; the stored state
//     then holds the shards, the per-replay pins AND the previous release's three per-project values.
//  2. old:  starts on that very directory, is ready, reads every ledger and replay the new binary wrote (no
//     corrupt), writes a ledger and a replay of its own (its layout alone).
//  3. new:  starts again and reads everything, including what the previous release wrote; writes again.
//  4. contract-indexes on the candidate: the per-project values are gone, the marker is present, everything is
//     still read, a further ledger and replay write leave no per-project value, and a repeat is a no-op.
//  5. recorded (not asserted): the previous release on a COPY of the contracted directory.
func runExpandContractStage(oldHost, newHost *binaryHost, site *installSite, fx *installFixture, report map[string]any) (result error) {
	stage := "expand_new_start"
	defer func() { result = annotateSmokeFailure("upgrade_rollback", stage, model.ID{}, result) }()
	dir := oldHost.dir
	rep := map[string]any{}
	report["expand_contract"] = rep
	var writes []expandWrite
	layoutOf := func() (storedLayout, error) { return readStoredLayout(dir, fx.org, fx.project) }

	// ---- 1. the candidate writes ----
	r, err := startOn(newHost, site, "new1")
	if err != nil {
		return err
	}
	defer func() { r.kill() }()
	owner, err := loginOwner(site, fx)
	if err != nil {
		return err
	}
	analyst, err := provisionAnalyst(owner, site, fx)
	if err != nil {
		return err
	}
	stage = "expand_new_write"
	w1, err := writeLedgerAndReplay(site, analyst, fx, dir, "new-1")
	if err != nil {
		return err
	}
	w1b, err := ingestReplay(site, fx)
	if err != nil {
		return err
	}
	writes = append(writes, w1, expandWrite{replay: w1b})
	if err = requireReads(site, analyst, fx, "new", writes); err != nil {
		return err
	}
	if err = r.stop(); err != nil {
		return err
	}
	stage = "expand_new_state"
	l, err := layoutOf()
	if err != nil {
		return err
	}
	rep["after_new_writes"] = l.summary()
	// The verdict on the shape of the stored state comes after the previous release has tried to read it: a
	// build that does not keep the previous release's values is then reported by what the previous release answers.
	shape := l.requireExpanded(true, true)
	for _, p := range shape {
		fmt.Fprintf(os.Stderr, "expand_new_state (verdict deferred until the previous release has read): %s\n", p)
	}

	// ---- 2. the previous release on that very directory ----
	stage = "expand_old_start"
	if r, err = startOn(oldHost, site, "old"); err != nil {
		return err
	}
	if analyst.login(site) != nil {
		return &smokeFailure{Stage: stage, Code: "old_login_refused"}
	}
	stage = "expand_old_reads_new"
	if err = requireReads(site, analyst, fx, "old", writes); err != nil {
		return err
	}
	rep["old_reads_new_ledger_and_replays"] = "ok"
	if len(shape) > 0 {
		return expandProblem("expand_new_state", "expanded_state_wrong", shape)
	}
	stage = "expand_old_writes"
	w2, err := writeLedgerAndReplay(site, analyst, fx, dir, "old-2")
	if err != nil {
		return err
	}
	writes = append(writes, w2)
	if err = requireReads(site, analyst, fx, "old", writes); err != nil {
		return err
	}
	if err = r.stop(); err != nil {
		return err
	}
	if l, err = layoutOf(); err != nil {
		return err
	}
	rep["after_old_writes"] = l.summary()
	if problems := l.problems(false); len(problems) > 0 {
		return expandProblem("expand_old_state", "state_after_old_writes_wrong", problems)
	}

	// ---- 3. the candidate again: reads what the previous release wrote ----
	stage = "expand_new2_start"
	if r, err = startOn(newHost, site, "new2"); err != nil {
		return err
	}
	if err = analyst.login(site); err != nil {
		return err
	}
	if owner, err = loginOwner(site, fx); err != nil {
		return err
	}
	stage = "expand_new2_reads_all"
	if err = requireReads(site, analyst, fx, "new2", writes); err != nil {
		return err
	}
	stage = "expand_new2_write"
	w3, err := writeLedgerAndReplay(site, analyst, fx, dir, "new-3")
	if err != nil {
		return err
	}
	writes = append(writes, w3)
	if err = requireReads(site, analyst, fx, "new2", writes); err != nil {
		return err
	}
	rep["new_reads_everything_incl_what_old_wrote"] = true
	l, err = layoutOf()
	if err != nil {
		return err
	}
	if problems := l.requireExpanded(true, true); len(problems) > 0 {
		return expandProblem("expand_new2_state", "expanded_state_wrong", problems)
	}
	rep["before_contract"] = l.summary()

	// ---- 4. contract ----
	stage = "contract_run"
	out, code, err := runContractCLI(newHost.path, r.url(), filepath.Join(dir, "server.crt"), owner.email, owner.password)
	if err != nil {
		return err
	}
	rep["contract_output"], rep["contract_exit"] = out, code
	if code != 0 || !strings.Contains(out, "indexes contracted") {
		fmt.Fprintf(os.Stderr, "contract-indexes exit %d: %s\n", code, out)
		return &smokeFailure{Stage: stage, Code: "contract_refused", Actual: code}
	}
	stage = "contract_state"
	if l, err = layoutOf(); err != nil {
		return err
	}
	rep["after_contract"] = l.summary()
	if problems := l.problems(true); len(problems) > 0 {
		return expandProblem(stage, "contracted_state_wrong", problems)
	}
	if err = requireReads(site, analyst, fx, "new_contracted", writes); err != nil {
		return err
	}
	stage = "contract_write"
	w4, err := writeLedgerAndReplay(site, analyst, fx, dir, "new-4")
	if err != nil {
		return err
	}
	writes = append(writes, w4)
	if err = requireReads(site, analyst, fx, "new_contracted", writes); err != nil {
		return err
	}
	if l, err = layoutOf(); err != nil {
		return err
	}
	rep["after_contracted_writes"] = l.summary()
	if problems := l.problems(true); len(problems) > 0 {
		return expandProblem("contract_after_write", "per_project_value_written_after_contract", problems)
	}
	stage = "contract_repeat"
	digest := l.Digest
	out, code, err = runContractCLI(newHost.path, r.url(), filepath.Join(dir, "server.crt"), owner.email, owner.password)
	if err != nil {
		return err
	}
	rep["repeat_output"] = out
	if code != 0 || !strings.Contains(out, "indexes already contracted") {
		fmt.Fprintf(os.Stderr, "repeat contract-indexes exit %d: %s\n", code, out)
		return &smokeFailure{Stage: stage, Code: "repeat_not_a_noop", Actual: code}
	}
	if l, err = layoutOf(); err != nil {
		return err
	}
	if l.Digest != digest {
		return &smokeFailure{Stage: stage, Code: "repeat_changed_the_stored_layout"}
	}
	if err = r.stop(); err != nil {
		return err
	}
	if l, err = layoutOf(); err != nil {
		return err
	}
	if problems := l.problems(true); len(problems) > 0 {
		return expandProblem("contract_final_state", "contracted_state_wrong", problems)
	}
	rep["final"] = l.summary()

	// ---- 5. recorded: the previous release on a copy of the contracted directory ----
	stage = "contract_old_recorded"
	copyDir, err := os.MkdirTemp("", "soundpost-contracted-copy-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(copyDir)
	if err = copyDataDir(dir, copyDir); err != nil {
		return err
	}
	probe := &binaryHost{path: oldHost.path, dir: copyDir, holdDir: oldHost.holdDir, logs: oldHost.logs}
	pr, err := probe.start()
	if err != nil {
		return err
	}
	if _, err = pr.waitCertificate(); err != nil {
		pr.kill()
		return err
	}
	probeSite := *site
	probeSite.base = pr.url()
	_ = pr.release()
	if pr.waitReady(60*time.Second) != nil {
		rep["old_on_contracted_copy"] = "unready"
	} else {
		if analyst.login(&probeSite) != nil {
			rep["old_on_contracted_copy"] = "ready, login refused"
		} else {
			st, intact, detail, _ := readArtifact(&probeSite, analyst, fx, writes[0].artifact)
			rep["old_on_contracted_copy"] = fmt.Sprintf("ready; artifact read of a ledger the candidate wrote: status %d intact=%t %s", st, intact, detail)
		}
	}
	pr.kill()
	return nil
}

// lastLines is the last n lines of s on one line, for failure messages.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " ⏎ ")
}

// trunc cuts s to n bytes for failure messages.
func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// oldTracksRecords says whether the previous release tracks the per-object records of D59 itself: true for
// 5475ef6 (the default), false for a release before D59 (SOUNDPOST_MIXED_OLD_GENERATION=pre-d59, e.g. ab3469c).
func oldTracksRecords() bool { return os.Getenv("SOUNDPOST_MIXED_OLD_GENERATION") != "pre-d59" }

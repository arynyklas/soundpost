// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type uploadEnv struct {
	*isoEnv
	org, project, source model.ID
	build                model.ID
	owner                person
}

func newUploadEnv(t *testing.T) *uploadEnv {
	t.Helper()
	e := &uploadEnv{isoEnv: newIsoEnv(t), project: model.NewID(), source: model.NewID()}
	e.org = e.isoEnv.org("upload stream", e.project)
	e.owner = e.user(e.org, "upload-owner@example.test")
	e.grant(e.org, e.owner, e.project, true, auth.ArtifactRead, auth.ArtifactWrite, auth.RawRead)
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	e.build = ids.Build
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, RetentionDays: map[model.Kind]uint32{model.Metric: 7}, MaxBytes: 32 << 20, MaxSeries: 100}
	e.onboard(e.org, e.project, e.source, ids, policy, auth.SourcePolicyConfig{ProjectID: e.project, Enabled: true, Readers: []model.ID{e.owner.ID}})
	return e
}

func (e *uploadEnv) mapOfSize(n int) []byte {
	pad := strings.Repeat("a", n)
	return []byte(`{"version":3,"sources":["src/app.ts"],"names":[],"mappings":"AAAA","sourcesContent":["` + pad + `"]}`)
}

func (e *uploadEnv) manifest(raw []byte, debug string) []byte {
	m := model.ArtifactManifest{Version: 1, Org: e.org, Project: e.project, Source: e.source, Build: e.build, DebugID: debug, GeneratedSHA256: model.HashCanonical([]byte("generated")), MapSHA256: model.HashCanonical(raw), Path: "dist/app.js", SourceContent: true, Size: model.Uint64(len(raw)), RetainUntil: model.UnixNano(4102444800_000000000)}
	out, err := json.Marshal(m)
	if err != nil {
		e.t.Fatal(err)
	}
	return out
}

// send posts a multipart body written by fill and returns the status and body.
func (e *uploadEnv) send(fill func(*multipart.Writer), midway func()) (int, []byte) {
	pr, pw := io.Pipe()
	w := multipart.NewWriter(pw)
	go func() {
		fill(w)
		pw.CloseWithError(w.Close())
	}()
	req, _ := http.NewRequest("POST", e.server.URL+"/api/v1/artifacts", pr)
	req.Header.Set("Cookie", "__Host-soundpost="+e.owner.Session.Token)
	req.Header.Set("Origin", e.server.URL)
	req.Header.Set("X-CSRF-Token", e.owner.Session.CSRF)
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func dirBytes(t *testing.T, dir string) int64 {
	t.Helper()
	var total int64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// TestArtifactUploadDoesNotSpoolToDisk: while an upload body is half sent, the
// process temp directory holds no byte of it (the multipart file part streams
// into Put, which admits before it reads). Observed peak temp bytes per size
// are logged; before this change they equalled the bytes received so far.
func TestArtifactUploadDoesNotSpoolToDisk(t *testing.T) {
	e := newUploadEnv(t)
	tmp := t.TempDir()
	for _, k := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(k, tmp)
	}
	for _, size := range []int{1 << 20, 8 << 20} {
		raw := e.mapOfSize(size)
		half := len(raw) / 2
		sent := make(chan struct{})
		release := make(chan struct{})
		var mid int64
		done := make(chan struct{})
		go func() {
			defer close(done)
			<-sent
			time.Sleep(400 * time.Millisecond)
			mid = dirBytes(t, tmp)
			close(release)
		}()
		status, body := e.send(func(w *multipart.Writer) {
			p, _ := w.CreateFormField("manifest")
			p.Write(e.manifest(raw, "debug-stream-"+strings.Repeat("x", 1)+string(rune('a'+size>>20))))
			p, _ = w.CreateFormFile("file", "app.js.map")
			p.Write(raw[:half])
			close(sent)
			<-release
			p.Write(raw[half:])
		}, nil)
		<-done
		if status != 200 {
			t.Fatalf("size %d: status %d %s", size, status, body)
		}
		t.Logf("upload %d bytes: peak temp bytes with half the body sent = %d", len(raw), mid)
		if mid != 0 {
			t.Errorf("size %d: %d bytes spooled to the temp dir before admission", len(raw), mid)
		}
	}
	if left := dirBytes(t, tmp); left != 0 {
		t.Fatalf("temp dir not empty after uploads: %d bytes", left)
	}
}

// A trailing part after the file is refused before anything is stored, and an
// upload shorter or longer than its manifest still fails as before.
func TestArtifactUploadStreamEdges(t *testing.T) {
	e := newUploadEnv(t)
	raw := e.mapOfSize(1000)
	manifest := e.manifest(raw, "debug-edges")
	field := func(w *multipart.Writer, body []byte) {
		p, _ := w.CreateFormField("manifest")
		p.Write(manifest)
		p, _ = w.CreateFormFile("file", "m.map")
		p.Write(body)
	}
	status, body := e.send(func(w *multipart.Writer) {
		field(w, raw)
		p, _ := w.CreateFormField("extra")
		p.Write([]byte("x"))
	}, nil)
	if status != 400 || !bytes.Contains(body, []byte(`"invalid"`)) {
		t.Fatalf("trailing part: %d %s", status, body)
	}
	if status, body = e.send(func(w *multipart.Writer) { field(w, raw[:len(raw)-1]) }, nil); status != 400 {
		t.Fatalf("short body: %d %s", status, body)
	}
	if status, body = e.send(func(w *multipart.Writer) { field(w, append(append([]byte{}, raw...), ' ')) }, nil); status == 200 {
		t.Fatalf("long body accepted: %s", body)
	}
	if status, body = e.send(func(w *multipart.Writer) { field(w, raw) }, nil); status != 200 {
		t.Fatalf("exact body: %d %s", status, body)
	}
}

// vmHWM is the peak resident set of this process in kB (Linux), 0 elsewhere.
func vmHWM() int {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(line, "VmHWM:"); ok {
			n, _ := strconv.Atoi(strings.Fields(rest)[0])
			return n
		}
	}
	return 0
}

// TestArtifactUploadPeakMemoryReport is a measurement, not an assertion: set
// SOUNDPOST_UPLOAD_MEASURE_MIB to the size of one upload and run the test alone
// in its own process; it logs the process peak RSS before and after one real
// HTTPS multipart upload through the served route (docs/artifacts/source-maps.md
// "Sizing" derives the memory limit from these numbers).
func TestArtifactUploadPeakMemoryReport(t *testing.T) {
	mib, _ := strconv.Atoi(os.Getenv("SOUNDPOST_UPLOAD_MEASURE_MIB"))
	if mib == 0 {
		t.Skip("measurement only: set SOUNDPOST_UPLOAD_MEASURE_MIB")
	}
	e := newUploadEnv(t)
	raw := e.mapOfSize(mib<<20 - 200)
	before := vmHWM()
	status, body := e.send(func(w *multipart.Writer) {
		p, _ := w.CreateFormField("manifest")
		p.Write(e.manifest(raw, "debug-measure"))
		p, _ = w.CreateFormFile("file", "app.js.map")
		p.Write(raw)
	}, nil)
	if status != 200 {
		t.Fatalf("status %d %s", status, body)
	}
	t.Logf("UPLOAD-RSS upload=%d bytes VmHWM before=%d kB after=%d kB delta=%d kB (%.1fx the upload)", len(raw), before, vmHWM(), vmHWM()-before, float64(vmHWM()-before)*1024/float64(len(raw)))
}

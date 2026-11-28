// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The journeys can attach to a cluster that someone else provisioned, bootstrapped and put through a node loss (07.07#16): the
// attach document names the members, the TLS material they serve, the owner of the installation, which member each journey leg
// uses and which members were killed and restored. Everything that document must prove is checked here against deliberately
// wrong documents; the run itself is `tools/drills --scenario node-loss-journeys`.

func attachMemberDoc(id int) map[string]any {
	m := map[string]any{}
	m["id"] = id
	m["address"] = fmt.Sprintf("127.0.0.1:%d", 41000+id)
	m["data_dir"] = fmt.Sprintf("/tmp/soundpost-drills/x/node-%d", id)
	m["node_config"] = fmt.Sprintf("/tmp/soundpost-drills/x/node-%d.json", id)
	return m
}

func validAttachDoc() map[string]any {
	doc := map[string]any{}
	doc["version"] = 1
	doc["control"] = "stdio"
	doc["tls"] = map[string]any{"ca": "/tmp/soundpost-drills/x/pki/ca.pem", "cert": "/tmp/soundpost-drills/x/pki/leaf.pem", "key": "/tmp/soundpost-drills/x/pki/leaf.key"}
	doc["owner"] = map[string]any{"email": "owner@drills.invalid", "password": "an owner password"}
	doc["members"] = []any{attachMemberDoc(1), attachMemberDoc(2), attachMemberDoc(3)}
	doc["recovered"] = []any{1, 3}
	doc["roles"] = map[string]any{"admin": 2, "gateway": 3, "api": 2, "jobs": 1, "web": 3, "webbuild": 3, "scan": 1}
	return doc
}

func encodeAttach(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestJourneyAttachAcceptsARecoveredCluster(t *testing.T) {
	a, err := parseJourneyAttach(encodeAttach(t, validAttachDoc()))
	if err != nil {
		t.Fatalf("a valid document was refused: %v", err)
	}
	if len(a.Members) != 3 || a.Owner.Email != "owner@drills.invalid" {
		t.Fatalf("decoded %+v", a)
	}
	for _, c := range [][2]string{{"admin", "127.0.0.1:41002"}, {"gateway", "127.0.0.1:41003"}, {"api", "127.0.0.1:41002"}, {"web", "127.0.0.1:41003"}, {"scan", "127.0.0.1:41001"}} {
		if got := a.roleAddress(c[0]); got != c[1] {
			t.Errorf("role %s: address %q, want %q", c[0], got, c[1])
		}
	}
	if m, ok := a.memberByID(3); !ok || m.DataDir != "/tmp/soundpost-drills/x/node-3" {
		t.Errorf("member 3: %+v %v", m, ok)
	}
	if _, ok := a.memberByID(9); ok {
		t.Error("an unknown member was found")
	}
}

func TestJourneyAttachRefusesWhatIsNotARecoveredCluster(t *testing.T) {
	member := func(d map[string]any, i int) map[string]any { return d["members"].([]any)[i].(map[string]any) }
	role := func(d map[string]any) map[string]any { return d["roles"].(map[string]any) }
	sub := func(d map[string]any, key string) map[string]any { return d[key].(map[string]any) }
	cases := []struct {
		name   string
		mutate func(d map[string]any)
	}{
		{"two members only", func(d map[string]any) {
			d["members"] = d["members"].([]any)[:2]
			d["recovered"] = []any{1}
			role(d)["gateway"], role(d)["web"], role(d)["webbuild"] = 2, 2, 2
		}},
		{"duplicate member id", func(d map[string]any) { member(d, 2)["id"] = 2 }},
		{"public address that is not loopback", func(d map[string]any) { member(d, 1)["address"] = "10.0.0.5:8443" }},
		{"public address without a port", func(d map[string]any) { member(d, 1)["address"] = "127.0.0.1" }},
		{"public address with port zero", func(d map[string]any) { member(d, 1)["address"] = "127.0.0.1:0" }},
		{"relative data directory", func(d map[string]any) { member(d, 0)["data_dir"] = "node-1" }},
		{"relative node configuration", func(d map[string]any) { member(d, 0)["node_config"] = "node-1.json" }},
		{"role names a member that is not there", func(d map[string]any) { role(d)["gateway"] = 9 }},
		{"a role is missing", func(d map[string]any) { delete(role(d), "api") }},
		{"a role nobody defined", func(d map[string]any) { role(d)["extra"] = 1 }},
		{"no member was killed and restored", func(d map[string]any) { d["recovered"] = []any{} }},
		{"recovered names a member that is not there", func(d map[string]any) { d["recovered"] = []any{1, 7} }},
		{"the scan member was never restored", func(d map[string]any) { d["recovered"] = []any{3} }},
		{"the admin member is the scan member", func(d map[string]any) { role(d)["admin"] = 1 }},
		{"the web member is not the gateway member (the page's connect-src names the gateway's)", func(d map[string]any) { role(d)["web"] = 2 }},
		{"an unknown control protocol", func(d map[string]any) { d["control"] = "socket" }},
		{"an unknown document version", func(d map[string]any) { d["version"] = 2 }},
		{"an empty owner password", func(d map[string]any) { sub(d, "owner")["password"] = "" }},
		{"an empty owner email", func(d map[string]any) { sub(d, "owner")["email"] = "" }},
		{"a missing TLS key", func(d map[string]any) { sub(d, "tls")["key"] = "" }},
		{"a relative TLS certificate", func(d map[string]any) { sub(d, "tls")["cert"] = "leaf.pem" }},
		{"a field the schema does not have", func(d map[string]any) { d["note"] = "x" }},
	}
	for _, c := range cases {
		doc := validAttachDoc()
		c.mutate(doc)
		if _, err := parseJourneyAttach(encodeAttach(t, doc)); err == nil {
			t.Errorf("%s: the document was accepted", c.name)
		}
	}
	if _, err := parseJourneyAttach(append(encodeAttach(t, validAttachDoc()), []byte(`{}`)...)); err == nil {
		t.Error("trailing data after the document was accepted")
	}
	if _, err := parseJourneyAttach([]byte(`not json`)); err == nil {
		t.Error("a document that is not JSON was accepted")
	}
}

// A journey leg pointed at a member that is not serving must fail the run before anything is provisioned: the members named
// by the document are asked for /readyz and every one of them has to answer ready.
func TestJourneyAttachAwaitsEveryMemberReady(t *testing.T) {
	answer := func(status int, body string) *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}))
	}
	ready1, ready2 := answer(200, `{"ready":true}`), answer(200, `{"ready":true}`)
	defer ready1.Close()
	defer ready2.Close()
	starting := answer(503, `{"ready":false,"reason":"starting"}`)
	defer starting.Close()
	notReady200 := answer(200, `{"ready":false,"reason":"catching_up"}`)
	defer notReady200.Close()
	dead := answer(200, `{"ready":true}`)
	deadAddress := dead.Listener.Addr().String()
	dead.Close()
	client := ready1.Client()
	host := func(s *httptest.Server) string { return strings.TrimPrefix(s.URL, "https://") }

	attach := func(third string) *journeyAttach {
		doc := validAttachDoc()
		members := doc["members"].([]any)
		members[0].(map[string]any)["address"] = host(ready1)
		members[1].(map[string]any)["address"] = host(ready2)
		members[2].(map[string]any)["address"] = third
		a, err := parseJourneyAttach(encodeAttach(t, doc))
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	if err := attach(host(ready1)).awaitMembersReady(client, 2*time.Second); err != nil {
		t.Fatalf("three ready members: %v", err)
	}
	for _, c := range []struct{ name, third string }{
		{"a member that answers 503 not ready", host(starting)},
		{"a member that answers 200 but not ready", host(notReady200)},
		{"a member that is dead (nothing listening)", deadAddress},
	} {
		err := attach(c.third).awaitMembersReady(client, 1500*time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "member 3") {
			t.Errorf("%s: error %v, want one naming member 3", c.name, err)
		}
	}
}

func TestClusterAnswerRetryability(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"a control write that lost its index race", 400, `{"code":"stale","retryable":true}`, true},
		{"a revision conflict", 409, `{"code":"conflict"}`, true},
		{"a conflict reported as 400", 400, `{"code":"conflict"}`, true},
		{"a member without quorum (typed 503)", 503, `{"code":"unavailable","retryable":true}`, true},
		{"a typed timeout", 503, `{"code":"timeout","retryable":true}`, true},
		{"a 503 that is not a typed retryable fault", 503, `<html>`, false},
		{"a typed 503 that says it is not retryable", 503, `{"code":"unavailable","retryable":false}`, false},
		{"a 503 with another code", 503, `{"code":"corrupt","retryable":true}`, false},
		{"an invalid request", 400, `{"code":"invalid"}`, false},
		{"a refused read", 403, `{"code":"forbidden"}`, false},
		{"a missing route", 404, `{"code":"not_found"}`, false},
		{"a server error", 500, `{"code":"internal"}`, false},
		{"a success", 200, `{"code":"stale"}`, false},
	} {
		if got := retryableClusterAnswer(c.status, []byte(c.body)); got != c.want {
			t.Errorf("%s: retryable=%v, want %v", c.name, got, c.want)
		}
	}
}

// ownerScript plays the cluster owner on the other end of the control channel: it records every request line and answers with
// the next scripted line; once the script is spent the channel closes like an owner that died.
func ownerScript(t *testing.T, answers []string) (*journeyControl, func() []string) {
	t.Helper()
	requests, requestsOut := io.Pipe()
	replies, repliesOut := io.Pipe()
	var got []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		in := bufio.NewReader(requests)
		for _, a := range answers {
			line, err := in.ReadString('\n')
			if err != nil {
				repliesOut.Close()
				return
			}
			got = append(got, strings.TrimSpace(line))
			if _, err = io.WriteString(repliesOut, a+"\n"); err != nil {
				return
			}
		}
		// The script is spent: the owner has gone away. Later requests are still read (so writing them does not block) and not answered.
		repliesOut.Close()
		_, _ = io.Copy(io.Discard, in)
	}()
	c := newJourneyControl(replies, requestsOut)
	return c, func() []string {
		requestsOut.Close()
		<-done
		return got
	}
}

func TestJourneyControlTakesTheOwnersAnswer(t *testing.T) {
	c, requests := ownerScript(t, []string{`{"ok":true}`, `{"ok":false,"code":"member_not_ready"}`, `{"ok":true}`})
	if err := c.stopMember(1); err != nil {
		t.Fatalf("stop answered ok: %v", err)
	}
	if err := c.startMember(1); err == nil || !strings.Contains(err.Error(), "member_not_ready") {
		t.Fatalf("a refused start must carry the owner's code: %v", err)
	}
	if err := c.phase("drive_begin"); err != nil {
		t.Fatalf("phase answered ok: %v", err)
	}
	// The owner has gone away: the next request must fail instead of waiting for an answer that never comes.
	if err := c.stopMember(2); err == nil {
		t.Fatal("a request to an owner that closed the channel succeeded")
	}
	want := []string{`{"op":"stop_member","member":1}`, `{"op":"start_member","member":1}`, `{"op":"phase","name":"drive_begin"}`}
	got := requests()
	if len(got) != len(want) {
		t.Fatalf("owner saw %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("request %d: %s, want %s", i, got[i], want[i])
		}
	}
}

func TestJourneyControlRefusesAnAnswerThatIsNotJSON(t *testing.T) {
	c, requests := ownerScript(t, []string{`ok`})
	defer requests()
	if err := c.phase("drive_end"); err == nil {
		t.Fatal("an answer that is not JSON was taken for success")
	}
}

func TestLoadJourneyPKIRefusesWhatTheMembersDoNotServe(t *testing.T) {
	good, err := newJourneyPKI(filepath.Join(t.TempDir(), "good"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := newJourneyPKI(filepath.Join(t.TempDir(), "other"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := loadJourneyPKI(good.CA, good.Cert, good.Key)
	if err != nil {
		t.Fatalf("a consistent PKI was refused: %v", err)
	}
	pair, err := tls.LoadX509KeyPair(good.Cert, good.Key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	server.StartTLS()
	defer server.Close()
	resp, err := p.client().Get(server.URL)
	if err != nil {
		t.Fatalf("the loaded PKI does not trust the leaf it was loaded with: %v", err)
	}
	resp.Body.Close()
	if pin, err := p.leafSPKIPin(); err != nil || len(pin) != 44 {
		t.Errorf("leaf pin %q: %v", pin, err)
	}
	for _, c := range []struct {
		name string
		args [3]string
	}{
		{"a key that does not belong to the leaf", [3]string{good.CA, good.Cert, other.Key}},
		{"a leaf another CA signed", [3]string{good.CA, other.Cert, other.Key}},
		{"a missing CA", [3]string{filepath.Join(t.TempDir(), "none.pem"), good.Cert, good.Key}},
		{"a CA that is a leaf, not a CA", [3]string{good.Cert, good.Cert, good.Key}},
	} {
		if _, err := loadJourneyPKI(c.args[0], c.args[1], c.args[2]); err == nil {
			t.Errorf("%s: loaded", c.name)
		}
	}
}

func TestScanLiveTreeToleratesVanishedFilesAndNothingElse(t *testing.T) {
	dir := t.TempDir()
	for _, f := range [][2]string{{"a/canary.bin", "xx CANARY_X yy"}, {"b/gone.bin", "-"}, {"c/ok.bin", "nothing here"}} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, f[0])), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f[0]), []byte(f[1]), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	vanish := func(p string) ([]byte, error) {
		if filepath.Base(p) == "gone.bin" {
			return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
		}
		return os.ReadFile(p)
	}
	hits, files, skipped, err := scanLiveTreeForCanaries(context.Background(), dir, []string{"CANARY_X"}, vanish)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || !strings.Contains(hits[0].Where, "canary.bin") || hits[0].Canary != "CANARY_X" {
		t.Errorf("hits %+v", hits)
	}
	if files != 2 || skipped != 1 {
		t.Errorf("files=%d skipped=%d, want 2 and 1", files, skipped)
	}
	broken := func(p string) ([]byte, error) {
		if filepath.Base(p) == "ok.bin" {
			return nil, errors.New("disk error")
		}
		return os.ReadFile(p)
	}
	if _, _, _, err = scanLiveTreeForCanaries(context.Background(), dir, []string{"CANARY_X"}, broken); err == nil {
		t.Error("a read error other than a vanished file was tolerated")
	}
}

// The drill writes this document (tools/drills TestJourneyAttachDocumentMatchesTheSmokeSchema holds its output to the same keys);
// the committed sample must be one this parser accepts.
func TestJourneyAttachSampleDocumentParses(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "journeys", "attach.json"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := parseJourneyAttach(raw)
	if err != nil {
		t.Fatalf("the committed sample is refused: %v", err)
	}
	if a.Roles["scan"] != 1 || len(a.Members) != 3 || len(a.Recovered) != 2 {
		t.Errorf("decoded %+v", a)
	}
}

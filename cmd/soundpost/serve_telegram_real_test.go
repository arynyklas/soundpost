// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// Real provider acceptance (plan 06 task 8, 06.08-W2) through the real serve path: the served process
// (the re-executed real main) evaluates a rule an administrator saved over POST /api/v1/rules, opens its
// condition, routes it to the organization's TELEGRAM destination (the chat is destination configuration,
// the bot token is its write-only sealed secret) and sends one real Bot API message to api.telegram.org
// under the production egress policy. The test needs a disposable bot and chat:
//
//	SOUNDPOST_TEST_TELEGRAM_TOKEN   the bot token
//	SOUNDPOST_TEST_TELEGRAM_CHAT    the numeric chat id (or @channel) the bot can write to
//
// Without them it is reported as skipped, and with SOUNDPOST_REQUIRE_REAL_TELEGRAM=1 it fails loudly, the same
// contract as providers.TestProvidersRealAcceptance. The token is never printed: every failure text is
// scrubbed of it, and the test records only the provider message ID of the accepted delivery.
func TestServeDeliversAConditionToARealTelegramChat(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes and signals")
	}
	token, chat := strings.TrimSpace(os.Getenv("SOUNDPOST_TEST_TELEGRAM_TOKEN")), strings.TrimSpace(os.Getenv("SOUNDPOST_TEST_TELEGRAM_CHAT"))
	if token == "" || chat == "" {
		const why = "real Telegram serve acceptance has no credentials: set SOUNDPOST_TEST_TELEGRAM_TOKEN and SOUNDPOST_TEST_TELEGRAM_CHAT"
		if os.Getenv("SOUNDPOST_REQUIRE_REAL_TELEGRAM") == "1" {
			t.Fatal(why)
		}
		t.Skip("NOT RUN: " + why + " (set SOUNDPOST_REQUIRE_REAL_TELEGRAM=1 to make this a failure)")
	}
	id := serveTelegramDelivery(t, token, chat)
	t.Logf("REAL TELEGRAM provider_message_id=%s", id)
}

// A local Bot API peer (TLS on a private interface, a private CA) exercises the same served path and the same
// assertions without a third party: the destination's chat and sealed token reach sendMessage as configured, and
// the message id the API answers is the provider ID of the accepted delivery.
func TestServeDeliversAConditionThroughATelegramBotAPIPeer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes and signals")
	}
	const token, chat, wantID = "123456:peer-token-ABCDEFGHIJKLMNOPQRSTUV", "-1001234567890", "424242"
	ip := privateAddress(t)
	caPath := filepath.Join(t.TempDir(), "peer-ca.pem")
	var mu sync.Mutex
	var seen []string
	origin := privateTLSServer(t, ip, caPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ChatID json.RawMessage `json:"chat_id"`
		}
		_ = json.Unmarshal(body, &req)
		mu.Lock()
		seen = append(seen, r.URL.Path+" chat="+strings.Trim(string(req.ChatID), `"`))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true,"result":{"message_id":`+wantID+`}}`)
	}))
	id := serveTelegramDelivery(t, token, chat, "--notify-telegram-api", origin, "--notify-egress-allow", netip.PrefixFrom(ip, 32).String(), "--notify-ca-file", caPath)
	if id != wantID {
		t.Fatalf("provider id %q, want the id the Bot API answered, %s", id, wantID)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != "/bot"+token+"/sendMessage chat="+chat {
		t.Fatalf("the Bot API peer saw %v, want exactly one sendMessage to the configured chat with the sealed token", seen)
	}
}

// realDestination is the organization destination one served-delivery acceptance sends to: the channel type, the
// address (a Telegram chat, an e-mail recipient), the write-only sealed secret (bot token, SMTP password) and the check
// of the provider identity the one accepted delivery must carry.
type realDestination struct {
	Type, Address, Secret string
	CheckProvider         func(id string) error
}

func serveTelegramDelivery(t *testing.T, token, chat string, serveArgs ...string) string {
	t.Helper()
	return serveDelivery(t, realDestination{Type: "telegram", Address: chat, Secret: token, CheckProvider: func(id string) error {
		_, err := strconv.ParseInt(id, 10, 64)
		return err
	}}, serveArgs...)
}

// serveDelivery runs the whole served path against the organization's destination (type, address and sealed secret
// as given; serveArgs point the node at the provider under test) and returns the provider identity of the one accepted
// delivery. Nothing it fails with contains the secret or the address.
func serveDelivery(t *testing.T, dest realDestination, serveArgs ...string) string {
	t.Helper()
	token, chat := dest.Secret, dest.Address
	scrub := func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, token, "<secret>"), chat, "<address>")
	}
	fatalf := func(format string, args ...any) {
		t.Helper()
		t.Fatal(scrub(fmt.Sprintf(format, args...)))
	}

	work := t.TempDir()
	dir := filepath.Join(work, "data")
	port := freePort(t)
	listen := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	cmd, lines, errOut := serveChild(t, append([]string{"--data-dir", dir, "--listen", listen, "--worker-interval", "100ms", "--public-origin", "https://soundpost.example.test"}, serveArgs...)...)
	defer cmd.Process.Kill()
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range lines {
		}
	}()
	var client *http.Client
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if pemBytes, err := os.ReadFile(filepath.Join(dir, "server.crt")); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pemBytes) {
				jar, _ := cookiejar.New(nil)
				client = &http.Client{Jar: jar, Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
				if resp, err := client.Get("https://" + listen + "/readyz"); err == nil {
					resp.Body.Close()
					if resp.StatusCode == 200 {
						break
					}
				}
			}
		}
		client = nil
		time.Sleep(200 * time.Millisecond)
	}
	if client == nil {
		fatalf("serve never became ready; stderr:\n%s", errOut.String())
	}
	a := &api{t: t, base: "https://" + listen, client: client}

	bootstrap, err := os.ReadFile(filepath.Join(dir, "bootstrap.token"))
	if err != nil {
		t.Fatal(err)
	}
	password := "serve telegram acceptance password 2026"
	code, raw := a.do("POST", "/api/v1/bootstrap", map[string]string{"Token": strings.TrimSpace(string(bootstrap)), "Email": "owner@example.test", "Password": password}, nil)
	var session struct {
		CSRF string `json:"csrf"`
	}
	if code != 200 || json.Unmarshal(raw, &session) != nil {
		t.Fatalf("bootstrap %d: %s", code, raw)
	}
	a.csrf = session.CSRF
	org, project, destID := model.NewID(), model.NewID(), model.NewID()
	a.command(org, "create_org", auth.AdminPayload{Name: "serve telegram acceptance"})
	a.command(org, "create_project", auth.AdminPayload{ID: project, Name: "serve telegram acceptance project"})
	destination, _ := json.Marshal(auth.DestinationConfig{Type: dest.Type, Address: chat, Enabled: true})
	a.command(org, "destination", auth.AdminPayload{ID: destID, Config: destination, Secret: token})

	code, raw = a.do("POST", "/api/v1/rules", map[string]any{"org": org, "project_id": project, "operation": "list"}, nil)
	var listed struct {
		Profiles []struct {
			ID          string   `json:"id"`
			FeatureSets []string `json:"feature_sets"`
		} `json:"profiles"`
	}
	if code != 200 || json.Unmarshal(raw, &listed) != nil {
		t.Fatalf("rule list %d: %s", code, raw)
	}
	featureSet := ""
	for _, p := range listed.Profiles {
		if p.ID == "promql-prometheus-3.13.5" && len(p.FeatureSets) > 0 {
			featureSet = p.FeatureSets[0]
		}
	}
	if featureSet == "" {
		t.Fatalf("no feature set advertised: %s", raw)
	}
	code, raw = a.do("POST", "/api/v1/rules", map[string]any{"org": org, "project_id": project, "operation": "save", "command_id": model.NewID(), "rule_id": model.NewID(), "expected_revision": "0", "reason": "serve telegram acceptance",
		"rule": map[string]any{"kind": "alert", "profile": "promql-prometheus-3.13.5", "feature_set": featureSet, "expression": "vector(1)", "interval_seconds": 60, "severity": "critical"}}, nil)
	if code != 200 {
		t.Fatalf("rule save %d: %s", code, raw)
	}

	// The runner evaluates the rule, opens the condition and delivers; the audit trail says how the first
	// attempt ended (accepted, or the closed code of a retry/terminal/unknown outcome).
	type auditEntry struct {
		Principal model.ID `json:"principal"`
		Action    string   `json:"action"`
		Reason    string   `json:"reason"`
	}
	var delivery *auditEntry
	for deadline = time.Now().Add(120 * time.Second); time.Now().Before(deadline) && delivery == nil; time.Sleep(500 * time.Millisecond) {
		code, raw = a.do("POST", "/api/v1/admin/read", map[string]any{"kind": "audit", "org_id": org}, nil)
		var audit struct {
			Audits []auditEntry `json:"audits"`
		}
		if code != 200 || json.Unmarshal(raw, &audit) != nil {
			t.Fatalf("audit read %d: %s", code, raw)
		}
		for i, e := range audit.Audits {
			if strings.HasPrefix(e.Action, "notify.delivery.") && e.Principal == auth.SystemPrincipal(org) && e.Action != "notify.delivery.queued" {
				delivery = &audit.Audits[i]
				break
			}
		}
	}
	if delivery == nil {
		fatalf("no delivery attempt was settled; stderr:\n%s", errOut.String())
	}
	t.Logf("first settled delivery audit: action=%s reason=%q", delivery.Action, scrub(delivery.Reason))
	if delivery.Action != "notify.delivery.accepted" {
		fatalf("the delivery did not end accepted: %s %q; stderr:\n%s", delivery.Action, delivery.Reason, errOut.String())
	}

	if err = cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-drained:
	case <-time.After(30 * time.Second):
		fatalf("serve did not stop after SIGINT; stderr:\n%s", errOut.String())
	}
	if err = cmd.Wait(); err != nil {
		fatalf("serve did not exit cleanly: %v\n%s", err, errOut.String())
	}
	if strings.Contains(errOut.String(), token) {
		t.Fatal("the served process wrote the destination secret to its error output")
	}

	// The node is stopped: read the committed delivery records from its data and record the provider's
	// message identity (Bot API message_id, not proof a human saw the message).
	app, err := appcore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx := context.Background()
	sess, err := app.Auth.Login(ctx, "owner@example.test", password, "")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := app.Auth.Authenticate(ctx, sess.Token)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := app.Auth.Authorize(ctx, cred, org, []model.ID{project}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := app.Control.Deliveries(ctx, scope, project, "", model.UnixNano(time.Now().UnixNano()), 0)
	if err != nil {
		t.Fatal(err)
	}
	accepted, providerID := 0, ""
	for _, r := range recs {
		if r.Phase != control.DeliveryAccepted {
			continue
		}
		accepted++
		if err := dest.CheckProvider(r.Provider); err != nil {
			t.Fatalf("the accepted delivery %s carries no usable provider identity: %q", r.ID, r.Provider)
		}
		if r.Uncertain || r.PossibleDuplicate {
			t.Fatalf("the accepted delivery %s is uncertain=%v possible_duplicate=%v", r.ID, r.Uncertain, r.PossibleDuplicate)
		}
		providerID = r.Provider
		t.Logf("ACCEPTED: delivery=%s route=%s attempts=%d provider_message_id=%s", r.ID, r.Route, len(r.Attempts), r.Provider)
	}
	if accepted != 1 {
		t.Fatalf("%d accepted deliveries, want exactly 1 (records: %d)", accepted, len(recs))
	}
	return providerID
}

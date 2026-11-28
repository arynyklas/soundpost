// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
	"github.com/arynyklas/soundpost/internal/notify/providers"
	"net/netip"
)

// The whole path with the REAL providers: an ingested error becomes an issue and an incident,
// the producer announces them, the signed event webhook sender reads the sealed secrets of
// control (current and, inside a rotation window, previous) and posts to a TLS receiver, and
// the reference Receiver verifies every request with either secret and deduplicates by
// delivery ID. (Needs a private IPv4 interface: the egress policy forbids loopback.)
func TestEventWebhookEndToEndWithTheRealProviders(t *testing.T) {
	r := newEventRig(t)
	recv := newReceiver(t)
	oldSecret, newSecret := "OLD-EVENT-SIGNING-SECRET-0123456789", "NEW-EVENT-SIGNING-SECRET-0123456789"
	ep := model.NewID()
	save := func(secret string) {
		cfg, _ := json.Marshal(auth.DestinationConfig{Type: auth.EventWebhookType, Endpoint: recv.url, Enabled: true, Name: "receiver", Events: []string{"incident.opened", "issue.new"}})
		r.command("destination", auth.AdminPayload{ID: ep, Config: cfg, Secret: secret})
	}
	save(oldSecret)
	save(newSecret) // a rotation: both secrets sign for 24 hours

	cfg := appcore.NotificationConfig{PublicOrigin: "https://soundpost.example.test", StateDir: filepath.Join(t.TempDir(), "notify"), RootCAs: recv.roots}
	cfg.Egress.AllowPrefixes = []netip.Prefix{netip.PrefixFrom(recv.addr, 32)}
	sender, err := r.app.NotificationSender(cfg)
	if err != nil {
		t.Fatal(err)
	}
	w := r.workers(func(c *appcore.WorkerConfig) { c.Sender = sender })
	r.tick(w) // baseline
	issuesBefore, incidentsBefore := r.issueIDs(), r.incidentIDs()
	r.ingest("TypeError", 5, true, false)
	rep := r.tick(w)
	if rep.Attempted != 2 {
		t.Fatalf("pass: %+v", rep)
	}
	issue, incident := added(issuesBefore, r.issueIDs())[0], added(incidentsBefore, r.incidentIDs())[0]
	posts := recv.received()
	if len(posts) != 2 {
		t.Fatalf("receiver got %d posts, want 2", len(posts))
	}
	byEvent := map[string]map[string]any{}
	for _, p := range posts {
		var body map[string]any
		if err = json.Unmarshal(p.body, &body); err != nil {
			t.Fatalf("body %s: %v", p.body, err)
		}
		event, _ := body["event"].(string)
		byEvent[event] = body
		if p.header.Get(providers.HeaderEvent) != event || p.header.Get(providers.HeaderDeliveryID) != body["delivery_id"] || body["org"] != r.org.String() || body["project"] != r.project.String() ||
			!strings.HasPrefix(body["url"].(string), "https://soundpost.example.test/#view=") {
			t.Fatalf("request %s %v", p.body, p.header)
		}
		// Both signatures are present and either secret verifies the request.
		if sigs := strings.Split(p.header.Get(providers.HeaderSignature), ","); len(sigs) != 2 {
			t.Fatalf("signature header during a rotation: %q", p.header.Get(providers.HeaderSignature))
		}
		for name, secret := range map[string]string{"current": newSecret, "previous": oldSecret} {
			recvr := providers.NewReceiver([]byte(secret), time.Now, 0)
			first, err := recvr.Receive(p.header, p.body)
			if err != nil || first.Duplicate {
				t.Fatalf("%s secret: %+v %v", name, first, err)
			}
			if again, err := recvr.Receive(p.header, p.body); err != nil || !again.Duplicate {
				t.Fatalf("%s secret: the repeat is not a duplicate: %+v %v", name, again, err)
			}
		}
		for _, secret := range []string{oldSecret, newSecret} {
			if strings.Contains(string(p.body), secret) || strings.Contains(p.header.Get(providers.HeaderSignature), secret) {
				t.Fatal("a secret is on the wire")
			}
		}
	}
	if byEvent["issue.new"]["issue"] != issue.String() || byEvent["incident.opened"]["incident"] != incident.String() || byEvent["incident.opened"]["severity"] == nil {
		t.Fatalf("bodies: %v", byEvent)
	}
	// A second pass sends nothing more, and no unsubscribed event was sent.
	if r.tick(w); len(recv.received()) != 2 {
		t.Fatalf("a repeat pass posted again: %d", len(recv.received()))
	}
	if got := r.rec.events(ep); len(got) != 0 {
		t.Fatalf("the recording sender was not replaced: %v", got)
	}
	// The sealed secrets never reached the outbox, its audit or the feed.
	for _, rec := range r.eventRecords() {
		if rec.Phase != "accepted" || strings.Contains(string(rec.Body), oldSecret) || strings.Contains(string(rec.Body), newSecret) {
			t.Fatalf("record %+v", rec)
		}
	}
	text := ""
	_ = r.app.Control.View(r.ctx, func(st model.ControlState) error {
		audits, _ := json.Marshal(st.Audits)
		books, _ := json.Marshal(st.DeliveryBooks)
		text = string(audits) + string(books)
		return nil
	})
	if strings.Contains(text, oldSecret) || strings.Contains(text, newSecret) {
		t.Fatal("an endpoint secret is in the audit log or the outbox")
	}
	_ = notify.EventSubject
}

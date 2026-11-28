// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package providers

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/notify"
)

const (
	envTelegramToken   = "SOUNDPOST_TEST_TELEGRAM_TOKEN"
	envTelegramChat    = "SOUNDPOST_TEST_TELEGRAM_CHAT"
	envRequireTelegram = "SOUNDPOST_REQUIRE_REAL_TELEGRAM"
)

// realTelegramCredentials reads the credentials of the real Bot API acceptance.
// Missing credentials are an error that names every missing variable: the test
// never passes by quietly doing nothing.
func realTelegramCredentials(getenv func(string) string) (token, chat string, err error) {
	var missing []string
	for _, name := range []string{envTelegramToken, envTelegramChat} {
		if strings.TrimSpace(getenv(name)) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return "", "", fmt.Errorf("real Telegram acceptance has no credentials: set %s", strings.Join(missing, " and "))
	}
	return strings.TrimSpace(getenv(envTelegramToken)), strings.TrimSpace(getenv(envTelegramChat)), nil
}

// TestProvidersRealAcceptance drives the production senders against real
// protocol peers: a local TLS SMTP relay, a local HTTPS receiver that verifies
// the signature with the reference Receiver, and (when credentials are given)
// the real Telegram Bot API. A sender that dies after the receiver may already
// have acted is replaced by a new sender instance: the retry carries the same
// stable delivery ID, so the receiver recognises the duplicate.
func TestProvidersRealAcceptance(t *testing.T) {
	t.Run("signed receiver: a sender that died after the receiver acted is retried by a new sender with the same delivery ID", func(t *testing.T) {
		o := newOrg(t)
		var (
			rc      = NewReceiver([]byte(canarySecret), func() time.Time { return time.Unix(1_800_000_000, 0).Add(90 * time.Second) }, 0)
			actions atomic.Int64
			calls   atomic.Int64
			mu      sync.Mutex
			ids     []string
		)
		srv := newTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			rcpt, err := rc.Receive(r.Header, body)
			if err != nil {
				http.Error(w, "rejected", http.StatusUnauthorized)
				return
			}
			mu.Lock()
			ids = append(ids, rcpt.DeliveryID)
			mu.Unlock()
			if !rcpt.Duplicate {
				actions.Add(1)
			}
			if calls.Add(1) == 1 {
				// the receiver acted, then the connection dies before the acknowledgement
				conn, _, herr := w.(http.Hijacker).Hijack()
				if herr == nil {
					_ = conn.Close()
				}
				return
			}
			w.Header().Set(HeaderReceiptID, "rcpt-"+rcpt.DeliveryID)
			w.WriteHeader(http.StatusNoContent)
		}))
		reg := newRegistry()
		reg.put(o.id, recipient, notify.DestinationRecord{Type: "webhook", Endpoint: srv.URL + "/hook/" + canaryPath, Enabled: true}, canarySecret)
		newSender := func(at time.Time) notify.Sender {
			s, err := NewWebhook(WebhookConfig{Common: testCommon(reg), Stamper: &stamper{now: at}}, reg, srv.client())
			if err != nil {
				t.Fatal(err)
			}
			return s
		}

		first, err := newSender(time.Unix(1_800_000_000, 0)).Send(context.Background(), o.scope, mkDelivery(o.id, 1))
		if err != nil || first.Kind != notify.OutcomeUnknown {
			t.Fatalf("a lost acknowledgement must be unknown (possible acceptance): %+v %v", first, err)
		}
		// the first sender is gone; a new instance with a later attempt stamp retries the same delivery
		second, err := newSender(time.Unix(1_800_000_000, 0).Add(60*time.Second)).Send(context.Background(), o.scope, mkDelivery(o.id, 2))
		if err != nil || second.Kind != notify.OutcomeAccepted || second.ProviderID != "rcpt-"+delivery1.String() {
			t.Fatalf("retry: %+v %v", second, err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(ids) != 2 || ids[0] != delivery1.String() || ids[1] != delivery1.String() {
			t.Fatalf("delivery IDs seen by the receiver: %v", ids)
		}
		if actions.Load() != 1 {
			t.Fatalf("the receiver acted %d times for one delivery; the stable ID must make the retry a duplicate", actions.Load())
		}
	})

	t.Run("SMTP relay: a connection that died after the end of data is retried with the same Message-ID", func(t *testing.T) {
		s := newSMTPServer(t, "implicit")
		s.dropData = true
		o := newOrg(t)
		host, port, _ := net.SplitHostPort(s.addr)
		p, _ := parsePort(port)
		reg := newRegistry()
		reg.put(o.id, recipient, notify.DestinationRecord{Type: "smtp", Address: "oncall@example.test", Enabled: true}, canarySecret)
		newSender := func() notify.Sender {
			c := testCommon(reg)
			sender, err := NewSMTP(SMTPConfig{Common: c, Host: host, Port: p, TLS: SMTPImplicitTLS, Username: "relay-user", RequireAuth: true, From: "soundpost@example.test", RootCAs: s.pool}, reg)
			if err != nil {
				t.Fatal(err)
			}
			return sender
		}
		messageID := func() string {
			s.mu.Lock()
			defer s.mu.Unlock()
			for _, l := range strings.Split(s.data, "\r\n") {
				if strings.HasPrefix(l, "Message-ID:") {
					return l
				}
			}
			return ""
		}

		first, err := newSender().Send(context.Background(), o.scope, mkDelivery(o.id, 1))
		if err != nil || first.Kind != notify.OutcomeUnknown {
			t.Fatalf("a drop after the data must be unknown: %+v %v", first, err)
		}
		want := "Message-ID: <" + delivery1.String() + "@soundpost.invalid>"
		if got := messageID(); got != want {
			t.Fatalf("first message id %q, want %q", got, want)
		}
		s.mu.Lock()
		s.dropData, s.data = false, ""
		s.mu.Unlock()
		second, err := newSender().Send(context.Background(), o.scope, mkDelivery(o.id, 2))
		if err != nil || second.Kind != notify.OutcomeAccepted || second.ProviderID != "4F2A91B" {
			t.Fatalf("retry: %+v %v", second, err)
		}
		if got := messageID(); got != want {
			t.Fatalf("a retry must keep the Message-ID so the duplicate is recognisable: %q, want %q", got, want)
		}
	})

	t.Run("real Telegram Bot API fails loudly without credentials", func(t *testing.T) {
		if _, _, err := realTelegramCredentials(func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), envTelegramToken) || !strings.Contains(err.Error(), envTelegramChat) {
			t.Fatalf("missing credentials must be an error naming both variables, got %v", err)
		}
		if _, _, err := realTelegramCredentials(func(n string) string {
			if n == envTelegramToken {
				return "123:token"
			}
			return ""
		}); err == nil || strings.Contains(err.Error(), envTelegramToken) || !strings.Contains(err.Error(), envTelegramChat) {
			t.Fatalf("only the missing variable is named, got %v", err)
		}
		token, chat, err := realTelegramCredentials(func(n string) string { return " " + n + " " })
		if err != nil || token != envTelegramToken || chat != envTelegramChat {
			t.Fatalf("%q %q %v", token, chat, err)
		}
	})

	t.Run("real Telegram Bot API accepts one message", func(t *testing.T) {
		token, chat, err := realTelegramCredentials(os.Getenv)
		if err != nil {
			if os.Getenv(envRequireTelegram) == "1" {
				t.Fatal(err)
			}
			t.Skipf("NOT RUN: %v (set %s=1 to make this a failure)", err, envRequireTelegram)
		}
		o := newOrg(t)
		reg := newRegistry()
		reg.put(o.id, recipient, notify.DestinationRecord{Type: "telegram", Address: chat, Enabled: true}, token)
		dests, err := notify.NewDestinations(reg, reg)
		if err != nil {
			t.Fatal(err)
		}
		// production egress and the real API origin
		s, err := NewTelegram(TelegramConfig{Common: Common{Destinations: dests, PublicOrigin: origin, Timeout: 20 * time.Second}}, reg, nil)
		if err != nil {
			t.Fatal(err)
		}
		out, err := s.Send(context.Background(), o.scope, mkDelivery(o.id, 1))
		if err != nil {
			t.Fatal(err)
		}
		if out.Kind != notify.OutcomeAccepted || out.ProviderID == "" {
			t.Fatalf("real Telegram outcome: kind=%s code=%s", out.Kind, out.Code)
		}
	})
}

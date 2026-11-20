// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Real SMTP acceptance (plan 06 task 8, 06.08#10 SMTP part; plan 06 task 9 smoke, 06.09#11) through the real serve path:
// the served process (the re-executed real main) evaluates a rule an administrator saved over POST /api/v1/rules, opens its
// condition, routes it to the organization's SMTP destination (the recipient is destination configuration, the relay password
// is its write-only sealed secret) and submits one message to a REAL submission relay over STARTTLS with AUTH PLAIN under
// the production egress policy and certificate verification. The relay and the mailbox are operator-provisioned:
//
//	SOUNDPOST_TEST_SMTP_HOST         the relay's host (an address when the relay has no DNS name)
//	SOUNDPOST_TEST_SMTP_PORT         the submission port (default 587)
//	SOUNDPOST_TEST_SMTP_TLS          starttls (default) or implicit
//	SOUNDPOST_TEST_SMTP_USER         the AUTH PLAIN identity
//	SOUNDPOST_TEST_SMTP_PASSWORD     its password (the destination's sealed secret; never printed)
//	SOUNDPOST_TEST_SMTP_FROM         the envelope and header sender
//	SOUNDPOST_TEST_SMTP_TO           the recipient mailbox address
//	SOUNDPOST_TEST_SMTP_CA_FILE      PEM trust root of the relay's certificate (system roots when absent)
//	SOUNDPOST_TEST_SMTP_SERVER_NAME  the name the certificate must match (the host when absent)
//	SOUNDPOST_TEST_SMTP_EGRESS_ALLOW comma-separated PRIVATE CIDRs the relay lives in (a relay on a private network)
//
// Without them it is reported as skipped, and with SOUNDPOST_REQUIRE_REAL_SMTP=1 it fails loudly, the same contract as the
// Telegram acceptance. The password is never printed: every failure text is scrubbed of it. The test records the provider's
// queue identity of the accepted delivery (the relay's own "queued as" id, not proof anyone read the mail); the message
// itself is then read raw from the mailbox by the operator who owns it (docs/operations/notification-channels.md).
func TestServeDeliversAConditionToARealSMTPRelay(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes and signals")
	}
	get := func(name string) string { return strings.TrimSpace(os.Getenv(name)) }
	host, user, password, from, to := get("SOUNDPOST_TEST_SMTP_HOST"), get("SOUNDPOST_TEST_SMTP_USER"), get("SOUNDPOST_TEST_SMTP_PASSWORD"), get("SOUNDPOST_TEST_SMTP_FROM"), get("SOUNDPOST_TEST_SMTP_TO")
	if host == "" || user == "" || password == "" || from == "" || to == "" {
		const why = "real SMTP serve acceptance has no relay: set SOUNDPOST_TEST_SMTP_HOST, _USER, _PASSWORD, _FROM and _TO"
		if os.Getenv("SOUNDPOST_REQUIRE_REAL_SMTP") == "1" {
			t.Fatal(why)
		}
		t.Skip("NOT RUN: " + why + " (set SOUNDPOST_REQUIRE_REAL_SMTP=1 to make this a failure)")
	}
	port := get("SOUNDPOST_TEST_SMTP_PORT")
	if port == "" {
		port = "587"
	}
	mode := get("SOUNDPOST_TEST_SMTP_TLS")
	if mode == "" {
		mode = "starttls"
	}
	args := []string{"--notify-smtp-host", host, "--notify-smtp-port", port, "--notify-smtp-tls", mode, "--notify-smtp-user", user, "--notify-smtp-from", from, "--notify-smtp-require-auth"}
	if name := get("SOUNDPOST_TEST_SMTP_SERVER_NAME"); name != "" {
		args = append(args, "--notify-smtp-server-name", name)
	}
	if ca := get("SOUNDPOST_TEST_SMTP_CA_FILE"); ca != "" {
		args = append(args, "--notify-ca-file", ca)
	}
	if allow := get("SOUNDPOST_TEST_SMTP_EGRESS_ALLOW"); allow != "" {
		args = append(args, "--notify-egress-allow", allow)
	}
	if _, err := strconv.Atoi(port); err != nil {
		t.Fatal("SOUNDPOST_TEST_SMTP_PORT is not a port number")
	}
	id := serveDelivery(t, realDestination{Type: "smtp", Address: to, Secret: password, CheckProvider: func(id string) error {
		if id == "" {
			return errors.New("no provider identity")
		}
		return nil
	}}, args...)
	t.Logf("REAL SMTP provider_queue_id=%s", id)
}

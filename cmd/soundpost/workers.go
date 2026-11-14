// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/notify/providers"
)

// workerOptions is the serve flag surface of the leader-only background runner:
// the node's own notification delivery environment. What is delivered where is
// organization configuration (the `destination` admin command), not a flag; see
// docs/operations/background-workers.md and notification-channels.md.
type workerOptions struct {
	interval        *time.Duration
	publicOrigin    *string
	egressAllow     *string
	caFile          *string
	telegramAPI     *string
	sendTimeout     *time.Duration
	smtpHost        *string
	smtpPort        *int
	smtpTLS         *string
	smtpUser        *string
	smtpFrom        *string
	smtpServerName  *string
	smtpRequireAuth *bool
}

func addWorkerFlags(f *flag.FlagSet) workerOptions {
	return workerOptions{
		interval:        f.Duration("worker-interval", 5*time.Second, "pause between background runner passes (rules, conditions, issues, jobs, notification delivery; at least 10ms)"),
		publicOrigin:    f.String("public-origin", "", "https origin links in notifications are built from (default: https://<--listen>, localhost for a wildcard host)"),
		egressAllow:     f.String("notify-egress-allow", "", "comma-separated PRIVATE CIDR prefixes notification delivery may reach (RFC 1918, CGNAT, unique-local); loopback, link-local and metadata ranges can never be allowed"),
		caFile:          f.String("notify-ca-file", "", "PEM file of extra trust roots for webhook, Telegram and SMTP TLS (system roots otherwise); verification is never disabled"),
		telegramAPI:     f.String("notify-telegram-api", "", "Telegram Bot API https origin (the public API by default)"),
		sendTimeout:     f.Duration("notify-send-timeout", 0, "bound of one notification send attempt (the providers' default when zero)"),
		smtpHost:        f.String("notify-smtp-host", "", "SMTP submission relay host; enables the e-mail channel (needs --notify-smtp-from)"),
		smtpPort:        f.Int("notify-smtp-port", 587, "SMTP submission port"),
		smtpTLS:         f.String("notify-smtp-tls", "starttls", "SMTP TLS mode: starttls or implicit"),
		smtpUser:        f.String("notify-smtp-user", "", "SMTP AUTH PLAIN identity; the destination's sealed secret is the password"),
		smtpFrom:        f.String("notify-smtp-from", "", "SMTP envelope and header sender address"),
		smtpServerName:  f.String("notify-smtp-server-name", "", "name the relay's certificate must match (the host by default)"),
		smtpRequireAuth: f.Bool("notify-smtp-require-auth", false, "refuse to submit without AUTH credentials"),
	}
}

// workerSettings is a validated runner configuration.
type workerSettings struct {
	interval time.Duration
	notify   appcore.NotificationConfig
}

// settings validates the flags before storage opens, so a bad value fails startup
// with a static reason and nothing else.
func (o workerOptions) settings(listen, dir string) (workerSettings, error) {
	origin := *o.publicOrigin
	if origin == "" {
		derived, err := originOf(listen)
		if err != nil {
			return workerSettings{}, err
		}
		origin = derived
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return workerSettings{}, errors.New("--public-origin must be an https origin")
	}
	cfg := appcore.NotificationConfig{PublicOrigin: "https://" + u.Host, StateDir: filepath.Join(dir, "notify"), TelegramAPI: *o.telegramAPI, Timeout: *o.sendTimeout}
	for _, part := range strings.Split(*o.egressAllow, ",") {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			return workerSettings{}, errors.New("--notify-egress-allow: not a CIDR prefix")
		}
		cfg.Egress.AllowPrefixes = append(cfg.Egress.AllowPrefixes, prefix)
	}
	if *o.caFile != "" {
		pem, err := os.ReadFile(*o.caFile)
		if err != nil {
			return workerSettings{}, errors.New("--notify-ca-file: unreadable")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return workerSettings{}, errors.New("--notify-ca-file: no certificate")
		}
		cfg.RootCAs = pool
	}
	if *o.smtpHost != "" {
		mode := providers.SMTPTLS(*o.smtpTLS)
		if mode != providers.SMTPStartTLS && mode != providers.SMTPImplicitTLS {
			return workerSettings{}, errors.New("--notify-smtp-tls must be starttls or implicit")
		}
		cfg.SMTP = &appcore.SMTPSettings{Host: *o.smtpHost, Port: *o.smtpPort, TLS: mode, Username: *o.smtpUser, RequireAuth: *o.smtpRequireAuth, From: *o.smtpFrom, ServerName: *o.smtpServerName}
	}
	return workerSettings{interval: *o.interval, notify: cfg}, nil
}

// originOf derives the default public origin from the listen address.
func originOf(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", errors.New("--listen: not a host:port address")
	}
	if ip, perr := netip.ParseAddr(host); host == "" || perr == nil && ip.IsUnspecified() {
		host = "localhost"
	}
	return "https://" + net.JoinHostPort(host, port), nil
}

// startWorkers runs the leader-only background runner under ctx and returns at
// once. The runner acts as the in-process system principal of each organization
// (no session, no stored token); it delivers through the real providers.
func startWorkers(ctx context.Context, core *appcore.App, s workerSettings) error {
	sender, err := core.NotificationSender(s.notify)
	if err != nil {
		return fmt.Errorf("notification delivery: %w", err)
	}
	cfg := appcore.WorkerConfig{
		Interval:  s.interval,
		Routing:   core.OrgRouting(),
		Sender:    sender,
		Producers: core.Producers(),
		Observe:   observeWorkers(),
	}
	if _, err = core.NewWorkers(cfg); err != nil {
		return fmt.Errorf("background workers: %w", err)
	}
	go func() { _ = core.RunWorkers(ctx, cfg) }()
	return nil
}

// observeWorkers logs, to stderr, each distinct set of failing stages once (closed
// stage and fault codes only, never text), and that they recovered.
func observeWorkers() func(appcore.PassReport) {
	var last string
	return func(r appcore.PassReport) {
		var parts []string
		for _, e := range r.Errors {
			parts = append(parts, e.Stage+"="+e.Code)
		}
		sig := strings.Join(parts, " ")
		if sig == last {
			return
		}
		if sig == "" {
			fmt.Fprintln(os.Stderr, "workers: recovered")
		} else {
			fmt.Fprintln(os.Stderr, "workers: failing stages: "+sig)
		}
		last = sig
	}
}

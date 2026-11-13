// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"soundpost/internal/auth"
	"soundpost/internal/backup"
	"soundpost/internal/health"
	"soundpost/internal/httpapi"
	"syscall"
	"time"
)

func main() {
	if code, ok := symbolicateWorker(os.Args); ok {
		os.Exit(code)
	}
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, failureLine(os.Args, e))
		os.Exit(1)
	}
}

// failureLine is the one line main prints for a failed command. `backup` prints the
// safe public error code (its failure matrix is keyed by it); every other command
// keeps one generic line, because its errors can carry operator-supplied paths.
func failureLine(args []string, err error) string {
	if len(args) >= 2 && args[1] == "backup" {
		return backupFailureLine(err)
	}
	if errors.Is(err, errInsecureMode) {
		return "soundpost: the data directory or TLS private key is accessible to other users; it must be mode 0700 and the key 0600"
	}
	if len(args) >= 2 && args[1] == "ready" {
		return "soundpost: not ready"
	}
	return "soundpost: startup or service failed"
}

// bootstrapNotice is what serve prints about the one-time bootstrap token. The
// token grants installation administration and both shipped units capture
// stderr into logs, so it is never printed: only the path of its 0600 file is.
func bootstrapNotice(dir string) string {
	if backup.IsRestoredRoot(dir) {
		return "A one-time recovery bootstrap token for this restored installation is in " + filepath.Join(dir, "bootstrap.token") + " (mode 0600); it is not printed."
	}
	return "A one-time bootstrap token is in " + filepath.Join(dir, "bootstrap.token") + " (mode 0600); it is not printed."
}
func run() error {
	if len(os.Args) >= 2 && os.Args[1] == "cluster-seed" {
		return runClusterSeed(os.Args[2:])
	}
	if len(os.Args) >= 2 && os.Args[1] == "backup" {
		return runBackup(os.Args[2:])
	}
	if len(os.Args) >= 2 && os.Args[1] == "version" {
		return runVersion(os.Args[2:], os.Stdout)
	}
	if len(os.Args) >= 2 && os.Args[1] == "ready" {
		return runReady(os.Args[2:], os.Stdout)
	}
	if len(os.Args) < 2 || os.Args[1] != "serve" {
		return fmt.Errorf("usage: soundpost serve --mode=single --data-dir PATH --listen ADDRESS --tls-cert PATH --tls-key PATH")
	}
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	mode := f.String("mode", "single", "deployment mode")
	dir := f.String("data-dir", "", "private durable directory")
	listen := f.String("listen", "127.0.0.1:8443", "HTTPS bind address")
	cert := f.String("tls-cert", "", "TLS certificate PEM")
	key := f.String("tls-key", "", "TLS private key PEM")
	oidcPath := f.String("oidc-config", "", "private OIDC configuration JSON")
	webDir := f.String("web-dir", "", "real built same-origin web asset directory (default: the UI compiled into the binary)")
	clusterConfig := f.String("cluster-config", "", "private mTLS node configuration JSON")
	nodeID := f.Uint64("node-id", 0, "configured Raft node identity")
	hold := f.String("startup-hold-file", "", "keep storage closed (GET /readyz reports startup_hold) until this file exists, e.g. a volume-mount sentinel")
	trustedProxy := f.String("trusted-proxy", "", "comma-separated CIDRs of reverse proxies whose X-Forwarded-For names the client for the login throttle (default: none, the peer address is used)")
	symbolicator := addSymbolicatorFlags(f)
	scrape := addScrapeFlags(f)
	authorityFlagSet := addAuthorityFlags(f)
	workerOpts := addWorkerFlags(f)
	if e := f.Parse(os.Args[2:]); e != nil {
		return e
	}
	if (*mode != "single" && *mode != "distributed") || *dir == "" || ((*cert == "") != (*key == "")) {
		return fmt.Errorf("valid mode, data directory and paired TLS files required")
	}
	proxies, e := httpapi.ParseTrustedProxies(*trustedProxy)
	if e != nil {
		return e
	}
	symbolicateSettings, e := symbolicator.settings()
	if e != nil {
		return e
	}
	scrapeCfg, e := scrape.settings()
	if e != nil {
		fmt.Fprintln(os.Stderr, scrapeFailureNotice(e))
		return e
	}
	workers, e := workerOpts.settings(*listen, *dir)
	if e != nil {
		return e
	}
	restoreAuthority, e := authorityFlagSet.open()
	if e != nil {
		fmt.Fprintln(os.Stderr, serveAuthorityNotice(e))
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e := preparePrivate(*dir, *key); e != nil {
		return e
	}
	if *cert == "" {
		var e error
		*cert, *key, e = localTLS(*dir, *listen)
		if e != nil {
			return e
		}
		fmt.Fprintln(os.Stderr, "Trust the generated server.crt through an authenticated channel before connecting.")
	}
	// The HTTPS listener exists before storage opens, so a probe sees "not ready" with a
	// closed reason while the journal and replication groups recover, never a refused
	// connection or a premature "ready".
	early, e := startEarly(*listen, *cert, *key)
	if e != nil {
		return e
	}
	defer early.server.Close()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = early.server.Shutdown(shutdown)
	}()
	if e = early.waitStartupHold(ctx, *hold); e != nil {
		return nil
	}
	core, e := openConfiguredCore(*dir, *mode, *clusterConfig, *nodeID)
	if e != nil {
		return e
	}
	defer core.Close()
	// The restore authority must be installed before any route can begin a deletion.
	if e = installServeAuthority(core, restoreAuthority); e != nil {
		fmt.Fprintln(os.Stderr, serveAuthorityNotice(e))
		return e
	}
	// Probes the sandbox, then swaps the frame resolver; this MUST precede Register.
	fmt.Fprintln(os.Stderr, symbolicatorNotice(core.ConfigureSymbolicator(ctx, symbolicateSettings)))
	scrapers, e := scrapeCfg.start(ctx, core)
	if e != nil {
		fmt.Fprintln(os.Stderr, scrapeFailureNotice(e))
		return e
	}
	if scrapers != nil {
		// Deferred after core.Close, so it runs first: the scrapers stop before storage closes.
		defer scrapers.Close()
		fmt.Fprintln(os.Stderr, scrapeStartedNotice(scrapers))
	}
	store, service := core.Control, core.Auth
	if _, e := store.BootstrapToken(); e == nil {
		fmt.Fprintln(os.Stderr, bootstrapNotice(*dir))
	}
	// Authentication and durable data services were opened together above.
	var cfg *auth.OIDCConfig
	if *oidcPath != "" {
		raw, e := os.ReadFile(*oidcPath)
		if e != nil {
			return e
		}
		cfg = &auth.OIDCConfig{}
		if e = json.Unmarshal(raw, cfg); e != nil {
			return e
		}
	}
	state := newAppState(core, version)
	ready := func(c context.Context) (health.Readiness, error) { return health.Ready(c, state) }
	routes := []func(*http.ServeMux){core.Register, func(mux *http.ServeMux) { httpapi.RegisterHealthRoutes(mux, ready) }}
	if register := scrapeStatusRoutes(core, scrapers); register != nil {
		routes = append(routes, register)
	}
	if *webDir != "" {
		register, err := httpapi.UIRoutes(os.DirFS(*webDir))
		if err != nil {
			return err
		}
		routes = append(routes, register)
	} else if assets, ok := embeddedWeb(); ok {
		register, err := httpapi.UIRoutes(assets)
		if err != nil {
			return err
		}
		routes = append(routes, register)
	}
	early.gate.Open(httpapi.NewServerBehind(proxies, *listen, service, cfg, routes...).Handler)
	go core.RunFences(ctx)
	// The leader-only background runner (rules, conditions, issue/incident/job
	// producers, notification delivery) acts as the in-process system principal of
	// each organization: no human session, no stored token.
	if e = startWorkers(ctx, core, workers); e != nil {
		return e
	}
	e = <-early.done
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}

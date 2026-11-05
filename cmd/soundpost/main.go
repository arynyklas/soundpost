// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"syscall"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "soundpost: startup or service failed")
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) >= 2 && os.Args[1] == "cluster-seed" {
		return runClusterSeed(os.Args[2:])
	}
	if len(os.Args) >= 2 && os.Args[1] == "backup" {
		return runBackup(os.Args[2:])
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
	webDir := f.String("web-dir", "", "real built same-origin web asset directory")
	clusterConfig := f.String("cluster-config", "", "private mTLS node configuration JSON")
	nodeID := f.Uint64("node-id", 0, "configured Raft node identity")
	if e := f.Parse(os.Args[2:]); e != nil {
		return e
	}
	if (*mode != "single" && *mode != "distributed") || *dir == "" || ((*cert == "") != (*key == "")) {
		return fmt.Errorf("valid mode, data directory and paired TLS files required")
	}
	core, e := openConfiguredCore(*dir, *mode, *clusterConfig, *nodeID)
	if e != nil {
		return e
	}
	defer core.Close()
	store, service := core.Control, core.Auth
	if *cert == "" {
		*cert, *key, e = localTLS(*dir, *listen)
		if e != nil {
			return e
		}
		fmt.Fprintln(os.Stderr, "Trust the generated server.crt through an authenticated channel before connecting.")
	}
	if token, e := store.BootstrapToken(); e == nil {
		fmt.Fprintln(os.Stderr, "One-time bootstrap token:", token)
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
	routes := []func(*http.ServeMux){core.Register}
	if *webDir != "" {
		register, err := httpapi.UIRoutes(os.DirFS(*webDir))
		if err != nil {
			return err
		}
		routes = append(routes, register)
	}
	server := httpapi.NewServer(*listen, service, cfg, routes...)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go core.RunFences(ctx)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	e = server.ListenAndServeTLS(*cert, *key)
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}

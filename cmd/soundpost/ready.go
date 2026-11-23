// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/health"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// errNotReady is the exit-1 outcome of `soundpost ready`: the server answered that it is
// not ready, or could not be asked. The reason is already on stdout.
var errNotReady = errors.New("not ready")

// runReady is `soundpost ready [--json] [--url URL] [--ca-cert PATH | --data-dir DIR]`.
//
// It asks the RUNNING server's unauthenticated GET /readyz, so the answer is the live node's
// own quorum/apply/disk/policy/schema decision. It never opens the data directory: a second
// opener would contend for the control and apply database locks of the running process, and
// a read-only open of a replicated store cannot say anything about quorum. The exit status is
// 0 only when the server answered 200 with ready=true; every other outcome (not ready, not
// reachable, untrusted certificate, malformed answer) is exit 1 with a closed reason.
// --data-dir only locates the installation's own public server.crt as the trust root;
// verification is never disabled.
func runReady(args []string, out io.Writer) error {
	f := flag.NewFlagSet("ready", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	asJSON := f.Bool("json", false, "machine-readable output")
	target := f.String("url", "https://127.0.0.1:8443", "HTTPS base URL of the running server")
	ca := f.String("ca-cert", "", "PEM certificate to trust (default: system roots)")
	dir := f.String("data-dir", "", "installation directory whose server.crt is the trust root")
	timeout := f.Duration("timeout", 5*time.Second, "request deadline")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || (*ca != "" && *dir != "") || *timeout <= 0 || *timeout > time.Minute {
		return fmt.Errorf("usage: soundpost ready [--json] [--url https://HOST:PORT] [--ca-cert PEM | --data-dir DIR] [--timeout 5s]")
	}
	if *dir != "" {
		*ca = filepath.Join(*dir, "server.crt")
	}
	result := probeReady(*target, *ca, *timeout)
	if *asJSON {
		if err := json.NewEncoder(out).Encode(result); err != nil {
			return err
		}
	} else if result.Ready {
		cursor := ""
		if result.Applied != nil {
			cursor = fmt.Sprintf(" applied=%s:%d", result.Applied.Group, result.Applied.Index)
		}
		role := ""
		if result.Role != "" {
			role = fmt.Sprintf(" role=%s leader=%d term=%d", result.Role, result.Leader, result.Term)
		}
		fmt.Fprintf(out, "ready version=%s%s%s\n", result.Version, cursor, role)
	} else {
		fmt.Fprintf(out, "not ready: %s\n", result.Reason)
	}
	if !result.Ready {
		return errNotReady
	}
	return nil
}

// probeReady never returns an error: every failure is an unready answer with a closed reason,
// because an operator script needs one shape whether the server said no or did not answer.
func probeReady(target, caPath string, timeout time.Duration) health.Readiness {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return health.Unready(health.ReasonUnreachable)
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13}
	if caPath != "" {
		pemBytes, err := os.ReadFile(caPath)
		if err != nil {
			return health.Unready(health.ReasonUnreachable)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pemBytes) {
			return health.Unready(health.ReasonUnreachable)
		}
		config.RootCAs = roots
	}
	client := &http.Client{
		Timeout:       timeout,
		Transport:     &http.Transport{TLSClientConfig: config, DisableKeepAlives: true, Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Get(strings.TrimSuffix(u.String(), "/") + "/readyz")
	if err != nil {
		return health.Unready(health.ReasonUnreachable)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return health.Unready(health.ReasonUnreachable)
	}
	var answer health.Readiness
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&answer) != nil || (resp.StatusCode == http.StatusOK) != answer.Ready {
		return health.Unready(health.ReasonStateUnavailable)
	}
	if !answer.Ready && !answer.Reason.Valid() {
		return health.Unready(health.ReasonStateUnavailable)
	}
	return answer
}

// earlyServer is the HTTPS listener a `serve` process owns from before storage opens until
// it stops. Its gate answers /readyz "starting" (or "startup_hold") while recovery runs, then
// hands every request to the real handler.
type earlyServer struct {
	gate   *httpapi.Gate
	server *http.Server
	done   chan error
	addr   string
}

func startEarly(listen, cert, key string) (*earlyServer, error) {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	gate := httpapi.NewGate(health.ReasonStarting)
	server := httpapi.StartupServer(listen, gate)
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, cert, key) }()
	return &earlyServer{gate: gate, server: server, done: done, addr: listener.Addr().String()}, nil
}

// waitStartupHold blocks while path is set and does not exist. It is the operator's startup
// gate: a volume-mount or unseal sentinel that keeps storage closed (and /readyz reporting
// startup_hold) until the data volume is really there. Only the file's existence is read.
func (e *earlyServer) waitStartupHold(ctx context.Context, path string) error {
	if path == "" {
		return nil
	}
	e.gate.SetReason(health.ReasonStartupHold)
	for {
		if _, err := os.Stat(path); err == nil {
			e.gate.SetReason(health.ReasonStarting)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// refuseSchema is the whole life of a member whose stored control-state format is not the one this
// binary supports (auth.SchemaError: newer, written by a newer build, or older, a layout that needs
// a migration this build does not run). It opens nothing further and serves nothing: every route
// but /readyz answers the gate's retryable 503, and /readyz answers unready with schema_newer or
// schema_old, the decision health.Ready makes for a running node, taken before the node exists. It
// is not corruption and not a failed start, so the process stays up (a probe, `soundpost ready` or
// a Compose health check reads the reason instead of finding a crash loop) until it is stopped.
func (e *earlyServer) refuseSchema(ctx context.Context, schema *auth.SchemaError) error {
	reason := health.ReasonSchemaOld
	if schema.Newer() {
		reason = health.ReasonSchemaNewer
	}
	e.gate.SetReason(reason)
	fmt.Fprintln(os.Stderr, schemaRefusalLine(reason, schema.Observed))
	select {
	case <-ctx.Done():
		return nil
	case err := <-e.done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// schemaRefusalLine is the one line logged when a member refuses its data directory's format. It
// carries the two format numbers and the closed reason, never a path.
func schemaRefusalLine(reason health.Reason, observed uint8) string {
	direction := "older than"
	if reason == health.ReasonSchemaNewer {
		direction = "newer than"
	}
	return fmt.Sprintf("soundpost: %s: the control-state format marker of this data directory (%d) is %s the formats this binary supports (%d to %d); nothing is served and /readyz stays unready with this reason. Run the release that wrote the data, or restore a backup taken before the format changed (docs/operations/upgrade.md)", reason, observed, direction, auth.MinSchemaMarker, auth.SchemaMarker)
}

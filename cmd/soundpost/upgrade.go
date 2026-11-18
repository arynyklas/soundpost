// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

var errUpgradeUsage = errors.New("usage: soundpost upgrade contract-indexes --url https://HOST:PORT --email ADDRESS --password-file PATH --reason TEXT [--ca PEM] [--code TOTP] [--command-id ID]")

// upgradeRefused is a typed refusal of the contraction route: the fault the server answered.
type upgradeRefused struct {
	status int
	fault  model.Fault
}

func (e *upgradeRefused) Error() string {
	return fmt.Sprintf("refused (http %d, code=%s, detail=%s)", e.status, e.fault.Code, e.fault.SafeDetail)
}

// runUpgrade is `soundpost upgrade contract-indexes`, the operator step that ends the expand phase of the
// sharded artifact ledger index and the per-replay pins (D70). Until it runs, a new binary keeps the
// per-project values of the previous release current, so every voter can still be rolled back; after it
// those values are deleted, writes no longer grow with the size of a project, and a rollback needs the
// backup taken before the step. It logs in over HTTPS as a system administrator (the password is read from
// a file, never from the command line), posts one audited request and logs out. The server refuses it,
// naming the members, unless the running binary of every control member answers the live layout question; it
// answers success without changing anything when every organization is already contracted, so it is safe to
// repeat.
func runUpgrade(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "contract-indexes" {
		return errUpgradeUsage
	}
	f := flag.NewFlagSet("upgrade contract-indexes", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	base := f.String("url", "", "HTTPS address of a member (https://HOST:PORT)")
	email := f.String("email", "", "system administrator's address")
	passwordFile := f.String("password-file", "", "file holding the administrator's password")
	code := f.String("code", "", "one-time code, when the administrator has a second factor")
	caFile := f.String("ca", "", "PEM certificate that signs (or is) the member's certificate; default: the system roots")
	reason := f.String("reason", "", "reason recorded in the audit log")
	commandID := f.String("command-id", "", "command ID of the audit rows (default: a new one)")
	if err := f.Parse(args[1:]); err != nil || f.NArg() != 0 || *base == "" || *email == "" || *passwordFile == "" || *reason == "" {
		return errUpgradeUsage
	}
	target, err := url.Parse(*base)
	if err != nil || target.Scheme != "https" || target.Host == "" || (target.Path != "" && target.Path != "/") {
		return errUpgradeUsage
	}
	raw, err := os.ReadFile(*passwordFile)
	if err != nil {
		return fmt.Errorf("read the password file: %w", err)
	}
	password := strings.TrimRight(string(raw), "\r\n")
	id := model.NewID()
	if *commandID != "" {
		if id, err = model.ParseID(*commandID); err != nil {
			return errUpgradeUsage
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			return fmt.Errorf("read the CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return errors.New("the CA file holds no certificate")
		}
		tlsConfig.RootCAs = pool
	}
	jar, _ := cookiejar.New(nil)
	// The contraction is one control transition per organization: allow it time.
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: true}, Jar: jar, Timeout: 10 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	origin := "https://" + target.Host
	post := func(path string, body any, csrf string) (int, []byte, error) {
		payload, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		req, err := http.NewRequest(http.MethodPost, origin+path, bytes.NewReader(payload))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		answer, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, answer, err
	}
	refused := func(status int, answer []byte) error {
		var fault model.Fault
		if json.Unmarshal(answer, &fault) != nil || fault.Code == "" {
			fault = model.Fault{Code: "unknown"}
		}
		return &upgradeRefused{status: status, fault: fault}
	}
	status, answer, err := post("/api/v1/login", map[string]string{"Email": *email, "Password": password, "Code": *code}, "")
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	if status != http.StatusOK {
		return refused(status, answer)
	}
	var session auth.Session
	if err = json.Unmarshal(answer, &session); err != nil || session.CSRF == "" {
		return errors.New("login answered without a session")
	}
	defer func() { _, _, _ = post("/api/v1/logout", struct{}{}, session.CSRF) }()
	status, answer, err = post("/api/v1/admin/upgrade/contract-indexes", auth.ContractIndexesRequest{CommandID: id, Reason: *reason}, session.CSRF)
	if err != nil {
		return fmt.Errorf("contract-indexes: %w", err)
	}
	if status != http.StatusOK {
		return refused(status, answer)
	}
	var result auth.ContractIndexesResult
	if err = json.Unmarshal(answer, &result); err != nil {
		return errors.New("contract-indexes answered with an unreadable result")
	}
	if result.Changed {
		_, err = fmt.Fprintf(out, "indexes contracted: %d organization(s) (control revision %d); the per-project values of the previous release are gone\n", result.Organizations, result.Revision)
	} else {
		_, err = fmt.Fprintf(out, "indexes already contracted (nothing changed)\n")
	}
	return err
}

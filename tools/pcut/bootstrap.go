// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// runBootstrap performs the single-installation bootstrap over HTTPS exactly like the drills and the install smoke (owner,
// organization, project, reader, grant, one onboarded source and its credential) against a running `serve --mode=single`, and
// writes the fixture the generator, prober and verifier use. The installation is then stopped and exported as the cluster seed.
func runBootstrap(args []string) error {
	fl := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	url := fl.String("url", "", "https base URL of the running single-mode bootstrap server")
	trust := fl.String("trust", "", "PEM (the server's own server.crt) the bootstrap connection trusts")
	tokenFile := fl.String("token-file", "", "the one-time bootstrap.token file")
	out := fl.String("out", "", "fixture file to write (0600)")
	ca := fl.String("ca", "", "PEM the clients will trust for the voters' public listeners")
	endpoints := fl.String("endpoints", "", "comma-separated name=id=https://host:port of the voters")
	series := fl.Int("series", 64, "number of series (label w=w00..)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *url == "" || *trust == "" || *tokenFile == "" || *out == "" || *ca == "" || *endpoints == "" || *series < 1 || *series > 900 {
		return errors.New("usage: pcut bootstrap --url U --trust PEM --token-file F --out FIXTURE --ca PEM --endpoints name=id=url,... [--series 64]")
	}
	var eps []Endpoint
	for _, part := range strings.Split(*endpoints, ",") {
		fields := strings.SplitN(part, "=", 3)
		if len(fields) != 3 {
			return fmt.Errorf("bad endpoint %q", part)
		}
		id, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return fmt.Errorf("bad endpoint %q", part)
		}
		eps = append(eps, Endpoint{Name: fields[0], ID: id, URL: fields[2]})
	}
	token, err := os.ReadFile(*tokenFile)
	if err != nil {
		return err
	}
	st, err := newSite("bootstrap", *url, *trust, true)
	if err != nil {
		return err
	}
	timeout := 20 * time.Second
	post := func(stage, path string, v any, csrf string, want int) ([]byte, error) {
		status, raw, err := st.postJSON(path, v, timeout, csrf, "")
		if err != nil {
			return nil, fmt.Errorf("%s: %s", stage, transportClass(err))
		}
		if status != want {
			return nil, fmt.Errorf("%s: unexpected status %d", stage, status)
		}
		return raw, nil
	}
	raw, err := post("bootstrap", "/api/v1/bootstrap", map[string]string{"Token": strings.TrimSpace(string(token)), "Email": "owner@pcut.invalid", "Password": ownerPassword}, "", 200)
	if err != nil {
		return err
	}
	var owner auth.Session
	if err = json.Unmarshal(raw, &owner); err != nil {
		return err
	}
	org, project, source := model.NewID(), model.NewID(), model.NewID()
	admin := func(kind string, p auth.AdminPayload) error {
		raw, err := post("admin_read", "/api/v1/admin/read", struct {
			Kind string `json:"kind"`
		}{"organizations"}, owner.CSRF, 200)
		if err != nil {
			return err
		}
		var view auth.AdminView
		if err = json.Unmarshal(raw, &view); err != nil {
			return err
		}
		p.Reason = "power cut drill"
		payload, _ := json.Marshal(p)
		_, err = post("admin_"+kind, "/api/v1/admin/commands", auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: view.Revision, OrgID: org, Kind: kind, Payload: payload}, owner.CSRF, 200)
		return err
	}
	reader := model.NewID()
	for _, step := range []struct {
		kind string
		p    auth.AdminPayload
	}{
		{"create_org", auth.AdminPayload{Name: "power cut drill"}},
		{"create_project", auth.AdminPayload{ID: project, Name: "power cut drill"}},
		{"create_user", auth.AdminPayload{ID: reader, Email: readerEmail, Password: readerPassword}},
		{"membership", auth.AdminPayload{UserID: reader, Enabled: true}},
		{"grant", auth.AdminPayload{UserID: reader, ProjectID: project, Enabled: true, Permissions: []string{string(auth.Read)}}},
	} {
		if err = admin(step.kind, step.p); err != nil {
			return err
		}
	}
	service, environment, build := model.NewID(), model.NewID(), model.NewID()
	names := make([]string, *series)
	for i := range names {
		names[i] = fmt.Sprintf("w%02d", i)
	}
	var approved model.Scalar
	_ = json.Unmarshal([]byte(`503`), &approved)
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric, model.Log, model.ErrorKind, model.SpanKind},
		Resources:     model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{"instance"}},
		Templates:     []model.LogTemplate{{ID: "failed", Revision: 1, Line: "operation failed: {status}", Severity: "error", Fields: []model.TemplateField{{Name: "status", Type: "int64", MaxBytes: 16, Sensitivity: "metadata", Values: []model.Scalar{approved}}}}},
		Operations:    []string{"operation"},
		Labels:        map[string][]string{seriesLabel: names},
		RetentionDays: map[model.Kind]uint32{model.Metric: 30, model.Log: 14, model.ErrorKind: 30, model.SpanKind: 14}, MaxBytes: 1 << 30, MaxSeries: 1000}
	raw, err = post("source_onboard", "/api/v1/sources", auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Expires: model.UnixNano(time.Now().Add(90 * 24 * time.Hour).UnixNano()), Policy: policy, Reason: "power cut drill"}, owner.CSRF, 200)
	if err != nil {
		return err
	}
	var issued auth.SourceOnboarded
	if err = json.Unmarshal(raw, &issued); err != nil || issued.Credential == "" {
		return errors.New("source_onboard: no credential")
	}
	fx := Fixture{Org: org.String(), Project: project.String(), Source: source.String(), Service: service.String(), Environment: environment.String(), Build: build.String(),
		Credential: issued.Credential, ReaderEmail: readerEmail, ReaderPassword: readerPassword, Series: names, CA: *ca, Endpoints: eps}
	body, err := json.MarshalIndent(fx, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(*out, append(body, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Printf("bootstrap ok: %d series, %d endpoints, fixture %s\n", len(names), len(eps), *out)
	return nil
}

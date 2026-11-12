// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"flag"
	"strconv"

	"soundpost/internal/appcore"
	"soundpost/internal/sources"
)

// scrapeOptions is the serve flag surface of OpenMetrics scraping: a private
// JSON file listing the approved targets and a private directory holding every
// secret they reference (see docs/operations/scraping.md).
type scrapeOptions struct {
	config     *string
	secretsDir *string
}

func addScrapeFlags(f *flag.FlagSet) scrapeOptions {
	return scrapeOptions{
		config:     f.String("scrape-config", "", "private JSON listing the OpenMetrics scrape targets this node scrapes (mode 0600, not group/world writable); requires --scrape-secrets-dir; see docs/operations/scraping.md"),
		secretsDir: f.String("scrape-secrets-dir", "", "private (0700) directory of 0600 secret files named by the references in --scrape-config: target credentials and the source credential each target admits as"),
	}
}

// scrapeSettings is a validated scrape configuration: empty when scraping is not configured.
type scrapeSettings struct {
	specs   []sources.ScrapeTargetSpec
	secrets sources.SecretReader
}

// errScrapeFlags is the pairing error of the two flags.
var errScrapeFlags = errors.New("--scrape-config and --scrape-secrets-dir are required together")

// settings loads and validates the configuration before storage opens, so a
// bad file fails startup with a static reason code and nothing else.
func (o scrapeOptions) settings() (scrapeSettings, error) {
	if *o.config == "" && *o.secretsDir == "" {
		return scrapeSettings{}, nil
	}
	if *o.config == "" || *o.secretsDir == "" {
		return scrapeSettings{}, errScrapeFlags
	}
	secrets, err := sources.NewDirSecretReader(*o.secretsDir)
	if err != nil {
		return scrapeSettings{}, err
	}
	cfg, err := sources.LoadScrapeConfig(*o.config)
	if err != nil {
		return scrapeSettings{}, err
	}
	specs, err := cfg.Specs(secrets)
	if err != nil {
		return scrapeSettings{}, err
	}
	return scrapeSettings{specs: specs, secrets: secrets}, nil
}

// start runs the scrapers under ctx against the opened node. It returns nil
// when scraping is not configured. The caller closes the host before closing
// the node.
func (s scrapeSettings) start(ctx context.Context, core *appcore.App) (*sources.ScrapeHost, error) {
	if len(s.specs) == 0 {
		return nil, nil
	}
	return sources.StartScrapeHost(ctx, sources.ScrapeHostDeps{Auth: core.Auth, Ingest: core.Ingest, Secrets: s.secrets}, s.specs)
}

// scrapeFailureNotice is the one stderr line serve prints when the scrape
// configuration is refused: only static reason codes, never a path, alias,
// URL or secret.
func scrapeFailureNotice(err error) string {
	var ce *sources.ScrapeConfigError
	var se *sources.SecretError
	switch {
	case errors.As(err, &ce):
		return "scrape: " + ce.Reason
	case errors.As(err, &se):
		return "scrape: secrets_" + se.Reason
	case errors.Is(err, errScrapeFlags):
		return "scrape: flags_incomplete"
	}
	return "scrape: startup_failed"
}

// scrapeStartedNotice is the one stderr line serve prints after the scrapers start.
func scrapeStartedNotice(host *sources.ScrapeHost) string {
	return "scrape: " + strconv.Itoa(len(host.Status())) + " target(s) started"
}

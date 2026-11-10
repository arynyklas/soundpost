// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package agent is the logic of soundpost-agent: policy-bound host metric
// collection and system log acquisition, submitted to the installation's C03
// ingest route over HTTPS with a source credential. The agent PRODUCES
// batches; it never decides admission. It reads no command lines or
// environments, assumes no Kubernetes metadata, and logs reason codes and
// counters only.
package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"soundpost/internal/host"
	"soundpost/internal/model"
	"soundpost/internal/sources"
)

// Duration is a JSON string such as "30s".
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// ResourceConfig is the registered resource identity of this host: the same
// service, environment and build IDs the installation's source policy lists.
type ResourceConfig struct {
	ServiceID     string            `json:"service_id"`
	EnvironmentID string            `json:"environment_id"`
	BuildID       string            `json:"build_id"`
	Instance      string            `json:"instance_pseudonym"`
	Labels        map[string]string `json:"labels,omitempty"`
}

// FilesystemConfig names a mount by an operator alias. Only the alias is ever
// exported; the path is used to ask the OS for free space.
type FilesystemConfig struct {
	Alias string `json:"alias"`
	Path  string `json:"path"`
}

// HostConfig enables host metric groups. A group that is not listed is denied
// by policy and reported as such, never as zero.
type HostConfig struct {
	Interval    Duration           `json:"interval"`
	Allow       []string           `json:"allow"`
	Filesystems []FilesystemConfig `json:"filesystems,omitempty"`
}

// LogConfig is one log source: the sources policy (revision and resource come
// from the top level) and its polling interval.
type LogConfig struct {
	sources.SourcePolicy
	Poll Duration `json:"poll_interval,omitempty"`
}

// Config is the agent's local, operator-owned configuration.
type Config struct {
	Version        int            `json:"version"`
	Server         string         `json:"server"`
	CAFile         string         `json:"ca_file,omitempty"`
	CredentialFile string         `json:"credential_file"`
	StateDir       string         `json:"state_dir"`
	Org            string         `json:"org"`
	Project        string         `json:"project"`
	Source         string         `json:"source"`
	PolicyRevision uint64         `json:"policy_revision"`
	Resource       ResourceConfig `json:"resource"`
	Host           *HostConfig    `json:"host,omitempty"`
	Logs           []LogConfig    `json:"logs,omitempty"`
}

const maxConfigBytes = 1 << 20

// LoadConfig reads and strictly decodes a config file: unknown fields, a second
// JSON value and files over 1 MiB are errors.
func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, errors.New("agent: config file unreadable")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil || len(raw) > maxConfigBytes {
		return Config{}, errors.New("agent: config file unreadable or too large")
	}
	return ParseConfig(raw)
}

// ParseConfig decodes config bytes strictly.
func ParseConfig(raw []byte) (Config, error) {
	var c Config
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return Config{}, errors.New("agent: config is not valid for this version")
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("agent: config has trailing data")
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

var aliasRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

func cfgErr(what string) error { return fmt.Errorf("agent: invalid config: %s", what) }

// Validate checks the configuration before anything is read or sent.
func (c Config) Validate() error {
	if c.Version != 1 {
		return cfgErr("version")
	}
	u, err := url.Parse(c.Server)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return cfgErr("server must be an https origin without credentials")
	}
	for name, p := range map[string]string{"credential_file": c.CredentialFile, "state_dir": c.StateDir} {
		if !filepath.IsAbs(p) {
			return cfgErr(name + " must be absolute")
		}
	}
	if c.CAFile != "" && !filepath.IsAbs(c.CAFile) {
		return cfgErr("ca_file must be absolute")
	}
	for name, v := range map[string]string{"org": c.Org, "project": c.Project, "source": c.Source, "resource.service_id": c.Resource.ServiceID, "resource.environment_id": c.Resource.EnvironmentID, "resource.build_id": c.Resource.BuildID} {
		if _, err := model.ParseID(v); err != nil {
			return cfgErr(name)
		}
	}
	if c.PolicyRevision == 0 || c.Resource.Instance == "" || len(c.Resource.Instance) > 256 {
		return cfgErr("policy_revision or resource.instance_pseudonym")
	}
	if c.Host == nil && len(c.Logs) == 0 {
		return cfgErr("nothing to collect: configure host or logs")
	}
	if h := c.Host; h != nil {
		if time.Duration(h.Interval) < time.Second || time.Duration(h.Interval) > time.Hour {
			return cfgErr("host.interval must be 1s..1h")
		}
		if _, err := h.policy(); err != nil {
			return cfgErr("host policy")
		}
	}
	names := map[string]bool{}
	res, err := c.resource()
	if err != nil {
		return cfgErr("resource")
	}
	for _, l := range c.Logs {
		if l.Revision != 0 || l.Resource.Instance != "" || l.Resource.Service != (model.ID{}) {
			return cfgErr("log sources take policy_revision and resource from the top level")
		}
		p := l.SourcePolicy
		p.Revision, p.Resource = model.Revision(c.PolicyRevision), res
		if err := p.Validate(); err != nil {
			return cfgErr("log source " + safeName(p.Name))
		}
		if names[p.Name] {
			return cfgErr("duplicate log source name")
		}
		names[p.Name] = true
		if l.Poll != 0 && (time.Duration(l.Poll) < time.Second || time.Duration(l.Poll) > time.Hour) {
			return cfgErr("poll_interval must be 1s..1h")
		}
	}
	return nil
}

func safeName(s string) string {
	if len(s) > 48 || strings.ContainsAny(s, "\r\n\x00") {
		return "?"
	}
	return s
}

func (c Config) resource() (model.Resource, error) {
	var r model.Resource
	var err error
	if r.Service, err = model.ParseID(c.Resource.ServiceID); err != nil {
		return r, err
	}
	if r.Environment, err = model.ParseID(c.Resource.EnvironmentID); err != nil {
		return r, err
	}
	if r.Build, err = model.ParseID(c.Resource.BuildID); err != nil {
		return r, err
	}
	r.Instance = c.Resource.Instance
	r.Labels = model.Labels{}
	for k, v := range c.Resource.Labels {
		r.Labels = append(r.Labels, model.Label{Name: k, Value: v})
	}
	sortLabels(r.Labels)
	return r, nil
}

func sortLabels(l model.Labels) {
	for i := 1; i < len(l); i++ {
		for j := i; j > 0 && l[j].Name < l[j-1].Name; j-- {
			l[j], l[j-1] = l[j-1], l[j]
		}
	}
}

func (h HostConfig) policy() (host.HostPolicy, error) {
	var p host.HostPolicy
	for _, g := range h.Allow {
		p.Allow = append(p.Allow, host.Group(g))
	}
	for _, f := range h.Filesystems {
		if !aliasRE.MatchString(f.Alias) {
			return p, cfgErr("filesystem alias")
		}
		p.Filesystems = append(p.Filesystems, host.FilesystemTarget{Alias: f.Alias, Path: f.Path})
	}
	return p, p.Validate()
}

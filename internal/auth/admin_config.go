// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"bytes"
	"encoding/json"
	"net/url"
	"soundpost/internal/model"
)

type SourcePolicyConfig struct {
	ProjectID  model.ID   `json:"project_id"`
	Origins    []string   `json:"origins"`
	Restricted bool       `json:"restricted"`
	Readers    []model.ID `json:"readers"`
	Enabled    bool       `json:"enabled"`
}
type DestinationConfig struct {
	Type     string `json:"type"`
	Endpoint string `json:"endpoint"`
	Address  string `json:"address"`
	Enabled  bool   `json:"enabled"`
}
type RetentionConfig struct {
	ProjectID model.ID `json:"project_id"`
	Signal    string   `json:"signal"`
	Days      uint32   `json:"days"`
}

func strictConfig(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return model.Fail(model.Invalid)
	}
	return nil
}
func validateAdminConfig(kind string, p AdminPayload, o *model.ControlOrg) error {
	switch kind {
	case "team":
		var team model.ControlTeam
		if e := strictConfig(p.Config, &team); e != nil {
			return e
		}
		for _, u := range team.Members {
			if !o.Members[u.String()] {
				return model.Fail(model.NotFound)
			}
		}
		for _, project := range team.Projects {
			if _, ok := o.Projects[project.String()]; !ok {
				return model.Fail(model.NotFound)
			}
		}
		for _, permission := range team.Permissions {
			if !validPermission(permission) {
				return model.Fail(model.Invalid)
			}
		}
		if o.Teams == nil {
			o.Teams = map[string]model.ControlTeam{}
		}
		o.Teams[p.ID.String()] = team
	case "source_policy":
		var cfg SourcePolicyConfig
		if e := strictConfig(p.Config, &cfg); e != nil {
			return e
		}
		if _, ok := o.Projects[cfg.ProjectID.String()]; !ok {
			return model.Fail(model.NotFound)
		}
		for _, reader := range cfg.Readers {
			if !o.Members[reader.String()] {
				return model.Fail(model.NotFound)
			}
		}
		for _, origin := range cfg.Origins {
			u, e := url.Parse(origin)
			if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
				return model.Fail(model.Invalid)
			}
		}
	case "sso":
		var cfg OIDCConfig
		if e := strictConfig(p.Config, &cfg); e != nil {
			return e
		}
		issuer, e := url.Parse(cfg.Issuer)
		redirect, re := url.Parse(cfg.RedirectURL)
		if e != nil || re != nil || issuer.Scheme != "https" || redirect.Scheme != "https" || cfg.ClientID == "" || cfg.ClientSecret != "" {
			return model.Fail(model.Invalid)
		}
		for _, user := range cfg.Subjects {
			if !o.Members[user.String()] && !o.Admins[user.String()] {
				return model.Fail(model.NotFound)
			}
		}
	case "destination":
		var cfg DestinationConfig
		if e := strictConfig(p.Config, &cfg); e != nil {
			return e
		}
		if cfg.Type != "" && cfg.Type != "smtp" && cfg.Type != "telegram" && cfg.Type != "webhook" {
			return model.Fail(model.Invalid)
		}
		if cfg.Endpoint != "" {
			u, e := url.Parse(cfg.Endpoint)
			if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				return model.Fail(model.Invalid)
			}
		}
	case "retention":
		var cfg RetentionConfig
		if e := strictConfig(p.Config, &cfg); e != nil {
			return e
		}
		if _, ok := o.Projects[cfg.ProjectID.String()]; !ok {
			return model.Fail(model.NotFound)
		}
		if cfg.Days == 0 || cfg.Days > 3650 {
			return model.Fail(model.Invalid)
		}
		switch cfg.Signal {
		case "metrics", "logs", "traces", "errors", "replay", "profiles", "audit":
		default:
			return model.Fail(model.Invalid)
		}
	}
	return nil
}

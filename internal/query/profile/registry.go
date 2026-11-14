// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
)

type FeatureSet struct {
	ID      string   `json:"id"`
	Enabled []string `json:"enabled"`
}
type Profile struct {
	ID              string                     `json:"id"`
	Commit          string                     `json:"commit"`
	ManifestVersion int                        `json:"manifest_version"`
	FeatureSets     []FeatureSet               `json:"feature_sets"`
	Configuration   map[string]json.RawMessage `json:"configuration"`
	Obligations     []string                   `json:"obligations"`
	Complete        bool                       `json:"complete"`
	// Resolve populates these fields. They are never trusted from disk manifests.
	ActiveFeatureSet  FeatureSet `json:"-"`
	ConfigurationHash string     `json:"-"`
	Identity          string     `json:"-"`
}
type Registry struct{ profiles map[string]Profile }

var pins = map[string]string{"promql-prometheus-3.1.0": "7086161a93b262aa0949dbf2aba15a5a7b13e0a3", "promql-prometheus-3.13.5": "f497435984d1ca1d84cda5ed309387ac2eb1f8f6", "logql-loki-3.5.2": "257d2f62bf8a81b44dea6fe88968d1d28c8e01e7"}

func Load(files fs.FS) (Registry, error) {
	r := Registry{profiles: map[string]Profile{}}
	names, err := fs.Glob(files, "*.json")
	if err != nil {
		return r, err
	}
	for _, name := range names {
		b, err := fs.ReadFile(files, name)
		if err != nil {
			return r, err
		}
		var p Profile
		if err = json.Unmarshal(b, &p); err != nil {
			return r, err
		}
		commit, known := pins[p.ID]
		if !known || p.Commit != commit || p.ManifestVersion != 1 {
			return r, fmt.Errorf("invalid pinned profile %s", p.ID)
		}
		if _, exists := r.profiles[p.ID]; exists {
			return r, fmt.Errorf("duplicate profile")
		}
		sets := map[string]bool{}
		for _, set := range p.FeatureSets {
			if set.ID == "" || sets[set.ID] {
				return r, fmt.Errorf("duplicate or empty feature set in %s", p.ID)
			}
			sets[set.ID] = true
		}
		if p.Complete && (len(p.FeatureSets) == 0 || len(p.Obligations) == 0 || len(p.Configuration) == 0) {
			return r, fmt.Errorf("accepted profile lacks configuration, feature sets or obligations")
		}
		r.profiles[p.ID] = p
	}
	if len(r.profiles) != len(pins) {
		return r, fmt.Errorf("missing pinned profiles")
	}
	return r, nil
}
func (r Registry) Resolve(id, featureSet string) (Profile, error) {
	p, ok := r.profiles[id]
	if !ok {
		return Profile{}, fmt.Errorf("unknown profile %s", id)
	}
	if !p.Complete {
		return Profile{}, fmt.Errorf("profile inventory not accepted: %s", id)
	}
	for _, set := range p.FeatureSets {
		if set.ID != featureSet {
			continue
		}
		out := p
		out.FeatureSets = make([]FeatureSet, len(p.FeatureSets))
		for i, registered := range p.FeatureSets {
			out.FeatureSets[i] = FeatureSet{ID: registered.ID, Enabled: append([]string(nil), registered.Enabled...)}
		}
		out.ActiveFeatureSet = FeatureSet{ID: set.ID, Enabled: append([]string(nil), set.Enabled...)}
		sort.Strings(out.ActiveFeatureSet.Enabled)
		out.Obligations = append([]string(nil), p.Obligations...)
		out.Configuration = make(map[string]json.RawMessage, len(p.Configuration))
		for name, raw := range p.Configuration {
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			var value any
			if err := decoder.Decode(&value); err != nil {
				return Profile{}, fmt.Errorf("invalid configuration %s: %w", name, err)
			}
			canonical, err := json.Marshal(value)
			if err != nil {
				return Profile{}, err
			}
			out.Configuration[name] = canonical
		}
		configuration, err := json.Marshal(out.Configuration)
		if err != nil {
			return Profile{}, err
		}
		configHash := sha256.Sum256(configuration)
		out.ConfigurationHash = hex.EncodeToString(configHash[:])
		identity, err := json.Marshal(struct {
			ID                string
			Commit            string
			ManifestVersion   int
			FeatureSet        FeatureSet
			ConfigurationHash string
		}{out.ID, out.Commit, out.ManifestVersion, out.ActiveFeatureSet, out.ConfigurationHash})
		if err != nil {
			return Profile{}, err
		}
		hash := sha256.Sum256(identity)
		out.Identity = hex.EncodeToString(hash[:])
		return out, nil
	}
	return Profile{}, fmt.Errorf("unregistered feature set %s", featureSet)
}

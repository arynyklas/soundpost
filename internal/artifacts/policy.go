// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"bytes"
	"encoding/json"
	"soundpost/internal/model"
	"soundpost/internal/sourcemap"
)

// transformMap reuses the owned v3 decoder's path/section/index/CPU budgets,
// then allowlists retained fields; ignored extensions can never carry sources.
func transformMap(raw []byte, includeSources bool) ([]byte, []byte, error) {
	if _, err := sourcemap.Decode(bytes.NewReader(raw), sourcemap.Limits{MaxBytes: model.ArtifactBundleLimit, MaxFiles: 1024, MaxDepth: 8}); err != nil {
		return nil, nil, model.Fail(model.Invalid)
	}
	var input map[string]json.RawMessage
	if model.StrictJSON(raw, &input) != nil {
		return nil, nil, model.Fail(model.Invalid)
	}
	clean, private, err := transformDocument(input, includeSources, 1)
	if err != nil {
		return nil, nil, err
	}
	publicBytes, err := json.Marshal(clean)
	if err != nil {
		return nil, nil, model.Fail(model.Invalid)
	}
	var sourceBytes []byte
	if includeSources {
		sourceBytes, err = json.Marshal(private)
	}
	if err != nil || len(publicBytes)+len(sourceBytes) > model.ArtifactBundleLimit {
		return nil, nil, model.Fail(model.TooLarge)
	}
	return publicBytes, sourceBytes, nil
}
func transformDocument(input map[string]json.RawMessage, include bool, depth int) (map[string]any, map[string]any, error) {
	if depth > 8 {
		return nil, nil, model.Fail(model.TooLarge)
	}
	clean := map[string]any{}
	private := map[string]any{}
	for _, key := range []string{"version", "sources", "sourceRoot", "names", "mappings"} {
		if raw, ok := input[key]; ok {
			clean[key] = raw
		}
	}
	if sections, ok := input["sections"]; ok {
		var list []struct {
			Offset json.RawMessage            `json:"offset"`
			Map    map[string]json.RawMessage `json:"map"`
		}
		if json.Unmarshal(sections, &list) != nil || len(list) > 1024 {
			return nil, nil, model.Fail(model.Invalid)
		}
		publicSections := make([]any, 0, len(list))
		privateSections := make([]any, 0, len(list))
		for _, section := range list {
			c, p, err := transformDocument(section.Map, include, depth+1)
			if err != nil {
				return nil, nil, err
			}
			publicSections = append(publicSections, map[string]any{"offset": section.Offset, "map": c})
			if include {
				privateSections = append(privateSections, map[string]any{"offset": section.Offset, "map": p})
			}
		}
		clean["sections"] = publicSections
		if include {
			private["sections"] = privateSections
		}
	}
	if include {
		var sources []string
		if raw, ok := input["sources"]; ok {
			if json.Unmarshal(raw, &sources) != nil {
				return nil, nil, model.Fail(model.Invalid)
			}
			private["sources"] = sources
		}
		if raw, ok := input["sourcesContent"]; ok {
			var content []*string
			if json.Unmarshal(raw, &content) != nil || len(content) != len(sources) {
				return nil, nil, model.Fail(model.Invalid)
			}
			private["sourcesContent"] = content
		}
		if raw, ok := input["sourceRoot"]; ok {
			private["sourceRoot"] = raw
		}
	}
	return clean, private, nil
}

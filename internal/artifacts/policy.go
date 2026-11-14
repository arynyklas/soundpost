// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/sourcemap"
)

// transformMap reuses the owned v3 decoder's path/section/index/CPU budgets,
// then allowlists retained fields; ignored extensions can never carry sources.
func transformMap(raw []byte, includeSources bool) ([]byte, []byte, error) {
	if _, err := sourcemap.DecodeBytes(raw, sourcemap.Limits{MaxBytes: model.ArtifactBundleLimit, MaxFiles: 1024, MaxDepth: 8}); err != nil {
		return nil, nil, model.Fail(model.Invalid)
	}
	// Run every check on the buffer itself, with no second streaming copy.
	var input map[string]json.RawMessage
	// StrictJSON's streaming decoder would copy the whole body again, so the
	// same checks run directly on the buffer: ValidateJSON rejects duplicate
	// keys, invalid UTF-8, lone surrogates and excess depth; Unmarshal rejects
	// trailing data, exactly as StrictJSON's second Decode did.
	if model.ValidateJSON(raw) != nil || json.Unmarshal(raw, &input) != nil {
		return nil, nil, model.Fail(model.Invalid)
	}
	// input owns independent copies of every retained value: raw is not read
	// again, so the caller dropping its reference lets it be collected here.
	clean, private, err := transformDocument(input, includeSources, 1)
	if err != nil {
		return nil, nil, err
	}
	// transformDocument deleted sourcesContent from input; the decoded strings
	// in private are the only copy left.
	publicBytes, err := json.Marshal(clean)
	if err != nil {
		return nil, nil, model.Fail(model.Invalid)
	}
	// Both outputs are marshaled before either is returned; clean is garbage now.
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
		for i := range list {
			c, p, err := transformDocument(list[i].Map, include, depth+1)
			if err != nil {
				return nil, nil, err
			}
			publicSections = append(publicSections, map[string]any{"offset": list[i].Offset, "map": c})
			if include {
				privateSections = append(privateSections, map[string]any{"offset": list[i].Offset, "map": p})
			}
			list[i].Map = nil
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
			// The decoded strings are the only copy needed from here on.
			delete(input, "sourcesContent")
		}
		if raw, ok := input["sourceRoot"]; ok {
			private["sourceRoot"] = raw
		}
	}
	return clean, private, nil
}

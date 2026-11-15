// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"sort"

	"github.com/arynyklas/soundpost/internal/model"
)

// AdminSource is one source of an organization as its administrators read it
// (POST /api/v1/admin/read kind "source"): the lifecycle state and the current
// admitted policy, which is what POST /api/v1/sources/policy changes by revision.
// It never carries a credential or the ID of one.
type AdminSource struct {
	ID      model.ID           `json:"id"`
	Project model.ID           `json:"project"`
	Browser bool               `json:"browser"`
	Origins []string           `json:"origins"`
	Expires model.UnixNano     `json:"expires_ns"`
	Revoked bool               `json:"revoked"`
	Retired bool               `json:"retired"`
	Closing bool               `json:"closing"`
	Policy  model.SourcePolicy `json:"policy"`
}

// adminSources lists the organization's sources in ID order.
func adminSources(st model.ControlState, org model.ID) []AdminSource {
	out := []AdminSource{}
	for _, src := range st.Sources {
		if src.Org != org {
			continue
		}
		origins := src.Origins
		if origins == nil {
			origins = []string{}
		}
		out = append(out, AdminSource{ID: src.ID, Project: src.Project, Browser: src.Browser, Origins: origins, Expires: src.Expires, Revoked: src.Revoked, Retired: src.Retired, Closing: src.Closing, Policy: src.Policy})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	return out
}

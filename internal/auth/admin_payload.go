// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"bytes"
	"encoding/json"
	"io"
	"soundpost/internal/model"
)

func (p AdminPayload) MarshalJSON() ([]byte, error) {
	v := map[string]any{"name": p.Name, "email": p.Email, "password": p.Password, "permissions": p.Permissions, "enabled": p.Enabled, "secret": p.Secret, "reason": p.Reason}
	if p.ID != (model.ID{}) {
		v["id"] = p.ID
	}
	if p.UserID != (model.ID{}) {
		v["user_id"] = p.UserID
	}
	if p.ProjectID != (model.ID{}) {
		v["project_id"] = p.ProjectID
	}
	if len(p.Config) > 0 {
		v["config"] = p.Config
	}
	return json.Marshal(v)
}
func (p *AdminPayload) UnmarshalJSON(b []byte) error {
	type plain AdminPayload
	var out plain
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(&out); e != nil {
		return model.Fail(model.Invalid)
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return model.Fail(model.Invalid)
	}
	*p = AdminPayload(out)
	return nil
}

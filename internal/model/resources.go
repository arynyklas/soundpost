// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

// ResourceRegistry is registered in the source's authenticated project. Display
// aliases are metadata, never an alternative native identity encoding.
type ResourceRegistry struct {
	Services     []ID     `json:"service_id"`
	Environments []ID     `json:"environment_id"`
	Builds       []ID     `json:"build_id"`
	Instances    []string `json:"instance_pseudonym"`
}

func (r ResourceRegistry) Validate() error {
	for _, ids := range [][]ID{r.Services, r.Environments, r.Builds} {
		if len(ids) == 0 {
			return Fail(Invalid)
		}
		for _, id := range ids {
			if id == (ID{}) {
				return Fail(Invalid)
			}
		}
	}
	if len(r.Instances) == 0 {
		return Fail(Invalid)
	}
	for _, instance := range r.Instances {
		if !safeCode(instance, 256) {
			return Fail(Invalid)
		}
	}
	return nil
}
func registeredResourceID(ids []ID, id ID) bool {
	if id == (ID{}) {
		return false
	}
	for _, registered := range ids {
		if registered == id {
			return true
		}
	}
	return false
}
func (r ResourceRegistry) Allows(value Resource) bool {
	return registeredResourceID(r.Services, value.Service) && registeredResourceID(r.Environments, value.Environment) && registeredResourceID(r.Builds, value.Build) && oneOf(value.Instance, r.Instances...)
}

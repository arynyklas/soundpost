// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention

import "soundpost/internal/model"

// references is the installed References source (nil: none is bound yet).
func (s *Service) references() References {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.References
}

// UseReferences installs the reference-aware expiry source on a Service built
// without one. The application builds this Service before the object that
// answers it can exist: the artifact lifecycle takes the Service itself as its
// delete-generation source (artifacts.LifecycleConfig.Deletes), so it can only be
// constructed afterwards. It may be installed once; a second binding is a
// Conflict, never a replacement, because a swapped source could silently stop
// vetoing erasure of what the first one protected. Expiry passes that run before
// the binding see no source, exactly as a Service configured without one.
func (s *Service) UseReferences(r References) error {
	if r == nil {
		return model.Fail(model.Invalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.References != nil {
		return model.Fail(model.Conflict)
	}
	s.cfg.References = r
	return nil
}

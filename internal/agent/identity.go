// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/arynyklas/soundpost/internal/durablefs"
	"github.com/arynyklas/soundpost/internal/model"
)

// identity is the agent's stable pseudonymous identity, created once in the
// state directory: the producer (the batch-routing identity) and the host
// pseudonym of its clock domain. Neither is derived from a host name, address
// or machine id.
type identity struct {
	Producer model.ID `json:"producer"`
	Host     model.ID `json:"host"`
}

func loadIdentity(dir string) (identity, error) {
	path := filepath.Join(dir, "identity.json")
	raw, err := os.ReadFile(path)
	if err == nil {
		var id identity
		if json.Unmarshal(raw, &id) != nil || id.Producer == (model.ID{}) || id.Host == (model.ID{}) {
			return identity{}, errors.New("agent: identity file is corrupt")
		}
		return id, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return identity{}, errors.New("agent: identity file unreadable")
	}
	id := identity{Producer: model.NewID(), Host: model.NewID()}
	raw, err = json.Marshal(id)
	if err != nil {
		return identity{}, err
	}
	if err := durablefs.MkdirAll(dir); err != nil {
		return identity{}, errors.New("agent: state directory unusable")
	}
	if err := durablefs.Exclusive(path, raw); err != nil && !errors.Is(err, os.ErrExist) {
		return identity{}, errors.New("agent: identity file not writable")
	}
	return loadIdentity(dir)
}

// bootID derives the clock domain's boot pseudonym. On Linux it is a hash of
// the kernel's boot id (so it changes on reboot and reveals nothing); elsewhere
// it falls back to the process epoch, which is conservative: a new epoch is
// never mistaken for the same boot.
func bootID(epoch model.ID) model.ID {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return epoch
	}
	sum := sha256.Sum256([]byte("soundpost.agent.boot.v1\x00" + strings.TrimSpace(string(raw))))
	var id model.ID
	copy(id[:], sum[:])
	if id == (model.ID{}) {
		return epoch
	}
	return id
}

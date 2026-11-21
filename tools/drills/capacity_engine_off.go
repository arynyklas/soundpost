//go:build !soundpost_faults

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import "errors"

// capEngineFaults needs the storage engine's fault seam, which exists only in builds tagged
// soundpost_faults (`go run -tags soundpost_faults ./tools/drills ...`). Without it the part is not
// run and the scenario fails with this reason: it never passes without having run.
func capEngineFaults(env *Env, rep *Report) (map[string]string, error) {
	return nil, errors.New("the engine fault part of capacity-faults needs a drills binary built with -tags soundpost_faults")
}

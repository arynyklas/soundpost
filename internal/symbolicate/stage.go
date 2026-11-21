// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

// The worker and probe argument vectors, and their staged forms. A staged vector is
// used only when CLONE_INTO_CGROUP is unavailable (see nativeGroup.stage): the same
// binary blocks on an inherited release pipe, is moved into the limited cgroup by its
// parent, and then execs the matching worker vector. Exact vectors, no other arguments.
const (
	workerArg      = "--worker-v1"
	probeArg       = "--probe-v1"
	stageWorkerArg = "--stage-worker-v1"
	stageProbeArg  = "--stage-probe-v1"
)

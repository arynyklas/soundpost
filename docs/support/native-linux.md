<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Native Linux collector qualification status

Required matrix: kernel 6.1 and 6.6 x amd64 and arm64, each with CPU, off-CPU, runqueue split, frame coverage, loss, memory, FDs, privacy, identity (exit, exec, PID reuse, namespaces, no frame pointers), CPU hotplug and container modes. A row is exercised only by a genuine runner of that exact series and architecture. Windows/WSL does not implicitly qualify them (design section 13), so the WSL2 host (kernel 6.6.87.2, amd64, root) is recorded as separate functional rows `wsl2-linux-kernel` that qualify nothing.

Observed on the WSL2 host (functional evidence): software-clock CPU capture with real callchains, frame coverage (about 1.00 with frame pointers, partial without), explicit loss under a stalled reader, memory and FD bounds, capture privacy, exit/exec/namespace/no-frame-pointer identity scenarios. A helper without capabilities against a foreign-uid target is **denied** (`permission_denied`), kept distinct from unsupported.

Not exercised or failed, with reasons:
- Off-CPU and runqueue split: `scheduler_pid_namespace_not_initial` (tracefs is readable as root, but the PID namespace is nested so raw scheduler PIDs cannot be attributed).
- PID reuse: the kernel never reused a PID within the smoke's attempt budget (no `pid_max`/`ns_last_pid` writes): not exercised.
- CPU hotplug (needs a host configuration change) and container/seccomp modes (no fixture): not exercised.
- Node and Bun native columns: measured failures, helper refused with `resource_limit` (cause not investigated).
- Kernel 6.1, arm64: no runner.

Staged `acquisition_pending`, empty-success, synthetic and no-op samplers are rejected by `qual.CheckCapture` controls that run before any native row is trusted.

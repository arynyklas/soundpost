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

## Real Linux 6.1 and 6.6 amd64 runners (07.06-W1, lane 4 wave 13)

Run as root (sudo) on two real VMs, one kernel series each, work tree based on commit `16c4060` (uncommitted changes on top); raw machine reports, gate output and envelopes are kept with the lane 4 wave 13 evidence. A row passes only on the exact kernel it names; a kernel never qualifies the other series or arm64.

| | Linux 6.1 amd64 | Linux 6.6 amd64 |
|---|---|---|
| `uname -r` | 6.1.0-54-amd64 (Debian 6.1.190-1) | 6.6.162-0606162-generic (mainline) |
| Config facts | `PERF_EVENTS`, `FTRACE`, `TRACING`, `SCHED_DEBUG`, `SCHEDSTATS`, `PREEMPT_DYNAMIC` (voluntary), `HZ=250`, `UNWINDER_ORC`, no frame-pointer kernel | same, `FRAME_POINTER` and `UNWINDER_FRAME_POINTER` |
| `perf_event_paranoid`, tracefs, CPUs | 1, mounted, 8 | 1, mounted, 8 |
| Privacy suite, native rows (`canary_boundaries`, `stored_exported_records`, `no_stack_bytes_config`, `negative_control`, `scheduler_canaries`) | all 5 passed; `no_stack_bytes_config`: 41 `perf_event_open` calls audited under `strace -f -v`, 14 CPU-event opens, 0 findings | all 5 passed |
| Acceptance `runqueue_split` | **not stable**: 5 of 8 recorded runs supported (74-100% of the workload's ground truth), 3 failed (0.2%, 46.5% and 67.1% of it; limit +-25%). The failing runs carry hundreds of domain-wide scheduler-coverage revocations from the correlator (kernel record loss 0, buffer overflow 0); cause open, see lane 4 wave 13 report | supported in both recorded runs (94.8% and 98.9% of the ground truth) |
| Acceptance `off_cpu`, `cpu`, `frame_coverage`, `loss`, `memory`, `fds`, `privacy` | supported | supported |
| Native overhead (`overhead --hz 99 --seconds 120 --repeats 5`, `cpu` fixture) | full run executed | full run executed |
| `qualification --require-all` | exit 1 in the 30 s run (runqueue_split failed; runtime columns python/node/bun not qualified on their own evidence) | exit 10 (runtime columns python/node/bun not qualified; the other series and arm64 not exercised on this host) |

Not exercised on these hosts: the other kernel series (one per host), arm64 (out of release scope, D10), Chrome 142 / Edge / Firefox rows, journeys (no OCI runtime), PID reuse, CPU hotplug, container modes, the Node 22/24 and Python runtime columns of the native acceptance runner (python critical `jobs` rows fail in the VM, see the runtime suite report), single-host and distributed gates.

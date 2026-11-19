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

The release gate (`fixtures/nativeperf/qualification`) qualifies a matrix row only for the exact pinned build: the kernel release must be the manifest row's pinned `kernel_build` and match the series' `uname -r` pattern (`6.1.<n>-<abi>-amd64|arm64`, `6.6.<n>-<build id>-generic`), and the result's kernel config digest must equal the row's `kernel_config.sha256`. The WSL2 kernel and any other 6.6 or 6.1 build are unqualified. The overhead report is merged only when its host identity, kernel config digest and run digest match the acceptance result and its own numbers; whether the full 120 s x 5 run was executed is read from the measured fixtures, not from the report's `full_run_executed` flag.

| | Linux 6.1 amd64 | Linux 6.6 amd64 |
|---|---|---|
| `uname -r` | 6.1.0-54-amd64 (Debian 6.1.190-1) | 6.6.162-0606162-generic (mainline) |
| Config facts | `PERF_EVENTS`, `FTRACE`, `TRACING`, `SCHED_DEBUG`, `SCHEDSTATS`, `PREEMPT_DYNAMIC` (voluntary), `HZ=250`, `UNWINDER_ORC`, no frame-pointer kernel | same, `FRAME_POINTER` and `UNWINDER_FRAME_POINTER` |
| `perf_event_paranoid`, tracefs, CPUs | 1, mounted, 8 | 1, mounted, 8 |
| Privacy suite, native rows (`canary_boundaries`, `stored_exported_records`, `no_stack_bytes_config`, `negative_control`, `scheduler_canaries`) | all 5 passed; `no_stack_bytes_config`: 41 `perf_event_open` calls audited under `strace -f -v`, 14 CPU-event opens, 0 findings | all 5 passed |
| Acceptance `runqueue_split` (wave 14) | 8 of 8 10 s runs supported after the correlator scoped a missing switch-out baseline to its task (runnable delay 100.0-100.5% of the ground truth; wave 13: 5 of 8, 0.2%-100.4%). The judge also bounds the sleeping coordinator's runnable delay by the workload's own measurement: a correlator that reports sleeping time as run-queue delay (3.99 s vs a 0.27 s bound) or no run-queue delay at all (0 vs 4.0 s) FAILS the row on this kernel | 8 of 8 supported (100.1-100.5%); the same two defective correlators fail |
| Acceptance `off_cpu`, `cpu`, `frame_coverage`, `loss`, `memory`, `fds`, `privacy` | supported | supported |
| Native overhead (`overhead --hz 99 --seconds 120 --repeats 5`, `cpu` fixture) | full run executed | full run executed |
| `qualification --require-all` (wave 14, final tree) | exit 10: every native row (cpu, off_cpu, runqueue_split, frame_coverage, loss, overhead, memory, fds, privacy) supported on 6.1.0-54-amd64, matrix 6.1 LTS amd64 qualified; unqualified: runtime python/node/bun columns, the other series and arm64 | exit 10: the same on 6.6.162, matrix 6.6 LTS amd64 qualified; same unqualified runtime columns and other series |

Not exercised on these hosts: the other kernel series (one per host), arm64 (out of release scope, D10), Chrome 142 / Edge / Firefox rows, journeys (no OCI runtime), PID reuse, CPU hotplug, container modes, the Node 22/24 and Python runtime columns of the native acceptance runner (python critical `jobs` rows fail in the VM, see the runtime suite report), single-host and distributed gates.

## Helper under an OCI runtime (07.02#6, lane 5 wave 24)

The release's `soundpost-perf-helper` image was started under Docker through the shipped `soundpost-perf-helper` Compose service and asked for a real capture (`fresh-install-matrix` row `native_profile_install`, `docs/operations/distributed.md`, "Evidence: the helper image under an OCI runtime"). This is a functional row of one host, not a kernel qualification: the kernel below is neither of the pinned 6.1/6.6 LTS builds, so it qualifies nothing in the matrix above.

| | |
|---|---|
| Host | Debian 13, `6.12.74+deb13+1-amd64`, amd64, 8 CPUs, unified cgroup v2, AppArmor on, Yama `ptrace_scope` 0 |
| Runtime | Docker 26.1.5 (classic image store), Compose 2.26.1; the helper image is the release's OCI archive plus the `manifest.json` Docker 26 needs |
| Container | uid 0, only `CAP_PERFMON`, deny-by-default `deploy/seccomp/soundpost-perf.json`, `no-new-privileges`, read-only root, no network, host cgroup namespace, PID namespace of the workload; audited with `docker inspect` after the run |
| `perf_event_paranoid=2` (set by the operator for the run, restored after) | 494 software CPU-clock samples in 5.0 s of a Go workload that spins in one function, every sample attributed to the target, 494 resolved to that function; the helper exits 0 on SIGTERM. Without `CAP_PERFMON` the same capture also succeeds (user-space-only events of a same-uid target need no capability at this level), so `CAP_PERFMON` is not what gates this helper's CPU mode here. A target of another uid (nonroot) is the typed denied result. |
| `perf_event_paranoid=3` (the host's own value) | the typed denied result (`denied` / `permission_denied`, zero samples) for all three cases, with `CAP_PERFMON` too: this Debian kernel gates `perf_event_open` on `CAP_SYS_ADMIN` at level 3, so a PERFMON-only helper cannot work there. The matrix row is `not_run` with that reason; no zero or off-CPU-complete capture is ever reported. |

Not exercised: the off-CPU and runqueue modes in a container (the scheduler tracepoints need the initial PID namespace, see above), the chart, Kubernetes, kernels 6.1/6.6 and arm64 in a container, a non-root workload through a helper that has an extra capability.

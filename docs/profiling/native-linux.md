<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Native Linux profiling

The native capability probe is not a profiler or a qualification certificate. It opens and immediately closes a disabled, fixed perf CPU event for each requested process, reads host permission settings and fixed scheduler tracepoint ABI IDs, and attempts disabled tracepoint opens. It never changes sysctls, escalates privileges, samples a workload, or returns invented samples. Support means this narrow event-open check succeeded, not that callchains, scheduler correlation, overhead or loss have been qualified. Frame/thread coverage remains unmeasured.

CPU acquisition requests 99 Hz, at most 128 frames, a 100 ms reorder window and at most 64 MiB acquisition/export memory. Native event timestamps have an explicit boot/host monotonic domain. Process-start plus namespace and generation identities prevent PID-reuse joins. Engine sample deltas are not OS nanosecond durations and cannot be added as the same unit.

The closed sanitized union permits only CPU addresses, numeric scheduler events, mapping/build identities, loss and target-generation events. Strict decoding rejects unknown fields. No command names, environment, register/stack byte arrays, heap, locals, object values or argument values are accepted. A future kernel ring may transiently contain kernel ABI names/paths: acquisition must skip these in place, never copy them to diagnostics/socket/export, and never persist raw perf.data. No ptrace or memory-unwind fallback is permitted.

Only authorized scheduler participants have nullable TaskKeys; idle/foreign identities are omitted. A missing switch-out callchain is explicit rather than reconstructed from an unrelated stack. Mapping updates bind a process identity without an invented TID, and per-CPU loss needs no invented task. Native CPU metadata separates software-CPU-clock period nanoseconds from hardware cycles and engine samples; callchain context markers are never instruction addresses. Throttle/unthrottle evidence is distinct from lost sample counts. Coverage validators reject unmeasured nonzero claims. Monotonic zero is a valid time in its explicit domain; identity/generation zero is not.

`Open` remains an explicit acquisition dependency error on Linux until task04.02 authorization/resource accounting and task04.03 helper/ring acquisition deliver real sessions. Capability probe success must not be presented as end-to-end capture. Non-Linux calls return typed unsupported results.

Run only against an authorized local workload:

```
go run ./fixtures/nativeperf/capability --probe-only --target-pid "$TARGET_PID"
```

The fixture resolves namespace/process-start identity locally and prints only capability metadata (no samples). Qualification rows in `fixtures/nativeperf/qualification.json` remain `not_run` until exact build/config/permissions/runtime flags, privacy, real samples, blocked intervals, loss, memory and overhead evidence are recorded. WSL is functional evidence only, not Linux LTS production qualification. Public fixtures must never include customer inventory or private process data.

Linux ABI constants/layouts are independently authored from the Linux perf_event_open manual and kernel trace event documentation, linked in the manifest. No GPL scheduler implementation, third-party profiling engine, restricted corpus or raw kernel buffers are redistributed. First-party files are Apache-2.0; the kernel remains an OS prerequisite.

## Qualification matrix, acceptance runner and measured limits (task 04.09)

Qualification is evidence, never a probe result. Four first-party commands under `fixtures/nativeperf/` produce it; every row they write is one of `supported` (exercised on this host, criterion measured and met), `unqualified` (cannot be exercised here, exact reason recorded), `not_run`, `denied`, `error` or `failed`. A row that was not exercised, was denied or errored can never be `supported`: `qual.Row.Validate` rejects it, and the release gate re-validates every report it reads.

```
cc -O2 -pthread -fno-omit-frame-pointer -g -o fixtures/nativeperf/acceptance/workloads fixtures/nativeperf/acceptance/workloads.c
go run ./fixtures/nativeperf/acceptance --manifest fixtures/nativeperf/qualification.json \
    --workload fixtures/nativeperf/acceptance/workloads --duration 60s --seed 451 \
    --endpoint-env SOUNDPOST_FIXTURE_API --out acceptance.json
go run ./fixtures/nativeperf/overhead --manifest fixtures/nativeperf/qualification.json --hz 99 --seconds 120 --repeats 5 --out overhead.json
go run ./fixtures/nativeperf/qualification --manifest fixtures/nativeperf/qualification.json --results acceptance.json,overhead.json --require-all
```

* `acceptance` starts the real `nativeperf.Helper` in its own process, sends a signed grant over its private socket and reads the sanitized stream with its own decoder. Frames are resolved by a verifier-side ELF symbol lookup over snapshots of the target's `/proc/<pid>/maps`; addresses outside the workload executable stay unresolved. It never exports to a node (04.08 covers export, storage and read privacy); `--endpoint-env` only records that an external endpoint was named.
* The workload (`workloads.c`) has a named hot function, a 200 ms timed sleep, pipe and futex waits woken by a foreign process, two threads pinned to one CPU, a migrating thread, an exec, a build without frame pointers and a 16-thread fan-out. It records every blocking interval, CPU phase and runnable delay itself with `CLOCK_MONOTONIC` and verifies its own ground truth. Threads and the foreign waker are created before the `ready` line and parked until `exit`, because the helper treats a thread or process creation or exit inside a live capture as a coverage change and ends the session.
* Before the real path runs, the capture checker (`qual.CheckCapture`) must reject a staged `acquisition_pending` session and capability, a successful empty session, a synthetic perfect-cadence sampler and two no-op samplers, and must accept a plausible capture. A report that lacks these controls is rejected by the gate. A genuine permission denial stays a distinct typed failure.
* The `acceptance` exit codes are 0 (every required row supported), 1 (an exercised row failed), 2 (usage), 4 (the checker accepted a contaminated capture) and 10 (required rows unexercised). `qualification --require-all` prints every unqualified required row and exits 10 or 1; without `--require-all` it only writes the machine report. Node success never qualifies Bun, amd64 never qualifies arm64, and a functional-evidence row never qualifies an LTS row.
* The runtime fixtures (`fixtures/nativeperf/runtime/{python.py,node.mjs,bun.ts}`) use the exact C09 supplements (`startProfile` in `packages/node` and `packages/bun`, `start_profile` in `sdk/python`). Their samples are runtime engine samples in their own column; they are never native engine output and never OS CPU time. The native capture of the same process is taken independently by the helper.
* `overhead` alternates baseline and capture runs, reports the target's CPU per iteration and throughput separately from the collector's CPU (helper process and client), and evaluates the budgets (<= 3% workload CPU, <= 64 MiB combined helper+client+ring memory) as constants it never adjusts. A run shorter than 120 s or with fewer than 5 repeats is marked reduced and is never promoted to the full result.

### Measured on this host (WSL2, kernel 6.6.87.2-microsoft-standard-WSL2, amd64, paranoid=2, root)

* CPU: real software CPU-clock samples at 99 Hz through the signed-grant helper process; the hot function `spqual_hot` appears in the frame-pointer callchains and is resolved by the verifier-side ELF lookup. Frame coverage of the true call chain is about 1.00 with frame pointers and about 0.40 without (the frames the unwinder cannot see are absent, never invented).
* Injected limits: a 4 KiB ring with a stalled reader produced explicit loss events; `RLIMIT_NOFILE` in the helper child and tiny `MaxMemory` values were refused with the closed code `resource_limit` and released every FD.
* Overhead (full approved command, `cpu` fixture only): -0.34% +- 0.57% workload CPU (budget 3%), throughput +0.37%, collector 4.6% of one core, about 36 MiB combined helper+client+ring memory (budget 64 MiB). The 16-thread fan-out fixture was only measured in short development runs and is not advertised.
* Scheduler off-CPU, runqueue split and blocked-time rows are **unqualified**. tracefs is readable as root in this session and the scheduler tracepoints open and fire, but their raw PIDs are init-namespace PIDs and this distribution runs in another PID namespace (`/proc/self/ns/pid` inode is not 4026531836), so no authorized task ever matched: a scheduler session succeeded and stayed empty. The engine now refuses instead. As a non-root user tracefs is denied (`EACCES`). A rerun on a host in the initial PID namespace (hostPID) is required; the capture/correlation runner exists but has never produced attributed events.
* The engine ends a session at the first thread or process creation/exit in the target (`thread_coverage_changed`); runtimes that create threads dynamically are therefore only partly capturable. Node and Bun native captures were refused with `resource_limit` in the recorded run (cause not investigated); Python 3.12.3 produced genuine native samples, all inside the interpreter binary (stripped, unresolved).
* Not run: Linux 6.1/6.6 LTS runners, arm64, PID reuse, CPU hotplug, container/cgroup namespace modes, CPython 3.13/3.14, Node 24, database wait.

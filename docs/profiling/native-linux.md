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

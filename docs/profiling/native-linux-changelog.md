<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Native Linux profiling changes

## 2026-11-03 — Task04.01

Added closed numeric event contracts, explicit clock/generation/unit validation, bounded configuration, capability probes and unsupported-platform errors. Qualification starts at `not_run`; probe success does not assert sample acquisition, coverage or measured overhead. Linux session acquisition remains dependent on tasks04.02/03. No customer system access, privilege changes or publication are included.

Review corrections: canonical C01 decimal round trips, nullable authorized scheduler participants, optional switch-out callchains, process-scoped mappings and CPU-scoped loss without invented thread keys. Native samples carry method/period units, actual period, requested rate, typed context markers and distinct loss/throttle evidence. Resource/identity refusals are classifiable; capabilities and intervals validate coverage/domain/unit invariants. These contract corrections do not qualify acquisition or overhead.

## 2026-11-10 — Task04.09

Added the qualification model, acceptance runner (real helper process, signed grant, real perf CPU samples, self-verifying C workloads), overhead runner, release gate (`qualification --require-all`) and runtime columns (Python 3.12.3, Node 22.23.4, Bun 1.3.14) under `fixtures/nativeperf/`. Measured on WSL2 6.6.87.2 amd64 only: CPU hot function in real callchains, frame coverage with and without frame pointers, injected loss/FD/memory limits, privacy canaries on the socket, and a full 120 s x 5 overhead run (-0.34% +- 0.57% workload CPU, 4.6% of one core collector, about 36 MiB combined memory for the single-thread fixture). Not qualified: scheduler off-CPU/runqueue rows (non-initial PID namespace), every other kernel/arch, other runtime versions.

Engine fixes found by the fixtures: the scheduler path now refuses (and `Probe` no longer reports) support outside the initial PID namespace instead of yielding an empty successful session; identity resolution of a target the caller may not inspect now reports `permission_denied` instead of `generation_changed`.

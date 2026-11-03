<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Native Linux profiling changes

## 2026-11-03 — Task04.01

Added closed numeric event contracts, explicit clock/generation/unit validation, bounded configuration, capability probes and unsupported-platform errors. Qualification starts at `not_run`; probe success does not assert sample acquisition, coverage or measured overhead. Linux session acquisition remains dependent on tasks04.02/03. No customer system access, privilege changes or publication are included.

Review corrections: canonical C01 decimal round trips, nullable authorized scheduler participants, optional switch-out callchains, process-scoped mappings and CPU-scoped loss without invented thread keys. Native samples carry method/period units, actual period, requested rate, typed context markers and distinct loss/throttle evidence. Resource/identity refusals are classifiable; capabilities and intervals validate coverage/domain/unit invariants. These contract corrections do not qualify acquisition or overhead.

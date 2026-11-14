<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Overhead budgets and measured status

Limits are pinned in `qualification/workloads.yaml` from design section 13 and are never adjusted by the code that compares against them. A missed budget is a measured failure that blocks the claim (`qualify --suite overhead` exits 1).

| Budget | Limit | Status (qualification run, shared WSL2/Windows host) |
|---|---|---|
| Server SDK p95 latency, core capture | <=5% | **FAILED**. Judged on delivered mode (flush() every 100 ms through an in-process ACKing receipt transport, 0 queue_full drops), Linux 6.1 2 vCPU KVM VM, 5 alternating runs: Node 22 +351% (3-hash) / +283% (100-hash), Node 24 +44% / +231%. Saturated mode (never flushed, spans dropped once the queue fills; not judged): Node 22 +103% / +243%, Node 24 +8% / +384%. The 100-hash p95 is GC-dominated (SDK load grows V8's young generation); see `.superpowers/sdd/approved-product/11.17-report.md` |
| Server SDK CPU per request | <=5% | **FAILED**. Delivered mode, same run: Node 22 +101% (3-hash, 204 -> 410 us) / +39% (100-hash), Node 24 +94% (153 -> 298 us) / +30%. Saturated mode (not judged): Node 22 +28% / +14%, Node 24 +30% / +18%. Before 11.17 (saturated): +253% / +127% and +268% / +137% |
| SDK queue | <=2 MiB | met (881,686 B acking and stalled) |
| Browser core gzip | <=40 KiB | met after 11.13: 36,411 B for the `@soundpost/browser` core entry (replay and profile are separate entries) |
| Browser replay gzip | <=60 KiB | met (5,882 B) |
| Recorder p95 per mutation batch | <=5 ms | not exercised (no harness) |
| Native CPU overhead per target | <=3% | met on the full run, WSL2 functional row, cpu fixture only (`overhead --hz 99 --seconds 120 --repeats 5`, `fixtures/nativeperf/qualification.json` `overhead_full_run`): workload CPU overhead -0.34% (stderr 0.57%), throughput change 0.37%; the collector itself used 4.57% of one core. The earlier reduced 20 s x 3 run (about 0.2%) is superseded |
| Native memory | <=64 MiB | met, 38,182,912 B (about 36 MiB) combined maximum in the same full run |
| Python / Bun core capture | <=5% | not exercised (no workload) |
| Native blocked/runqueue workload | <=3% | not exercised (scheduler, no harness) |
| Single-host, distributed, queries | section 13 table | not exercised (no fixture hosts/1 h runs) |

Server numbers use a synthetic loopback handler, 5 alternating runs of 3 s at 1000 req/s; raw series and requested/observed intervals are in the report JSON. Other jobs ran on the host. Linux arm64, Node 24 and Python rows are not exercised.

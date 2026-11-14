<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Overhead budgets and measured status

Limits are pinned in `qualification/workloads.yaml` from design section 13 and are never adjusted by the code that compares against them. A missed budget is a measured failure that blocks the claim (`qualify --suite overhead` exits 1).

| Budget | Limit | Status (qualification run, shared WSL2/Windows host) |
|---|---|---|
| Server SDK p95 latency, core capture | <=5% | **FAILED**: after 11.17 on the Linux 6.1 2 vCPU VM, Node 22 +26% (3-hash) / +299% (100-hash), Node 24 +10% / +298%; the 100-hash p95 is GC-dominated (SDK load grows V8's young generation), see `.superpowers/sdd/approved-product/11.17-report.md`. Earlier: Node 22 Linux +69% / +79%; Windows +182%/+101% |
| Server SDK CPU per request | <=5% | **FAILED**: after 11.17 on the same VM (queue saturated, fixture never flushes), Node 22 +26% (3-hash) / +15% (100-hash), Node 24 +27% / +12% (before: +253% / +127% and +268% / +137%). Earlier: Node 22 Linux +219%/+129%; Windows +384%/+126% |
| SDK queue | <=2 MiB | met (881,686 B acking and stalled) |
| Browser core gzip | <=40 KiB | **FAILED**: 46,570 B (index re-exports replay; no core-only entry) |
| Browser replay gzip | <=60 KiB | met (5,882 B) |
| Recorder p95 per mutation batch | <=5 ms | not exercised (no harness) |
| Native CPU overhead per target | <=3% | met on the full run, WSL2 functional row, cpu fixture only (`overhead --hz 99 --seconds 120 --repeats 5`, `fixtures/nativeperf/qualification.json` `overhead_full_run`): workload CPU overhead -0.34% (stderr 0.57%), throughput change 0.37%; the collector itself used 4.57% of one core. The earlier reduced 20 s x 3 run (about 0.2%) is superseded |
| Native memory | <=64 MiB | met, 38,182,912 B (about 36 MiB) combined maximum in the same full run |
| Python / Bun core capture | <=5% | not exercised (no workload) |
| Native blocked/runqueue workload | <=3% | not exercised (scheduler, no harness) |
| Single-host, distributed, queries | section 13 table | not exercised (no fixture hosts/1 h runs) |

Server numbers use a synthetic loopback handler, 5 alternating runs of 3 s at 1000 req/s; raw series and requested/observed intervals are in the report JSON. Other jobs ran on the host. Linux arm64, Node 24 and Python rows are not exercised.

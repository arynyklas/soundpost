<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Query admission and storage scan slots

Concurrency of the query service is limited in one place, the admission scheduler (`internal/query/scheduler.go`).
Everything below it is sized so that an admitted query never fails for lack of a lower-level resource.

## Admission limits (shipped defaults)

| Limit | Default | Meaning |
|---|---|---|
| `MaxConcurrent` | 16 | queries running at once, process-wide |
| `MaxPerOrg` | 8 | running queries of one organization |
| `MaxPerPrincipal` | 4 | running queries of one principal |
| `MaxQueuedPerOrg` | 16 | waiting queries of one organization; one more is refused `quota` (HTTP 429) |
| `MaxQueueWait` | 10 s | longest wait for admission; then `timeout` |
| `GlobalMemory` | 1 GiB | accounted working memory of every running query together; a charge over it is `quota` |

Why 16/8/4 and not 8/4/2: the Queries gate row runs 10 interactive queries at once. With 8 running, the ninth and
tenth always waited behind the long 24 h queries, and the wait was the p95 of every short class. Measured on the
gate mix (10 workers, 240 s, 8 CPUs, one principal per organization, requests spread over 10 organizations):
1,181 of 2,305 queries queued (51 %); the limit that blocked them was the global one for 1,002 and the principal
one for 343 (a query counts once per limit that blocked it; the organization limit never did); queue wait summed
to 555 s with a longest wait of 6.1 s, while the execution p95 of promql_instant, logql_lines, promql_range_1h
and logql_rate_6h was 99, 124, 174 and 278 ms. Queueing does not make a saturated CPU faster, it only makes the
short queries wait for the long ones; the Go scheduler shares the CPUs among running queries. The resource that
has to be bounded on a node is memory, and `GlobalMemory` bounds it whatever the number of running queries (peak
298 MB in that mix against 1 GiB). The limits stay operator-configurable (`Limits`), and the per-organization and
per-principal limits keep one tenant from taking all slots.

Counters of the queue (`Usage().Admission`, and `query_admission` in the diagnostic build's endpoint): admitted,
queued, blocked by the global, organization and principal limit, refused for a full queue, timed out, cancelled,
queue wait sum and maximum. Every response also carries `stats.queue_wait_ns` per project (the wait for admission,
which `stats.elapsed_ns` does not include).

## Storage scan slots (D105)

`storage.Engine.Scan` takes one slot of a pool of `storage.ScanSlots` (2048) for the life of the iterator and
`Subscribe` takes one of a separate pool of `storage.LiveSlots` (32). A caller that finds the pool empty waits, in
arrival order, until its context ends (the query deadline), and is then answered `cancelled` or `timeout` like any
other wait. `too_large` is only the answer to a request that is too large by itself. The wait is made before the
engine lock is taken, so a waiting scan never holds `e.mu`; the iterator returns its slot exactly once, in
`closeLocked`, which every close, cancel and failure path reaches; an early return of `Scan` or `Subscribe` returns
the slot it took.

Bound: an admitted query selects at most `MaxProjects` (128) projects and holds at most one iterator per selected
project, so the pool must hold `MaxConcurrent x MaxProjects` = 16 x 128 = 2048 iterators. `Limits.validate`
refuses limits whose product is larger than `storage.ScanSlots`. Live subscriptions never share the scan pool: the
live service admits at most 24 streams (`MaxStreams`), `LiveSlots` is 32, and a full set of tails therefore cannot
starve an interactive scan, nor a burst of scans a tail.

## Query memory accounting

Each query's account charges the process-wide pool in grains of 2 KiB instead of on every sample (a
compare-and-swap on one shared counter was 6 % of the CPU of the gate mix). An account holds at most two grains
beyond what it has handed out, returns the surplus on release and everything on finish, and never holds more than its
per-query limit; a pool that cannot spare a grain is charged exactly what is needed. The per-query limit and the
pool limit are enforced as before; the slack is at most two grains per running query (64 KiB for 16 queries).

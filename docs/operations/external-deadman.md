# External deadman

Copyright 2026 Aryn Yklas. SPDX-License-Identifier: Apache-2.0.

The deadman is the thing that tells a human the notification system itself is
down. It is **never an in-process Soundpost rule**: a product that has stopped
cannot report that it stopped. It is a separately operated observer, with its own
credentials, its own storage, its own schedule and its own path to a destination
a person reads. This page defines what the observer polls, what it concludes,
what the product does and does not guarantee about it, and what the acceptance
fixture in this repository does and does not prove.

## The independence claim this repository does NOT make

The observer in `tests/acceptance/observer` is a separate operating-system
process with its own state directory and credentials, and the acceptance test
keeps it running while the product, its notification worker and its node are
stopped. **It runs on the same host as the product.** A host, hypervisor, power,
network or storage failure takes both down. Therefore:

> The independence of the failure domain is **not demonstrated** by this fixture.
> It demonstrates a mechanism (a separate process with separate state and
> credentials keeps detecting and delivering while the product is stopped), not a
> separate failure domain.

A real deployment must provision, and an operator must evidence, all of:

1. **A separately provisioned host** (different physical machine, and where one
   exists a different hypervisor, rack or availability zone) that shares no disk,
   power feed or scheduler with any product node.
2. **A separate network path**: its own uplink, DNS and routing to the product's
   heartbeat endpoints and to the alert destination. The alert must not pass
   through the product, its ingress or its egress allowlist.
3. **Separate credentials**: a poll credential that can read the heartbeat
   endpoints only (a read-scoped service credential issued to the observer, not an
   administrator's) and a delivery credential for the destination that the product
   does not hold. Neither is stored in product control state.
4. **A separate execution and schedule**: its own supervisor or scheduler, not the
   product's cluster, cron or orchestrator, and its own clock source.
5. **An authorized destination** the observer is explicitly allowlisted for, read
   by a human who is not depending on the product to be told (a pager or an
   independent chat or mail route).
6. **Its own liveness watched by something else.** Nothing in this product
   detects that the observer died: see *Unknown observer state*.

Until those are provisioned and evidenced, the customer-facing statement is
"deadman mechanism qualified in a same-host fixture; independent deployment not
yet provisioned". Real SMTP, Telegram and webhook third parties are **not**
contacted by this feature's tests: the destination is a loopback receiver the
observer was allowlisted for with a test-only flag (`-test-allow-loopback`), and the
observer refuses to start for a destination that is not on its allowlist or that is a
local address without that flag.

## Heartbeat semantics

The observer polls three components separately; each can fail alone, and a failure
of one never implies anything about the others.

| Component | A healthy heartbeat means | A missing heartbeat means |
| --- | --- | --- |
| `product` | the product process is up and the control group answered a quorum round now (it can commit and read control state) | the product, its control quorum or the path to it is not answering |
| `ingest` | a canary sample was **admitted through the same C03 admission path sources use and acknowledged durably** (a receipt), now | telemetry would not be durably accepted: ingest is down, refused or saturated, even if the product is up |
| `notification` | the notification worker **completed a pass recently** (it claims, sends and completes, and leases are not stuck) | no notification would be sent: the worker is dead, wedged or fenced, even if the product is up and telemetry is accepted |

The contract the observer relies on: `GET <url>` with
`Authorization: Bearer <poll credential>` answers `200` with a JSON body
`{"component":"<name>","ok":true,"seq":<n>,"at_ns":<t>}`. Anything else (another
status, a timeout, a refused connection, a malformed body, the wrong component
name) is **no heartbeat**. `seq` increases, so a replayed or cached answer is
distinguishable from a live one. The acceptance fixture serves exactly these three
from the real node (`tests/acceptance/notification_outage_test.go`); the product's
own readiness endpoints are the distribution work's and must satisfy the same
contract before an operator points an observer at them.

A component is **missing** when no healthy heartbeat arrived for the configured
`missing-after` (default one second in the fixture; an operator chooses it from the
product's own cadence plus margin). A component never seen healthy is
**unknown**, not missing, until `missing-after` has passed since the observer
started, and then it is declared missing with `never_seen`.

## What the observer does

For each component, once per `interval`: poll; track the last healthy time; on the
transition to missing open **one** outage (identity, last healthy time, detection
time); deliver one alert per outage with a stable idempotency key, retrying on a
bounded budget (each attempt is recorded with its time and its status code or closed
error class, never a response body); when the heartbeat returns, record the
recovery and deliver **one** recovery notice, which is not an emergency. State is
written atomically (write, fsync, rename) every cycle and every attempt is appended
to an append-only log. A restarted observer, including after a hard kill, reloads
its state and repeats nothing that was already accepted.

Observed in the fixture (loopback, `interval` 200 ms, `missing-after` 1.5 s): with the
whole product stopped, all three components were detected 1.6 s after their last
healthy heartbeat, never before the stop (no false alarm while healthy); the first
delivery attempt, which the destination refused with 503, stayed in the record next to
the accepted retry; after the product restarted each outage was closed with exactly one
recovery notice and no second alert; a SIGKILLed and restarted observer kept its
record and repeated no notice.

## Recovery: what is and is not announced

* **The outage and its failed attempts are never erased.** They are in the observer's
  record, and an outage that has recovered stays an outage with a recovery time.
* **The product's own backlog is not re-announced as new emergencies.** A delivery
  committed before the outage is sent after it under its **original** delivery ID within
  its normal budget (the outbox's at-least-once contract: see
  [delivery semantics](delivery-semantics.md)); no new delivery or ID is invented for
  the outage. Evidence that merely arrives late (a window that closed more than ten
  minutes before it is decided) or as a backfill is recorded as late history and
  announces nothing. Only an explicit `operator_replay` is processed as live.
* The observer's recovery notice is one message per outage, labelled as a recovery.

## Unknown observer state

The product never knows continuously whether the observer is alive. It knows only what
it is shown. The cutover barrier requires an **independent observer proof**: the observer,
the failure domain asserted for it and for the product, and when the observer last proved
itself armed. The product refuses the barrier when the proof is absent (an **unknown
observer state**), when it is older than fifteen minutes, when it is dated in the future,
when the two asserted domains are equal, or when the observer is one of the owners. In the
acceptance run the observer's own last completed cycle is the proof: accepted while it
runs, refused once it was killed and its proof went stale.

This is a point-in-time check at a barrier, not continuous monitoring. **Who watches the
observer** is an operator prerequisite (a second, independent check, or a human routine,
on the observer's own liveness). The failure domains in the evidence are asserted by the
operator flow and recorded; the product checks only that they differ. In the fixture the
domain labels are the fixture's own assertion because it cannot truthfully claim
independence, and the test shows the product refusing the barrier when the truthful
same-host domain is stated.

## Running the fixture

```
go test ./tests/acceptance -run 'TestNotificationCutover|TestNotificationOutage|TestConcurrentIncidentDelivery' -count=1
```

`TestNotificationOutage` builds `tests/acceptance/observer` with the toolchain that runs
the tests and starts it as a subprocess, so it needs a Go toolchain at test time and
loopback networking. It contacts no external host.

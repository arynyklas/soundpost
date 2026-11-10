# External deadman observer: how to run it independently

Copyright 2026 Aryn Yklas. SPDX-License-Identifier: Apache-2.0.

The deadman tells a human that the notification system itself is down, so it can never be an
in-process Soundpost rule. The observer program is `tests/acceptance/observer` (06.09). This
directory is the recipe for building and running **that same program** as a separately provisioned
process; it is not a fork and not a copy. The failure drill `external-deadman`
(`go run ./tools/drills --scenario external-deadman --target isolated --report DIR`) builds and runs
it the same way and shows what the mechanism does while every Soundpost component is stopped.

> **What this host cannot show.** On a single machine the observer is a separate operating-system
> process with its own state directory, poll credential and delivery credential. That shows the
> *mechanism*: it keeps detecting and delivering while the product is stopped. It does **not** show
> failure-domain independence. A host, hypervisor, power, network or storage failure that stops the
> product stops an observer on the same host too, and nothing run from this repository can prove
> otherwise. Independence exists only where the observer runs on separately provisioned
> infrastructure, and has to be evidenced there (see "Provisioning" below). The drill therefore
> records `failure-domain independence` as **not run** in every report.

## Files

| File | What it is |
| --- | --- |
| `run-observer.sh` | POSIX `sh` launcher: validates the settings, builds the observer if asked to, starts it with only its own two credentials. `--check` validates and prints the command with the credentials redacted. |
| `observer.env.example` | The settings, with obviously fake credentials. Copy to `observer.env`, edit, `chmod 600`. |

## The observer

It polls heartbeat endpoints, declares a component **missing** when no healthy heartbeat arrived for
`-missing-after`, opens one outage per missing component, delivers one alert per outage to an
authorized destination (idempotency key `<outage>-alert`, bounded retries, every attempt recorded
with its time and status or closed error class), and after the heartbeat returns delivers one
recovery notice. It imports nothing of the product and shares only the heartbeat contract:

`GET <url>` with `Authorization: Bearer <poll credential>` answers `200` and
`{"component":"<name>","ok":true,"seq":N,"at_ns":T}` when the component works; anything else
(another status, a timeout, a refused connection, a malformed body, the wrong component name) is no
heartbeat. The contract and the three components (`product`, `ingest`, `notification`) are defined in
[`docs/operations/external-deadman.md`](../../../docs/operations/external-deadman.md).

Flags (`go run ./tests/acceptance/observer -h`):

| Flag | Meaning |
| --- | --- |
| `-state DIR` | the observer's own storage: `state.json` (atomic, fsynced every cycle) and `attempts.jsonl` (append-only) |
| `-id NAME` | identity; a state directory belongs to one identity |
| `-poll name=url,...` | heartbeat endpoints |
| `-interval`, `-missing-after`, `-timeout` | poll interval, missing threshold, per-request timeout |
| `-destination URL` | where notices are delivered |
| `-authorized-destination host:port,...` | the only hosts it may deliver to; anything else is refused at start |
| `-test-allow-loopback` | **test only**: permit a loopback or private destination |
| `-max-attempts N` | delivery attempts per notice |

Credentials come **only** from the environment, `OBSERVER_POLL_TOKEN` and
`OBSERVER_DELIVERY_TOKEN`, never from arguments, and are never logged or stored.

## Recipe

1. **Provision a separate host** (see below). Install a Go toolchain there only to build, or build on
   a build machine and copy the binary.
2. **Build the observer** from a checkout of this repository at the release being run:
   `go build -o observer ./tests/acceptance/observer`
3. **Create its own credentials.** The *poll credential* is a read-scoped service credential issued
   to the observer that can read the heartbeat endpoints only, not an administrator's. The *delivery
   credential* is for the destination; the product must not hold it. Two different values, neither
   stored in product control state.
4. **Write its settings**: `cp observer.env.example observer.env; chmod 600 observer.env` and edit.
   `OBSERVER_STATE_DIR` must be a local directory that the product does not use.
5. **Check, then run**: `./run-observer.sh --check observer.env` and then
   `OBSERVER_BIN=./observer ./run-observer.sh observer.env`. The script refuses a settings file other
   accounts can read, a placeholder or shared credential, a relative state directory and one inside a
   product directory. The observer starts with `env -i`: only `PATH` and its two credentials.
6. **Run it under its own supervisor** (a systemd unit on that host, with `Restart=always`), not
   under the product's orchestrator.
7. **Prove it before relying on it.** Stop the product's heartbeats and see an alert arrive at the
   destination; start them and see exactly one recovery notice. A hard kill of the observer and a
   restart must keep `state.json` and repeat no notice that was already accepted.

## Provisioning an independent failure domain (operator prerequisites)

None of these can be demonstrated on the host that runs the product:

1. a separately provisioned host sharing no disk, power feed or scheduler with any product node,
   and where one exists a different hypervisor, rack or availability zone;
2. its own network path, DNS and routing to the heartbeats and to the destination; the alert must
   not pass through the product, its ingress or its egress allowlist;
3. its own credentials (above);
4. its own supervisor, schedule and clock source;
5. an authorized destination read by a human who does not depend on the product to be told;
6. its own liveness watched by something else: nothing in the product detects that the observer
   died, so **who watches the observer** is an operator routine.

Until all of that is evidenced the honest statement is: *deadman mechanism qualified in a same-host
fixture; independent deployment not yet provisioned.*

## What the drill checks with this observer

With the observer running as a separate process, the drill stops the product's heartbeat endpoints,
its notification worker and its node, and requires: the observer detects each missing heartbeat
within its schedule and never before the stop; it delivers an alert per component to a loopback
destination **while every product component is still stopped**; the destination's first refusal
(503) stays in the record next to the accepted retry; after the product restarts each outage is closed
with one recovery notice and no second alert, no outage or attempt is erased, a hard-killed and
restarted observer repeats nothing, and the product's pre-outage delivery is sent once under its
original id with late evidence announcing nothing. No real SMTP, Telegram or webhook destination is
contacted.

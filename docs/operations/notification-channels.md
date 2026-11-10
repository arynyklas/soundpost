# Notification channels: SMTP, Telegram and signed webhooks

Copyright 2026 Aryn Yklas. SPDX-License-Identifier: Apache-2.0.

These are the real delivery adapters behind the `notify.Sender` seam of the
durable outbox (see [delivery semantics](delivery-semantics.md)). The code is
`internal/notify/providers/{provider,smtp,telegram,webhook}.go` and the
destination registry `internal/notify/destinations.go`. The notification worker
does not import the providers package; the application composition binds them.

## Destinations and secrets

* A destination is organization-owned configuration (`destination:<id>` in the
  control group: type, https endpoint or address, enabled) plus an optional
  sealed secret. The destination ID is the delivery's recipient ID. A delivery
  has typed fields only, so nothing from telemetry (no chat, token, URL, host or
  address) can select where a notification goes. A recipient that is not a
  configured destination of the delivery's organization, a disabled one, or one
  of another channel sends nothing and is a visible failure (`no_destination`,
  `destination_disabled`).
* The registry (`notify.Destinations`) is org-scoped at every step: the scope,
  the delivery and the destination must be the same organization. It is looked up
  fresh at every attempt, so removal, disabling and rotation take effect at the
  next attempt.
* Secrets are the control store's AES-256-GCM envelope-encrypted values (separately
  restricted key file or KMS, rotation by key ID, plaintext never logged). The
  sender gets one through the narrow `notify.SecretReader` and the registry only
  releases the secret of a destination configured in the caller's organization:
  a reference to another organization's secret, to an unknown destination and to
  a destination without a secret all fail with the same `forbidden` fault, before
  the sealed store is touched. A reader failure is reduced to `unavailable`.
  The secret is held for one attempt and zeroed. It is never part of an outcome,
  the outbox, an audit entry, a log line, a DTO (`Destination` prints, marshals
  and logs only a redacted view: id, channel, host or domain, "has secret") or a
  rendered notification.
* Rendered notifications are the approved template only: typed enums, counts, the
  delivery ID and a link built from the configured public https origin
  (`<origin>/<incidents|issues|conditions>/<id>`). No log, error message, source,
  replay or profile text exists in a delivery, so none can be pasted outward.

## Egress

All connections (SMTP, Telegram, webhook) use one dialer. It resolves the host,
refuses the **whole name** if any answer is blocked, then dials the checked
address itself, and the socket `Control` hook checks the address the kernel is
about to connect to once more, so DNS rebinding between a check and the connect
cannot reach a blocked address. A blocked attempt makes no connection and is a
terminal `egress_blocked`.

Blocked by default: loopback, RFC 1918 private, link-local (including
169.254.169.254), unique-local (fc00::/7), CGNAT (100.64.0.0/10), multicast,
unspecified, broadcast/reserved, documentation and benchmark ranges, known cloud
metadata addresses (169.254.169.254, fd00:ec2::254, 100.100.100.200,
168.63.129.16, 192.0.0.192), and IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible,
NAT64 and 6to4 IPv6 forms. Zoned addresses are refused.

* An operator can lift the block for explicit **private** prefixes
  (`EgressPolicy.AllowPrefixes`, for example an internal relay). Loopback,
  link-local, multicast, unspecified and metadata ranges can never be allow-listed;
  such an entry fails construction.
* `EgressPolicy.OrgHosts` narrows an organization to exact host names.
* Webhook and Telegram require https; plain `http` endpoints are invalid
  destinations. SMTP requires TLS (below). Certificate verification cannot be
  disabled, TLS 1.2 is the minimum, and proxies are ignored.
* Redirects are never followed: the response is a terminal `redirect_refused` and
  the redirect target is never contacted.
* A `*http.Client` handed to a constructor contributes only its timeout and TLS
  roots; its dialer, proxy and redirect policy are replaced.
* Responses are bounded (64 KiB HTTP body, 32 KiB headers, 256 KiB SMTP replies)
  and every attempt has a timeout.
* Tests reach loopback servers through an unexported field of `EgressPolicy` that
  is assigned only in `_test.go` files. It is not reachable from configuration or
  the wire, and a test proves the production constructors and senders refuse
  loopback.

## Outcomes

| Situation | Outcome |
| --- | --- |
| Connection refused, DNS failure, TLS failure or connect timeout before any request byte | `retry` (definite) |
| Timeout, reset or EOF **after** the request may have been written (HTTP: after the connection was established; SMTP: after the end-of-data line was written) | `unknown` (possible acceptance) |
| HTTP 5xx / 408 | `retry`, with `Retry-After` |
| HTTP 429 / 503 | `retry`, honouring `Retry-After` (seconds or date, capped at 24 h) |
| HTTP 4xx (other) | `terminal` |
| 3xx | `terminal` `redirect_refused` |
| Egress blocked, destination invalid, missing/forbidden secret | `terminal` |

Provider-specific:

* **SMTP**: implicit TLS (465) or STARTTLS (587); there is no plaintext mode. With
  STARTTLS a server that does not offer it is a `retry` (`starttls_unavailable`):
  nothing is authenticated or submitted. `AUTH PLAIN` is sent only after TLS is
  established. `250` after the data is `accepted` with the relay's queue ID
  (`queued as <id>`, or `id=<id>`); a `250` without a queue ID is accepted with
  `smtp-250:<delivery id>` (the relay's `250` is the evidence). This is queued by
  the relay, never proof that the recipient read it. 4xx is `retry`, 5xx
  `terminal`, `535` is `terminal` `auth_failed`. The Message-ID is derived from the
  delivery ID so a duplicate after an unknown attempt is recognizable.
* **Telegram** (HTTPS Bot API `sendMessage`, plain text, no markup mode): `ok:true`
  with a `message_id` is `accepted` with that ID (not proof a human saw it); `429`
  is `retry` with `parameters.retry_after`; other 4xx is `terminal`; 5xx `retry`; a
  2xx that does not parse as an acceptance is `unknown`. The bot token is part of
  the request URL, so no transport error text is ever kept.
* **Webhook**: any 2xx is `accepted` with the receipt (`Soundpost-Receipt-ID` if the
  receiver sends one, else `webhook-<status>:<delivery id>`): the receiver took the
  notification, nothing says remediation ran.

## Signed webhook (version 1)

```
POST <endpoint>        Content-Type: application/json
Soundpost-Delivery-ID: <stable delivery id (hex)>
Soundpost-Timestamp:   <unix seconds of this attempt>
Soundpost-Signature:   v1=<hex HMAC-SHA256(secret, "<ts>.<delivery-id>.<exact body bytes>")>
```

Body: `version` (1), `delivery_id`, `event_kind`, `org_id`, `entity {kind,id}`,
`impact_revision`, `ordinal`, `impact` (the typed template: tier, severity,
source state, freshness, human status, acknowledged, count/rate explanation,
service, reminder/queue numbers) and `link` (configured public origin).

* The body is a pure function of the delivery, so **a retry sends the exact same
  bytes and the same delivery ID**. Only the timestamp and therefore the signature
  change, so a delivery retried for hours still satisfies the receiver's window.
* The per-attempt timestamp is persisted outside the deterministic control apply
  through the narrow `AttemptStamper` seam: it must be idempotent per
  `(delivery, attempt)` (a crash and re-send of the same claim reuses it) and a new
  attempt gets a fresh value. If it cannot be read nothing is sent (`retry`,
  `timestamp_unavailable`).
* **Receiver rules** (`providers.Receiver` is the reference implementation): verify
  the signature over the exact raw body, accept only a timestamp within **5
  minutes** of the receiver clock, check that the body names the signed delivery
  ID, then deduplicate by delivery ID (remembered for longer than the 24 hour retry
  budget), independently of signature freshness. A duplicate with a valid fresh
  signature is acknowledged with 2xx and not acted on again. Signing secrets are at
  least 16 bytes.

## What is verified, and what is not

`internal/notify/providers/providers_test.go` runs a real SMTP protocol server
(implicit TLS and STARTTLS, AUTH PLAIN, DATA, queue IDs, 4xx/5xx, silence and
connection drop after the data) and real HTTPS servers (webhook and Telegram Bot
API shapes) on loopback with a private test CA, and verifies the egress cases
above. `internal/notify/destinations_test.go` covers the registry. No real
Telegram account, public SMTP relay or third-party receiver has been called: the
`TestProvidersRealAcceptance` smoke needs a separately authorized disposable
chat and secret supplied through the test environment and has not been run.

Not built here: HTTP routes for destination administration, the application
wiring (a `DestinationSource` over control state, a `SecretReader` over the control
store's `OpenSecret`, and an `AttemptStamper` persisting attempt timestamps), and
the public web routes the links point at.

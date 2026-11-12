<!-- Copyright 2026 Aryn Yklas -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Source policies for host, log and scrape collection

A collector only exports what an installation's **source policy** allows. The
installation holds the authoritative `model.SourcePolicy` for each source
(project, kinds, registered log templates, allowed label values, resource
registry, retention, restricted-raw grant). The agent holds a **local copy of
what it needs to filter before it exports**; the server validates every record
again at admission, and a mismatch is a typed refusal, not a silent drop.

## What the installation's source policy must contain for the agent

| Policy field | Value for a host and log agent |
| --- | --- |
| `Kinds` | `metric` (host metrics), `log` (log sources), `capability` (host groups and log sources), `loss` (gaps and lost host batches). A kind not listed is forbidden at admission |
| `Class` | `structured`. `restricted_raw` only for an explicitly approved raw source (see below) |
| `Templates` | every registered log template revision the agent may export (id, revision, line, severity, typed fields with approved values) |
| `Resources` | the service, environment and build ids and the instance pseudonym the agent is configured with |
| `Labels` | host metric label values (`mode`, `state`, `window`, `mount` - see `host.md`) and the stream label values of each log source (for example `source`) |
| `RetentionDays`, `MaxBytes`, `MaxSeries` | per the installation; host metrics add one series per mode/state/alias |

The agent's top-level configuration carries `org`, `project`, `source`,
`policy_revision` and the resource ids. A revision that no longer matches the
installation's is refused (`stale`), and the agent reports the failure instead
of exporting under an old policy.

## Log source policy (`sources.SourcePolicy`)

| Field | Meaning |
| --- | --- |
| `name` | operator alias `^[a-z][a-z0-9_-]{0,47}$`: checkpoint file name, capability method suffix, log label. Never a path |
| `kind` | `file`, `syslog` or `journal` (exactly the matching spec is set) |
| `class` | `structured` (default) or `restricted_raw` |
| `stream_labels` | sorted, unique labels attached to every record; each value must be allowed by the installation's `Labels` |
| `templates` | the registered `model.LogTemplate` revisions; each template line is also the message pattern |
| `raw` | only for `restricted_raw`: `owner`, `rationale` (at most 512 bytes), `expires_ns`, `max_bytes` (1..65536) |
| `max_records` | per read, 1..512, default 256 |
| `max_line_bytes` | 64..65536, default 8192; a longer line is counted and skipped |
| `file` / `syslog` / `journal` | the adapter spec (absolute paths; approved tags; approved identifiers and units) |

`SourcePolicy.Validate` runs `model.ValidateSourcePolicy` over the local copy,
so a malformed template, a placeholder with no declared field, a structured
source with a raw field or a raw source with a retention over 7 days is refused
before any source byte is read. Unknown-by-default rules:

- a journal source needs at least one approved identifier or unit; a syslog
  source needs at least one approved tag; there is no "everything" source;
- a template that matches nothing is not an error, a line that matches nothing
  is dropped and counted;
- permission or presence failures are capabilities, not empty sources.

## Restricted raw sources

A raw source needs, in both the installation's policy and the agent's local
policy: a named owner, a rationale, an expiry, a maximum size and a template
whose field has sensitivity `restricted_raw` (no approved value list). Retention
for a raw source is at most 7 days and only for `log`, `capability` and `loss`
kinds (enforced by `model.ValidateSourcePolicy`). Reading raw text additionally
needs the named-source reader grant on the read side. The agent stops reading
at expiry. Raw text appears in the export queue only; it is never written to the
agent's state directory.

## Scrape targets (`sources.ScrapeTarget`)

OpenMetrics scraping is acquisition for existing sources. A target is **local
operator configuration**, never a URL taken from telemetry:

| Field | Meaning |
| --- | --- |
| `alias` | the only identifier in results and health |
| `url` | absolute `http` or `https` URL without userinfo or fragment |
| `interval`, `timeout` | interval at least 1 s; `0 < timeout <= interval` bounds the whole exchange |
| `max_bytes` | response cap, 1 B..64 MiB; exceeding it is a failure, never a truncated admission |
| `tls` | trust roots and server name; TLS 1.2 minimum; verification can not be disabled |
| `egress` | allowed private prefixes and a resolver |
| `auth`, `secret` | `bearer` or `basic` and a **secret reference** read fresh for every fetch through a local `SecretReader`; the bytes are zeroed after the header is built and never appear in a result, error or log |
| `profile` | the plan 02 `queryinput.InputProfile` (limits, name mode, out-of-order, histograms, exemplars, help) |
| `stale` | `on_disappear` and `on_failure` stale marker policy |

Egress follows the notification providers' discipline (mirrored, not imported:
the providers' dialer is private): the name is resolved, **any** blocked answer
refuses the whole name, the validated literal address is dialed, and the
address the socket is about to connect to is checked again (rebinding).
Loopback, link-local, multicast, unspecified, cloud-metadata and translated
forms are never allowed; private ranges are blocked unless the operator lists
the exact prefix. A literal-IP target is checked before any dial. Redirects are
never followed and the redirect target is never requested; there is no proxy.

Result semantics: a runtime failure (timeout, reset, refusal, egress denial,
bad status, wrong content type, oversize, undecodable body, missing secret) is
a typed health status with coverage `unknown`, not an error and not a zero;
`on_failure` additionally marks the previous series stale at the failure time,
`on_disappear` marks series that vanished from a successful scrape. Batch and
record identifiers bind the target alias and the scrape time (the decoder's own
identifiers derive from the body only, which would make two scrapes of an
unchanged exporter one conflicting admission), so a retry of one scrape is
idempotent and two scrapes are distinct.

**Where scraping runs:** `FetchScrape` needs a `policy.SourceGrant`, which only
the installation's authority can issue. A scrape therefore runs inside the node:
`soundpost serve --scrape-config PATH --scrape-secrets-dir DIR` starts one
`sources.Scraper` per configured target (`sources.StartScrapeHost`, started by
`cmd/soundpost` after the node opens and closed before storage closes). Each
attempt resolves a fresh grant from a **source credential the operator provisioned
through the existing owner path** and stored in the secrets directory
(`AuthenticateSource`, then `ingest.Service.ResolveSource` for the configured
project, source and policy revision), admits through `ingest.Service.Admit`, the
same service the HTTP ingest route calls, and carries the stale-marker state
forward only after every batch has its receipt. The node holds no identity of its
own: revoking or expiring the source stops admission, typed (`grant_denied`). The
remote `soundpost-agent` does **not** scrape.

The configuration file (closed JSON, unknown fields refused), the secrets
directory (a private directory of `0600` files named by reference; no traversal, no
symbolic links, read fresh per fetch, never cached or logged), the flags, the
startup reason codes and the per-target health reasons are in
`docs/operations/scraping.md`. Loopback targets can not be scraped by the node
(the egress rule above has no loopback exception); the `ScrapeTarget` loopback
allowance exists only in this package's own tests.

<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->

# OpenMetrics scraping: `soundpost serve --scrape-config`

`soundpost serve` can scrape OpenMetrics endpoints that the operator approved in a
private file. Scraping runs **inside the node**: the node resolves a policy grant,
which only the installation's authority can issue, so the remote
`soundpost-agent` does not scrape. A scraped batch is admitted through exactly the
service the HTTP ingest route uses (`ingest.Service.ResolveSource` then `Admit`), so
source policy, quota, fencing and the durable receipt apply unchanged. The target
semantics (egress, TLS, size cap, stale markers, closed health statuses) are in
`docs/collection/source-policies.md`, "Scrape targets".

## Flags

| Flag | Meaning |
| --- | --- |
| `--scrape-config PATH` | Private JSON listing the approved targets. A regular file that is **not group- or world-writable** (create it `0600`; the same rule as `--symbolicate-config`). The file holds no secret, only secret *references*. Unknown fields, trailing data, an unknown version, no targets, a duplicate alias or any invalid target refuse startup. |
| `--scrape-secrets-dir DIR` | Private directory of secrets, referenced by name from the configuration. The directory must be a real directory (not a symbolic link) with no group or world access (`0700`). Required together with `--scrape-config`; giving only one of them is a startup error. |

Neither flag: nothing is scraped and nothing changes.

Startup validates the whole configuration **before** storage opens. A refusal
prints one stderr line of static codes and exits non-zero; the line never contains
a path, an alias, a URL or a secret:

| Line | Cause |
| --- | --- |
| `scrape: config_unreadable` | missing, not a regular file |
| `scrape: config_not_private` | group- or world-writable |
| `scrape: config_invalid` | unknown field, trailing data, version, empty or oversize target list |
| `scrape: config_target_invalid` | a target failed validation (alias, URL, interval/timeout, max bytes, auth/secret pairing, egress prefix, profile word, IDs, policy revision) or an alias repeats |
| `scrape: config_tls_roots_invalid` | `tls.roots_file` missing or without a certificate |
| `scrape: secrets_dir_invalid` / `secrets_dir_insecure` | the secrets directory is missing, a link or not a directory / is accessible to other users |
| `scrape: flags_incomplete` | only one of the two flags was given |

After the node opens, serve prints `scrape: N target(s) started`. The scrapers
stop before storage closes (on SIGINT/SIGTERM).

## Configuration file

```json
{
  "version": 1,
  "targets": [
    {
      "alias": "node-exporter",
      "url": "https://10.20.0.7:9100/metrics",
      "interval": "15s",
      "timeout": "5s",
      "max_bytes": 4194304,
      "tls": { "roots_file": "/etc/soundpost/exporter-ca.pem", "server_name": "exporter.internal" },
      "egress": { "allow_prefixes": ["10.20.0.0/16"] },
      "auth": "bearer",
      "secret": "node-exporter-token",
      "stale": { "on_disappear": true, "on_failure": true },
      "profile": { "names": "strict", "out_of_order": "sort", "histograms": "preserve", "exemplars": "reject", "help": "reject", "default_unit": "" },
      "source": {
        "project": "<32 hex>", "source": "<32 hex>", "producer": "<32 hex>",
        "policy_revision": 1,
        "credential_secret": "scrape-source-token",
        "resource": { "service": "<32 hex>", "environment": "<32 hex>", "build": "<32 hex>", "instance": "host-1", "labels": { "zone": "a" } }
      }
    }
  ]
}
```

* `alias`, `url`, `interval`, `timeout`, `max_bytes`, `tls`, `egress`, `auth`,
  `secret`, `stale` map one-to-one to `sources.ScrapeTarget` and are validated by
  it. `interval` and `timeout` are Go duration strings. `egress.allow_prefixes` can
  lift only the private ranges; **loopback, link-local, multicast, unspecified and
  cloud-metadata addresses are never allowed**, so a node cannot scrape an exporter
  bound to `127.0.0.1` (use an address of the host that the exporter listens on, and
  list its prefix). `tls` is only valid for an `https` URL; `roots_file` is a PEM
  bundle read once at startup; verification is never disabled. `auth` is empty,
  `bearer` (the secret is the whole token) or `basic` (the secret is
  `user:password`); `secret` is then required and is a reference into the secrets
  directory. Credentials over a plain `http` URL travel in clear text: use `https`.
* `profile` words are the closed vocabularies of the decoder
  (`names`: `strict`|`utf8`; `out_of_order`: `sort`|`reject`; `histograms`:
  `preserve`|`reject`; `exemplars`: `reject`|`trace_link`; `help`:
  `reject`|`discard`). An empty value takes the first listed.
* `source` names the installation source the target **admits as**:
  `project`, `source`, `policy_revision` must be those of a source an owner
  onboarded (`policy_revision` must equal the source's current policy revision; a
  policy change makes cycles fail typed as `policy_stale` until the file is
  updated), `producer` and `resource` stamp every sample. `credential_secret`
  references the raw source credential.

## Secrets directory

Each secret is one regular file named by its reference, mode `0600` (no group or
world bits; `0400` is fine). A reference is `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` and
contains no `..`: no path separator, no hidden file, no traversal. The reader
refuses (as a typed secret failure, never an error with a path):
a symbolic link (also a dangling one), a non-regular file, a file with group or
world permission bits, a file over 4 KiB, an empty file, and a file replaced
between the check and the open. Every fetch reads the file again; nothing is
cached, logged or retained, and the bytes are zeroed after the header is built. One
trailing newline (or CRLF) is not part of the secret. In a container orchestrator,
mount the directory with an explicit file mode of `0400`/`0600`: the orchestrator
default of `0644` is refused, and symbolic-link projections are refused.

A missing or refused secret is **health, not a crash**: a target secret reads as
`secret_unavailable` (no request is made), a source credential as
`credential_unavailable`.

## Identity: how the node obtains a grant

A grant cannot be conjured by the node. The operator provisions a **source** with
the existing owner path (`OnboardSource`, the same call the onboarding CLI and
admin API make), receives its raw credential once, and stores it in the secrets
directory under `credential_secret`. For every attempt the scraper resolves a new
grant: read the credential file, `AuthenticateSource`, then
`ingest.Service.ResolveSource` for the configured project, source and policy
revision (a grant lives five seconds; none is kept between attempts). Revoking the
source, letting it expire, or changing its policy revision therefore stops
admission on the next attempt, typed. The node gains no new identity or privilege
to scrape: it can only act as sources the owner gave it credentials for.

## Health

`ScrapeHost.Status()` (per target, in alias order) returns the cycle count, the last
`ScrapeResult` (health status, coverage, sample and stale marker counts, series
carried) and a closed `Reason`:

| Reason | Meaning |
| --- | --- |
| *(empty)* | the last cycle scraped and every batch has its receipt |
| a scrape status: `timeout`, `connection_reset`, `connection_refused`, `unreachable`, `egress_denied`, `tls_failed`, `redirect_refused`, `bad_status`, `too_large`, `decode_failed`, `secret_unavailable`, `cancelled` | the scrape failed; coverage is `unknown` |
| `credential_unavailable` | the source credential secret could not be read |
| `grant_denied` | the credential is unknown, revoked or expired, or does not cover the configured project/source |
| `policy_stale` | the source's policy revision differs from `policy_revision` |
| `grant_unavailable` | the node could not answer (not a verdict) |
| `admit_failed` | a batch was refused or could not be made durable; the stale-marker state is not advanced |
| `invalid` | the target or grant failed validation before any request |
| `cancelled` | the node is stopping |

A status carries no URL, header, body, secret or transport error text. A failed
wrong secret therefore shows as `bad_status` (HTTP 401) with nothing admitted.

## Limits of this release

* There is no HTTP or CLI route that exposes `Status()`; it is readable in process.
  The only operator-visible signals are the startup lines.
* The carried series set (what stale markers are computed against) is in memory: a
  restart forgets it, so series that disappeared while the node was down get no
  stale marker.
* Policy revisions are static in the file (no automatic follow).

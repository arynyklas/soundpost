<!-- Copyright 2026 Aryn Yklas -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Soundpost to GitLab bridge (reference receiver)

A small program that receives the signed Soundpost event webhook and mirrors three events into GitLab. It is the reference receiver of
section 9 of `docs/operations/console-api.md`: copy it, read it, adapt it. It is standard-library Go only, imports nothing from
Soundpost and keeps no state but one small file.

| Event | Action in GitLab |
|---|---|
| `issue.new` | Creates a GitLab issue `Soundpost issue <8 hex>` for the error issue, once. |
| `issue.regressed` | Adds a note to that GitLab issue (creating the issue first if it does not exist), once per delivery. |
| `incident.opened` | Creates a GitLab issue `Soundpost incident <8 hex> (<severity>)`, once. |
| `test.ping` | Answers `pong`. |
| anything else | Acknowledged (`200`) and ignored, so Soundpost does not retry it. |

The payload carries identifiers and links only, so the issue holds identifiers, the severity word, the release ID and a link back to the
console, and ends with a marker line `Soundpost reference: soundpost-bridge-<hex>`. No title, message, stack, log or note ever reaches
GitLab.

## Guarantees

* **Signature.** `Soundpost-Signature` is `v1=<hex HMAC-SHA256(secret, "<ts>.<delivery-id>.<body>")>`, possibly several values separated
  by commas (during a secret rotation Soundpost signs with the new and the previous secret). A delivery is accepted when any value
  matches the current or the optional previous secret (constant-time compares) and `Soundpost-Timestamp` is within five minutes of the
  bridge's clock. Anything else is `401` and nothing is sent to GitLab.
* **Exactly-once effect.** A delivery ID is recorded **after** its action succeeded (kept 25 hours, in bounded memory, in an append-only
  file so a restart keeps it). A replay of a recorded delivery is `200 duplicate`. If the process dies after GitLab did the work and
  before the ID was written, the retry looks the issue up **by its marker before creating** (and a regression note by its delivery ID
  before adding), so nothing is duplicated. The lookup matches the marker in the issue description itself; GitLab's search result alone is
  never trusted.
* **Retries.** `2xx` only after the action succeeded. A GitLab failure of any kind (including `401`/`403`, which are configuration errors that
  deserve to stay visible) is `502`, so Soundpost retries within its retry budget.
* **Bounds.** Request bodies are limited to 64 KiB, GitLab answers to 256 KiB, GitLab calls time out after 10 seconds, redirects are not
  followed and no proxy is used.
* **No secrets in logs.** The log has delivery IDs, event names and outcomes. Never a secret, the token, a signature or a body.

## Configuration

`config.example.json` is the template. Secrets come from the environment (preferred):

| Variable | Meaning |
|---|---|
| `SOUNDPOST_WEBHOOK_SECRET` | The endpoint's secret as saved in Soundpost (16 bytes or more). |
| `SOUNDPOST_WEBHOOK_SECRET_PREVIOUS` | Optional: the previous secret, accepted while you rotate. |
| `GITLAB_TOKEN` | A GitLab project access token (role Reporter or higher; scope `api`). |

(The file fields `secret`, `previous_secret` and `gitlab_token` exist for setups where the configuration file is itself protected; the
environment wins.)

| Field | Meaning |
|---|---|
| `listen` | Address to listen on (default `127.0.0.1:8443`). |
| `tls_cert_file`, `tls_key_file` | Serve HTTPS. Required unless the program is started with `-http`. |
| `gitlab_base_url` | `https://` URL of GitLab, no credentials. |
| `gitlab_ca_file` | Optional PEM file of extra trust roots for a private CA. |
| `state_file` | Where delivery IDs are kept across restarts (created with mode 0600). |
| `projects` | Soundpost project ID (32 hex) to `{ "gitlab_project": "group/project" (or the numeric ID), "labels": [...] }`. An event of an unmapped project is acknowledged and ignored. |

## Running

```
go build -o gitlab-bridge ./contrib/gitlab-bridge
SOUNDPOST_WEBHOOK_SECRET=... GITLAB_TOKEN=... ./gitlab-bridge -config /etc/soundpost-gitlab-bridge/config.json
```

* HTTPS directly: set `tls_cert_file` and `tls_key_file`.
* Behind a TLS-terminating proxy: start with `-http` and keep `listen` on a loopback or private address. Only the proxy may reach it.

Then, in the Soundpost console, add an event webhook endpoint whose URL is `https://<your host>/soundpost`, choose the events
(`issue.new`, `issue.regressed`, `incident.opened`), set the secret, and press **test**: the bridge answers `pong`. The endpoint URL must
pass the same egress rules as every webhook: a bridge on a private address needs the administrator to allow its prefix
(`--notify-egress-allow`). `GET /healthz` answers `200` for a probe (no information).

To rotate the secret: set `SOUNDPOST_WEBHOOK_SECRET_PREVIOUS` to the old value and `SOUNDPOST_WEBHOOK_SECRET` to the new one, restart the
bridge, save the new secret in the console (Soundpost signs with both for 24 hours), then drop the previous value.

## Security notes

* The signature is the only authentication: keep the secret out of the repository and the process list (use the environment or a protected
  file), and give the GitLab token the least role that can create issues in the mapped projects.
* Only Soundpost can produce a valid delivery within the five minute window, and a captured delivery cannot be replayed after it was
  recorded (and a replay of an unrecorded one finds its issue by the marker instead of creating another).
* The bridge writes only what the payload carries after validation (hex IDs, a severity word, a decimal revision, an https link without
  credentials). Anything else in a payload is refused with `400`.
* The bridge makes outbound calls to `gitlab_base_url` only. Run it where it may reach GitLab and where Soundpost may reach it.

## Tests

`go test ./contrib/gitlab-bridge/` runs against a local stub GitLab (a bad signature, a stale timestamp, a replay, dedup across a restart,
lookup before create, a GitLab 500 followed by success, unknown events). No real GitLab instance is involved.

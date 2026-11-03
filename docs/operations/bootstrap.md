<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# First boot and local administration

Soundpost single mode is durable but not highly available. Store its data directory on a local, encrypted, durable volume with restricted OS access. On Unix it creates the directory with mode 0700 and authority/key/token files with mode 0600. On Windows configure an equivalent account-only ACL; POSIX modes do not establish Windows ACL isolation.

Start with a certificate trusted by your clients and a separately protected private key:

```sh
soundpost serve --mode=single --data-dir /private/soundpost --listen 127.0.0.1:8443 --tls-cert /private/tls/server.pem --tls-key /private/tls/server.key
```

The exact minimal command may omit both TLS-file flags. First boot then creates a stable private `server.key` and public `server.crt` in the data directory. Explicitly trust that public certificate through an authenticated channel; never disable client verification. Restart retains this identity. Use externally issued certificates for externally managed deployments.

There is no HTTP listener, default password, public signup or memory-only authority. TLS 1.3 is required. The first start writes a cryptographically random one-use token to `bootstrap.token` and prints it to the controlling console. Do not forward console output to shared logs. A successful bootstrap durably consumes its hash and deletes the token file. A restart cannot reactivate it.

POST `/api/v1/bootstrap` with JSON `Token`, `Email`, `Password` and an `Origin` matching the HTTPS server origin. Passwords must contain 16–1024 bytes. The first user is an instance administrator; bootstrap returns a secure, HTTP-only, host-only, SameSite=Strict session cookie and a CSRF token. Passwords are hashed using Argon2id (64 MiB, three iterations, parallelism two, 32-byte output, random salt).

## Session and MFA

- POST `/api/v1/login`: `Email`, `Password`, `Code` (TOTP or a recovery code when MFA is enabled).
- GET `/api/v1/session`: current user, session expiry and CSRF token, never the bearer token.
- POST `/api/v1/reauthenticate`: `Password`, `Code`; rotates the session and CSRF token and revokes the previous session.
- POST `/api/v1/logout`: revokes the durable session.
- POST `/api/v1/totp/start`: returns a new enrollment secret once.
- POST `/api/v1/totp/confirm`: `Code`; activates TOTP and returns ten one-use recovery codes. Save these offline; only hashes persist. TOTP secrets persist as AES-256-GCM envelopes. Thirty-second steps accept one adjacent step and reject replayed steps.

Authenticated POSTs require both the exact HTTPS Origin and `X-CSRF-Token`. Login/bootstrap/OIDC-start require exact Origin but cannot require an already authenticated session. Sessions expire after twelve hours. Sensitive administrative changes and elevation require authentication within five minutes.

## Narrow server credentials

Freshly authenticated organization administrators may POST `/api/v1/admin/tokens/issue` with `org_id`, `principal`, `projects`, `permissions`, decimal-string `expires` (Unix seconds) and `reason`. The principal must already be an explicit organization member, and its current project grants remain the upper bound. The returned bearer token is disclosed once; only its hash persists. `/api/v1/admin/tokens/revoke` accepts `org_id`, `id`, `reason` and durably revokes it. Server tokens cannot authenticate browser sessions, administer organizations or elevate. `httpapi.AuthenticateRequest` is the shared bearer parser; it accepts only server tokens in Authorization headers, never browser session tokens. Permission probes at POST `/api/v1/control/authorize` support those explicit server credentials without ambient-cookie CSRF semantics.

## Administration

POST `/api/v1/admin/read` with `{ "kind": "organizations" }` obtains the current revision and lists only organizations explicitly administered by the caller. Reads are closed selectors `organizations`, `organization`, `audit`, `team`, `source_policy`, `sso`, `destination` or `retention`; organization-specific reads include `org_id`. Write-only secrets are never returned.

POST `/api/v1/admin/commands` has `command_id` (nonzero lowercase 32-hex), `expected_revision` (decimal string), `org_id`, `kind`, `payload`. Commands use optimistic revision fencing and durable idempotency by command ID. Every command needs a nonempty `reason` in payload. Instance administrators create organizations and local users. An organization creator receives explicit organization administration, not project data access. Organization administrators create projects, add memberships and grant project permissions. Membership alone grants no data access. Cross-organization IDs return not-found.

Command kinds: `create_org`, `create_user`, `create_project`, `membership`, `org_admin`, `grant`, `team`, `source_policy`, `sso`, `destination`, `retention`. Payload identifiers are `id`, `user_id`, `project_id`; grant payloads specify `permissions` and `enabled`. Destination/source/SSO secrets belong only in the write-only `secret` field. `config` is decoded into a closed per-kind DTO and rejects unrecognized fields/embedded SSO credentials. Teams explicitly select `members`, `projects`, `permissions`, `enabled`; disabled teams and revoked memberships grant no data. Source policies select `project_id`, exact HTTPS `origins`, `restricted`, named `readers` and `enabled`. Retention settings select `project_id`, `signal`, `days`. The later telemetry/control owners consume those durable settings and implement data-group barriers; this task does not pretend to implement telemetry deletion or Raft.

## OIDC

SSO is configurable through the authenticated `sso` admin command: `config` contains `Issuer`, `ClientID`, `RedirectURL` and explicit `Subjects` (provider subject to pre-created, explicitly admitted local account ID), while the provider client secret goes only in the separate encrypted `secret` field. POST `/api/v1/oidc/start` selects `org_id` and `provider_id` and obtains an authorization URL. An optional private `--oidc-config` file can configure a single installation-managed provider instead. No email-domain autojoin exists. The issuer and callback use HTTPS. GET `/api/v1/oidc/callback` consumes single-use state bound to the initiating browser. PKCE S256, nonce, signed issuer/audience/expiry validation and explicit subject mapping are mandatory; local organization/project grants remain authoritative.

## Elevation and storage

POST `/api/v1/elevation` with `Reason`, `Orgs` selects organizations for at most fifteen minutes. It commits an elevation audit before returning a handle. Read integrations resolve the handle against its session and call `ElevatedScope`, which commits a separate read audit before scope release. Any authority failure denies access.

`control.db` is bbolt-backed and fsyncs transactions before success. `envelope.key`, any `envelope-<key-ID>.key` files and `envelope.active` must be backed up separately with independent protection. Secret envelopes include a key ID; `control.Store.RotateSecretKey` atomically selects a new active key and retains previous keys for decryption. A KMS is not required for the local-key configuration. The later backup/restore task owns deletion-safe disaster restore and fresh authentication generation reconciliation; do not claim HA, disaster recovery qualification or automatic restore authorization from this local adapter. Never copy an old authority database into a running installation.

## Lease, audit and process integration

Long-running consumers must check `Scope.LeaseDeadline()` and perform `Revalidate(ctx, scope)` at least every five seconds, as well as before every result/chunk release. Successful revalidation performs a fresh authoritative read and refreshes the same opaque scope's shared lease; it does not impose a five-second total scope lifetime or require query consumers to replace their Scope. The deadline is capped by credential expiry and any elevation expiry. Failed revalidation clears that lease. Policy-epoch changes and credential revocations still deny rather than silently updating the old authorization.

HTTPS admission supplies a trusted `X-Request-ID` response header and request context. Audited mutations persist that actual correlation ID and committed outcome; non-HTTP control commands use their command ID when no request context is supplied. Encoding does not substitute an audit ID or invent an allowed outcome. Previously recorded synthetic correlation values cannot be retroactively recovered. No new denial-logging stream is enabled by this change.

Server-token expiry remains operator-selected, subject to current grants and immediate revocation. It is not silently capped to the twelve-hour browser-session lifetime.

The process handles SIGINT and, where delivered by the operating system, SIGTERM with bounded graceful HTTPS shutdown. Force-kill recovery is a different test from graceful shutdown or power-loss qualification.

The current local adapter's fsynced database does **not** establish power-loss durability for its directory entries and side files. Bootstrap-token publication, initial TLS key/certificate publication, initial envelope-key publication and active-key renames need the platform filesystem primitive integration assigned to tasks 01.03/01.06. Until those write-ordering fixes and real filesystem crash qualification land, do not treat the process-kill restart evidence as power-loss qualification.

## Installation-owned bearer hash authority

Server/API credential records store purpose-separated **HMAC-SHA256** digests, not bare SHA256 hashes. Service startup loads one installation-owned 256-bit hash key from the encrypted `ControlState.BearerHashKey` envelope, creating it once before serving on a new installation. Envelope encryption key rotation does not rotate that immutable hash key; ordinary restarts and envelope rotation therefore preserve valid credentials. The encrypted hash-key envelope and the referenced old decrypt key must both remain recoverable.

Source-bearer owners use the same injected `auth.Service.BearerDigest` authority with the distinct `auth.SourceBearer` purpose; server/API owners use `auth.ServerAPIBearer`. Raw bearers and the plaintext hash key must never be logged or included in artifacts. The bare digest helper remains only for unrelated random session/one-use handles and non-authority fingerprints.

There is no legacy SHA-only bearer lookup or silent lost-key replacement. A persisted hash-key format marker distinguishes a never-initialized installation from a lost key; after initialization, startup fails closed on a missing hash-key envelope even when the server-token set is empty. It also denies missing-key server authority, unknown key formats and undecryptable envelopes. The unreleased prior server-token format is not supported.

Tasks 01.03/01.09 must preserve durable key-file/envelope ordering and separately protected key backups. Disaster restore is not an ordinary restart: it must fence old authentication generations, create a fresh authentication/hash-key authority and deactivate pre-restore bearer/source credentials before serving, as the approved restore contract requires. Restoring old encryption material alone must not reactivate old credential authority.

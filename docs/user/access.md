<!-- Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0 -->
# Access to Soundpost

Open the installation’s trusted HTTPS origin. The production browser bundle and `/api/v1` must be served by the same Soundpost process/origin. Never disable certificate checks or use a development proxy for authentication acceptance.

## First boot

Choose **First boot** and supply the one-use token from `bootstrap.token` in the installation's data directory (the service log names the file but never prints the token), your email and a password of at least sixteen bytes. No default password, public signup or role selector exists. A successful request consumes the token. First boot is not disaster restore; the deletion-safe restore and audited reauthorization backend remains a separate integration prerequisite. The UI does not claim that old restored identities are active.

## Local account and recovery

Choose **Local account**, enter your password and, when enabled, a TOTP or one-use recovery code. Account access offers authenticator enrollment through the actual authority. Enter the displayed secret in an authenticator and confirm its current code. Save the returned recovery codes offline immediately; they are not retrievable later. They remain only in browser component memory until explicit dismissal, logout, authoritative session denial or a focus/navigation refresh. A transient validation outage hides protected views without discarding undismissed codes; confirmed access restores the view. Do not capture secrets in screenshots or shared logs. An already-used authenticator/recovery code is not reusable.

## Single sign-on

Choose **Single sign-on** and supply administrator-provided organization and provider IDs. Soundpost redirects to the configured HTTPS provider and consumes its real authorization code using PKCE. Only explicit provider-subject mappings to admitted local accounts work. An email domain or organization membership does not automatically grant project data. The server validates issuer, audience, nonce, state and browser binding; a failed callback does not create a session.

## Session and permissions

The host-only session cookie is Secure, HttpOnly and SameSite Strict. CSRF tokens stay in application memory; no bearer credentials are put in browser storage. Sign out revokes the server session. Fresh reauthentication rotates the session and CSRF token. The boundary revalidates on focus, browser navigation and every five seconds. Authoritative 401/403 denial clears authenticated content and transient secrets; network/5xx failure instead pauses protected views and reports unavailable validation without claiming that the session expired. A changed account triggers a fresh boundary load. Server release-time scope validation remains authoritative, not this browser poll.

Organization listings are the actual administrative read response, not a project entitlement inventory. Empty and forbidden results remain explicit. Telemetry, restricted raw sources, artifacts, replay and profiles have independent permissions. This access page does not invent a queue or healthy status when investigation surfaces are absent.

Instance elevation selects explicitly returned organizations, requires current password/MFA and a reason, and requests a committed audit before accepting the real returned handle. It expires after fifteen minutes. Focus/navigation clears the elevated view; expiry removes its keyed content. Clearing the view is not server-side revocation of the handle; server expiry/session revocation remain authoritative. Ordinary/project administrators cannot gain instance authority by changing this UI.

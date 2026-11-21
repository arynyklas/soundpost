#!/bin/sh
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
# usage: in-trust-ns.sh COMMAND ARGS...   (called by h.sh; environment E2E_TRUST_OVERLAY and E2E_TRUST_DIR, set by h.sh trust_files)
#
# WebKit (the Playwright build, GnuTLS through glib-networking) has no switch for an extra CA and reads only the system CA bundle. On a host where
# the harness has no root, the bundle cannot be edited, so the command runs in a private user+mount namespace in which the bundle's directory
# (E2E_TRUST_DIR) is overlaid read-only with E2E_TRUST_OVERLAY, a directory holding the same bundle file with this run's CA appended. Nothing
# outside the namespace changes and the overlay disappears with the command. Without the two variables the command just runs: Chromium trusts the
# run's leaf by its SPKI pin and Firefox through an enterprise policy.
set -eu
if [ -z "${E2E_TRUST_OVERLAY:-}" ] || [ "${E2E_BROWSER:-chromium}" != webkit ]; then
	exec "$@"
fi
if ! unshare -Urm true 2>/dev/null; then
	echo "in-trust-ns: this host does not allow unprivileged user+mount namespaces: install the run CA in the system bundle and set E2E_WEBKIT_TRUST=system" >&2
	exit 97
fi
# The overlay is mounted by the namespace's own root (the caller mapped to uid 0); the command then runs inside it, never with ignoreHTTPSErrors.
exec unshare -Urm sh -c 'mount -t overlay overlay -o "lowerdir=$E2E_TRUST_OVERLAY:$E2E_TRUST_DIR" "$E2E_TRUST_DIR" && exec "$@"' sh "$@"

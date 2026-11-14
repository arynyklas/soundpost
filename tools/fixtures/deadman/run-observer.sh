#!/bin/sh
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
#
# Runs the external deadman observer (tests/acceptance/observer, built, never forked) as its own
# process, from a settings file. Read README.md first: this script makes the observer a separate
# OPERATING-SYSTEM PROCESS with its own state directory and credentials; it cannot make it a
# separate FAILURE DOMAIN. That is decided by where you run it (a separately provisioned host).
#
#   run-observer.sh [--check] [observer.env]
#
# --check validates the settings and prints the command with both credentials redacted, then exits
# without starting anything. The settings file may also be named in $OBSERVER_ENV.
set -eu

check=0
if [ "${1:-}" = "--check" ]; then
	check=1
	shift
fi
env_file=${1:-${OBSERVER_ENV:-observer.env}}

die() {
	printf 'run-observer: %s\n' "$*" >&2
	exit 2
}

[ -f "$env_file" ] || die "settings file $env_file not found (copy observer.env.example and edit it)"

# The settings hold both credentials: nobody but the observer's own account may read them.
mode=$(stat -c %a "$env_file" 2>/dev/null || stat -f %Lp "$env_file" 2>/dev/null || echo unknown)
case "$mode" in
*00) ;;
*) die "settings file $env_file has mode $mode: it holds credentials, chmod 600" ;;
esac

set -a
# shellcheck disable=SC1090
. "$env_file"
set +a

need() {
	eval "value=\${$1:-}"
	[ -n "$value" ] || die "$1 is required"
}
for name in OBSERVER_ID OBSERVER_STATE_DIR OBSERVER_POLL OBSERVER_DESTINATION OBSERVER_AUTHORIZED_DESTINATION OBSERVER_POLL_TOKEN OBSERVER_DELIVERY_TOKEN; do
	need "$name"
done
case "$OBSERVER_POLL_TOKEN$OBSERVER_DELIVERY_TOKEN" in
*replace-me*) die "a credential still holds the example placeholder" ;;
esac
[ "$OBSERVER_POLL_TOKEN" != "$OBSERVER_DELIVERY_TOKEN" ] || die "the poll credential and the delivery credential must be two different credentials"

# The observer's state must not live where the product keeps its own.
case "$OBSERVER_STATE_DIR" in
*/../* | */..) die "OBSERVER_STATE_DIR must not contain .." ;;
/*) ;;
*) die "OBSERVER_STATE_DIR must be an absolute path" ;;
esac
state=${OBSERVER_STATE_DIR%/}
for product in "${SOUNDPOST_DATA_DIR:-}" /var/lib/soundpost /etc/soundpost /opt/soundpost; do
	[ -n "$product" ] || continue
	case "$state/" in
	"$product"/* | "$product"/) die "OBSERVER_STATE_DIR $state is inside the product's directory $product" ;;
	esac
done

bin=${OBSERVER_BIN:-./observer}
if [ ! -x "$bin" ]; then
	repo=${OBSERVER_REPO:-}
	[ -n "$repo" ] && [ -f "$repo/go.mod" ] || die "no observer binary at $bin: build it (go build -o $bin ./tests/acceptance/observer from the repository root) or set OBSERVER_REPO to the repository root so this script can"
	(cd "$repo" && go build -o "$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")" ./tests/acceptance/observer) || die "building the observer failed"
fi

set -- -state "$state" -id "$OBSERVER_ID" -poll "$OBSERVER_POLL" \
	-interval "${OBSERVER_INTERVAL:-1s}" -missing-after "${OBSERVER_MISSING_AFTER:-30s}" -timeout "${OBSERVER_TIMEOUT:-5s}" \
	-max-attempts "${OBSERVER_MAX_ATTEMPTS:-8}" \
	-destination "$OBSERVER_DESTINATION" -authorized-destination "$OBSERVER_AUTHORIZED_DESTINATION"
if [ "${OBSERVER_TEST_ALLOW_LOOPBACK:-}" = "1" ]; then
	set -- "$@" -test-allow-loopback
fi

if [ "$check" = 1 ]; then
	printf 'would run: OBSERVER_POLL_TOKEN=<redacted> OBSERVER_DELIVERY_TOKEN=<redacted> %s' "$bin"
	for arg in "$@"; do
		printf ' %s' "$arg"
	done
	printf '\n'
	exit 0
fi

mkdir -p "$state"
chmod 700 "$state"
# The observer gets its two credentials and PATH, and nothing else of this environment.
exec env -i PATH="$PATH" OBSERVER_POLL_TOKEN="$OBSERVER_POLL_TOKEN" OBSERVER_DELIVERY_TOKEN="$OBSERVER_DELIVERY_TOKEN" "$bin" "$@"

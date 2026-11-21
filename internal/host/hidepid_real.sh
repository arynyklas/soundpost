#!/bin/sh
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
#
# Recipe for TestRealHostProcessCountOnAHidepidMount (07.03-W4): a real /proc
# mount with hidepid, made without root through a user namespace.
#
#   sh internal/host/hidepid_real.sh <test binary built with `go test -c`>
#
# plain:      the host's own /proc.
# exempt:     a user+pid namespace (the caller maps to root there), /proc mounted
#             and remounted hidepid=2, the test run as that root.
# restricted: the same mount, the test run in a nested user namespace as the
#             caller's own non-zero uid, with no capability.
set -eu
t="$1"
run() { "$t" -test.run '^TestRealHostProcessCountOnAHidepidMount$' -test.v; }
echo "== plain"
SOUNDPOST_REAL_HIDEPID=plain run
echo "== exempt (namespace root, hidepid=2)"
SOUNDPOST_REAL_HIDEPID=exempt unshare --user --map-root-user --mount --pid --fork --mount-proc \
  sh -c 'mount -o remount,hidepid=2 /proc && grep " /proc " /proc/self/mountinfo && "$0" -test.run "^TestRealHostProcessCountOnAHidepidMount$" -test.v' "$t"
echo "== restricted (nested user namespace, uid $(id -u), hidepid=2)"
uid=$(id -u)
SOUNDPOST_REAL_HIDEPID=restricted unshare --user --map-root-user --mount --pid --fork --mount-proc \
  sh -c 'mount -o remount,hidepid=2 /proc && exec unshare --user --map-user='"$uid"' "$0" -test.run "^TestRealHostProcessCountOnAHidepidMount$" -test.v' "$t"

#!/usr/bin/env bash
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
#
# Runs the symbolicate package tests against the REAL native worker sandbox, inside a transient system unit that
# carries the hardening of deploy/systemd/soundpost.service (the delegated cgroup subtree, the namespace/syscall
# restrictions). Plain `go test` and the sharded CI jobs skip every test that needs a sandbox configuration
# (SOUNDPOST_SYMBOLICATE_TEST_CONFIG), so without this job a regression such as the warm-spare watchdog (the
# worker's 100 ms processing bound must start with the request, not with the handshake) would pass unnoticed.
#
# Needs: Linux with systemd >= 254 (DelegateSubgroup) and cgroup v2, passwordless sudo, Go on PATH.
# Usage: deploy/ci/symbolicate-native.sh   (from anywhere; SOUNDPOST_CI_DIR / SOUNDPOST_CI_RUN override the work
# directory and the test regexp).
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
dir=${SOUNDPOST_CI_DIR:-/opt/soundpost-symbolicate-ci}
unit=soundpost-symbolicate-ci
run=${SOUNDPOST_CI_RUN:-.}
# These must run and pass: a skip is a failure of this job.
required=(TestAHandshakenWorkerThatWaitsStillAnswersItsRequest TestActualSandboxDeniesFileNetworkExec TestActualSandboxMemoryKilled TestActualSandboxDeadlineAndRestart)

sudo systemctl stop "$unit.service" 2>/dev/null || true
sudo rm -rf "$dir"
sudo install -d -m 755 -o "$(id -u)" -g "$(id -g)" "$dir"

# The worker is the one soundpost binary (re-exec worker); the tests are compiled once and run by the unit's user.
(cd "$root" && CGO_ENABLED=0 go build -trimpath -o "$dir/soundpost" ./cmd/soundpost && go test -c -o "$dir/symbolicate.test" ./internal/symbolicate)
mkdir "$dir/src"
# tar exits 1 when a file changed while it was read (a developer tree being edited); that is no failure of the copy.
(cd "$root" && tar --exclude=./.git --exclude=./.tools --exclude=./.superpowers --exclude=./node_modules -cf - . || [ $? -eq 1 ]) | tar -C "$dir/src" -xf -
chmod -R a+rX "$dir"
hash=$(sha256sum "$dir/soundpost" | cut -d' ' -f1)

cat >"$dir/run.sh" <<EOF
set -eu
cgroup_root=\$(dirname "/sys/fs/cgroup\$(cut -d: -f3 /proc/self/cgroup)")
printf '{"mode":"native","worker_path":"%s","worker_sha256":"%s","cgroup_root":"%s"}\n' "$dir/soundpost" "$hash" "\$cgroup_root" >/tmp/native.json
export SOUNDPOST_SYMBOLICATE_TEST_CONFIG=/tmp/native.json SOUNDPOST_SYMBOLICATE_DELEGATED_ROOT=\$cgroup_root
export SOUNDPOST_SYMBOLICATE_TEST_OCI='skip:native sandbox job; the OCI runtime tests run where a runtime exists'
cd "$dir/src/internal/symbolicate"
exec "$dir/symbolicate.test" -test.count=1 -test.v -test.timeout 20m -test.run '$run'
EOF

set +e
sudo systemd-run --system --unit="$unit" --wait --pipe --collect \
	-p User=nobody -p UMask=0077 -p Delegate="memory pids" -p DelegateSubgroup=main \
	-p NoNewPrivileges=yes -p CapabilityBoundingSet= -p AmbientCapabilities= \
	-p ProtectSystem=strict -p ProtectHome=yes -p PrivateTmp=yes -p PrivateDevices=yes \
	-p ProtectKernelTunables=yes -p ProtectKernelModules=yes -p ProtectKernelLogs=yes -p ProtectControlGroups=yes \
	-p ReadWritePaths="/sys/fs/cgroup/system.slice/$unit.service" \
	-p ProtectClock=yes -p ProtectHostname=yes -p ProtectProc=invisible -p ProcSubset=pid \
	-p RestrictAddressFamilies="AF_INET AF_INET6 AF_UNIX" -p RestrictNamespaces=yes -p RestrictRealtime=yes \
	-p RestrictSUIDSGID=yes -p LockPersonality=yes -p MemoryDenyWriteExecute=yes \
	-p SystemCallArchitectures=native -p SystemCallFilter=@system-service -p SystemCallFilter=seccomp -p SystemCallErrorNumber=EPERM \
	-p LimitNOFILE=65536 -p TasksMax=4096 -p MemoryMax=2G \
	bash "$dir/run.sh" 2>&1 | tee "$dir/out.txt"
status=${PIPESTATUS[0]}
set -e

if [ "$status" -ne 0 ]; then
	echo "native sandbox tests failed (unit exit $status)" >&2
	exit 1
fi
for name in "${required[@]}"; do
	if ! grep -q -- "--- PASS: $name " "$dir/out.txt"; then
		echo "required native sandbox test did not pass (skipped or missing): $name" >&2
		exit 1
	fi
done
echo "native sandbox tests passed: ${required[*]}"

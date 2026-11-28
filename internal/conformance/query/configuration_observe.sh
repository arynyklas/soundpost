#!/bin/sh
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
#
# Observation script of the configuration-phase oracle variant. It runs INSIDE the
# disposable no-network container, as the entrypoint override
# `/bin/sh /fixture/observe.sh`, next to the unmodified upstream /bin/prometheus
# of the pinned image. For every scenario it starts that binary on the authored
# configuration and reports only what the binary itself does: whether it became
# ready (the configuration loaded) or exited, the error it logged, and the
# effective configuration it serves on /api/v1/status/config. Nothing here
# interprets a semantic; the Go harness projects the text this script prints.
#
# Fixture layout (read-only mount at /fixture): `index` lists scenario names, one
# per line; <name>.yml is the configuration; <name>.flags is one line of flags.
set -u
PORT=19090
BASE=http://127.0.0.1:$PORT

sha=$(sha256sum /etc/prometheus/soundpost-configuration-phase.yaml | cut -d' ' -f1)
echo "@@control-sha256 $sha"
echo "@@version $(/bin/prometheus --version 2>&1 | head -n 1)"
echo "@@revision $(/bin/prometheus --version 2>&1 | sed -n 's/.*revision: \([0-9a-f]*\).*/\1/p' | head -n 1)"

observe() {
	name=$1
	config=$2
	flags=$3
	echo "@@begin $name"
	/bin/prometheus --config.file="$config" --storage.tsdb.path=/tmp/data-$name \
		--web.listen-address=127.0.0.1:$PORT --log.format=json $flags >/tmp/log-$name 2>&1 &
	pid=$!
	ready=0
	i=0
	while [ $i -lt 400 ]; do
		if wget -q -O /dev/null $BASE/-/ready 2>/dev/null; then
			ready=1
			break
		fi
		kill -0 $pid 2>/dev/null || break
		i=$((i + 1))
		sleep 0.05
	done
	if [ $ready = 1 ]; then
		echo "@@ready"
		echo "@@status"
		wget -q -O - $BASE/api/v1/status/config
		echo
	else
		echo "@@exited"
		grep '"level":"ERROR"' /tmp/log-$name | head -n 3
	fi
	kill $pid 2>/dev/null
	wait $pid 2>/dev/null
	rm -rf /tmp/data-$name /tmp/log-$name
	echo "@@end $name"
}

observe control /etc/prometheus/soundpost-configuration-phase.yaml ""
while read -r name; do
	[ -n "$name" ] || continue
	observe "$name" "/fixture/$name.yml" "$(cat /fixture/$name.flags)"
done </fixture/index
echo "@@done"

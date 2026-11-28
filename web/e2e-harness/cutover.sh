#!/bin/bash
# A REAL ownership cutover for the cutover-panel browser test (e2e/cutover-real.spec.ts), on the Linux worker VM (run from the checkout root through vm.py start).
#   cutover.sh MODE PLAYWRIGHT_ARGS...      MODE is pw (headless) or headed (xvfb, screenshots + traces in $OUT)
# `h.sh up` gives the installation (bootstrapped owner e2e-owner). e2e-provision/cutover-seed.spec.ts seeds it through the real admin and source routes
# (organization, project, destination, source). The cutover itself is advanced only by the operator facade, never by the console, so between the three
# stages the server is stopped and web/fixtures/cutoverseed commits the next transitions through notify.CutoverService.AdvanceCutover into the stopped
# installation's control state; the server is then started again on the same data and the spec runs against what it serves:
#   stage shadow       cutoverseed -phases shadow                                       the spec saves a rule; the served workers record shadow decisions
#   stage new_active   cutoverseed -phases quiescing_old,barrier_verified,new_active
#   stage old_active   cutoverseed -phases rollback_quiescing,old_active
# Extra arguments go to every `playwright test` run. The exit code is the first failing stage's.
set -euo pipefail
export E2E_P=${E2E_P:-l6w1cut}
MODE=$1; shift
ROOT=$(pwd)
P=$E2E_P; PORT=${E2E_PORT:-18711}
T=/tmp/$P-$PORT; PKI=$T/pki; DATA=$T/data; W=$T/cutover
BIN=${SOUNDPOST_BIN:-/tmp/$P-soundpost}
CHROME=${CHROME:-$HOME/tools/chrome-linux156/chrome-linux64/chrome}
OUT=${E2E_OUT:-$HOME/out/$P}
ORIGIN=https://127.0.0.1:$PORT
H="sh $ROOT/web/e2e-harness/h.sh"
PW_CLI="node node_modules/@playwright/test/cli.js"

stop_server() {
	if [ -f "$W/server.pid" ]; then
		pid=$(cat "$W/server.pid")
		kill "$pid" 2>/dev/null || true
		i=0; while kill -0 "$pid" 2>/dev/null && [ $i -lt 30 ]; do i=$((i + 1)); sleep 1; done
		kill -9 "$pid" 2>/dev/null || true
		rm -f "$W/server.pid"
	fi
}
trap 'stop_server; $H down >/dev/null 2>&1 || true' EXIT

start_server() {
	SOUNDPOST_FAULT_DIR=$T/fault SSL_CERT_FILE=$PKI/ca.pem setsid nohup "$BIN" serve --mode single --data-dir "$DATA" --listen 127.0.0.1:$PORT --tls-cert "$PKI/leaf.pem" --tls-key "$PKI/leaf.key" --web-dir "$ROOT/web/dist" >>"$W/server.log" 2>&1 </dev/null &
	echo $! >"$W/server.pid"
	i=0
	until [ "$(curl -s --cacert "$PKI/ca.pem" -o /dev/null -w '%{http_code}' "$ORIGIN/readyz")" = 200 ]; do
		i=$((i + 1)); [ $i -gt 90 ] && { echo "server not ready" >&2; grep -v '^raft' "$W/server.log" | tail -20 >&2; exit 1; }; sleep 1
	done
	echo "server pid $(cat "$W/server.pid") origin $ORIGIN"
}

seed() { # phases
	echo "cutoverseed $1:"
	"$W/cutoverseed" -data-dir "$DATA" -org "$CUTOVER_ORG" -project "$CUTOVER_PROJECT" -source "$CUTOVER_SOURCE" -source-version "$CUTOVER_SOURCE_VERSION" -phases "$1" | tee -a "$OUT/cutoverseed.jsonl"
}

$H prep >/dev/null
$H up
mkdir -p "$W" "$OUT"; : >"$W/server.log"; : >"$OUT/cutoverseed.jsonl"
( cd "$ROOT" && go build -o "$W/cutoverseed" ./web/fixtures/cutoverseed )
export NODE_EXTRA_CA_CERTS=$PKI/ca.pem SOUNDPOST_TEST_ORIGIN=$ORIGIN SOUNDPOST_SCOPE_EMAIL=e2e-owner@example.test SOUNDPOST_SCOPE_PASSWORD='e2e instance owner password 2026'
export E2E_SPKI=$(cat "$PKI/spki.txt") CHROME E2E_OUT_DIR=$OUT/test-results E2E_EVIDENCE_DIR=$OUT/evidence
( cd "$ROOT/web" && PROVISION_OUT=$W/seed.env $PW_CLI test -c zz-pw.provision.config.ts e2e-provision/cutover-seed.spec.ts )
. "$W/seed.env"
$H down >/dev/null
export E2E_SERVER_LOG=$W/server.log E2E_DATA_DIR=$DATA E2E_BIN=$BIN E2E_ORIGIN_PORT=$PORT E2E_PKI=$PKI

rc=0
run_stage() { # stage phases [playwright args...]
	stage=$1; phases=$2; shift 2
	stop_server
	seed "$phases"
	start_server
	echo "=== stage $stage"
	cd "$ROOT/web"
	case $MODE in
	pw) CUTOVER_STAGE=$stage $PW_CLI test -c zz-pw.local.config.ts --project=chromium e2e/cutover-real.spec.ts "$@" ;;
	headed) CUTOVER_STAGE=$stage E2E_HEADED=1 xvfb-run -a -s "-screen 0 1440x1000x24" $PW_CLI test -c zz-pw.local.config.ts --project=chromium e2e/cutover-real.spec.ts "$@" ;;
	*) echo "mode pw|headed" >&2; exit 2 ;;
	esac
}
export CUTOVER_ORG CUTOVER_PROJECT CUTOVER_SOURCE CUTOVER_SOURCE_VERSION
# The stages are cumulative (each commits the next transitions of the same cutover): stop at the first failing one.
for stage in "shadow shadow" "new_active quiescing_old,barrier_verified,new_active" "old_active rollback_quiescing,old_active"; do
	# shellcheck disable=SC2086
	run_stage $stage "$@" || { rc=$?; break; }
done
exit $rc

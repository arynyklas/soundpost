#!/bin/bash
# Wave 4b: a REAL disaster restore for the browser test, on the Linux worker VM (run from the checkout root through vm.py start).
#   restore.sh MODE PLAYWRIGHT_ARGS...      MODE is pw (headless) or headed (xvfb, screenshots + traces in $OUT)
# `h.sh up` gives the SOURCE installation (bootstrapped owner e2e-owner); e2e-provision/restore-seed.spec.ts seeds it through the real
# admin routes (organization, project, reader, administrator, SSO provider, a destination and a source); the stopped installation is
# backed up (`soundpost backup create`), restored into a fresh root, activated and served; then the named specs run against it.
set -eu
export E2E_P=l3w4
MODE=$1; shift
ROOT=$(pwd)
P=l3w4; PORT=${E2E_PORT:-18711}
T=/tmp/$P-$PORT; PKI=$T/pki; DATA=$T/data; W=$T/restore; DST=$W/dst
BIN=${SOUNDPOST_BIN:-/tmp/$P-soundpost}
CHROME=${CHROME:-$HOME/tools/chrome-linux156/chrome-linux64/chrome}
OUT=${E2E_OUT:-$HOME/out/$P}
ORIGIN=https://127.0.0.1:$PORT
H="sh $ROOT/web/e2e-harness/h.sh"
PW_CLI="node node_modules/@playwright/test/cli.js"

stop_restored() {
	if [ -f "$W/server.pid" ]; then
		pid=$(cat "$W/server.pid")
		kill "$pid" 2>/dev/null || true
		i=0; while kill -0 "$pid" 2>/dev/null && [ $i -lt 30 ]; do i=$((i + 1)); sleep 1; done
		kill -9 "$pid" 2>/dev/null || true
		rm -f "$W/server.pid"
	fi
}
trap 'stop_restored; $H down >/dev/null 2>&1 || true' EXIT

$H prep >/dev/null
$H up
rm -rf "$W"; mkdir -p "$W/keys" "$W/dest" "$W/authority" "$OUT"; chmod 700 "$W" "$W/keys" "$W/dest" "$W/authority"
export NODE_EXTRA_CA_CERTS=$PKI/ca.pem SOUNDPOST_TEST_ORIGIN=$ORIGIN SOUNDPOST_SCOPE_EMAIL=e2e-owner@example.test SOUNDPOST_SCOPE_PASSWORD='e2e instance owner password 2026'
export E2E_SPKI=$(cat "$PKI/spki.txt") CHROME E2E_OUT_DIR=$OUT/test-results E2E_EVIDENCE_DIR=$OUT/evidence
( cd "$ROOT/web" && PROVISION_OUT=$W/seed.env $PW_CLI test -c zz-pw.provision.config.ts e2e-provision/restore-seed.spec.ts )
$H down >/dev/null
# back up the stopped installation, restore it into a fresh root, activate it
"$BIN" backup keygen --key-dir "$W/keys" --id data-kek
"$BIN" backup keygen --key-dir "$W/keys" --id secret-kek
"$BIN" backup authority-keygen --out "$W/authority-keys.json" --restricted-out "$W/authority-restricted.json" --id authority-1
"$BIN" backup authority-init --data-dir "$DATA" --authority-keys "$W/authority-keys.json" --authority-dir "$W/authority"
SOUNDPOST_ADMIN_PASSWORD='e2e instance owner password 2026' "$BIN" backup create --data-dir "$DATA" --admin-email e2e-owner@example.test --key-dir "$W/keys" --data-kek data-kek --secret-kek secret-kek --authority-keys "$W/authority-keys.json" --authority-dir "$W/authority" --dest-dir "$W/dest"
ID=$(ls "$W/dest/backups" | head -1)
[ -n "$ID" ] || { echo "no backup" >&2; exit 1; }
"$BIN" backup restore --backup-id "$ID" --root "$DST" --key-dir "$W/keys" --authority-keys "$W/authority-restricted.json" --dest-dir "$W/dest" --authority-dir "$W/authority"
"$BIN" backup activate --root "$DST" --authority-keys "$W/authority-restricted.json" --authority-dir "$W/authority"
SSL_CERT_FILE=$PKI/ca.pem setsid nohup "$BIN" serve --mode single --data-dir "$DST" --listen 127.0.0.1:$PORT --tls-cert "$PKI/leaf.pem" --tls-key "$PKI/leaf.key" --web-dir "$ROOT/web/dist" >"$W/server.log" 2>&1 </dev/null &
echo $! >"$W/server.pid"
i=0
until [ "$(curl -s --cacert "$PKI/ca.pem" -o /dev/null -w '%{http_code}' "$ORIGIN/readyz")" = 200 ]; do
	i=$((i + 1)); [ $i -gt 90 ] && { echo "restored server not ready" >&2; grep -v raft "$W/server.log" >&2; exit 1; }; sleep 1
done
until [ -s "$DST/bootstrap.token" ]; do i=$((i + 1)); [ $i -gt 120 ] && { echo "no recovery token" >&2; exit 1; }; sleep 1; done
echo "restored server pid $(cat "$W/server.pid") origin $ORIGIN backup $ID"
. "$W/seed.env"
export SOUNDPOST_RESTORE_TOKEN=$(cat "$DST/bootstrap.token")
export E2E_SERVER_LOG=$W/server.log E2E_DATA_DIR=$DST E2E_BIN=$BIN E2E_ORIGIN_PORT=$PORT E2E_PKI=$PKI
cd "$ROOT/web"
case $MODE in
pw) exec_rc=0; $PW_CLI test -c zz-pw.local.config.ts --project=chromium "$@" || exec_rc=$? ;;
headed) exec_rc=0; E2E_HEADED=1 xvfb-run -a -s "-screen 0 1440x1000x24" $PW_CLI test -c zz-pw.local.config.ts --project=chromium "$@" || exec_rc=$? ;;
*) echo "mode pw|headed" >&2; exit 2 ;;
esac
exit $exec_rc

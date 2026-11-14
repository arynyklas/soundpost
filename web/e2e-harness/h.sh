#!/bin/sh
# Lane 3 wave 2 real-browser harness for the Linux worker VM (run from the checkout root through tools vm.py start).
# Real `soundpost serve --mode single` over HTTPS with a private CA; Linux Chrome 156 trusts the private leaf by SPKI pin
# (--ignore-certificate-errors-spki-list), Go and Node trust it through SSL_CERT_FILE / NODE_EXTRA_CA_CERTS.
#   h.sh prep            install web deps, build binaries + web dist (once per run)
#   h.sh up [oidc]       fresh server (+ OIDC fixture when "oidc"), bootstrap the owner, provision accounts
#   h.sh pw ARGS...      headless playwright (chromium project) with ARGS
#   h.sh headed ARGS...  headed playwright under xvfb, screenshots + traces kept in $OUT
#   h.sh down            stop server and fixture
set -eu
ROOT=$(pwd)
P=${E2E_P:-l3w2}
PORT=${E2E_PORT:-18711}
OPORT=${E2E_OIDC_PORT:-18799}
T=/tmp/$P-$PORT
PKI=$T/pki
DATA=$T/data
BIN=${SOUNDPOST_BIN:-/tmp/$P-soundpost}
CHROME=${CHROME:-$HOME/tools/chrome-linux156/chrome-linux64/chrome}
OUT=${E2E_OUT:-$HOME/out/$P}
ORIGIN=https://127.0.0.1:$PORT
mkdir -p "$T" "$OUT"

pki() {
	rm -rf "$PKI"; mkdir -p "$PKI"; cd "$PKI"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.key -out ca.pem -days 2 -subj "/CN=Soundpost l3w2 e2e private CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout leaf.key -out leaf.csr -subj "/CN=localhost" 2>/dev/null
	printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n" >ext.cnf
	openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out leaf.pem -days 2 -extfile ext.cnf 2>/dev/null
	openssl x509 -in leaf.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64 >spki.txt
	cd "$ROOT"
}

prep() {
	( cd "$ROOT" && pnpm install --frozen-lockfile --filter @soundpost/web... 2>&1 | tail -3 )
	# E2E_WIRE_HEALTH=1 applies, to this run's VM copy only, the one-line wiring the parent applies to internal/appcore/app.go:
	# investigator.WithHealth(c) right after the investigator is built.
	if [ "${E2E_WIRE_HEALTH:-}" = 1 ] && ! grep -q 'investigator.WithHealth(c)' "$ROOT/internal/appcore/app.go"; then
		sed -i 's|^\tincidentService, e := incidents.New(c, releaseActionClock{})|\tinvestigator.WithHealth(c)\n&|' "$ROOT/internal/appcore/app.go"
		grep -q 'investigator.WithHealth(c)' "$ROOT/internal/appcore/app.go" || { echo "health wiring did not apply" >&2; exit 1; }
	fi
	( cd "$ROOT" && go build -o "$BIN" ./cmd/soundpost )
	( cd "$ROOT/web" && node node_modules/typescript/bin/tsc -p tsconfig.json && node node_modules/vite/bin/vite.js build 2>&1 | tail -2 )
	echo prep-ok
}

stop_pid() {
	f=$1
	[ -f "$f" ] || return 0
	pid=$(cat "$f")
	if kill -0 "$pid" 2>/dev/null; then
		kill "$pid"; i=0
		while kill -0 "$pid" 2>/dev/null && [ $i -lt 30 ]; do i=$((i + 1)); sleep 1; done
		kill -0 "$pid" 2>/dev/null && kill -9 "$pid" || true
	fi
	rm -f "$f"
}
down() { stop_pid "$T/server.pid"; stop_pid "$T/oidc.pid"; echo down; }

up() {
	down >/dev/null
	pki
	issuer=https://localhost:$OPORT
	if [ "${1:-}" = oidc ]; then
		( cd "$ROOT" && go build -o "$T/oidc" ./web/fixtures/oidc )
		setsid nohup "$T/oidc" --listen 127.0.0.1:$OPORT --issuer "$issuer" --callback "$ORIGIN/api/v1/oidc/callback" --tls-cert "$PKI/leaf.pem" --tls-key "$PKI/leaf.key" >"$T/oidc.log" 2>&1 </dev/null &
		echo $! >"$T/oidc.pid"; sleep 2
	fi
	rm -rf "$DATA"; mkdir -p "$DATA"
	SSL_CERT_FILE=$PKI/ca.pem setsid nohup "$BIN" serve --mode single --data-dir "$DATA" --listen 127.0.0.1:$PORT --tls-cert "$PKI/leaf.pem" --tls-key "$PKI/leaf.key" --web-dir "$ROOT/web/dist" ${SERVE_ARGS:-} >"$T/server.log" 2>&1 </dev/null &
	echo $! >"$T/server.pid"
	i=0
	until [ "$(curl -s --cacert "$PKI/ca.pem" -o /dev/null -w '%{http_code}' "$ORIGIN/readyz")" = 200 ]; do
		i=$((i + 1)); [ $i -gt 60 ] && { echo "not ready" >&2; cat "$T/server.log" >&2; exit 1; }; sleep 1
	done
	i=0
	until [ -s "$DATA/bootstrap.token" ]; do i=$((i + 1)); [ $i -gt 30 ] && { echo "no bootstrap token" >&2; exit 1; }; sleep 1; done
	TOKEN=$(cat "$DATA/bootstrap.token")
	code=$(curl -s --cacert "$PKI/ca.pem" -o "$T/bootstrap.json" -w '%{http_code}' -H "Origin: $ORIGIN" -H "Content-Type: application/json" -X POST "$ORIGIN/api/v1/bootstrap" -d "{\"Token\":\"$TOKEN\",\"Email\":\"e2e-owner@example.test\",\"Password\":\"e2e instance owner password 2026\"}")
	[ "$code" = 200 ] || { echo "bootstrap failed: HTTP $code" >&2; cat "$T/bootstrap.json" >&2; exit 1; }
	rm -f "$T/bootstrap.json"
	cfgs
	SOUNDPOST_OIDC_ISSUER=$issuer PROVISION_OUT=$T/provision.env pw_env exec_pw -c zz-pw.provision.config.ts e2e-provision/provision.spec.ts
	echo "up pid $(cat "$T/server.pid") origin $ORIGIN"
}

cfgs() {
	cd "$ROOT/web"
	cat >zz-pw.local.config.ts <<'XX'
import base from './playwright.config';
const args=['--ignore-certificate-errors-spki-list='+process.env.E2E_SPKI];
const headed=process.env.E2E_HEADED==='1';
export default {...base,outputDir:process.env.E2E_OUT_DIR||'test-results',use:{...base.use,...(headed?{headless:false,screenshot:'on',trace:'on'}:{})},projects:base.projects.filter((p)=>p.name==='chromium').map((p)=>({...p,use:{...p.use,launchOptions:{executablePath:process.env.CHROME,args,...(headed?{slowMo:120}:{})}}}))};
XX
	cat >zz-pw.provision.config.ts <<'XX'
import base from './playwright.provision.config';
const args=['--ignore-certificate-errors-spki-list='+process.env.E2E_SPKI];
export default {...base,projects:base.projects.map((p)=>({...p,use:{...p.use,launchOptions:{executablePath:process.env.CHROME,args}}}))};
XX
	cd "$ROOT"
}

pw_env() {
	export NODE_EXTRA_CA_CERTS=$PKI/ca.pem SOUNDPOST_TEST_ORIGIN=$ORIGIN SOUNDPOST_SCOPE_EMAIL=e2e-owner@example.test SOUNDPOST_SCOPE_PASSWORD='e2e instance owner password 2026'
	export E2E_SPKI=$(cat "$PKI/spki.txt") CHROME E2E_SERVER_LOG=$T/server.log E2E_DATA_DIR=$DATA E2E_BIN=$BIN E2E_ORIGIN_PORT=$PORT E2E_PKI=$PKI E2E_OUT_DIR=${E2E_OUT_DIR:-$OUT/test-results} E2E_EVIDENCE_DIR=${E2E_EVIDENCE_DIR:-$OUT/evidence}
	[ -f "$T/provision.env" ] && . "$T/provision.env"
	"$@"
}
exec_pw() { ( cd "$ROOT/web" && exec node node_modules/@playwright/test/cli.js test "$@" ); }

case "${1:-}" in
prep) prep ;;
up) shift; up "$@" ;;
down) down ;;
pw) shift; cfgs; case " $* " in *" --project"*) ;; *) set -- --project=chromium "$@" ;; esac; pw_env exec_pw -c zz-pw.local.config.ts "$@" ;;
headed) shift; cfgs; E2E_HEADED=1 pw_env xvfb-run -a -s "-screen 0 1440x1000x24" sh -c "cd '$ROOT/web' && exec node node_modules/@playwright/test/cli.js test -c zz-pw.local.config.ts --project=chromium \"\$@\"" sh "$@" ;;
run) shift; mode=$1; shift; oidc=$1; shift; [ "$oidc" = oidc ] || oidc=""; rc=0; up $oidc && sh "$0" "$mode" "$@" || rc=$?; down >/dev/null; exit $rc ;;
*) echo "usage: $0 prep|up [oidc]|pw ARGS|headed ARGS|down" >&2; exit 2 ;;
esac

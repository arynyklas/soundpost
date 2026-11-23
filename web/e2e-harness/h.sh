#!/bin/sh
# Lane 3 wave 2 real-browser harness for the Linux worker VM (run from the checkout root through tools vm.py start).
# Real `soundpost serve --mode single` over HTTPS with a private CA; Linux Chrome 156 trusts the private leaf by SPKI pin
# (--ignore-certificate-errors-spki-list), Go and Node trust it through SSL_CERT_FILE / NODE_EXTRA_CA_CERTS.
#   h.sh prep            install web deps, build binaries + web dist, take the real native CPU capture (once per run)
#   h.sh sched           the real scheduler capture (sched_switch/sched_wakeup of a real workload); needs tracefs + CAP_PERFMON, i.e. root; the file
#                        is copied to the browser host and named by E2E_NATIVE_SCHED_PROFILE (the real-scheduler case of replay-profile.spec.ts)
#   h.sh up [oidc]       fresh server (+ OIDC fixture when "oidc"), bootstrap the owner, provision accounts
#   h.sh demo            fresh server with the DEMO data set (e2e-provision/demo.spec.ts: Example Co, 3 projects, named people, 7 incidents, issue with mapped
#                        frames, releases, traces, metrics with a gap, jobs, replays, profile) through the real routes; the server stays up; needs `prep`
#   h.sh shots DIR       screenshots of every console screen, dark and light, of the running demo server into DIR (e2e-provision/shots.spec.ts)
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
	printf "subjectAltName=DNS:localhost,IP:127.0.0.1${E2E_NOTIFY_IP:+,IP:$E2E_NOTIFY_IP}\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n" >ext.cnf
	openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out leaf.pem -days 2 -extfile ext.cnf 2>/dev/null
	openssl x509 -in leaf.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64 >spki.txt
	cd "$ROOT"
}

prep() {
	# The Node and Bun SDK packages are installed too: the SDK profile drivers (web/e2e/support/sdk_profile_js.ts) import them from source.
	# The reference estate's page (examples/reference/web, Vite) and packages/build are installed for web/e2e/support/estate.ts.
	( cd "$ROOT" && pnpm install --frozen-lockfile --filter @soundpost/web... --filter @soundpost/browser... --filter @soundpost/node... --filter @soundpost/bun... --filter @soundpost/reference-web... --filter @soundpost/build... 2>&1 | tail -3 )
	# E2E_WIRE_HEALTH=1 applies, to this run's VM copy only, the one-line wiring the parent applies to internal/appcore/app.go:
	# investigator.WithHealth(c) right after the investigator is built.
	if [ "${E2E_WIRE_HEALTH:-}" = 1 ] && ! grep -q 'investigator.WithHealth(c)' "$ROOT/internal/appcore/app.go"; then
		sed -i 's|^\tincidentService, e := incidents.New(c, releaseActionClock{})|\tinvestigator.WithHealth(c)\n&|' "$ROOT/internal/appcore/app.go"
		grep -q 'investigator.WithHealth(c)' "$ROOT/internal/appcore/app.go" || { echo "health wiring did not apply" >&2; exit 1; }
	fi
	# E2E_WIRE_TRACE_LINKS=1 applies, to this run's VM copy only, the one-line wiring the parent applies to internal/appcore/app.go:
	# the trace route resolves span links through the C04 resolver built a few lines above it.
	if [ "${E2E_WIRE_TRACE_LINKS:-}" = 1 ] && ! grep -q 'NewStorageSpanSource(engine)).WithLinks(resolver)' "$ROOT/internal/appcore/app.go"; then
		sed -i 's|^\ttraces := httpapi.NewTraces(httpapi.NewStorageSpanSource(engine))$|\ttraces := httpapi.NewTraces(httpapi.NewStorageSpanSource(engine)).WithLinks(resolver)|' "$ROOT/internal/appcore/app.go"
		grep -q 'NewStorageSpanSource(engine)).WithLinks(resolver)' "$ROOT/internal/appcore/app.go" || { echo "trace link wiring did not apply" >&2; exit 1; }
	fi
	# E2E_WIRE_TRACE_ISSUES=1 applies, to this run's VM copy only, the wiring the parent applies to internal/appcore/app.go:
	# bindIssueLinks(c, resolver) (internal/appcore/link_issues.go) right after the resolver is built, so a trace error occurrence links to its issue.
	if [ "${E2E_WIRE_TRACE_ISSUES:-}" = 1 ] && ! grep -q 'bindIssueLinks(c, resolver)' "$ROOT/internal/appcore/app.go"; then
		sed -i 's|^\tinvestigator, e := httpapi.NewInvestigator(a, queryEngine, resolver)$|\tif e = bindIssueLinks(c, resolver); e != nil {\n\t\treturn fail(e)\n\t}\n&|' "$ROOT/internal/appcore/app.go"
		grep -q 'bindIssueLinks(c, resolver)' "$ROOT/internal/appcore/app.go" || { echo "issue link wiring did not apply" >&2; exit 1; }
	fi
	# E2E_FAULTS=1 builds the server with the soundpost_faults tag: it then reads shard-removal requests from $T/fault (cmd/soundpost/faultcontrol.go).
	# The served binary is built the way the release builds it, CGO_ENABLED=0 (static). Its symbolication worker is this same binary re-executed under a
	# seccomp allowlist, and a build with cgo (what a plain `go build` makes where a C compiler exists) is dynamically linked against glibc, a different
	# program than the one released: its worker died intermittently (SIGABRT) and a frame read worker_failure. A binary that is not CGO_ENABLED=0 is refused.
	( cd "$ROOT" && CGO_ENABLED=0 go build ${E2E_FAULTS:+-tags soundpost_faults} -o "$BIN" ./cmd/soundpost && go version -m "$BIN" | grep -q 'CGO_ENABLED=0' ) || { echo "the served binary is not a CGO_ENABLED=0 build" >&2; exit 1; }
	( cd "$ROOT/web" && node node_modules/typescript/bin/tsc -p tsconfig.json && node node_modules/vite/bin/vite.js build 2>&1 | tail -2 )
	# The suite's native profile is a REAL capture (fixtures/nativeperf/e2eprofile: perf_event_open software CPU-clock samples of the compiled
	# fixtures/nativeperf/cpu/loop.c through the in-process native helper, assembled by nativeperf.AssembleProfile). No fallback: a host that
	# cannot capture (perf_event_paranoid > 1, a refused start, no sample) fails prep with the helper's reason. 1730000000000000000 is T0 of
	# web/e2e/support/real.ts: only the wall anchor of the clock pair is mapped to it so every spec's T0-based window contains the profile.
	( cd "$ROOT" && cc -O2 -g -fno-pie -no-pie -fno-omit-frame-pointer -pthread -Wl,--build-id -o "$T/native-loop" fixtures/nativeperf/cpu/loop.c \
		&& go build -o "$T/native-capture" ./fixtures/nativeperf/e2eprofile \
		&& "$T/native-capture" -workload "$T/native-loop" -out "$T/native-profile.json" -wall-ns 1730000000000000000 -seconds 6 ) || { echo "the real native capture failed (see above): no synthetic profile is substituted" >&2; exit 1; }
	echo prep-ok
}

# sched: the REAL scheduler capture of the real-scheduler spec (replay-profile.spec.ts). The compiled fixtures/nativeperf/export/workloads/cpu_wait.c (one thread burns CPU and naps, a second blocks
# on a condition variable and burns when woken) runs under the in-process native helper with the CPU sampler AND the scheduler tracepoints (sched_switch/sched_wakeup); the per-session
# correlator turns the real events into blocked/runnable intervals, assembled with the CPU samples into $T/native-sched-profile.json. It needs tracefs and CAP_PERFMON (run it as root on
# a host like that); a host without them fails here with the probe's reason and no synthetic interval is substituted. Copy the file to the host that runs the browsers and name it with
# E2E_NATIVE_SCHED_PROFILE. E2E_SCHED_OFF=1 takes the same capture with the scheduler tracepoints disabled: the CPU-only profile the real-scheduler spec must refuse (its red).
sched() {
	flag=-scheduler; [ -n "${E2E_SCHED_OFF:-}" ] && flag=
	( cd "$ROOT" && cc -O2 -g -fno-pie -no-pie -fno-omit-frame-pointer -fno-optimize-sibling-calls -pthread -Wl,--build-id -o "$T/native-cpu-wait" fixtures/nativeperf/export/workloads/cpu_wait.c \
		&& CGO_ENABLED=0 go build -o "$T/native-capture" ./fixtures/nativeperf/e2eprofile \
		&& "$T/native-capture" -workload "$T/native-cpu-wait" -hot burn $flag -out "$T/native-sched-profile.json" -wall-ns 1730000000000000000 -seconds 4 ) || { echo "the real scheduler capture failed (see above): no synthetic profile is substituted" >&2; exit 1; }
	echo "sched-ok $T/native-sched-profile.json"
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
down() {
	if [ -f "$T/server.unit" ]; then systemctl --user stop "$(cat "$T/server.unit")" 2>/dev/null || true; rm -f "$T/server.unit" "$T/server.pid"; fi
	stop_pid "$T/server.pid"; stop_pid "$T/oidc.pid"; echo down
}

up() {
	down >/dev/null
	pki
	issuer=https://localhost:$OPORT
	if [ "${1:-}" = oidc ]; then
		( cd "$ROOT" && go build -o "$T/oidc" ./web/fixtures/oidc )
		setsid nohup "$T/oidc" --listen 127.0.0.1:$OPORT --issuer "$issuer" --callback "$ORIGIN/api/v1/oidc/callback" --tls-cert "$PKI/leaf.pem" --tls-key "$PKI/leaf.key" >"$T/oidc.log" 2>&1 </dev/null &
		echo $! >"$T/oidc.pid"; sleep 2
	fi
	rm -rf "$DATA" "$T/fault"; mkdir -p "$DATA" "$T/fault"
	notify_args=""
	# E2E_NOTIFY_IP (a private address of this host): the notification worker may reach exactly that address, trusts the private CA
	# and gives up on a send after 3s, so a receiver that never answers yields a real uncertain delivery.
	[ -n "${E2E_NOTIFY_IP:-}" ] && notify_args="--notify-egress-allow $E2E_NOTIFY_IP/32 --notify-ca-file $PKI/ca.pem --notify-send-timeout 3s"
	if [ "${E2E_SANDBOX:-}" = 1 ]; then
		# The native symbolication sandbox needs an empty delegated cgroup v2 subtree (docs/operations/symbolication.md): run the server as a
		# transient user unit with Delegate=memory pids and DelegateSubgroup=main, exactly as the shipped unit does. Without it every frame
		# answers sandbox_unavailable and no frame can be mapped.
		UNIT=$P-$PORT
		: >"$T/server.log"
		CGROOT=/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/app.slice/$UNIT.service
		systemd-run --user --collect --quiet --unit="$UNIT" -p "Delegate=memory pids" -p DelegateSubgroup=main -p "StandardOutput=append:$T/server.log" -p "StandardError=append:$T/server.log" -E "SSL_CERT_FILE=$PKI/ca.pem" -E "SOUNDPOST_FAULT_DIR=$T/fault" "$BIN" serve --mode single --data-dir "$DATA" --listen 127.0.0.1:$PORT --tls-cert "$PKI/leaf.pem" --tls-key "$PKI/leaf.key" --web-dir "$ROOT/web/dist" --symbolicate-cgroup-root "$CGROOT" $notify_args ${SERVE_ARGS:-}
		echo "$UNIT" >"$T/server.unit"
		systemctl --user show -p MainPID --value "$UNIT" >"$T/server.pid"
	else
		SOUNDPOST_FAULT_DIR=$T/fault SSL_CERT_FILE=$PKI/ca.pem setsid nohup "$BIN" serve --mode single --data-dir "$DATA" --listen 127.0.0.1:$PORT --tls-cert "$PKI/leaf.pem" --tls-key "$PKI/leaf.key" --web-dir "$ROOT/web/dist" $notify_args ${SERVE_ARGS:-} >"$T/server.log" 2>&1 </dev/null &
		echo $! >"$T/server.pid"
	fi
	i=0
	until [ "$(curl -s --cacert "$PKI/ca.pem" -o /dev/null -w '%{http_code}' "$ORIGIN/readyz")" = 200 ]; do
		i=$((i + 1)); [ $i -gt "${E2E_READY_WAIT:-60}" ] && { echo "not ready" >&2; cat "$T/server.log" >&2; exit 1; }; sleep 1
	done
	i=0
	if [ "${E2E_SANDBOX:-}" = 1 ] && ! grep -q 'symbolicator: ready' "$T/server.log"; then echo "the symbolication sandbox is not ready" >&2; grep symbolicator "$T/server.log" >&2; exit 1; fi
	until [ -s "$DATA/bootstrap.token" ]; do i=$((i + 1)); [ $i -gt 30 ] && { echo "no bootstrap token" >&2; exit 1; }; sleep 1; done
	TOKEN=$(cat "$DATA/bootstrap.token")
	code=$(curl -s --cacert "$PKI/ca.pem" -o "$T/bootstrap.json" -w '%{http_code}' -H "Origin: $ORIGIN" -H "Content-Type: application/json" -X POST "$ORIGIN/api/v1/bootstrap" -d "{\"Token\":\"$TOKEN\",\"Email\":\"e2e-owner@example.test\",\"Password\":\"e2e instance owner password 2026\"}")
	[ "$code" = 200 ] || { echo "bootstrap failed: HTTP $code" >&2; cat "$T/bootstrap.json" >&2; exit 1; }
	rm -f "$T/bootstrap.json"
	cfgs
	# The provisioning spec is Chromium-only (it runs with the leaf's SPKI pin), whatever browser the run is for: never inside the WebKit trust namespace.
	E2E_BROWSER=chromium SOUNDPOST_OIDC_ISSUER=$issuer PROVISION_OUT=$T/provision.env pw_env exec_pw -c zz-pw.provision.config.ts e2e-provision/provision.spec.ts
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
	# E2E_BROWSER=firefox|webkit selects the Playwright-bundled browser (PLAYWRIGHT_BROWSERS_PATH). Neither takes Chrome's SPKI pin flag, and neither runs with
	# ignoreHTTPSErrors: they verify the loopback origin's certificate against the CA THIS run generated, which pw_env makes them trust (trust_files):
	# Firefox through an enterprise policy (Certificates.Install) and WebKit through a private mount namespace whose CA bundle also lists the run CA.
	cat >zz-pw.other.config.ts <<'XX'
import base from './playwright.config';
const headed=process.env.E2E_HEADED==='1';
const name=process.env.E2E_BROWSER||'firefox';
export default {...base,outputDir:process.env.E2E_OUT_DIR||'test-results',use:{...base.use,...(headed?{headless:false,screenshot:'on',trace:'on'}:{})},projects:base.projects.filter((p)=>p.name===name).map((p)=>({...p,use:{...p.use,launchOptions:{...(headed?{slowMo:120}:{})}}}))};
XX
	cat >zz-pw.provision.config.ts <<'XX'
import base from './playwright.provision.config';
const args=['--ignore-certificate-errors-spki-list='+process.env.E2E_SPKI];
export default {...base,projects:base.projects.map((p)=>({...p,use:{...p.use,launchOptions:{executablePath:process.env.CHROME,args}}}))};
XX
	cd "$ROOT"
}

# trust_files: what Firefox and WebKit need to verify this run's private CA (Chromium has the leaf's SPKI pin instead). Firefox reads the policy file named by
# PLAYWRIGHT_FIREFOX_POLICIES_JSON (a Playwright Firefox feature) and installs the CA into its own store. WebKit has no certificate switch and reads the system
# CA bundle; with no root to change it, in-trust-ns.sh runs the test runner (and so the browser) in a private user+mount namespace where the bundle's directory is
# overlaid with one that also lists the run CA. Nothing outside that namespace changes, and the overlay dies with the run.
trust_files() {
	printf '{"policies":{"Certificates":{"Install":["%s"]}}}\n' "$PKI/ca.pem" >"$PKI/firefox-policies.json"
	export PLAYWRIGHT_FIREFOX_POLICIES_JSON=$PKI/firefox-policies.json
	for bundle in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem; do [ -r "$bundle" ] && break; bundle=""; done
	if [ -n "$bundle" ] && [ "${E2E_WEBKIT_TRUST:-ns}" = ns ]; then
		rm -rf "$PKI/trust-overlay"; mkdir -p "$PKI/trust-overlay"
		cat "$bundle" "$PKI/ca.pem" >"$PKI/trust-overlay/$(basename "$bundle")"
		export E2E_TRUST_OVERLAY=$PKI/trust-overlay E2E_TRUST_DIR=$(dirname "$bundle")
	else
		# E2E_WEBKIT_TRUST=system: the host's own CA bundle already lists the run CA (installed by an administrator).
		unset E2E_TRUST_OVERLAY E2E_TRUST_DIR
	fi
}

# firefox_fonts: Firefox's content-process sandbox reads fonts only from the SYSTEM font directories and $XDG_DATA_HOME/fonts. A host whose fonts live anywhere
# else (a user-space extraction, no root, no /usr/share/fonts) leaves the sandboxed process with none: the first text shaping of a page then takes ~9 s
# (measured on a lab VM: native profile view 9084 ms against 69 ms) and the 5 s expectations of accessibility.spec.ts and replay-profile.spec.ts fail while the
# same specs pass headed. HOST REQUIREMENT (docs/user/investigation-acceptance.md): a font directory with at least one .ttf/.otf/.pfb/.pcf file, named by
# E2E_FONT_DIR (default /usr/share/fonts). The harness copies it to $PKI/xdg/fonts and points XDG_DATA_HOME there, so the fonts Firefox sees are the same on
# every host; a host without any font is refused here instead of failing later as a timeout.
firefox_fonts() {
	src=${E2E_FONT_DIR:-/usr/share/fonts}
	if [ -z "$(find -L "$src" -type f \( -name '*.ttf' -o -name '*.otf' -o -name '*.pfb' -o -name '*.pcf*' \) 2>/dev/null | head -1)" ]; then
		echo "firefox needs a font directory: E2E_FONT_DIR (default /usr/share/fonts) '$src' holds no font file" >&2
		exit 1
	fi
	rm -rf "$PKI/xdg"; mkdir -p "$PKI/xdg/fonts"
	cp -RL "$src"/. "$PKI/xdg/fonts/"
	export XDG_DATA_HOME=$PKI/xdg
}

pw_env() {
	export NODE_EXTRA_CA_CERTS=$PKI/ca.pem SOUNDPOST_TEST_ORIGIN=$ORIGIN SOUNDPOST_SCOPE_EMAIL=e2e-owner@example.test SOUNDPOST_SCOPE_PASSWORD='e2e instance owner password 2026'
	export E2E_FAULT_DIR=$T/fault E2E_SPKI=$(cat "$PKI/spki.txt") CHROME E2E_SERVER_LOG=$T/server.log E2E_DATA_DIR=$DATA E2E_BIN=$BIN E2E_ORIGIN_PORT=$PORT E2E_PKI=$PKI E2E_NATIVE_PROFILE=$T/native-profile.json E2E_OUT_DIR=${E2E_OUT_DIR:-$OUT/test-results} E2E_EVIDENCE_DIR=${E2E_EVIDENCE_DIR:-$OUT/evidence}
	# The real scheduler capture (see `sched`): taken on this host, or copied from a root host and named by E2E_NATIVE_SCHED_PROFILE. Absent, only the spec that needs it fails.
	[ -n "${E2E_NATIVE_SCHED_PROFILE:-}" ] || ! [ -f "$T/native-sched-profile.json" ] || export E2E_NATIVE_SCHED_PROFILE=$T/native-sched-profile.json
	[ -f "$T/provision.env" ] && . "$T/provision.env"
	trust_files
	[ "${E2E_BROWSER:-chromium}" = firefox ] && firefox_fonts
	"$@"
}
exec_pw() { ( cd "$ROOT/web" && exec sh "$ROOT/web/e2e-harness/in-trust-ns.sh" node node_modules/@playwright/test/cli.js test "$@" ); }

case "${1:-}" in
prep) prep ;;
sched) sched ;;
up) shift; up "$@" ;;
demo) shift; export E2E_SANDBOX=${E2E_SANDBOX:-1}; up "$@"; cfgs; E2E_BROWSER=chromium DEMO_OUT=$T/demo.json pw_env exec_pw -c zz-pw.provision.config.ts e2e-provision/demo.spec.ts; echo "demo-ok $T/demo.json" ;;
shots) shift; [ -n "${1:-}" ] || { echo "usage: $0 shots DIR" >&2; exit 2; }; mkdir -p "$1"; cfgs; E2E_BROWSER=chromium DEMO_JSON=$T/demo.json SHOTS_OUT=$(cd "$1" && pwd) pw_env exec_pw -c zz-pw.provision.config.ts e2e-provision/shots.spec.ts ;;
down) down ;;
pw) shift; cfgs; b=${E2E_BROWSER:-chromium}; cfg=zz-pw.local.config.ts; [ "$b" = chromium ] || cfg=zz-pw.other.config.ts; case " $* " in *" --project"*) ;; *) set -- --project=$b "$@" ;; esac; pw_env exec_pw -c $cfg "$@" ;;
headed) shift; cfgs; b=${E2E_BROWSER:-chromium}; cfg=zz-pw.local.config.ts; [ "$b" = chromium ] || cfg=zz-pw.other.config.ts; E2E_HEADED=1 pw_env xvfb-run -a -s "-screen 0 1440x1000x24" sh -c "cd '$ROOT/web' && exec sh '$ROOT/web/e2e-harness/in-trust-ns.sh' node node_modules/@playwright/test/cli.js test -c $cfg --project=$b \"\$@\"" sh "$@" ;;
run) shift; mode=$1; shift; oidc=$1; shift; [ "$oidc" = oidc ] || oidc=""; rc=0; up $oidc && sh "$0" "$mode" "$@" || rc=$?; down >/dev/null; exit $rc ;;
# suite ARGS: the whole committed suite (every spec but restore.spec.ts, which needs restore.sh, and cutover-real.spec.ts, which needs cutover.sh) with the OIDC fixture. The fault specs remove shards
# of the server FOR GOOD (server-states removes all 64, shard-loss half and all of them) and say they need a server of their own: every spec after
# one of them, on the same server, would meet a server whose data groups are gone (ingest answers 503). So the ordinary specs share one server and
# each fault spec gets a fresh one. The exit code is the first failing run's.
suite) shift; rc=0
	rest=$(cd "$ROOT/web" && ls e2e/*.spec.ts | grep -v -e '/restore.spec.ts$' -e '/cutover-real.spec.ts$' -e '/server-states.spec.ts$' -e '/shard-loss.spec.ts$' | tr '\n' ' ')
	# shellcheck disable=SC2086
	sh "$0" run pw oidc "$@" $rest || rc=$?
	for f in e2e/server-states.spec.ts e2e/shard-loss.spec.ts; do sh "$0" run pw oidc "$@" $f || { [ $rc -ne 0 ] || rc=$?; }; done
	exit $rc ;;
*) echo "usage: $0 prep|sched|up [oidc]|pw ARGS|headed ARGS|run MODE oidc|no ARGS|suite ARGS|down" >&2; exit 2 ;;
esac

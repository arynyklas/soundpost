#!/bin/sh
# Runs on a worker VM from the checkout root (through tools vm.py start; see .superpowers/sdd/approved-product/fe-evidence/shots.sh): prep (unless NOPREP=1),
# the demo data set (h.sh demo), the screenshots of every screen in both themes (h.sh shots) and a tarball of them.
#   usage: [NOPREP=1] demo-vm.sh RUN_ID
# Half the CPU of the VM: Go builds with -p=2 and GOMAXPROCS=4; one heavy run at a time through a lock.
set -eu
RUN=${1:?run id}
export E2E_SANDBOX=1 PLAYWRIGHT_BROWSERS_PATH=$HOME/pw-browsers PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS=1
[ -d "$HOME/sysroot" ] && export LD_LIBRARY_PATH=$HOME/sysroot/usr/lib/x86_64-linux-gnu FONTCONFIG_FILE=$HOME/sysroot/fonts.conf XDG_DATA_HOME=$HOME/sysroot/usr/share
export PATH=$HOME/xvfb/pathbin:/usr/local/bin:/usr/local/go/bin:/usr/bin:/bin:$HOME/.local/bin:$HOME/.bun/bin GOTOOLCHAIN=local GOFLAGS="-mod=readonly -p=2" GOMAXPROCS=4
export E2E_P=feshots E2E_PORT=${E2E_PORT:-18761} E2E_OUT=$HOME/out/feshots-$RUN
OUT=$HOME/out/feshots-$RUN/screens
mkdir -p "$OUT"
exec 9>/tmp/feshots-heavy.lock
flock 9
[ "${NOPREP:-}" = 1 ] || sh web/e2e-harness/h.sh prep
rc=0
sh web/e2e-harness/h.sh demo || rc=$?
if [ $rc -eq 0 ]; then sh web/e2e-harness/h.sh shots "$OUT" || rc=$?; fi
cp "/tmp/$E2E_P-$E2E_PORT/server.log" "$HOME/out/feshots-$RUN/server.log" 2>/dev/null || true
sh web/e2e-harness/h.sh down || true
tar czf "/tmp/feshots-$RUN.tgz" -C "$OUT" . && echo "tarball /tmp/feshots-$RUN.tgz"
exit $rc

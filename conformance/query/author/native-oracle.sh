#!/bin/bash
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
# Runs the PromQL evaluation phase and the LogQL metric phase against the pinned references on a host
# WITHOUT an OCI runtime (the worker VMs). The references are built natively from the sha256-verified
# upstream source archives named in source-lock.json, with the recipe of
# oracles/promql-prometheus-<v>.Dockerfile and oracles/logql-loki-3.5.2.Dockerfile (same driver
# sources, build tags and ldflags, Go toolchain pinned by GOTOOLCHAIN). Nothing is copied from upstream
# into the repository. An observation made this way is a native build of the pinned source archive, not
# the digest-locked OCI image; record it as such (D63).
#
#   conformance/query/author/native-oracle.sh build              # download, verify, build both Prometheus references
#   conformance/query/author/native-oracle.sh build-loki         # download, verify, build the Loki 3.5.2 driver
#   conformance/query/author/native-oracle.sh build-loki-shard-probe   # build conformance/query/author/logql-shard-probe (shard mapper / replica merge probe) in the same verified Loki tree
#   conformance/query/author/native-oracle.sh setup <repo-dir>   # copy of querycheck using them + a fake runtime
#   go run ./cmd/soundpost-querycheck compare --phase evaluation --cases ... \
#       --profiles promql-prometheus-3.1.0,promql-prometheus-3.13.5 --require-locked \
#       --runtime "$NATIVE_ORACLE_DIR/docker-shim"
#   conformance/query/author/native-oracle.sh run-logql <cases.json> <report.json>   # the logql-metric phase against the native Loki
#                                                  # driver (from the repository root, after `setup` of the same tree; the exit code is the compare's)
#
# Only the evaluation phase (Prometheus) and the LogQL phases the Go driver serves (logql-metric, pipeline,
# template; not the stock /usr/bin/loki) are served; the syntax and configuration phases need the real
# /bin/prometheus binaries of the images. NATIVE_ORACLE_DIR defaults to $HOME/native-oracle.
set -eu
W=${NATIVE_ORACLE_DIR:-$HOME/native-oracle}
mkdir -p "$W"

fetch() { # <dir> <commit> <sha256>
  [ -d "$W/$1" ] && return 0
  curl -fsSL -o "$W/$1.tgz" "https://codeload.github.com/prometheus/prometheus/tar.gz/$2"
  echo "$3  $W/$1.tgz" | sha256sum -c -
  mkdir -p "$W/$1" && tar -xzf "$W/$1.tgz" -C "$W/$1" --strip-components=1
}

build() { # <short> <tag> <version> <commit> <sha256> <toolchain>
  fetch "p$1" "$4" "$5"
  rm -rf "$W/p$1/_soundpost_evaluation" && mkdir -p "$W/p$1/_soundpost_evaluation"
  for f in "$REPO"/conformance/query/oracles/evaluation/*.go; do
    case $f in *_test.go) ;; *) cp "$f" "$W/p$1/_soundpost_evaluation/" ;; esac
  done
  (cd "$W/p$1" && GOTOOLCHAIN=$6 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS=-mod=readonly \
    go build -tags=soundpost_evaluation_oracle,$2 -trimpath \
    -ldflags="-X main.compiledProfile=promql-prometheus-$3 -X main.compiledCommit=$4 -X main.compiledSourceSHA256=$5" \
    -o "$W/evaluation-reference-$1" ./_soundpost_evaluation)
}

# The Loki driver is built from the source archive with go1.24.5 (the Dockerfile's digest-locked Go image),
# -mod=vendor, the bridge file copied into pkg/logql/log. The driver reads its time zone dataset from a
# path compiled in as /oracle-zoneinfo.zip in the image; the native build points it at the zoneinfo.zip of
# the same Go 1.24.5 toolchain.
build_loki() {
  LC=257d2f62bf8a81b44dea6fe88968d1d28c8e01e7
  LS=0db690662744694667c031a81d3e20cdd3a68a387a8050c8096bebbdf2ff8db2
  if [ ! -d "$W/loki" ]; then
    curl -fsSL -o "$W/loki.tgz" "https://codeload.github.com/grafana/loki/tar.gz/$LC"
    echo "$LS  $W/loki.tgz" | sha256sum -c -
    mkdir -p "$W/loki" && tar -xzf "$W/loki.tgz" -C "$W/loki" --strip-components=1
  fi
  rm -rf "$W/loki/_soundpost_logql" && mkdir -p "$W/loki/_soundpost_logql"
  for f in "$REPO"/conformance/query/oracles/logql-native/*.go; do
    case $f in *_test.go) ;; *) cp "$f" "$W/loki/_soundpost_logql/" ;; esac
  done
  cp "$REPO"/conformance/query/oracles/logql-native/bridge/*.go "$W/loki/pkg/logql/log/"
  ZI=$(cd "$W/loki" && GOTOOLCHAIN=go1.24.5 GOFLAGS= go env GOROOT)/lib/time/zoneinfo.zip
  cp "$ZI" "$W/oracle-zoneinfo.zip"
  sed -i "s#\"/oracle-zoneinfo.zip\"#\"$W/oracle-zoneinfo.zip\"#g" "$W/loki/_soundpost_logql/main.go"
  (cd "$W/loki" && GOTOOLCHAIN=go1.24.5 GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS=-mod=vendor \
    go build -tags=soundpost_logql_oracle -trimpath \
    -ldflags="-X main.compiledProfile=logql-loki-3.5.2 -X main.compiledCommit=$LC -X main.compiledSourceSHA256=$LS" \
    -o "$W/logql-reference" ./_soundpost_logql)
  sha256sum "$W/logql-reference" "$W/oracle-zoneinfo.zip"
}

# The shard/replica probe (author/logql-shard-probe) is compiled inside the same sha256-verified Loki
# source tree as the oracle driver (go1.24.5, -mod=vendor), in a directory of its own so the driver
# sources and bridge files stay untouched. It reads authored cases on stdin and writes observations.
build_loki_shard_probe() {
  LC=257d2f62bf8a81b44dea6fe88968d1d28c8e01e7
  LS=0db690662744694667c031a81d3e20cdd3a68a387a8050c8096bebbdf2ff8db2
  if [ ! -d "$W/loki" ]; then
    curl -fsSL -o "$W/loki.tgz" "https://codeload.github.com/grafana/loki/tar.gz/$LC"
    echo "$LS  $W/loki.tgz" | sha256sum -c -
    mkdir -p "$W/loki" && tar -xzf "$W/loki.tgz" -C "$W/loki" --strip-components=1
  fi
  rm -rf "$W/loki/_soundpost_shard_probe" && mkdir -p "$W/loki/_soundpost_shard_probe"
  for f in "$REPO"/conformance/query/author/logql-shard-probe/*.go; do
    case $f in *_test.go) ;; *) cp "$f" "$W/loki/_soundpost_shard_probe/" ;; esac
  done
  (cd "$W/loki" && GOTOOLCHAIN=go1.24.5 GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOMAXPROCS=4 GOFLAGS="-mod=vendor -p=2" \
    go build -tags=soundpost_logql_shard_probe -trimpath \
    -ldflags="-X main.compiledProfile=logql-loki-3.5.2 -X main.compiledCommit=$LC -X main.compiledSourceSHA256=$LS" \
    -o "$W/logql-shard-probe" ./_soundpost_shard_probe)
  sha256sum "$W/logql-shard-probe"
}

case "${1:-}" in
build)
  REPO=$(cd "$(dirname "$0")/../../.." && pwd)
  build 310 prometheus_310 3.1.0 7086161a93b262aa0949dbf2aba15a5a7b13e0a3 1a394b385e1fca89a6b81eab782074de26c5d35fccdebfef15c68daa55029de5 go1.23.4
  build 313 prometheus_313 3.13.5 f497435984d1ca1d84cda5ed309387ac2eb1f8f6 c2f96e97afede2cb4b43266bf62d964bed9194c7a1ac37759e1c6fd68600b410 go1.26.10
  ls -la "$W"
  ;;
build-loki)
  REPO=$(cd "$(dirname "$0")/../../.." && pwd)
  build_loki
  ;;
build-loki-shard-probe)
  REPO=$(cd "$(dirname "$0")/../../.." && pwd)
  build_loki_shard_probe
  ;;
run-logql)
  # run-logql <cases.json> <report.json>: the logql-metric phase of querycheck against the native Loki driver.
  # Run from the repository root; `setup` must have been run on the same tree.
  "$W/qc-adapter" compare --phase logql-metric --cases "$2" --profiles logql-loki-3.5.2 --require-locked \
    --runtime "$W/docker-shim" > "$3"
  ;;
setup)
  CK=$2
  rm -rf "$W/qc" && mkdir -p "$W/qc"
  for d in go.mod go.sum cmd internal profiles third_party; do cp -r "$CK/$d" "$W/qc/"; done
  (cd "$W/qc" && sed -i 's#exec.CommandContext(ctx, "/evaluation-reference")#exec.CommandContext(ctx, nativeEvaluationReference(profileID))#' internal/conformance/query/evaluation_adapter.go)
  (cd "$W/qc" && sed -i "s#exec.CommandContext(ctx, \"/logql-reference\")#exec.CommandContext(ctx, \"$W/logql-reference\")#" internal/conformance/query/logql_adapter.go)
  cat >> "$W/qc/internal/conformance/query/evaluation_adapter.go" <<GO

func nativeEvaluationReference(profileID string) string {
	if strings.HasSuffix(profileID, "3.1.0") {
		return "$W/evaluation-reference-310"
	}
	return "$W/evaluation-reference-313"
}
GO
  (cd "$W/qc" && GOTOOLCHAIN=local CGO_ENABLED=0 go build -o "$W/qc-adapter" ./cmd/soundpost-querycheck)
  # The fake OCI runtime: `rm` is a no-op; `run [flags] -i <image-id> ...` runs the adapter of that image's profile.
  cat > "$W/docker-shim" <<SH
#!/bin/bash
[ "\$1" = rm ] && exit 0
[ "\$1" = run ] || { echo "unsupported: \$*" >&2; exit 2; }
shift
while [ \$# -gt 0 ] && [ "\$1" != "-i" ]; do shift; done
shift
image=\$1
shift
case "\$image" in
  sha256:6234d450*) profile=promql-prometheus-3.1.0 ;;
  sha256:1f2f79b4*) profile=promql-prometheus-3.13.5 ;;
  sha256:fb2284f9*) profile=logql-loki-3.5.2 ;;
  *) echo "unsupported image \$image" >&2; exit 2 ;;
esac
exec env -i $W/qc-adapter adapter \$profile "\$@"
SH
  chmod +x "$W/docker-shim"
  echo "runtime: $W/docker-shim"
  ;;
*)
  sed -n 2,23p "$0" >&2
  exit 2
  ;;
esac

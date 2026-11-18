#!/bin/bash
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
# Runs the PromQL evaluation phase against the pinned Prometheus references on a host WITHOUT an OCI
# runtime (the worker VMs). The references are built natively from the sha256-verified upstream source
# archives named in source-lock.json, with the recipe of oracles/promql-prometheus-<v>.Dockerfile
# (same driver sources, build tags and ldflags, Go toolchain pinned by GOTOOLCHAIN). Nothing is
# copied from upstream into the repository. An observation made this way is a native build of the
# pinned source, not the digest-locked OCI image; record it as such.
#
#   conformance/query/author/native-oracle.sh build              # download, verify, build both references
#   conformance/query/author/native-oracle.sh setup <repo-dir>   # copy of querycheck using them + a fake runtime
#   go run ./cmd/soundpost-querycheck compare --phase evaluation --cases ... \
#       --profiles promql-prometheus-3.1.0,promql-prometheus-3.13.5 --require-locked \
#       --runtime "$NATIVE_ORACLE_DIR/docker-shim"
#
# Only the evaluation phase is served (the syntax, configuration and LogQL phases need the real
# /bin/prometheus or Loki binaries of the images). NATIVE_ORACLE_DIR defaults to $HOME/native-oracle.
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

case "${1:-}" in
build)
  REPO=$(cd "$(dirname "$0")/../../.." && pwd)
  build 310 prometheus_310 3.1.0 7086161a93b262aa0949dbf2aba15a5a7b13e0a3 1a394b385e1fca89a6b81eab782074de26c5d35fccdebfef15c68daa55029de5 go1.23.4
  build 313 prometheus_313 3.13.5 f497435984d1ca1d84cda5ed309387ac2eb1f8f6 c2f96e97afede2cb4b43266bf62d964bed9194c7a1ac37759e1c6fd68600b410 go1.26.10
  ls -la "$W"
  ;;
setup)
  CK=$2
  rm -rf "$W/qc" && mkdir -p "$W/qc"
  for d in go.mod go.sum cmd internal profiles third_party; do cp -r "$CK/$d" "$W/qc/"; done
  (cd "$W/qc" && sed -i 's#exec.CommandContext(ctx, "/evaluation-reference")#exec.CommandContext(ctx, nativeEvaluationReference(profileID))#' internal/conformance/query/evaluation_adapter.go)
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
  sha256:6f238ce5*) profile=promql-prometheus-3.1.0 ;;
  sha256:2251b830*) profile=promql-prometheus-3.13.5 ;;
  *) echo "unsupported image \$image" >&2; exit 2 ;;
esac
exec env -i $W/qc-adapter adapter \$profile "\$@"
SH
  chmod +x "$W/docker-shim"
  echo "runtime: $W/docker-shim"
  ;;
*)
  sed -n 2,20p "$0" >&2
  exit 2
  ;;
esac

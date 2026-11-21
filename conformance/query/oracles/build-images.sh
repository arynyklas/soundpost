#!/bin/bash
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
#
# Builds the five locked local oracle images on a daemon that does not hold them (a hosted CI runner, a fresh lab
# host) from the pinned inputs, with the Dockerfiles of this directory unchanged:
#
#   soundpost-oracle-promql-prometheus-3.1.0:current          soundpost-oracle-promql-prometheus-3.1.0-configuration:current
#   soundpost-oracle-promql-prometheus-3.13.5:current         soundpost-oracle-promql-prometheus-3.13.5-configuration:current
#   soundpost-oracle-logql-loki-3.5.2:current
#
# Every input is pinned by content: the upstream release images by their linux/amd64 digest (the FROM line of each
# Dockerfile), the Go toolchain image by digest (source-lock.json, profiles[].reference_compiler.builder_image; the
# Dockerfiles refuse a tag), the upstream source archives by the sha256 of their ADD --checksum. The adapter
# (querycheck-linux-amd64, an ignored build output) is built here from the tree under test with the toolchain on PATH.
#
# A rebuilt image has another image id than the one source-lock.json records (layer timestamps), so it is never
# accepted by id. The harness (internal/conformance/query, oracle_image.go) accepts it only after proving the files
# that determine the oracle's behaviour byte for byte against profiles[].artifact.content_identity of the lock; see
# conformance/query/README.md ("Oracle images without the locked ids").
#
#   conformance/query/oracles/build-images.sh            # builds, then prints the five ids
#
# Needs: docker (BuildKit, network to mirror.gcr.io and codeload.github.com), jq, go (for the adapter).
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
lock=$root/conformance/query/source-lock.json
ctx=$root/conformance/query/oracles

for tool in docker jq go; do
  command -v "$tool" >/dev/null || { echo "build-images.sh: $tool is required" >&2; exit 1; }
done

echo "== adapter (querycheck-linux-amd64) from the tree under test"
(cd "$root" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$ctx/querycheck-linux-amd64" ./cmd/soundpost-querycheck)

build_arg_for() { # <profile id> -> name of the Dockerfile's Go image build argument
  case "$1" in
    promql-*) echo EVALUATION_GO_IMAGE ;;
    logql-*) echo LOGQL_GO_IMAGE ;;
    *) echo "build-images.sh: unknown profile $1" >&2; exit 1 ;;
  esac
}

for id in $(jq -r '.profiles[].id' "$lock"); do
  builder=$(jq -r --arg id "$id" '.profiles[] | select(.id == $id) | .reference_compiler.builder_image' "$lock")
  case "$builder" in
    *@sha256:*) ;;
    *) echo "build-images.sh: profile $id has no digest-pinned reference_compiler.builder_image in the lock" >&2; exit 1 ;;
  esac
  echo "== soundpost-oracle-$id:current (Go image $builder)"
  docker build --provenance=false --sbom=false \
    --build-arg "$(build_arg_for "$id")=$builder" \
    -f "$ctx/$id.Dockerfile" -t "soundpost-oracle-$id:current" "$ctx"
done

# The configuration variants are FROM name@sha256:<locked id of the evaluation oracle>. That id is the lab daemon's;
# a named build context maps the base onto the image just built, the Dockerfile stays as locked.
for id in $(jq -r '.profiles[] | select(.configuration_oracle != null) | .id' "$lock"); do
  locked=$(jq -r --arg id "$id" '.profiles[] | select(.id == $id) | .artifact.path' "$lock")
  config_image=$(jq -r --arg id "$id" '.profiles[] | select(.id == $id) | .configuration_oracle.image' "$lock")
  echo "== $config_image"
  docker build --pull=false --provenance=false --sbom=false \
    --build-context "soundpost-oracle-$id@$locked=docker-image://soundpost-oracle-$id:current" \
    -f "$ctx/$id-configuration.Dockerfile" -t "$config_image" "$ctx"
done

echo "== built images"
for tag in $(jq -r '.profiles[] | "soundpost-oracle-\(.id):current", (.configuration_oracle.image // empty)' "$lock"); do
  printf '%s %s\n' "$tag" "$(docker image inspect --format '{{.Id}}' "$tag")"
done

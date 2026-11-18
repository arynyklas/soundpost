# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
# Configuration-phase observation variant (decision D29). Built FROM the existing
# digest-pinned evaluation oracle image of the same profile; it adds exactly one
# file and changes no entrypoint, binary or layer below it. The upstream
# /bin/prometheus of that image is the reference; the harness starts it with
# --entrypoint, never through /adapter.
#   docker build --pull=false -f promql-prometheus-3.1.0-configuration.Dockerfile \
#     -t soundpost-oracle-promql-prometheus-3.1.0-configuration:current .
FROM soundpost-oracle-promql-prometheus-3.1.0@sha256:6234d450fe5c3770af5c0a3d20adff668e4594d3abd626a29d626a73ab69d417
COPY --chmod=0444 promql-prometheus-3.1.0-configuration.yaml /etc/prometheus/soundpost-configuration-phase.yaml

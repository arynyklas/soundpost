# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
# Configuration-phase observation variant (decision D29). Built FROM the existing
# digest-pinned evaluation oracle image of the same profile; it adds exactly one
# file and changes no entrypoint, binary or layer below it. The upstream
# /bin/prometheus of that image is the reference; the harness starts it with
# --entrypoint, never through /adapter.
#   docker build --pull=false -f promql-prometheus-3.13.5-configuration.Dockerfile \
#     -t soundpost-oracle-promql-prometheus-3.13.5-configuration:current .
FROM soundpost-oracle-promql-prometheus-3.13.5@sha256:1f2f79b4dd8c1d4ecee0d0cec6471f633324eebc01924f8e4fa4c2742ef2bf4f
COPY --chmod=0444 promql-prometheus-3.13.5-configuration.yaml /etc/prometheus/soundpost-configuration-phase.yaml

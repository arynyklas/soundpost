# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
# Configuration-phase observation variant (decision D29). Built FROM the existing
# digest-pinned evaluation oracle image of the same profile; it adds exactly one
# file and changes no entrypoint, binary or layer below it. The upstream
# /bin/prometheus of that image is the reference; the harness starts it with
# --entrypoint, never through /adapter.
#   docker build --pull=false -f promql-prometheus-3.13.5-configuration.Dockerfile \
#     -t soundpost-oracle-promql-prometheus-3.13.5-configuration:current .
FROM soundpost-oracle-promql-prometheus-3.13.5@sha256:2251b83038a6c0c61c21ed8721cb94a699ceb3bee38c1f115b4efae338fbe453
COPY --chmod=0444 promql-prometheus-3.13.5-configuration.yaml /etc/prometheus/soundpost-configuration-phase.yaml

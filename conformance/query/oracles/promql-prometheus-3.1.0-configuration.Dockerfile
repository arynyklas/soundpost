# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
# Configuration-phase observation variant (decision D29). Built FROM the existing
# digest-pinned evaluation oracle image of the same profile; it adds exactly one
# file and changes no entrypoint, binary or layer below it. The upstream
# /bin/prometheus of that image is the reference; the harness starts it with
# --entrypoint, never through /adapter.
#   docker build --pull=false -f promql-prometheus-3.1.0-configuration.Dockerfile \
#     -t soundpost-oracle-promql-prometheus-3.1.0-configuration:current .
FROM soundpost-oracle-promql-prometheus-3.1.0@sha256:6f238ce554111c3d86b2df22c3bb74e8f293bd0eb194aa38aab0a300ee6e0b79
COPY --chmod=0444 promql-prometheus-3.1.0-configuration.yaml /etc/prometheus/soundpost-configuration-phase.yaml

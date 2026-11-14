# syntax=docker/dockerfile:1.7
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
# Parent supplies an immutable official Go 1.26.10 image digest at rebuild.
ARG EVALUATION_GO_IMAGE
FROM ${EVALUATION_GO_IMAGE} AS evaluation-build
ARG EVALUATION_GO_IMAGE
RUN case "$EVALUATION_GO_IMAGE" in *@sha256:*) ;; *) echo "digest-locked Go image required" >&2; exit 1 ;; esac
ADD --checksum=sha256:c2f96e97afede2cb4b43266bf62d964bed9194c7a1ac37759e1c6fd68600b410 https://codeload.github.com/prometheus/prometheus/tar.gz/f497435984d1ca1d84cda5ed309387ac2eb1f8f6 /source.tar.gz
RUN mkdir /src && tar -xzf /source.tar.gz -C /src --strip-components=1
COPY evaluation/*.go /src/_soundpost_evaluation/
WORKDIR /src
RUN test "$(go env GOVERSION)" = go1.26.10 && GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -tags=soundpost_evaluation_oracle,prometheus_313 -trimpath -ldflags="-X main.compiledProfile=promql-prometheus-3.13.5 -X main.compiledCommit=f497435984d1ca1d84cda5ed309387ac2eb1f8f6 -X main.compiledSourceSHA256=c2f96e97afede2cb4b43266bf62d964bed9194c7a1ac37759e1c6fd68600b410" -o /evaluation-reference ./_soundpost_evaluation

FROM mirror.gcr.io/prom/prometheus@sha256:dc30314819e04a1a3d18d0b37eaa9c8e4e18f33f026e3e2d81bf127c7cddcd55
COPY --chmod=0555 querycheck-linux-amd64 /adapter
COPY --from=evaluation-build --chmod=0555 /evaluation-reference /evaluation-reference
COPY --from=evaluation-build --chmod=0444 /src/LICENSE /oracle-licenses/evaluation-LICENSE
COPY --from=evaluation-build --chmod=0444 /src/NOTICE /oracle-licenses/evaluation-NOTICE
ENTRYPOINT ["/adapter", "adapter", "promql-prometheus-3.13.5"]

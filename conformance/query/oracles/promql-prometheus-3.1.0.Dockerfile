# syntax=docker/dockerfile:1.7
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
# Parent supplies an immutable official Go 1.23.4 image digest at rebuild.
ARG EVALUATION_GO_IMAGE
FROM ${EVALUATION_GO_IMAGE} AS evaluation-build
ARG EVALUATION_GO_IMAGE
RUN case "$EVALUATION_GO_IMAGE" in *@sha256:*) ;; *) echo "digest-locked Go image required" >&2; exit 1 ;; esac
ADD --checksum=sha256:1a394b385e1fca89a6b81eab782074de26c5d35fccdebfef15c68daa55029de5 https://codeload.github.com/prometheus/prometheus/tar.gz/7086161a93b262aa0949dbf2aba15a5a7b13e0a3 /source.tar.gz
RUN mkdir /src && tar -xzf /source.tar.gz -C /src --strip-components=1
COPY evaluation/*.go /src/_soundpost_evaluation/
WORKDIR /src
RUN test "$(go env GOVERSION)" = go1.23.4 && GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -tags=soundpost_evaluation_oracle,prometheus_310 -trimpath -ldflags="-X main.compiledProfile=promql-prometheus-3.1.0 -X main.compiledCommit=7086161a93b262aa0949dbf2aba15a5a7b13e0a3 -X main.compiledSourceSHA256=1a394b385e1fca89a6b81eab782074de26c5d35fccdebfef15c68daa55029de5" -o /evaluation-reference ./_soundpost_evaluation

FROM mirror.gcr.io/prom/prometheus@sha256:da1630c5102817ed365a523448c766e417030a53ec3dfbe064d429df504e023e
COPY --chmod=0555 querycheck-linux-amd64 /adapter
COPY --from=evaluation-build --chmod=0555 /evaluation-reference /evaluation-reference
COPY --from=evaluation-build --chmod=0444 /src/LICENSE /oracle-licenses/evaluation-LICENSE
COPY --from=evaluation-build --chmod=0444 /src/NOTICE /oracle-licenses/evaluation-NOTICE
ENTRYPOINT ["/adapter", "adapter", "promql-prometheus-3.1.0"]

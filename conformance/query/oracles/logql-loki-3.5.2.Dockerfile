# syntax=docker/dockerfile:1.7
# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
ARG LOGQL_GO_IMAGE
FROM ${LOGQL_GO_IMAGE} AS logql-native-build
ARG LOGQL_GO_IMAGE
RUN case "$LOGQL_GO_IMAGE" in *@sha256:*) ;; *) echo "digest-locked Go1.24.5 image required" >&2; exit 1 ;; esac
ADD --checksum=sha256:0db690662744694667c031a81d3e20cdd3a68a387a8050c8096bebbdf2ff8db2 https://codeload.github.com/grafana/loki/tar.gz/257d2f62bf8a81b44dea6fe88968d1d28c8e01e7 /source.tar.gz
RUN mkdir /src && tar -xzf /source.tar.gz -C /src --strip-components=1
COPY logql-native/*.go /src/_soundpost_logql/
COPY logql-native/bridge/*.go /src/pkg/logql/log/
WORKDIR /src
RUN test "$(go env GOVERSION)" = go1.24.5 && GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=vendor -tags=soundpost_logql_oracle -trimpath -ldflags="-X main.compiledProfile=logql-loki-3.5.2 -X main.compiledCommit=257d2f62bf8a81b44dea6fe88968d1d28c8e01e7 -X main.compiledSourceSHA256=0db690662744694667c031a81d3e20cdd3a68a387a8050c8096bebbdf2ff8db2" -o /logql-reference ./_soundpost_logql
RUN test -f /src/LICENSE && cp /usr/local/go/lib/time/zoneinfo.zip /oracle-zoneinfo.zip

FROM mirror.gcr.io/grafana/loki@sha256:d12ab5b1cd7ac58c1c0ea8cb43e0d151d1d5bee1cb897c7e7eaf225adae07928
COPY --chmod=0555 querycheck-linux-amd64 /adapter
COPY --from=logql-native-build --chmod=0555 /logql-reference /logql-reference
COPY --from=logql-native-build --chmod=0444 /oracle-zoneinfo.zip /oracle-zoneinfo.zip
COPY --from=logql-native-build --chmod=0444 /src/LICENSE /oracle-licenses/native-loki-LICENSE
# Retain the original source archive, including every bundled LICENSE/NOTICE.
# No upstream source or dependency is imported by the production query engine.
COPY --from=logql-native-build --chmod=0444 /source.tar.gz /oracle-source/loki-257d2f62bf8a81b44dea6fe88968d1d28c8e01e7.tar.gz
ENTRYPOINT ["/adapter", "adapter", "logql-loki-3.5.2"]

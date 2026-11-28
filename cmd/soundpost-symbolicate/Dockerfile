# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
# Build context contains only the parent's verified static worker binary.
FROM scratch
ARG WORKER_SHA256
LABEL org.soundpost.worker.sha256=$WORKER_SHA256
COPY soundpost-symbolicate /soundpost-symbolicate
USER 65534:65534
ENTRYPOINT ["/soundpost-symbolicate"]

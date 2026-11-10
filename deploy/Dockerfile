# Copyright 2026 Aryn Yklas
# SPDX-License-Identifier: Apache-2.0
#
# Soundpost single-host server image. The build context is made by
# `go run ./build image-context --release DIST --arch amd64 --out CTX` and holds exactly:
#   soundpost   the verified static binary (its sha256 is checked against DIST/SHA256SUMS)
#   data/       an empty directory
# Nothing is downloaded, copied from the network or run during the image build, so it works
# with `docker build --network=none`. FROM scratch pulls no base image: the only content is
# the static binary and the data directory.
FROM scratch

ARG SOUNDPOST_VERSION=unset
ARG SOUNDPOST_SHA256=unset
LABEL org.opencontainers.image.title="soundpost" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${SOUNDPOST_VERSION}" \
      org.soundpost.binary.sha256="${SOUNDPOST_SHA256}"

COPY --chown=65532:65532 --chmod=0555 soundpost /soundpost
# The only writable place: owned by the unprivileged user, mode 0700. Files the server
# creates inside it (control.db, apply.db, envelope keys, bootstrap.token, server.key) are 0600.
COPY --chown=65532:65532 --chmod=0700 data/ /var/lib/soundpost/

USER 65532:65532
WORKDIR /var/lib/soundpost
VOLUME ["/var/lib/soundpost"]
EXPOSE 8443

# Functional readiness: the running node's own quorum, apply, disk, policy and schema decision
# over its verified HTTPS route, not a listening port. A listener alone is never healthy.
HEALTHCHECK --interval=10s --timeout=6s --start-period=30s --retries=3 \
  CMD ["/soundpost", "ready", "--data-dir", "/var/lib/soundpost", "--timeout", "5s"]

STOPSIGNAL SIGTERM
ENTRYPOINT ["/soundpost"]
CMD ["serve", "--mode=single", "--data-dir=/var/lib/soundpost", "--listen=0.0.0.0:8443"]

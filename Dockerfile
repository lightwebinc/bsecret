# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
#
# Two images from one build, each a single static binary on a distroless
# nonroot base:
#
#   docker build -t ghcr.io/lightwebinc/bsecret .                             # the command (default)
#   docker build --target devchain -t ghcr.io/lightwebinc/bsecret-devchain .  # the local chain
#
# The builder is pinned by digest at go.mod's Go release line (1.27), so
# scanning sees the standard library that ships.
#
# No ENV defaults are baked in. The hosts, the header source, the node and
# the settlement leg are addresses of somebody's deployment and have no
# default anywhere: a default would send an organization's records, or a
# member's questions, to a server nobody configured. Pass them as
# BSECRET_<KEY> variables or in a config file (docs/usage.md).
#
# The command keeps an identity's state (key, coin pool, state file) under
# $BSECRET_HOME, ~/.bsecret by default, which is /home/nonroot/.bsecret
# here. The image carries that directory, empty, owned by nonroot and mode
# 0700, so a new named volume mounted there starts with the same owner and
# mode:
#
#   docker run --rm -v bsecret-home:/home/nonroot/.bsecret ghcr.io/lightwebinc/bsecret init
#
# A volume mounted on a path the image lacks is created root-owned, and
# every write to it is then refused. A bind mount keeps the host
# directory's owner instead: make it writable by uid 65532, or run with
# --user.

# The builder runs on the build machine's own platform and cross-compiles
# to the target's, so an arm64 image needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
ENV GOWORK=off

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eux; \
    mkdir -p /out /state/.bsecret /state/devchain /state/content; \
    for cmd in bsecret devchain; do \
      CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
        go build -trimpath -buildvcs=false \
          -ldflags "-s -w -X main.version=${VERSION}" \
          -o /out/$cmd ./cmd/$cmd; \
    done

# The local chain for trying bsecret without a node or coin: a node's RPC
# and asset API and a header source on port 8080. It has no proof of work
# and no peers, and nothing it mines is money. Its journal, which replays
# the chain after a restart, is kept in /var/lib/devchain; mount a volume
# there.
FROM gcr.io/distroless/static:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88 AS devchain
USER nonroot:nonroot
COPY --from=builder /out/devchain /usr/local/bin/devchain
COPY --from=builder --chown=65532:65532 --chmod=0700 /state/devchain /var/lib/devchain
COPY LICENSE NOTICE LICENSE-THIRD-PARTY /usr/share/doc/bsecret/
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/devchain", "-journal", "/var/lib/devchain/journal"]

# The command. Last, so a plain build produces it.
FROM gcr.io/distroless/static:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88 AS bsecret
USER nonroot:nonroot
COPY --from=builder /out/bsecret /usr/local/bin/bsecret
COPY --from=builder --chown=65532:65532 --chmod=0700 /state/.bsecret /home/nonroot/.bsecret
# Where a ciphertext too large to ride in its record is written when
# BSECRET_CONTENT names it: ciphertext is public, so others may read it.
COPY --from=builder --chown=65532:65532 --chmod=0755 /state/content /var/lib/bsecret-content

# The licenses travel with the image. The binary statically contains
# go-sdk and the other modules LICENSE-THIRD-PARTY lists, whose licences
# require their text in any copy, and static linking leaves those files
# behind.
COPY LICENSE NOTICE LICENSE-THIRD-PARTY /usr/share/doc/bsecret/

# No EXPOSE: bsecret listens on nothing. It is a client of overlay hosts, a
# header source, a node and a settlement leg.
ENTRYPOINT ["/usr/local/bin/bsecret"]

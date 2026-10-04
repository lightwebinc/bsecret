# syntax=docker/dockerfile:1.27.1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
#
# bsecret-host: an overlay host image with the bsecret module
# (tm_bsecret_<crypt> and ls_bsecret) built in, beside the borg module, so a
# host that carries a crypt and the hall its vaults' groups live in is one
# image and needs no file copied onto it. Build from the repository root:
#
#   docker build -f host/Dockerfile \
#     --build-arg BORG_HOST_IMAGE=<borg's host image> \
#     -t ghcr.io/lightwebinc/bsecret-host .
#
# BORG_HOST_IMAGE names the image the module is added to: borg's host image,
# which is a reference overlay host (its application is /app/dist/index.js
# with its node_modules beside it, it loads the absolute paths in
# OVERLAY_MODULES and reads the OVERLAY_* settings) with the borg module at
# /app/modules/borg/borg-module.js. It is a build argument with no default,
# so what the image is built on is always stated, and a release pins it; the
# placeholder below only makes a build that forgot it fail with a name that
# says so.

ARG BORG_HOST_IMAGE=set-the-borg-host-image-build-arg

# The bundle is JavaScript, the same bytes on every platform, so it is
# built once on the build machine's own platform; the final stage only
# copies files onto the host image, so an arm64 image needs no emulation.
FROM --platform=$BUILDPLATFORM node:24@sha256:64af3819f9275802414d7cdc38c27e9d82bd564dec4d4da87d008255d36c63b4 AS bundle
WORKDIR /src/host
COPY host/package.json host/package-lock.json ./
COPY host/vendor ./vendor
RUN npm ci --no-audit --no-fund
COPY host/ ./
RUN npm run check && npm run build && npm run bundle

FROM ${BORG_HOST_IMAGE}
# Beside the host's own node_modules, so the bundle's one import (@bsv/sdk)
# resolves to the host's copy (docs/host.md).
COPY --from=bundle /src/host/bundle/bsecret-module.js /app/modules/bsecret/bsecret-module.js
COPY --chmod=0755 host/entrypoint.sh /usr/local/bin/bsecret-host
COPY LICENSE NOTICE LICENSE-THIRD-PARTY /usr/share/doc/bsecret/
# The state directory, kept for the host's life (docs/host.md): the lifetime
# rows and the payment ledger. Mount a volume here. Others may read it: the
# rows are public facts, and a payment pays only the payee's key, so the
# payee's settle can read the ledger as another user.
USER root
RUN mkdir -p /var/lib/bsecret && chown node:node /var/lib/bsecret && chmod 0755 /var/lib/bsecret
USER node
# OVERLAY_MODULES is emptied so that the entrypoint names the modules by
# what the host is asked to carry; set it to name them yourself.
ENV OVERLAY_MODULES= \
    BSECRET_STATE_DIR=/var/lib/bsecret
ENTRYPOINT ["/usr/local/bin/bsecret-host"]

#!/bin/sh
# Starts the overlay host with the bsecret module, and with the borg module
# when the host also carries halls. Three things are added to the stock
# start:
#
#  - BSECRET_CRYPTS is required. When OVERLAY_TOPICS is unset it is derived:
#    tm_bsecret_<crypt> for each crypt, and tm_borg_<hall> for each entry of
#    BORG_HALLS when that is set. So a host is configured by the lines
#    `bsecret crypt new` and `borg hall new` print. The modules check the
#    grammar.
#  - when OVERLAY_MODULES is unset the bsecret module is loaded, and the
#    borg module beside it when BORG_HALLS is set: a host that carries only
#    crypts, with the groups' hall on other hosts, loads only bsecret's.
#  - an unset OVERLAY_ADMIN_TOKEN is replaced by a random one for this run,
#    because the host requires one. Nothing can use the admin surface until
#    the operator sets their own.
set -eu

if [ -z "${BSECRET_CRYPTS:-}" ]; then
  echo "bsecret-host: BSECRET_CRYPTS is empty. Create a crypt with 'bsecret crypt new <name>' and set BSECRET_CRYPTS to the crypt it prints (several crypts: comma separated)." >&2
  exit 64
fi

if [ -z "${OVERLAY_TOPICS:-}" ]; then
  topics=""
  for crypt in $(printf '%s' "$BSECRET_CRYPTS" | tr ',' ' '); do
    topics="${topics:+$topics,}tm_bsecret_$crypt"
  done
  for hall in $(printf '%s' "${BORG_HALLS:-}" | tr ',' ' '); do
    topics="${topics:+$topics,}tm_borg_$hall"
  done
  OVERLAY_TOPICS=$topics
  export OVERLAY_TOPICS
fi

if [ -z "${OVERLAY_MODULES:-}" ]; then
  OVERLAY_MODULES=/app/modules/bsecret/bsecret-module.js
  if [ -n "${BORG_HALLS:-}" ]; then
    OVERLAY_MODULES=/app/modules/borg/borg-module.js,$OVERLAY_MODULES
  fi
  export OVERLAY_MODULES
fi

if [ -z "${OVERLAY_ADMIN_TOKEN:-}" ]; then
  OVERLAY_ADMIN_TOKEN=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
  export OVERLAY_ADMIN_TOKEN
  echo "bsecret-host: OVERLAY_ADMIN_TOKEN is unset; using a random one for this run (set it to use /admin)" >&2
fi

echo "bsecret-host: topics $OVERLAY_TOPICS" >&2
exec node /app/dist/index.js "$@"

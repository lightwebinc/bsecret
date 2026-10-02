#!/usr/bin/env bash
# QUICKSTART.md, run as written, in a throwaway copy of the quickstart
# compose project: the local chain, two hosts and MySQL; an organisation,
# three members and a group (borg); a crypt and a vault on the group; three
# secrets every member reads; a removal, which begins a new epoch; the
# acknowledgement and the re-keying, after which the removed member reads
# none of the new versions; a retirement; the audit paid through its 402,
# verified from headers, with its exposure window, and the payee settling
# it; and a fill that finds the two hosts agree.
#
#   scripts/quickstart-check.sh
#
# Needs the images the compose file names: this repository's three (make
# docker-build, make docker-build-host) and borg's command image. COMPOSE
# names the compose command (default "docker compose", else Compose from
# the docker:cli image with the work directory mounted where it is).
# Everything it creates, volumes included, is removed at the end, pass or
# fail.
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
project=bsecret-quickstart-check-$$
cp "$here/deploy/quickstart/compose.yaml" "$work/"
cd "$work"
if [ -n "${COMPOSE:-}" ]; then
	compose=$COMPOSE
elif docker compose version >/dev/null 2>&1; then
	compose="docker compose"
else
	compose="docker run --rm -i -v /var/run/docker.sock:/var/run/docker.sock -v $work:$work -w $work docker:cli compose"
fi

dc() { $compose -p "$project" "$@"; }
borg() { local who=$1; shift; dc run --rm -T -e "BORG_HOME=/home/nonroot/.borg/$who" borg "$@"; }
bs() { local who=$1; shift; dc run --rm -T -e "BSECRET_HOME=/home/nonroot/.bsecret/$who" bsecret "$@"; }
cleanup() {
	dc --profile cli down -v --remove-orphans >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT
step() { printf '\n== %s\n' "$*"; }
fail() {
	echo "quickstart-check: $*" >&2
	dc logs --no-color --tail 40 >&2 || true
	exit 1
}
key() { sed -n 's/^identity *//p' "$1"; }

step "1. the local chain"
dc up -d chain

step "2. an organisation and three members (borg), and a home of each for bsecret"
borg org init | tee org.txt
borg org fund
for m in alice bob carol; do borg $m init | tee $m.txt; done
ORG=$(key org.txt) ALICE=$(key alice.txt) BOB=$(key bob.txt) CAROL=$(key carol.txt)
[ -n "$ORG" ] && [ -n "$ALICE" ] && [ -n "$BOB" ] && [ -n "$CAROL" ] || fail "borg init printed no identity"
for m in org alice bob carol; do bs $m init -borg /home/nonroot/.borg/$m | tee bs-$m.txt; done
[ "$(key bs-org.txt)" = "$ORG" ] && [ "$(key bs-bob.txt)" = "$BOB" ] || fail "a bsecret home is not around its borg home's identity"
bs org fund
bs payee init
bs auditor init
bs auditor fund

step "3. a hall, a crypt, the payee key"
borg org hall new example | tee hall.txt
bs org crypt new example | tee crypt.txt
sed -n 's/^host *//p' hall.txt crypt.txt >.env
echo "BSECRET_ORG=$ORG" >>.env
bs payee payee key -out - >>.env
grep -q '^BORG_HALLS=example_[a-z]\{10\}$' .env && grep -q '^BSECRET_CRYPTS=example_[a-z]\{10\}$' .env &&
	grep -q '^BSECRET_PAYEE_KEY=[0-9a-f]\{64\}$' .env || fail "the .env lines are missing"

step "4. two hosts that carry the hall and the crypt"
dc up -d
for i in $(seq 1 90); do
	out=$(bs org doctor 2>/dev/null || true)
	[ "$(printf '%s\n' "$out" | grep -c '^host .* answering$')" = 2 ] && printf '%s\n' "$out" | grep -q '^paid host .* serves terms' && break
	sleep 2
done
printf '%s\n' "$out"
[ "$(printf '%s\n' "$out" | grep -c '^host .* answering$')" = 2 ] || fail "the hosts did not come up"

step "5. the organisation, a group, and the signer key (borg)"
borg org org create 'Example Organisation' -member "$ALICE" -member "$BOB" -member "$CAROL" | tee create.txt
[ "$(grep -c '^grant ' create.txt)" = 3 ] || fail "org create did not issue three grants"
borg org group create engineering -member "$ALICE" -member "$BOB" -member "$CAROL" | tee group.txt
GROUP=$(sed -n 's/^group *//p' group.txt)
[ -n "$GROUP" ] || fail "group create printed no group"
borg org org signer | tee signer.txt
grep -q '^signer ' signer.txt || fail "org signer"

step "6. a vault on the group, and three secrets"
bs org vault create engineering -name ops | tee vault.txt
VAULT=$(sed -n 's/^vault *//p' vault.txt)
[ -n "$VAULT" ] && grep -q "^group   $GROUP in hall" vault.txt || fail "vault create"
printf 'hunter2' | bs org put db/password | tee put1.txt
printf 'tok-1' | bs org put api/token | tee put2.txt
printf 'KEY' | bs org put tls/key | tee put3.txt
grep -q '^secret  db/password version 1 .*(created)$' put1.txt && grep -q '3 secret(s), 0 stale, epoch 0' put3.txt || fail "put"
grep -q '^host http://host-b:8080: took .* missed 0' put3.txt || fail "host-b missed something"

step "7. every member reads"
for m in alice bob carol; do
	[ "$(bs $m get db/password 2>get-$m.txt)" = hunter2 ] || fail "$m did not read db/password"
	grep -q 'anchored, current$' get-$m.txt || fail "$m: the version is not current"
done
cat get-alice.txt
bs alice list 2>&1 | tee list.txt
[ "$(grep -c "the set's root reproduced" list.txt)" = 2 ] && grep -q '^tls/key  version 1' list.txt || fail "list"

step "8. revoke bob: the removal (borg), then the acknowledgement and the re-keying"
printf 'correct horse' | bs org rotate -check -set db/password=- -same-all | tee check.txt
grep -q '^ready ' check.txt || fail "rotate -check"
borg org org remove "$BOB" -group engineering | tee remove.txt
grep -q 'epoch 1 (a new epoch' remove.txt || fail "the removal did not rotate"
bs alice get db/password 2>behind.txt >/dev/null
cat behind.txt
grep -q 'BEHIND' behind.txt && grep -q 'EXPOSED' behind.txt || fail "a reader did not report the vault behind"
rc=0; bs org rotate >norotate.txt 2>&1 || rc=$?
[ "$rc" = 2 ] && grep -q '3 secret(s) have no choice' norotate.txt || fail "rotate with no choices exited $rc"
printf 'correct horse' | bs org rotate -set db/password=- -same-all | tee rotate.txt
grep -q '^epoch   1 acknowledged' rotate.txt && grep -q '^rekeyed db/password: a new value' rotate.txt &&
	grep -q '0 stale, epoch 1' rotate.txt && grep -q '^swept ' rotate.txt && grep -q 'settled at epoch 1' rotate.txt || fail "rotate"
[ "$(bs alice get db/password 2>/dev/null)" = "correct horse" ] || fail "alice did not read the new value"
[ "$(bs carol get tls/key 2>/dev/null)" = KEY ] || fail "carol did not read the re-keyed tls/key"
rc=0; bs bob get db/password >bob.txt 2>&1 || rc=$?
cat bob.txt
[ "$rc" = 1 ] && grep -q 'undecryptable' bob.txt || fail "bob read the new version, or exited $rc"

step "9. a retirement"
bs org retire api/token | tee retire.txt
grep -q '^retired api/token' retire.txt || fail "retire"
rc=0; bs alice get api/token >gone.txt 2>&1 || rc=$?
[ "$rc" = 1 ] && grep -q 'holds no secret named api/token' gone.txt || fail "the retired secret is still read, or exit $rc"

step "10. the audit, paid, and the payee settling it"
bs auditor terms | tee terms.txt
grep -q '^audit          20 sat a question' terms.txt || fail "terms"
bs auditor audit | tee audit.txt
grep -q '^paid 20 sat to ' audit.txt && grep -q '^window  epoch 1: [0-9]* block(s) from' audit.txt && grep -q '^audit   OK' audit.txt || fail "audit"
bs nobody -org "$ORG" -vault "$VAULT" audit -free | tee audit-free.txt
[ "$(grep '^window ' audit.txt)" = "$(grep '^window ' audit-free.txt)" ] || fail "the free audit reports another window"
bs payee payee settle /var/lib/bsecret-a/payments.jsonl | tee settle.txt
grep -q '^1 payment(s) settled, 20 sat' settle.txt || fail "payee settle"

step "11. the hosts agree"
bs alice fill | tee fill.txt
grep -q '^filled  0 object(s) at 0 host(s)' fill.txt || fail "fill found the hosts differ"
bs alice due | tee due.txt
grep -q '^nothing is due' due.txt || fail "something is due"

echo
echo "quickstart-check: ok"

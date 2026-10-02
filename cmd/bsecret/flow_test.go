package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/lightwebinc/bcommon/nodeapi"

	"github.com/lightwebinc/bsecret/internal/engine"
	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/state"
	"github.com/lightwebinc/bsecret/internal/testhost"
	"github.com/lightwebinc/bsecret/internal/vread"
)

// The exit criterion: a revoke forces rotation. The removed member reads
// what was keyed under the epoch it held, and nothing keyed after the
// vault re-keyed; the members who remain read the new versions.
func TestRevokeForcesRotation(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	for name, value := range map[string]string{"db/password": "hunter2", "api/token": "tok-1", "tls/key": "KEY"} {
		r := h.put(name, value)
		if !strings.Contains(r.stdout, "secret  "+name+" version 1") || !strings.Contains(r.stdout, "(created)") {
			t.Fatalf("put %s:\n%s\n%s", name, r.stdout, r.stderr)
		}
	}
	for _, m := range []string{"alice", "bob", "carol", "org"} {
		r := h.must(m, "get", "db/password")
		if r.stdout != "hunter2" || !strings.Contains(r.stderr, "anchored, current") || !strings.Contains(r.stderr, "settled at epoch 0") {
			t.Fatalf("%s get:\n%q\n%s", m, r.stdout, r.stderr)
		}
	}
	if err := h.borg.Remove(h.group, h.keys["bob"]); err != nil {
		t.Fatal(err)
	}
	// The vault is behind: every reader says so, and its values are
	// exposed; the owner's tooling builds nothing but the acknowledgement.
	r := h.must("alice", "get", "db/password")
	if !strings.Contains(r.stderr, "BEHIND") || !strings.Contains(r.stderr, "EXPOSED") {
		t.Fatalf("a reader of a vault behind its group:\n%s", r.stderr)
	}
	h.want(h.run("org", "new", "put", "db/password"), exitUsage, "BEHIND")
	// A revoke needs a choice for every secret.
	h.want(h.run("org", "", "rotate"), exitUsage, "3 secret(s) have no choice")
	h.want(h.run("org", "", "rotate", "-same", "tls/key"), exitUsage, "2 secret(s) have no choice")
	newFile := h.file("new-password", "correct horse")
	r = h.must("org", "rotate", "-set", "db/password="+newFile, "-same", "tls/key", "-retire", "api/token")
	for _, want := range []string{"epoch   1 acknowledged", "rekeyed db/password: a new value", "rekeyed tls/key: the same value", "retired api/token",
		"0 stale, epoch 1", "swept   3 version(s)", "settled at epoch 1"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("rotate lacks %q:\n%s\n%s", want, r.stdout, r.stderr)
		}
	}
	for _, m := range []string{"alice", "carol", "org"} {
		r := h.must(m, "get", "db/password")
		if r.stdout != "correct horse" || !strings.Contains(r.stderr, "version 2") || !strings.Contains(r.stderr, "anchored, current") {
			t.Fatalf("%s get after the rotation:\n%q\n%s", m, r.stdout, r.stderr)
		}
		if r := h.must(m, "get", "tls/key"); r.stdout != "KEY" {
			t.Fatalf("%s: the same-value re-keying changed the value: %q", m, r.stdout)
		}
	}
	// The removed member holds no key of the epoch the new versions name.
	r = h.run("bob", "", "get", "db/password")
	h.want(r, exitRefused, "undecryptable")
	if r.stdout != "" {
		t.Fatalf("bob read %q", r.stdout)
	}
	h.want(h.run("alice", "", "get", "api/token"), exitRefused, "holds no secret named api/token")
}

// Every member of the epoch reads; the hosts agree; the set's root is
// reproduced from each host's answer; a key that was never a member reads
// nothing; and nothing a host or the owner wrote reaches the terminal
// unfiltered.
func TestMembersReadAndHostsAgree(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	id := h.vault()
	h.put("db/password", "hunter2", "-label", "restricted", "-type", "text/plain")
	h.put("api/token", "tok-1")
	for _, m := range []string{"alice", "bob", "carol"} {
		r := h.must(m, "list")
		if !strings.Contains(r.stdout, "api/token  version 1 label confidential epoch 0") ||
			!strings.Contains(r.stdout, "db/password  version 1 label restricted epoch 0") ||
			strings.Count(r.stderr, "the set's root reproduced") != 2 || strings.Contains(r.stderr, "DISAGREES") {
			t.Fatalf("%s list:\n%s\n%s", m, r.stdout, r.stderr)
		}
	}
	r := h.must("alice", "get", "db/password")
	if !strings.Contains(r.stderr, "label restricted") || !strings.Contains(r.stderr, "type text/plain") || !strings.Contains(r.stderr, "read as a member") {
		t.Fatalf("get:\n%s", r.stderr)
	}
	if r := h.must("org", "get", "db/password"); !strings.Contains(r.stderr, "read as the owner") {
		t.Fatalf("the owner's get:\n%s", r.stderr)
	}
	r = h.must("alice", "vault", "show")
	if !strings.Contains(r.stdout, "vault   "+id) || strings.Count(r.stdout, ": consistent") != 3 || !strings.Contains(r.stdout, "state   settled at epoch 0") ||
		!strings.Contains(r.stdout, "its output is unspent per the node") {
		t.Fatalf("vault show:\n%s\n%s", r.stdout, r.stderr)
	}
	r = h.must("alice", "vault", "list")
	if !strings.Contains(r.stdout, id+"  ops  seq 2 epoch 0, 2 secret(s), 0 stale, version") {
		t.Fatalf("vault list:\n%s", r.stdout)
	}
	// By name, by identifier, and a name that names nothing.
	h.must("alice", "-vault", "ops", "get", "api/token")
	h.must("alice", "-vault", id, "get", "api/token")
	h.want(h.run("alice", "", "-vault", "nope", "get", "api/token"), exitUsage, "no vault named")
	// A key that is in no epoch of the group.
	h.identity("mallory", false)
	h.want(h.run("mallory", "", "get", "db/password"), exitRefused, "undecryptable")
	r = h.must("mallory", "list")
	if strings.Contains(r.stdout, "db/password") || strings.Count(r.stdout, "undecryptable") != 2 {
		t.Fatalf("a stranger's list:\n%s", r.stdout)
	}
	// A reader with no spend source does not call a version current.
	delete(h.env, "BSECRET_ASSET")
	r = h.must("alice", "get", "db/password")
	if !strings.Contains(r.stderr, "may be stale") || !strings.Contains(r.stderr, "not known to be current") {
		t.Fatalf("no spend source:\n%s", r.stderr)
	}
	h.want(h.run("alice", "", "get", "db/password", "-strict"), exitIncomplete, "nothing says the token read is the vault's latest")
}

// A member added to the group reads what is keyed under the epoch it
// joined: a grant is a group add, and nothing changes in the vault.
func TestAGrantIsAGroupAdd(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "hunter2")
	h.identity("dave", false)
	h.want(h.run("dave", "", "get", "db/password"), exitRefused, "undecryptable")
	if err := h.borg.Add(h.group, h.keys["dave"]); err != nil {
		t.Fatal(err)
	}
	if r := h.must("dave", "get", "db/password"); r.stdout != "hunter2" {
		t.Fatalf("dave: %q\n%s", r.stdout, r.stderr)
	}
	// Nothing changed in the vault: it is still settled.
	if r := h.must("org", "rotate"); !strings.Contains(r.stdout, "nothing to rotate") {
		t.Fatalf("rotate after an add:\n%s", r.stdout)
	}
}

// An update lists a new version; the one before stays answered as history
// by the version class, and is read as history.
func TestUpdateAndHistory(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	r := h.put("db/password", "two")
	if !strings.Contains(r.stdout, "secret  db/password version 2") || !strings.Contains(r.stdout, "(updated)") {
		t.Fatalf("update:\n%s", r.stdout)
	}
	if r := h.must("alice", "get", "db/password"); r.stdout != "two" || !strings.Contains(r.stderr, "version 2") {
		t.Fatalf("get: %q\n%s", r.stdout, r.stderr)
	}
	r = h.must("alice", "get", "db/password", "-version", "1")
	if r.stdout != "one" || !strings.Contains(r.stderr, "history: a token of the vault listed it") || strings.Contains(r.stderr, "UNANCHORED") {
		t.Fatalf("get -version 1: %q\n%s", r.stdout, r.stderr)
	}
	h.want(h.run("alice", "", "get", "db/password", "-version", "9"), exitIncomplete, "no host answers a carrier")
	// A label outside the vault's set, a name outside the grammar, no value.
	h.want(h.run("org", "x", "put", "db/password", "-label", "secret"), exitUsage, "not one of the vault's labels")
	h.want(h.run("org", "x", "put", "DB/Password"), exitUsage, "lowercase letters")
	h.want(h.run("org", "", "put", "db/password"), exitUsage, "no value")
	// A member cannot write: its home owns no vault.
	h.want(h.run("alice", "x", "put", "db/password"), exitUsage, "owns no vault")
}

// In unicast every object goes to each host; a token must reach every host
// named, so with one down the token stays persisted (exit 2) and the next
// command publishes it before anything else.
func TestUnicastTokenNeedsEveryHostAndResumes(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.env["BSECRET_MODE"] = "unicast"
	delete(h.env, "BSECRET_FACADE")
	h.vault()
	r := h.put("db/password", "hunter2")
	if strings.Count(r.stdout, "missed 0") != 2 {
		t.Fatalf("unicast tallies:\n%s", r.stdout)
	}
	for _, kind := range []string{"token", "secret"} {
		if a, b := h.a.Txids(kind), h.b.Txids(kind); len(a) == 0 || strings.Join(a, ",") != strings.Join(b, ",") {
			t.Fatalf("unicast: the hosts hold different %ss: %v %v", kind, a, b)
		}
	}
	h.b.SetDown(true)
	r = h.run("org", "next", "put", "db/password")
	h.want(r, exitUsage, "1 of 2 host(s) took it and the quorum is 2")
	h.b.SetDown(false)
	r = h.must("org", "doctor")
	if !strings.Contains(r.stdout, "outbox      secret") {
		t.Fatalf("doctor:\n%s", r.stdout)
	}
	r = h.put("api/token", "tok")
	if !strings.Contains(r.stderr, "publishing what a previous run persisted") {
		t.Fatalf("resume:\n%s\n%s", r.stdout, r.stderr)
	}
	// The carrier that was persisted is published and was never listed: it
	// is retracted, and the vault holds what the tokens list.
	if !strings.Contains(r.stdout, "swept   1 version(s) published earlier and never listed") {
		t.Fatalf("the unlisted leftover:\n%s\n%s", r.stdout, r.stderr)
	}
	if r := h.must("alice", "get", "db/password"); r.stdout != "hunter2" || strings.Contains(r.stderr, "DISAGREES") {
		t.Fatalf("after the resume: %q\n%s", r.stdout, r.stderr)
	}
	// A quorum of one publishes a carrier with a host down; the token still
	// needs both.
	h.env["BSECRET_QUORUM"] = "one"
	h.b.SetDown(true)
	r = h.run("org", "v3", "put", "db/password")
	h.want(r, exitUsage, "vault-token")
	if !strings.Contains(r.stderr, "the quorum is 2") {
		t.Fatalf("a token with a host down:\n%s\n%s", r.stdout, r.stderr)
	}
	h.b.SetDown(false)
	r = h.must("org", "doctor")
	if !strings.Contains(r.stdout, "outbox      vault-token") {
		t.Fatalf("doctor:\n%s", r.stdout)
	}
	h.want(h.run("alice", "", "get", "db/password"), exitIncomplete, "DISAGREES")
	r = h.put("api/token", "tok-2")
	if !strings.Contains(r.stderr, "vault-token") || !strings.Contains(r.stderr, "publishing what a previous run persisted") {
		t.Fatalf("the token persisted is published first:\n%s\n%s", r.stdout, r.stderr)
	}
	if r := h.must("alice", "get", "db/password"); r.stdout != "v3" || strings.Contains(r.stderr, "DISAGREES") {
		t.Fatalf("after b came back: %q\n%s", r.stdout, r.stderr)
	}
}

// A host that lost a token disagrees with the other, and a reader says so
// rather than merge silently; fill replays what it lacks.
func TestHostsDisagreeAndFill(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "hunter2")
	r := h.put("api/token", "tok")
	tokens := h.a.Txids("token")
	secrets := h.a.Txids("secret")
	_ = r
	// Host b loses the latest token and one carrier.
	var latest string
	rr := h.must("alice", "vault", "show")
	for _, l := range strings.Split(rr.stdout, "\n") {
		if strings.HasPrefix(l, "token   seq 2 ") {
			latest = strings.Fields(l)[3]
		}
	}
	if latest == "" || len(tokens) != 3 || len(secrets) != 2 {
		t.Fatalf("setup: %q %v %v", latest, tokens, secrets)
	}
	h.b.Forget(latest)
	h.b.Forget(secrets[0])
	r = h.run("alice", "", "get", "db/password")
	h.want(r, exitIncomplete, "DISAGREES: it does not answer seq 2")
	if r.stdout != "hunter2" {
		t.Fatalf("the value is still read from the host that answers: %q", r.stdout)
	}
	r = h.must("alice", "fill")
	if !strings.Contains(r.stdout, "filled  2 object(s) at 1 host(s)") || !strings.Contains(r.stdout, "vault token seq 2") {
		t.Fatalf("fill:\n%s\n%s", r.stdout, r.stderr)
	}
	if r := h.must("alice", "fill"); !strings.Contains(r.stdout, "filled  0 object(s) at 0 host(s)") {
		t.Fatalf("a second fill:\n%s", r.stdout)
	}
	h.must("alice", "get", "db/password")
	// The first token too: its parent is the chain tree, read from the node.
	first := ""
	for _, l := range strings.Split(rr.stdout, "\n") {
		if strings.HasPrefix(l, "token   seq 0 ") {
			first = strings.Fields(l)[3]
		}
	}
	for _, id := range h.b.Txids("token") {
		h.b.Forget(id)
	}
	r = h.must("alice", "fill")
	if !strings.Contains(r.stdout, "vault token seq 0 "+first[:12]) || !strings.Contains(r.stdout, "filled  3 object(s)") {
		t.Fatalf("fill from seq 0:\n%s\n%s", r.stdout, r.stderr)
	}
}

// A reader keeps the chain it verified: the next read starts from the
// token it remembers and asks the hosts only what came after; and it
// refuses an older state from every host: no going back.
func TestAReaderRemembersAndNeverGoesBack(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	h.must("alice", "get", "db/password")
	// A second read walks nothing again: the chain it kept is where it
	// starts, held to its own headers.
	before := h.a.Questions("vault-seq")
	h.must("alice", "get", "db/password")
	if n := h.a.Questions("vault-seq") - before; n != 0 {
		t.Fatalf("a reader that remembers the chain asked %d seqs again", n)
	}
	h.put("db/password", "two")
	before = h.a.Questions("vault-seq")
	if r := h.must("alice", "get", "db/password"); r.stdout != "two" {
		t.Fatalf("alice: %q\n%s", r.stdout, r.stderr)
	}
	if n := h.a.Questions("vault-seq") - before; n != 1 {
		t.Fatalf("a reader that remembers seq 1 asked %d seqs for one new token", n)
	}
	// A reader with no home remembers nothing and walks from seq 0.
	before = h.a.Questions("vault-seq")
	h.must("nobody", "vault", "show")
	if n := h.a.Questions("vault-seq") - before; n != 3 {
		t.Fatalf("a reader with no memory asked %d seqs of a chain of 3", n)
	}
	// One host goes back to the state before the update: it is named, and
	// the vault is read from the other.
	var latest string
	r := h.must("alice", "vault", "show")
	for _, l := range strings.Split(r.stdout, "\n") {
		if strings.HasPrefix(l, "token   seq 2 ") {
			latest = strings.Fields(l)[3]
		}
	}
	h.b.Forget(latest)
	r = h.run("alice", "", "get", "db/password")
	h.want(r, exitIncomplete, "answers the vault to seq 1 as its latest, and this home verified seq 2")
	if r.stdout != "two" {
		t.Fatalf("the value is read from the host that is not behind: %q", r.stdout)
	}
	// Both hosts go back: refused.
	h.a.Forget(latest)
	r = h.run("alice", "", "get", "db/password")
	h.want(r, exitRefused, "rollback")
	if r.stdout != "" {
		t.Fatalf("an older value was written: %q", r.stdout)
	}
	// A reader with no memory has only the spend source: the node says the
	// token the hosts answer is spent by the vault's next token.
	h.want(h.run("carol", "", "get", "db/password"), exitIncomplete, "is spent by its next token")
}

// A secret over the inline bound is kept by its hash in a content
// directory: the record names it, a reader fetches it within its budget,
// and the hash check names whoever served other bytes.
func TestLargeSecretByHash(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	big := strings.Repeat("0123456789abcdef", 2500) // 40000 bytes
	r := h.put("blob/archive", big)
	m := regexp.MustCompile(`(?m)^stored  (\S+) \((\d+) bytes of ciphertext; serve it under (uhrp://\S+)\)$`).FindStringSubmatch(r.stdout)
	if m == nil {
		t.Fatalf("put of a large secret:\n%s\n%s", r.stdout, r.stderr)
	}
	if r := h.must("alice", "get", "blob/archive"); r.stdout != big {
		t.Fatalf("a member's read of a large secret: %d bytes\n%s", len(r.stdout), r.stderr)
	}
	// A reader's budget bounds what it fetches.
	h.env["BSECRET_MAX_FETCH"] = "1000"
	h.want(h.run("alice", "", "get", "blob/archive"), exitUsage, "over this reader's fetch budget")
	delete(h.env, "BSECRET_MAX_FETCH")
	// Substituted, then cut: check 1, before any wrap is opened.
	raw, err := os.ReadFile(m[1])
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), raw...)
	bad[100] ^= 1
	for _, b := range [][]byte{bad, raw[:16400]} {
		if err := os.WriteFile(m[1], b, 0o644); err != nil {
			t.Fatal(err)
		}
		r := h.run("alice", "", "get", "blob/archive")
		h.want(r, exitRefused, "hash: the ciphertext served is not the one the record names")
		if r.stdout != "" {
			t.Fatal("a substituted ciphertext was opened")
		}
	}
	// Served by nobody: unreadable, and that proves nothing.
	if err := os.Remove(m[1]); err != nil {
		t.Fatal(err)
	}
	h.want(h.run("alice", "", "get", "blob/archive"), exitIncomplete, "no content source holds the ciphertext")
	// With no content directory a large secret cannot be written.
	delete(h.env, "BSECRET_CONTENT")
	h.want(h.run("org", big, "put", "blob/other"), exitUsage, "no content directory is configured")
	// A same-value re-keying of a large secret needs its ciphertext too.
	h.env["BSECRET_CONTENT"] = filepath.Join(h.dir, "content")
	if err := os.WriteFile(m[1], raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := h.borg.Rotate(h.group); err != nil {
		t.Fatal(err)
	}
	h.must("org", "rotate", "-same-all")
	if r := h.must("alice", "get", "blob/archive"); r.stdout != big || !strings.Contains(r.stderr, "version 2") {
		t.Fatalf("after the re-keying: %d bytes\n%s", len(r.stdout), r.stderr)
	}
}

// The owner's tooling refuses to publish a version whose content key it
// has published under before: a key and salt used twice give anyone the
// XOR of the two plaintexts. Not parallel: it replaces the key source.
func TestACommitmentIsNeverPublishedTwice(t *testing.T) {
	h := newHarness(t)
	h.vault()
	var k [32]byte
	k[31] = 7
	sampleHook = func() ([32]byte, [secrec.SaltLen]byte, error) { return k, [secrec.SaltLen]byte{1, 2, 3, 4}, nil }
	defer func() { sampleHook = nil }()
	h.put("db/password", "one")
	before := len(h.a.Txids("secret"))
	r := h.run("org", "two", "put", "api/token")
	h.want(r, exitRefused, "this commitment was published or listed before")
	r = h.run("org", "two", "put", "db/password")
	h.want(r, exitRefused, "refusing to publish")
	if n := len(h.a.Txids("secret")); n != before {
		t.Fatalf("a carrier was published under a used key: %d carriers, %d before", n, before)
	}
	// A fresh key is taken.
	k[31] = 8
	h.put("api/token", "two")
}

// An interval vault: a version published and not listed is taken by its
// link to the listed one and marked unanchored; anchor lists the latest,
// and the versions between are retracted.
func TestIntervalVault(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault("-anchor", "interval")
	// A secret's first version is listed.
	h.want(h.run("org", "t0", "put", "svc/token", "-defer"), exitUsage, "a secret's first version is listed")
	h.put("svc/token", "t1")
	if r := h.put("svc/token", "t2", "-defer"); !strings.Contains(r.stdout, "deferred: published and not listed") {
		t.Fatalf("put -defer:\n%s", r.stdout)
	}
	r := h.must("alice", "get", "svc/token")
	if r.stdout != "t2" || !strings.Contains(r.stderr, "version 2") || !strings.Contains(r.stderr, "UNANCHORED") {
		t.Fatalf("an unlisted successor: %q\n%s", r.stdout, r.stderr)
	}
	h.put("svc/token", "t3", "-defer")
	if r := h.must("alice", "get", "svc/token"); r.stdout != "t3" || !strings.Contains(r.stderr, "UNANCHORED") {
		t.Fatalf("a run of two: %q\n%s", r.stdout, r.stderr)
	}
	// The set still lists version 1: a reader that takes only listed
	// versions sees it, and the list says which is listed.
	if r := h.must("alice", "list"); !strings.Contains(r.stdout, "svc/token  version 1") {
		t.Fatalf("list:\n%s", r.stdout)
	}
	r = h.must("org", "anchor")
	// Version 2 came and went between two tokens: it is retracted. Version
	// 1 was listed and replaced under the same epoch: it stays, as history.
	if !strings.Contains(r.stdout, "anchored 1 secret(s)") || !strings.Contains(r.stdout, "swept   1 version(s) that came and went") {
		t.Fatalf("anchor:\n%s\n%s", r.stdout, r.stderr)
	}
	r = h.must("alice", "get", "svc/token")
	if r.stdout != "t3" || !strings.Contains(r.stderr, "version 3") || !strings.Contains(r.stderr, "anchored, current") {
		t.Fatalf("after the anchor: %q\n%s", r.stdout, r.stderr)
	}
	if r := h.must("org", "anchor"); !strings.Contains(r.stdout, "nothing to anchor") {
		t.Fatalf("a second anchor:\n%s", r.stdout)
	}
	// In a per-version vault nothing is deferred.
	h2 := newHarness(t)
	h2.vault()
	h2.put("svc/token", "t1")
	h2.want(h2.run("org", "t2", "put", "svc/token", "-defer"), exitUsage, "-defer is for an interval vault")
	h2.want(h2.run("org", "", "anchor"), exitUsage, "per-version")
}

// The priced classes: a host answers 402, the command pays it and reads;
// the audit verifies the trail from headers and reports the exposure
// window; the payee settles what the host recorded.
func TestPaidAuditHistoryAndThePayee(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	id := h.vault()
	h.identity("payee", false)
	h.identity("auditor", true)
	h.put("db/password", "one")
	h.put("db/password", "two")
	h.put("api/token", "tok")
	if err := h.borg.Remove(h.group, h.keys["bob"]); err != nil {
		t.Fatal(err)
	}
	// One token written late, under the old epoch, would be refused by the
	// tooling; the acknowledgement comes two blocks after the removal.
	h.chain.Generate(2, "")
	h.must("org", "rotate", "-same", "db/password", "-retire", "api/token", "-keep")
	h.startPaid("payee", map[string]uint64{"history": 5, "history-after": 5, "audit": 20, "audit-after": 20})
	r := h.must("auditor", "terms")
	if !strings.Contains(r.stdout, "audit          20 sat a question") || !strings.Contains(r.stdout, "history        5 sat a question") {
		t.Fatalf("terms:\n%s", r.stdout)
	}
	// The priced class is refused on the host's own lookup.
	r = h.must("auditor", "audit")
	for _, want := range []string{"paid 20 sat to ", " for audit,", "vault   " + id + " ops", "(a member removed): acknowledged at height", "settled at height",
		"window  epoch 1: ", "re-keyed at seq 4", "retired at seq 4", "audit   OK: 5 token(s) mined"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("audit lacks %q:\n%s\n%s", want, r.stdout, r.stderr)
		}
	}
	win := regexp.MustCompile(`(?m)^window  epoch 1: (\d+) block\(s\) from`).FindStringSubmatch(r.stdout)
	if win == nil || win[1] == "0" {
		t.Fatalf("the exposure window:\n%s", r.stdout)
	}
	// The same trail, free, token by token, with no home at all.
	r2 := h.must("nobody", "-org", h.env["BSECRET_ORG"], "-vault", id, "audit", "-free")
	if strings.Contains(r2.stdout, "paid ") || !strings.Contains(r2.stdout, "window  epoch 1: "+win[1]+" block(s)") || !strings.Contains(r2.stdout, "audit   OK") {
		t.Fatalf("audit -free from no home:\n%s\n%s", r2.stdout, r2.stderr)
	}
	// Without a home the priced class cannot be paid.
	h.want(h.run("nobody", "", "-org", h.env["BSECRET_ORG"], "-vault", id, "audit"), exitUsage, "paid from a home's pool")
	// As JSON.
	r = h.must("auditor", "audit", "-json", "-free")
	var rep auditReport
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil || !rep.OK || len(rep.Tokens) != 5 || len(rep.Windows) != 1 || rep.Windows[0].Open || len(rep.Events) != 2 {
		t.Fatalf("audit -json: %v\n%s", err, r.stdout)
	}
	// A price over the limit is not paid.
	h.want(h.run("auditor", "", "audit", "-max-sats", "10"), exitUsage, "-max-sats")
	// History: every version a host still holds, the one the rotation kept
	// included.
	r = h.must("auditor", "history", "db/password")
	if !strings.Contains(r.stdout, "paid 5 sat to ") || strings.Count(r.stdout, "\nversion ") != 3 || !strings.Contains(r.stdout, "version 1 ") {
		t.Fatalf("history:\n%s\n%s", r.stdout, r.stderr)
	}
	// The payee settles the host's ledger.
	ledger := h.file("payments.jsonl", string(h.paid.Ledger()))
	r = h.must("payee", "payee", "settle", ledger)
	if !strings.Contains(r.stdout, "2 payment(s) settled, 25 sat") {
		t.Fatalf("payee settle:\n%s\n%s", r.stdout, r.stderr)
	}
	if r := h.must("payee", "payee", "settle", ledger); !strings.Contains(r.stdout, "0 payment(s) settled, 0 sat; 2 settled before") {
		t.Fatalf("a second settle:\n%s", r.stdout)
	}
}

// A vault that never acknowledges: every host admits it, and the audit
// counts the tokens written under the old epoch and reports the window
// open.
func TestAuditOfAVaultThatDoesNotAcknowledge(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	if err := h.borg.Remove(h.group, h.keys["bob"]); err != nil {
		t.Fatal(err)
	}
	h.chain.Generate(3, "")
	r := h.must("alice", "audit")
	if !strings.Contains(r.stdout, "NEVER ACKNOWLEDGED in this trail") || !strings.Contains(r.stdout, "window  epoch 1: OPEN") ||
		!strings.Contains(r.stdout, "1 secret(s) still listed under an earlier epoch") || !strings.Contains(r.stdout, "audit   OK") {
		t.Fatalf("audit of a vault behind:\n%s\n%s", r.stdout, r.stderr)
	}
	r = h.run("alice", "", "due")
	h.want(r, exitIncomplete, "the group began epoch 1")
	h.want(h.run("alice", "", "get", "db/password", "-strict"), exitRefused, "exposed or the vault is not settled")
	// The owner's own home names what is due.
	r = h.run("org", "", "due")
	h.want(r, exitIncomplete, "due     db/password version 1 is keyed under epoch 0")
}

// A second home made around the organisation's identity rebuilds from the
// hosts and writes; the first home, whose vault another instance moved,
// refuses to write until it catches up.
func TestSyncOnASecondHome(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	id := h.vault()
	h.put("db/password", "one")
	h.put("api/token", "tok")
	org2 := h.identity("org2", true, "-borg", h.borg.Home)
	if org2 != h.env["BSECRET_ORG"] {
		t.Fatal("the second home is another identity")
	}
	h.want(h.run("org2", "x", "put", "db/password"), exitUsage, "owns no vault")
	r := h.must("org2", "sync")
	if !strings.Contains(r.stdout, "synced  1 vault(s) (1 new), 3 token(s), 2 version(s) read, 2 name(s) opened, 1 funding tree(s) recorded") {
		t.Fatalf("sync:\n%s\n%s", r.stdout, r.stderr)
	}
	r = h.mustIn("org2", "two", "put", "db/password")
	if !strings.Contains(r.stdout, "secret  db/password version 2") {
		t.Fatalf("put from the second home:\n%s", r.stdout)
	}
	if r := h.must("alice", "get", "db/password"); r.stdout != "two" {
		t.Fatalf("alice: %q", r.stdout)
	}
	// The first home's record is behind: its evidence fails closed.
	h.want(h.run("org", "three", "put", "db/password"), exitRefused, "run `bsecret sync`")
	r = h.must("org", "sync")
	if !strings.Contains(r.stdout, "synced  1 vault(s) (0 new), 1 token(s)") {
		t.Fatalf("the first home catches up:\n%s", r.stdout)
	}
	r = h.mustIn("org", "three", "put", "db/password")
	if !strings.Contains(r.stdout, "secret  db/password version 3") {
		t.Fatalf("put after the catch-up:\n%s", r.stdout)
	}
	// The second home rotates what the first wrote, and sweeps a version
	// another instance published, from the tree sync recorded.
	if err := h.borg.Remove(h.group, h.keys["bob"]); err != nil {
		t.Fatal(err)
	}
	h.must("org2", "sync")
	r = h.must("org2", "rotate", "-same-all")
	if !strings.Contains(r.stdout, "rekeyed api/token") || !strings.Contains(r.stdout, "rekeyed db/password") || !strings.Contains(r.stdout, "swept   ") {
		t.Fatalf("rotate from the second home:\n%s\n%s", r.stdout, r.stderr)
	}
	h.want(h.run("bob", "", "get", "db/password"), exitRefused, "undecryptable")
	if r := h.must("carol", "-vault", id, "get", "db/password"); r.stdout != "three" {
		t.Fatalf("carol: %q", r.stdout)
	}
}

// The kill switch retracts every version the home published; a reader
// checks a record's funding outpoint itself, so a host that missed the
// sweep and still answers the carrier does not get it read.
func TestKillAndARetractedVersionIsNeverRead(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	r := h.must("org", "kill", "-confirm", "KILL")
	if !strings.Contains(r.stdout, "tree(s) to sweep; nothing was sent") || len(h.a.Txids("sweep")) != 0 {
		t.Fatalf("kill without -yes:\n%s", r.stdout)
	}
	h.want(h.run("org", "", "kill"), exitUsage, "-confirm KILL")
	r = h.must("org", "kill", "-confirm", "KILL", "-yes")
	if !strings.Contains(r.stdout, "killed  ") || !strings.Contains(r.stderr, "not erasure") {
		t.Fatalf("kill:\n%s\n%s", r.stdout, r.stderr)
	}
	// Honest hosts stop answering it: nothing is held, which proves
	// nothing, and the chain stays.
	h.want(h.run("alice", "", "get", "db/password"), exitIncomplete, "no host answers its carrier")
	h.must("alice", "vault", "show")
	// Host b loses the sweep and answers the carrier again; host a answers
	// the sweep, and the reader refuses the record.
	for _, id := range h.b.Txids("sweep") {
		h.b.Forget(id)
	}
	r = h.run("alice", "", "get", "db/password")
	h.want(r, exitRefused, "retracted")
	if r.stdout != "" {
		t.Fatalf("a retracted version was read: %q", r.stdout)
	}
	// Fill gives host b the sweep it lacks.
	r = h.run("alice", "", "fill")
	if !strings.Contains(r.stdout, "filled  sweep ") {
		t.Fatalf("fill of a sweep:\n%s\n%s", r.stdout, r.stderr)
	}
	h.want(h.run("alice", "", "get", "db/password"), exitIncomplete, "no host answers its carrier")
	// With no host answering the sweep, the node's view of the funding
	// output finds it, by its proof; with neither, a reader cannot know.
	for _, host := range []*testhost.Host{h.a, h.b} {
		for _, id := range host.Txids("sweep") {
			host.Forget(id)
		}
	}
	h.want(h.run("alice", "", "get", "db/password"), exitRefused, "retracted")
	delete(h.env, "BSECRET_ASSET")
	if r := h.run("alice", "", "get", "db/password"); r.code != exitOK || r.stdout != "one" {
		t.Fatalf("with neither a host's sweep nor a chain source: exit %d %q\n%s", r.code, r.stdout, r.stderr)
	}
	h.env["BSECRET_ASSET"] = h.chainS.URL
	// Nothing is funded from a killed tree again.
	if r := h.must("org", "kill", "-confirm", "KILL"); !strings.Contains(r.stdout, "0 tree(s) to sweep") {
		t.Fatalf("after the kill:\n%s", r.stdout)
	}
}

// A version keyed under a new epoch is published only once borg's wraps of
// that epoch's key are: otherwise the members who remain could not open it.
func TestRotateWaitsForTheWraps(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	// The readiness check, before the removal: every secret needs a choice.
	h.want(h.run("org", "", "rotate", "-check"), exitRefused, "not ready: 1 secret(s) have no choice")
	if r := h.must("org", "rotate", "-check", "-same-all"); !strings.Contains(r.stdout, "were the group to begin a new epoch now") {
		t.Fatalf("rotate -check:\n%s", r.stdout)
	}
	h.want(h.run("org", "", "rotate", "-check", "-retire", "db/pasword"), exitRefused, "not a secret this vault ever held")
	h.borg.NoWraps = true
	if err := h.borg.Remove(h.group, h.keys["bob"]); err != nil {
		t.Fatal(err)
	}
	before := len(h.a.Txids("token"))
	r := h.run("org", "", "rotate", "-same-all")
	h.want(r, exitIncomplete, "borg's wraps of the new epoch's key are not published")
	if len(h.a.Txids("token")) != before {
		t.Fatal("a token was minted before the wraps were published")
	}
	if err := h.borg.Wrap(h.group); err != nil {
		t.Fatal(err)
	}
	h.must("org", "rotate", "-same-all")
	if r := h.must("alice", "get", "db/password"); r.stdout != "one" || !strings.Contains(r.stderr, "epoch 1") {
		t.Fatalf("alice: %q\n%s", r.stdout, r.stderr)
	}
	// Run again: nothing is owed, and the choices are not used.
	if r := h.must("org", "rotate", "-same-all"); !strings.Contains(r.stdout, "nothing to rotate") {
		t.Fatalf("a second rotate:\n%s", r.stdout)
	}
}

// A vault of more secrets than one token changes re-keys in several
// tokens, one a block: the acknowledgement carries the first batch, and the
// chain admits nothing else until the rest are done. (A token changes 8
// here; the record bound is 64.)
func TestRotateTakesSeveralTokens(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.env["BSECRET_TREE_COUNT"] = "64"
	h.vault()
	g, _, errb := h.global("org")
	ctx := context.Background()
	w, err := g.openWriter(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const n = 19
	for start := 0; start < n; start += 8 {
		wr, err := g.ready(ctx, w)
		if err != nil {
			t.Fatal(err)
		}
		var items []engine.Item
		for i := start; i < min(start+8, n); i++ {
			items = append(items, engine.Item{Name: fmt.Sprintf("svc/key-%02d", i), Value: []byte(fmt.Sprintf("value %d", i))})
		}
		if _, err := w.eng.Put(ctx, wr, items, false); err != nil {
			t.Fatalf("put: %v\n%s", err, errb)
		}
	}
	wr, err := g.ready(ctx, w)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.eng.Put(ctx, wr, make([]engine.Item, 9), false); err == nil || !strings.Contains(err.Error(), "at most 8") {
		t.Fatalf("nine secrets in one token: %v", err)
	}
	w.close(ctx, g)
	if err := h.borg.Remove(h.group, h.keys["bob"]); err != nil {
		t.Fatal(err)
	}
	r := h.must("org", "rotate", "-same-all", "-retire", "svc/key-18")
	// Three tokens: stale 19 - 8, then - 8, then the last 3.
	for _, want := range []string{", 11 stale, epoch 1", ", 3 stale, epoch 1", "18 secret(s), 0 stale, epoch 1", "retired svc/key-18", "swept   19 version(s)"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("a rotation in three tokens lacks %q:\n%s", want, r.stdout)
		}
	}
	if strings.Count(r.stdout, "rekeyed ") != 18 || strings.Count(r.stdout, "\ntoken   ") != 3 {
		t.Fatalf("a rotation in three tokens:\n%s", r.stdout)
	}
	if r := h.must("alice", "get", "svc/key-07"); r.stdout != "value 7" {
		t.Fatalf("alice: %q", r.stdout)
	}
	h.want(h.run("bob", "", "get", "svc/key-07"), exitRefused, "undecryptable")
	r = h.must("alice", "audit")
	if !strings.Contains(r.stdout, "audit   OK: 7 token(s)") || strings.Count(r.stdout, "\nsecret  ") != 19 || !strings.Contains(r.stdout, "window  epoch 1: 3 block(s)") {
		t.Fatalf("audit:\n%s", r.stdout)
	}
	// More secrets than one page of the secrets class holds.
	if r := h.must("alice", "list"); strings.Count(r.stdout, "svc/key-") != 18 || strings.Count(r.stderr, "the set's root reproduced") != 2 {
		t.Fatalf("list across pages:\n%s\n%s", r.stdout, r.stderr)
	}
}

// An object the plane lost on the way to one host is found missing by the
// publisher's own lookup and offered to that host directly.
func TestThePlaneLosesAnObject(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.plane.Lost = func(host int, _ []byte) bool { return host == 1 }
	r := h.put("db/password", "one")
	if !strings.Contains(r.stderr, "lacked it after the plane's delivery; offered directly and confirmed") {
		t.Fatalf("a lost carrier:\n%s", r.stderr)
	}
	if a, b := h.a.Txids("secret"), h.b.Txids("secret"); len(b) != 1 || a[0] != b[0] {
		t.Fatalf("host b lacks the carrier: %v %v", a, b)
	}
	if r := h.must("alice", "get", "db/password"); strings.Contains(r.stderr, "DISAGREES") {
		t.Fatalf("the hosts disagree:\n%s", r.stderr)
	}
}

// The value is written only when standard output is not a terminal, or
// with -show; and a display name is someone else's text.
func TestTheTerminal(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.organisation()
	h.identity("alice", false)
	gid, err := h.borg.CreateGroup("engineering", h.keys["alice"])
	if err != nil {
		t.Fatal(err)
	}
	// This tooling writes no such name; a vault's owner can sign one all
	// the same, with any other.
	h.env["BSECRET_VAULT"] = h.namedVault(gid, "ops\x1b[2J\x1b]0;owned\x07")
	h.put("db/password", "hunter2")
	ctx := context.Background()
	g, out, errb := h.global("alice")
	g.terminal = true
	if err := cmdGet(ctx, g, []string{"db/password"}); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 || !strings.Contains(errb.String(), "not written: standard output is a terminal") {
		t.Fatalf("a terminal was written a value: %q\n%s", out, errb)
	}
	if strings.ContainsAny(errb.String(), "\x1b\x07") {
		t.Fatalf("the vault's name reached the terminal unfiltered: %q", errb.String())
	}
	g, out, _ = h.global("alice")
	g.terminal = true
	if err := cmdGet(ctx, g, []string{"db/password", "-show"}); err != nil || out.String() != "hunter2" {
		t.Fatalf("-show: %v %q", err, out)
	}
	for _, args := range [][]string{{"vault", "show"}, {"vault", "list"}, {"audit", "-free"}, {"due"}} {
		r := h.run("alice", "", args...)
		if strings.ContainsAny(r.stdout+r.stderr, "\x1b\x07") {
			t.Fatalf("%v wrote a control sequence: %q", args, r.stdout+r.stderr)
		}
	}
	if r := h.must("org", "doctor"); strings.ContainsAny(r.stdout, "\x1b\x07") {
		t.Fatalf("doctor wrote a control sequence: %q", r.stdout)
	}
}

// copyHome copies a home, as a second device of one owner would hold it.
func copyHome(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		dst := filepath.Join(to, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o700)
		}
		if d.Name() == "lock" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A transition another transition beat to the chain is discarded: nothing
// it listed is listed, and what it published is unlisted.
func TestALostTransition(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	// A second home of the organisation, with coin and funding trees of
	// its own, caught up by sync: two instances never share a tree.
	h.identity("org2", true, "-borg", h.borg.Home)
	h.must("org2", "sync")
	// Between the first home's evidence and its send, the second home's
	// transition takes the vault's tip.
	var won result
	h.mu.Lock()
	h.onSend = func(*transaction.Transaction) { won = h.run("org2", "theirs", "put", "db/password") }
	h.mu.Unlock()
	r := h.run("org", "ours", "put", "db/password")
	if won.code != exitOK {
		t.Fatalf("the second home's put: exit %d\n%s\n%s", won.code, won.stdout, won.stderr)
	}
	h.want(r, exitRefused, "lost: its predecessor is spent by ")
	r = h.must("org", "doctor")
	if !strings.Contains(r.stdout, "1 version(s) published and not listed") || strings.Contains(r.stdout, "transition  ") {
		t.Fatalf("doctor after a lost transition:\n%s", r.stdout)
	}
	// The home's evidence now fails closed: its tip is spent.
	h.want(h.run("org", "three", "put", "db/password"), exitRefused, "run `bsecret sync`")
	h.must("org", "sync")
	h.put("db/password", "three")
	if r := h.must("alice", "get", "db/password"); r.stdout != "three" {
		t.Fatalf("alice: %q\n%s", r.stdout, r.stderr)
	}
}

// A spender of the predecessor that the node cannot show settles nothing:
// it may be this very transition under another txid (a re-encoded copy,
// which is the same transition). The transition is kept until the spender
// is read.
func TestASpenderTheNodeCannotShowDiscardsNothing(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	r := h.must("org", "vault", "show")
	var tip string
	for _, l := range strings.Split(r.stdout, "\n") {
		if strings.HasPrefix(l, "token   seq 1 ") {
			tip = strings.Fields(l)[3]
		}
	}
	other := strings.Repeat("ab", 32)
	h.mu.Lock()
	h.onSend = func(*transaction.Transaction) { h.chain.SpendElsewhere(tip, 0, other) }
	h.mu.Unlock()
	r = h.run("org", "two", "put", "db/password")
	if r.code != exitUsage || strings.Contains(r.stderr, "lost") || !strings.Contains(r.stderr, "which the node could not show") {
		t.Fatalf("a spender the node cannot show: exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	if r := h.must("org", "doctor"); !strings.Contains(r.stdout, "transition  ") {
		t.Fatalf("the transition was discarded:\n%s", r.stdout)
	}
}

// A persisted transition is given up only when the node names ANOTHER
// transaction as the spender of its predecessor or its fee coin. A leg
// that refuses it while the node shows the predecessor spent by this very
// transaction (it was taken before, and has not mined) changes nothing: it
// stays persisted, and nothing it listed is thrown away.
func TestATransitionIsKeptUnlessAnotherSpends(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	r := h.must("org", "vault", "show")
	var tip string
	for _, l := range strings.Split(r.stdout, "\n") {
		if strings.HasPrefix(l, "token   seq 1 ") {
			tip = strings.Fields(l)[3]
		}
	}
	h.mu.Lock()
	h.onSend = func(tx *transaction.Transaction) { h.chain.SpendElsewhere(tip, 0, tx.TxID().String()) }
	h.mu.Unlock()
	h.env["BSECRET_TIMEOUT"] = "1s"
	r = h.run("org", "two", "put", "db/password")
	if r.code != exitUsage || strings.Contains(r.stderr, "lost") || !strings.Contains(r.stderr, "it is persisted; the next command sends it again") {
		t.Fatalf("a transition the leg refused while the node names it as the spender: exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	r = h.must("org", "doctor")
	if !strings.Contains(r.stdout, "transition  ") || !strings.Contains(r.stdout, "persisted and not yet mined") {
		t.Fatalf("the transition was discarded:\n%s", r.stdout)
	}
}

// A sweep is marked failed only when the node names another transaction
// as the spender of one of its inputs. A leg's refusal alone leaves it in
// flight: the next command sends the same bytes again.
func TestASweepIsKeptUnlessAnotherSpends(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	h.put("api/token", "tok")
	refused := false
	// The sweep is refused once by the leg, with every input unspent.
	h.chain.Refuse = func(tx *transaction.Transaction) string {
		if refused || len(tx.Outputs) == 0 || !secrec.IsFundingShape(*tx.Outputs[0].LockingScript) {
			return ""
		}
		refused = true
		return "txn-mempool-conflict"
	}
	r := h.run("org", "", "kill", "-confirm", "KILL", "-yes")
	if !refused || strings.Contains(r.stdout+r.stderr, "marked failed") || !strings.Contains(r.stderr, "NOT SWEPT") {
		t.Fatalf("a sweep the leg refused once: exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	if r := h.must("org", "doctor"); !strings.Contains(r.stdout, "in flight") || strings.Contains(r.stdout, "FAILED") {
		t.Fatalf("the sweep is not in flight:\n%s", r.stdout)
	}
	r = h.must("org", "kill", "-confirm", "KILL", "-yes")
	if !strings.Contains(r.stdout, "killed  ") {
		t.Fatalf("the sweep was not finished by the next run:\n%s\n%s", r.stdout, r.stderr)
	}
	h.want(h.run("alice", "", "get", "db/password"), exitIncomplete, "no host answers its carrier")
}

type fakeHeaders struct {
	ok  bool
	err error
}

func (f fakeHeaders) IsValidRootForHeight(context.Context, *chainhash.Hash, uint32) (bool, error) {
	return f.ok, f.err
}
func (f fakeHeaders) CurrentHeight(context.Context) (uint32, error) { return 1 << 20, f.err }

type fakeSource struct {
	mp  *transaction.MerklePath
	err error
}

func (f fakeSource) Spender(context.Context, string, uint32) (string, error) { return "", nil }
func (f fakeSource) TxRaw(context.Context, string) ([]byte, error)           { return nil, errors.New("none") }
func (f fakeSource) MerkleProof(context.Context, string) (*transaction.MerklePath, error) {
	return f.mp, f.err
}

// The floor a reader keeps is never forgotten because a source failed: a
// header source that errors, or a copy of the chain that does not read
// back, leaves the highest seq verified in force, and hosts that roll the
// vault back are still refused. Only the node's word that the remembered
// token is not mined, after its stored proof stopped verifying, is a
// reorganisation.
func TestTheFloorSurvivesAFailingSource(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	id := h.vault()
	h.put("db/password", "one")
	h.put("db/password", "two")
	if r := h.must("alice", "get", "db/password"); r.stdout != "two" {
		t.Fatal("setup")
	}
	org, _ := hex.DecodeString(h.env["BSECRET_ORG"])
	vault, _ := vread.Hex32(id)
	home := filepath.Join(h.dir, "alice")
	kept := state.LoadChain(home, h.crypt, h.env["BSECRET_ORG"], id)
	if len(kept) != 3 {
		t.Fatalf("alice kept %d tokens", len(kept))
	}
	ctx := context.Background()
	rem := func(beefs [][]byte, hd fakeHeaders, src vread.ChainSource) vread.Memory {
		_, m := vread.Remembered(ctx, beefs, h.crypt, org, vault, hd, src)
		return m
	}
	_, last, err := secrec.StoredToken(kept[2])
	if err != nil || last == nil {
		t.Fatal(err)
	}
	tx, _, _ := secrec.StoredToken(kept[2])
	for _, c := range []struct {
		what string
		got  vread.Memory
		want vread.Memory
	}{
		{"the proof verifies", rem(kept, fakeHeaders{ok: true}, nil), vread.MemoryHeld},
		{"the header source errors", rem(kept, fakeHeaders{err: errors.New("down")}, fakeSource{err: nodeapi.ErrNotMined}), vread.MemoryUnknown},
		{"the proof fails and there is no chain source", rem(kept, fakeHeaders{}, nil), vread.MemoryUnknown},
		{"the proof fails and the chain source errors", rem(kept, fakeHeaders{}, fakeSource{err: errors.New("down")}), vread.MemoryUnknown},
		{"the proof fails and the chain source's proof fails too", rem(kept, fakeHeaders{}, fakeSource{mp: tx.MerklePath}), vread.MemoryUnknown},
		{"the proof fails and the chain source says not mined", rem(kept, fakeHeaders{}, fakeSource{err: nodeapi.ErrNotMined}), vread.MemoryDisplaced},
		{"a token is missing from the copy", rem(kept[1:], fakeHeaders{ok: true}, nil), vread.MemoryCorrupt},
		{"the copy is not a token", rem([][]byte{{1, 2, 3}}, fakeHeaders{ok: true}, nil), vread.MemoryCorrupt},
		{"nothing kept", rem(nil, fakeHeaders{ok: true}, nil), vread.MemoryNone},
	} {
		if c.got != c.want {
			t.Errorf("%s: memory %d, want %d", c.what, c.got, c.want)
		}
	}
	// A read while the header source is down fails, and forgets nothing.
	url := h.env["BSECRET_HEADER_URL"]
	h.env["BSECRET_HEADER_URL"] = "http://127.0.0.1:1"
	if r := h.run("alice", "", "get", "db/password"); r.code == exitOK {
		t.Fatalf("a read with no header source passed:\n%s", r.stderr)
	}
	h.env["BSECRET_HEADER_URL"] = url
	// The copy of the chain is damaged too.
	if err := state.SaveChain(home, h.crypt, h.env["BSECRET_ORG"], id, [][]byte{{1, 2, 3}}); err != nil {
		t.Fatal(err)
	}
	// Both hosts roll the vault back.
	r := h.must("carol", "vault", "show")
	for _, l := range strings.Split(r.stdout, "\n") {
		if strings.HasPrefix(l, "token   seq 2 ") {
			h.a.Forget(strings.Fields(l)[3])
			h.b.Forget(strings.Fields(l)[3])
		}
	}
	r = h.run("alice", "", "get", "db/password")
	h.want(r, exitRefused, "rollback")
	if r.stdout != "" || !strings.Contains(r.stderr, "does not read back") {
		t.Fatalf("a rolled-back value after a failing source: %q\n%s", r.stdout, r.stderr)
	}
}

// One question is paid for once, and a payment that left this process is
// never given back to the pool: a host that keeps answering 402 is handed
// one payment and no more, and a host that took a payment and did not
// answer leaves the payer's next payment on other coins, so both settle.
func TestOnePaymentAQuestionAndNoRefundOnceSent(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.identity("payee", false)
	h.identity("auditor", true)
	h.put("db/password", "one")
	h.startPaid("payee", map[string]uint64{"audit": 20, "audit-after": 20})
	sends := func() int { return h.chain.Sent }
	// A host that asks again and again.
	h.paid.Again = true
	before := sends()
	r := h.run("auditor", "", "audit")
	h.want(r, exitRefused, "asked for a payment again after one was sent")
	if strings.Count(r.stderr, "was sent to") != 1 {
		t.Fatalf("a host that keeps answering 402:\n%s\n%s", r.stdout, r.stderr)
	}
	// Exactly one payment of this home's reached the settlement leg: the
	// one it made, kept as made.
	if n := sends() - before; n != 1 {
		t.Fatalf("%d transactions were sent for one question", n)
	}
	h.paid.Again = false
	// A host that takes the payment and does not answer.
	h.paid.FailPaid = true
	r = h.run("auditor", "", "audit")
	if r.code != exitUsage || !strings.Contains(r.stderr, "it left this process, so it is kept as made") || !strings.Contains(r.stderr, "status 500") {
		t.Fatalf("a host that took a payment and answered 500: exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	h.paid.FailPaid = false
	// The next payment spends other coin, and the question is answered.
	r = h.must("auditor", "audit")
	if !strings.Contains(r.stdout, "paid 20 sat to ") || !strings.Contains(r.stdout, "audit   OK") {
		t.Fatalf("the audit after:\n%s\n%s", r.stdout, r.stderr)
	}
	// Both payments the host recorded settle: neither was made on a coin
	// that another spent.
	ledger := h.file("payments.jsonl", string(h.paid.Ledger()))
	r = h.must("payee", "payee", "settle", ledger)
	if !strings.Contains(r.stdout, "2 payment(s) settled, 40 sat") || strings.Contains(r.stdout+r.stderr, "REFUSED") {
		t.Fatalf("payee settle:\n%s\n%s", r.stdout, r.stderr)
	}
}

// The home's lock is taken before its wallet is opened: the coin pool is
// read whole and written back whole, so a pool read before the lock could
// put back coins another command spent. A command that finds the home in
// use says so before it has read anything of the wallet.
func TestTheLockComesBeforeTheWallet(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	home := filepath.Join(h.dir, "org")
	unlock, err := state.Lock(filepath.Join(home, "lock"))
	if err != nil {
		t.Fatal(err)
	}
	// A wallet file that does not read: a command that opened the wallet
	// before the lock would trip on it instead of on the lock.
	pool := filepath.Join(home, "wallet.json")
	raw, err := os.ReadFile(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pool, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	txid := strings.Repeat("ab", 32)
	for _, args := range [][]string{{"anchor"}, {"sync"}, {"fund"}, {"fund", "-txid", txid}, {"crypt", "new", "other"}, {"init"},
		{"kill", "-confirm", "KILL", "-yes"}, {"retire", "x"}, {"rotate"}, {"payee", "settle", pool}, {"vault", "create", h.group, "-name", "v"}} {
		r := h.run("org", "", args...)
		if r.code != exitUsage || !strings.Contains(r.stderr, "another bsecret command is using the home") {
			t.Errorf("%v with the home locked: exit %d\n%s", args, r.code, r.stderr)
		}
	}
	if err := os.WriteFile(pool, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	unlock()
	h.put("db/password", "one")
}

// What a node names as a spender is a transaction id or it is refused: it
// is never printed as the node wrote it.
func TestANodeSuppliedSpenderIsNotPrinted(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	r := h.must("alice", "vault", "show")
	var tip string
	for _, l := range strings.Split(r.stdout, "\n") {
		if strings.HasPrefix(l, "token   seq 1 ") {
			tip = strings.Fields(l)[3]
		}
	}
	h.chain.SpendElsewhere(tip, 0, "\x1b[2J\x1b]0;owned\x07evil")
	for _, args := range [][]string{{"audit", "-free"}, {"vault", "show"}, {"get", "db/password"}, {"audit", "-free", "-json"}} {
		r := h.run("alice", "", args...)
		if strings.ContainsAny(r.stdout+r.stderr, "\x1b\x07") || strings.Contains(r.stdout+r.stderr, "owned") {
			t.Errorf("%v printed what the node named as a spender: %q", args, r.stdout+r.stderr)
		}
	}
	if r := h.run("alice", "", "audit", "-free"); !strings.Contains(r.stdout, "the node could not say") {
		t.Errorf("audit with a node that names no txid:\n%s", r.stdout)
	}
	// The owner's tooling fails closed on such a node, and prints nothing
	// of it either.
	r = h.run("org", "two", "put", "db/password")
	if r.code == exitOK || strings.ContainsAny(r.stdout+r.stderr, "\x1b\x07") {
		t.Errorf("a put on a node that names no txid: exit %d %q", r.code, r.stderr)
	}
}

// On the plane a carrier counts as published only once the hosts named
// answer it by lookup: the facade's "nothing admitted" is a duplicate and a
// refusal alike. A carrier no host holds is never listed by a token.
func TestAnUnconfirmedCarrierIsNotPublished(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	tokens := len(h.a.Txids("token"))
	carrier := func(tx *transaction.Transaction) bool { return tx.LockTime != 0 }
	h.a.Drop, h.b.Drop = carrier, carrier
	r := h.run("org", "two", "put", "db/password")
	if r.code != exitUsage || !strings.Contains(r.stderr, "0 of 2 host(s) named answer it") || !strings.Contains(r.stderr, "it is persisted") {
		t.Fatalf("a carrier no host took: exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	if n := len(h.a.Txids("token")); n != tokens {
		t.Fatalf("a token was minted for a carrier no host holds: %d tokens, %d before", n, tokens)
	}
	if r := h.must("org", "doctor"); !strings.Contains(r.stdout, "outbox      secret") {
		t.Fatalf("doctor:\n%s", r.stdout)
	}
	// One host of two, with a quorum of all: still not published. With a
	// quorum of one it is, and the token lists it.
	h.b.Drop = nil
	h.a.Drop = carrier
	h.want(h.run("org", "three", "put", "db/password"), exitUsage, "1 of 2 host(s) named answer it and 2 must")
	h.env["BSECRET_QUORUM"] = "one"
	r = h.put("db/password", "four")
	if !strings.Contains(r.stderr, "publishing what a previous run persisted") {
		t.Fatalf("with a quorum of one:\n%s\n%s", r.stdout, r.stderr)
	}
	h.a.Drop = nil
	if r := h.run("alice", "", "get", "db/password"); r.stdout != "four" {
		t.Fatalf("alice: %q\n%s", r.stdout, r.stderr)
	}
}

// After a reorganisation a proof kept from before may name a block that is
// no longer in the best chain. A reader handed such a proof by a host, and
// an owner holding one in its home, each take the transaction's current
// proof from the node and verify that against their own headers.
func TestStaleProofsAreReplaced(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	// The hosts answer every token and carrier under a proof of another
	// block.
	h.a.Stale, h.b.Stale = true, true
	if r := h.must("alice", "get", "db/password"); r.stdout != "one" || strings.Contains(r.stderr, "REFUSED") {
		t.Fatalf("a reader given stale proofs: %q\n%s", r.stdout, r.stderr)
	}
	if r := h.must("carol", "audit", "-free"); !strings.Contains(r.stdout, "audit   OK") {
		t.Fatalf("an audit given stale proofs:\n%s\n%s", r.stdout, r.stderr)
	}
	// With no chain source there is nothing to replace them with: nothing
	// verifies, and nothing is taken.
	delete(h.env, "BSECRET_ASSET")
	h.want(h.run("bob", "", "get", "db/password"), exitIncomplete, "no host answers this vault")
	h.env["BSECRET_ASSET"] = h.chainS.URL
	h.a.Stale, h.b.Stale = false, false

	// The owner's home: the proofs it kept of its latest token and of its
	// funding tree name another block.
	path := filepath.Join(h.dir, "org", state.File)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	shift := func(m map[string]any) {
		mp, err := transaction.NewMerklePathFromHex(m["bumpHex"].(string))
		if err != nil {
			t.Fatal(err)
		}
		mp.BlockHeight += 3
		m["bumpHex"] = mp.Hex()
	}
	tokens := st["vaults"].([]any)[0].(map[string]any)["tokens"].([]any)
	for _, tok := range tokens {
		shift(tok.(map[string]any))
	}
	trees := st["trees"].(map[string]any)["secret"].(map[string]any)
	shift(trees["tree"].(map[string]any))
	for _, tr := range trees["trees"].([]any) {
		shift(tr.(map[string]any))
	}
	out, _ := json.Marshal(st)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	r := h.put("db/password", "two")
	if !strings.Contains(r.stderr, "the node's current proof") {
		t.Fatalf("a put from a home with stale proofs:\n%s\n%s", r.stdout, r.stderr)
	}
	if r := h.must("alice", "get", "db/password"); r.stdout != "two" || strings.Contains(r.stderr, "DISAGREES") {
		t.Fatalf("after the put: %q\n%s", r.stdout, r.stderr)
	}
	// The home is healed: the next put says nothing of proofs.
	if r := h.put("db/password", "three"); strings.Contains(r.stderr, "the node's current proof") {
		t.Fatalf("the home kept its stale proofs:\n%s", r.stderr)
	}
}

// A same-value re-keying in an interval vault re-keys the value readers
// hold: the latest deferred version's, not the listed one's.
func TestSameValueRekeyOfADeferredVersion(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault("-anchor", "interval")
	h.put("svc/token", "t1", "-label", "restricted")
	h.put("svc/token", "t2", "-defer")
	h.put("svc/token", "t3", "-defer", "-label", "internal")
	if err := h.borg.Remove(h.group, h.keys["bob"]); err != nil {
		t.Fatal(err)
	}
	h.must("org", "rotate", "-same-all")
	r := h.must("alice", "get", "svc/token")
	if r.stdout != "t3" || !strings.Contains(r.stderr, "version 4 label internal epoch 1") || !strings.Contains(r.stderr, "anchored, current") {
		t.Fatalf("the re-keyed version: %q\n%s", r.stdout, r.stderr)
	}
}

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/testhost"
	"github.com/lightwebinc/bsecret/internal/vread"
)

// An audit that stops before it folds anything (the group's epochs are not
// one chain) gives no status per token; the report lists the tokens all the
// same, and says they were not folded.
func TestAnAuditThatStopsEarlyListsItsTokens(t *testing.T) {
	rec := &secrec.Vault{Seq: 0, Root: secrec.SetRoot(nil)}
	toks := []*vread.Tok{{Txid: "aa", Token: &secrec.VaultToken{Vault: rec}}}
	rep := secrec.Audit([]secrec.Mined{{Vault: rec}}, []secrec.EpochEvent{{Epoch: 0}, {Epoch: 2, EpochID: [32]byte{1}}})
	if rep.OK || len(rep.Statuses) != 0 {
		t.Fatalf("epochs 0 and 2 are not one chain: ok %v, statuses %v", rep.OK, rep.Statuses)
	}
	got := auditTokens(toks, rep.Statuses)
	if len(got) != 1 || got[0].Status != "not folded" {
		t.Fatalf("tokens of an audit that stopped early: %+v", got)
	}
}

// sweepVersion retracts one version of the organisation's only vault, as
// its owner: a sweep of the funding output its carrier spent.
func (h *harness) sweepVersion(version uint64) {
	h.t.Helper()
	ctx := context.Background()
	g, _, errb := h.global("org")
	w, err := g.openWriter(ctx)
	if err != nil {
		h.t.Fatalf("%v\n%s", err, errb)
	}
	defer w.close(ctx, g)
	v := &w.h.st.Vaults[0]
	for i := range v.Versions {
		if x := &v.Versions[i]; x.Version == version {
			if _, err := w.eng.Retract(ctx, v.Crypt, x.Tree, []uint32{x.Vout}); err != nil {
				h.t.Fatalf("sweep of version %d: %v\n%s", version, err, errb)
			}
			return
		}
	}
	h.t.Fatalf("the home holds no version %d", version)
}

// forgetSweeps makes both hosts lose every sweep they hold, so that they
// answer what it retracted again and only the chain source shows the spend.
func (h *harness) forgetSweeps() {
	for _, host := range []*testhost.Host{h.a, h.b} {
		for _, id := range host.Txids("sweep") {
			host.Forget(id)
		}
	}
}

// In an interval vault a retracted version is not a link: a reader takes
// the highest version it can link below it, and says a later one exists.
func TestNothingLinksThroughARetractedVersion(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault("-anchor", "interval")
	h.put("svc/token", "t1")
	h.put("svc/token", "t2", "-defer")
	h.put("svc/token", "t3", "-defer")
	h.put("svc/token", "t4", "-defer")
	// The top link is retracted, and the hosts lost the sweep: the reader
	// falls back to the highest version that is not.
	h.sweepVersion(4)
	h.forgetSweeps()
	r := h.must("alice", "get", "svc/token")
	if r.stdout != "t3" || !strings.Contains(r.stderr, "version 4 is retracted") || !strings.Contains(r.stderr, "a later version exists") {
		t.Fatalf("a retracted top link: %q\n%s", r.stdout, r.stderr)
	}
	// A link in the middle: nothing above it is reached through it.
	h.sweepVersion(2)
	h.forgetSweeps()
	r = h.must("alice", "get", "svc/token")
	if r.stdout != "t1" || !strings.Contains(r.stderr, "version 2 is retracted") || !strings.Contains(r.stderr, "anchored") || strings.Contains(r.stderr, "UNANCHORED") {
		t.Fatalf("a retracted link in the middle: %q\n%s", r.stdout, r.stderr)
	}
}

// Hosts that withhold a token in the middle of a vault's chain cannot hide
// that later ones exist: the tokens they answer above the gap verify and
// do not link, and a reader with no memory is told so (exit 3).
func TestWithheldTokensAreNotANote(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	h.put("db/user", "two")
	h.put("db/host", "three")
	withhold := func(q *secrec.Question, outs []testhost.Output) []testhost.Output {
		if q.Class.Name == "vault-seq" && q.Members["seq"] == "2" {
			return nil
		}
		return outs
	}
	h.a.Rewrite, h.b.Rewrite = withhold, withhold
	// With no chain source nothing else says a later token exists.
	delete(h.env, "BSECRET_ASSET")
	r := h.run("alice", "", "get", "db/password")
	if r.code != exitIncomplete || r.stdout != "one" || !strings.Contains(r.stderr, "WITHHELD: 1 verified token(s) of the vault exist above seq 1") {
		t.Fatalf("a reader with no memory, a token withheld: exit %d %q\n%s", r.code, r.stdout, r.stderr)
	}
	if r := h.run("carol", "", "audit", "-free"); r.code != exitIncomplete || !strings.Contains(r.stderr, "WITHHELD") {
		t.Fatalf("an audit, a token withheld: exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	h.a.Rewrite, h.b.Rewrite = nil, nil
	h.env["BSECRET_ASSET"] = h.chainS.URL
	if r := h.must("alice", "get", "db/host"); r.stdout != "three" || strings.Contains(r.stderr, "WITHHELD") {
		t.Fatalf("with nothing withheld: %q\n%s", r.stdout, r.stderr)
	}
}

// A host that answers a token that does not verify is at fault, and is
// named; the read stands on what verified, and is incomplete, not refused:
// one hostile host cannot make every read of a vault fail a check.
func TestAHostAnsweringJunkDoesNotFailTheRead(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	h.b.Rewrite = func(q *secrec.Question, outs []testhost.Output) []testhost.Output {
		if q.Class.Name == "vault" {
			return append(outs, testhost.Output{Beef: []byte{1, 2, 3}})
		}
		return outs
	}
	r := h.run("alice", "", "get", "db/password")
	if r.code != exitIncomplete || r.stdout != "one" || !strings.Contains(r.stderr, "REFUSED token") {
		t.Fatalf("one host answers junk: exit %d %q\n%s", r.code, r.stdout, r.stderr)
	}
}

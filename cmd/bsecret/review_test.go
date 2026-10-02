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

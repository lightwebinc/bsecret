package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/lightwebinc/bsecret/internal/state"
)

// A run that stops is a home as its files stood at that moment. These
// tests copy the owner's home at the moment a funding tree reaches the
// settlement leg, after the home recorded it and before anything else, and
// go on in the copy: the home the next command finds.

// stopAt copies the home name to the home as when the next funding tree
// the home recorded reaches the settlement leg, and returns that tree once
// run has returned. land says whether the chain then takes the tree; either
// way the run that sent it hears a refusal, nothing it sends afterwards
// reaches the chain, and its own home is left behind.
func (h *harness) stopAt(name, as string, land bool, run func()) *transaction.Transaction {
	h.t.Helper()
	var sent *transaction.Transaction
	var failed error
	h.mu.Lock()
	h.refuse = func(tx *transaction.Transaction) bool {
		if sent != nil {
			return true
		}
		st, err := state.Load(filepath.Join(h.dir, name), h.env["BSECRET_ORG"])
		if err != nil || st.PendingTreeOf(tx.TxID().String()) == nil {
			return false
		}
		sent = tx
		failed = stoppedHome(filepath.Join(h.dir, name), filepath.Join(h.dir, as))
		if land && failed == nil {
			failed = h.chain.Send(tx)
		}
		return true
	}
	h.mu.Unlock()
	run()
	h.mu.Lock()
	h.refuse = nil
	h.mu.Unlock()
	if sent == nil || failed != nil {
		h.t.Fatalf("the run sent %v to the settlement leg: %v", sent, failed)
	}
	return sent
}

// stoppedHome copies a home a command is running in: the lock and the
// temporary files of a save under way are left out.
func stoppedHome(from, to string) error {
	return filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		rel, _ := filepath.Rel(from, p)
		dst := filepath.Join(to, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o700)
		}
		if d.Name() == "lock" || strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		b, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o600)
	})
}

// records are the home's records of trees signed and not adopted.
func (h *harness) records(name string) []state.PendingTree {
	h.t.Helper()
	st, err := state.Load(filepath.Join(h.dir, name), h.env["BSECRET_ORG"])
	if err != nil {
		h.t.Fatal(err)
	}
	return st.PendingTrees
}

// A put stopped after its secret tree reached the settlement leg and
// before the home adopted it. doctor names the record, a command that only
// reads leaves it alone, and the same put run again asks the node, adopts
// the tree, and publishes the version on its first output.
func TestAPutStoppedAfterItsTreeWasSent(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	tree := h.stopAt("org", "stopped", true, func() {
		if r := h.run("org", "one", "put", "db/password"); r.code == 0 {
			t.Fatalf("the run that stops went on:\n%s\n%s", r.stdout, r.stderr)
		}
	})
	id := tree.TxID().String()
	recs := h.records("stopped")
	if len(recs) != 1 || recs[0].Tree.Txid != id || recs[0].Kind != state.TreeSecret {
		t.Fatalf("the home the run left: %+v", recs)
	}
	named := "tree        secret: " + id + " signed for coin " + recs[0].Coin.Outpoint() + " and not recorded as minted"
	if r := h.must("stopped", "doctor"); !strings.Contains(r.stdout, named) {
		t.Fatalf("doctor does not name the record:\n%s", r.stdout)
	}
	// A reader asks nothing about a tree.
	if r := h.must("stopped", "list"); strings.Contains(r.stderr, "funding tree") || len(h.records("stopped")) != 1 {
		t.Fatalf("a command that only reads touched the record:\n%s", r.stderr)
	}
	r := h.mustIn("stopped", "one", "put", "db/password")
	if !strings.Contains(r.stderr, "funding tree "+id+" is recovered") || len(h.records("stopped")) != 0 {
		t.Fatalf("the put run again:\n%s\n%s", r.stdout, r.stderr)
	}
	st, err := state.Load(filepath.Join(h.dir, "stopped"), h.env["BSECRET_ORG"])
	if err != nil {
		t.Fatal(err)
	}
	if cur := st.Set(state.TreeSecret).Tree; cur == nil || cur.Txid != id || cur.Next != 1 || len(st.Set(state.TreeSecret).Trees) != 1 {
		t.Fatalf("the secret tree after: %+v", cur)
	}
	if r := h.must("alice", "get", "db/password"); r.stdout != "one" || !strings.Contains(r.stderr, "anchored, current") {
		t.Fatalf("alice: %q\n%s", r.stdout, r.stderr)
	}
	if r := h.must("stopped", "doctor"); strings.Contains(r.stdout, "not recorded as minted") {
		t.Fatalf("doctor still names a record:\n%s", r.stdout)
	}
}

// A put stopped before its secret tree reached the settlement leg. The
// next command that publishes puts the coin back and says so; the record
// is kept for that one command, which doctor says, and the command after
// drops it. A put then mints its tree and finishes. Signing is
// deterministic, so the tree a put mints from the coin that went back is
// the tree the stopped run signed: it is recorded again, sent, and adopted
// under the same txid.
func TestAPutStoppedBeforeItsTreeWasSent(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	tree := h.stopAt("org", "stopped", false, func() {
		if r := h.run("org", "one", "put", "db/password"); r.code == 0 {
			t.Fatalf("the run that stops went on:\n%s\n%s", r.stdout, r.stderr)
		}
	})
	id := tree.TxID().String()
	coin := h.records("stopped")[0].Coin.Outpoint()
	// A command that publishes and spends no secret tree.
	r := h.must("stopped", "sync")
	if !strings.Contains(r.stderr, "funding tree "+id+" never reached the chain: its fee coin "+coin+" is unspent and back in the pool") ||
		!strings.Contains(r.stderr, "its record is kept for one more command") {
		t.Fatalf("the first command after:\n%s\n%s", r.stdout, r.stderr)
	}
	if recs := h.records("stopped"); len(recs) != 1 || !recs[0].ReturnedOnce {
		t.Fatalf("the record after one command: %+v", recs)
	}
	if r := h.must("stopped", "doctor"); !strings.Contains(r.stdout, "asked once: the node did not know it") {
		t.Fatalf("doctor after one command:\n%s", r.stdout)
	}
	r = h.must("stopped", "sync")
	if !strings.Contains(r.stderr, "funding tree "+id+": the node still does not know it, so its record is dropped") || len(h.records("stopped")) != 0 {
		t.Fatalf("the command after:\n%s\n%s", r.stdout, r.stderr)
	}
	r = h.mustIn("stopped", "one", "put", "db/password")
	st, err := state.Load(filepath.Join(h.dir, "stopped"), h.env["BSECRET_ORG"])
	if err != nil {
		t.Fatal(err)
	}
	if cur := st.Set(state.TreeSecret).Tree; cur == nil || cur.Txid != id || len(st.PendingTrees) != 0 {
		t.Fatalf("the secret tree after the put: %+v, records %+v\n%s", cur, st.PendingTrees, r.stderr)
	}
	if r := h.must("alice", "get", "db/password"); r.stdout != "one" {
		t.Fatalf("alice: %q\n%s", r.stdout, r.stderr)
	}
}

// The same put run again at once, with no command between: the tree it
// mints from the coin that went back is the tree the stopped run signed,
// so the record made again is the one the adoption drops, and nothing is
// left.
func TestAPutRunAgainRebuildsTheSameTree(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	tree := h.stopAt("org", "stopped", false, func() {
		if r := h.run("org", "one", "put", "db/password"); r.code == 0 {
			t.Fatalf("the run that stops went on:\n%s\n%s", r.stdout, r.stderr)
		}
	})
	r := h.mustIn("stopped", "one", "put", "db/password")
	st, err := state.Load(filepath.Join(h.dir, "stopped"), h.env["BSECRET_ORG"])
	if err != nil {
		t.Fatal(err)
	}
	if cur := st.Set(state.TreeSecret).Tree; cur == nil || cur.Txid != tree.TxID().String() || len(st.PendingTrees) != 0 ||
		!strings.Contains(r.stderr, "is unspent and back in the pool") {
		t.Fatalf("the secret tree after the put: %+v, records %+v\n%s", cur, st.PendingTrees, r.stderr)
	}
	if r := h.must("stopped", "doctor"); strings.Contains(r.stdout, "not recorded as minted") {
		t.Fatalf("doctor still names a record:\n%s", r.stdout)
	}
}

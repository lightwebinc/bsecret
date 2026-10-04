package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/lightwebinc/bsecret/internal/state"
)

// chainTree is the chain tree the vault's first token spends, as the home
// name records it.
func (h *harness) chainTree(name string) string {
	h.t.Helper()
	st, err := state.Load(filepath.Join(h.dir, name), "")
	if err != nil || len(st.Vaults) == 0 || len(st.Vaults[0].Tokens) == 0 {
		h.t.Fatalf("state of %s: %v", name, err)
	}
	return st.Vaults[0].Tokens[0].Parent
}

// hasTree reports whether the home name keeps a record of tree txid.
func (h *harness) hasTree(name, txid string) bool {
	h.t.Helper()
	st, err := state.Load(filepath.Join(h.dir, name), "")
	if err != nil {
		h.t.Fatal(err)
	}
	_, _, ok := st.TreeOf(txid)
	return ok
}

// editState rewrites the home name's state file through edit.
func (h *harness) editState(name string, edit func(st map[string]any)) {
	h.t.Helper()
	path := filepath.Join(h.dir, name, state.File)
	raw, err := os.ReadFile(path)
	if err != nil {
		h.t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(raw, &st); err != nil {
		h.t.Fatal(err)
	}
	edit(st)
	out, _ := json.Marshal(st)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// editChainTrees applies edit to every record of a chain tree the home
// name keeps.
func (h *harness) editChainTrees(name string, edit func(tr map[string]any)) {
	h.t.Helper()
	h.editState(name, func(st map[string]any) {
		set, _ := st["trees"].(map[string]any)["chain"].(map[string]any)
		if set == nil {
			h.t.Fatalf("%s keeps no chain trees", name)
		}
		if tr, ok := set["tree"].(map[string]any); ok {
			edit(tr)
		}
		if all, ok := set["trees"].([]any); ok {
			for _, tr := range all {
				edit(tr.(map[string]any))
			}
		}
	})
}

// forgetTokens makes host b lose every vault token it holds.
func (h *harness) forgetTokens() []string {
	ids := h.b.Txids("token")
	for _, id := range ids {
		h.b.Forget(id)
	}
	return ids
}

// Once the node drops the chain tree (fully spent), a host that lost the
// vault's first token is filled from the owner's home, which keeps the
// tree with its proof; a second home records the tree when it syncs. A
// home that is not the owner's, and a home made before the record was
// kept, name the tree and fail.
func TestFillTakesAPrunedChainTreeFromTheOwnerHome(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	h.identity("org2", true, "-borg", h.borg.Home)
	h.must("org2", "sync")
	tree := h.chainTree("org")
	if !h.hasTree("org2", tree) {
		t.Fatalf("the second home did not record chain tree %s when it synced", tree)
	}
	h.prune(tree)

	lost := h.forgetTokens()
	r := h.run("alice", "", "fill")
	h.want(r, exitIncomplete, "the chain tree "+tree+": this home is not the vault owner's")
	if !strings.Contains(r.stderr, "run bsecret fill from the owner's home") {
		t.Fatalf("fill from a member's home:\n%s\n%s", r.stdout, r.stderr)
	}

	r = h.must("org", "fill")
	if !strings.Contains(r.stdout, "vault token seq 0 ") {
		t.Fatalf("fill from the owner's home:\n%s\n%s", r.stdout, r.stderr)
	}
	for _, id := range lost {
		if !h.b.Holds(id) {
			t.Fatalf("host b still lacks %s after the fill:\n%s", id, r.stdout)
		}
	}

	h.forgetTokens()
	if r := h.must("org2", "fill"); !strings.Contains(r.stdout, "vault token seq 0 ") {
		t.Fatalf("fill from the second home:\n%s\n%s", r.stdout, r.stderr)
	}

	// A home made by sync before the record was kept has none.
	h.editState("org2", func(st map[string]any) {
		delete(st["trees"].(map[string]any), "chain")
	})
	h.forgetTokens()
	r = h.run("org2", "", "fill")
	h.want(r, exitIncomplete, "the chain tree "+tree+": this home keeps no record of it")
	if strings.Contains(r.stdout, "filled  vault token seq 0") {
		t.Fatalf("fill from a home without the record:\n%s\n%s", r.stdout, r.stderr)
	}
}

// A chain tree in the home is held to what the node's answer would be: a
// record whose bytes are another transaction is refused, and a kept proof
// a reorganisation left stale is replaced by the node's current one, or
// named when the node gives none.
func TestFillChecksTheHomeChainTree(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	tree := h.chainTree("org")

	h.editChainTrees("org", func(tr map[string]any) {
		mp, err := transaction.NewMerklePathFromHex(tr["bumpHex"].(string))
		if err != nil {
			t.Fatal(err)
		}
		mp.BlockHeight += 3
		tr["bumpHex"] = mp.Hex()
	})
	h.forgetTokens()
	r := h.must("org", "fill")
	if !strings.Contains(r.stdout, "vault token seq 0 ") || !strings.Contains(r.stderr, "the node's current proof") {
		t.Fatalf("fill with a stale kept proof:\n%s\n%s", r.stdout, r.stderr)
	}
	h.prune(tree)
	h.forgetTokens()
	r = h.run("org", "", "fill")
	h.want(r, exitIncomplete, "its kept proof does not verify against the header source (a reorganisation, or no proof kept), and the node gives no current one")

	h.editChainTrees("org", func(tr map[string]any) {
		raw := tr["rawHex"].(string)
		last := "0"
		if raw[len(raw)-1] == '0' {
			last = "1"
		}
		tr["rawHex"] = raw[:len(raw)-1] + last
	})
	h.forgetTokens()
	r = h.run("org", "", "fill")
	h.want(r, exitIncomplete, "this home's record of the chain tree "+tree+" is REFUSED: its bytes are transaction")
	if strings.Contains(r.stdout, "filled  vault token seq 0") {
		t.Fatalf("a token was filled from a tampered tree:\n%s", r.stdout)
	}
}

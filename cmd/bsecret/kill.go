package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/lightwebinc/bcommon/funding"

	"github.com/lightwebinc/bsecret/internal/engine"
	"github.com/lightwebinc/bsecret/internal/state"
)

const killHelp = `usage: bsecret kill -confirm KILL [-yes]

The kill switch (spec section 12.5). It sweeps every secret tree this home
holds: one mined transaction per tree, spending every funding output it
has, used or not. Once a sweep mines, every carrier those outputs funded is
a double spend, and every honest host retracts it: every version of every
secret this identity published stops being answered. It is IRREVERSIBLE.

Without -yes it prints what it would sweep and sends nothing. With -yes
each sweep is persisted, settled, waited for until it mines (one block a
tree) and published to the plane and to every host named, in every crypt
that holds a version the tree funded: a funding tree is the identity's, not
a crypt's. A run that stops part way is finished by running kill again: a
tree already swept is passed over.

Work an earlier command left unfinished (an object a host has not taken, a
transition not yet mined) does not stop it: that work is reported and left
for the next command. An output the chain already shows spent is left out
of the sweep, and the transaction that spends it is taken as its sweep and
published as one: another instance of the tooling swept it.

What it does not do: the vaults' tokens are mined and stay, and they name
identifiers, versions, content ids and commitments, never a value or a
name; a copy of a carrier anyone kept stays a copy; and a value anyone read
stays read. A tree another home of this organization minted is swept only
once this home knows it (bsecret sync records the tree of every carrier the
hosts answer).`

type killTree struct {
	txid     string
	count    uint32
	vouts    []uint32
	versions int
}

// killTrees are the secret trees a home holds that still have an output no
// sweep of this home's spends, each once.
func killTrees(st *state.State, swept func(txid string, vout uint32) bool) []killTree {
	var out []killTree
	seen := map[string]bool{}
	ts := st.Trees[state.TreeSecret]
	if ts == nil {
		return nil
	}
	add := func(t *funding.Tree) {
		if t == nil || seen[t.Txid] {
			return
		}
		seen[t.Txid] = true
		kt := killTree{txid: t.Txid, count: t.Count}
		for v := uint32(0); v < t.Count; v++ {
			if !swept(t.Txid, v) {
				kt.vouts = append(kt.vouts, v)
			}
		}
		for vi := range st.Vaults {
			for i := range st.Vaults[vi].Versions {
				if x := &st.Vaults[vi].Versions[i]; x.Tree == t.Txid && x.Swept == "" {
					kt.versions++
				}
			}
		}
		if len(kt.vouts) > 0 {
			out = append(out, kt)
		}
	}
	add(ts.Tree)
	for i := range ts.Trees {
		add(&ts.Trees[i])
	}
	for i := range ts.Ahead {
		add(&ts.Ahead[i])
	}
	return out
}

// sweptIn reports whether a sweep recorded in st, not failed, spends an
// output.
func sweptIn(st *state.State, txid string, vout uint32) bool {
	for i := range st.Sweeps {
		sw := &st.Sweeps[i]
		if sw.Failed != "" || sw.Tree != txid {
			continue
		}
		for _, v := range sw.Vouts {
			if v == vout {
				return true
			}
		}
	}
	return false
}

func cmdKill(ctx context.Context, g *global, args []string) error {
	fs := g.flagSet("kill", killHelp)
	confirm := fs.String("confirm", "", "must be the literal KILL")
	yes := fs.Bool("yes", false, "actually sweep: mine and publish")
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return usage("kill -confirm KILL [-yes]")
	}
	if *confirm != "KILL" {
		return usage("kill sweeps every secret tree of this home and retracts every version it ever published; pass -confirm KILL")
	}
	if !*yes {
		st := g.peekState()
		if st == nil {
			return usage("no home at %s (run `bsecret init`)", g.cfg.Home)
		}
		trees := killTrees(st, func(txid string, vout uint32) bool { return sweptIn(st, txid, vout) })
		for _, t := range trees {
			fmt.Fprintf(g.stdout, "would sweep secret tree %s: %d of %d output(s), %d version(s) of this home's record on it\n", t.txid, len(t.vouts), t.count, t.versions)
		}
		fmt.Fprintf(g.stdout, "%d tree(s) to sweep; nothing was sent (pass -yes)\n", len(trees))
		return nil
	}
	// Work an earlier command left unfinished does not stop the kill
	// switch: it is reported and left.
	w, err := g.openWriterFor(ctx, true)
	if err != nil {
		return err
	}
	defer w.close(ctx, g)
	crypt := g.cfg.Crypt
	if crypt == "" && len(w.h.st.Vaults) > 0 {
		crypt = w.h.st.Vaults[0].Crypt
	}
	if crypt == "" {
		return usage("this home published nothing in any crypt it records, so there is nothing to sweep; name the crypt (-crypt) to sweep trees it minted")
	}
	trees := killTrees(w.h.st, func(txid string, vout uint32) bool { return w.eng.SweptBy(txid, vout) != nil })
	failed := 0
	for _, t := range trees {
		// A sweep refused because another transaction spends one of its
		// inputs (its fee coin, or an output swept since the node was
		// asked) is built again without that input.
		sw, err := w.eng.Retract(ctx, crypt, t.txid, t.vouts)
		for try := 0; try < 2; try++ {
			var again *engine.SweepRefusedError
			if !errors.As(err, &again) {
				break
			}
			g.say("%v", err)
			sw, err = w.eng.Retract(ctx, crypt, t.txid, t.vouts)
		}
		if err != nil {
			failed++
			g.say("secret tree %s: NOT SWEPT: %v", t.txid, err)
			continue
		}
		fmt.Fprintf(g.stdout, "swept   secret tree %s with %s: %d output(s), mined at height %d\n", t.txid, sw.Txid, len(sw.Vouts), sw.Height)
	}
	if err := w.eng.RetireTrees(); err != nil {
		return err
	}
	if failed > 0 {
		return refused("%d of %d tree(s) not swept; run bsecret kill -confirm KILL -yes again", failed, len(trees))
	}
	// An output another transaction spends that has not mined yet is
	// neither swept nor sweepable: the next run takes that spend as its
	// sweep once it mines.
	if rest := killTrees(w.h.st, func(txid string, vout uint32) bool { return w.eng.SweptBy(txid, vout) != nil }); len(rest) > 0 {
		n := 0
		for _, t := range rest {
			n += len(t.vouts)
		}
		return incomplete("%d output(s) of %d tree(s) are spent by a transaction that has not mined yet or that the node could not show; run bsecret kill -confirm KILL -yes again", n, len(rest))
	}
	fmt.Fprintf(g.stdout, "killed  %d tree(s) swept: every version they funded is retracted at every honest host\n", len(trees))
	g.say("a sweep is not erasure: the vaults' tokens stay, a copy anyone kept stays a copy, and a value anyone read stays read")
	return nil
}

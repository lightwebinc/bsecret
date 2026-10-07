package engine

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/lightwebinc/bcommon/bwallet"
	"github.com/lightwebinc/bcommon/funding"
	"github.com/lightwebinc/bcommon/nodeapi"
	"github.com/lightwebinc/bcommon/producer"
	"github.com/lightwebinc/bcommon/publish"

	"github.com/lightwebinc/bsecret/internal/state"
)

// A run that stops is a home as its files stood at that moment. These
// tests copy the home at the moment a funding tree reaches the settlement
// leg, after the home recorded it and before anything else, and go on in
// the copy: the home the next command finds.

// stopped is a settlement leg that copies the home when the first
// transaction reaches it. With land set the chain then takes the
// transaction; without, the leg fails and the transaction is kept.
type stopped struct {
	publish.Settler
	t        *testing.T
	from, to string
	land     bool
	sent     *transaction.Transaction
}

func (s *stopped) Submit(ctx context.Context, tx *transaction.Transaction) error {
	if s.sent != nil {
		return s.Settler.Submit(ctx, tx)
	}
	s.sent = tx
	if err := copyHome(s.from, s.to); err != nil {
		s.t.Errorf("copying the home: %v", err)
	}
	if s.land {
		return s.Settler.Submit(ctx, tx)
	}
	return errors.New("the run stopped")
}

// copyHome copies a home a command is running in: the lock and the
// temporary files of a save under way are left out.
func copyHome(from, to string) error {
	return filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
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
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o600)
	})
}

// stop runs one spend in a fresh publisher over the home and returns the
// home as it stood when the spend's funding tree reached the settlement
// leg, as a rig of its own over the same chain, with the tree.
func (r *rig) stop(land bool) (*rig, *transaction.Transaction) {
	r.t.Helper()
	a := r.open(0, nil)
	s := &stopped{Settler: a.payer.Settler, t: r.t, from: r.dir, to: filepath.Join(r.t.TempDir(), "stopped"), land: land}
	a.payer.Settler = s
	_, _, err := a.spend(context.Background(), kind)
	if s.sent == nil || land && err != nil || !land && err == nil {
		r.t.Fatalf("the run that stops: sent %v, %v\n%s", s.sent != nil, err, r.said())
	}
	if land {
		id := s.sent.TxID().String()
		for end := time.Now().Add(20 * time.Second); r.chain.Tx(id) == nil; time.Sleep(time.Millisecond) {
			if time.Now().After(end) {
				r.t.Fatalf("funding tree %s never reached the chain", id)
			}
		}
	}
	return &rig{t: r.t, dir: s.to, chain: r.chain, rpc: r.rpc, asset: r.asset}, s.sent
}

// holds counts the pool's coins at the outpoint op, and reports whether
// the pool holds an output of the transaction txid.
func holds(pool *bwallet.Pool, op, txid string) (coin int, change bool) {
	for _, o := range pool.Outputs() {
		if o.Outpoint() == op {
			coin++
		}
		change = change || o.TxID == txid
	}
	return coin, change
}

// one is the home's one record of a tree signed and not adopted.
func one(t *testing.T, e *Engine) state.PendingTree {
	t.Helper()
	if len(e.St.PendingTrees) != 1 {
		t.Fatalf("the records of trees signed and not adopted: %+v", e.St.PendingTrees)
	}
	return e.St.PendingTrees[0]
}

// A run that stopped after it recorded a funding tree and before the tree
// reached the settlement leg: the node knows no such tree and shows the
// coin unspent. The coin goes back to the pool, once, the record is kept
// for one more command, and the command after drops it.
func TestARunStoppedBeforeItsTreeWasSent(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	home, tree := r.stop(false)
	id := tree.TxID().String()

	b := home.build(0, nil)
	p := one(t, b)
	op := p.Coin.Outpoint()
	if n, _ := holds(b.Pool, op, id); p.Tree.Txid != id || p.Kind != kind || n != 0 || b.St.Set(kind).Tree != nil || r.chain.Tx(id) != nil {
		t.Fatalf("the home the run left: record %s of kind %s, its coin in the pool %d time(s), tree %+v", p.Tree.Txid, p.Kind, n, b.St.Set(kind).Tree)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	said := home.said()
	if n, _ := holds(b.Pool, op, id); n != 1 || len(b.St.PendingTrees) != 1 || !b.St.PendingTrees[0].ReturnedOnce || len(b.St.UnsettledTrees()) != 1 ||
		!strings.Contains(said, "never reached the chain: its fee coin "+op+" is unspent and back in the pool") ||
		!strings.Contains(said, "its record is kept for one more command") {
		t.Fatalf("the first command after: coin in the pool %d time(s), records %+v\n%s", n, b.St.PendingTrees, said)
	}
	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The second command finds the same, and the record is done with.
	c := home.open(0, nil)
	said = home.said()
	if n, _ := holds(c.Pool, op, id); n != 1 || len(c.St.PendingTrees) != 0 || !strings.Contains(said, "its record is dropped") {
		t.Fatalf("the second command after: coin in the pool %d time(s), records %+v\n%s", n, c.St.PendingTrees, said)
	}
	// The home goes on: the next spend mints a tree and adopts it.
	if got := home.use(c); c.St.Set(kind).Tree == nil || got != c.St.Set(kind).Tree.Txid+".0" || len(c.St.PendingTrees) != 0 {
		t.Fatalf("the next spend answered %s: tree %+v, records %+v\n%s", got, c.St.Set(kind).Tree, c.St.PendingTrees, home.said())
	}
}

// A run that stopped after the settlement leg took its funding tree and
// before the home adopted it: the tree is on the chain. The next command
// adopts it, takes its change, and never holds its fee coin again.
func TestARunStoppedAfterItsTreeWasSent(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	home, tree := r.stop(true)
	id := tree.TxID().String()

	b := home.build(0, nil)
	p := one(t, b)
	op := p.Coin.Outpoint()
	if b.St.Set(kind).Tree != nil || len(b.St.UnsettledTrees()) != 1 {
		t.Fatalf("the home the run left: tree %+v, records %+v", b.St.Set(kind).Tree, b.St.PendingTrees)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	said := home.said()
	n, change := holds(b.Pool, op, id)
	if cur := b.St.Set(kind).Tree; cur == nil || cur.Txid != id || len(b.St.Set(kind).Trees) != 1 || len(b.St.PendingTrees) != 0 || n != 0 || !change ||
		!strings.Contains(said, "funding tree "+id+" is recovered") {
		t.Fatalf("after the recovery: tree %+v, records %+v, fee coin in the pool %d time(s), change in the pool %v\n%s", cur, b.St.PendingTrees, n, change, said)
	}
	if got := home.use(b); got != id+".0" {
		t.Fatalf("the next spend answered %s\n%s", got, home.said())
	}
	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The home on disk agrees, and no later command asks again.
	c := home.open(0, nil)
	if got := home.use(c); got != id+".1" || len(c.St.PendingTrees) != 0 || strings.Contains(home.said(), "recovered") {
		t.Fatalf("the command after answered %s, records %+v", got, c.St.PendingTrees)
	}
}

// A tree handed to the settlement leg an instant before the run stopped
// can reach the node after the next command asked. That command puts the
// coin back and keeps the record; the one after finds the tree on the
// chain, takes the coin, now spent, out of the pool, and adopts the tree.
func TestATreeThatLandsAfterItsCoinWentBack(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	home, tree := r.stop(false)
	id := tree.TxID().String()

	b := home.open(0, nil)
	p := one(t, b)
	op := p.Coin.Outpoint()
	if n, _ := holds(b.Pool, op, id); n != 1 || !p.ReturnedOnce {
		t.Fatalf("the first command after: coin in the pool %d time(s), record %+v\n%s", n, p, home.said())
	}
	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	home.said()
	if err := r.chain.Send(tree); err != nil {
		t.Fatal(err)
	}
	c := home.open(0, nil)
	said := home.said()
	n, change := holds(c.Pool, op, id)
	if cur := c.St.Set(kind).Tree; cur == nil || cur.Txid != id || len(c.St.PendingTrees) != 0 || n != 0 || !change ||
		!strings.Contains(said, "its fee coin "+op+" is spent and is taken out of the pool") || !strings.Contains(said, "is recovered") {
		t.Fatalf("after the tree landed: tree %+v, records %+v, fee coin in the pool %d time(s), change in the pool %v\n%s", cur, c.St.PendingTrees, n, change, said)
	}
	if got := home.use(c); got != id+".0" {
		t.Fatalf("the next spend answered %s\n%s", got, home.said())
	}
}

// A tree that never reached the chain whose coin another transaction
// spent is gone: its record is dropped at once, and the coin is not put
// back.
func TestATreeWhoseCoinAnotherTransactionSpent(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	home, tree := r.stop(false)
	id := tree.TxID().String()
	b := home.build(0, nil)
	p := one(t, b)
	by := strings.Repeat("ab", 32)
	r.chain.SpendElsewhere(p.Coin.TxID, p.Coin.Vout, by)
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	said := home.said()
	if n, _ := holds(b.Pool, p.Coin.Outpoint(), id); n != 0 || len(b.St.PendingTrees) != 0 || b.St.Set(kind).Tree != nil ||
		!strings.Contains(said, "never reached the chain: its fee coin "+p.Coin.Outpoint()+" is spent by "+by) {
		t.Fatalf("after the recovery: coin in the pool %d time(s), records %+v, tree %+v\n%s", n, b.St.PendingTrees, b.St.Set(kind).Tree, said)
	}
}

// A node that cannot answer decides nothing: the record is kept as it is,
// the command is told, and it goes on.
func TestARecordTheNodeCannotSettleIsKept(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	home, tree := r.stop(false)
	b := home.build(0, nil)
	p := one(t, b)
	b.payer.Chain = &nodeapi.Asset{Base: "http://127.0.0.1:1"}
	if err := b.RecoverTrees(context.Background()); err != nil {
		t.Fatal(err)
	}
	said := home.said()
	if n, _ := holds(b.Pool, p.Coin.Outpoint(), tree.TxID().String()); n != 0 || len(b.St.PendingTrees) != 1 || b.St.PendingTrees[0].ReturnedOnce ||
		!strings.Contains(said, "secret funding tree "+p.Tree.Txid+" was signed by a run that stopped before recording it") ||
		!strings.Contains(said, "its record is kept and the next command asks again") {
		t.Fatalf("a node that cannot answer: coin in the pool %d time(s), records %+v\n%s", n, b.St.PendingTrees, said)
	}
	// A record of a kind this version does not know is kept too, and the
	// node is not asked about it.
	b.St.PendingTrees[0].Kind = "other"
	if err := b.RecoverTrees(context.Background()); err != nil {
		t.Fatal(err)
	}
	if said := home.said(); len(b.St.PendingTrees) != 1 || !strings.Contains(said, "of a kind this bsecret does not know") {
		t.Fatalf("a record of an unknown kind: %+v\n%s", b.St.PendingTrees, said)
	}
}

// A run that stopped while a tree it minted ahead was on its way never
// recorded the tree among the trees minted ahead. The next command finds
// the tree on the chain while the current tree has outputs left: it holds
// the tree, records it as minted ahead, takes its change, and keeps the
// record until the switch. Later commands, which hold nothing in memory,
// spend the current tree out and switch to the tree once, from its first
// output.
func TestARunStoppedWhileATreeWasMintedAhead(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	// A tree of four: the first spend leaves three, so the next is minted
	// ahead. The run stops there: it is never closed.
	a := r.open(3, nil)
	spent := map[string]bool{r.use(a): true}
	current := a.St.Set(kind).Tree.Txid
	p := r.landed(a)
	id, op := p.Tree.Txid, p.Coin.Outpoint()
	r.said()

	b := r.build(0, nil)
	if len(b.St.Set(kind).Ahead) != 0 || len(b.St.UnsettledTrees()) != 1 {
		t.Fatalf("the home the run left: ahead %+v, records %+v", b.St.Set(kind).Ahead, b.St.PendingTrees)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	said := r.said()
	n, change := holds(b.Pool, op, id)
	ts := b.St.Set(kind)
	if ts.Tree.Txid != current || len(ts.Ahead) != 1 || ts.Ahead[0].Txid != id || len(b.St.PendingTrees) != 1 || len(b.St.UnsettledTrees()) != 0 ||
		n != 0 || !change || !strings.Contains(said, "funding tree "+id+" is recovered and waits for the switch") {
		t.Fatalf("after the recovery: current %s, ahead %+v, records %+v, fee coin in the pool %d time(s), change in the pool %v\n%s",
			ts.Tree.Txid, ts.Ahead, b.St.PendingTrees, n, change, said)
	}
	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Seven outputs are left: three on the current tree, four on the tree
	// minted ahead.
	var order []string
	for i := 0; i < 7; i++ {
		d := r.open(0, nil)
		if strings.Contains(r.said(), "is recovered") {
			t.Fatal("a later command asked about a tree already recorded as minted ahead")
		}
		got := r.use(d)
		if spent[got] {
			t.Fatalf("funding output %s is spent twice\n%s", got, r.said())
		}
		spent[got] = true
		if tree := got[:64]; len(order) == 0 || order[len(order)-1] != tree {
			order = append(order, tree)
		}
		if err := d.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	last := r.build(0, nil)
	ts = last.St.Set(kind)
	if len(order) != 2 || order[0] != current || order[1] != id || len(ts.Trees) != 2 || len(ts.Ahead) != 0 || len(last.St.PendingTrees) != 0 {
		t.Fatalf("the trees were spent in the order %v: %d adopted, ahead %+v, records %+v", order, len(ts.Trees), ts.Ahead, last.St.PendingTrees)
	}
	for _, tr := range ts.Trees {
		if tr.Remaining() != 0 {
			t.Fatalf("funding tree %s has %d output(s) stranded", tr.Txid, tr.Remaining())
		}
	}
}

// A tree minted ahead by a run that ended is recorded among the trees
// minted ahead, and its record stays until the switch: it is settled, so
// doctor does not name it and no later command asks the node about it.
func TestATreeMintedAheadByARunThatEndedIsSettled(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	a := r.open(3, nil)
	r.use(a)
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	b := r.open(0, nil)
	ts := b.St.Set(kind)
	if len(ts.Ahead) != 1 || len(b.St.PendingTrees) != 1 || b.St.PendingTrees[0].Tree.Txid != ts.Ahead[0].Txid || len(b.St.UnsettledTrees()) != 0 ||
		strings.Contains(r.said(), "recovered") {
		t.Fatalf("the home a run that ended left: ahead %+v, records %+v", ts.Ahead, b.St.PendingTrees)
	}
}

// Adopting a tree drops its record as a tree signed and not yet adopted,
// in the save that records it as adopted, and leaves every other record.
func TestAdoptDropsTheTreesRecord(t *testing.T) {
	dir := t.TempDir()
	w, err := bwallet.Create(dir, Profile)
	if err != nil {
		t.Fatal(err)
	}
	id := w.Signer().IdentityHex()
	st, err := state.Load(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{St: st, Signer: w.Signer()}
	first := funding.Tree{IdentityKeyHex: id, Txid: strings.Repeat("22", 32), Count: 8}
	second := funding.Tree{IdentityKeyHex: id, Txid: strings.Repeat("33", 32), Count: 8}
	coin := bwallet.Output{TxID: strings.Repeat("11", 32), Vout: 1, Satoshis: 5}
	// The record is on disk before the hook returns.
	if err := e.prepareTree(state.TreeSecret, first, coin); err != nil {
		t.Fatal(err)
	}
	if err := e.prepareTree(state.TreeChain, second, coin); err != nil {
		t.Fatal(err)
	}
	if saved, err := state.Load(dir, id); err != nil || len(saved.PendingTrees) != 2 || saved.PendingTrees[0].Coin.Outpoint() != coin.Outpoint() ||
		saved.PendingTrees[0].Kind != state.TreeSecret || saved.PendingTrees[1].Kind != state.TreeChain {
		t.Fatalf("the records the hook saved: %v %+v", err, saved)
	}
	if err := (treeState{e, state.TreeSecret}).Adopt(first); err != nil {
		t.Fatal(err)
	}
	saved, err := state.Load(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	if cur := saved.Set(state.TreeSecret).Tree; cur == nil || cur.Txid != first.Txid || len(saved.PendingTrees) != 1 || saved.PendingTrees[0].Tree.Txid != second.Txid {
		t.Fatalf("after adopting one: tree %+v, records %+v", cur, saved.PendingTrees)
	}
}

// A record that cannot be saved aborts the mint, and is not kept in memory.
func TestARecordThatCannotBeSavedAbortsTheMint(t *testing.T) {
	w, err := bwallet.Create(t.TempDir(), Profile)
	if err != nil {
		t.Fatal(err)
	}
	st, err := state.Load(filepath.Join(t.TempDir(), "gone"), w.Signer().IdentityHex())
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{St: st, Signer: w.Signer()}
	if err := e.prepareTree(state.TreeSecret, funding.Tree{Txid: strings.Repeat("22", 32)}, bwallet.Output{}); err == nil || len(st.PendingTrees) != 0 {
		t.Fatalf("a record that could not be saved: %v %+v", err, st.PendingTrees)
	}
}

// The library's refusal for a wallet whose only coin a tree minted ahead
// still holds is worded for the user.
func TestTheFeeErrorNamesAMintInFlight(t *testing.T) {
	for _, c := range []struct {
		held, minting int
		has           []string
	}{
		{0, 0, []string{"run `bsecret fund`"}},
		{2, 0, []string{"change from 2 transaction(s) whose proofs have not arrived"}},
		{0, 1, []string{"1 funding tree(s) minted ahead still hold the coin they took", "run the command again"}},
		{2, 1, []string{"change from 2 transaction(s)", "1 funding tree(s) minted ahead", "run the command again"}},
	} {
		err := FeeError(fmt.Errorf("sweep fee: %w", &producer.NoCoinError{Err: bwallet.ErrNoSpendable, Held: c.held, Minting: c.minting}))
		for _, h := range c.has {
			if !strings.Contains(err.Error(), h) {
				t.Fatalf("held %d, minting %d: %v lacks %q", c.held, c.minting, err, h)
			}
		}
		if c.minting > 0 && strings.Contains(err.Error(), "bsecret fund") {
			t.Fatalf("a mint in flight is not an empty wallet: %v", err)
		}
	}
}

// A command that ends records every tree the library still holds among the
// trees minted ahead, in the library's order, not only the first: a later
// command, which holds nothing in memory, switches to them from that list.
func TestCloseRecordsEveryHeldTree(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	a := r.open(3, nil)
	r.use(a)
	first := r.landed(a)
	b := r.open(3, func(st *state.State) { st.DropPendingTree(first.Tree.Txid) })
	r.use(b)
	second := r.landed(b)
	c := r.open(0, func(st *state.State) { st.KeepPendingTree(first) })
	if len(c.trees[kind].Held()) != 2 {
		t.Fatalf("held: %+v\n%s", c.trees[kind].Held(), r.said())
	}
	// Whatever the list held before, the close writes both.
	c.St.Set(kind).Ahead = nil
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	d := r.build(0, nil)
	ahead := d.St.Set(kind).Ahead
	if len(ahead) != 2 || ahead[0].Txid != second.Tree.Txid || ahead[1].Txid != first.Tree.Txid || len(d.St.PendingTrees) != 2 {
		t.Fatalf("after the close: ahead %+v, records %+v", ahead, d.St.PendingTrees)
	}
}

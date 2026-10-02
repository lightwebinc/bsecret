package engine

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/lightwebinc/bcommon/bwallet"
	"github.com/lightwebinc/bcommon/carrier"
	"github.com/lightwebinc/bcommon/funding"
	"github.com/lightwebinc/bcommon/guard"
	"github.com/lightwebinc/bcommon/mint"
	"github.com/lightwebinc/bcommon/producer"

	"github.com/lightwebinc/bsecret/internal/secrec"

	"github.com/lightwebinc/bsecret/internal/state"
	"github.com/lightwebinc/bsecret/internal/vread"
)

// Retraction (spec section 12.5): a sweep spends funding-tree outputs,
// used or not, with bcommon carrier.Sweep, whose output 0 is a
// funding-shaped tombstone, so a host admits it. Once it mines, every
// carrier that spent one of those outputs is a double spend, and every
// conforming host retracts it. A sweep is persisted before it is settled,
// waited for until it mines, and published once, after the propagation
// delay, to the plane and to every host named. Only honest hosts drop what
// a sweep retracts: it is not erasure, and a copy anyone kept stays a copy.

// Retract builds and persists one sweep of vouts of the funding tree txid,
// with its fee from the pool, then settles and publishes it in crypt.
func (e *Engine) Retract(ctx context.Context, crypt, txid string, vouts []uint32) (*state.Sweep, error) {
	if e.St.InFlight() != nil {
		var refusedErr *SweepRefusedError
		if err := e.FinishSweep(ctx); errors.As(err, &refusedErr) {
			e.note("%v", err)
		} else if err != nil {
			return nil, err
		}
	}
	if len(vouts) == 0 {
		return nil, errors.New("a sweep spends at least one output")
	}
	var left []uint32
	for _, v := range vouts {
		if e.SweptBy(txid, v) == nil {
			left = append(left, v)
		}
	}
	if len(left) == 0 {
		return e.SweptBy(txid, vouts[0]), nil
	}
	_, kind, ok := e.St.TreeOf(txid)
	if !ok {
		return nil, fmt.Errorf("transaction %s is not a funding tree this home keeps", txid)
	}
	// An output the chain already shows spent cannot be swept again, and a
	// sweep that named it would be refused whole, for good: the node is
	// asked about each, and what another transaction spends is left out
	// and that spend taken as the sweep it is.
	left, err := e.adoptSpends(ctx, crypt, txid, left)
	if err != nil {
		return nil, err
	}
	if len(left) == 0 {
		for _, v := range vouts {
			if sw := e.SweptBy(txid, v); sw != nil {
				return sw, nil
			}
		}
		return nil, fmt.Errorf("every output named of funding tree %s is spent by a transaction that has not mined yet, or that the node could not show: nothing is swept now; the next run takes that spend as the sweep once it mines", Short(txid))
	}
	vouts = left
	tree, err := e.kept.Tx(txid)
	if err != nil {
		return nil, err
	}
	if tree.MerklePath != nil {
		if err := e.reproveTree(ctx, tree); err != nil {
			return nil, err
		}
	}
	payer := e.NewPayer()
	fee, coin, err := e.sweepFee(ctx, payer)
	if err != nil {
		return nil, FeeError(fmt.Errorf("sweep fee: %w", err))
	}
	change, err := e.Signer.FundScript()
	if err != nil {
		payer.GiveBack()
		return nil, err
	}
	tx, err := carrier.Sweep(ctx, e.Signer, e.Signer.Originator, Params(kind), tree, vouts, fee.Tx, fee.Vout, fee.Unlocker, change,
		e.Opts.Fees.SatPerByte, e.Opts.Fees.Floor)
	if err != nil {
		payer.GiveBack()
		return nil, err
	}
	sw := state.Sweep{Tree: txid, Vouts: slices.Clone(vouts), Crypt: crypt, Crypts: e.cryptsOf(crypt, txid, vouts),
		Txid: tx.TxID().String(), RawHex: tx.Hex(), Fee: coin}
	e.St.Sweeps = append(e.St.Sweeps, sw)
	if t := e.St.Set(kind).Tree; t != nil && t.Txid == txid {
		// The rest of the tree stays usable only past every output swept.
		if last := slices.Max(vouts); last >= t.Next {
			t.Next = last + 1
		}
	}
	if err := e.St.Save(); err != nil {
		payer.GiveBack()
		return nil, err
	}
	if err := e.FinishSweep(ctx); err != nil {
		return &e.St.Sweeps[len(e.St.Sweeps)-1], err
	}
	return &e.St.Sweeps[len(e.St.Sweeps)-1], nil
}

// cryptsOf are the crypts a sweep of vouts of the funding tree txid is
// published in: crypt, and every other crypt that holds a version one of
// those outputs funded. A funding tree is the identity's, not a crypt's,
// and a host learns of a spend only from a sweep admitted in the crypt's
// own topic.
func (e *Engine) cryptsOf(crypt, txid string, vouts []uint32) []string {
	out := []string{crypt}
	for vi := range e.St.Vaults {
		v := &e.St.Vaults[vi]
		if slices.Contains(out, v.Crypt) {
			continue
		}
		for i := range v.Versions {
			if x := &v.Versions[i]; x.Tree == txid && slices.Contains(vouts, x.Vout) {
				out = append(out, v.Crypt)
				break
			}
		}
	}
	return out
}

// adoptSpends asks the node what spends each of vouts of the funding tree
// txid, and returns those still to sweep. An output another transaction
// spends is left out. Once that transaction is mined it is recorded as the
// sweep of the outputs of the tree it spends, and published as one in
// every crypt they funded a version in, when a host would admit it: the
// sweep of another instance of the tooling, or one of this home's that an
// earlier run gave up on and that mined all the same. An output whose
// spender is not mined yet is left for the next run. A node that cannot
// answer leaves the output in: the sweep is then what finds out.
func (e *Engine) adoptSpends(ctx context.Context, crypt, txid string, vouts []uint32) ([]uint32, error) {
	if e.Legs.Asset == nil {
		return vouts, nil
	}
	var left []uint32
	spenders := map[string]bool{}
	var order []string
	for _, v := range vouts {
		by, err := e.Legs.Asset.Spender(ctx, txid, v)
		if err != nil || by == "" {
			left = append(left, v)
			continue
		}
		if !spenders[by] {
			spenders[by] = true
			order = append(order, by)
		}
	}
	for _, by := range order {
		if !chainhashOK(by) {
			e.note("funding tree %s: the node names a spender that is not a transaction id; its outputs are left for the next run", Short(txid))
			continue
		}
		raw, err := e.Legs.Asset.TxRaw(ctx, by)
		if err != nil {
			e.note("funding tree %s: an output is spent by %s, which the node could not show (%v); it is left for the next run", Short(txid), Short(by), err)
			continue
		}
		tx, err := guard.ParseTransaction(raw, guard.DefaultBound)
		if err != nil || tx.TxID().String() != by {
			e.note("funding tree %s: an output is spent by %s, and the node answered other bytes for it; it is left for the next run", Short(txid), Short(by))
			continue
		}
		mp, height, err := e.Legs.Asset.Proof(ctx, by)
		if err != nil {
			e.note("funding tree %s: an output is spent by %s, which has not mined yet; it is left for the next run", Short(txid), Short(by))
			continue
		}
		var spent []uint32
		for _, in := range tx.Inputs {
			if in.SourceTXID != nil && in.SourceTXID.String() == txid {
				spent = append(spent, in.SourceTxOutIndex)
			}
		}
		if len(spent) == 0 {
			continue
		}
		sw := state.Sweep{Tree: txid, Vouts: spent, Crypt: crypt, Crypts: e.cryptsOf(crypt, txid, spent), Txid: by, RawHex: tx.Hex(),
			BumpHex: mp.Hex(), Height: height, Submitted: true, Adopted: true}
		// One this home built and gave up on is taken back as it is.
		e.St.Sweeps = slices.DeleteFunc(e.St.Sweeps, func(x state.Sweep) bool { return x.Txid == by })
		e.St.Sweeps = append(e.St.Sweeps, sw)
		if err := e.St.Save(); err != nil {
			return nil, err
		}
		e.note("funding tree %s: %d output(s) are already spent by %s, mined at height %d: it is taken as their sweep", Short(txid), len(spent), Short(by), height)
		if err := e.FinishSweep(ctx); err != nil {
			return nil, err
		}
	}
	return left, nil
}

func chainhashOK(txid string) bool {
	_, err := vread.Hash(txid)
	return err == nil
}

// RetireTrees stops the home spending every secret tree it holds: after
// the kill switch no output of them funds anything again.
func (e *Engine) RetireTrees() error {
	for _, kind := range []string{state.TreeSecret} {
		ts := e.St.Trees[kind]
		if ts == nil {
			continue
		}
		if ts.Tree != nil {
			ts.Tree.Next = ts.Tree.Count
		}
		for i := range ts.Trees {
			ts.Trees[i].Next = ts.Trees[i].Count
		}
		for i := range ts.Ahead {
			ts.Ahead[i].Next = ts.Ahead[i].Count
		}
	}
	return e.St.Save()
}

// sweepFee takes the sweep's fee coin, and the coin as the pool held it,
// so a refused sweep can give it back. When every coin left is change from
// a transaction not yet mined, it waits up to Opts.Wait for one.
func (e *Engine) sweepFee(ctx context.Context, payer *producer.Payer) (mint.Input, *bwallet.Output, error) {
	var deadline time.Time
	collected := false
	for {
		before := e.Pool.Outputs()
		fee, err := payer.Take(ctx)
		var nc *producer.NoCoinError
		if errors.As(err, &nc) && nc.Held == 0 && !collected {
			// A funding tree this run minted ahead holds the coin it took
			// until its mint is collected, and its change is this home's
			// next coin: a home with one coin has none in between. The
			// mint is collected here, so that the change is waited for
			// below rather than reported as an empty wallet.
			collected = true
			for _, kind := range state.TreeKinds {
				if t := e.trees[kind]; t != nil {
					_ = t.Wait(ctx)
				}
			}
			if ctx.Err() != nil {
				return mint.Input{}, nil, ctx.Err()
			}
			continue
		}
		if errors.As(err, &nc) && nc.Held > 0 {
			if deadline.IsZero() {
				deadline = time.Now().Add(e.Opts.Wait)
				e.note("fee: every coin is change from %d transaction(s) not yet mined; waiting for one", nc.Held)
			}
			if time.Now().After(deadline) {
				return mint.Input{}, nil, err
			}
			poll := e.Opts.Poll
			if poll <= 0 {
				poll = producer.DefaultPoll
			}
			if err := e.Sleep(ctx, poll); err != nil {
				return mint.Input{}, nil, err
			}
			CollectChange(ctx, e.Pool, e.Legs.Asset)
			continue
		}
		if err != nil {
			return mint.Input{}, nil, err
		}
		op := fmt.Sprintf("%s.%d", fee.Tx.TxID(), fee.Vout)
		for i := range before {
			if before[i].Outpoint() == op {
				return fee, &before[i], nil
			}
		}
		return fee, nil, nil
	}
}

// FinishSweep takes the sweep in flight, if any, through settlement, its
// proof and its publication. A sweep the network definitively refuses is
// marked failed, its fee coin given back when the node shows it unspent,
// and a *SweepRefusedError returned. Any other failure leaves it in flight.
func (e *Engine) FinishSweep(ctx context.Context) error {
	sw := e.St.InFlight()
	if sw == nil {
		return nil
	}
	tx, err := funding.Rebuild(sw.RawHex, sw.BumpHex, "")
	if err != nil {
		return fmt.Errorf("sweep %s: %w", sw.Txid, err)
	}
	if sw.BumpHex == "" {
		payer := e.NewPayer()
		if !sw.Submitted {
			if err := e.sources(ctx, tx); err != nil {
				return fmt.Errorf("sweep %s: %w (it is persisted; the next command sends it again)", sw.Txid, err)
			}
			if err := e.Legs.Settler.Submit(ctx, tx); err != nil && !alreadyKnown(err) {
				if why := e.refusal(ctx, tx, err); why != "" {
					return e.failSweep(ctx, sw, why)
				}
				return fmt.Errorf("sweep %s: settle via %s: %w (it is persisted; the next command sends it again)", sw.Txid, e.Legs.Settler.Name(), err)
			}
			sw.Submitted = true
			if err := e.St.Save(); err != nil {
				return err
			}
		}
		if why := e.refusal(ctx, tx, nil); why != "" {
			return e.failSweep(ctx, sw, why)
		}
		mp, height, err := payer.Await(ctx, "sweep", tx)
		if err != nil {
			if why := e.refusal(ctx, tx, nil); why != "" {
				return e.failSweep(ctx, sw, why)
			}
			return fmt.Errorf("sweep %s: %w (the next command waits again)", sw.Txid, err)
		}
		sw.BumpHex, sw.Height = mp.Hex(), height
		payer.Change(tx, height, mp)
		if err := e.St.Save(); err != nil {
			return err
		}
		tx.MerklePath = mp
	}
	if changed, err := e.current(ctx, tx); err == nil && changed {
		// A sweep mined again after a reorganisation: its current proof.
		sw.BumpHex, sw.Height = tx.MerklePath.Hex(), tx.MerklePath.BlockHeight
		if err := e.St.Save(); err != nil {
			return err
		}
	}
	mp, err := Minimal(tx.MerklePath, tx.TxID())
	if err != nil {
		return fmt.Errorf("sweep %s: %w", sw.Txid, err)
	}
	tx.MerklePath = mp
	if err := e.inHeaders(ctx, "sweep", tx); err != nil {
		return err
	}
	beef, err := tx.AtomicBEEF(false)
	if err != nil {
		return err
	}
	crypts := sw.Crypts
	if len(crypts) == 0 {
		crypts = []string{sw.Crypt}
	}
	admitted := true
	for _, crypt := range crypts {
		if _, err := secrec.Admit(ctx, beef, nil, secrec.Host{Crypt: crypt, Headers: e.Legs.Headers, MaxSweepInputs: len(tx.Inputs)}); err != nil {
			if !sw.Adopted {
				return fmt.Errorf("sweep %s breaks the host's rules (%s) and is not published: %w", Short(sw.Txid), secrec.Reason(err), err)
			}
			// A spend this home did not build may not be a sweep a host
			// admits. It is mined all the same, so the outputs are spent;
			// a reader finds that from a chain source.
			e.note("the transaction %s that spends the outputs is not a sweep a host admits (%s): it is recorded and not published", Short(sw.Txid), secrec.Reason(err))
			admitted = false
			break
		}
	}
	sw.Done = true
	for vi := range e.St.Vaults {
		v := &e.St.Vaults[vi]
		for i := range v.Versions {
			x := &v.Versions[i]
			if x.Tree == sw.Tree && slices.Contains(sw.Vouts, x.Vout) {
				// A swept version is retracted for good: its carrier is
				// not kept.
				x.Swept, x.Raw = sw.Txid, ""
			}
		}
	}
	if !admitted {
		return e.St.Save()
	}
	// The sweep is in the outbox for every crypt before it is published in
	// any: a run that stops part way publishes the rest.
	var ps []state.Pending
	for _, crypt := range crypts {
		p := state.Pending{Kind: state.KindSweep, Crypt: crypt, Txid: sw.Txid, Beef: hex.EncodeToString(beef),
			Outpoint: fmt.Sprintf("%s.%d", sw.Tree, sw.Vouts[0]), NotBefore: e.Now().Add(e.Opts.Delay).Unix()}
		if !e.St.Queued(p.Txid, p.Crypt) {
			e.St.Outbox = append(e.St.Outbox, p)
		}
		ps = append(ps, p)
	}
	if err := e.St.Save(); err != nil {
		return err
	}
	var first error
	for _, p := range ps {
		if err := e.queue(ctx, p); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// SweptBy is the sweep that spends output vout of the funding tree txid,
// or nil. A failed sweep spends nothing.
func (e *Engine) SweptBy(txid string, vout uint32) *state.Sweep {
	for i := range e.St.Sweeps {
		if sw := &e.St.Sweeps[i]; sw.Failed == "" && sw.Tree == txid && slices.Contains(sw.Vouts, vout) {
			return sw
		}
	}
	return nil
}

// sources gives every input of a transaction rebuilt from its raw bytes the
// transaction it spends: a settlement leg takes Extended Format (BRC-30).
// A funding tree or vault token is the home's own; anything else is read
// from the node.
func (e *Engine) sources(ctx context.Context, tx *transaction.Transaction) error {
	for i, in := range tx.Inputs {
		if in.SourceTransaction != nil {
			continue
		}
		id := in.SourceTXID.String()
		src, err := e.kept.Tx(id)
		if err != nil {
			src, err = e.ownToken(id)
		}
		if err != nil {
			if e.Legs.Asset == nil {
				return fmt.Errorf("input %d: %s is not kept and no node is configured to read it from", i, id)
			}
			raw, ferr := e.Legs.Asset.TxRaw(ctx, id)
			if ferr != nil {
				return fmt.Errorf("input %d: reading %s from the node: %w", i, id, ferr)
			}
			if src, err = guard.ParseTransaction(raw, guard.DefaultBound); err != nil {
				return fmt.Errorf("input %d: %s from the node: %w", i, id, err)
			}
		}
		if src.TxID().String() != id || int(in.SourceTxOutIndex) >= len(src.Outputs) {
			return fmt.Errorf("input %d: the transaction found for %s is not the one it spends", i, id)
		}
		in.SourceTransaction = src
	}
	return nil
}

// Tx is a funding tree the home keeps, rebuilt.
func (e *Engine) Tx(txid string) (*transaction.Transaction, error) { return e.kept.Tx(txid) }

package module

import (
	"context"
	"fmt"
	"sort"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"

	bmodule "github.com/lightwebinc/bcommon/module"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

type restoreRow struct {
	o     bmodule.Output
	tx    *transaction.Transaction
	sweep bool
}

// Restore implements module.Restorer (spec section 11.4): it rebuilds the
// index. The rows from the journal, then every output of this module's
// topics the host hands over (a row handed without its BEEF is read again
// from storage with it), then every token, carrier and sweep the journal
// names that the unspent rows did not carry (a token its successor spent,
// say), and then each held token's predecessors, read through the input
// that spends them. A token is read as the engine stores it, so a
// predecessor is the token the host holds at seq - 1, never a BEEF's.
// Sweeps are taken in storage's order, so the bounded table keeps the
// newest. Chains are rooted and folded from seq 0 whatever order storage
// returns rows in, and each seq is held to its bound only once every
// token's descent is known. A storage failure propagates: a restore that
// skipped a sweep would answer retracted carriers.
func (s *Service) Restore(ctx context.Context, outputs []bmodule.Output, storage bmodule.RestoreStorage) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clear()
	lines, err := s.journal.Load()
	if err != nil {
		return 0, err
	}
	for i := range lines {
		s.apply(&lines[i])
	}
	s.storage = storage
	seen := map[string]bool{}
	var queue []bmodule.Output
	key := func(topic, txid string, vout uint32) string { return fmt.Sprintf("%s|%s.%d", topic, txid, vout) }
	for _, o := range outputs {
		k := key(o.Topic, o.Outpoint.Txid.String(), o.Outpoint.Index)
		if _, ok := s.cryptOf(o.Topic); !ok || seen[k] {
			continue
		}
		seen[k] = true
		queue = append(queue, o)
	}
	type named struct {
		topic, txid string
		vout        uint32
	}
	var names []named
	for c, sc := range s.seen {
		if s.crypts[sc.crypt] {
			names = append(names, named{secrec.Topic(sc.crypt), chainhash.Hash(h32(c)).String(), 0})
		}
	}
	for txid, t := range s.tokenSeen {
		if s.crypts[t.crypt] {
			names = append(names, named{secrec.Topic(t.crypt), txid, t.vout})
		}
	}
	for _, r := range s.rows {
		for _, sid := range r.order {
			if sp := r.sweeps[sid]; s.crypts[sp.crypt] {
				names = append(names, named{secrec.Topic(sp.crypt), sid, 0})
			}
		}
	}
	for sid, crypts := range s.spentSweeps {
		for c := range crypts {
			if s.crypts[c] {
				names = append(names, named{secrec.Topic(c), sid, 0})
			}
		}
	}
	sort.Slice(names, func(i, j int) bool {
		if names[i].topic != names[j].topic {
			return names[i].topic < names[j].topic
		}
		if names[i].txid != names[j].txid {
			return names[i].txid < names[j].txid
		}
		return names[i].vout < names[j].vout
	})
	for _, n := range names {
		k := key(n.topic, n.txid, n.vout)
		if seen[k] {
			continue
		}
		seen[k] = true
		h, err := chainhash.NewHashFromHex(n.txid)
		if err != nil {
			continue
		}
		o, err := storage.FindOutput(ctx, &transaction.Outpoint{Txid: *h, Index: n.vout}, n.topic)
		if err != nil {
			return 0, err
		}
		if o != nil {
			queue = append(queue, *o)
		}
	}
	read := func(o bmodule.Output) (*transaction.Transaction, error) {
		row := o
		if row.Beef == nil {
			full, err := storage.FindOutput(ctx, &row.Outpoint, row.Topic)
			if err != nil {
				return nil, err
			}
			if full != nil {
				row = *full
			}
		}
		if row.Beef == nil {
			return nil, nil
		}
		tx, err := parse(row.Beef)
		if err != nil {
			return nil, nil
		}
		return tx, nil
	}
	var txs []restoreRow
	for _, o := range queue {
		tx, err := read(o)
		if err != nil {
			return 0, err
		}
		if tx == nil {
			s.host.Log("ls_bsecret could not restore an output without its transaction", map[string]any{"topic": o.Topic, "txid": o.Outpoint.Txid.String()})
			continue
		}
		sweep := false
		if int(o.Outpoint.Index) < len(tx.Outputs) && o.Outpoint.Index == 0 && tx.Outputs[0] != nil && tx.Outputs[0].LockingScript != nil {
			sweep = secrec.IsFundingShape(*tx.Outputs[0].LockingScript)
		}
		txs = append(txs, restoreRow{o: o, tx: tx, sweep: sweep})
	}
	// Carriers and tokens first, sweeps after them in storage's order.
	sort.SliceStable(txs, func(i, j int) bool {
		a, b := txs[i], txs[j]
		if a.sweep != b.sweep {
			return !a.sweep
		}
		if !a.sweep {
			return false
		}
		if a.o.Score != b.o.Score {
			return a.o.Score < b.o.Score
		}
		return a.o.Outpoint.Txid.String() < b.o.Outpoint.Txid.String()
	})
	indexed := 0
	s.restoring = true
	take := func(o bmodule.Output, tx *transaction.Transaction) {
		crypt, _ := s.cryptOf(o.Topic)
		if s.index(crypt, tx, o.Outpoint.Index, o.Score) {
			indexed++
		}
	}
	for _, r := range txs {
		take(r.o, r.tx)
	}
	// Each held token's predecessors, through the input that spends them.
	type step struct {
		topic string
		tx    *transaction.Transaction
		prev  string
	}
	var walk []step
	next := func(o bmodule.Output, tx *transaction.Transaction) {
		txid := o.Outpoint.Txid.String()
		if k, ok := s.tokenVault[txid]; ok {
			if t := s.vaults[k].byTxid[txid]; t != nil && t.vout == o.Outpoint.Index && t.prev != "" {
				walk = append(walk, step{o.Topic, tx, t.prev})
			}
		}
	}
	for _, r := range txs {
		next(r.o, r.tx)
	}
	for len(walk) > 0 {
		w := walk[len(walk)-1]
		walk = walk[:len(walk)-1]
		if _, held := s.tokenVault[w.prev]; held {
			continue
		}
		var in *transaction.TransactionInput
		for _, i := range w.tx.Inputs {
			if srcTxid(i) == w.prev {
				in = i
				break
			}
		}
		if in == nil {
			continue
		}
		h, err := chainhash.NewHashFromHex(w.prev)
		if err != nil {
			continue
		}
		o, err := storage.FindOutput(ctx, &transaction.Outpoint{Txid: *h, Index: in.SourceTxOutIndex}, w.topic)
		if err != nil {
			return 0, err
		}
		if o == nil {
			continue
		}
		tx, err := read(*o)
		if err != nil {
			return 0, err
		}
		if tx == nil {
			continue
		}
		take(*o, tx)
		next(*o, tx)
	}
	s.restoring = false
	keys := make([]string, 0, len(s.vaults))
	for k := range s.vaults {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := s.vaults[k]
		for _, t := range v.bySeq[0] {
			s.rootFrom(v, t, true)
		}
		for _, t := range v.byTxid {
			if !t.rooted {
				s.counted(v, t)
			}
		}
		var seqs []uint64
		for seq := range v.bySeq {
			seqs = append(seqs, seq)
		}
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
		for _, seq := range seqs {
			s.bound(v, seq)
		}
	}
	s.enforceTable()
	s.drain(ctx)
	s.flush(ctx)
	return indexed, nil
}

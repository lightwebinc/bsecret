package engine

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"

	"github.com/lightwebinc/bcommon/bwallet"
	"github.com/lightwebinc/bcommon/funding"
	"github.com/lightwebinc/bcommon/guard"
	"github.com/lightwebinc/bcommon/mint"
	"github.com/lightwebinc/bcommon/producer"
	"github.com/lightwebinc/bcommon/pushdrop"

	"github.com/lightwebinc/borg/reader"

	"github.com/lightwebinc/bsecret/internal/limits"
	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/state"
	"github.com/lightwebinc/bsecret/internal/vread"
)

// LostError is a transition another transaction spending the same
// predecessor beat to the chain (spec section 8.4): nothing it listed is
// listed, and the versions it published stay unlisted until they are swept.
type LostError struct {
	What string
	Txid string
	By   string
	// Fee is set when it was the fee coin, not the predecessor, that
	// another transaction spent: no transition beat this one.
	Fee bool
}

func (e *LostError) Error() string {
	if e.Fee {
		return fmt.Sprintf("%s %s lost: its fee coin is spent by %s, a transaction of another instance of the tooling that held the same coin; nothing it listed is listed; run the command again", e.What, Short(e.Txid), Short(e.By))
	}
	return fmt.Sprintf("%s %s lost: its predecessor is spent by %s, another transition; nothing it listed is listed; run `bsecret sync`, then the command again", e.What, Short(e.Txid), Short(e.By))
}

// rebuild rebuilds a mined token of the home's own.
func rebuild(t *state.Token) (*transaction.Transaction, error) {
	return funding.Rebuild(t.RawHex, t.BumpHex, "")
}

// ownToken finds a token of the home's own vaults by txid, rebuilt.
func (e *Engine) ownToken(txid string) (*transaction.Transaction, error) {
	for vi := range e.St.Vaults {
		ts := e.St.Vaults[vi].Tokens
		for i := range ts {
			if ts[i].Txid == txid {
				return rebuild(&ts[i])
			}
		}
	}
	return nil, fmt.Errorf("%s is not a token of this home's", txid)
}

// Records are a vault's own chain, decoded.
func Records(v *state.Vault) ([]*secrec.Vault, error) {
	var out []*secrec.Vault
	for _, t := range v.Tokens {
		b, err := hex.DecodeString(t.Record)
		if err != nil {
			return nil, err
		}
		r, err := secrec.DecodeVault(b)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// Fold folds a vault's own chain from seq 0. A chain that does not fold
// consistently is an error: the home never builds on one.
func Fold(v *state.Vault) (*secrec.VaultFold, []*secrec.Vault, error) {
	recs, err := Records(v)
	if err != nil {
		return nil, nil, err
	}
	f := secrec.NewVaultFold()
	for _, r := range recs {
		if st := f.Apply(r); st != secrec.StatusConsistent {
			return nil, nil, fmt.Errorf("vault %s: its own chain folds to %s at seq %d: nothing is built on it (spec section 11.2)", vread.Short(v.ID), st, r.Seq)
		}
	}
	return f, recs, nil
}

func hashOf(txid string) [32]byte {
	h, err := chainhash.NewHashFromHex(txid)
	if err != nil {
		panic(err)
	}
	return [32]byte(*h)
}

func hex32(s string) [32]byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		panic("engine: a 32-byte value that is not 32 bytes")
	}
	return [32]byte(b)
}

func (e *Engine) created() uint64 {
	t := e.Now().Unix()
	if t < 1 {
		t = 1
	}
	return uint64(t) //nolint:gosec // a clock after 1970
}

// Writer is a writer's view of one vault at the moment it holds the
// evidence the contract asks for before any transition (spec section 7.1):
// the vault's own chain folded, its latest token mined in the writer's
// headers and unspent per the node, and the group's chain read through
// borg with its latest token unspent too.
type Writer struct {
	Vault *state.Vault
	// Recs are the vault's chain; Pred its latest record and Last that
	// token.
	Recs []*secrec.Vault
	Pred *secrec.Vault
	Last *state.Token
	// Fold is the fold of the chain; a transition is tried on a clone.
	Fold *secrec.VaultFold
	// Group is the vault's group and Stand the vault's standing against it.
	Group *vread.Group
	Stand vread.Standing
	// At is when the evidence was gathered.
	At time.Time
}

// ErrStale is evidence a writer could not gather: without it nothing is
// written (spec section 7.1: fail closed).
var ErrStale = errors.New("no positive evidence that the vault's and the group's latest tokens are the latest")

// Ready gathers a writer's evidence for one vault. Without it the tooling
// does not write.
func (e *Engine) Ready(ctx context.Context, v *state.Vault) (*Writer, error) {
	if v.Pending != nil {
		return nil, fmt.Errorf("vault %s: %s %s is persisted and not yet mined; the next command finishes it", vread.Short(v.ID), v.Pending.What, Short(v.Pending.Txid))
	}
	f, recs, err := Fold(v)
	if err != nil {
		return nil, err
	}
	last := state.Latest(v.Tokens)
	if last == nil {
		return nil, fmt.Errorf("vault %s has no token yet", vread.Short(v.ID))
	}
	w := &Writer{Vault: v, Recs: recs, Pred: recs[len(recs)-1], Last: last, Fold: f, At: e.Now()}
	// 1. the vault's latest token is the latest: mined in the writer's own
	// headers, and its output unspent per a source that indexes spends.
	if _, err := e.tokenTx(ctx, last); err != nil {
		return nil, fmt.Errorf("%w: the vault's latest token: %v", ErrStale, err)
	}
	by, err := e.Legs.Asset.Spender(ctx, last.Txid, last.Vout)
	if err != nil {
		return nil, fmt.Errorf("%w: the node could not say whether %s.%d is spent: %v", ErrStale, last.Txid, last.Vout, err)
	}
	if by != "" {
		return nil, fmt.Errorf("%w: the vault's latest token %s is spent by %s: another instance moved the vault, or it is terminated; run `bsecret sync` to read the chain again", ErrStale, Short(last.Txid), Short(by))
	}
	// 2. the group's latest epoch is the latest (borg's writer rule).
	g, err := e.group(ctx, v)
	if err != nil {
		return nil, err
	}
	if err := vread.GroupFresh(ctx, e.Legs.Asset, e.Legs.Asset.TxRaw, g, e.Now()); err != nil {
		return nil, fmt.Errorf("%w: the group: %v", ErrStale, err)
	}
	w.Group, w.Stand = g, g.Stand(w.Pred)
	if w.Stand.Ahead {
		return nil, fmt.Errorf("vault %s is %s: its owner wrote a token no honest tooling writes, and nothing is built on it", vread.Short(v.ID), w.Stand)
	}
	return w, nil
}

// refresh asks the spend source again whether the vault's and the group's
// latest tokens, as the writer holds them, are unspent. A vault or a group
// that moved since Ready is no evidence: fail closed.
func (e *Engine) refresh(ctx context.Context, w *Writer) error {
	by, err := e.Legs.Asset.Spender(ctx, w.Last.Txid, w.Last.Vout)
	if err != nil {
		return fmt.Errorf("%w: the node could not say whether %s.%d is spent: %v", ErrStale, w.Last.Txid, w.Last.Vout, err)
	}
	if by != "" {
		return fmt.Errorf("%w: the vault's latest token %s is spent by %s; run `bsecret sync`", ErrStale, Short(w.Last.Txid), Short(by))
	}
	if err := vread.GroupFresh(ctx, e.Legs.Asset, e.Legs.Asset.TxRaw, w.Group, e.Now()); err != nil {
		return fmt.Errorf("%w: the group: %v", ErrStale, err)
	}
	w.At = e.Now()
	return nil
}

// tokenTx rebuilds a mined token of the home's own under a proof that
// verifies against the publisher's headers, replacing a kept proof a
// reorganisation left stale with the node's current one, in the home too.
func (e *Engine) tokenTx(ctx context.Context, t *state.Token) (*transaction.Transaction, error) {
	tx, err := rebuild(t)
	if err != nil {
		return nil, err
	}
	changed, err := e.current(ctx, tx)
	if err != nil {
		return nil, err
	}
	if changed {
		e.note("token %s: its kept proof named a block that is no longer in the header source's chain; the node's current proof, at height %d, replaces it", Short(t.Txid), tx.MerklePath.BlockHeight)
		t.BumpHex, t.Height = tx.MerklePath.Hex(), tx.MerklePath.BlockHeight
		if err := e.St.Save(); err != nil {
			return nil, err
		}
	}
	return tx, nil
}

// group reads the vault's group through borg's reader.
func (e *Engine) group(ctx context.Context, v *state.Vault) (*vread.Group, error) {
	gid, err := reader.ParseGroup(v.Group)
	if err != nil {
		return nil, err
	}
	g, err := vread.ReadGroup(ctx, e.Legs.Groups, v.Hall, e.OrgKey(), gid)
	if err != nil {
		return nil, fmt.Errorf("the vault's group %s in hall %s: %w", v.Group, v.Hall, err)
	}
	if g.Rejoined {
		e.note("warning: the group re-added a removed key without a new epoch (rejoin-unrotated): that key reads what was written while it was away; rotate the group (borg epoch rotate)")
	}
	return g, nil
}

// EpochKey opens the symmetric key of one epoch of the group as the
// organisation: through the wrap borg made to the organisation's signer
// key, by borg's member checks.
func (e *Engine) EpochKey(ctx context.Context, g *vread.Group, epoch uint64) ([32]byte, error) {
	if e.Key == nil {
		return [32]byte{}, errors.New("the organisation's identity key is not open: the signer key cannot be derived")
	}
	w, pub, err := vread.SignerWallet(e.Key)
	if err != nil {
		return [32]byte{}, err
	}
	sym, err := vread.OpenEpoch(ctx, e.Legs.Groups, w, pub, g, epoch)
	if err != nil {
		return [32]byte{}, fmt.Errorf("the organisation's signer key %s opens no wrap of epoch %d of the group: %w; run `borg org signer` in the organisation's borg home, which makes the signer key a member of every group so that the organisation's tooling holds each epoch's key (docs/usage.md)", hex.EncodeToString(pub), epoch, err)
	}
	return sym, nil
}

// CreateVault creates a vault keyed to a group of the organisation (spec
// section 8.1): a chain tree, mined; vault token seq 0 spending one of its
// outputs, with the vault identifier that outpoint gives, the group and its
// latest epoch, the label set and the anchor mode; once it is mined, the
// token is published with the chain tree in its BEEF. The vault is created
// empty: its first secrets are put afterwards.
func (e *Engine) CreateVault(ctx context.Context, crypt, name, hall string, group [secrec.GroupIDLen]byte, labels []string, anchor uint64) (*state.Vault, error) {
	for vi := range e.St.Vaults {
		if p := e.St.Vaults[vi].Pending; p != nil {
			return nil, fmt.Errorf("%s %s is persisted and not yet mined; the next command finishes it", p.What, Short(p.Txid))
		}
	}
	labels = append([]string(nil), labels...)
	sort.Strings(labels)
	probe := &state.Vault{Hall: hall, Group: reader.GroupHex(group)}
	g, err := e.group(ctx, probe)
	if err != nil {
		return nil, err
	}
	if err := vread.GroupFresh(ctx, e.Legs.Asset, e.Legs.Asset.TxRaw, g, e.Now()); err != nil {
		return nil, fmt.Errorf("%w: the group: %v", ErrStale, err)
	}
	cur := g.Current()
	// The organisation must be able to write under the epoch it names.
	if _, err := e.EpochKey(ctx, g, cur.Epoch); err != nil {
		return nil, err
	}
	chainTree, cv, err := e.spend(ctx, state.TreeChain)
	if err != nil {
		return nil, err
	}
	id := secrec.VaultID([32]byte(*chainTree.TxID()), cv)
	rec := &secrec.Vault{Crypt: crypt, Org: e.OrgKey(), Vault: id, Name: name, Hall: hall, Group: group,
		Epoch: cur.Epoch, EpochID: cur.EpochID, Labels: labels, Anchor: anchor, Root: secrec.SetRoot(nil), Created: e.created()}
	if st := secrec.NewVaultFold().Apply(rec); st != secrec.StatusConsistent {
		return nil, fmt.Errorf("the vault's first token would fold to %s; it is not built", st)
	}
	b, err := rec.Encode()
	if err != nil {
		return nil, fmt.Errorf("the vault record breaks its own rules (%s): %w", secrec.Reason(err), err)
	}
	vid := hex.EncodeToString(id[:])
	e.St.Vaults = append(e.St.Vaults, state.Vault{ID: vid, Crypt: crypt, Name: name, Hall: hall, Group: reader.GroupHex(group),
		Anchor: anchor, Labels: labels})
	v := e.St.VaultByID(vid)
	tr, tx, err := e.buildToken(ctx, v, 0, b, chainTree, cv, secrec.ChainDerivation)
	if err != nil {
		e.St.Vaults = e.St.Vaults[:len(e.St.Vaults)-1]
		return nil, err
	}
	tr.What = fmt.Sprintf("vault %s token seq 0", vread.Short(vid))
	e.markSpent(state.TreeChain, chainTree, cv)
	if err := e.run(ctx, v, tr, tx); err != nil {
		return e.St.VaultByID(vid), err
	}
	return e.St.VaultByID(vid), nil
}

// Change is a vault transition asked for.
type Change struct {
	// Create and Update are the versions entering the set, each with the
	// record a carrier already published carries; Retire the identifiers
	// leaving it.
	Create []*Minted
	Update []*Minted
	Retire [][32]byte
	// Epoch, when set, is the later epoch of the group the transition
	// acknowledges; nil keeps the vault's epoch.
	Epoch *secrec.EpochEvent
	What  string
}

// Build makes the next vault record for a change and proves, before
// anything is signed, that no host and no index would flag it: the record
// is applied to a copy of the fold of the vault's own chain, which must
// answer consistent, held to the transition rules a host checks against
// its predecessor, and every version it lists is held to the record the
// carrier published. It returns the record, encoded.
func (w *Writer) Build(c Change, created uint64) (*secrec.Vault, []byte, error) {
	pred := w.Pred
	if c.Epoch == nil && len(c.Create)+len(c.Update)+len(c.Retire) == 0 {
		return nil, nil, errors.New("the transition changes nothing; it is not built")
	}
	rec := &secrec.Vault{Crypt: pred.Crypt, Org: pred.Org, Vault: pred.Vault, Seq: pred.Seq + 1, Prev: hashOf(w.Last.Txid),
		Name: pred.Name, Hall: pred.Hall, Group: pred.Group, Epoch: pred.Epoch, EpochID: pred.EpochID,
		Labels: append([]string(nil), pred.Labels...), Anchor: pred.Anchor, Created: created}
	if c.Epoch != nil {
		if c.Epoch.Epoch <= pred.Epoch {
			return nil, nil, fmt.Errorf("epoch %d is not later than the vault's epoch %d", c.Epoch.Epoch, pred.Epoch)
		}
		rec.Epoch, rec.EpochID = c.Epoch.Epoch, c.Epoch.EpochID
	}
	set := map[[32]byte]secrec.Current{}
	for _, cur := range w.Fold.Set() {
		set[cur.ID] = cur
	}
	for _, id := range c.Retire {
		if _, ok := set[id]; !ok {
			return nil, nil, fmt.Errorf("secret %s is not in the vault's set", vread.Short(hex.EncodeToString(id[:])))
		}
		delete(set, id)
		rec.Retire = append(rec.Retire, id)
	}
	for _, list := range []struct {
		in  []*Minted
		out *[]secrec.Entry
		new bool
	}{{c.Update, &rec.Update, false}, {c.Create, &rec.Create, true}} {
		for _, m := range list.in {
			if _, ok := set[m.Entry.ID]; ok == list.new {
				if list.new {
					return nil, nil, fmt.Errorf("secret %q is in the vault's set already", m.Name)
				}
				return nil, nil, fmt.Errorf("secret %q is not in the vault's set", m.Name)
			}
			set[m.Entry.ID] = secrec.Current{ID: m.Entry.ID, Version: m.Entry.Version, ContentID: m.Entry.ContentID, Epoch: rec.Epoch, Seq: rec.Seq}
			*list.out = append(*list.out, m.Entry)
		}
	}
	sort.Slice(rec.Create, func(i, j int) bool { return bytes.Compare(rec.Create[i].ID[:], rec.Create[j].ID[:]) < 0 })
	sort.Slice(rec.Update, func(i, j int) bool { return bytes.Compare(rec.Update[i].ID[:], rec.Update[j].ID[:]) < 0 })
	sort.Slice(rec.Retire, func(i, j int) bool { return bytes.Compare(rec.Retire[i][:], rec.Retire[j][:]) < 0 })
	now := make([]secrec.Current, 0, len(set))
	for _, cur := range set {
		now = append(now, cur)
		if cur.Epoch < rec.Epoch {
			rec.Stale++
		}
	}
	rec.Count, rec.Root = uint64(len(now)), secrec.SetRoot(now)
	if rec.Count > secrec.MaxSecrets {
		return nil, nil, fmt.Errorf("a vault holds at most %d secrets", secrec.MaxSecrets)
	}
	raw, err := rec.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("the transition breaks the record's own rules (%s); it is not built: %w", secrec.Reason(err), err)
	}
	if err := secrec.CheckVaultTransition(pred, hashOf(w.Last.Txid), rec); err != nil {
		return nil, nil, fmt.Errorf("the transition breaks the rules every host checks (%s); it is not built: %w", secrec.Reason(err), err)
	}
	if st := w.Fold.Clone().Apply(rec); st != secrec.StatusConsistent {
		return nil, nil, fmt.Errorf("the transition would be reported %s by every host's index, which ends a vault for good; it is not built", st)
	}
	for _, m := range append(append([]*Minted(nil), c.Create...), c.Update...) {
		if err := secrec.CheckListed(rec, m.Record); err != nil {
			return nil, nil, fmt.Errorf("the token would list %q as something other than the record its carrier published (mismatched); it is not built", m.Name)
		}
	}
	// The record a reader decodes is the record that was folded.
	back, err := secrec.DecodeVault(raw)
	if err != nil {
		return nil, nil, err
	}
	if again, err := back.Encode(); err != nil || !bytes.Equal(again, raw) {
		return nil, nil, errors.New("the vault record does not read back as it was written; it is not built")
	}
	return rec, raw, nil
}

// transition mints the vault's next token for a change.
func (e *Engine) transition(ctx context.Context, w *Writer, c Change) error {
	// The evidence is taken again at the moment of building, so it is as
	// fresh as it can be when the token is signed.
	if err := e.refresh(ctx, w); err != nil {
		return err
	}
	n := len(c.Create) + len(c.Update) + len(c.Retire)
	if len(c.Create) > secrec.MaxDelta || len(c.Update) > secrec.MaxDelta || len(c.Retire) > secrec.MaxDelta {
		return fmt.Errorf("one token creates, updates and retires at most %d secrets each; a larger change is several transitions", secrec.MaxDelta)
	}
	rec, raw, err := w.Build(c, e.created())
	if err != nil {
		return err
	}
	if e.Legs.Facade != nil && n > limits.PlaneChangesWarn && w.Pred.Stale == 0 && c.Epoch == nil {
		e.note("warning: %d changes in one token on the plane; a token and its parent then pass 6 packets (docs/limits.md)", n)
	}
	if rec.Count > limits.SecretsWarn {
		e.note("warning: the vault holds %d secrets; a removal from its group then takes more than 4 blocks to settle (docs/limits.md)", rec.Count)
	}
	parent, err := e.tokenTx(ctx, w.Last)
	if err != nil {
		return err
	}
	tr, tx, err := e.buildToken(ctx, w.Vault, rec.Seq, raw, parent, w.Last.Vout, secrec.VaultDerivation)
	if err != nil {
		return err
	}
	tr.What = c.What
	if tr.What == "" {
		tr.What = fmt.Sprintf("vault %s token seq %d", vread.Short(w.Vault.ID), rec.Seq)
	}
	return e.run(ctx, w.Vault, tr, tx)
}

// buildToken builds and signs a vault token spending output parentVout of
// parent (unlocked under parentDeriv) and a fee coin from the pool.
func (e *Engine) buildToken(ctx context.Context, v *state.Vault, seq uint64, record []byte, parent *transaction.Transaction, parentVout uint32, parentDeriv pushdrop.Derivation) (*state.Transition, *transaction.Transaction, error) {
	lock, err := secrec.VaultDerivation.Lock(ctx, e.Signer, e.Signer.Originator, [][]byte{secrec.TagVault, record}, true)
	if err != nil {
		return nil, nil, err
	}
	payer, fee, coin, err := e.tokenFee(ctx, v, seq, parent)
	if err != nil {
		return nil, nil, err
	}
	change, err := e.Signer.FundScript()
	if err != nil {
		payer.GiveBack()
		return nil, nil, err
	}
	tx, err := mint.Transition(lock, 1, &mint.Input{Tx: parent, Vout: parentVout, Unlocker: parentDeriv.Unlocker(ctx, e.Signer, e.Signer.Originator)},
		fee, change, e.Opts.Fees)
	if err != nil {
		payer.GiveBack()
		return nil, nil, err
	}
	// What every host checks of a token's inputs (spec section 11.1 rule 8)
	// is checked here, before anything is sent: a token mined that no host
	// admits can never be published, and its vault's chain would end there.
	if err := spendsItsParent(tx, parent, parentVout, seq); err != nil {
		payer.GiveBack()
		return nil, nil, err
	}
	// What was signed is what was folded: the token output's record, read
	// back from the transaction, is the record built.
	tok, err := secrec.ReadToken(tx)
	if err != nil || !bytes.Equal(tok.Record, record) || tok.Vout != 0 {
		payer.GiveBack()
		return nil, nil, fmt.Errorf("the token built does not carry the record folded (%v); it is not sent", err)
	}
	tr := &state.Transition{Vault: v.ID, Seq: seq, Txid: tx.TxID().String(), RawHex: tx.Hex(), Record: hex.EncodeToString(record),
		Vout: 0, Parent: parent.TxID().String(), ParentVout: parentVout, Fee: coin}
	return tr, tx, nil
}

// spendsItsParent holds a token just built to the host's rule on its
// inputs: a first token spends exactly one output of its parent, the chain
// tree; a later one spends its predecessor's token output and no other
// token output of that transaction (its other outputs it may spend).
func spendsItsParent(tx, parent *transaction.Transaction, parentVout uint32, seq uint64) error {
	if seq == 0 {
		n, ptxid := 0, *parent.TxID()
		for _, in := range tx.Inputs {
			if in.SourceTXID != nil && *in.SourceTXID == ptxid {
				n++
			}
		}
		if n != 1 {
			return fmt.Errorf("%w: the first token built spends %d outputs of its chain tree, and every host admits exactly one; it is not sent", secrec.ErrTokenInput, n)
		}
		return nil
	}
	if vout, ok := secrec.PredecessorSpend(tx, parent); !ok || vout != parentVout {
		return fmt.Errorf("%w: the token built does not spend its predecessor's token output exactly once; it is not sent", secrec.ErrTokenInput)
	}
	return nil
}

// tokenFee takes the coin that pays a token's fee, and returns it with the
// payer that holds it reserved.
//
// A first token spends exactly one output of its parent, the chain tree
// (spec section 11.1 rule 8): a second input that spends the tree is
// refused token-input by every host. So a first token's fee is never the
// tree's own change, which is the one coin a home holds when its one coin
// paid for the tree. Another coin is taken when the pool has one. When it
// has none, the tree's change is first paid to this home's own fund key in
// a transaction of its own, and once that is mined its outputs pay the fee.
func (e *Engine) tokenFee(ctx context.Context, v *state.Vault, seq uint64, parent *transaction.Transaction) (*producer.Payer, mint.Input, *bwallet.Output, error) {
	fromParent := func(in mint.Input) bool {
		return seq == 0 && in.Tx != nil && *in.Tx.TxID() == *parent.TxID()
	}
	for moved := 0; ; moved++ {
		payer := e.NewPayer()
		fee, coin, err := e.sweepFee(ctx, payer)
		if err != nil {
			return nil, mint.Input{}, nil, FeeError(err)
		}
		if !fromParent(fee) {
			return payer, fee, coin, nil
		}
		// The tree's change stays reserved while another coin is looked
		// for, so the pool cannot hand it out again.
		before := e.Pool.Outputs()
		other := e.NewPayer()
		if alt, err := other.Take(ctx); err == nil {
			if !fromParent(alt) {
				payer.GiveBack()
				op := fmt.Sprintf("%s.%d", alt.Tx.TxID(), alt.Vout)
				for i := range before {
					if before[i].Outpoint() == op {
						return other, alt, &before[i], nil
					}
				}
				return other, alt, nil, nil
			}
			other.GiveBack()
		}
		if moved > 0 {
			payer.GiveBack()
			return nil, mint.Input{}, nil, errors.New("the only coins this home holds are its chain tree's own outputs, after one was moved; fund the home with another coin (bsecret fund)")
		}
		fund, err := e.Signer.FundScript()
		if err != nil {
			payer.GiveBack()
			return nil, mint.Input{}, nil, err
		}
		step, err := mint.Payment(ctx, fund, fee.Tx.Outputs[fee.Vout].Satoshis/2, fee, fund, e.Opts.Fees)
		if err != nil {
			payer.GiveBack()
			return nil, mint.Input{}, nil, fmt.Errorf("the only coin this home holds is its chain tree's own change, which a first token cannot spend, and it cannot be moved: %w; fund the home with another coin (bsecret fund)", err)
		}
		id := step.TxID().String()
		e.note("vault %s: the only coin this home holds is its chain tree's own change, and a first token spends exactly one output of its chain tree (every host refuses a second): the coin is first paid to this home's own fund key in %s. If this run stops before that is mined, import it with `bsecret fund -txid %s`", Short(v.ID), id, id)
		if err := e.Legs.Settler.Submit(ctx, step); err != nil && !alreadyKnown(err) {
			payer.GiveBack()
			return nil, mint.Input{}, nil, fmt.Errorf("the payment %s to this home's own fund key: settle via %s: %w", Short(id), e.Legs.Settler.Name(), err)
		}
		mp, h, err := payer.Await(ctx, "the payment to this home's own fund key", step)
		if err != nil {
			// It reached the settlement leg: the coin is not given back.
			// The next command's journal puts it back only when the node
			// shows it unspent.
			return nil, mint.Input{}, nil, fmt.Errorf("the payment %s to this home's own fund key: %w; once it is mined, import it with `bsecret fund -txid %s` and run the command again", Short(id), err, id)
		}
		step.MerklePath = mp
		payer.Change(step, h, mp)
		if err := e.St.Save(); err != nil {
			return nil, mint.Input{}, nil, err
		}
	}
}

// pendingTx is the transition built in this run, so its inputs keep their
// source transactions for the settlement leg.
type pendingTx struct {
	txid string
	tx   *transaction.Transaction
}

// run persists a transition before anything is sent, then takes it through
// settlement, its proof and publication.
func (e *Engine) run(ctx context.Context, v *state.Vault, tr *state.Transition, tx *transaction.Transaction) error {
	v.Pending = tr
	if err := e.St.Save(); err != nil {
		return err
	}
	e.pending = &pendingTx{tr.Txid, tx}
	return e.finish(ctx, v)
}

// FinishTransitions takes every persisted transition to the chain.
// Every vault is tried: a transition that is lost, or cannot finish yet,
// does not keep another vault's from the chain. The first failure is
// returned, a *LostError only when nothing else failed.
func (e *Engine) FinishTransitions(ctx context.Context) error {
	// By identifier: a first token that is lost takes its vault out of
	// the home.
	ids := make([]string, 0, len(e.St.Vaults))
	for vi := range e.St.Vaults {
		ids = append(ids, e.St.Vaults[vi].ID)
	}
	var first error
	var lost *LostError
	for _, id := range ids {
		v := e.St.VaultByID(id)
		if v == nil {
			continue
		}
		err := e.finish(ctx, v)
		var l *LostError
		switch {
		case err == nil:
		case ctx.Err() != nil:
			return err
		case errors.As(err, &l) && lost == nil:
			lost = l
		case !errors.As(err, &l) && first == nil:
			first = err
		default:
			e.note("%v", err)
		}
	}
	if first != nil {
		if lost != nil {
			e.note("%v", lost)
		}
		return first
	}
	if lost != nil {
		return lost
	}
	return nil
}

// finish takes a vault's persisted transition, if any, to the chain: it is
// sent (again, the same bytes, when a previous run stopped), its proof
// awaited, and once mined in the publisher's own headers it joins the
// chain and is published. One that loses its predecessor to another
// transaction is discarded (spec section 8.4), unless the transaction that
// won carries byte for byte the same record: then it is the same
// transition, re-encoded, and is taken as it is (spec section 7.1).
func (e *Engine) finish(ctx context.Context, v *state.Vault) error {
	tr := v.Pending
	if tr == nil {
		return nil
	}
	var tx *transaction.Transaction
	if e.pending != nil && e.pending.txid == tr.Txid {
		tx = e.pending.tx
	} else {
		var err error
		if tx, err = funding.Rebuild(tr.RawHex, "", ""); err != nil {
			return fmt.Errorf("%s: %w", tr.What, err)
		}
	}
	payer := e.NewPayer()
	if mp, h, err := e.Legs.Asset.Proof(ctx, tr.Txid); err == nil {
		tx.MerklePath = mp
		return e.adopt(ctx, v, tr, tx, mp, h, payer)
	}
	if !tr.Submitted {
		if err := e.sources(ctx, tx); err != nil {
			return fmt.Errorf("%s: %w (it is persisted; the next command sends it again)", tr.What, err)
		}
		e.note("%s %s: settling via %s", tr.What, Short(tr.Txid), e.Legs.Settler.Name())
		if err := e.Legs.Settler.Submit(ctx, tx); err != nil && !alreadyKnown(err) {
			if why := e.refusal(ctx, tx, err); why != "" {
				return e.lostOrCopy(ctx, v, tr, why, payer)
			}
			return fmt.Errorf("%s: settle via %s: %w (it is persisted; the next command sends it again)", tr.What, e.Legs.Settler.Name(), err)
		}
		tr.Submitted = true
		if err := e.St.Save(); err != nil {
			return err
		}
	}
	mp, h, err := payer.Await(ctx, tr.What, tx)
	if err != nil {
		if errors.Is(err, producer.ErrRefused) {
			return e.lostOrCopy(ctx, v, tr, err.Error(), payer)
		}
		return fmt.Errorf("%s %s: %w (it is persisted; the next command waits again)", tr.What, Short(tr.Txid), err)
	}
	return e.adopt(ctx, v, tr, tx, mp, h, payer)
}

// lostOrCopy settles a transition the network will not mine: the
// predecessor's spender is read from the node; a mined spender carrying
// the same record is this transition re-encoded and is adopted; anything
// else won, and this one is discarded.
func (e *Engine) lostOrCopy(ctx context.Context, v *state.Vault, tr *state.Transition, why string, payer *producer.Payer) error {
	by, err := e.Legs.Asset.Spender(ctx, tr.Parent, tr.ParentVout)
	if err != nil {
		return fmt.Errorf("%s: refused (%s), and the node could not say what spends its predecessor: %w (the next command looks again)", tr.What, why, err)
	}
	if by != "" && by != tr.Txid {
		// Another transaction spends the predecessor. Whether it won, or is
		// this transition re-encoded, is settled only by reading it: a node
		// that cannot show it settles nothing, and the transition is kept.
		raw, err := e.Legs.Asset.TxRaw(ctx, by)
		if err != nil {
			return fmt.Errorf("%s: its predecessor is spent by %s, which the node could not show (%v): whether that is this transition under another txid is not known yet; it is kept, and the next command looks again", tr.What, Short(by), err)
		}
		other, err := guard.ParseTransaction(raw, guard.DefaultBound)
		if err != nil || other.TxID().String() != by {
			return fmt.Errorf("%s: its predecessor is spent by %s, and the node answered other bytes for it; it is kept, and the next command looks again", tr.What, Short(by))
		}
		if t, err := secrec.ReadToken(other); err == nil && hex.EncodeToString(t.Record) == tr.Record {
			mp, h, perr := e.Legs.Asset.Proof(ctx, by)
			if perr != nil {
				return fmt.Errorf("%s: a copy of it, %s, spends its predecessor and has not mined yet (the next command looks again)", tr.What, Short(by))
			}
			e.note("%s: a copy with another txid, %s, carrying the same record, was mined in its place: the same transition", tr.What, Short(by))
			other.MerklePath = mp
			tr.Vout = t.Vout
			return e.adopt(ctx, v, tr, other, mp, h, payer)
		}
	}
	feeLost := false
	if by == "" || by == tr.Txid {
		// The predecessor is unspent, or spent by this very transaction
		// (the node took it, and it has not mined yet): no transition beat
		// this one, whatever a leg answered. Only if its fee coin is spent
		// by ANOTHER transaction can these bytes never mine: the
		// transition is then discarded like a lost one, and built again.
		// Anything else keeps it persisted, to be sent and waited for
		// again.
		kept := fmt.Errorf("%s %s: refused (%s), and its predecessor is not spent by another transaction: it is kept, and the next command sends it and waits again", tr.What, Short(tr.Txid), why)
		f := tr.Fee
		if f == nil {
			return kept
		}
		spent, err := e.Legs.Asset.Spender(ctx, f.TxID, f.Vout)
		if err != nil || spent == "" || spent == tr.Txid {
			return kept
		}
		by, feeLost = spent, true
	}
	v.Pending = nil
	if f := tr.Fee; f != nil {
		if spent, err := e.Legs.Asset.Spender(ctx, f.TxID, f.Vout); err == nil && spent == "" {
			_ = e.Pool.Return(*f)
		}
	}
	if tr.Seq == 0 && len(v.Tokens) == 0 {
		id := v.ID
		for i := range e.St.Vaults {
			if e.St.Vaults[i].ID == id {
				e.St.Vaults = append(e.St.Vaults[:i], e.St.Vaults[i+1:]...)
				break
			}
		}
	}
	if err := e.St.Save(); err != nil {
		return err
	}
	e.pending = nil
	return &LostError{What: tr.What, Txid: tr.Txid, By: by, Fee: feeLost}
}

// adopt joins a mined transition to its vault's chain, marks what it
// listed and ended, and publishes it.
func (e *Engine) adopt(ctx context.Context, v *state.Vault, tr *state.Transition, tx *transaction.Transaction, mp *transaction.MerklePath, h uint32, payer *producer.Payer) error {
	payer.Change(tx, h, mp)
	tok := state.Token{Seq: tr.Seq, Txid: tx.TxID().String(), RawHex: tx.Hex(), BumpHex: mp.Hex(), Height: h, Record: tr.Record,
		Vout: tr.Vout, Parent: tr.Parent}
	raw, err := hex.DecodeString(tr.Record)
	if err != nil {
		return err
	}
	rec, err := secrec.DecodeVault(raw)
	if err != nil {
		return err
	}
	v.Tokens = append(v.Tokens, tok)
	Mark(e.St, v, rec)
	v.Pending = nil
	e.pending = nil
	if err := e.St.Save(); err != nil {
		return err
	}
	return e.publishToken(ctx, v, tok.Txid)
}

// Mark records in the home what a mined token of the vault did: the
// versions it listed are listed and their commitments recorded, and the
// versions it replaced or retired are ended.
func Mark(st *state.State, v *state.Vault, rec *secrec.Vault) {
	end := func(id string, below uint64, all bool) {
		for i := range v.Versions {
			x := &v.Versions[i]
			if x.ID == id && x.Listed && (all || x.Version < below) {
				x.Ended = true
			}
		}
	}
	for _, id := range rec.Retire {
		end(hex.EncodeToString(id[:]), 0, true)
	}
	for _, l := range [][]secrec.Entry{rec.Create, rec.Update} {
		for _, en := range l {
			id, cid := hex.EncodeToString(en.ID[:]), hex.EncodeToString(en.ContentID[:])
			st.Commit(hex.EncodeToString(en.Commitment[:]))
			end(id, en.Version, false)
			x := v.VersionOf(id, cid)
			if x == nil {
				v.Versions = append(v.Versions, state.SecretVersion{ID: id, Version: en.Version, ContentID: cid,
					Commitment: hex.EncodeToString(en.Commitment[:]), Epoch: rec.Epoch, Created: rec.Created})
				x = &v.Versions[len(v.Versions)-1]
			}
			x.Listed, x.Seq, x.Ended = true, rec.Seq, false
		}
	}
}

// tokenRef finds a token of a vault's chain.
func tokenRef(v *state.Vault, txid string) (*state.Token, error) {
	for i := range v.Tokens {
		if v.Tokens[i].Txid == txid {
			return &v.Tokens[i], nil
		}
	}
	return nil, fmt.Errorf("token %s is not in the home", txid)
}

// inHeaders waits, up to Opts.Wait, until tx's proof verifies against the
// publisher's own headers: a mined object is published only once its block
// is in them (spec section 8.3).
func (e *Engine) inHeaders(ctx context.Context, what string, tx *transaction.Transaction) error {
	deadline := time.Now().Add(e.Opts.Wait)
	for {
		if secrec.IsMined(ctx, tx, e.Legs.Headers) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s %s: its block is not in the header source's chain yet; it is kept and the next command publishes it", what, Short(tx.TxID().String()))
		}
		poll := e.Opts.Poll
		if poll <= 0 {
			poll = producer.DefaultPoll
		}
		if err := e.Sleep(ctx, poll); err != nil {
			return err
		}
	}
}

// TokenBEEF assembles the BEEF a host admits a token in: the token and its
// parent, each with its minimal proof, held to the host's rules for crypt
// against headers.
func TokenBEEF(ctx context.Context, crypt string, token, parent *transaction.Transaction, headers chaintracker.ChainTracker) ([]byte, error) {
	tc, pc := token.ShallowClone(), parent.ShallowClone()
	var err error
	if tc.MerklePath, err = Minimal(token.MerklePath, token.TxID()); err != nil {
		return nil, err
	}
	if pc.MerklePath, err = Minimal(parent.MerklePath, parent.TxID()); err != nil {
		return nil, err
	}
	beef, err := secrec.TokenBEEF(tc, pc)
	if err != nil {
		return nil, err
	}
	a, err := secrec.Admit(ctx, beef, nil, secrec.Host{Crypt: crypt, Headers: headers})
	if err != nil {
		return nil, fmt.Errorf("the token's BEEF breaks the host's rules (%s): %w", secrec.Reason(err), err)
	}
	if a.Kind != secrec.TxVaultToken {
		return nil, fmt.Errorf("the token would be admitted as a %s", a.Kind)
	}
	return beef, nil
}

// publishToken publishes a mined token of the home's own, after the
// propagation delay, in the BEEF a host admits: the token and its parent,
// each with its minimal proof. It is held to the host's rules first.
func (e *Engine) publishToken(ctx context.Context, v *state.Vault, txid string) error {
	t, err := tokenRef(v, txid)
	if err != nil {
		return err
	}
	// A token just mined waits for its block to reach the header source;
	// one whose kept proof a reorganisation left stale takes the node's
	// current proof.
	tx, err := e.tokenTx(ctx, t)
	if err != nil {
		if tx, err = rebuild(t); err != nil {
			return err
		}
		if err := e.inHeaders(ctx, state.KindToken, tx); err != nil {
			return err
		}
	}
	parent, err := e.parentTx(ctx, v, t)
	if err != nil {
		return fmt.Errorf("token %s: its parent %s: %w", Short(txid), Short(t.Parent), err)
	}
	beef, err := TokenBEEF(ctx, v.Crypt, tx, parent, e.Legs.Headers)
	if err != nil {
		return fmt.Errorf("token %s is not published: %w", Short(txid), err)
	}
	if len(beef) > e.Opts.ObjectBound {
		return fmt.Errorf("token %s: its BEEF is %d bytes, over the object bound of %d", Short(txid), len(beef), e.Opts.ObjectBound)
	}
	p := state.Pending{Kind: state.KindToken, Crypt: v.Crypt, Txid: txid, Beef: hex.EncodeToString(beef), Org: e.orgHex(), Vault: v.ID, Seq: t.Seq,
		NotBefore: e.Now().Add(e.Opts.Delay).Unix()}
	return e.queue(ctx, p)
}

// parentTx is the transaction a token's predecessor input spends, under a
// proof that verifies against the publisher's headers: the token before it
// in the vault, or at seq 0 the chain tree.
func (e *Engine) parentTx(ctx context.Context, v *state.Vault, t *state.Token) (*transaction.Transaction, error) {
	for i := range v.Tokens {
		if v.Tokens[i].Txid == t.Parent {
			return e.tokenTx(ctx, &v.Tokens[i])
		}
	}
	return e.treeTx(ctx, t.Parent)
}

// Owed publishes what the home owes its crypts: a token of its own vaults
// mined and not yet published.
func (e *Engine) Owed(ctx context.Context) error {
	var first error
	for vi := range e.St.Vaults {
		v := &e.St.Vaults[vi]
		for i := range v.Tokens {
			t := &v.Tokens[i]
			if !t.Published && !e.St.Queued(t.Txid, v.Crypt) {
				if err := e.publishToken(ctx, v, t.Txid); err != nil {
					if ctx.Err() != nil {
						return err
					}
					if first == nil {
						first = err
					} else {
						e.note("%v", err)
					}
					// A later token of this vault is published only after
					// this one.
					break
				}
			}
		}
	}
	return first
}

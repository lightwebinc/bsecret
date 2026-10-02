package vread

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
	"github.com/lightwebinc/bcommon/lookup"
	"github.com/lightwebinc/bcommon/nodeapi"

	"github.com/lightwebinc/bsecret/internal/limits"
	"github.com/lightwebinc/bsecret/internal/secrec"
)

// ChainView is one vault's chain as a reader established it from every host
// it asked (spec section 14): the canonical chain, which descends by spends
// from the vault's first token, each token verified against the reader's
// headers, held to the transition rules and folded, and how each host's
// answers compare with it.
type ChainView struct {
	Crypt string
	Org   []byte
	Vault [32]byte
	// Tokens are the canonical chain, seq 0 to the latest.
	Tokens []*Tok
	// Statuses are the fold's status of each token (spec section 11.2).
	Statuses []string
	// HostLatest is the highest seq each host answered to the vault class;
	// HostErr the hosts that could not be asked.
	HostLatest map[string]uint64
	HostErr    map[string]error
	// Lacks are, per host that answered, the canonical seqs it did not
	// answer: a host behind, or withholding.
	Lacks map[string][]uint64
	// Refused are answered tokens that did not verify.
	Refused []Refusal
	// Forks are tokens that verified at a seq of the canonical chain but do
	// not continue it.
	Forks []*Tok

	fold *secrec.VaultFold
	// reused are the content ids of versions a commitment-reuse token
	// listed under a commitment an earlier token of the vault listed; seen
	// every commitment a token of the chain listed.
	reused map[[32]byte]bool
	seen   map[[32]byte]bool
}

// Latest is the canonical chain's last token, or nil.
func (v *ChainView) Latest() *Tok {
	if len(v.Tokens) == 0 {
		return nil
	}
	return v.Tokens[len(v.Tokens)-1]
}

// Usable is how many tokens from seq 0 fold without a mismatch: a reader
// fails closed from the first mismatched token on.
func (v *ChainView) Usable() int {
	for i, s := range v.Statuses {
		if s == secrec.StatusSetMismatch || s == secrec.StatusStaleMismatch {
			return i
		}
	}
	return len(v.Tokens)
}

// Broken reports the status that ended the chain's use, or "".
func (v *ChainView) Broken() string {
	if u := v.Usable(); u < len(v.Tokens) {
		return v.Statuses[u]
	}
	return ""
}

// Head is the last usable token: the one whose set a reader takes.
func (v *ChainView) Head() *Tok {
	if u := v.Usable(); u > 0 {
		return v.Tokens[u-1]
	}
	return nil
}

// Agree reports whether every host that answered holds the whole canonical
// chain.
func (v *ChainView) Agree() bool {
	for _, l := range v.Lacks {
		if len(l) > 0 {
			return false
		}
	}
	return true
}

// Set is the current set after the last usable token, ascending by id.
func (v *ChainView) Set() []secrec.Current { return v.fold.Set() }

// Fold is the fold of the usable chain: a writer tries its next transition
// on a clone of it before it signs.
func (v *ChainView) Fold() *secrec.VaultFold { return v.fold.Clone() }

// Trail is every event of the usable chain, in order.
func (v *ChainView) Trail() []secrec.Event { return v.fold.Trail() }

// Current is the version of id the set holds, when it holds one.
func (v *ChainView) Current(id [32]byte) (secrec.Current, bool) {
	for _, c := range v.fold.Set() {
		if c.ID == id {
			return c, true
		}
	}
	return secrec.Current{}, false
}

// Reused reports whether the version with this content id was listed under
// a commitment an earlier token of the vault listed (commitment-reuse): a
// reader refuses it, since its key is one an earlier version's readers
// hold.
func (v *ChainView) Reused(contentID [32]byte) bool { return v.reused[contentID] }

// ErrNoChain is a vault no host answered.
var ErrNoChain = errors.New("vread: no host answers this vault")

// VaultHex is a vault identifier as a question writes it.
func VaultHex(v [32]byte) string { return hex.EncodeToString(v[:]) }

func (v *ChainView) base() Query {
	return Query{"crypt": v.Crypt, "org": hex.EncodeToString(v.Org), "vault": VaultHex(v.Vault)}
}

func with(q Query, k, val string) Query {
	out := Query{}
	for a, b := range q {
		out[a] = b
	}
	out[k] = val
	return out
}

// Chain establishes a vault's chain. Every host is asked the vault class;
// then every seq from 0 to the highest any host answered is asked of every
// host, so the reader walks the chain from seq 0 itself: the first token by
// the outpoint its vault identifier hashes, every later one by its spend of
// the token before it and the transition rules, each folded as it goes.
//
// known is the chain this reader verified before, from seq 0 (Remembered):
// the walk then starts from the token it remembers (spec section 14), and
// the hosts are asked only the seqs above it. A host that answers a latest
// token below the remembered one is answering an older state; the caller
// refuses that (rollback).
func (c *Client) Chain(ctx context.Context, crypt string, org []byte, vault [32]byte, known ...*Tok) (*ChainView, error) {
	if c.Headers == nil {
		return nil, ErrNoHeaders
	}
	if len(c.Hosts) == 0 {
		return nil, ErrNoHosts
	}
	v := &ChainView{Crypt: crypt, Org: org, Vault: vault, HostLatest: map[string]uint64{}, HostErr: map[string]error{},
		Lacks: map[string][]uint64{}, fold: secrec.NewVaultFold(), reused: map[[32]byte]bool{}}
	verify := func(h string, o lookup.Output, seq *uint64) *Tok {
		t, err := c.Token(ctx, o.Beef, crypt, org, &vault)
		if err == nil && seq != nil && t.Seq() != *seq {
			err = errors.New("vread: the token is not of the seq asked")
		}
		if err != nil {
			v.Refused = append(v.Refused, Refusal{Host: h, Txid: SubjectID(o.Beef), Reason: secrec.Reason(err), Err: err})
			return nil
		}
		return t
	}
	// top is the highest seq any host claimed as the vault's latest. It
	// ends the walk early; it never sizes anything, and a walk never gets
	// to a seq whose predecessor is not on the chain.
	var top uint64
	found := len(known) > 0
	if found {
		top = known[len(known)-1].Seq()
	}
	for _, h := range c.Hosts {
		outs, err := c.Ask(ctx, h, v.base())
		if err != nil {
			v.HostErr[h] = err
			continue
		}
		v.HostLatest[h] = 0
		for _, o := range capOutputs(outs, seqAnswers) {
			t := verify(h, o, nil)
			if t == nil {
				continue
			}
			found = true
			if t.Seq() >= v.HostLatest[h] {
				v.HostLatest[h] = t.Seq()
			}
			if t.Seq() > top {
				top = t.Seq()
			}
		}
	}
	if !found {
		if len(v.HostErr) == len(c.Hosts) {
			return v, fmt.Errorf("%w: every host failed (%v)", ErrNoChain, firstErr(v.HostErr))
		}
		return v, ErrNoChain
	}
	// The chain is walked seq by seq, and a seq is asked for only once the
	// one before it is on the chain: a token is taken only as the spend of
	// the token before it, so the work is bounded by the chain itself and
	// never by a seq a host, or an owner's stray token, names.
	for _, t := range known {
		if !v.extend([]*Tok{t}) {
			// What was kept does not link: walk from the first token.
			v.Tokens, v.Statuses, v.Forks = nil, nil, nil
			v.fold, v.reused, v.seen = secrec.NewVaultFold(), map[[32]byte]bool{}, nil
			break
		}
	}
	from := uint64(len(v.Tokens))
	live := map[string]bool{}
	for _, h := range c.Hosts {
		live[h] = v.HostErr[h] == nil
	}
	for s := from; s <= top; s++ {
		var cands []*Tok
		holds := map[string]map[string]bool{}
		asked := false
		for _, h := range c.Hosts {
			if !live[h] {
				continue
			}
			outs, err := c.Ask(ctx, h, with(v.base(), "seq", Seq(s)))
			if err != nil {
				v.HostErr[h], live[h] = err, false
				continue
			}
			asked = true
			holds[h] = map[string]bool{}
			for _, o := range capOutputs(outs, seqAnswers) {
				t := verify(h, o, &s)
				if t == nil {
					continue
				}
				holds[h][t.Txid] = true
				dup := false
				for _, x := range cands {
					dup = dup || x.Txid == t.Txid
				}
				if !dup {
					cands = append(cands, t)
				}
			}
		}
		if !asked || !v.extend(cands) {
			v.Forks = append(v.Forks, cands...)
			break
		}
		last := v.Tokens[len(v.Tokens)-1]
		for h, set := range holds {
			if !set[last.Txid] {
				v.Lacks[h] = append(v.Lacks[h], s)
			}
		}
	}
	if len(v.Tokens) == 0 {
		return v, fmt.Errorf("%w: no first token verifies", ErrNoChain)
	}
	return v, nil
}

// seqAnswers is the most outputs taken from one answer to a seq: a host
// keeps at most 8 tokens a seq, and what a hostile one adds is not read.
const seqAnswers = 16

// capOutputs is at most n of a host's answered outputs.
func capOutputs(outs []lookup.Output, n int) []lookup.Output {
	if len(outs) > n {
		return outs[:n]
	}
	return outs
}

// Memory is what became of the chain a reader kept.
type Memory int

// What Remembered found.
const (
	// MemoryNone: the reader kept nothing.
	MemoryNone Memory = iota
	// MemoryHeld: the chain kept is returned; its last token is mined in
	// the reader's headers.
	MemoryHeld
	// MemoryUnknown: whether the last token is still mined could not be
	// settled (the header source failed, or its stored proof does not
	// verify and no chain source could give a current one). Nothing is
	// forgotten on that: the reader walks the chain again, and what it
	// verified before stays its floor.
	MemoryUnknown
	// MemoryDisplaced: the last token's stored proof does not verify and
	// the chain source says the transaction is not mined: a reorganisation
	// displaced it. The reader forgets it and reads the chain again (spec
	// section 14).
	MemoryDisplaced
	// MemoryCorrupt: what was kept does not read back as the vault's
	// chain. The copy is dropped; the floor is not.
	MemoryCorrupt
)

// Remembered rebuilds the chain a reader verified before from the tokens it
// kept, each as a host answered it (Tok.Beef), in seq order from 0. Every
// token is read again as a well-formed token of the vault, and the last
// one's proof must verify against the reader's headers. When the stored
// proof no longer does, the chain source is asked for the transaction's
// current proof (spec section 14): one that verifies replaces the stored
// one; only the source's word that the transaction is not mined is a
// reorganisation. A header source or chain source that fails proves
// nothing, and nothing is forgotten on its account: forgetting would let a
// host that rolled the vault back be believed by a reader whose header
// source blinked. The tokens before the last are held to it by spends when
// the chain is walked, and a transaction a mined one spends is mined.
func Remembered(ctx context.Context, beefs [][]byte, crypt string, org []byte, vault [32]byte, headers chaintracker.ChainTracker, source ChainSource) ([]*Tok, Memory) {
	if len(beefs) == 0 {
		return nil, MemoryNone
	}
	var out []*Tok
	for i, b := range beefs {
		if len(b) > limits.MaxBEEF {
			return nil, MemoryCorrupt
		}
		tx, tok, err := secrec.StoredToken(b)
		if err != nil || tok.Vault.Crypt != crypt || !bytes.Equal(tok.Vault.Org, org) || tok.Vault.Vault != vault || tok.Vault.Seq != uint64(i) || tx.MerklePath == nil {
			return nil, MemoryCorrupt
		}
		t := &Tok{Txid: tx.TxID().String(), Tx: tx, Token: tok, Beef: b}
		t.place()
		out = append(out, t)
	}
	last := out[len(out)-1]
	if headers == nil {
		return nil, MemoryUnknown
	}
	ok, err := last.Tx.MerklePath.Verify(ctx, last.Tx.TxID(), headers)
	switch {
	case err != nil:
		return nil, MemoryUnknown
	case ok:
		return out, MemoryHeld
	case source == nil:
		return nil, MemoryUnknown
	}
	mp, err := source.MerkleProof(ctx, last.Txid)
	switch {
	case errors.Is(err, nodeapi.ErrNotMined):
		return nil, MemoryDisplaced
	case err != nil || mp == nil:
		return nil, MemoryUnknown
	}
	if ok, err := mp.Verify(ctx, last.Tx.TxID(), headers); err != nil || !ok {
		return nil, MemoryUnknown
	}
	// Mined again elsewhere: the same transaction under its current proof.
	last.Tx.MerklePath = mp
	beef, err := last.Tx.AtomicBEEF(false)
	if err != nil {
		return nil, MemoryUnknown
	}
	last.Beef = beef
	last.place()
	return out, MemoryHeld
}

// place sets the token's height and position from its proof.
func (t *Tok) place() {
	t.Height, t.Pos = t.Tx.MerklePath.BlockHeight, 0
	if len(t.Tx.MerklePath.Path) == 0 {
		return
	}
	for _, l := range t.Tx.MerklePath.Path[0] {
		if l.Hash != nil && *l.Hash == *t.Tx.TxID() {
			t.Pos = l.Offset
		}
	}
}

// FromTokens establishes a chain from tokens a reader was handed (the audit
// class's answer, or a trail from any source), each already verified. It
// is walked from seq 0 by spends; a token at a seq the walk never reaches
// is a fork, whatever seq it names.
func FromTokens(crypt string, org []byte, vault [32]byte, toks []*Tok) (*ChainView, error) {
	v := &ChainView{Crypt: crypt, Org: org, Vault: vault, HostLatest: map[string]uint64{}, HostErr: map[string]error{},
		Lacks: map[string][]uint64{}, fold: secrec.NewVaultFold(), reused: map[[32]byte]bool{}}
	by := map[uint64][]*Tok{}
	for _, t := range toks {
		by[t.Seq()] = append(by[t.Seq()], t)
	}
	for s := uint64(0); ; s++ {
		cands := by[s]
		delete(by, s)
		if !v.extend(cands) {
			v.Forks = append(v.Forks, cands...)
			break
		}
	}
	for _, rest := range by {
		v.Forks = append(v.Forks, rest...)
	}
	if len(v.Tokens) == 0 {
		return v, fmt.Errorf("%w: no first token verifies", ErrNoChain)
	}
	return v, nil
}

// extend takes the chain's next token from the candidates at the next seq:
// at seq 0 the first-mined token whose input's outpoint hashes to the vault
// identifier, afterwards the first-mined token that spends the token before
// it under the transition rules. It folds the token it takes, and reports
// false, taking nothing, when no candidate continues the chain.
func (v *ChainView) extend(cands []*Tok) bool {
	s := uint64(len(v.Tokens))
	var best *Tok
	for _, t := range cands {
		if t.Seq() != s {
			continue
		}
		if s == 0 {
			if _, _, err := secrec.CheckFirstToken(t.Tx); err != nil {
				continue
			}
		} else {
			prev := v.Tokens[s-1]
			if _, err := secrec.CheckNextToken(prev.Tx, prev.Token, t.Tx); err != nil {
				continue
			}
		}
		if best == nil || t.Before(best) {
			best = t
		}
	}
	if best == nil {
		return false
	}
	for _, t := range cands {
		if t != best {
			v.Forks = append(v.Forks, t)
		}
	}
	v.Tokens = append(v.Tokens, best)
	st := v.fold.Apply(best.Token.Vault)
	v.Statuses = append(v.Statuses, st)
	rec := best.Token.Vault
	if st == secrec.StatusConsistent || st == secrec.StatusCommitmentReuse {
		if v.seen == nil {
			v.seen = map[[32]byte]bool{}
		}
		for _, l := range [][]secrec.Entry{rec.Create, rec.Update} {
			for _, e := range l {
				if v.seen[e.Commitment] {
					v.reused[e.ContentID] = true
				}
				v.seen[e.Commitment] = true
			}
		}
	}
	return true
}

// Commitments are every commitment a usable token of the chain listed.
func (v *ChainView) Commitments() [][32]byte {
	var out [][32]byte
	for _, t := range v.Tokens[:v.Usable()] {
		for _, l := range [][]secrec.Entry{t.Token.Vault.Create, t.Token.Vault.Update} {
			for _, e := range l {
				out = append(out, e.Commitment)
			}
		}
	}
	return out
}

// Vaults asks every host the vaults class for org (all pages) and returns,
// by identifier, the latest verified token each host answered for each of
// org's vaults. A host's answer here is a claim about which vaults exist
// and which token is latest, never evidence of descent: a reader that
// uses a vault walks its chain (Chain).
func (c *Client) Vaults(ctx context.Context, crypt string, org []byte) (map[[32]byte]*Tok, map[string]error) {
	q := Query{"crypt": crypt, "vaultsOf": hex.EncodeToString(org)}
	out := map[[32]byte]*Tok{}
	errs := map[string]error{}
	cursor := func(o lookup.Output) string {
		_, t, err := secrec.StoredToken(o.Beef)
		if err != nil {
			return ""
		}
		return VaultHex(t.Vault.Vault)
	}
	for _, h := range c.Hosts {
		ho := c.Pages(ctx, h, q, cursor, func(a, b string) bool { return a < b })
		if ho.Err != nil {
			errs[h] = ho.Err
			continue
		}
		for _, o := range ho.Outputs {
			t, err := c.Token(ctx, o.Beef, crypt, org, nil)
			if err != nil {
				continue
			}
			id := t.Token.Vault.Vault
			if old := out[id]; old == nil || t.Seq() > old.Seq() {
				out[id] = t
			}
		}
	}
	return out, errs
}

// Txid is a hash in display order.
func Txid(h [32]byte) string { return chainhash.Hash(h).String() }

func (r *Refusal) Error() string { return "an answered output does not verify: " + r.Err.Error() }

// Trail reads a vault's whole chain through the audit class, page after
// page: q is the first question, ask asks one (at a price, when the host
// prices the class) and verify checks one answered token. A page never
// splits a seq and a seq holds at most 8 tokens, so a page of fewer than
// 57 tokens is the last, and no further page is asked or paid for. A token
// that does not verify ends the walk with a *Refusal.
func Trail(q Query, ask func(Query) ([]lookup.Output, error), verify func(beef []byte) (*Tok, error)) ([]*Tok, error) {
	page := Query{}
	for k, v := range q {
		page[k] = v
	}
	var toks []*Tok
	seen := map[string]bool{}
	for n := 0; n < limits.MaxPages; n++ {
		outs, err := ask(page)
		if err != nil {
			return nil, err
		}
		var top uint64
		grew := false
		for _, o := range outs {
			tok, err := verify(o.Beef)
			if err != nil {
				return nil, &Refusal{Txid: SubjectID(o.Beef), Reason: secrec.Reason(err), Err: err}
			}
			if tok.Seq() > top {
				top = tok.Seq()
			}
			if !seen[tok.Txid] {
				seen[tok.Txid], grew = true, true
				toks = append(toks, tok)
			}
		}
		if !grew || len(outs) <= limits.TokenPage-8 {
			break
		}
		page["after"] = Seq(top)
	}
	return toks, nil
}

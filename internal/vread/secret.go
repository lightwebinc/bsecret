package vread

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/lightwebinc/bcommon/guard"
	"github.com/lightwebinc/bcommon/lookup"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// Failure is a reader's check that failed (docs/spec.md section 7.2): its
// label, which names the culprit, and what was found.
type Failure struct {
	// Label is listing, successor, retracted, hash, undecryptable,
	// commitment, tag, payload or rollback.
	Label string
	Err   error
}

func (f *Failure) Error() string { return f.Label + ": " + f.Err.Error() }
func (f *Failure) Unwrap() error { return f.Err }

func failed(label, format string, args ...any) *Failure {
	return &Failure{Label: label, Err: fmt.Errorf(format, args...)}
}

// The labels beside secrec's own.
const (
	LabelRetracted = "retracted"
	LabelRollback  = "rollback"
)

// ErrUnavailable is a ciphertext no configured source holds: nothing names
// a store that serves none (spec section 18).
var ErrUnavailable = errors.New("vread: no content source holds the ciphertext")

func (v *ChainView) secretQuery(id [32]byte) Query {
	return with(v.base(), "secret", hex.EncodeToString(id[:]))
}

// carriers verifies the outputs one host answered as secret carriers of
// the vault, keeping each once.
func (c *Client) carriers(ctx context.Context, v *ChainView, host string, outs []lookup.Output, seen map[string]*Car, refused *[]Refusal) {
	for _, o := range outs {
		car, err := VerifyCarrier(ctx, o.Beef, v.Crypt, c.Headers)
		if err == nil {
			s := car.Carrier.Secret
			if hex.EncodeToString(s.Org) != hex.EncodeToString(v.Org) || s.Vault != v.Vault {
				err = errors.New("vread: the record is of another owner or vault")
			}
		}
		if err != nil {
			*refused = append(*refused, Refusal{Host: host, Txid: SubjectID(o.Beef), Reason: secrec.Reason(err), Err: err})
			continue
		}
		if old := seen[car.Txid]; old != nil {
			if len(old.Context) == 0 {
				old.Context = o.Context
			}
			continue
		}
		car.Context, car.Host = o.Context, host
		seen[car.Txid] = car
	}
}

func sorted(seen map[string]*Car) []*Car {
	out := make([]*Car, 0, len(seen))
	for _, c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Carrier.Secret, out[j].Carrier.Secret
		if a.ID != b.ID {
			return hex.EncodeToString(a.ID[:]) < hex.EncodeToString(b.ID[:])
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return out[i].Txid < out[j].Txid
	})
	return out
}

// Secret asks every host the secret class for id and returns the carriers
// that verified, each once, with the hosts that could not be asked.
func (c *Client) Secret(ctx context.Context, v *ChainView, id [32]byte) ([]*Car, []Refusal, map[string]error) {
	return c.class(ctx, v, v.secretQuery(id))
}

// Version asks every host the version class for version n of id.
func (c *Client) Version(ctx context.Context, v *ChainView, id [32]byte, n uint64) ([]*Car, []Refusal, map[string]error) {
	return c.class(ctx, v, with(v.secretQuery(id), "version", Seq(n)))
}

// Pending asks every host the pending class for id: the carriers held for
// versions above the one the set holds.
func (c *Client) Pending(ctx context.Context, v *ChainView, id [32]byte) ([]*Car, []Refusal, map[string]error) {
	return c.class(ctx, v, with(v.base(), "pending", hex.EncodeToString(id[:])))
}

func (c *Client) class(ctx context.Context, v *ChainView, q Query) ([]*Car, []Refusal, map[string]error) {
	seen := map[string]*Car{}
	var refused []Refusal
	errs := map[string]error{}
	for _, h := range c.Hosts {
		outs, err := c.Ask(ctx, h, q)
		if err != nil {
			errs[h] = err
			continue
		}
		c.carriers(ctx, v, h, outs, seen, &refused)
	}
	return sorted(seen), refused, errs
}

// SetAnswer is the set as one host answered it.
type SetAnswer struct {
	Host string
	// Cars are the carriers that verified.
	Cars []*Car
	// Matches is set when the host answered a carrier for every version
	// the set holds and no other: the set's root is reproduced from its
	// answer.
	Matches   bool
	Refused   []Refusal
	Err       error
	Truncated bool
}

// Secrets asks every host the secrets class (all pages) and compares what
// each answered with the set the reader folded: a host whose answer does
// not reproduce the root withheld or added a record (spec section 14).
func (c *Client) Secrets(ctx context.Context, v *ChainView) []SetAnswer {
	q := Query{"crypt": v.Crypt, "org": hex.EncodeToString(v.Org), "secretsOf": VaultHex(v.Vault)}
	cursor := func(o lookup.Output) string {
		car, err := VerifyCarrier(ctx, o.Beef, v.Crypt, c.Headers)
		if err != nil {
			return ""
		}
		return hex.EncodeToString(car.Carrier.Secret.ID[:])
	}
	var out []SetAnswer
	for _, h := range c.Hosts {
		ho := c.Pages(ctx, h, q, cursor, func(a, b string) bool { return a < b })
		sa := SetAnswer{Host: h, Err: ho.Err, Truncated: ho.Truncated}
		seen := map[string]*Car{}
		c.carriers(ctx, v, h, ho.Outputs, seen, &sa.Refused)
		sa.Cars = sorted(seen)
		var answered []secrec.Current
		ids := map[[32]byte]bool{}
		for _, car := range sa.Cars {
			s := car.Carrier.Secret
			if !ids[s.ID] {
				ids[s.ID] = true
				answered = append(answered, secrec.Current{ID: s.ID, Version: s.Version, ContentID: car.Carrier.ContentID})
			}
		}
		sa.Matches = sa.Err == nil && !sa.Truncated && secrec.SetRoot(answered) == secrec.SetRoot(v.Set())
		out = append(out, sa)
	}
	return out
}

// Listed is a reader's check 0 on a carrier a host answered for the set
// (spec section 7.2), made against the chain the reader folded: the set of
// the last usable token holds the record's identifier at its version and
// content id; the token that listed it lists its commitment, names the
// record's crypt, owner, vault and group and one of the vault's labels, and
// is of the record's epoch and epoch id; and no earlier token listed the
// commitment. An inclusion path the host answered is checked too when it
// names the token the reader holds, and a path that does not verify is
// reported and otherwise ignored: the fold is the stronger check.
func (v *ChainView) Listed(car *Car) (pathOK bool, err error) {
	rec := car.Carrier.Secret
	cur, ok := v.Current(rec.ID)
	if !ok {
		return false, failed("listing", "the vault's set holds no secret %s", Short(hex.EncodeToString(rec.ID[:])))
	}
	if cur.Version != rec.Version || cur.ContentID != car.Carrier.ContentID {
		return false, failed("listing", "the set holds version %d of the secret, and the host answered version %d (or another record at that version)", cur.Version, rec.Version)
	}
	tok := v.Tokens[cur.Seq]
	if err := secrec.CheckListed(tok.Token.Vault, rec); err != nil {
		return false, failed("listing", "the token at seq %d does not list this record as it is: the owner listed under one epoch a record keyed under another, or with another commitment", cur.Seq)
	}
	if v.Reused(car.Carrier.ContentID) {
		return false, failed("listing", "the version's commitment is one an earlier token of the vault listed (commitment-reuse): its key is one an earlier version's readers hold")
	}
	if len(car.Context) > 0 {
		head := v.Head()
		if ic, err := secrec.DecodeContext(car.Context); err == nil && ic.Seq == head.Seq() && ic.Token == head.Hash() {
			pathOK = secrec.CheckInSet(head.Token.Vault, head.Hash(), rec, ic) == nil
		}
	}
	return pathOK, nil
}

// Linked takes, for an interval vault, the highest version that links to
// the listed one successor by successor (spec section 4.4). links are the
// carriers held above the listed version. It returns the run, lowest
// version first, and whether a later version exists that does not link.
func (v *ChainView) Linked(listed *Car, links []*Car) ([]*Car, bool, error) {
	head := v.Head().Token.Vault
	if head.Anchor != secrec.AnchorInterval {
		return nil, len(links) > 0, nil
	}
	by := map[*secrec.Secret]*Car{}
	var recs []*secrec.Secret
	for _, l := range links {
		if l.Carrier.Secret.Version <= listed.Carrier.Secret.Version {
			continue
		}
		by[l.Carrier.Secret] = l
		recs = append(recs, l.Carrier.Secret)
	}
	run, err := secrec.CheckLinks(head, listed.Carrier.Secret, recs)
	if err != nil {
		return nil, false, &Failure{Label: "successor", Err: err}
	}
	var out []*Car
	seen := map[[32]byte]bool{}
	for _, c := range v.Commitments() {
		seen[c] = true
	}
	for _, r := range run {
		// A reader that folded the chain refuses a commitment any token
		// listed.
		if seen[r.Commitment] {
			return nil, false, failed("successor", "version %d repeats a commitment a token of the vault listed", r.Version)
		}
		out = append(out, by[r])
	}
	return out, len(recs) > len(run), nil
}

// Swept reports the mined transaction that spends op, when one is found by
// the sweep class at a host or by the chain source, and its proof verifies
// against the reader's headers: a reader must not use a record whose
// funding outpoint a mined sweep spends (spec section 14). Only a mined
// spend retracts: a spender with no proof that verifies does not count.
func (c *Client) Swept(ctx context.Context, crypt string, op transaction.Outpoint) (string, error) {
	q := Query{"crypt": crypt, "spent": op.String()}
	var lastErr error
	asked := 0
	for _, h := range c.Hosts {
		outs, err := c.Ask(ctx, h, q)
		if err != nil {
			lastErr = err
			continue
		}
		asked++
		for _, o := range outs {
			spent, txid, err := VerifySweep(ctx, o.Beef, crypt, c.Headers)
			if err != nil {
				continue
			}
			for _, s := range spent {
				if s == op {
					return txid, nil
				}
			}
		}
	}
	if c.Source != nil {
		if by, err := c.Source.Spender(ctx, op.Txid.String(), op.Index); err == nil && by != "" && c.minedSpend(ctx, by, op) {
			return by, nil
		}
	}
	if asked == 0 && lastErr != nil {
		return "", lastErr
	}
	return "", nil
}

// minedSpend reports whether the chain source's transaction by spends op
// and its proof verifies against the reader's headers.
func (c *Client) minedSpend(ctx context.Context, by string, op transaction.Outpoint) bool {
	raw, err := c.Source.TxRaw(ctx, by)
	if err != nil {
		return false
	}
	tx, err := guard.ParseTransaction(raw, guard.DefaultBound)
	if err != nil || tx.TxID().String() != by {
		return false
	}
	spends := false
	for _, in := range tx.Inputs {
		spends = spends || (in.SourceTXID != nil && *in.SourceTXID == op.Txid && in.SourceTxOutIndex == op.Index)
	}
	if !spends {
		return false
	}
	mp, err := c.Source.MerkleProof(ctx, by)
	if err != nil || mp == nil {
		return false
	}
	ok, err := mp.Verify(ctx, tx.TxID(), c.Headers)
	return err == nil && ok
}

// Keys are what a reader opens a content key with.
type Keys struct {
	// Owner, when set, is the owner's wallet: the self wrap is opened
	// through it and no epoch key is needed (spec section 6.4).
	Owner wallet.Interface
	// Epoch returns the BRC-369 symmetric key of one epoch of the vault's
	// group, for a member that held it; an error when this reader holds no
	// key of that epoch.
	Epoch func(ctx context.Context, epoch uint64) ([32]byte, error)
}

// Content fetches a ciphertext that is not carried in its record, by its
// hash, bounded by the reader's budget and the record's length.
type Content interface {
	Get(ctx context.Context, hash [32]byte, length uint64) ([]byte, error)
}

// Reading is one version read.
type Reading struct {
	Car     *Car
	Payload *secrec.Payload
	// Anchored is set when a mined token of the vault lists the version;
	// an unanchored version was taken by its links in an interval vault.
	Anchored bool
	// Exposed is set when the version is keyed under an epoch before the
	// group's latest: someone the group has since removed, or a key it has
	// rotated away from, opens it.
	Exposed bool
	// PathOK is set when the host's inclusion path verified against the
	// token the reader holds.
	PathOK bool
}

// Open performs a reader's checks on one carrier in the signed order
// (spec section 7.2) and stops at the first failure, which names its own
// culprit: the listing (or, for an unanchored version, the links the
// caller verified), every epoch against the group's chain, and the
// retraction; the ciphertext's length and hash, before any wrap is opened;
// the wrap, under the key of the epoch the record names and no other, or
// the owner's self wrap; the commitment; every segment's tag; the payload
// and its name.
func (c *Client) Open(ctx context.Context, v *ChainView, g *Group, car *Car, anchored bool, keys Keys, content Content) (*Reading, error) {
	rec := car.Carrier.Secret
	rd := &Reading{Car: car, Anchored: anchored}
	// 0. listing.
	if anchored {
		ok, err := v.Listed(car)
		if err != nil {
			return nil, err
		}
		rd.PathOK = ok
	}
	if secrec.CheckGroupEpoch(g.Epochs, rec.Epoch, rec.EpochID) != nil {
		return nil, failed("listing", "the record names epoch %d under an id the group's chain did not begin", rec.Epoch)
	}
	if by, err := c.Swept(ctx, v.Crypt, car.Carrier.Funding); err != nil {
		return nil, err
	} else if by != "" {
		return nil, failed(LabelRetracted, "the owner swept this version's funding output in %s: it is retracted", by)
	}
	rd.Exposed = rec.Epoch < g.Current().Epoch
	// 1. hash, before any wrap is opened.
	ct := rec.Inline
	if ct == nil {
		if content == nil {
			return nil, fmt.Errorf("%w: its %d bytes are not carried in the record; they are at %s (config key content)", ErrUnavailable, rec.Length, secrec.Locator(rec.Hash))
		}
		var err error
		if ct, err = content.Get(ctx, rec.Hash, rec.Length); err != nil {
			return nil, err
		}
	}
	if err := secrec.CheckCiphertext(rec, ct); err != nil {
		return nil, failed("hash", "the ciphertext served is not the one the record names: whoever served the bytes substituted or cut them")
	}
	// 2a to 4.
	var p *secrec.Payload
	var err error
	if keys.Owner != nil {
		p, err = secrec.ReadAsOwner(ctx, keys.Owner, rec, ct)
	} else {
		if keys.Epoch == nil {
			return nil, failed("undecryptable", "this reader holds no key")
		}
		sym, kerr := keys.Epoch(ctx, rec.Epoch)
		if kerr != nil {
			return nil, failed("undecryptable", "this key holds no key of epoch %d, the epoch the record names: %v", rec.Epoch, kerr)
		}
		p, err = secrec.ReadAsMember(rec, ct, sym)
	}
	if err != nil {
		return nil, &Failure{Label: secrec.Reason(err), Err: err}
	}
	rd.Payload = p
	return rd, nil
}

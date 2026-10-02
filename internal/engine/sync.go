package engine

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/lightwebinc/bcommon/funding"

	"github.com/lightwebinc/borg/reader"

	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/state"
	"github.com/lightwebinc/bsecret/internal/vread"
)

// SyncReport is what a catch-up found.
type SyncReport struct {
	Vaults, NewVaults  int
	Tokens             int
	Versions, Named    int
	Trees              int
	Unreadable, Broken []string
	// Ahead are the vaults whose chain this home holds further than any
	// host answered: the home's own tokens are kept and published again.
	Ahead []string
}

// Sync catches this home up with the hosts (spec section 8.5): every vault
// of the organisation in crypt, its chain from seq 0 read as any reader
// reads it, against the home's own headers, and folded; every current
// secret's record, and each one's name and claims through its self wrap,
// which needs only the organisation's identity key; and every commitment
// any token listed, so that none is ever published again. The funding tree
// of every carrier the hosts answer is recorded, spent, so that a sweep or
// the kill switch reaches versions another instance published; this home
// never funds a carrier from one (two instances must not share a tree).
//
// What it cannot bring back: a version published and not yet listed whose
// carrier no host kept, and another instance's unpublished objects.
func (e *Engine) Sync(ctx context.Context, crypt string) (*SyncReport, error) {
	rd := e.Legs.Reader
	if rd == nil {
		return nil, errors.New("sync reads the hosts: none is configured (config key hosts)")
	}
	rep := &SyncReport{}
	org := e.OrgKey()
	answered, errs := rd.Vaults(ctx, crypt, org)
	if len(errs) == len(rd.Hosts) && len(rd.Hosts) > 0 {
		for h, err := range errs {
			return nil, fmt.Errorf("no host could be asked for the vaults (%s: %w)", h, err)
		}
	}
	ids := map[[32]byte]bool{}
	for id := range answered {
		ids[id] = true
	}
	for i := range e.St.Vaults {
		if e.St.Vaults[i].Crypt == crypt {
			ids[hex32(e.St.Vaults[i].ID)] = true
		}
	}
	order := make([][32]byte, 0, len(ids))
	for id := range ids {
		order = append(order, id)
	}
	sort.Slice(order, func(i, j int) bool { return bytes.Compare(order[i][:], order[j][:]) < 0 })
	for _, id := range order {
		idHex := hex.EncodeToString(id[:])
		cv, err := rd.Chain(ctx, crypt, org, id)
		if err != nil {
			if e.St.VaultByID(idHex) != nil && errors.Is(err, vread.ErrNoChain) {
				rep.Ahead = append(rep.Ahead, idHex)
				continue
			}
			return rep, fmt.Errorf("vault %s: %w", vread.Short(idHex), err)
		}
		rep.Vaults++
		if b := cv.Broken(); b != "" {
			rep.Broken = append(rep.Broken, fmt.Sprintf("%s (%s at seq %d)", idHex, b, cv.Usable()))
		}
		v := e.St.VaultByID(idHex)
		if v == nil {
			first := cv.Tokens[0].Token.Vault
			e.St.Vaults = append(e.St.Vaults, state.Vault{ID: idHex, Crypt: crypt, Name: first.Name, Hall: first.Hall,
				Group: reader.GroupHex(first.Group), Anchor: first.Anchor, Labels: first.Labels})
			v = e.St.VaultByID(idHex)
			rep.NewVaults++
		}
		if v.Pending != nil {
			return rep, fmt.Errorf("vault %s: %s %s is persisted and not yet mined; finish it first", vread.Short(idHex), v.Pending.What, Short(v.Pending.Txid))
		}
		usable := cv.Tokens[:cv.Usable()]
		// The chain the hosts answer replaces the home's from the first
		// token that differs; a home that holds further than any host
		// keeps its own.
		same := 0
		for same < len(v.Tokens) && same < len(usable) && v.Tokens[same].Txid == usable[same].Txid {
			same++
		}
		if same == len(usable) && len(v.Tokens) > len(usable) {
			rep.Ahead = append(rep.Ahead, idHex)
		} else {
			v.Tokens = v.Tokens[:same]
			for _, t := range usable[same:] {
				parent := ""
				if t.Seq() == 0 {
					_, op, err := secrec.CheckFirstToken(t.Tx)
					if err != nil {
						return rep, err
					}
					parent = op.Txid.String()
				} else {
					parent = usable[t.Seq()-1].Txid
				}
				v.Tokens = append(v.Tokens, state.Token{Seq: t.Seq(), Txid: t.Txid, RawHex: t.Tx.Hex(), BumpHex: t.Tx.MerklePath.Hex(),
					Height: t.Height, Record: hex.EncodeToString(t.Token.Record), Vout: t.Token.Vout, Parent: parent, Published: true})
				rep.Tokens++
			}
		}
		// What the chain lists, from seq 0: versions, ends and commitments.
		for i := range v.Versions {
			v.Versions[i].Listed, v.Versions[i].Ended = false, false
		}
		recs, err := Records(v)
		if err != nil {
			return rep, err
		}
		for _, r := range recs {
			Mark(e.St, v, r)
		}
		// Every current secret's record, and its name through the self
		// wrap.
		for _, sa := range rd.Secrets(ctx, cv) {
			if sa.Err != nil {
				e.note("host %s: the vault's set could not be read: %v", sa.Host, sa.Err)
				continue
			}
			for _, car := range sa.Cars {
				if _, err := cv.Listed(car); err != nil {
					continue
				}
				x := v.VersionOf(hex.EncodeToString(car.Carrier.Secret.ID[:]), hex.EncodeToString(car.Carrier.ContentID[:]))
				if x == nil || x.Raw != "" {
					continue
				}
				e.adoptCarrier(ctx, x, car, rep)
			}
		}
		for i := range v.Versions {
			if x := &v.Versions[i]; x.Listed && !x.Ended && x.Name == "" {
				rep.Unreadable = append(rep.Unreadable, x.ID)
			}
		}
	}
	return rep, e.St.Save()
}

// adoptCarrier fills a version from a carrier a host answered: its record,
// its funding outpoint and tree, and, through the self wrap, its name and
// the payload's claims.
func (e *Engine) adoptCarrier(ctx context.Context, x *state.SecretVersion, car *vread.Car, rep *SyncReport) {
	rec := car.Carrier.Secret
	x.Label, x.Txid, x.Epoch, x.Created = rec.Label, car.Txid, rec.Epoch, rec.Created
	x.Tree, x.Vout = car.Carrier.Funding.Txid.String(), car.Carrier.Funding.Index
	x.Raw, x.Hash, x.Stored = car.Tx.Hex(), hex.EncodeToString(rec.Hash[:]), rec.Inline == nil
	rep.Versions++
	if e.keepTree(car.Tx) {
		rep.Trees++
	}
	ct := rec.Inline
	if ct == nil && e.Legs.Content != nil {
		ct, _ = e.Legs.Content.Get(ctx, rec.Hash, rec.Length)
	}
	if ct == nil {
		return
	}
	p, err := secrec.ReadAsOwner(ctx, e.Signer, rec, ct)
	if err != nil {
		e.note("secret %s version %d: its self wrap does not open with this home's key (%s)", vread.Short(x.ID), x.Version, secrec.Reason(err))
		return
	}
	x.Name, x.RotateEvery, x.NotAfter = p.Name, p.RotateEvery, p.NotAfter
	rep.Named++
}

// keepTree records the funding tree a carrier spends when the home does
// not keep it: every output marked used, so nothing is ever funded from it
// here, and a sweep or the kill switch finds it.
func (e *Engine) keepTree(carrier *transaction.Transaction) bool {
	if len(carrier.Inputs) != 1 || carrier.Inputs[0].SourceTransaction == nil {
		return false
	}
	tree := carrier.Inputs[0].SourceTransaction
	id := tree.TxID().String()
	if _, _, ok := e.St.TreeOf(id); ok || tree.MerklePath == nil {
		return false
	}
	lock, err := secrec.FundingScriptOf(secrec.SecretDerivation, e.OrgKey())
	if err != nil {
		return false
	}
	var count uint32
	var sats uint64
	for i, o := range tree.Outputs {
		if o == nil || o.LockingScript == nil || !bytes.Equal(*o.LockingScript, lock) {
			break
		}
		count, sats = uint32(i)+1, o.Satoshis //nolint:gosec // an output index
	}
	if count == 0 {
		return false
	}
	ts := e.St.Set(state.TreeSecret)
	ts.Trees = append(ts.Trees, funding.Tree{IdentityKeyHex: e.orgHex(), Txid: id, RawHex: tree.Hex(), BumpHex: tree.MerklePath.Hex(),
		Height: tree.MerklePath.BlockHeight, Sats: sats, Count: count, Next: count, Funder: "another instance"})
	return true
}

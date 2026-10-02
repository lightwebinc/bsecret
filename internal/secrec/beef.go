package secrec

import (
	"errors"
	"fmt"
	"sort"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/lightwebinc/bcommon/chaintoken"
)

// DefaultMaxBEEF is the BEEF bound Admit applies when a host names none: the
// floor docs/spec.md section 11.1 sets for a host's own bound.
const DefaultMaxBEEF = chaintoken.DefaultMaxBEEF

// DefaultMaxSweepInputs is the sweep input bound Admit applies when a host
// names none: the floor docs/spec.md section 11.1 sets.
const DefaultMaxSweepInputs = 1024

// TokenBEEF assembles the BEEF a vault token is admitted in (docs/spec.md
// sections 11.1 and 11.6): a BEEF V1 of exactly the parent then the token,
// each with its own minimal path, or one merged path when both are in one
// block (bcommon chaintoken.TokenBEEF). A replayer builds it from the token
// as a host stores it and its parent: the token before it, or at seq 0 the
// chain tree.
func TokenBEEF(token, parent *transaction.Transaction) ([]byte, error) {
	return chaintoken.TokenBEEF(token, parent)
}

// StoredToken reads a vault token as a host stores it: the token's
// transaction alone, with its proof (docs/spec.md section 11.4). It returns
// the transaction and the token output's record, decoded, without the
// parent. An index and a reader read a stored token this way and never
// admit it again.
func StoredToken(b []byte) (*transaction.Transaction, *VaultToken, error) {
	tx, err := chaintoken.Stored(b, DefaultMaxBEEF)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrBEEF, err)
	}
	t, err := ReadToken(tx)
	return tx, t, err
}

// MinimalPath is mp cut to the proof of txid alone (docs/spec.md section 11.1: every
// path is minimal): at the lowest level txid, flagged as the txid, and its
// sibling; above that the one sibling each level needs, computed from the
// leaves below when mp holds only those. A node may answer a proof that
// carries more of its block than one transaction needs, and a host refuses
// a carrier or token whose BEEF carries such a proof. The result proves the
// same root.
func MinimalPath(mp *transaction.MerklePath, txid *chainhash.Hash) (*transaction.MerklePath, error) {
	if mp == nil || len(mp.Path) == 0 {
		return nil, errors.New("secrec: no proof")
	}
	index := transaction.IndexedPath(make([]map[uint64]*transaction.PathElement, len(mp.Path)))
	var at *transaction.PathElement
	for l, leaves := range mp.Path {
		index[l] = map[uint64]*transaction.PathElement{}
		for _, e := range leaves {
			index[l][e.Offset] = e
			if l == 0 && e.Hash != nil && *e.Hash == *txid {
				at = e
			}
		}
	}
	if at == nil {
		return nil, fmt.Errorf("secrec: the proof does not hold %s", txid)
	}
	isTxid := true
	path := make([][]*transaction.PathElement, len(mp.Path))
	path[0] = []*transaction.PathElement{{Offset: at.Offset, Hash: txid, Txid: &isTxid}}
	for l := range mp.Path {
		off := at.Offset>>uint(l) ^ 1
		e := index.GetOffsetLeaf(l, off)
		if e == nil {
			return nil, fmt.Errorf("secrec: the proof lacks the sibling at level %d", l)
		}
		leaf := &transaction.PathElement{Offset: off}
		if e.Duplicate != nil && *e.Duplicate {
			dup := true
			leaf.Duplicate = &dup
		} else {
			h := *e.Hash
			leaf.Hash = &h
		}
		path[l] = append(path[l], leaf)
	}
	sort.Slice(path[0], func(i, j int) bool { return path[0][i].Offset < path[0][j].Offset })
	out := transaction.NewMerklePath(mp.BlockHeight, path)
	want, err := mp.ComputeRoot(txid)
	if err != nil {
		return nil, err
	}
	got, err := out.ComputeRoot(txid)
	if err != nil || *got != *want {
		return nil, fmt.Errorf("secrec: the minimal proof of %s does not reach the block's root", txid)
	}
	return out, nil
}

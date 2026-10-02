package vread

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/lightwebinc/bcommon/nodeapi"

	"github.com/lightwebinc/borg/borgrec"
	"github.com/lightwebinc/borg/reader"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// Group is the vault's group as borg's reader established it: its canonical
// chain, verified against the reader's own headers, and the epochs that
// chain began. Everything here is borg's own code reading borg's own
// records (docs/spec.md section 16.1).
type Group struct {
	*reader.GroupView
	// Epochs are the epochs the canonical chain began, ascending: each with
	// its id (the hash of the group record that began it), the height of
	// the block that mined that token, and whether the token removed
	// anyone.
	Epochs []secrec.EpochEvent
}

// Forgetter is a reader's Floor that can forget one chain: what ReadGroup
// asks of the floor when the token it remembers was displaced by a
// reorganisation.
type Forgetter interface {
	Forget(hall, org, chain string)
}

// ReadGroup establishes the chain of group of org in hall through borg's
// reader. org is the vault's owner: borg's reader verifies every token as
// that organisation's, so a group it returns is the vault's organisation's
// (spec section 7.2).
//
// When the reader has a Floor (borg's reader.Client.Floor), the group is
// held to the latest token this caller verified of it before (spec section
// 14, no going back): hosts that answer the group's chain only below it
// are answering an older state, one in which a member since removed is
// still a member and the epoch that removal began does not exist. That is
// refused (rollback). Only the chain source's word that the remembered
// token is no longer mined, a reorganisation, makes the floor forget it;
// a source that fails proves nothing, and nothing is forgotten on its
// account.
func ReadGroup(ctx context.Context, rd *reader.Client, hall string, org []byte, group [secrec.GroupIDLen]byte) (*Group, error) {
	if rd == nil || len(rd.Hosts) == 0 {
		return nil, errors.New("no overlay host configured for the group's hall (config key hall_hosts, or hosts)")
	}
	gid := reader.GroupHex(group)
	gv, err := rd.Group(ctx, hall, org, gid)
	var back *reader.RollbackError
	if errors.As(err, &back) {
		if f, ok := rd.Floor.(Forgetter); ok && rd.Source != nil {
			if _, perr := rd.Source.MerkleProof(ctx, back.Txid); errors.Is(perr, nodeapi.ErrNotMined) {
				f.Forget(hall, hex.EncodeToString(org), gid)
				gv, err = rd.Group(ctx, hall, org, gid)
			}
		}
	}
	if errors.As(err, &back) {
		return nil, &Failure{Label: LabelRollback, Err: fmt.Errorf("the hosts of hall %s answer group %s to seq %d, and this home verified seq %d (%s): an older state of the group, in which a member since removed may still be one; ask other hosts", hall, gid, back.Answered, back.Seq, back.Txid)}
	}
	if err != nil {
		return nil, err
	}
	g := &Group{GroupView: gv}
	for e, t := range gv.Begins {
		g.Epochs = append(g.Epochs, secrec.EpochEvent{Epoch: uint64(e), EpochID: borgrec.EpochID(t.Token.Record),
			Height: t.Height, Removed: len(t.Token.Group.Remove) > 0})
	}
	sort.Slice(g.Epochs, func(i, j int) bool { return g.Epochs[i].Epoch < g.Epochs[j].Epoch })
	if len(g.Epochs) == 0 {
		return nil, errors.New("the group's chain begins no epoch")
	}
	return g, nil
}

// Current is the group's latest epoch.
func (g *Group) Current() secrec.EpochEvent { return g.Epochs[len(g.Epochs)-1] }

// EpochAt is the epoch numbered e, when the group began it.
func (g *Group) EpochAt(e uint64) (secrec.EpochEvent, bool) {
	for _, x := range g.Epochs {
		if x.Epoch == e {
			return x, true
		}
	}
	return secrec.EpochEvent{}, false
}

// Standing is a vault's state against its group (spec section 7.3).
type Standing struct {
	// Ahead: the vault names an epoch the group has not begun, or another
	// epoch id than the group's for that epoch. A reader takes nothing
	// from it.
	Ahead bool
	// Behind: the vault's epoch is before the group's latest.
	Behind bool
	// Stale is the latest token's stale count: above zero, the vault is in
	// debt.
	Stale uint64
	// Epoch is the vault's epoch and Group the group's latest.
	Epoch, Group uint64
}

// Settled reports a vault that owes nothing: its epoch is the group's
// latest and nothing in it is stale.
func (s Standing) Settled() bool { return !s.Ahead && !s.Behind && s.Stale == 0 }

func (s Standing) String() string {
	switch {
	case s.Ahead:
		return fmt.Sprintf("AHEAD: it names epoch %d, which the group's chain did not begin under that id", s.Epoch)
	case s.Behind && s.Stale > 0:
		return fmt.Sprintf("BEHIND and IN DEBT: it acknowledges epoch %d, the group is at epoch %d, and %d secret(s) are still under an earlier epoch", s.Epoch, s.Group, s.Stale)
	case s.Behind:
		return fmt.Sprintf("BEHIND: it acknowledges epoch %d and the group is at epoch %d", s.Epoch, s.Group)
	case s.Stale > 0:
		return fmt.Sprintf("IN DEBT: %d secret(s) are still under an epoch before %d", s.Stale, s.Epoch)
	}
	return fmt.Sprintf("settled at epoch %d", s.Epoch)
}

// Stand is the standing of a vault token against the group.
func (g *Group) Stand(v *secrec.Vault) Standing {
	s := Standing{Epoch: v.Epoch, Group: g.Current().Epoch, Stale: v.Stale}
	if secrec.CheckGroupEpoch(g.Epochs, v.Epoch, v.EpochID) != nil {
		s.Ahead = true
		return s
	}
	s.Behind = v.Epoch < s.Group
	return s
}

// OpenEpoch opens the key of one epoch of the group for the key me, whose
// wallet is w, by borg's member checks (borg's reader.Open: the token that
// began the epoch from the canonical chain, a wrap that verifies and holds
// an entry for me, the wallet's decryption, the commitment), and returns
// the epoch's BRC-369 symmetric key, the input of the epoch wrap key
// (docs/spec.md section 6.3). A key that was not a member of the epoch
// holds no wrap of it and opens nothing.
func OpenEpoch(ctx context.Context, rd *reader.Client, w wallet.Interface, me []byte, g *Group, epoch uint64) ([32]byte, error) {
	if epoch > secrec.MaxEpoch {
		return [32]byte{}, fmt.Errorf("epoch %d is out of range", epoch)
	}
	op := rd.Open(ctx, w, me, g.GroupView, uint32(epoch)) //nolint:gosec // bounded above
	if op.Label != "" {
		return [32]byte{}, fmt.Errorf("epoch %d (%s): %w", epoch, op.Label, op.Err)
	}
	return borgrec.SymmetricKey(op.Key), nil
}

// SignerWallet is the wallet of the organisation's signer key: the key
// derived from the organisation's identity key that borg keeps a member of
// each group once `borg org signer` has run, so that every instance of the
// organisation's tooling opens the epoch keys another instance sampled
// (borg's spec section 7.4; docs/spec.md section 8.5). It returns the
// wallet and the signer's public key.
func SignerWallet(orgKey *ec.PrivateKey) (wallet.Interface, []byte, error) {
	k, err := borgrec.SignerPrivate(orgKey)
	if err != nil {
		return nil, nil, err
	}
	w, err := wallet.NewCompletedProtoWallet(k)
	if err != nil {
		return nil, nil, err
	}
	return w, k.PubKey().Compressed(), nil
}

// WrapsMissing are the members of the group's latest token that no host
// answers a wrap of epoch for: a version keyed under a new epoch is
// published only after borg's wraps of the epoch's key are (spec section
// 8.3), or the members who remain could not open it.
func WrapsMissing(ctx context.Context, rd *reader.Client, g *Group, epoch uint64) ([][]byte, error) {
	if epoch > secrec.MaxEpoch {
		return nil, fmt.Errorf("epoch %d is out of range", epoch)
	}
	cars, _ := rd.Wraps(ctx, g.GroupView, uint32(epoch)) //nolint:gosec // bounded above
	have := map[string]bool{}
	for _, car := range cars {
		for _, r := range car.Carrier.Wrap.Recipients() {
			have[string(r)] = true
		}
	}
	var missing [][]byte
	for _, m := range g.Members {
		if !have[string(m)] {
			missing = append(missing, m)
		}
	}
	return missing, nil
}

// Spends is a source that indexes spends (borg's reader.Spends).
type Spends = reader.Spends

// GroupFresh is a writer's evidence that the group's latest token is the
// latest (spec section 7.1 rule 2): borg's reader.Latest.
func GroupFresh(ctx context.Context, spends Spends, raw func(ctx context.Context, txid string) ([]byte, error), g *Group, now time.Time) error {
	f, err := reader.Latest(ctx, spends, raw, g.GroupView, now)
	if err != nil {
		return err
	}
	if !f.OK() {
		return errors.New("the group's latest token is not positively the latest")
	}
	return nil
}

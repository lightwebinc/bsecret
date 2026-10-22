package testhost

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/lightwebinc/bcommon/bwallet"
	"github.com/lightwebinc/bcommon/carrier"
	"github.com/lightwebinc/bcommon/mint"
	"github.com/lightwebinc/bcommon/nodeapi"
	"github.com/lightwebinc/bcommon/producer"
	"github.com/lightwebinc/bcommon/publish"
	"github.com/lightwebinc/bcommon/pushdrop"

	"github.com/lightwebinc/borg/borgrec"
)

// borgIndex is what a hall's lookup service answers a vault's reader: the
// group tokens by chain and seq, and the wrap carriers.
type borgIndex struct {
	tokens map[string]*borgTok
	wraps  map[string]*borgWrap
}

type borgTok struct {
	txid   string
	hall   string
	org    string
	group  string
	seq    uint64
	stored []byte
}

type borgWrap struct {
	txid string
	hall string
	org  string
	beef []byte
	wrap *borgrec.WrapRecord
}

func newBorgIndex() *borgIndex {
	return &borgIndex{tokens: map[string]*borgTok{}, wraps: map[string]*borgWrap{}}
}

func (x *borgIndex) admit(hall, id string, beef []byte, tx *transaction.Transaction, a *borgrec.Admission) {
	switch a.Kind {
	case borgrec.TxWrap:
		x.wraps[id] = &borgWrap{txid: id, hall: hall, org: hex.EncodeToString(a.Carrier.Owner), beef: beef, wrap: a.Carrier.Wrap}
	case borgrec.TxGroupToken:
		stored, err := cloneTx(tx).AtomicBEEF(false)
		if err != nil {
			return
		}
		g := a.Token.Group
		x.tokens[id] = &borgTok{txid: id, hall: hall, org: hex.EncodeToString(g.Org), group: hex.EncodeToString(g.Group[:]), seq: g.Seq, stored: stored}
	}
}

// answer answers the ls_borg classes a vault's reader asks: a group's
// latest token and its token at a seq, the organization's groups, and the
// wraps of an epoch.
func (x *borgIndex) answer(q *borgrec.Question) ([]Output, error) {
	m := q.Members
	rows := func(group string) map[uint64][]*borgTok {
		out := map[uint64][]*borgTok{}
		for _, t := range x.tokens {
			if t.hall == m["hall"] && (t.org == m["org"] || t.org == m["groupsOf"]) && t.group == group {
				out[t.seq] = append(out[t.seq], t)
			}
		}
		return out
	}
	toks := func(rs []*borgTok) []Output {
		sort.Slice(rs, func(i, j int) bool { return rs[i].txid < rs[j].txid })
		out := []Output{}
		for _, t := range limit(rs, q.Class.Limit) {
			out = append(out, Output{Beef: t.stored})
		}
		return out
	}
	top := func(by map[uint64][]*borgTok) []*borgTok {
		var best uint64
		found := false
		for s := range by {
			if !found || s > best {
				best, found = s, true
			}
		}
		return by[best]
	}
	switch q.Class.Name {
	case "group":
		return toks(top(rows(m["group"]))), nil
	case "group-seq":
		s, _ := strconv.ParseUint(m["seq"], 10, 64)
		return toks(rows(m["group"])[s]), nil
	case "groups", "groups-after":
		ids := map[string]bool{}
		for _, t := range x.tokens {
			if t.hall == m["hall"] && t.org == m["groupsOf"] && (m["after"] == "" || t.group > m["after"]) {
				ids[t.group] = true
			}
		}
		order := make([]string, 0, len(ids))
		for g := range ids {
			order = append(order, g)
		}
		sort.Strings(order)
		out := []Output{}
		for _, g := range limit(order, q.Class.Limit) {
			if rs := top(rows(g)); len(rs) > 0 {
				out = append(out, Output{Beef: rs[0].stored})
			}
		}
		return out, nil
	case "wraps", "wraps-after", "wrap":
		e, _ := strconv.ParseUint(m["epoch"], 10, 32)
		var rs []*borgWrap
		for _, w := range x.wraps {
			if w.hall != m["hall"] || w.org != m["org"] || hex.EncodeToString(w.wrap.Group[:]) != m["group"] || w.wrap.Epoch != e {
				continue
			}
			if a := m["after"]; a != "" && w.txid <= a {
				continue
			}
			if k := m["member"]; k != "" {
				found := false
				for _, r := range w.wrap.Recipients() {
					found = found || hex.EncodeToString(r) == k
				}
				if !found {
					continue
				}
			}
			rs = append(rs, w)
		}
		sort.Slice(rs, func(i, j int) bool { return rs[i].txid < rs[j].txid })
		out := []Output{}
		for _, w := range limit(rs, q.Class.Limit) {
			out = append(out, Output{Beef: w.beef})
		}
		return out, nil
	}
	return nil, fmt.Errorf("class %s is not answered here", q.Class.Name)
}

// Take offers a BEEF to the host under a topic, as a submission does, and
// reports whether it admitted anything.
func (h *Host) Take(topic string, beef []byte) (bool, error) {
	rec := &recorder{header: map[string][]string{}, code: 200}
	req, err := newSubmit(topic, beef)
	if err != nil {
		return false, err
	}
	h.ServeHTTP(rec, req)
	if rec.code != 200 {
		return false, fmt.Errorf("status %d: %s", rec.code, rec.body.String())
	}
	return !bytes.Contains(rec.body.Bytes(), []byte(`"outputsToAdmit":[]`)), nil
}

// Borg is an organization's borg tooling reduced to what a vault needs of
// it: a hall, groups whose tokens are real mined transactions under borg's
// own derivations and records (borgrec), epoch keys sampled at random and
// wrapped to each member and to the organization's signer key, and
// removals that begin a new epoch. Its home holds an identity.json as a
// borg home does, which is what a bsecret home is made around. It issues no
// grant and keeps no organization chain: neither a host's admission of a
// group token nor a vault's reader looks at one.
type Borg struct {
	Home  string
	Hall  string
	e     *bwallet.Embedded
	rpc   *nodeapi.RPC
	asset *nodeapi.Asset
	hosts []*Host
	chain map[string]*borgGroup
	// NoWraps holds back the wraps of every epoch begun while it is set,
	// until Wrap is called: a new epoch whose key is not yet released.
	NoWraps bool
	// NoSigner leaves the organization's signer key out of new groups.
	NoSigner bool
	rec      *transaction.Transaction
	recNext  uint32
}

type borgGroup struct {
	id      [borgrec.GroupIDLen]byte
	members map[string]bool
	last    *transaction.Transaction
	record  *borgrec.Group
	keys    map[uint64][32]byte
	ids     map[uint64][32]byte
	wrapped map[uint64]map[string]bool
}

var borgProfile = bwallet.Profile{FundProtocol: borgrec.Protocol, FundKeyID: borgrec.KeyFund, FundBasket: "borg fund",
	Version: "borg-1", LegacyPoolFile: "borg-pool.json"}

func borgParams(d pushdrop.Derivation) carrier.Params {
	return carrier.Params{Derivation: d, FundingTag: borgrec.TagFunding, ValidatePayload: func([]byte) error { return nil }, ErrIdentity: borgrec.ErrIdentity}
}

// NewBorg makes an organization whose home is dir, funded from the chain
// served at chainURL, in a new hall the hosts carry.
func NewBorg(dir, chainURL string, hosts ...*Host) (*Borg, error) {
	e, err := bwallet.Create(dir, borgProfile)
	if err != nil {
		return nil, err
	}
	e.Originator = "borg"
	hall, err := borgrec.NewHall("example", rand.Reader)
	if err != nil {
		return nil, err
	}
	b := &Borg{Home: dir, Hall: hall, e: e, hosts: hosts, chain: map[string]*borgGroup{},
		rpc: &nodeapi.RPC{URL: chainURL + "/rpc", User: "bitcoin", Pass: "bitcoin", ID: "borg"}, asset: &nodeapi.Asset{Base: chainURL}}
	for _, h := range hosts {
		h.CarryHall(hall)
	}
	if _, _, err := bwallet.FundFromCoinbase(context.Background(), e.Signer(), e.Pool, b.rpc, b.asset, 104, bwallet.DefaultFundBatch); err != nil {
		return nil, err
	}
	return b, nil
}

// Identity is the organization's identity key, hex.
func (b *Borg) Identity() string { return b.e.Signer().IdentityHex() }

// Key is the organization's identity key, compressed.
func (b *Borg) Key() []byte { return b.e.Signer().Identity.Compressed() }

// Signer is the organization's signer key, compressed.
func (b *Borg) Signer() []byte {
	k, err := borgrec.SignerKey(b.Key())
	if err != nil {
		panic(err)
	}
	return k
}

func (b *Borg) payer() (*producer.Payer, error) {
	tip, err := b.asset.BestHeader(context.Background())
	if err != nil {
		return nil, err
	}
	s := b.e.Signer()
	return &producer.Payer{Pool: b.e.Pool, Tip: tip.Height, Keys: map[string]*bwallet.Signer{s.IdentityHex(): s},
		Kept:    &producer.Kept{Load: func(string) (*transaction.Transaction, error) { return nil, errors.New("not kept") }},
		Settler: &publish.RPCSettler{RPC: b.rpc}, Asset: b.asset, Fees: mint.DefaultFees, Poll: time.Millisecond}, nil
}

// settle mines tx and returns it with its proof.
func (b *Borg) settle(p *producer.Payer, what string, tx *transaction.Transaction) error {
	mp, h, err := p.SettleAndWait(context.Background(), what, tx)
	if err != nil {
		return err
	}
	tx.MerklePath = mp
	p.Change(tx, h, mp)
	return nil
}

// tree mints and mines a funding tree of count outputs under d.
func (b *Borg) tree(d pushdrop.Derivation, count int) (*transaction.Transaction, error) {
	ctx := context.Background()
	s := b.e.Signer()
	lock, err := carrier.FundingLock(ctx, s, s.Originator, borgParams(d))
	if err != nil {
		return nil, err
	}
	p, err := b.payer()
	if err != nil {
		return nil, err
	}
	fee, err := p.Take(ctx)
	if err != nil {
		return nil, err
	}
	change, err := s.FundScript()
	if err != nil {
		return nil, err
	}
	tx, err := mint.FundingTree(lock, count, 1, fee, change, mint.DefaultFees)
	if err != nil {
		return nil, err
	}
	return tx, b.settle(p, "tree", tx)
}

// publish offers a BEEF to every host that is up.
func (b *Borg) publish(beef []byte) error {
	took := 0
	for _, h := range b.hosts {
		if ok, err := h.Take(borgrec.Topic(b.Hall), beef); err == nil && ok {
			took++
		}
	}
	if took == 0 {
		return errors.New("no host admitted the object")
	}
	return nil
}

func sortKeys(a [][]byte) {
	sort.Slice(a, func(i, j int) bool { return bytes.Compare(a[i], a[j]) < 0 })
}

func (g *borgGroup) list() [][]byte {
	out := make([][]byte, 0, len(g.members))
	for m := range g.members {
		out = append(out, []byte(m))
	}
	sortKeys(out)
	return out
}

// token mints the group's next token, mines it and publishes it.
func (b *Borg) token(g *borgGroup, rec *borgrec.Group, parent *transaction.Transaction, vout uint32, d pushdrop.Derivation) error {
	ctx := context.Background()
	s := b.e.Signer()
	raw, err := rec.Encode()
	if err != nil {
		return err
	}
	lock, err := borgrec.GroupDerivation.Lock(ctx, s, s.Originator, [][]byte{borgrec.TagGroup, raw}, true)
	if err != nil {
		return err
	}
	p, err := b.payer()
	if err != nil {
		return err
	}
	fee, err := p.Take(ctx)
	if err != nil {
		return err
	}
	change, err := s.FundScript()
	if err != nil {
		return err
	}
	tx, err := mint.Transition(lock, 1, &mint.Input{Tx: parent, Vout: vout, Unlocker: d.Unlocker(ctx, s, s.Originator)}, fee, change, mint.DefaultFees)
	if err != nil {
		return err
	}
	if err := b.settle(p, "group token", tx); err != nil {
		return err
	}
	beef, err := borgrec.TokenBEEF(tx, parent)
	if err != nil {
		return err
	}
	if err := b.publish(beef); err != nil {
		return fmt.Errorf("group token seq %d: %w", rec.Seq, err)
	}
	g.last, g.record = tx, rec
	if rec.BeginsEpoch() {
		g.ids[rec.Epoch] = borgrec.EpochID(raw)
	}
	return nil
}

// CreateGroup creates a group of members (identity keys, compressed), with
// the organization's signer key among them, and wraps epoch 0's key to
// each. It returns the group's identifier, hex.
func (b *Borg) CreateGroup(name string, members ...[]byte) (string, error) {
	gid, err := borgrec.NewGroupID(rand.Reader)
	if err != nil {
		return "", err
	}
	g := &borgGroup{id: gid, members: map[string]bool{}, keys: map[uint64][32]byte{}, ids: map[uint64][32]byte{}, wrapped: map[uint64]map[string]bool{}}
	for _, m := range members {
		g.members[string(m)] = true
	}
	if !b.NoSigner {
		g.members[string(b.Signer())] = true
	}
	k, err := borgrec.SampleKey(nil)
	if err != nil {
		return "", err
	}
	all := g.list()
	rec := &borgrec.Group{Hall: b.Hall, Org: b.Key(), Group: gid, Name: name, Commitment: borgrec.Commitment(k), Add: all,
		Count: uint64(len(all)), Members: borgrec.MembersRoot(all), Created: uint64(time.Now().Unix())} //nolint:gosec // a clock after 1970
	tree, err := b.tree(borgrec.ChainDerivation, 2)
	if err != nil {
		return "", err
	}
	g.keys[0] = k
	if err := b.token(g, rec, tree, 0, borgrec.ChainDerivation); err != nil {
		return "", err
	}
	id := hex.EncodeToString(gid[:])
	b.chain[id] = g
	return id, b.wrapOwed(g)
}

// Change mints the group's next token: add and remove members; a removal,
// or rotate, begins a new epoch with a fresh key, wrapped to the members
// who remain.
func (b *Borg) Change(group string, add, remove [][]byte, rotate bool) error {
	g := b.chain[group]
	if g == nil {
		return fmt.Errorf("no group %s", group)
	}
	pred := g.record
	rec := *pred
	rec.Seq, rec.Prev, rec.Created = pred.Seq+1, [32]byte(*g.last.TxID()), uint64(time.Now().Unix()) //nolint:gosec // a clock after 1970
	rec.Add, rec.Remove = nil, nil
	for _, m := range remove {
		if !g.members[string(m)] {
			return fmt.Errorf("%x is not a member", m)
		}
		delete(g.members, string(m))
		rec.Remove = append(rec.Remove, m)
	}
	for _, m := range add {
		g.members[string(m)] = true
		rec.Add = append(rec.Add, m)
	}
	sortKeys(rec.Add)
	sortKeys(rec.Remove)
	all := g.list()
	rec.Count, rec.Members = uint64(len(all)), borgrec.MembersRoot(all)
	if rotate || len(remove) > 0 {
		k, err := borgrec.SampleKey(nil)
		if err != nil {
			return err
		}
		rec.Epoch, rec.EpochSeq, rec.Commitment = pred.Epoch+1, rec.Seq, borgrec.Commitment(k)
		g.keys[rec.Epoch] = k
	}
	if err := borgrec.CheckGroupTransition(pred, [32]byte(*g.last.TxID()), &rec); err != nil {
		return err
	}
	if err := b.token(g, &rec, g.last, 0, borgrec.GroupDerivation); err != nil {
		return err
	}
	if b.NoWraps {
		return nil
	}
	return b.wrapOwed(g)
}

// Remove removes one member: a new epoch.
func (b *Borg) Remove(group string, member []byte) error {
	return b.Change(group, nil, [][]byte{member}, false)
}

// Add adds one member under the current epoch.
func (b *Borg) Add(group string, member []byte) error {
	return b.Change(group, [][]byte{member}, nil, false)
}

// Rotate begins a new epoch with the same members.
func (b *Borg) Rotate(group string) error { return b.Change(group, nil, nil, true) }

// Wrap publishes the wraps a group's current epoch owes its members.
func (b *Borg) Wrap(group string) error {
	g := b.chain[group]
	if g == nil {
		return fmt.Errorf("no group %s", group)
	}
	return b.wrapOwed(g)
}

// wrapOwed wraps the current epoch's key to every member not yet wrapped
// to, in records of up to 8 entries, each on its own record-tree output.
func (b *Borg) wrapOwed(g *borgGroup) error {
	ctx := context.Background()
	s := b.e.Signer()
	epoch := g.record.Epoch
	if g.wrapped[epoch] == nil {
		g.wrapped[epoch] = map[string]bool{}
	}
	var owed [][]byte
	for _, m := range g.list() {
		if !g.wrapped[epoch][string(m)] {
			owed = append(owed, m)
		}
	}
	for start := 0; start < len(owed); start += 8 {
		chunk := owed[start:min(start+8, len(owed))]
		w := &borgrec.WrapRecord{Hall: b.Hall, Org: b.Key(), Group: g.id, Epoch: epoch, EpochID: g.ids[epoch]}
		for _, m := range chunk {
			pub, err := ec.PublicKeyFromBytes(m)
			if err != nil {
				return err
			}
			entry, err := borgrec.Wrap(ctx, s, b.Key(), pub, g.ids[epoch], uint32(epoch), g.keys[epoch]) //nolint:gosec // a small epoch
			if err != nil {
				return err
			}
			w.Entries = append(w.Entries, entry)
		}
		raw, err := w.Encode()
		if err != nil {
			return err
		}
		if b.rec == nil || int(b.recNext) >= len(b.rec.Outputs)-1 {
			if b.rec, err = b.tree(borgrec.RecordDerivation, 16); err != nil {
				return err
			}
			b.recNext = 0
		}
		k, err := carrier.Mint(ctx, s, s.Originator, borgParams(borgrec.RecordDerivation), raw, b.rec, b.recNext)
		if err != nil {
			return err
		}
		b.recNext++
		beef, err := k.AtomicBEEF(false)
		if err != nil {
			return err
		}
		if err := b.publish(beef); err != nil {
			return fmt.Errorf("wrap of epoch %d: %w", epoch, err)
		}
		for _, m := range chunk {
			g.wrapped[epoch][string(m)] = true
		}
	}
	return nil
}

// Epoch is a group's current epoch.
func (b *Borg) Epoch(group string) uint64 { return b.chain[group].record.Epoch }

// LatestToken is the txid of a group's latest token.
func (b *Borg) LatestToken(group string) string { return b.chain[group].last.TxID().String() }

// identityKey reads a home's identity key.
func identityKey(home string) (*ec.PrivateKey, error) {
	raw, err := os.ReadFile(filepath.Join(home, "identity.json"))
	if err != nil {
		return nil, err
	}
	var id struct {
		WIF string `json:"wif"`
	}
	if err := json.Unmarshal(raw, &id); err != nil {
		return nil, err
	}
	return ec.PrivateKeyFromWif(id.WIF)
}

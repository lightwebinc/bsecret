// Package engine is a bsecret publisher: the owner's tooling (docs/spec.md
// sections 7, 8, 12 and 13), run from one identity's home. It creates
// vaults on a borg group, seals and wraps each version of a secret, mints
// the vault's chain tokens, acknowledges a new epoch of the group and
// re-keys what the vault held, retracts by sweep, and publishes every
// object on the plane or to each host.
//
// It is built on bcommon's producer package. A Payer pays for funding trees
// and vault tokens from the home's coin pool, and Trees mints the two kinds
// of funding tree the contract keeps apart (spec section 12.4): secret
// trees, which fund carriers and are minted ahead, so the next is on its
// way before the current runs out, and chain trees, which pay for a vault's
// first token. A funding tree is never published to a crypt on its own:
// every carrier carries its own, and a vault's first token carries its
// chain tree.
//
// Every object is persisted in the home's state before it is sent: a
// carrier with the funding output it spends marked used and its commitment
// recorded, a transition with the record it signs. A run that stops part
// way sends the same bytes again (Resume), and never a second carrier on
// one funding output. A transition takes effect only when a transaction
// spending its predecessor is mined in the publisher's own headers and
// carries byte for byte the record built (spec section 7.1).
//
// The tooling folds before it signs. One token whose counts its change
// lists do not give ends a vault for good (spec section 11.2), so every
// transition is applied to a copy of the fold of the vault's own chain and
// held to the host's transition rules before it is built, and one that
// either would flag is refused here, unbuilt.
package engine

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"

	"github.com/lightwebinc/bcommon/bwallet"
	"github.com/lightwebinc/bcommon/carrier"
	"github.com/lightwebinc/bcommon/funding"
	"github.com/lightwebinc/bcommon/mint"
	"github.com/lightwebinc/bcommon/nodeapi"
	"github.com/lightwebinc/bcommon/producer"
	"github.com/lightwebinc/bcommon/publish"
	"github.com/lightwebinc/bcommon/pushdrop"

	"github.com/lightwebinc/borg/reader"

	"github.com/lightwebinc/bsecret/internal/limits"
	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/state"
	"github.com/lightwebinc/bsecret/internal/unicast"
	"github.com/lightwebinc/bsecret/internal/vread"
)

// Profile is the embedded wallet's profile: the fund key under [1,
// "bsecret"] key id fund, and the registered basket.
var Profile = bwallet.Profile{
	FundProtocol:   secrec.Protocol,
	FundKeyID:      secrec.KeyFund,
	FundBasket:     "bsecret fund",
	Version:        "bsecret-1",
	LegacyPoolFile: "bsecret-pool.json",
}

// derivationOf is the derivation a tree kind's outputs are locked under.
func derivationOf(kind string) pushdrop.Derivation {
	if kind == state.TreeSecret {
		return secrec.SecretDerivation
	}
	return secrec.ChainDerivation
}

// Params are the carrier parameters of a tree kind: its derivation and the
// funding tag. A payload is checked by the host's rules before anything is
// persisted, so it is not checked again here.
func Params(kind string) carrier.Params {
	return carrier.Params{Derivation: derivationOf(kind), FundingTag: secrec.TagFunding,
		ValidatePayload: func([]byte) error { return nil }, ErrIdentity: secrec.ErrIdentity}
}

// Options are a publisher's choices. None of them is frozen.
type Options struct {
	// TreeCount sizes secret trees, ChainTreeCount chain trees; TreeSats is
	// each output's value; Ahead is how few outputs a secret tree has left
	// when the next is minted ahead.
	TreeCount      int
	ChainTreeCount int
	TreeSats       uint64
	Ahead          uint32
	// Fees is the fee policy of trees, tokens, sweeps and payments.
	Fees mint.Fees
	// ObjectBound is the plane's object bound, in bytes.
	ObjectBound int
	// Poll paces proof waits and Wait bounds one.
	Poll time.Duration
	Wait time.Duration
	// Delay is the propagation delay before a mined object is published.
	Delay time.Duration
	// Freshness is how old a writer's evidence may be (spec section 7.1).
	Freshness time.Duration
	// Segment is the plaintext bytes of one segment of a new version.
	Segment uint64
}

// Legs are the endpoints a publisher talks to. Objects go to exactly one of
// Facade (mode plane) and Hosts (mode unicast). In mode plane, Direct are
// the other hosts every mined object is also submitted to. Reader confirms,
// by lookup, a host that admitted nothing. Groups reads the vault's group
// from its hall's hosts, through borg's reader. Headers are the publisher's
// own block headers: a mined object is published only once its block is in
// them. Content is where a ciphertext too large to carry is written.
type Legs struct {
	Settler publish.Settler
	Asset   *nodeapi.Asset
	Arcade  *publish.Arcade
	Facade  *publish.Facade
	Hosts   *unicast.Set
	Direct  *unicast.Set
	Reader  *vread.Client
	Groups  *reader.Client
	Headers chaintracker.ChainTracker
	Content *vread.Store
}

// Engine is one publisher run over one home.
type Engine struct {
	St     *state.State
	Signer *bwallet.Signer
	// Key is the organisation's identity private key. It derives the
	// signer key, the member of the vault's group through which the
	// organisation opens an epoch's key (vread.SignerWallet).
	Key  *ec.PrivateKey
	Pool *bwallet.Pool
	Legs Legs
	Opts Options
	// Now is the clock records are stamped with; Sleep waits.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
	// Sample draws a content key and its salt; nil draws them at random. A
	// test sets it to show that a repeated key is refused.
	Sample func() ([32]byte, [secrec.SaltLen]byte, error)
	// Note receives progress lines.
	Note    func(format string, args ...any)
	Verbose bool

	payer   *producer.Payer
	kept    *producer.Kept
	trees   map[string]*producer.Trees
	pending *pendingTx
}

// New builds an engine over a home's state.
func New(st *state.State, signer *bwallet.Signer, pool *bwallet.Pool, legs Legs, o Options) (*Engine, error) {
	if st.Identity != signer.IdentityHex() {
		return nil, fmt.Errorf("the state belongs to identity %s, not this home's %s", st.Identity, signer.IdentityHex())
	}
	if legs.Settler == nil || legs.Asset == nil {
		return nil, errors.New("a publisher needs a settlement leg and a node (config keys settle and asset)")
	}
	if (legs.Facade == nil) == (legs.Hosts == nil) {
		return nil, errors.New("a publisher needs either a facade (mode plane) or hosts (mode unicast)")
	}
	if legs.Headers == nil {
		return nil, errors.New("a publisher needs a header source: a mined object is published only once its block is in the publisher's headers")
	}
	if o.Segment == 0 {
		o.Segment = limits.DefaultSegment
	}
	if o.Freshness <= 0 {
		o.Freshness = limits.DefaultFreshness
	}
	e := &Engine{St: st, Signer: signer, Pool: pool, Legs: legs, Opts: o, Now: time.Now, Sleep: sleep,
		trees: map[string]*producer.Trees{}}
	e.kept = &producer.Kept{Load: e.load}
	e.payer = e.NewPayer()
	// Trees are settled without waiting for a block: a tree minted ahead
	// comes back as soon as the settlement leg takes it, and spend waits
	// for a proof only when a carrier or a token needs it.
	e.payer.Async = true
	for _, kind := range state.TreeKinds {
		count, ahead := o.TreeCount, o.Ahead
		if kind == state.TreeChain {
			count, ahead = o.ChainTreeCount, 0
		}
		k := kind
		lock := func(ctx context.Context) (*script.Script, error) {
			return carrier.FundingLock(ctx, signer, signer.Originator, Params(k))
		}
		e.trees[kind] = &producer.Trees{Payer: e.payer, State: treeState{e, kind}, Identity: signer.IdentityHex(),
			Count: count, Sats: o.TreeSats, Funder: "pool", Lock: lock, Change: signer.FundScript,
			Facade: unicast.Kept(), Topic: "tm_bsecret_kept", Ahead: ahead}
	}
	return e, nil
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// NewPayer is a Payer over the engine's pool and legs.
func (e *Engine) NewPayer() *producer.Payer {
	p := &producer.Payer{
		Pool: e.Pool, Keys: map[string]*bwallet.Signer{e.Signer.IdentityHex(): e.Signer},
		Kept: e.kept, Settler: e.Legs.Settler, Asset: e.Legs.Asset, Fees: e.Opts.Fees,
		Timeout: e.Opts.Wait, Poll: e.Opts.Poll, Note: e.libraryNote,
	}
	if e.payer != nil {
		p.Tip = e.payer.Tip
	}
	return p
}

// libraryNote passes the library's lines on, except the one that reports a
// funding tree's publication: a bsecret tree is never published on its own.
func (e *Engine) libraryNote(format string, args ...any) {
	if strings.HasPrefix(format, "funding tree published") {
		return
	}
	e.note(format, args...)
}

func (e *Engine) note(format string, args ...any) {
	if e.Note != nil {
		e.Note(format, args...)
	}
}

// treeState is one kind of the home's funding trees as a
// producer.TreeState.
type treeState struct {
	e    *Engine
	kind string
}

func (t treeState) Current() *funding.Tree { return t.e.St.Set(t.kind).Tree }

func (t treeState) Adopt(tr funding.Tree) error {
	ts := t.e.St.Set(t.kind)
	ts.Tree = &tr
	ts.Trees = append(ts.Trees, tr)
	ts.Ahead = slices.DeleteFunc(ts.Ahead, func(a funding.Tree) bool { return a.Txid == tr.Txid })
	return t.e.St.Save()
}

// load rebuilds a funding tree the home keeps.
func (e *Engine) load(txid string) (*transaction.Transaction, error) {
	if t, _, ok := e.St.TreeOf(txid); ok {
		return funding.Rebuild(t.RawHex, t.BumpHex, t.BeefHex)
	}
	return nil, fmt.Errorf("transaction %s is not a funding tree this home keeps", txid)
}

// FeeError words the library's refusals to find a fee input.
func FeeError(err error) error {
	var nc *producer.NoCoinError
	var nk *producer.NoKeyError
	switch {
	case errors.As(err, &nc):
		if nc.Held > 0 {
			return fmt.Errorf("fee input: %w: the other coins are change from %d transaction(s) whose proofs have not arrived; they become spendable once mined", nc.Err, nc.Held)
		}
		return fmt.Errorf("fee input: %w (run `bsecret fund`)", nc.Err)
	case errors.As(err, &nk):
		return fmt.Errorf("wallet output %s is locked to a key this home does not hold", nk.Outpoint)
	}
	return err
}

// Start reads the chain tip for coinbase maturity, collects the proofs of
// change the pool holds back, and finishes whatever a previous run
// persisted and did not finish: a sweep, every object not confirmed
// published, a transition, and a token mined and not yet published.
func (e *Engine) Start(ctx context.Context) error {
	h, err := e.Legs.Asset.BestHeader(ctx)
	if err != nil {
		return fmt.Errorf("node tip: %w", err)
	}
	e.payer.Tip = h.Height
	CollectChange(ctx, e.Pool, e.Legs.Asset)
	var refusedErr *SweepRefusedError
	if err := e.FinishSweep(ctx); errors.As(err, &refusedErr) {
		e.note("%v", err)
	} else if err != nil {
		return err
	}
	if err := e.Resume(ctx); err != nil {
		return err
	}
	if err := e.FinishTransitions(ctx); err != nil {
		return err
	}
	return e.Owed(ctx)
}

// CollectChange gives every unproven coin in the pool its proof, once its
// transaction has mined.
func CollectChange(ctx context.Context, pool *bwallet.Pool, asset *nodeapi.Asset) int {
	n := 0
	for _, id := range pool.UnprovenTxids() {
		mp, h, err := asset.Proof(ctx, id)
		if err != nil {
			continue
		}
		if k, err := pool.Prove(id, mp.Hex(), h); err == nil {
			n += k
		}
	}
	return n
}

// Resume publishes every object a previous run persisted: the same bytes,
// so a host that already holds one answers a duplicate.
func (e *Engine) Resume(ctx context.Context) error {
	for len(e.St.Outbox) > 0 {
		p := e.St.Outbox[0]
		e.note("%s %s: publishing what a previous run persisted", p.Kind, Short(p.Txid))
		if err := e.publish(ctx, p); err != nil {
			return err
		}
		e.done(p)
		if err := e.St.Save(); err != nil {
			return err
		}
	}
	return nil
}

// done removes a published object from the outbox and records what its
// publication settles: a token every host named took.
func (e *Engine) done(p state.Pending) {
	e.St.Done(p.Txid)
	if p.Kind != state.KindToken {
		return
	}
	if v := e.St.VaultByID(p.Vault); v != nil {
		for i := range v.Tokens {
			if v.Tokens[i].Txid == p.Txid {
				v.Tokens[i].Published = true
			}
		}
	}
}

// Close collects a tree still being minted ahead, so its change reaches the
// pool, and records one never adopted in its kind's Ahead list, so a sweep
// finds it.
func (e *Engine) Close(ctx context.Context) error {
	for _, kind := range state.TreeKinds {
		t := e.trees[kind]
		_ = t.Wait(ctx)
		if p := t.Prepared(); p != nil {
			ts := e.St.Set(kind)
			ts.Ahead = producer.Index(ts.Ahead, p)
		}
	}
	return e.St.Save()
}

// spend returns the funding tree of kind the next carrier or first token
// spends and the output, the tree's proof cut to the minimal one a host
// admits.
func (e *Engine) spend(ctx context.Context, kind string) (*transaction.Transaction, uint32, error) {
	e.promoteAhead(kind)
	t := e.trees[kind]
	if e.hasAhead(kind) || kind == state.TreeChain {
		t.Ahead = 0
	} else {
		t.Ahead = e.Opts.Ahead
	}
	tree, vout, err := t.Spend(ctx, 1)
	if err != nil {
		return nil, 0, FeeError(fmt.Errorf("%s funding tree: %w", kind, err))
	}
	if tree.MerklePath == nil {
		if err := e.prove(ctx, kind, tree); err != nil {
			return nil, 0, err
		}
	}
	mp, err := Minimal(tree.MerklePath, tree.TxID())
	if err != nil {
		return nil, 0, fmt.Errorf("funding tree %s: %w", tree.TxID(), err)
	}
	tree.MerklePath = mp
	return tree, vout, nil
}

func (e *Engine) hasAhead(kind string) bool {
	ts := e.St.Set(kind)
	for _, t := range ts.Ahead {
		if t.IdentityKeyHex == e.Signer.IdentityHex() && t.Remaining() > 0 && (ts.Tree == nil || t.Txid != ts.Tree.Txid) {
			return true
		}
	}
	return false
}

func (e *Engine) promoteAhead(kind string) {
	ts := e.St.Set(kind)
	if ts.Tree != nil && ts.Tree.Remaining() > 0 {
		return
	}
	for _, t := range ts.Ahead {
		if t.IdentityKeyHex == e.Signer.IdentityHex() && t.Remaining() > 0 {
			_ = treeState{e, kind}.Adopt(t)
			e.note("switching to %s funding tree %s, minted ahead by an earlier run", kind, t.Txid)
			return
		}
	}
}

// prove waits for a funding tree's proof: a carrier spends only a mined
// tree and carries it with its proof (spec section 12.4).
func (e *Engine) prove(ctx context.Context, kind string, tree *transaction.Transaction) error {
	id := tree.TxID().String()
	mp, height, err := producer.Proofs{Arcade: e.Legs.Arcade, Asset: e.Legs.Asset}.Of(ctx, id)
	if err != nil {
		e.note("%s funding tree %s: waiting for it to mine", kind, id)
		if mp, height, err = e.NewPayer().Await(ctx, kind+" funding tree", tree); err != nil {
			return fmt.Errorf("%s funding tree %s: %w (it is recorded; the next command waits again)", kind, id, err)
		}
	}
	tree.MerklePath = mp
	e.kept.Prove(id, mp)
	CollectChange(ctx, e.Pool, e.Legs.Asset)
	if t, _, ok := e.St.TreeOf(id); ok {
		t.BumpHex, t.Height, t.BeefHex = mp.Hex(), height, ""
	}
	ts := e.St.Set(kind)
	for i := range ts.Trees {
		if ts.Trees[i].Txid == id {
			ts.Trees[i].BumpHex, ts.Trees[i].Height, ts.Trees[i].BeefHex = mp.Hex(), height, ""
		}
	}
	return e.St.Save()
}

// markSpent records that vout of the current tree of kind is used.
func (e *Engine) markSpent(kind string, tree *transaction.Transaction, vout uint32) {
	ts := e.St.Set(kind)
	if ts.Tree != nil && ts.Tree.Txid == tree.TxID().String() {
		ts.Tree.Next = vout + 1
		ts.Trees = producer.Index(ts.Trees, ts.Tree)
	}
}

// carrierFor mints the carrier of a secret record on the next secret-tree
// output, holds it to the host's rules for crypt, and returns what a host
// admits of it, the carrier and its Atomic BEEF.
func (e *Engine) carrierFor(ctx context.Context, crypt string, payload []byte, tree *transaction.Transaction, vout uint32) (*secrec.Admission, *transaction.Transaction, []byte, error) {
	k, err := carrier.Mint(ctx, e.Signer, e.Signer.Originator, Params(state.TreeSecret), payload, tree, vout)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("carrier: %w", err)
	}
	beef, err := k.AtomicBEEF(false)
	if err != nil {
		return nil, nil, nil, err
	}
	// The publisher's own copy of the host's rules: a carrier a host would
	// refuse is never persisted or published.
	a, err := secrec.Admit(ctx, beef, nil, secrec.Host{Crypt: crypt, Headers: e.Legs.Headers})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("the carrier breaks the host's rules (%s): %w", secrec.Reason(err), err)
	}
	if a.Kind != secrec.TxSecret {
		return nil, nil, nil, fmt.Errorf("the carrier would be admitted as a %s", a.Kind)
	}
	if len(beef) > e.Opts.ObjectBound {
		return nil, nil, nil, fmt.Errorf("the carrier's BEEF is %d bytes, over the object bound of %d (a smaller tree_count)", len(beef), e.Opts.ObjectBound)
	}
	return a, k, beef, nil
}

// Retries are the waits between the tries of a submission to the facade.
var Retries = limits.Retries

// Short is a txid's first 12 digits.
func Short(txid string) string { return vread.Short(txid) }

// publish submits a persisted object by the configured mode, once its
// NotBefore has passed. A mined object reaches every host named, on the
// plane too; a carrier in unicast reaches the quorum.
func (e *Engine) publish(ctx context.Context, p state.Pending) error {
	if wait := time.Until(time.Unix(p.NotBefore, 0)); p.NotBefore > 0 && wait > 0 {
		e.note("%s %s: waiting %s, the propagation delay, so the hosts' headers have its block", p.Kind, Short(p.Txid), wait.Round(time.Second))
		if err := e.Sleep(ctx, wait); err != nil {
			return err
		}
	}
	beef, err := hex.DecodeString(p.Beef)
	if err != nil {
		return fmt.Errorf("%s %s: persisted BEEF: %w", p.Kind, p.Txid, err)
	}
	topic := secrec.Topic(p.Crypt)
	what := fmt.Sprintf("%s %s", p.Kind, Short(p.Txid))
	confirm := e.confirm(p)
	if e.Legs.Hosts != nil {
		need := 0
		if p.Mined() {
			need = len(e.Legs.Hosts.Hosts)
		}
		o := e.Legs.Hosts.Send(ctx, what, topic, beef, need, confirm)
		if err := o.Err(); err != nil {
			return fmt.Errorf("%s: publish: %w; it is persisted and the next command publishes it", what, err)
		}
		return nil
	}
	if err := e.submitFacade(ctx, what, topic, beef); err != nil {
		return err
	}
	if p.Mined() && e.Legs.Direct != nil {
		o := e.Legs.Direct.Send(ctx, what, topic, beef, len(e.Legs.Direct.Hosts), confirm)
		if err := o.Err(); err != nil {
			return fmt.Errorf("%s: a mined object reaches every host named, off the plane too: %w; it is persisted and the next command publishes it", what, err)
		}
	}
	e.confirmOnPlane(ctx, what, topic, beef, confirm)
	return nil
}

// confirmOnPlane confirms an object at every host the publisher names, once
// the facade took it, and offers it again, directly, to a host the plane
// did not deliver it to (spec section 13). Every object is answered by a
// free class as soon as a host holds it, so a host that still lacks it
// after PlaneWait was missed: the plane repairs loss within its window, and
// a carrier nobody confirms would leave one host unable to answer a reader.
// A direct copy that races the plane's is a duplicate and harmless. A host
// that cannot be asked, or does not take it, is noted and left to fill.
func (e *Engine) confirmOnPlane(ctx context.Context, what, topic string, beef []byte, confirm unicast.Confirm) {
	rd := e.Legs.Reader
	if rd == nil || confirm == nil {
		return
	}
	for _, host := range rd.Hosts {
		held, asked := false, true
		for i := 0; ; i++ {
			ok, err := confirm(ctx, host)
			if err != nil {
				e.note("%s: host %s could not be asked whether it holds it: %v", what, host, err)
				asked = false
				break
			}
			if ok {
				held = true
				break
			}
			if i == len(limits.PlaneWait) || e.Sleep(ctx, limits.PlaneWait[i]) != nil {
				break
			}
		}
		if held || !asked {
			continue
		}
		set := &unicast.Set{Hosts: []string{host}, Need: 1, Retries: Retries, HTTP: rd.HTTP, Note: e.Note}
		if err := set.Send(ctx, what, topic, beef, 1, confirm).Err(); err != nil {
			e.note("%s: host %s lacks it after the plane's delivery and did not take it directly: %v (bsecret fill offers it again)", what, host, err)
			continue
		}
		e.note("%s: host %s lacked it after the plane's delivery; offered directly and confirmed", what, host)
	}
}

func (e *Engine) submitFacade(ctx context.Context, what, topic string, beef []byte) error {
	var err error
	for i := 0; ; i++ {
		var res publish.Result
		res, err = e.Legs.Facade.Submit(ctx, topic, beef)
		if err == nil {
			if res.Duplicate {
				e.note("%s: the facade admitted nothing: it holds this already, or refused it", what)
			}
			return nil
		}
		if i == len(Retries) || ctx.Err() != nil {
			break
		}
		e.note("%s: publish failed (%v); retrying", what, err)
		if err := e.Sleep(ctx, Retries[i]); err != nil {
			return err
		}
	}
	return fmt.Errorf("%s: publish: %w; it is persisted and the next command publishes it", what, err)
}

// confirm is the lookup that shows a host took p (spec section 13): the
// version class for a carrier, the vault-seq class for a token, the sweep
// class for a sweep.
func (e *Engine) confirm(p state.Pending) unicast.Confirm {
	if e.Legs.Reader == nil {
		return nil
	}
	var q vread.Query
	switch p.Kind {
	case state.KindSecret:
		q = vread.Query{"crypt": p.Crypt, "org": p.Org, "vault": p.Vault, "secret": p.Secret, "version": vread.Seq(p.Version)}
	case state.KindToken:
		q = vread.Query{"crypt": p.Crypt, "org": p.Org, "vault": p.Vault, "seq": vread.Seq(p.Seq)}
	case state.KindSweep:
		q = vread.Query{"crypt": p.Crypt, "spent": p.Outpoint}
	default:
		return nil
	}
	return func(ctx context.Context, host string) (bool, error) {
		return e.Legs.Reader.Held(ctx, host, q, p.Txid)
	}
}

// queue persists p in the outbox and publishes it, removing it once
// published.
func (e *Engine) queue(ctx context.Context, p state.Pending) error {
	if !e.St.Queued(p.Txid) {
		e.St.Outbox = append(e.St.Outbox, p)
	}
	if err := e.St.Save(); err != nil {
		return err
	}
	if err := e.publish(ctx, p); err != nil {
		return err
	}
	e.done(p)
	return e.St.Save()
}

// OrgKey is the owner's identity key, compressed.
func (e *Engine) OrgKey() []byte { return e.Signer.Identity.Compressed() }

func (e *Engine) orgHex() string { return e.Signer.IdentityHex() }

// alreadyKnown reports a node's answer for a transaction it already holds.
func alreadyKnown(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "already")
}

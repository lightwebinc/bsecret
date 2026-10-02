package vectors

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/spv"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/bsv-blockchain/go-sdk/util"
	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/lightwebinc/bcommon/carrier"
	"github.com/lightwebinc/bcommon/mint"
	"github.com/lightwebinc/bcommon/pushdrop"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// OtherCrypt is a well-formed crypt that is not the vectors' topic.
const OtherCrypt = "other_crypt_qwertyuiop"

// Headers is the test chain's block headers: a merkle root per height. It is
// the chain tracker the transaction vectors are admitted against.
type Headers map[uint32]chainhash.Hash

// IsValidRootForHeight holds root to the one the test chain has at height.
func (h Headers) IsValidRootForHeight(_ context.Context, root *chainhash.Hash, height uint32) (bool, error) {
	want, ok := h[height]
	return ok && root != nil && *root == want, nil
}

// CurrentHeight is the highest height held.
func (h Headers) CurrentHeight(context.Context) (uint32, error) {
	var top uint32
	for k := range h {
		top = max(top, k)
	}
	return top, nil
}

// unproven is a height nothing is mined at: a proof there verifies against no
// header the test chain holds.
const unproven = 999

// chain mines transactions into blocks at successive heights.
type chain struct {
	height  uint32
	headers Headers
}

func fixedHash(b byte) *chainhash.Hash {
	h := chainhash.Hash(bytes.Repeat([]byte{b}, 32))
	return &h
}

// mine proves tx at offset 1 of a block of two beside a fixed sibling.
func (c *chain) mine(tx *transaction.Transaction) *transaction.Transaction {
	c.height++
	t := true
	tx.MerklePath = transaction.NewMerklePath(c.height, [][]*transaction.PathElement{{
		{Offset: 0, Hash: fixedHash(0x33)},
		{Offset: 1, Hash: tx.TxID(), Txid: &t},
	}})
	c.root(tx)
	return tx
}

// mineTogether proves a and b in one block of four, at offsets 1 and 2, each
// with its own minimal path.
func (c *chain) mineTogether(a, b *transaction.Transaction) {
	c.height++
	t := true
	s0, s3 := fixedHash(0x35), fixedHash(0x36)
	left := chainhash.DoubleHashH(append(append([]byte{}, s0[:]...), a.TxID()[:]...))
	right := chainhash.DoubleHashH(append(append([]byte{}, b.TxID()[:]...), s3[:]...))
	a.MerklePath = transaction.NewMerklePath(c.height, [][]*transaction.PathElement{
		{{Offset: 0, Hash: s0}, {Offset: 1, Hash: a.TxID(), Txid: &t}},
		{{Offset: 1, Hash: &right}},
	})
	b.MerklePath = transaction.NewMerklePath(c.height, [][]*transaction.PathElement{
		{{Offset: 2, Hash: b.TxID(), Txid: &t}, {Offset: 3, Hash: s3}},
		{{Offset: 0, Hash: &left}},
	})
	c.root(a)
}

// wide proves tx at offset 2 of a block of four with a path that also holds
// the leaf at offset 0, which the proof does not need.
func (c *chain) wide(tx *transaction.Transaction) *transaction.Transaction {
	c.height++
	l0, l1, l3 := fixedHash(0x30), fixedHash(0x31), fixedHash(0x34)
	pair := chainhash.DoubleHashH(append(append([]byte{}, l0[:]...), l1[:]...))
	t := true
	tx.MerklePath = transaction.NewMerklePath(c.height, [][]*transaction.PathElement{
		{{Offset: 0, Hash: l0}, {Offset: 2, Hash: tx.TxID(), Txid: &t}, {Offset: 3, Hash: l3}},
		{{Offset: 0, Hash: &pair}},
	})
	c.root(tx)
	return tx
}

func (c *chain) root(tx *transaction.Transaction) {
	root, err := tx.MerklePath.ComputeRoot(tx.TxID())
	if err != nil {
		panic(err)
	}
	c.headers[c.height] = *root
}

// actor is one test identity's wallet and keys for transactions.
type actor struct {
	p       Party
	w       wallet.Interface
	fee     *ec.PrivateKey // [1, "bsecret"] fund, counterparty self
	feeLock *script.Script
}

func newActor(p Party) (*actor, error) {
	a := &actor{p: p, w: p.Wallet()}
	var err error
	d := wallet.NewKeyDeriver(p.Priv)
	if a.fee, err = d.DerivePrivateKey(secrec.Protocol, secrec.KeyFund, wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}); err != nil {
		return nil, err
	}
	addr, err := script.NewAddressFromPublicKey(a.fee.PubKey(), false)
	if err != nil {
		return nil, err
	}
	a.feeLock, err = p2pkh.Lock(addr)
	return a, err
}

func (a *actor) feeUnlocker() transaction.UnlockingScriptTemplate {
	u, err := p2pkh.Unlock(a.fee, nil)
	if err != nil {
		panic(err)
	}
	return u
}

func (a *actor) unlocker(d pushdrop.Derivation) transaction.UnlockingScriptTemplate {
	return d.Unlocker(context.Background(), a.w, "")
}

func (a *actor) lock(d pushdrop.Derivation, sign bool, fields ...[]byte) *script.Script {
	s, err := d.Lock(context.Background(), a.w, "", fields, sign)
	if err != nil {
		panic(err)
	}
	return s
}

func (a *actor) key(d pushdrop.Derivation) *ec.PublicKey { return mustKey(d, a.p.Priv.PubKey()) }

// derivedPriv is the actor's private key under d, counterparty anyone.
func (a *actor) derivedPriv(d pushdrop.Derivation) *ec.PrivateKey {
	k, err := wallet.NewKeyDeriver(a.p.Priv).DerivePrivateKey(d.Protocol, d.KeyID, pushdrop.Anyone())
	if err != nil {
		panic(err)
	}
	return k
}

func mustKey(d pushdrop.Derivation, identity *ec.PublicKey) *ec.PublicKey {
	k, err := d.ExpectedLockingKey(identity)
	if err != nil {
		panic(err)
	}
	return k
}

func scr(b []byte) *script.Script { s := script.Script(b); return &s }

func out(sats uint64, s *script.Script) *transaction.TransactionOutput {
	return &transaction.TransactionOutput{Satoshis: sats, LockingScript: s}
}

func params(d pushdrop.Derivation) carrier.Params {
	return carrier.Params{Derivation: d, FundingTag: secrec.TagFunding,
		ValidatePayload: func([]byte) error { return nil }, ErrIdentity: secrec.ErrIdentity}
}

// txEnv is everything the transaction vectors are built from: a real chain
// tree, a real secret tree, and one vault whose tokens and carriers are real
// transactions, so that every txid a record names is a transaction's.
type txEnv struct {
	ctx  context.Context
	o, d *actor // the organisation, and a stranger
	c    *chain
	coin *transaction.Transaction
	sec  *transaction.Transaction // the secret tree, funding carriers
	tree *transaction.Transaction // the chain tree, paying for first tokens
	misc *transaction.Transaction // outputs nothing may be funded from

	v        *Scenario                           // the vault, keyed to the real chain tree
	carriers map[string]*transaction.Transaction // by version key
	funded   map[string]uint32                   // the secret-tree output each carrier spends
	tokens   []*transaction.Transaction          // the vault's tokens, seq 0 to 3
	second   *transaction.Transaction            // another vault's first token, on chain-tree output 1
	loose    *transaction.Transaction            // a token output at seq 7 that spends no predecessor
	onLoose  *transaction.Transaction            // seq 8 built on it
	unlisted *Version                            // a version no token lists
	sweep    *transaction.Transaction
	held     map[transaction.Outpoint]bool
	coinNext uint32
}

// nextFee hands out the next coin output for a fee input.
func (e *txEnv) nextFee() mint.Input {
	v := e.coinNext
	e.coinNext++
	if int(v) >= len(e.coin.Outputs) {
		panic("the coin has no output left")
	}
	return mint.Input{Tx: e.coin, Vout: v, Unlocker: e.o.feeUnlocker()}
}

func newTxEnv(s *Scenario) (*txEnv, error) {
	e := &txEnv{ctx: context.Background(), c: &chain{height: 800, headers: Headers{}},
		carriers: map[string]*transaction.Transaction{}, funded: map[string]uint32{}}
	var err error
	if e.o, err = newActor(Org); err != nil {
		return nil, err
	}
	if e.d, err = newActor(Dave); err != nil {
		return nil, err
	}
	return e, e.build(s)
}

// fundingTree mints a funding tree of n outputs of 1000 under d, mined.
func (e *txEnv) fundingTree(d pushdrop.Derivation, n int) (*transaction.Transaction, error) {
	lock, err := carrier.FundingLock(e.ctx, e.o.w, "", params(d))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(*lock, secrec.FundingScript(e.o.key(d))) {
		return nil, fmt.Errorf("bcommon's funding lock is not the funding script")
	}
	t, err := mint.FundingTree(lock, n, 1000, e.nextFee(), e.o.feeLock, mint.DefaultFees)
	if err != nil {
		return nil, err
	}
	return e.c.mine(t), nil
}

// token builds a vault token: the lock under vault of [tag, record], signed,
// spending prev (the predecessor or a chain-tree output) and a fee coin.
func (e *txEnv) token(record []byte, prev *transaction.Transaction, vout uint32) (*transaction.Transaction, error) {
	return mintRaw(e, e.o.lock(secrec.VaultDerivation, true, secrec.TagVault, record), 1, prev, vout)
}

// mintRaw builds a token transaction with an arbitrary lock and value,
// spending prev:vout (signed for what it is) and a fee coin.
func mintRaw(e *txEnv, lock *script.Script, sats uint64, prev *transaction.Transaction, vout uint32) (*transaction.Transaction, error) {
	return mint.Transition(lock, sats, &mint.Input{Tx: prev, Vout: vout, Unlocker: e.prevUnlocker(prev, vout)}, e.nextFee(), e.o.feeLock, mint.DefaultFees)
}

// prevUnlocker signs for an output of prev: a token under vault, a funding
// output under the key it is locked to, anything else under the fund key.
func (e *txEnv) prevUnlocker(prev *transaction.Transaction, vout uint32) transaction.UnlockingScriptTemplate {
	s := *prev.Outputs[vout].LockingScript
	if secrec.Classify(s) == secrec.KindVault {
		return e.o.unlocker(secrec.VaultDerivation)
	}
	for _, d := range []pushdrop.Derivation{secrec.ChainDerivation, secrec.SecretDerivation} {
		if bytes.Equal(s, secrec.FundingScript(e.o.key(d))) {
			return e.o.unlocker(d)
		}
	}
	return e.o.feeUnlocker()
}

// carry mints the carrier of a version on secret-tree output vout.
func (e *txEnv) carry(v *Version, vout uint32) (*transaction.Transaction, error) {
	k, err := carrier.Mint(e.ctx, e.o.w, "", params(secrec.SecretDerivation), v.Raw, e.sec, vout)
	if err != nil {
		return nil, err
	}
	e.carriers[vkey(v.Name, v.Number)], e.funded[vkey(v.Name, v.Number)] = k, vout
	return k, nil
}

// next mints, and mines unless hold is set, the vault's next token.
func (e *txEnv) next(epoch uint64, create, update []*Version, retire []string, hold bool) (*transaction.Transaction, error) {
	raw, v, err := e.v.record(epoch, create, update, retire)
	if err != nil {
		return nil, err
	}
	var t *transaction.Transaction
	if v.Seq == 0 {
		t, err = e.token(raw, e.tree, 0)
	} else {
		t, err = e.token(raw, e.tokens[v.Seq-1], 0)
	}
	if err != nil {
		return nil, err
	}
	if !hold {
		e.c.mine(t)
	}
	e.v.push(v, raw, [32]byte(*t.TxID()), e.c.height)
	e.tokens = append(e.tokens, t)
	return t, nil
}

func (e *txEnv) build(s *Scenario) error {
	// The coin: outputs paying the organisation's fund key, from nowhere,
	// mined.
	e.coin = transaction.NewTransaction()
	e.coin.AddInput(&transaction.TransactionInput{SourceTXID: fixedHash(0x11), UnlockingScript: &script.Script{},
		SequenceNumber: transaction.MaxTxInSequenceNum})
	for range 128 {
		e.coin.AddOutput(out(50000, e.o.feeLock))
	}
	e.c.mine(e.coin)
	var err error
	if e.sec, err = e.fundingTree(secrec.SecretDerivation, 16); err != nil {
		return err
	}
	if e.tree, err = e.fundingTree(secrec.ChainDerivation, 6); err != nil {
		return err
	}

	// misc: outputs a secret carrier must not be funded from, each spent by
	// one signature: a bare pay-to-public-key under the secret key, the
	// funding tag under the secret key with a field signature, another tag
	// under the secret key, and a funding output under the vault key.
	e.misc = transaction.NewTransaction()
	e.misc.AddInputFromTx(e.coin, e.nextFee().Vout, e.o.feeUnlocker())
	sk := e.o.key(secrec.SecretDerivation)
	bare := script.Script(append(append([]byte{33}, sk.Compressed()...), script.OpCHECKSIG))
	e.misc.AddOutput(out(1000, &bare))
	e.misc.AddOutput(out(1000, e.o.lock(secrec.SecretDerivation, true, secrec.TagFunding)))
	e.misc.AddOutput(out(1000, e.o.lock(secrec.SecretDerivation, false, []byte{'s', 'e', 0x04})))
	e.misc.AddOutput(out(1000, scr(secrec.FundingScript(e.o.key(secrec.VaultDerivation)))))
	e.misc.AddOutput(out(45500, e.o.feeLock))
	if err := e.misc.Sign(); err != nil {
		return err
	}
	e.c.mine(e.misc)

	// The vault: its identifier is the hash of chain-tree output 0, which
	// its first token spends. It shares the owner's commitment record with
	// the record vectors' vault.
	e.v = &Scenario{Versions: map[string]*Version{}, set: map[[32]byte]secrec.Current{}, Labels: secrec.DefaultLabels,
		Name: "Mined vault", Used: s.Used}
	e.v.Genesis = [32]byte(*e.tree.TxID())
	e.v.VaultID = secrec.VaultID(e.v.Genesis, 0)
	const seg = 16384
	n := uint64(0)
	mk := func(name string, ver, epoch uint64, lbl string, value []byte, inline bool, vout uint32) (*Version, error) {
		n++
		v, err := e.v.version(name, ver, epoch, lbl, value, "text/plain", seg, inline, Created+3600+60*n)
		if err != nil {
			return nil, err
		}
		_, err = e.carry(v, vout)
		return v, err
	}

	// Epoch 0. seq 0 creates two secrets; seq 1 updates one and creates a
	// large one whose ciphertext is not carried.
	api1, err := mk("tx/api-token", 1, 0, "internal", []byte("tok_1001_example"), true, 0)
	if err != nil {
		return err
	}
	db1, err := mk("tx/db-password", 1, 0, "confidential", []byte("a password in a mined vault"), true, 1)
	if err != nil {
		return err
	}
	if _, err = e.next(0, []*Version{api1, db1}, nil, nil, false); err != nil {
		return err
	}
	api2, err := mk("tx/api-token", 2, 0, "internal", []byte("tok_1002_example"), true, 2)
	if err != nil {
		return err
	}
	tls1, err := mk("tx/tls-key", 1, 0, "restricted", bigValue(700), false, 3)
	if err != nil {
		return err
	}
	t1, err := e.next(0, []*Version{tls1}, []*Version{api2}, nil, true)
	if err != nil {
		return err
	}
	// The group begins epoch 1. seq 2 acknowledges it and re-keys one
	// secret, leaving two stale; it is mined in the same block as seq 1.
	db2, err := mk("tx/db-password", 2, 1, "confidential", []byte("a new password after the removal"), true, 4)
	if err != nil {
		return err
	}
	t2, err := e.next(1, nil, []*Version{db2}, nil, true)
	if err != nil {
		return err
	}
	e.c.mineTogether(t1, t2)
	e.v.Heights[1], e.v.Heights[2] = e.c.height, e.c.height
	// seq 3 clears the debt: one more secret re-keyed, the large one
	// retired.
	api3, err := mk("tx/api-token", 3, 1, "internal", []byte("tok_1003_example"), true, 5)
	if err != nil {
		return err
	}
	if _, err = e.next(1, nil, []*Version{api3}, []string{"tx/tls-key"}, false); err != nil {
		return err
	}
	f := secrec.NewVaultFold()
	for i, v := range e.v.Vaults {
		if st := f.Apply(v); st != secrec.StatusConsistent {
			return fmt.Errorf("mined vault seq %d folds %s", i, st)
		}
	}
	// A version published and never listed.
	if e.unlisted, err = mk("tx/ssh-key", 1, 1, "restricted", []byte("published, not yet listed"), true, 6); err != nil {
		return err
	}

	// Another vault of the same owner, on chain-tree output 1.
	other := &Scenario{Versions: map[string]*Version{}, set: map[[32]byte]secrec.Current{}, Labels: secrec.DefaultLabels,
		Name: "Second vault", Used: s.Used}
	other.Genesis = e.v.Genesis
	other.VaultID = secrec.VaultID(other.Genesis, 1)
	raw, _, err := other.record(0, nil, nil, nil)
	if err != nil {
		return err
	}
	if e.second, err = e.token(raw, e.tree, 1); err != nil {
		return err
	}
	e.c.mine(e.second)

	// A well-formed token output at seq 7 in a mined transaction that
	// spends no predecessor, and a token at seq 8 built on it: a chain that
	// never reaches a first token.
	lv := *e.v.Vaults[3]
	lv.Seq, lv.Prev, lv.Create, lv.Update, lv.Retire = 7, label("txid/never-admitted"), []secrec.Entry{}, []secrec.Entry{}, [][32]byte{}
	lraw, err := lv.Encode()
	if err != nil {
		return err
	}
	if e.loose, err = mint.Transition(e.o.lock(secrec.VaultDerivation, true, secrec.TagVault, lraw), 1, nil, e.nextFee(), e.o.feeLock, mint.DefaultFees); err != nil {
		return err
	}
	e.c.mine(e.loose)
	nv := lv
	nv.Seq, nv.Prev, nv.Created = 8, [32]byte(*e.loose.TxID()), lv.Created+600
	nraw, err := nv.Encode()
	if err != nil {
		return err
	}
	if e.onLoose, err = e.token(nraw, e.loose, 0); err != nil {
		return err
	}
	e.c.mine(e.onLoose)

	// The sweep: secret-tree outputs 1 (the funding outpoint of the first
	// db-password version) and 15 (unused); the tree pays the fee and the
	// tombstone takes the rest.
	if e.sweep, err = carrier.Sweep(e.ctx, e.o.w, "", params(secrec.SecretDerivation), e.sec, []uint32{1, 15}, nil, 0, nil, e.o.feeLock, 1, 250); err != nil {
		return err
	}
	e.c.mine(e.sweep)

	// What the topic holds once the admitted cases are admitted: each
	// carrier's record output, each token output and the sweep's tombstone.
	e.held = map[transaction.Outpoint]bool{{Txid: *e.sweep.TxID(), Index: 0}: true}
	for _, k := range e.carriers {
		e.held[transaction.Outpoint{Txid: *k.TxID(), Index: 0}] = true
	}
	for _, t := range append(append([]*transaction.Transaction{}, e.tokens...), e.second, e.onLoose) {
		e.held[transaction.Outpoint{Txid: *t.TxID(), Index: 0}] = true
	}
	return nil
}

// ---- helpers that build what the cases change ----

// flagUnlocker signs a single-signature input with key under another
// sighash type.
type flagUnlocker struct {
	key  *ec.PrivateKey
	flag sighash.Flag
}

func (u flagUnlocker) Sign(tx *transaction.Transaction, i uint32) (*script.Script, error) {
	d, err := tx.CalcInputSignatureHash(i, u.flag)
	if err != nil {
		return nil, err
	}
	sig, err := u.key.Sign(d)
	if err != nil {
		return nil, err
	}
	return scr(push(append(sig.Serialize(), byte(u.flag)))), nil
}

func (u flagUnlocker) EstimateLength(*transaction.Transaction, uint32) uint32 { return 74 }

func signAll(tx *transaction.Transaction) *transaction.Transaction {
	if err := tx.Sign(); err != nil {
		panic(err)
	}
	return tx
}

// carrierFrom builds a carrier by hand: one input spending src:vout, the
// given outputs, the carrier's locktime and sequence, signed.
func carrierFrom(src *transaction.Transaction, vout uint32, u transaction.UnlockingScriptTemplate, outs ...*transaction.TransactionOutput) *transaction.Transaction {
	tx := transaction.NewTransaction()
	tx.LockTime = carrier.LockTime
	tx.AddInputFromTx(src, vout, u)
	tx.Inputs[0].SequenceNumber = carrier.Sequence
	for _, o := range outs {
		tx.AddOutput(o)
	}
	return signAll(tx)
}

func derInt(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) == 0 || b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return b
}

// highSBytes rewrites a strict low-S DER signature to its high-S twin.
func highSBytes(der []byte) []byte {
	sig, err := ec.ParseDERSignature(der)
	if err != nil {
		panic(err)
	}
	r, s := derInt(sig.R), derInt(new(big.Int).Sub(ec.S256().N, sig.S))
	body := append(append([]byte{0x02, byte(len(r))}, r...), append([]byte{0x02, byte(len(s))}, s...)...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

// cloneTx copies tx, keeping each input's source transaction.
func cloneTx(tx *transaction.Transaction) *transaction.Transaction {
	cp := &transaction.Transaction{Version: tx.Version, LockTime: tx.LockTime, MerklePath: tx.MerklePath}
	for _, in := range tx.Inputs {
		c := *in
		cp.Inputs = append(cp.Inputs, &c)
	}
	for _, o := range tx.Outputs {
		c := *o
		cp.Outputs = append(cp.Outputs, &c)
	}
	return cp
}

// rewriteUnlock replaces input i's unlocking script with f of its one push.
func rewriteUnlock(tx *transaction.Transaction, i int, f func(sig []byte) []byte) *transaction.Transaction {
	cp := cloneTx(tx)
	ch, err := tx.Inputs[i].UnlockingScript.Chunks()
	if err != nil {
		panic(err)
	}
	cp.Inputs[i].UnlockingScript = scr(f(ch[0].Data))
	cp.MerklePath = nil
	return cp
}

// spendFrom returns tx with input 0's source replaced by src, the same
// transaction under another proof (or none).
func spendFrom(tx, src *transaction.Transaction) *transaction.Transaction {
	cp := cloneTx(tx)
	cp.Inputs[0].SourceTransaction = src
	return cp
}

// reproved is tx under another proof.
func reproved(tx *transaction.Transaction, mp *transaction.MerklePath) *transaction.Transaction {
	cp := cloneTx(tx)
	cp.MerklePath = mp
	return cp
}

func push(d []byte) []byte {
	s := &script.Script{}
	if err := s.AppendPushData(d); err != nil {
		panic(err)
	}
	return *s
}

// push4 pushes d with OP_PUSHDATA4, which is never the minimal push of
// anything a record or a tag holds.
func push4(d []byte) []byte {
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(d)))
	return append(append([]byte{script.OpPUSHDATA4}, n[:]...), d...)
}

// fieldSigOf rebuilds a signed PushDrop's fields under key with its field
// signature replaced by f(signature), canonically otherwise.
func fieldSigOf(s *script.Script, key *ec.PublicKey, nfields int, f func([]byte) []byte) *script.Script {
	fields, _ := pushdrop.Fields(*s)
	return scr(secrec.PushDropScript(key, fields[:nfields], f(fields[nfields])))
}

func sigOf(s *script.Script, nfields int) []byte {
	fields, _ := pushdrop.Fields(*s)
	return fields[nfields]
}

func signWith(k *ec.PrivateKey, msg []byte) func([]byte) []byte {
	return func([]byte) []byte {
		d := sha256.Sum256(msg)
		sg, err := k.Sign(d[:])
		if err != nil {
			panic(err)
		}
		return sg.Serialize()
	}
}

// beefV1 writes a BEEF V1 by hand: the BUMPs, then each transaction with the
// index of its BUMP (-1 for none), in the order given; the last is the
// subject.
func beefV1(bumps []*transaction.MerklePath, txs []*transaction.Transaction, bumpOf []int) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(0xEFBE0001))
	b.Write(util.VarInt(uint64(len(bumps))).Bytes())
	for _, m := range bumps {
		b.Write(m.Bytes())
	}
	b.Write(util.VarInt(uint64(len(txs))).Bytes())
	for i, tx := range txs {
		b.Write(tx.Bytes())
		if bumpOf[i] < 0 {
			b.WriteByte(0)
			continue
		}
		b.WriteByte(1)
		b.Write(util.VarInt(uint64(bumpOf[i])).Bytes())
	}
	return b.Bytes()
}

// beefV2 writes a BEEF V2 (BRC-96) by hand: format 0 raw, 1 raw with a BUMP
// index, 2 txid only (a nil transaction at that place, its txid in ids).
func beefV2(bumps []*transaction.MerklePath, txs []*transaction.Transaction, bumpOf []int, ids map[int][32]byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint32(0xEFBE0002))
	b.Write(util.VarInt(uint64(len(bumps))).Bytes())
	for _, m := range bumps {
		b.Write(m.Bytes())
	}
	b.Write(util.VarInt(uint64(len(txs))).Bytes())
	for i, tx := range txs {
		if id, ok := ids[i]; ok {
			b.WriteByte(2)
			b.Write(id[:])
			continue
		}
		if bumpOf[i] < 0 {
			b.WriteByte(0)
			b.Write(tx.Bytes())
			continue
		}
		b.WriteByte(1)
		b.Write(util.VarInt(uint64(bumpOf[i])).Bytes())
		b.Write(tx.Bytes())
	}
	return b.Bytes()
}

// atomic wraps a BEEF V1 or V2 as Atomic BEEF (BRC-95) of subject.
func atomic(subject *chainhash.Hash, inner []byte) []byte {
	out := []byte{0x01, 0x01, 0x01, 0x01}
	out = append(out, subject[:]...)
	return append(out, inner...)
}

func tokenBEEF(t, parent *transaction.Transaction) []byte {
	b, err := secrec.TokenBEEF(t, parent)
	if err != nil {
		panic(err)
	}
	return b
}

// scriptsVerify runs the interpreter over tx's own inputs, each against the
// output it spends.
func scriptsVerify(ctx context.Context, tx *transaction.Transaction) bool {
	cp := tx.ShallowClone()
	cp.MerklePath = nil
	ok, err := spv.Verify(ctx, cp, &spv.GullibleHeadersClient{}, nil)
	return err == nil && ok
}

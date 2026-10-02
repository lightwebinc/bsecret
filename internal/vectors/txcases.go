package vectors

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	sighash "github.com/bsv-blockchain/go-sdk/transaction/sighash"

	"github.com/lightwebinc/bcommon/carrier"
	"github.com/lightwebinc/bcommon/cbor"
	"github.com/lightwebinc/bcommon/mint"
	"github.com/lightwebinc/bcommon/pushdrop"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// The frozen-list rows the transaction vectors pin (docs/frozen.md section
// 2). Every refused case names the row whose rule refuses it.
const (
	rowCarrier   = "carrier shape"
	rowToken     = "vault token shape"
	rowCanonical = "script canonicality"
	rowSigs      = "signatures"
	rowOneClaim  = "one claiming output"
	rowSweep     = "sweep"
)

type admitJSON struct {
	Kind        string   `json:"kind"`
	Outputs     []int    `json:"outputsToAdmit"`
	Retain      []int    `json:"coinsToRetain"`
	Commitment  string   `json:"commitment,omitempty"`
	Record      string   `json:"record,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	ContentID   string   `json:"contentId,omitempty"`
	FundingTxid string   `json:"fundingTxid,omitempty"`
	FundingVout *int     `json:"fundingVout,omitempty"`
	Seq         *uint64  `json:"seq,omitempty"`
	Parent      string   `json:"parentTxid,omitempty"`
	PredSeq     *uint64  `json:"predecessorSeq,omitempty"`
	Spends      string   `json:"spends,omitempty"`
	Spent       []string `json:"spent,omitempty"`
}

type coinJSON struct {
	InputIndex int    `json:"inputIndex"`
	Txid       string `json:"txid"`
	Vout       uint32 `json:"vout"`
}

type txJSON struct {
	Name  string     `json:"name"`
	Note  string     `json:"note"`
	Rule  string     `json:"rule,omitempty"`
	Txid  string     `json:"txid"`
	RawTx string     `json:"rawTx"`
	BEEF  string     `json:"beef"`
	Coins []coinJSON `json:"previousCoins"`
	// MaxSweepInputs is set where a case admits under a host sweep bound
	// other than the default.
	MaxSweepInputs int        `json:"maxSweepInputs,omitempty"`
	Scripts        bool       `json:"scriptsVerify"`
	Verdict        string     `json:"verdict"`
	Reason         string     `json:"reason,omitempty"`
	Admits         *admitJSON `json:"admits,omitempty"`
}

type txCase struct {
	name, note, rule string
	tx               *transaction.Transaction
	beef             []byte // the BEEF as submitted; the Atomic BEEF of tx when nil
	reason           string // "" admits
	held             []int  // overrides the computed previous coins when not nil
	maxSweep         int
}

// heldInputs is the previous coins the engine hands the topic manager for tx.
func (e *txEnv) heldInputs(tx *transaction.Transaction) []int {
	held := []int{}
	for i, in := range tx.Inputs {
		if e.held[transaction.Outpoint{Txid: *in.SourceTXID, Index: in.SourceTxOutIndex}] {
			held = append(held, i)
		}
	}
	return held
}

func outpointString(o transaction.Outpoint) string {
	return fmt.Sprintf("%s.%d", o.Txid.String(), o.Index)
}

func admission(a *secrec.Admission) *admitJSON {
	j := &admitJSON{Kind: a.Kind.String(), Outputs: append([]int{}, a.Outputs...), Retain: append([]int{}, a.Retain...)}
	if c := a.Carrier; c != nil {
		v := int(c.Funding.Index)
		j.Commitment, j.Record, j.Owner, j.ContentID = hx(c.Commitment[:]), hx(c.Record), hx(c.Owner), hx(c.ContentID[:])
		j.FundingTxid, j.FundingVout = c.Funding.Txid.String(), &v
	}
	if t := a.Token; t != nil {
		seq := t.Vault.Seq
		j.Seq, j.Record, j.Parent, j.Spends = &seq, hx(t.Record), displayHex(a.Parent), outpointString(a.Spends)
		if a.Predecessor != nil {
			p := a.Predecessor.Vault.Seq
			j.PredSeq = &p
		}
	}
	for _, o := range a.Spent {
		j.Spent = append(j.Spent, outpointString(o))
	}
	return j
}

// recordWith re-encodes a record with key k set to v, whatever its rules
// say: the record rules are what refuse it.
func recordWith(rec []byte, k uint64, v cbor.Value) []byte { return mutate(rec, k, v) }

// cases builds every transaction case.
func (e *txEnv) cases() ([]txCase, error) {
	o := e.o
	sd := secrec.SecretDerivation
	ka := e.carriers["tx/api-token@1"]
	lockA := ka.Outputs[0].LockingScript
	recA, _ := pushdrop.FirstPush(*lockA)
	sUnlock := o.unlocker(sd)
	sk := o.key(sd)
	var cs []txCase
	add := func(c txCase) { cs = append(cs, c) }

	// ---- admitted ----
	for _, k := range e.v.Order {
		v := e.v.Versions[k]
		how := "its ciphertext inline"
		if v.Rec.Inline == nil {
			how = "its ciphertext not carried, found by its hash"
		}
		add(txCase{name: "secret-carrier-" + fileName(v.Name)[3:] + fmt.Sprintf("-v%d", v.Number),
			note: fmt.Sprintf("version %d of %s, keyed under epoch %d, %s, spending secret-tree output %d", v.Number, v.Name, v.Epoch, how, e.funded[k]), tx: e.carriers[k]})
	}
	v1, err := ka.BEEF()
	if err != nil {
		return nil, err
	}
	add(txCase{name: "secret-carrier-beef-v1", note: "secret-carrier-api-token-v1 submitted as BEEF V1 (BRC-62) rather than Atomic BEEF: the same two transactions and one proof", tx: ka, beef: v1})
	t0, t1, t2, t3 := e.tokens[0], e.tokens[1], e.tokens[2], e.tokens[3]
	add(txCase{name: "vault-token-create", note: "the vault's seq 0, creating two secrets under epoch 0 and spending chain-tree output 0, whose outpoint hashes to the vault identifier; its BEEF is BEEF V1 of the chain tree then the token, each with its own path", tx: t0, beef: tokenBEEF(t0, e.tree)})
	add(txCase{name: "vault-token-second-vault", note: "another vault of the same owner, empty at seq 0, spending chain-tree output 1: another outpoint, another identifier", tx: e.second, beef: tokenBEEF(e.second, e.tree)})
	add(txCase{name: "vault-token-update", note: "seq 1 updates one secret and creates one: it spends seq 0's token output, which the topic holds and retains; the predecessor is read from the parent in the BEEF", tx: t1, beef: tokenBEEF(t1, t0)})
	add(txCase{name: "vault-token-update-predecessor-not-held", note: "vault-token-update offered with no previous coins, as to a host that does not hold seq 0: admitted all the same (the index reports it pending)", tx: t1, beef: tokenBEEF(t1, t0), held: []int{}})
	add(txCase{name: "vault-token-rekey-same-block", note: "seq 2 acknowledges epoch 1 and re-keys one of three secrets, leaving two stale; it is mined in the same block as its parent (seq 1), so the BEEF holds one path merged as the SDK merges it, flagging exactly both txids", tx: t2, beef: tokenBEEF(t2, t1)})
	add(txCase{name: "vault-token-settle", note: "seq 3 re-keys one stale secret and retires the other: nothing is stale", tx: t3, beef: tokenBEEF(t3, t2)})
	add(txCase{name: "vault-token-v2", note: "vault-token-settle as a BEEF V2 (BRC-96)", tx: t3,
		beef: beefV2([]*transaction.MerklePath{t2.MerklePath, t3.MerklePath}, []*transaction.Transaction{t2, t3}, []int{0, 1}, nil)})
	alt, err := e.token(e.v.VaultRecs[3], t2, 0)
	if err != nil {
		return nil, err
	}
	alt = cloneTx(alt)
	alt.MerklePath = nil
	alt.AddInputFromTx(t2, 1, o.feeUnlocker())
	e.c.mine(signAll(alt))
	add(txCase{name: "vault-token-spends-parent-change-too", note: "seq 3's record in another transaction that spends its predecessor's token and also its change output: a token's other inputs pay its fee from any source and are not read, the parent's other outputs included", tx: alt, beef: tokenBEEF(alt, t2), held: []int{0}})
	add(txCase{name: "vault-token-on-unadmitted-parent", note: "seq 8 built on a mined transaction whose token output (seq 7) spends no predecessor and is itself refused (vault-token-no-predecessor): admitted, because the predecessor is read from the BEEF and not held to its own admission; the index never roots it", tx: e.onLoose, beef: tokenBEEF(e.onLoose, e.loose)})
	add(txCase{name: "sweep", note: "a mined sweep of secret-tree outputs 1 (the funding outpoint of db-password version 1) and 15: its tombstone, output 0, is admitted and both outpoints are recorded, which retracts that carrier", tx: e.sweep})
	add(txCase{name: "funding-tree-alone", note: "the secret tree, mined, published on its own: it claims nothing and its output 0 is funding-shaped, so it is indistinguishable from a sweep and is admitted as one (output 0 alone, its input's outpoint recorded)", tx: e.sec})
	add(txCase{name: "sweep-at-the-bound", note: "the sweep of two inputs under a host whose sweep bound is 2", tx: e.sweep, maxSweep: 2})

	// ---- carriers: shape, one claiming output ----
	two := carrierFrom(e.sec, 11, sUnlock, out(1000, lockA))
	two.AddInputFromTx(e.sec, 12, sUnlock)
	add(txCase{name: "carrier-two-inputs", note: "the api-token record output with a second funding input", rule: rowCarrier, tx: signAll(two), reason: "shape"})
	add(txCase{name: "carrier-two-outputs", note: "the record output with 999 and a second output of 1", rule: rowCarrier,
		tx: carrierFrom(e.sec, 0, sUnlock, out(999, lockA), out(1, o.feeLock)), reason: "shape"})
	lockB := e.carriers["tx/db-password@1"].Outputs[0].LockingScript
	add(txCase{name: "carrier-two-secrets", note: "two outputs each claim a secret", rule: rowOneClaim,
		tx: carrierFrom(e.sec, 0, sUnlock, out(500, lockA), out(500, lockB)), reason: "shape"})
	tokLock := t0.Outputs[0].LockingScript
	add(txCase{name: "carrier-secret-and-token", note: "one output claims a secret and another a vault token", rule: rowOneClaim,
		tx: carrierFrom(e.sec, 0, sUnlock, out(999, lockA), out(1, tokLock)), reason: "shape"})

	// ---- carriers: the BEEF ----
	bare := cloneTx(e.sec)
	bare.MerklePath = nil
	add(txCase{name: "carrier-beef-tree-unproven", note: "secret-carrier-api-token-v1 (same txid) with its funding tree unproven, so its BEEF also carries the tree's parent: refused, raising, so this BEEF cannot suppress the genuine one", rule: rowCarrier, tx: spendFrom(ka, bare), reason: "beef"})
	wide := e.c.wide(cloneTx(e.sec))
	add(txCase{name: "carrier-beef-proof-extra-leaf", note: "secret-carrier-api-token-v1 with its funding tree proven by a path holding a leaf the proof does not need", rule: rowCarrier, tx: spendFrom(ka, wide), reason: "beef"})
	add(txCase{name: "carrier-beef-extra-transaction", note: "secret-carrier-api-token-v1's BEEF with an unrelated mined transaction and its proof riding along", rule: rowCarrier,
		tx: ka, beef: beefV1([]*transaction.MerklePath{e.misc.MerklePath, e.sec.MerklePath}, []*transaction.Transaction{e.misc, e.sec, ka}, []int{0, 1, -1}), reason: "beef"})
	add(txCase{name: "carrier-beef-no-funding-tree", note: "secret-carrier-api-token-v1's BEEF without its funding tree", rule: rowCarrier,
		tx: ka, beef: beefV1(nil, []*transaction.Transaction{ka}, []int{-1}), reason: "beef"})
	add(txCase{name: "carrier-beef-txid-only", note: "secret-carrier-api-token-v1 in a BEEF V2 whose funding tree is a txid-only entry", rule: rowCarrier,
		tx: ka, beef: beefV2([]*transaction.MerklePath{e.sec.MerklePath}, []*transaction.Transaction{nil, ka}, []int{0, -1}, map[int][32]byte{0: [32]byte(*e.sec.TxID())}), reason: "beef"})
	badHash := recordWith(recA, secrec.SKHash, make([]byte, 32))
	add(txCase{name: "carrier-beef-before-record", note: "breaks the beef rule (funding tree unproven) and the record rules (an inline ciphertext that does not hash to hash): refused for the BEEF", rule: rowCarrier,
		tx: spendFrom(carrierFrom(e.sec, 0, sUnlock, out(1000, o.lock(sd, true, badHash))), bare), reason: "beef"})
	add(txCase{name: "carrier-shape-before-beef", note: "breaks the shape rule (two outputs) and the beef rule (funding tree unproven): refused for the shape", rule: rowCarrier,
		tx: spendFrom(carrierFrom(e.sec, 0, sUnlock, out(999, lockA), out(1, o.feeLock)), bare), reason: "shape"})

	// ---- carriers: the record, the crypt ----
	add(txCase{name: "carrier-record-content", note: "a secret record whose inline ciphertext does not hash to hash, signed", rule: rowCarrier,
		tx: carrierFrom(e.sec, 0, sUnlock, out(1000, o.lock(sd, true, badHash))), reason: "content"})
	add(txCase{name: "carrier-record-length", note: "a secret record without its ciphertext whose length is 2^27 + 1, above the bound", rule: rowCarrier,
		tx: carrierFrom(e.sec, 0, sUnlock, out(1000, o.lock(sd, true, recordWith(recordWith(recA, secrec.SKInline, deleted{}), secrec.SKLength, uint64(secrec.MaxLength+1))))), reason: "range"})
	oc := *e.v.Versions["tx/api-token@1"].Rec
	oc.Crypt = OtherCrypt
	ocRec, err := oc.Encode()
	if err != nil {
		return nil, err
	}
	otherCrypt := carrierFrom(e.sec, 0, sUnlock, out(1000, o.lock(sd, true, ocRec)))
	add(txCase{name: "carrier-other-crypt", note: "a well-formed secret record naming another crypt than the topic's", rule: rowCarrier, tx: otherCrypt, reason: "crypt"})
	ocBad := carrierFrom(e.sec, 0, sUnlock, out(1000, o.lock(sd, true, recordWith(ocRec, secrec.SKHash, make([]byte, 32)))))
	add(txCase{name: "carrier-record-before-crypt", note: "breaks the record rules (an inline ciphertext that does not hash to hash) and the crypt rule: refused for the record", rule: rowCarrier, tx: ocBad, reason: "content"})
	finalOther := cloneTx(otherCrypt)
	finalOther.Inputs[0].SequenceNumber = transaction.MaxTxInSequenceNum
	add(txCase{name: "carrier-crypt-before-mineable", note: "breaks the crypt rule and the mineable rule (a final input): refused for the crypt", rule: rowCarrier, tx: signAll(finalOther), reason: "crypt"})

	// ---- carriers: mineable, unlock ----
	low := carrierFrom(e.sec, 0, sUnlock, out(1000, lockA))
	low.LockTime = carrier.LockTime - 1
	add(txCase{name: "carrier-locktime-below", note: "nLockTime one second before 2100", rule: rowCarrier, tx: signAll(low), reason: "mineable"})
	final := carrierFrom(e.sec, 0, sUnlock, out(1000, lockA))
	final.Inputs[0].SequenceNumber = transaction.MaxTxInSequenceNum
	add(txCase{name: "carrier-final-input", note: "the input's nSequence is 0xFFFFFFFF", rule: rowCarrier, tx: signAll(final), reason: "mineable"})
	add(txCase{name: "carrier-locktime-max", note: "the api-token record on its outpoint under nLockTime 0xFFFFFFFF and nSequence 0xFFFFFFFE: any locktime from 2100 and any non-final sequence is admitted; a second carrier on one outpoint is the index's to supersede",
		tx: e.secondCarrier()})
	spk := o.derivedPriv(sd)
	finalHigh := rewriteUnlock(signAll(cloneTx(final)), 0, func(sg []byte) []byte { return push(append(highSBytes(sg[:len(sg)-1]), sg[len(sg)-1])) })
	add(txCase{name: "carrier-mineable-before-unlock", note: "breaks the mineable rule (a final input) and the unlock rule (a high-S input signature): refused as mineable", rule: rowCarrier, tx: finalHigh, reason: "mineable"})
	add(txCase{name: "carrier-unlock-high-s", note: "secret-carrier-api-token-v1 with its input signature's high-S twin, which verifies: another txid, same record", rule: rowSigs,
		tx: rewriteUnlock(ka, 0, func(sg []byte) []byte { return push(append(highSBytes(sg[:len(sg)-1]), sg[len(sg)-1])) }), reason: "unlock"})
	add(txCase{name: "carrier-unlock-pushdata1", note: "the signature pushed by OP_PUSHDATA1", rule: rowCarrier,
		tx: rewriteUnlock(ka, 0, func(sg []byte) []byte { return append([]byte{script.OpPUSHDATA1, byte(len(sg))}, sg...) }), reason: "unlock"})
	add(txCase{name: "carrier-unlock-extra-push", note: "OP_0 pushed before the signature", rule: rowCarrier,
		tx: rewriteUnlock(ka, 0, func(sg []byte) []byte { return append([]byte{script.Op0}, push(sg)...) }), reason: "unlock"})
	add(txCase{name: "carrier-unlock-sighash-single", note: "the input signed SIGHASH_SINGLE|FORKID (0x43), which verifies", rule: rowSigs,
		tx: carrierFrom(e.sec, 0, flagUnlocker{spk, sighash.SingleForkID}, out(1000, lockA)), reason: "unlock"})
	add(txCase{name: "carrier-unlock-sighash-anyonecanpay", note: "the input signed SIGHASH_ALL|ANYONECANPAY|FORKID (0xc1), which verifies", rule: rowSigs,
		tx: carrierFrom(e.sec, 0, flagUnlocker{spk, sighash.AllForkID | sighash.AnyOneCanPay}, out(1000, lockA)), reason: "unlock"})
	add(txCase{name: "carrier-unlock-before-lock", note: "breaks the unlock rule (SIGHASH_SINGLE) and the lock rule (the record under the vault key): refused for the unlocking script", rule: rowCarrier,
		tx: carrierFrom(e.sec, 0, flagUnlocker{spk, sighash.SingleForkID}, out(1000, o.lock(secrec.VaultDerivation, true, recA))), reason: "unlock"})

	// ---- carriers: lock (script canonicality) ----
	add(txCase{name: "carrier-secret-under-vault-key", note: "the secret record locked and signed under the vault key, not secret", rule: rowCanonical,
		tx: carrierFrom(e.sec, 0, sUnlock, out(1000, o.lock(secrec.VaultDerivation, true, recA))), reason: "lock"})
	alice, err := newActor(Alice)
	if err != nil {
		return nil, err
	}
	add(txCase{name: "carrier-lock-member-key", note: "the organisation's secret record locked and signed under alice's secret key: the lock is bound to the record's org. The field signature does not verify under the organisation's key either, and the lock is what refuses it", rule: rowCanonical,
		tx: carrierFrom(e.sec, 0, sUnlock, out(1000, alice.lock(sd, true, recA))), reason: "lock"})
	sigA := sigOf(lockA, 1)
	head := append(append([]byte{33}, sk.Compressed()...), script.OpCHECKSIG)
	wideLock := append(append(append(append([]byte{}, head...), push4(recA)...), push(sigA)...), script.Op2DROP)
	add(txCase{name: "carrier-lock-non-minimal-push", note: "the record pushed with OP_PUSHDATA4 where a shorter push is minimal", rule: rowCanonical,
		tx: carrierFrom(e.sec, 0, sUnlock, out(1000, scr(wideLock))), reason: "lock"})
	dd := append(append([]byte{}, (*lockA)[:len(*lockA)-1]...), script.OpDROP, script.OpDROP)
	add(txCase{name: "carrier-lock-drop-drop", note: "OP_DROP OP_DROP where OP_2DROP is the fewest", rule: rowCanonical, tx: carrierFrom(e.sec, 0, sUnlock, out(1000, scr(dd))), reason: "lock"})
	add(txCase{name: "carrier-lock-unsigned", note: "the record output carries no field signature", rule: rowCanonical,
		tx: carrierFrom(e.sec, 0, sUnlock, out(1000, scr(secrec.PushDropScript(sk, [][]byte{recA}, nil)))), reason: "lock"})
	add(txCase{name: "carrier-lock-extra-field", note: "a third push after the record and its signature, dropped canonically", rule: rowCanonical,
		tx: carrierFrom(e.sec, 0, sUnlock, out(1000, scr(secrec.PushDropScript(sk, [][]byte{recA, sigA}, []byte{0x73, 0x65})))), reason: "lock"})
	add(txCase{name: "carrier-lock-trailing-opcode", note: "the canonical script followed by OP_NOP", rule: rowCanonical,
		tx: carrierFrom(e.sec, 0, sUnlock, out(1000, scr(append(append([]byte{}, *lockA...), script.OpNOP)))), reason: "lock"})
	hybrid := append([]byte{}, *lockA...)
	hybrid[1] ^= 0x01 // 0x02 <-> 0x03: the other point with this x-coordinate
	add(txCase{name: "carrier-lock-other-parity", note: "the canonical script with the key's parity byte flipped: another key, which neither the lock nor the funding output is under", rule: rowCanonical,
		tx: carrierFrom(e.sec, 0, sUnlock, out(1000, scr(hybrid))), reason: "lock"})

	// ---- carriers: field signature ----
	add(txCase{name: "carrier-field-signature-high-s", note: "the field signature's high-S twin, which verifies", rule: rowSigs,
		tx: carrierFrom(e.sec, 0, sUnlock, out(1000, fieldSigOf(lockA, sk, 1, highSBytes))), reason: "signature"})
	add(txCase{name: "carrier-field-signature-wrong-key", note: "a strict signature over the record by a stranger's key", rule: rowSigs,
		tx: carrierFrom(e.sec, 0, sUnlock, out(1000, fieldSigOf(lockA, sk, 1, signWith(Dave.Priv, recA)))), reason: "signature"})
	add(txCase{name: "carrier-field-signature-identity-key", note: "a strict signature over the record by the organisation's identity key rather than its secret key", rule: rowSigs,
		tx: carrierFrom(e.sec, 0, sUnlock, out(1000, fieldSigOf(lockA, sk, 1, signWith(Org.Priv, recA)))), reason: "signature"})
	add(txCase{name: "carrier-field-signature-padded", note: "the field signature with a zero byte before its R value: not the strict encoding", rule: rowSigs,
		tx: carrierFrom(e.sec, 0, sUnlock, out(1000, fieldSigOf(lockA, sk, 1, padR))), reason: "signature"})

	add(txCase{name: "carrier-signature-before-funding", note: "breaks the signature rule (the high-S twin) and the funding rule (a chain-tree output): refused for the signature", rule: rowCarrier,
		tx: carrierFrom(e.tree, 5, o.unlocker(secrec.ChainDerivation), out(1000, fieldSigOf(lockA, sk, 1, highSBytes))), reason: "signature"})
	add(txCase{name: "carrier-lock-before-funding", note: "breaks the lock rule (the record under the vault key) and the funding rule (a funding output under the vault key): refused for the lock", rule: rowCarrier,
		tx: carrierFrom(e.misc, 3, o.unlocker(secrec.VaultDerivation), out(1000, o.lock(secrec.VaultDerivation, true, recA))), reason: "lock"})

	// ---- carriers: funding ----
	add(txCase{name: "carrier-on-chain-tree", note: "the secret record funded from a chain-tree output (funding-shaped under the chain key): secret and chain trees are kept apart by their keys", rule: rowCarrier,
		tx: carrierFrom(e.tree, 5, o.unlocker(secrec.ChainDerivation), out(1000, lockA)), reason: "funding"})
	add(txCase{name: "carrier-funding-vault-key", note: "spends a funding-shaped output under the vault key", rule: rowCarrier,
		tx: carrierFrom(e.misc, 3, o.unlocker(secrec.VaultDerivation), out(1000, lockA)), reason: "funding"})
	add(txCase{name: "carrier-funding-bare-p2pk", note: "spends a bare pay-to-public-key under the secret key", rule: rowCarrier, tx: carrierFrom(e.misc, 0, sUnlock, out(1000, lockA)), reason: "funding"})
	add(txCase{name: "carrier-funding-signed-tag", note: "spends an output under the secret key whose one field is the funding tag with a field signature", rule: rowCanonical, tx: carrierFrom(e.misc, 1, sUnlock, out(1000, lockA)), reason: "funding"})
	add(txCase{name: "carrier-funding-other-tag", note: "spends an output under the secret key whose one field is 73 65 04", rule: rowCarrier, tx: carrierFrom(e.misc, 2, sUnlock, out(1000, lockA)), reason: "funding"})
	add(txCase{name: "carrier-value-short", note: "the one output carries 999 of the funding output's 1000", rule: rowCarrier,
		tx: carrierFrom(e.sec, 0, sUnlock, out(999, lockA)), reason: "funding"})

	if err := e.tokenCases(add); err != nil {
		return nil, err
	}

	// ---- transactions that claim nothing ----
	unminedSweep := cloneTx(e.sweep)
	unminedSweep.MerklePath = nil
	add(txCase{name: "sweep-unmined", note: "the sweep with no proof, its BEEF carrying the tree it spends: not a sweep and its own path, so it is refused and decided again when it arrives mined", rule: rowSweep, tx: unminedSweep, reason: "beef"})
	add(txCase{name: "sweep-no-proof", note: "the sweep alone in a BEEF V1 with no proof at all", rule: rowSweep,
		tx: e.sweep, beef: beefV1(nil, []*transaction.Transaction{e.sweep}, []int{-1}), reason: "beef"})
	add(txCase{name: "sweep-beef-extra-transaction", note: "the sweep in a BEEF V1 that also carries an unrelated mined transaction", rule: rowSweep,
		tx: e.sweep, beef: beefV1([]*transaction.MerklePath{e.misc.MerklePath, e.sweep.MerklePath}, []*transaction.Transaction{e.misc, e.sweep}, []int{0, 1}), reason: "beef"})
	off := reproved(e.sweep, transaction.NewMerklePath(unproven, e.sweep.MerklePath.Path))
	add(txCase{name: "sweep-proof-unknown-height", note: "the sweep with a proof at a height the headers do not hold: only a mined spend retracts", rule: rowSweep, tx: off, reason: "unmined"})
	add(txCase{name: "sweep-over-the-bound", note: "the sweep of two inputs under a host whose sweep bound is 1", rule: rowSweep, tx: e.sweep, maxSweep: 1, reason: "too-large"})
	add(txCase{name: "sweep-unmined-before-too-large", note: "breaks the unmined rule (a height the headers do not hold) and the bound (two inputs, bound 1): refused as unmined", rule: rowSweep, tx: off, maxSweep: 1, reason: "unmined"})
	wideSweep := e.c.wide(cloneTx(e.sweep))
	add(txCase{name: "sweep-beef-before-unmined", note: "breaks the beef rule (a path with a leaf it does not need) at a height the default headers hold: refused for the BEEF", rule: rowSweep, tx: wideSweep, reason: "beef"})
	late := transaction.NewTransaction()
	late.AddInputFromTx(e.sec, 7, sUnlock)
	late.AddOutput(out(700, o.feeLock))
	late.AddOutput(out(100, scr(secrec.FundingScript(sk))))
	add(txCase{name: "sweep-tombstone-second", note: "a mined spend of secret-tree output 7 whose funding-shaped output is output 1, not 0", rule: rowSweep, tx: e.c.mine(signAll(late)), reason: "not-bsecret"})
	tomb := secrec.FundingScript(sk)
	loose := append(append(append([]byte{}, tomb[:35]...), script.OpPUSHDATA1, 3), tomb[36:]...)
	odd := transaction.NewTransaction()
	odd.AddInputFromTx(e.sec, 8, sUnlock)
	odd.AddOutput(out(800, scr(loose)))
	add(txCase{name: "sweep-tombstone-pushdata1", note: "a mined spend whose output 0 pushes the funding tag with OP_PUSHDATA1: not funding-shaped", rule: rowCanonical, tx: e.c.mine(signAll(odd)), reason: "not-bsecret"})
	spend := transaction.NewTransaction()
	spend.AddInputFromTx(e.sweep, 0, sUnlock)
	spend.AddOutput(out(e.sweep.Outputs[0].Satoshis-200, o.feeLock))
	add(txCase{name: "spend-held-tombstone", note: "an unmined transaction spending the sweep's tombstone, which the topic holds: a spend of held outputs is never accepted", rule: rowSweep, tx: signAll(spend), reason: "not-bsecret"})
	both := transaction.NewTransaction()
	both.AddInputFromTx(e.sec, 9, sUnlock)
	both.AddOutput(out(500, scr(secrec.FundingScript(sk))))
	both.AddOutput(out(400, lockA))
	add(txCase{name: "sweep-with-a-secret-output", note: "a mined transaction whose output 0 is funding-shaped and whose output 1 claims a secret: it claims something, so it is judged as a carrier, and it has two outputs", rule: rowSweep, tx: e.c.mine(signAll(both)), reason: "shape"})
	// A first token spends exactly one output of its parent, and the
	// tree's own change is an output of its parent like any other. Built
	// last, so that the block it is mined in follows every other case's.
	g5 := *e.v.Vaults[0]
	g5.Vault = secrec.VaultID([32]byte(*e.tree.TxID()), 5)
	raw5, err := g5.Encode()
	if err != nil {
		return nil, err
	}
	onChange, err := mint.Transition(o.lock(secrec.VaultDerivation, true, secrec.TagVault, raw5), 1,
		&mint.Input{Tx: e.tree, Vout: 5, Unlocker: o.unlocker(secrec.ChainDerivation)},
		mint.Input{Tx: e.tree, Vout: uint32(len(e.tree.Outputs) - 1), Unlocker: o.feeUnlocker()}, o.feeLock, mint.DefaultFees) //nolint:gosec // a few outputs
	if err != nil {
		return nil, err
	}
	if secrec.IsFundingShape(*e.tree.Outputs[len(e.tree.Outputs)-1].LockingScript) {
		return nil, fmt.Errorf("the chain tree's last output is not its change")
	}
	e.c.mine(onChange)
	add(txCase{name: "token-genesis-spends-tree-change", note: "a seq 0 spending chain-tree output 5, with the identifier that outpoint gives, and paying its fee from the chain tree's own change output: two inputs spend its parent, and a first token spends exactly one, whatever the second output is", rule: rowToken,
		tx: onChange, beef: tokenBEEF(onChange, e.tree), reason: "token-input"})
	return cs, nil
}

// secondCarrier is a second carrier on the api-token version's outpoint.
func (e *txEnv) secondCarrier() *transaction.Transaction {
	ka := e.carriers["tx/api-token@1"]
	f := carrierFrom(e.sec, 0, e.o.unlocker(secrec.SecretDerivation), out(1000, ka.Outputs[0].LockingScript))
	f.LockTime, f.Inputs[0].SequenceNumber = 0xffffffff, 0xfffffffe
	return signAll(f)
}

// padR rewrites a strict DER signature with a zero byte before R: the same
// (r, s) in another encoding.
func padR(der []byte) []byte {
	rl := int(der[3])
	out := append([]byte{0x30, der[1] + 1, 0x02, der[3] + 1, 0x00}, der[4:4+rl]...)
	return append(out, der[4+rl:]...)
}

// tokenCases are the vault tokens' refusals.
func (e *txEnv) tokenCases(add func(txCase)) error {
	o := e.o
	vd := secrec.VaultDerivation
	t0, t1, t2, t3 := e.tokens[0], e.tokens[1], e.tokens[2], e.tokens[3]
	r1, r2, r3 := e.v.Vaults[1], e.v.Vaults[2], e.v.Vaults[3]
	rec1 := e.v.VaultRecs[1]
	vk := o.key(vd)

	// on builds the token of a record changed by f from base, spending
	// prev:vout, mined.
	on := func(base *secrec.Vault, prev *transaction.Transaction, vout uint32, f func(*secrec.Vault)) (*transaction.Transaction, error) {
		r := *base
		f(&r)
		b, err := r.Encode()
		if err != nil {
			return nil, err
		}
		t, err := e.token(b, prev, vout)
		if err != nil {
			return nil, err
		}
		return e.c.mine(t), nil
	}
	// A token at seq 1 with an arbitrary lock, spending t0.
	lock1 := func(lock *script.Script, sats uint64) *transaction.Transaction {
		t, err := mintRaw(e, lock, sats, t0, 0)
		if err != nil {
			panic(err)
		}
		return e.c.mine(t)
	}
	refuse := func(name, note, rule string, tx, parent *transaction.Transaction, reason string) {
		add(txCase{name: name, note: note, rule: rule, tx: tx, beef: tokenBEEF(tx, parent), reason: reason})
	}

	// shape, one claiming output.
	two := lock1(t1.Outputs[0].LockingScript, 2)
	refuse("token-two-satoshis", "seq 1's token output holding 2 satoshis", rowToken, two, t0, "shape")
	three := lock1(o.lock(vd, true, secrec.TagVault, rec1, []byte{0x01}), 1)
	refuse("token-three-fields", "seq 1's token with a third field before the signature", rowToken, three, t0, "shape")
	one := lock1(o.lock(vd, true, secrec.TagVault), 1)
	refuse("token-one-field", "a signed PushDrop of the tag alone, with no record", rowToken, one, t0, "shape")
	unsigned := lock1(scr(secrec.PushDropScript(vk, [][]byte{secrec.TagVault, rec1}, nil)), 1)
	refuse("token-unsigned", "seq 1's tag and record with no field signature", rowToken, unsigned, t0, "shape")
	twin := cloneTx(t1)
	twin.MerklePath = nil
	twin.Outputs = append([]*transaction.TransactionOutput{twin.Outputs[0], out(1, twin.Outputs[0].LockingScript)}, out(twin.Outputs[1].Satoshis-1, twin.Outputs[1].LockingScript))
	e.c.mine(signAll(twin))
	refuse("token-two-token-outputs", "seq 1's token output twice in one transaction", rowOneClaim, twin, t0, "shape")
	ka := e.carriers["tx/api-token@1"]
	mixed := cloneTx(t1)
	mixed.MerklePath = nil
	mixed.Outputs = append([]*transaction.TransactionOutput{mixed.Outputs[0], out(1, ka.Outputs[0].LockingScript)}, out(mixed.Outputs[1].Satoshis-1, mixed.Outputs[1].LockingScript))
	e.c.mine(signAll(mixed))
	refuse("token-and-secret", "seq 1's token output beside an output that claims a secret", rowOneClaim, mixed, t0, "shape")

	// beef.
	add(txCase{name: "token-atomic-beef", note: "vault-token-update's token and parent in an Atomic BEEF: a token is never an Atomic BEEF", rule: rowToken,
		tx: t1, beef: atomic(t1.TxID(), tokenBEEF(t1, t0)), reason: "beef"})
	add(txCase{name: "token-alone", note: "seq 3 alone with its proof, as a host stores it: without its parent it is not admissible", rule: rowToken, tx: t3, reason: "beef"})
	add(txCase{name: "token-extra-transaction", note: "seq 3 and its parent with an unrelated mined transaction", rule: rowToken,
		tx: t3, beef: beefV1([]*transaction.MerklePath{e.misc.MerklePath, t2.MerklePath, t3.MerklePath}, []*transaction.Transaction{e.misc, t2, t3}, []int{0, 1, 2}), reason: "beef"})
	add(txCase{name: "token-parent-not-spent", note: "seq 3 with an unrelated mined transaction in its parent's place", rule: rowToken,
		tx: t3, beef: beefV1([]*transaction.MerklePath{e.misc.MerklePath, t3.MerklePath}, []*transaction.Transaction{e.misc, t3}, []int{0, 1}), reason: "beef"})
	t2bare := cloneTx(t2)
	t2bare.MerklePath = nil
	add(txCase{name: "token-parent-unproven", note: "seq 3 with its parent carried without a proof", rule: rowToken,
		tx: t3, beef: beefV1([]*transaction.MerklePath{t3.MerklePath}, []*transaction.Transaction{t2bare, t3}, []int{-1, 0}), reason: "beef"})
	add(txCase{name: "token-parent-txid-only", note: "seq 3 in a BEEF V2 whose parent is a txid-only entry", rule: rowToken,
		tx: t3, beef: beefV2([]*transaction.MerklePath{t3.MerklePath}, []*transaction.Transaction{nil, t3}, []int{-1, 0}, map[int][32]byte{0: [32]byte(*t2.TxID())}), reason: "beef"})
	wideT0 := e.c.wide(cloneTx(t0))
	add(txCase{name: "token-parent-proof-extra-leaf", note: "seq 1 with its parent proven by a path holding a leaf it does not need", rule: rowToken,
		tx: t1, beef: beefV1([]*transaction.MerklePath{wideT0.MerklePath, t1.MerklePath}, []*transaction.Transaction{wideT0, t1}, []int{0, 1}), reason: "beef"})
	add(txCase{name: "token-same-block-two-paths", note: "vault-token-rekey-same-block with its parent's and its own paths kept apart: two paths of one block are refused, BEEF writers merge them", rule: rowToken,
		tx: t2, beef: beefV1([]*transaction.MerklePath{t1.MerklePath, t2.MerklePath}, []*transaction.Transaction{t1, t2}, []int{0, 1}), reason: "beef"})
	badRec := lock1(o.lock(vd, true, secrec.TagVault, recordWith(rec1, secrec.VKCreated, uint64(0))), 1)
	add(txCase{name: "token-beef-before-record", note: "breaks the beef rule (alone, no parent) and the record rules (created 0): refused for the BEEF", rule: rowToken, tx: badRec, reason: "beef"})
	add(txCase{name: "token-shape-before-beef", note: "breaks the shape rule (2 satoshis) and the beef rule (alone): refused for the shape", rule: rowToken, tx: two, reason: "shape"})

	// the record, the crypt.
	refuse("token-record-refused", "seq 1 whose record has created 0, signed", rowToken, badRec, t0, "range")
	debtRec := lock1(o.lock(vd, true, secrec.TagVault, recordWith(rec1, secrec.VKStale, uint64(1))), 1)
	refuse("token-record-creates-while-stale", "seq 1 creating a secret while it counts one stale: the record's own rule, before any predecessor is read", rowToken, debtRec, t0, "debt")
	oc, err := on(r1, t0, 0, func(r *secrec.Vault) { r.Crypt = OtherCrypt })
	if err != nil {
		return err
	}
	refuse("token-other-crypt", "seq 1 naming another crypt", rowToken, oc, t0, "crypt")

	ocBad := lock1(o.lock(vd, true, secrec.TagVault, recordWith(recordWith(rec1, secrec.VKCrypt, OtherCrypt), secrec.VKCreated, uint64(0))), 1)
	refuse("token-record-before-crypt", "breaks the record rules (created 0) and the crypt rule: refused for the record", rowToken, ocBad, t0, "range")
	ocRec := recordWith(rec1, secrec.VKCrypt, OtherCrypt)
	ocLock := lock1(o.lock(secrec.SecretDerivation, true, secrec.TagVault, ocRec), 1)
	refuse("token-crypt-before-lock", "breaks the crypt rule and the lock rule (the record under the secret key): refused for the crypt", rowToken, ocLock, t0, "crypt")

	// lock.
	us := lock1(o.lock(secrec.SecretDerivation, true, secrec.TagVault, rec1), 1)
	refuse("token-under-secret-key", "seq 1's vault record locked and signed under the secret key", rowCanonical, us, t0, "lock")
	alice, err := newActor(Alice)
	if err != nil {
		return err
	}
	ua := lock1(alice.lock(vd, true, secrec.TagVault, rec1), 1)
	refuse("token-lock-member-key", "the organisation's seq 1 record locked and signed under alice's vault key. The field signature does not verify under the organisation's key either, and the lock is what refuses it", rowCanonical, ua, t0, "lock")
	sig1 := sigOf(t1.Outputs[0].LockingScript, 2)
	head := append(append([]byte{33}, vk.Compressed()...), script.OpCHECKSIG)
	nm := append(append(append(append(append([]byte{}, head...), push(secrec.TagVault)...), push4(rec1)...), push(sig1)...), script.Op2DROP, script.OpDROP)
	tnm := lock1(scr(nm), 1)
	refuse("token-lock-non-minimal-push", "seq 1's record pushed with OP_PUSHDATA4 where a shorter push is minimal", rowCanonical, tnm, t0, "lock")
	canon := *t1.Outputs[0].LockingScript
	ddd := append(append([]byte{}, canon[:len(canon)-2]...), script.OpDROP, script.OpDROP, script.OpDROP)
	tddd := lock1(scr(ddd), 1)
	refuse("token-lock-three-drops", "seq 1's token with OP_DROP OP_DROP OP_DROP where OP_2DROP OP_DROP is the fewest", rowCanonical, tddd, t0, "lock")

	// signature.
	hs := lock1(fieldSigOf(t1.Outputs[0].LockingScript, vk, 2, highSBytes), 1)
	refuse("token-field-signature-high-s", "seq 1's field signature's high-S twin", rowSigs, hs, t0, "signature")
	recOnly := lock1(fieldSigOf(t1.Outputs[0].LockingScript, vk, 2, signWith(o.derivedPriv(vd), rec1)), 1)
	refuse("token-field-signature-record-only", "a strict signature by the vault key over the record alone, not the tag and the record", rowSigs, recOnly, t0, "signature")
	stranger := lock1(fieldSigOf(t1.Outputs[0].LockingScript, vk, 2, signWith(Dave.Priv, append(append([]byte{}, secrec.TagVault...), rec1...))), 1)
	refuse("token-field-signature-wrong-key", "a strict signature over the tag and the record by a stranger's key", rowSigs, stranger, t0, "signature")

	hsx := reproved(hs, transaction.NewMerklePath(unproven, hs.MerklePath.Path))
	refuse("token-signature-before-unmined", "breaks the signature rule (the high-S twin) and the unmined rule (a height the headers do not hold): refused for the signature", rowToken, hsx, t0, "signature")

	// unmined.
	t0x := reproved(t0, transaction.NewMerklePath(unproven, t0.MerklePath.Path))
	refuse("token-parent-proof-unknown-height", "seq 1 whose parent's proof names a height the headers do not hold", rowToken, t1, t0x, "unmined")
	t3x := reproved(t3, transaction.NewMerklePath(unproven, t3.MerklePath.Path))
	refuse("token-proof-unknown-height", "seq 3 proven at a height the headers do not hold", rowToken, t3x, t2, "unmined")

	// token-input.
	pc, err := on(r1, t0, 0, func(r *secrec.Vault) { r.Prev = label("txid/elsewhere") })
	if err != nil {
		return err
	}
	refuse("token-prev-not-parent", "seq 1 whose prev names another transaction than the parent it spends", rowToken, pc, t0, "token-input")
	pcx := reproved(pc, transaction.NewMerklePath(unproven, pc.MerklePath.Path))
	refuse("token-unmined-before-token-input", "breaks the unmined rule (a height the headers do not hold) and the token-input rule (prev is not the parent): refused as unmined", rowToken, pcx, t0, "unmined")
	sk, err := on(r1, t0, 0, func(r *secrec.Vault) { r.Seq = 2 })
	if err != nil {
		return err
	}
	refuse("token-seq-skips", "a token at seq 2 spending seq 0", rowToken, sk, t0, "token-input")
	ch, err := mint.Transition(t1.Outputs[0].LockingScript, 1, &mint.Input{Tx: t0, Vout: 1, Unlocker: o.feeUnlocker()}, e.nextFee(), o.feeLock, mint.DefaultFees)
	if err != nil {
		return err
	}
	e.c.mine(ch)
	refuse("token-spends-change", "seq 1's record spending seq 0's change output, not its token", rowToken, ch, t0, "token-input")
	ov, err := on(r1, e.second, 0, func(r *secrec.Vault) { r.Prev = [32]byte(*e.second.TxID()) })
	if err != nil {
		return err
	}
	refuse("token-spends-another-vault", "seq 1 of the vault spending the first token of the owner's second vault, and naming it as prev", rowToken, ov, e.second, "token-input")
	refuse("vault-token-no-predecessor", "a well-formed token output at seq 7 in a transaction that spends only a fee coin: no input spends a token of its parent", rowToken, e.loose, e.coin, "token-input")
	pred := *r1
	pred.Prev = [32]byte(*hs.TxID())
	pred.Seq, pred.Create, pred.Update = 2, []secrec.Entry{}, []secrec.Entry{}
	pred.Count, pred.Root = r1.Count, r1.Root
	onBad, err := on(&pred, hs, 0, func(*secrec.Vault) {})
	if err != nil {
		return err
	}
	refuse("token-predecessor-not-well-formed", "seq 2 spending a mined token output whose field signature is the high-S twin (token-field-signature-high-s): the predecessor is not a well-formed token", rowToken, onBad, hs, "token-input")
	predNM := pred
	predNM.Prev = [32]byte(*tnm.TxID())
	onNM, err := on(&predNM, tnm, 0, func(*secrec.Vault) {})
	if err != nil {
		return err
	}
	refuse("token-predecessor-non-canonical", "seq 2 spending a mined token output whose record is pushed with OP_PUSHDATA4 (token-lock-non-minimal-push): the predecessor's script is not the canonical one", rowCanonical, onNM, tnm, "token-input")
	pred2 := pred
	pred2.Prev = [32]byte(*twin.TxID())
	both := cloneTx(func() *transaction.Transaction {
		b, err := pred2.Encode()
		if err != nil {
			panic(err)
		}
		t, err := e.token(b, twin, 0)
		if err != nil {
			panic(err)
		}
		return t
	}())
	both.MerklePath = nil
	both.AddInputFromTx(twin, 1, o.unlocker(vd))
	e.c.mine(signAll(both))
	refuse("token-spends-two-tokens", "seq 2 spending both token outputs of a parent that has two (token-two-token-outputs): more than one input spends a token output of the parent", rowToken, both, twin, "token-input")

	// seq 0.
	g0 := e.v.Vaults[0]
	gid := func(tx *transaction.Transaction, vout uint32) func(*secrec.Vault) {
		return func(r *secrec.Vault) { r.Vault = secrec.VaultID([32]byte(*tx.TxID()), vout) }
	}
	onSec, err := on(g0, e.sec, 10, gid(e.sec, 10))
	if err != nil {
		return err
	}
	refuse("token-genesis-on-secret-tree", "a seq 0 spending a secret-tree output, not a chain-tree output, with the identifier that outpoint gives", rowToken, onSec, e.sec, "token-input")
	onSecID, err := on(g0, e.sec, 10, func(*secrec.Vault) {})
	if err != nil {
		return err
	}
	refuse("token-input-before-vault-id", "breaks the token-input rule (a secret-tree output) and the vault-id rule (the identifier of another outpoint): refused for the input", rowToken, onSecID, e.sec, "token-input")
	onTok, err := on(g0, t3, 0, gid(t3, 0))
	if err != nil {
		return err
	}
	refuse("token-genesis-spends-token", "a seq 0 spending a token output", rowToken, onTok, t3, "token-input")
	g2raw, err := func() ([]byte, error) { r := *g0; gid(e.tree, 2)(&r); return r.Encode() }()
	if err != nil {
		return err
	}
	twoIn, err := e.token(g2raw, e.tree, 2)
	if err != nil {
		return err
	}
	twoIn = cloneTx(twoIn)
	twoIn.MerklePath = nil
	twoIn.AddInputFromTx(e.tree, 3, o.unlocker(secrec.ChainDerivation))
	e.c.mine(signAll(twoIn))
	refuse("token-genesis-two-chain-outputs", "a seq 0 spending chain-tree outputs 2 and 3: a first token has exactly one input that spends its parent, so one outpoint gives its identifier", rowToken, twoIn, e.tree, "token-input")

	// vault-id.
	wrongID, err := on(g0, e.tree, 4, func(*secrec.Vault) {})
	if err != nil {
		return err
	}
	refuse("token-vault-id", "a seq 0 spending chain-tree output 4 and naming the identifier of output 0", rowToken, wrongID, e.tree, "vault-id")

	// transition rules against the predecessor, in their order.
	tr := func(name, note string, base *secrec.Vault, prev *transaction.Transaction, f func(*secrec.Vault), reason string) error {
		t, err := on(base, prev, 0, f)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		refuse(name, note, rowToken, t, prev, reason)
		return nil
	}
	e0, e2 := GroupEpochs[0], GroupEpochs[2]
	extra := secrec.Entry{ID: label("id/never-held"), Version: 1, ContentID: label("cid/never-held"), Commitment: label("commitment/never-held")}
	for _, c := range []struct {
		name, note string
		base       *secrec.Vault
		prev       *transaction.Transaction
		f          func(*secrec.Vault)
		reason     string
	}{
		{"token-labels-change", "seq 1 with another label set, fixed at the first token", r1, t0, func(r *secrec.Vault) { r.Labels = []string{"internal", "public"} }, "transition"},
		{"token-anchor-changes", "seq 1 switching the vault to the interval anchor mode", r1, t0, func(r *secrec.Vault) { r.Anchor = secrec.AnchorInterval }, "transition"},
		{"token-group-changes", "seq 1 naming another group", r1, t0, func(r *secrec.Vault) { r.Group[0] ^= 1 }, "transition"},
		{"token-hall-changes", "seq 1 naming another hall", r1, t0, func(r *secrec.Vault) { r.Hall = "other_hall_qwertyuiop" }, "transition"},
		{"token-epoch-goes-back", "seq 3 naming epoch 0 after seq 2 acknowledged epoch 1", r3, t2, func(r *secrec.Vault) { r.Epoch, r.EpochID = 0, e0.EpochID }, "epoch"},
		{"token-epoch-same-other-id", "seq 1 keeping epoch 0 under another epoch id", r1, t0, func(r *secrec.Vault) { r.EpochID = e2.EpochID }, "epoch"},
		{"token-epoch-later-same-id", "seq 1 naming epoch 1 under epoch 0's id", r1, t0, func(r *secrec.Vault) { r.Epoch = 1 }, "epoch"},
		{"token-transition-before-epoch", "breaks the transition rule (another anchor mode) and the epoch rule (epoch 1 under epoch 0's id): refused for the transition", r1, t0,
			func(r *secrec.Vault) { r.Anchor, r.Epoch = secrec.AnchorInterval, 1 }, "transition"},
		{"token-rekey-claims-nothing-stale", "seq 2 acknowledging epoch 1, re-keying one of three secrets and claiming none is stale: a revoke without the rotation", r2, t1, func(r *secrec.Vault) { r.Stale = 0 }, "debt"},
		{"token-rekey-without-rekeying", "seq 2 acknowledging epoch 1 with no change and nothing stale", r2, t1,
			func(r *secrec.Vault) { r.Update, r.Stale, r.Root = []secrec.Entry{}, 0, r1.Root }, "debt"},
		{"token-debt-understated", "seq 3 re-keying one and retiring one of two stale secrets and still counting one stale", r3, t2, func(r *secrec.Vault) { r.Stale = 1 }, "debt"},
		{"token-stale-from-nothing", "seq 1 with nothing stale before it, counting one stale", r1, t0,
			func(r *secrec.Vault) { r.Create, r.Stale, r.Count = []secrec.Entry{}, 1, 2 }, "debt"},
		{"token-debt-clears-more-than-stale", "seq 3 updating two secrets and retiring one while two are stale: more than the debt", r3, t2,
			func(r *secrec.Vault) { r.Update = sortEntries(append(append([]secrec.Entry{}, r.Update...), extra)) }, "debt"},
		{"token-epoch-before-debt", "breaks the epoch rule (epoch 2 under epoch 1's id) and the debt rule: refused for the epoch", r3, t2,
			func(r *secrec.Vault) { r.Epoch, r.Stale = 2, 1 }, "epoch"},
		{"token-count", "seq 1 whose count is not the predecessor's plus one created", r1, t0, func(r *secrec.Vault) { r.Count = 4 }, "count"},
		{"token-debt-before-count", "breaks the debt rule (one stale with nothing stale before it) and the count rule: refused for the debt", r1, t0,
			func(r *secrec.Vault) { r.Create, r.Stale, r.Count = []secrec.Entry{}, 1, 9 }, "debt"},
	} {
		if err := tr(c.name, c.note, c.base, c.prev, c.f, c.reason); err != nil {
			return err
		}
	}
	return nil
}

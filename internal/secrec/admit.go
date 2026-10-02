package secrec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"

	"github.com/lightwebinc/bcommon/carrier"
	"github.com/lightwebinc/bcommon/chaintoken"
	"github.com/lightwebinc/bcommon/guard"
	"github.com/lightwebinc/bcommon/pushdrop"
)

// The transaction refusals of docs/spec.md section 11.1, beside the record
// refusals. A transaction is refused for the first rule it breaks. A record
// that names another crypt than the topic's is refused with ErrCrypt, the
// label of a crypt that breaks the grammar.
var (
	ErrShape      = errors.New("secrec: transaction has the wrong shape")
	ErrBEEF       = chaintoken.ErrBEEF
	ErrMineable   = errors.New("secrec: carrier is mineable")
	ErrUnlock     = errors.New("secrec: unlocking script is not one canonical signature push")
	ErrLock       = errors.New("secrec: output script is not the canonical one for the owner")
	ErrFieldSig   = errors.New("secrec: field signature is not strict or does not verify")
	ErrFunding    = errors.New("secrec: carrier does not spend a funding output of the owner, or does not carry its value")
	ErrUnmined    = errors.New("secrec: proof does not verify against the host's headers")
	ErrTokenInput = errors.New("secrec: token does not spend its predecessor, or its chain tree at seq 0")
	ErrVaultID    = errors.New("secrec: vault is not the identifier of the outpoint the first token spends")
	ErrNotBsecret = errors.New("secrec: transaction is not for this topic")
	ErrHostConfig = errors.New("secrec: host configuration or previous coins out of range")

	errNoPredRead = errors.New("secrec: predecessor is not a well-formed token")
)

// TxKind is what an admitted transaction is to the topic.
type TxKind int

// The kinds of admitted transaction.
const (
	TxSecret TxKind = iota + 1
	TxVaultToken
	TxSweep
)

func (k TxKind) String() string {
	switch k {
	case TxSecret:
		return "secret"
	case TxVaultToken:
		return "vault-token"
	case TxSweep:
		return "sweep"
	}
	return "none"
}

// Host is what admission needs beyond the submission: the topic's crypt, a
// chain tracker over the host's own block headers, the host's BEEF bound
// (DefaultMaxBEEF when zero) and its sweep input bound
// (DefaultMaxSweepInputs when zero). Nothing the topic holds is here: a
// verdict never reads another record (docs/spec.md section 11.1).
type Host struct {
	Crypt          string
	Headers        chaintracker.ChainTracker
	MaxBEEF        int
	MaxSweepInputs int
}

// Carrier is an admitted secret carrier.
type Carrier struct {
	Secret *Secret
	// Owner is the record's org, the key the carrier is bound to.
	Owner []byte
	// Record is the record exactly as carried.
	Record []byte
	// ContentID is the version's content id.
	ContentID [32]byte
	// Commitment is C = txid(K), hash byte order.
	Commitment [32]byte
	// Funding is the outpoint the carrier spends; a mined sweep of it
	// retracts the carrier.
	Funding transaction.Outpoint
}

// VaultToken is a vault token's output: its record, decoded.
type VaultToken struct {
	Vault *Vault
	// Record is the record exactly as carried (the token's second field).
	Record []byte
	// Vout is the token output's index.
	Vout uint32
}

// Admission is what a host admits from one transaction: the outputs to admit
// and the held inputs to retain (BRC-22's admittance instructions), and what
// the lookup service records.
type Admission struct {
	Kind TxKind
	// Txid is the transaction's txid, hash byte order.
	Txid [32]byte
	// Outputs are the output indices admitted.
	Outputs []int
	// Retain are the input indices that spend an output the topic holds.
	Retain []int
	// Carrier is set for TxSecret.
	Carrier *Carrier
	// Token, Predecessor and Parent are set for a vault token. Predecessor
	// is the token at seq - 1 read from the parent the BEEF carries; nil at
	// seq 0, where the parent is the chain tree. Spends is the outpoint the
	// token's predecessor input (at seq 0, its funding input) spends.
	Token       *VaultToken
	Predecessor *VaultToken
	Parent      [32]byte
	Spends      transaction.Outpoint
	// Spent is, for TxSweep, every outpoint the sweep's inputs spend.
	Spent []transaction.Outpoint
}

// Admit applies docs/spec.md section 11.1 to one submission: the BEEF as it
// arrived, and held, the indices of its subject's inputs that spend an
// output the topic holds (BRC-22's previous coins, as the engine hands them
// to the topic manager). held is checked against the subject's inputs and
// decides only what is retained, never a verdict: the predecessor of a token
// is read from the parent its BEEF carries, every spend a rule reads is read
// from the transactions in the BEEF, and no rule reads another topic or
// anything this topic holds. SPV of the BEEF is the engine's and is assumed
// to have run, including the scripts of an unproven carrier's input.
//
// Every refusal is an error: a topic manager raises it rather than answer
// with empty instructions, so the engine records nothing for the txid.
func Admit(ctx context.Context, beef []byte, held []int, h Host) (*Admission, error) {
	if CheckCrypt(h.Crypt) != nil {
		return nil, fmt.Errorf("%w: crypt breaks the grammar", ErrHostConfig)
	}
	bound := h.MaxBEEF
	if bound == 0 {
		bound = DefaultMaxBEEF
	}
	w, err := chaintoken.ReadWire(beef, bound)
	if err != nil {
		return nil, err
	}
	tx := w.SubjectTx()
	retain, err := retained(tx, held)
	if err != nil {
		return nil, err
	}
	a := &Admission{Txid: [32]byte(*tx.TxID()), Retain: retain}

	// Classify: the one output that claims a secret or a token.
	claim, claims, at := KindNone, 0, 0
	for i, o := range tx.Outputs {
		if o == nil || o.LockingScript == nil {
			continue
		}
		if k := Classify(*o.LockingScript); k != KindNone && k != KindFunding {
			claim, at = k, i
			claims++
		}
	}
	if claims > 1 {
		return nil, fmt.Errorf("%w: %d outputs claim a secret or a token", ErrShape, claims)
	}
	switch claim {
	case KindSecret:
		c, err := checkCarrier(w, tx, h)
		if err != nil {
			return nil, err
		}
		a.Kind, a.Carrier, a.Outputs = TxSecret, c, []int{0}
		return a, nil
	case KindVault:
		if err := a.checkToken(ctx, w, tx, at, h); err != nil {
			return nil, err
		}
		a.Kind, a.Outputs = TxVaultToken, []int{at}
		return a, nil
	}

	// Sweep: nothing claimed, output 0 funding-shaped under any key, mined.
	if len(tx.Outputs) > 0 && tx.Outputs[0] != nil && tx.Outputs[0].LockingScript != nil && IsFundingShape(*tx.Outputs[0].LockingScript) {
		if err := w.Alone(tx); err != nil {
			return nil, err
		}
		if !IsMined(ctx, tx, h.Headers) {
			return nil, ErrUnmined
		}
		max := h.MaxSweepInputs
		if max == 0 {
			max = DefaultMaxSweepInputs
		}
		if len(tx.Inputs) > max {
			return nil, fmt.Errorf("%w: a sweep of %d inputs, host bound %d", ErrTooLarge, len(tx.Inputs), max)
		}
		a.Kind, a.Outputs = TxSweep, []int{0}
		for _, in := range tx.Inputs {
			a.Spent = append(a.Spent, transaction.Outpoint{Txid: *in.SourceTXID, Index: in.SourceTxOutIndex})
		}
		return a, nil
	}
	return nil, ErrNotBsecret
}

// retained checks held against the inputs and returns it sorted, once each.
func retained(tx *transaction.Transaction, held []int) ([]int, error) {
	seen := map[int]bool{}
	out := []int{}
	for _, i := range held {
		if i < 0 || i >= len(tx.Inputs) {
			return nil, fmt.Errorf("%w: previous coin names input %d of %d", ErrHostConfig, i, len(tx.Inputs))
		}
		if !seen[i] {
			seen[i] = true
			out = append(out, i)
		}
	}
	sort.Ints(out)
	return out, nil
}

// lockingKey derives the key an owner's output is locked to under d.
func lockingKey(d pushdrop.Derivation, owner []byte) *ec.PublicKey {
	pub, err := guard.ParsePubKey(owner)
	if err != nil {
		panic(err) // the record's key rule already held it to a canonical key
	}
	key, err := d.ExpectedLockingKey(pub)
	if err != nil {
		panic(err)
	}
	return key
}

// IsMined reports whether tx carries a proof that verifies against the
// headers (bcommon chaintoken.Mined).
func IsMined(ctx context.Context, tx *transaction.Transaction, headers chaintracker.ChainTracker) bool {
	return chaintoken.Mined(ctx, tx, headers)
}

// checkCarrier is the secret carrier's rules 1 to 9; 5 to 8 in bcommon
// carrier.Validate's order (unmineability, the unlocking script, the lock,
// the signature).
func checkCarrier(w *chaintoken.Wire, tx *transaction.Transaction, h Host) (*Carrier, error) {
	// 1. shape.
	if len(tx.Inputs) != 1 || len(tx.Outputs) != 1 {
		return nil, fmt.Errorf("%w: %d inputs, %d outputs", ErrShape, len(tx.Inputs), len(tx.Outputs))
	}
	in, out := tx.Inputs[0], tx.Outputs[0]
	// 2. beef: the carrier (unproven) and its funding tree (proven,
	// minimally).
	tree, err := w.Carrier(tx)
	if err != nil {
		return nil, err
	}
	// 3. the record's own rules, the inline ciphertext's length and hash
	// among them.
	record, _ := pushdrop.FirstPush(*out.LockingScript)
	s, err := DecodeSecret(record)
	if err != nil {
		return nil, err
	}
	c := &Carrier{Secret: s, Owner: s.Org, Record: record, Commitment: carrier.Commitment(tx),
		Funding: transaction.Outpoint{Txid: tree.Txid, Index: in.SourceTxOutIndex}}
	if c.ContentID, err = s.ContentID(); err != nil {
		return nil, err
	}
	// 4. crypt.
	if s.Crypt != h.Crypt {
		return nil, fmt.Errorf("%w: not this topic's crypt", ErrCrypt)
	}
	// 5. mineable.
	if tx.LockTime < carrier.LockTime || in.SequenceNumber == transaction.MaxTxInSequenceNum {
		return nil, ErrMineable
	}
	// 6. unlock, bcommon's check.
	if err := carrier.CheckUnlocking(tx); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnlock, err)
	}
	// 7. lock: the one-field signed PushDrop under derive(owner, "secret").
	key := lockingKey(SecretDerivation, c.Owner)
	fields, _ := pushdrop.Fields(*out.LockingScript)
	if len(fields) != 2 {
		return nil, fmt.Errorf("%w: %d pushes, want the record and a signature", ErrLock, len(fields))
	}
	sig := fields[1]
	if !bytes.Equal(*out.LockingScript, PushDropScript(key, [][]byte{record}, sig)) {
		return nil, ErrLock
	}
	// 8. signature.
	if !chaintoken.VerifyField(key, record, sig) {
		return nil, ErrFieldSig
	}
	// 9. funding: the output spent, read from the funding tree in the BEEF,
	// is a funding output under the same key, and its whole value is
	// carried.
	if int(in.SourceTxOutIndex) >= len(tree.Tx.Outputs) {
		return nil, fmt.Errorf("%w: the funding tree has no such output", ErrFunding)
	}
	src := tree.Tx.Outputs[in.SourceTxOutIndex]
	if src == nil || src.LockingScript == nil || !bytes.Equal(*src.LockingScript, FundingScript(key)) {
		return nil, ErrFunding
	}
	if src.Satoshis != out.Satoshis {
		return nil, fmt.Errorf("%w: output %d of input %d", ErrFunding, out.Satoshis, src.Satoshis)
	}
	return c, nil
}

// checkToken is the vault token's rules 1 to 10.
func (a *Admission) checkToken(ctx context.Context, w *chaintoken.Wire, tx *transaction.Transaction, at int, h Host) error {
	out := tx.Outputs[at]
	// 1. shape: a PushDrop of two fields and a signature, of 1 satoshi.
	to, ok := chaintoken.ReadOutput(out, uint32(at), 2)
	if !ok {
		return fmt.Errorf("%w: a token is two fields, a signature and 1 satoshi", ErrShape)
	}
	// 2. beef: the token and its parent, each proven minimally, or one
	// merged path when both are in one block. Never an Atomic BEEF.
	parent, err := w.Token(tx)
	if err != nil {
		return err
	}
	// 3. the record's own rules.
	v, err := DecodeVault(to.Fields[1])
	if err != nil {
		return err
	}
	t := &VaultToken{Vault: v, Record: to.Fields[1], Vout: uint32(at)}
	// 4. crypt.
	if v.Crypt != h.Crypt {
		return fmt.Errorf("%w: not this topic's crypt", ErrCrypt)
	}
	// 5. lock.
	key := lockingKey(VaultDerivation, v.Org)
	if !to.LockedTo(*out.LockingScript, key) {
		return ErrLock
	}
	// 6. signature.
	if !to.SignedBy(key) {
		return ErrFieldSig
	}
	// 7. unmined: the token's and the parent's proofs.
	if !IsMined(ctx, tx, h.Headers) || !IsMined(ctx, parent.Tx, h.Headers) {
		return ErrUnmined
	}
	// 8. token-input: every spend is read from the parent in the BEEF.
	ptxid := [32]byte(parent.Txid)
	spends := chaintoken.Spends(tx, parent)
	a.Token, a.Parent = t, ptxid
	if v.Seq == 0 {
		if len(spends) != 1 {
			return fmt.Errorf("%w: seq 0 has %d inputs spending its parent, want one", ErrTokenInput, len(spends))
		}
		sp := spends[0]
		if !bytes.Equal(*sp.Output.LockingScript, FundingScript(lockingKey(ChainDerivation, v.Org))) {
			return fmt.Errorf("%w: seq 0 does not spend a chain-tree output of the owner", ErrTokenInput)
		}
		// 9. vault-id.
		if v.Vault != VaultID(ptxid, sp.Vout) {
			return ErrVaultID
		}
		a.Spends = transaction.Outpoint{Txid: parent.Txid, Index: sp.Vout}
		return nil
	}
	var pred *VaultToken
	spendsToken := 0
	for _, sp := range spends {
		if Classify(*sp.Output.LockingScript) != KindVault {
			continue
		}
		spendsToken++
		if p, err := readTokenOutput(sp.Output, sp.Vout); err == nil {
			pred = p
		}
	}
	if ptxid != v.Prev || spendsToken != 1 || pred == nil || !samePredecessor(v, pred.Vault) {
		return fmt.Errorf("%w: the parent's token at seq - 1 is not spent exactly once", ErrTokenInput)
	}
	// 10. the transition rules against the predecessor.
	if err := CheckVaultTransition(pred.Vault, ptxid, v); err != nil {
		return err
	}
	a.Predecessor = pred
	a.Spends = transaction.Outpoint{Txid: parent.Txid, Index: pred.Vout}
	return nil
}

// samePredecessor is rule 8's "a well-formed vault token of the same crypt,
// owner and vault at seq - 1".
func samePredecessor(t, p *Vault) bool {
	return p.Crypt == t.Crypt && bytes.Equal(p.Org, t.Org) && p.Vault == t.Vault && p.Seq+1 == t.Seq
}

// readTokenOutput is the well-formed reading of one token output (docs/spec.md
// section 11.1): it classifies as a vault token, is a PushDrop of exactly
// two fields and a signature holding 1 satoshi, its record decodes, its
// script is the canonical one under the key derived from the record's org,
// and its field signature is strict and verifies under that key. The record
// is not held to its own transition rules.
func readTokenOutput(o *transaction.TransactionOutput, vout uint32) (*VaultToken, error) {
	if o == nil || o.LockingScript == nil || Classify(*o.LockingScript) != KindVault {
		return nil, errNoPredRead
	}
	to, ok := chaintoken.ReadOutput(o, vout, 2)
	if !ok {
		return nil, errNoPredRead
	}
	v, err := DecodeVault(to.Fields[1])
	if err != nil {
		return nil, err
	}
	key := lockingKey(VaultDerivation, v.Org)
	if !to.LockedTo(*o.LockingScript, key) || !to.SignedBy(key) {
		return nil, errNoPredRead
	}
	return &VaultToken{Vault: v, Record: to.Fields[1], Vout: vout}, nil
}

// ReadToken reads the one vault token a transaction holds, well formed,
// without its parent: how the index and a reader read a stored token
// (docs/spec.md section 11.4), which the engine keeps alone with its proof.
func ReadToken(tx *transaction.Transaction) (*VaultToken, error) {
	var found *VaultToken
	for i, o := range tx.Outputs {
		if o == nil || o.LockingScript == nil || Classify(*o.LockingScript) != KindVault {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%w: two token outputs", ErrShape)
		}
		t, err := readTokenOutput(o, uint32(i))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrShape, err)
		}
		found = t
	}
	if found == nil {
		return nil, ErrNotBsecret
	}
	return found, nil
}

// PredecessorSpend finds the input of a stored token that spends the token
// output of prev, the transaction holding the token before it: the check a
// reader and the index make when they walk a chain by spends (docs/spec.md
// sections 11.2 and 14). It reports false when no input, or more than one,
// spends a token output of prev.
func PredecessorSpend(tx, prev *transaction.Transaction) (uint32, bool) {
	ptxid := *prev.TxID()
	found, n := uint32(0), 0
	for _, in := range tx.Inputs {
		if in.SourceTXID == nil || *in.SourceTXID != ptxid || int(in.SourceTxOutIndex) >= len(prev.Outputs) {
			continue
		}
		o := prev.Outputs[in.SourceTxOutIndex]
		if o != nil && o.LockingScript != nil && Classify(*o.LockingScript) == KindVault {
			found = in.SourceTxOutIndex
			n++
		}
	}
	return found, n == 1
}

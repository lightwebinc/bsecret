// Package limits measures what bsecret puts on the plane, so that
// docs/limits.md quotes sizes a program produced rather than estimates.
package limits

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/lightwebinc/bcommon/carrier"
	"github.com/lightwebinc/bcommon/mint"

	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/vectors"
)

// fragment is the object bytes one plane packet carries at the 1280-byte
// IPv6 minimum MTU, less the IPv6, UDP and object fragment headers.
const fragment = 1128

// depth is the Merkle path depth of a mined transaction's block: 2^16 is a
// block of about 65,000 transactions.
const depth = 16

func prove(tx *transaction.Transaction) {
	isTxid := true
	path := make([][]*transaction.PathElement, depth)
	for l := 0; l < depth; l++ {
		sib := chainhash.Hash{byte(l + 1)}
		path[l] = []*transaction.PathElement{{Offset: 1, Hash: &sib}}
	}
	path[0] = append([]*transaction.PathElement{{Offset: 0, Hash: tx.TxID(), Txid: &isTxid}}, path[0]...)
	tx.MerklePath = transaction.NewMerklePath(900_000, path)
}

func coin(k *ec.PrivateKey, sats uint64) (*transaction.Transaction, *script.Script) {
	addr, _ := script.NewAddressFromPublicKey(k.PubKey(), false)
	payTo, _ := p2pkh.Lock(addr)
	c := transaction.NewTransaction()
	nowhere := chainhash.Hash{0x11}
	c.AddInput(&transaction.TransactionInput{SourceTXID: &nowhere, UnlockingScript: &script.Script{}, SequenceNumber: transaction.MaxTxInSequenceNum})
	c.AddOutput(&transaction.TransactionOutput{Satoshis: sats, LockingScript: payTo})
	return c, payTo
}

// carrierBEEF mints a real carrier for rec from a mined funding tree of
// count outputs and returns the size of the Atomic BEEF a publisher sends.
func carrierBEEF(t *testing.T, rec []byte, count int) int {
	t.Helper()
	ctx := context.Background()
	k := vectors.Org.Priv
	w, err := wallet.NewCompletedProtoWallet(k)
	if err != nil {
		t.Fatal(err)
	}
	p := carrier.Params{Derivation: secrec.SecretDerivation, FundingTag: secrec.TagFunding,
		ValidatePayload: func(b []byte) error { _, err := secrec.DecodeSecret(b); return err }}
	c, payTo := coin(k, 10_000_000)
	payer, _ := p2pkh.Unlock(k, nil)
	lock, err := carrier.FundingLock(ctx, w, "", p)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := mint.FundingTree(lock, count, 1000, mint.Input{Tx: c, Vout: 0, Unlocker: payer}, payTo, mint.DefaultFees)
	if err != nil {
		t.Fatal(err)
	}
	prove(tree)
	tx, err := carrier.Mint(ctx, w, "", p, rec, tree, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := secrec.Classify(*tx.Outputs[0].LockingScript); got != secrec.KindSecret {
		t.Fatalf("a minted carrier's output classifies %q", got)
	}
	if got := secrec.Classify(*tree.Outputs[0].LockingScript); got != secrec.KindFunding {
		t.Fatalf("a funding output classifies %q", got)
	}
	beef, err := tx.AtomicBEEF(false)
	if err != nil {
		t.Fatal(err)
	}
	return len(beef)
}

// tokenBEEF builds a vault token of the real shape (the signed token output,
// a fee input and change, and a stand-in for the predecessor input: one push
// of 72 bytes) and returns the size of the BEEF a publisher sends: the token
// and a parent of the same shape, each with a path. The sizes are real; the
// stand-in input would not pass a script interpreter.
func tokenBEEF(t *testing.T, rec, parentRec []byte) int {
	t.Helper()
	ctx := context.Background()
	k := vectors.Org.Priv
	w, _ := wallet.NewCompletedProtoWallet(k)
	lock, err := secrec.VaultDerivation.Lock(ctx, w, "", [][]byte{secrec.TagVault, rec}, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := secrec.Classify(*lock); got != secrec.KindVault {
		t.Fatalf("a vault token's output classifies %q", got)
	}
	parentLock, err := secrec.VaultDerivation.Lock(ctx, w, "", [][]byte{secrec.TagVault, parentRec}, true)
	if err != nil {
		t.Fatal(err)
	}
	c, payTo := coin(k, 100_000)
	payer, _ := p2pkh.Unlock(k, nil)
	tx := transaction.NewTransaction()
	if err := tx.AddInputFrom(c.TxID().String(), 0, c.Outputs[0].LockingScript.String(), 100_000, payer); err != nil {
		t.Fatal(err)
	}
	tx.Inputs[0].SourceTransaction = c
	prevTok := chainhash.Hash{0x22}
	sig := bytes.Repeat([]byte{0x30}, 72)
	unlock := script.Script(append([]byte{byte(len(sig))}, sig...))
	tx.AddInput(&transaction.TransactionInput{SourceTXID: &prevTok, UnlockingScript: &unlock, SequenceNumber: transaction.MaxTxInSequenceNum})
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: lock})
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: 99_000, LockingScript: payTo})
	if err := tx.Sign(); err != nil {
		t.Fatal(err)
	}
	prove(tx)
	parent := transaction.NewTransaction()
	nowhere := chainhash.Hash{0x33}
	parent.AddInput(&transaction.TransactionInput{SourceTXID: &nowhere, UnlockingScript: &unlock, SequenceNumber: transaction.MaxTxInSequenceNum})
	parent.AddInput(&transaction.TransactionInput{SourceTXID: &nowhere, SourceTxOutIndex: 1, UnlockingScript: &unlock, SequenceNumber: transaction.MaxTxInSequenceNum})
	parent.AddOutput(&transaction.TransactionOutput{Satoshis: 1, LockingScript: parentLock})
	parent.AddOutput(&transaction.TransactionOutput{Satoshis: 99_000, LockingScript: payTo})
	prove(parent)
	b := transaction.NewBeefV1()
	if _, err := b.MergeTransaction(parent); err != nil {
		t.Fatal(err)
	}
	tx.Inputs[0].SourceTransaction = nil
	if _, err := b.MergeTransaction(tx); err != nil {
		t.Fatal(err)
	}
	beef, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	back, err := transaction.NewBeefFromBytes(beef)
	if err != nil || back.FindTransaction(parent.TxID().String()) == nil || back.FindTransaction(tx.TxID().String()) == nil {
		t.Fatalf("the token's BEEF lost a transaction: %v", err)
	}
	return len(beef)
}

func packets(n int) int { return (n + fragment - 1) / fragment }

// secretRecord builds a secret record whose payload carries a value of n
// bytes, padded to 256, inline or not.
func secretRecord(t *testing.T, n int, inline bool) []byte {
	t.Helper()
	k := sha256.Sum256([]byte("size"))
	p := &secrec.Payload{Name: "a/secret", Value: bytes.Repeat([]byte{7}, n), Type: "text/plain"}
	b, err := p.EncodePadded(256)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := secrec.Seal(k, [secrec.SaltLen]byte{1}, 16384, b)
	if err != nil {
		t.Fatal(err)
	}
	s := &secrec.Secret{Crypt: vectors.Crypt, Org: vectors.Org.Pub(), Version: 1, Label: "confidential", Commitment: secrec.Commitment(k),
		Hash: sha256.Sum256(ct), Length: uint64(len(ct)), Salt: [secrec.SaltLen]byte{1}, Segment: 16384, Created: vectors.Created,
		Self: make([]byte, secrec.WrapLen), Wrap: make([]byte, secrec.WrapLen)}
	if inline {
		s.Inline = ct
	}
	raw, err := s.Encode()
	if err != nil {
		t.Fatalf("a value of %d bytes: %v", n, err)
	}
	return raw
}

func vaultRecord(t *testing.T, seq uint64, create, update, retire int) []byte {
	t.Helper()
	mk := func(tag byte, n int) []secrec.Entry {
		out := make([]secrec.Entry, n)
		for i := range out {
			out[i] = secrec.Entry{ID: sha256.Sum256([]byte{tag, byte(i), 1}), Version: 7, ContentID: sha256.Sum256([]byte{tag, byte(i), 2}),
				Commitment: sha256.Sum256([]byte{tag, byte(i), 3})}
		}
		for i := 1; i < len(out); i++ {
			for j := i; j > 0 && bytes.Compare(out[j-1].ID[:], out[j].ID[:]) > 0; j-- {
				out[j-1], out[j] = out[j], out[j-1]
			}
		}
		return out
	}
	ret := make([][32]byte, retire)
	for i := range ret {
		ret[i] = sha256.Sum256([]byte{9, byte(i)})
	}
	for i := 1; i < len(ret); i++ {
		for j := i; j > 0 && bytes.Compare(ret[j-1][:], ret[j][:]) > 0; j-- {
			ret[j-1], ret[j] = ret[j], ret[j-1]
		}
	}
	v := &secrec.Vault{Crypt: vectors.Crypt, Org: vectors.Org.Pub(), Seq: seq, Name: "Example vault", Hall: vectors.Hall,
		Labels: secrec.DefaultLabels, Create: mk(1, create), Update: mk(2, update), Retire: ret, Count: 200, Created: vectors.Created}
	if seq > 0 {
		v.Prev = sha256.Sum256([]byte("prev"))
	} else {
		v.Count = uint64(create)
	}
	raw, err := v.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestSizes prints the table docs/limits.md quotes and holds the sizes the
// document's recommendations rest on.
func TestSizes(t *testing.T) {
	// want is the table docs/limits.md prints, row for row: record bytes,
	// BEEF bytes, packets. A size that moves fails here, so the document
	// cannot drift from what is measured.
	want := [][3]int{
		{778, 2252, 2}, {778, 3428, 4}, {778, 6759, 6},
		{1802, 4451, 4}, {4874, 7523, 7}, {16650, 19300, 18},
		{504, 3154, 3},
		{437, 2913, 3}, {1165, 3641, 4}, {1997, 4473, 4}, {6990, 9468, 9}, {15824, 18300, 17},
		{1997, 6033, 6}, {6990, 16022, 15},
	}
	var lines []string
	row := func(what string, rec, beef int) {
		if n := len(lines); n >= len(want) || want[n] != [3]int{rec, beef, packets(beef)} {
			t.Errorf("row %d (%s): record %d, BEEF %d, packets %d is not what docs/limits.md prints", n, what, rec, beef, packets(beef))
		}
		lines = append(lines, fmt.Sprintf("%-58s record %5d  BEEF %6d  packets %2d", what, rec, beef, packets(beef)))
	}
	for _, tree := range []int{8, 32, 100} {
		rec := secretRecord(t, 32, true)
		n := carrierBEEF(t, rec, tree)
		row(fmt.Sprintf("secret, 32-byte value, tree of %d", tree), len(rec), n)
		if tree == 32 && packets(n) > 4 {
			t.Errorf("a small secret's carrier is %d packets", packets(n))
		}
	}
	for _, value := range []int{1024, 4096, 16000} {
		rec := secretRecord(t, value, true)
		n := carrierBEEF(t, rec, 32)
		row(fmt.Sprintf("secret, %d-byte value inline, tree of 32", value), len(rec), n)
		if value == 16000 && packets(n) > 18 {
			t.Errorf("the largest inline secret's carrier is %d packets", packets(n))
		}
	}
	rec := secretRecord(t, 1<<20, false)
	n := carrierBEEF(t, rec, 32)
	row("secret, 1 MiB value not carried, tree of 32", len(rec), n)
	if packets(n) > 3 {
		t.Errorf("a secret whose ciphertext is not carried is %d packets", packets(n))
	}
	small := vaultRecord(t, 1, 0, 1, 0)
	for _, c := range []struct{ create, update, retire int }{{0, 1, 0}, {0, 8, 0}, {0, 16, 0}, {0, 64, 0}, {64, 64, 64}} {
		rec := vaultRecord(t, 2, c.create, c.update, c.retire)
		n := tokenBEEF(t, rec, small)
		row(fmt.Sprintf("vault token: %d created, %d updated, %d retired", c.create, c.update, c.retire), len(rec), n)
		if c.update == 8 && packets(n) > 4 {
			t.Errorf("a vault token of 8 changes is %d packets", packets(n))
		}
	}
	rec16 := vaultRecord(t, 2, 0, 16, 0)
	n = tokenBEEF(t, rec16, rec16)
	row("vault token: 16 updated, after a token of 16 updated", len(rec16), n)
	full := vaultRecord(t, 2, 0, 64, 0)
	n = tokenBEEF(t, full, full)
	row("vault token: 64 updated, after a token of 64 updated", len(full), n)
	if len(lines) != len(want) {
		t.Errorf("%d rows measured, %d printed", len(lines), len(want))
	}
	// The largest objects: a carrier's BEEF carries its whole funding tree,
	// and a token's its parent. docs/limits.md quotes these three.
	big := carrierBEEF(t, secretRecord(t, 32, true), 1000)
	lines = append(lines, fmt.Sprintf("%-58s BEEF %6d  packets %2d", "secret, 32-byte value, tree of 1000", big, packets(big)))
	bigInline := carrierBEEF(t, secretRecord(t, 16000, true), 1000)
	lines = append(lines, fmt.Sprintf("%-58s BEEF %6d  packets %2d", "secret, 16000-byte value inline, tree of 1000", bigInline, packets(bigInline)))
	all := vaultRecord(t, 2, 64, 64, 64)
	bigToken := tokenBEEF(t, all, all)
	lines = append(lines, fmt.Sprintf("%-58s BEEF %6d  packets %2d", "vault token: 64/64/64, after a token of 64/64/64", bigToken, packets(bigToken)))
	if big != 50862 || bigInline != 66732 || bigToken != 33687 {
		t.Errorf("the largest objects are %d, %d and %d bytes, not what docs/limits.md prints", big, bigInline, bigToken)
	}
	for _, l := range lines {
		t.Log(l)
	}
}

package borgread

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/lightwebinc/bcommon/keyed"
)

// The fixtures under testdata are borg's own golden vectors, unchanged: the
// four tokens of its example group, the wraps of each epoch's key, and the
// epochs as borg derives them.

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(name, ".hex") {
		if b, err = hex.DecodeString(strings.TrimSpace(string(b))); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

type epochJSON struct {
	Epoch      uint64 `json:"epoch"`
	Key        string `json:"key"`
	Symmetric  string `json:"symmetricKey"`
	Commitment string `json:"commitment"`
	EpochID    string `json:"epochId"`
	Began      uint64 `json:"beganAtSeq"`
}

func epochs(t *testing.T) []epochJSON {
	t.Helper()
	var f struct {
		Epochs []epochJSON `json:"epochs"`
	}
	if err := json.Unmarshal(fixture(t, "epoch-v1.json"), &f); err != nil {
		t.Fatal(err)
	}
	return f.Epochs
}

// party is one of borg's test identities: 32 bytes of one value.
func party(b byte) *ec.PrivateKey {
	k, _ := ec.PrivateKeyFromBytes(bytes.Repeat([]byte{b}, 32))
	return k
}

func walletOf(k *ec.PrivateKey) wallet.Interface {
	w, err := wallet.NewCompletedProtoWallet(k)
	if err != nil {
		panic(err)
	}
	return w
}

var chainFiles = []string{"group-create.hex", "group-add.hex", "group-remove.hex", "group-rotate.hex"}

// links builds the chain from the fixtures: each token's txid is the one its
// successor names as prev.
func links(t *testing.T) []Link {
	t.Helper()
	var out []Link
	for i, f := range chainFiles {
		rec := fixture(t, f)
		g, err := DecodeGroup(rec)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if i > 0 {
			out[i-1].Txid = g.Prev
		}
		out = append(out, Link{Record: rec, Height: uint32(1000 + 10*i)})
	}
	return out
}

func TestFoldReproducesBorgEpochs(t *testing.T) {
	v, err := Fold(links(t))
	if err != nil {
		t.Fatal(err)
	}
	if v.Usable() != 4 {
		t.Fatalf("usable %d, statuses %v", v.Usable(), v.Statuses)
	}
	want := epochs(t)
	if len(v.Epochs) != len(want) || len(want) != 3 {
		t.Fatalf("%d epochs, want %d", len(v.Epochs), len(want))
	}
	for i, e := range v.Epochs {
		w := want[i]
		if e.Epoch != w.Epoch || hex.EncodeToString(e.ID[:]) != w.EpochID || hex.EncodeToString(e.Commitment[:]) != w.Commitment || e.Seq != w.Began {
			t.Errorf("epoch %d: %+v, want %+v", i, e, w)
		}
		k, _ := hex.DecodeString(w.Key)
		c := keyed.Commitment([32]byte(k))
		s := keyed.SymmetricKey([32]byte(k))
		if c != e.Commitment || hex.EncodeToString(s[:]) != w.Symmetric {
			t.Errorf("epoch %d: the key does not give the commitment and symmetric key", i)
		}
	}
	if !v.Epochs[1].Removed || v.Epochs[0].Removed || v.Epochs[2].Removed {
		t.Errorf("removed flags %+v", v.Epochs)
	}
	if len(v.Members()) != 2 || v.Latest().Epoch != 2 {
		t.Errorf("members %d, latest epoch %d", len(v.Members()), v.Latest().Epoch)
	}
	if e, ok := v.EpochByNumber(1); !ok || e.Seq != 2 {
		t.Errorf("epoch 1: %+v %v", e, ok)
	}
	if _, ok := v.EpochByNumber(3); ok {
		t.Error("epoch 3 was never begun")
	}
}

func TestFoldRefuses(t *testing.T) {
	l := links(t)
	if _, err := Fold(l[1:]); !errors.Is(err, ErrChain) {
		t.Errorf("a chain that starts at seq 1: %v", err)
	}
	skip := []Link{l[0], l[2]}
	if _, err := Fold(skip); !errors.Is(err, ErrTransition) {
		t.Errorf("a missing token: %v", err)
	}
	wrong := append([]Link(nil), l...)
	wrong[0].Txid[0] ^= 1
	if _, err := Fold(wrong); !errors.Is(err, ErrTransition) {
		t.Errorf("a prev that is not the predecessor's txid: %v", err)
	}
	low := append([]Link(nil), l...)
	low[2].Height = 5
	if _, err := Fold(low); !errors.Is(err, ErrChain) {
		t.Errorf("a token mined below its predecessor: %v", err)
	}
	cut := append([]byte(nil), l[0].Record...)
	if _, err := Fold([]Link{{Record: cut[:len(cut)-1]}}); Reason(err) != "cbor" {
		t.Errorf("a cut record: %v", err)
	}
}

func TestWrapsOpenForTheirMembers(t *testing.T) {
	ctx := context.Background()
	l := links(t)
	began := map[uint64][]byte{0: l[0].Record, 1: l[2].Record, 2: l[3].Record}
	es := epochs(t)
	members := map[string]*ec.PrivateKey{"alice": party(0x52), "bob": party(0x53), "carol": party(0x54)}
	opened := map[string]map[uint64]bool{"alice": {}, "bob": {}, "carol": {}}
	for _, f := range []string{"wrap-create.hex", "wrap-add.hex", "wrap-remove.hex", "wrap-rotate.hex"} {
		w, err := DecodeWrap(fixture(t, f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for name, k := range members {
			got, err := Open(ctx, walletOf(k), k.PubKey().Compressed(), began[w.Epoch], w)
			if err != nil {
				continue
			}
			if hex.EncodeToString(got[:]) != es[w.Epoch].Key {
				t.Errorf("%s: %s opened another key", f, name)
			}
			opened[name][w.Epoch] = true
		}
		// The wrap held against another epoch's token is refused.
		other := began[(w.Epoch+1)%3]
		if _, err := CheckEpochToken(other, w); !errors.Is(err, ErrToken) {
			t.Errorf("%s against another epoch's token: %v", f, err)
		}
		// A stranger holds no entry.
		d := party(0x56)
		if _, err := Open(ctx, walletOf(d), d.PubKey().Compressed(), began[w.Epoch], w); Reason(err) != "undecryptable" {
			t.Errorf("%s: a stranger: %v", f, err)
		}
	}
	for name, want := range map[string][]bool{"alice": {true, true, true}, "bob": {true, false, false}, "carol": {true, true, true}} {
		for e, w := range want {
			if opened[name][uint64(e)] != w {
				t.Errorf("%s epoch %d: opened %v, want %v", name, e, opened[name][uint64(e)], w)
			}
		}
	}
}

func TestWrapEntryRules(t *testing.T) {
	rec := fixture(t, "wrap-create.hex")
	w, err := DecodeWrap(rec)
	if err != nil {
		t.Fatal(err)
	}
	e := w.Entries[0]
	if _, err := CheckEntry(e, w.Org, w.EpochID, uint32(w.Epoch)+1); !errors.Is(err, ErrEntry) {
		t.Errorf("an entry replayed to another epoch: %v", err)
	}
	if _, err := CheckEntry(e[:len(e)-1], w.Org, w.EpochID, uint32(w.Epoch)); !errors.Is(err, ErrEntry) {
		t.Errorf("a short entry: %v", err)
	}
	bad := append([]byte(nil), e...)
	bad[0] = 0x10
	if _, err := CheckEntry(bad, w.Org, w.EpochID, uint32(w.Epoch)); !errors.Is(err, ErrEntry) {
		t.Errorf("another version prefix: %v", err)
	}
	// A wrong key wrapped: the member's wallet opens it and the commitment
	// refuses it.
	l := links(t)
	g, _ := DecodeGroup(l[0].Record)
	alice := party(0x52)
	org, _ := ec.PublicKeyFromBytes(w.Org)
	var mine []byte
	for _, x := range w.Entries {
		if bytes.Equal(x[37:70], alice.PubKey().Compressed()) {
			mine = x
		}
	}
	var other [32]byte
	other[0] = 1
	if _, err := Unwrap(context.Background(), walletOf(alice), mine, org, w.EpochID, uint32(w.Epoch), other); Reason(err) != "commitment" {
		t.Errorf("a key that is not the committed one: %v", err)
	}
	if _, err := Unwrap(context.Background(), walletOf(alice), mine, org, w.EpochID, uint32(w.Epoch), g.Commitment); err != nil {
		t.Errorf("alice's own entry: %v", err)
	}
}

// tokenTx builds a transaction whose output 0 is a group token of rec,
// locked and signed by k under borg's group derivation.
func tokenTx(t *testing.T, k *ec.PrivateKey, rec []byte, sats uint64) *transaction.Transaction {
	t.Helper()
	lock, err := GroupDerivation.Lock(context.Background(), walletOf(k), "", [][]byte{TagGroup, rec}, true)
	if err != nil {
		t.Fatal(err)
	}
	tx := transaction.NewTransaction()
	src := chainhash.Hash{0x11}
	tx.AddInput(&transaction.TransactionInput{SourceTXID: &src, UnlockingScript: &script.Script{}, SequenceNumber: 0xffffffff})
	tx.AddOutput(&transaction.TransactionOutput{Satoshis: sats, LockingScript: lock})
	return tx
}

func TestReadToken(t *testing.T) {
	rec := fixture(t, "group-create.hex")
	org := party(0x51)
	tok, err := ReadToken(tokenTx(t, org, rec, 1))
	if err != nil {
		t.Fatal(err)
	}
	if tok.Group.Seq != 0 || !bytes.Equal(tok.Record, rec) || tok.Vout != 0 {
		t.Errorf("read %+v", tok)
	}
	if _, err := ReadToken(tokenTx(t, org, rec, 2)); !errors.Is(err, ErrToken) {
		t.Errorf("a token of 2 satoshis: %v", err)
	}
	if _, err := ReadToken(tokenTx(t, party(0x52), rec, 1)); !errors.Is(err, ErrToken) {
		t.Errorf("the organisation's record under a member's key: %v", err)
	}
	two := tokenTx(t, org, rec, 1)
	two.AddOutput(two.Outputs[0])
	if _, err := ReadToken(two); !errors.Is(err, ErrToken) {
		t.Errorf("two token outputs: %v", err)
	}
	none := transaction.NewTransaction()
	if _, err := ReadToken(none); !errors.Is(err, ErrToken) {
		t.Errorf("no token output: %v", err)
	}
}

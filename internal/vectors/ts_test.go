package vectors

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// tsFile is testdata/ts/ts-v1.json, written by the TypeScript codec.
type tsFile struct {
	Crypt     string `json:"crypt"`
	CryptDraw struct {
		Name   string `json:"name"`
		Random string `json:"random"`
		Crypt  string `json:"crypt"`
	} `json:"cryptDraw"`
	Vault  string `json:"vault"`
	Epochs []struct {
		Epoch     uint64 `json:"epoch"`
		Key       string `json:"key"`
		Symmetric string `json:"symmetricKey"`
		EpochID   string `json:"epochId"`
	} `json:"epochs"`
	Vaults  []string `json:"vaults"`
	Secrets []struct {
		Name      string `json:"name"`
		Version   uint64 `json:"version"`
		Epoch     uint64 `json:"epoch"`
		Value     string `json:"value"`
		Key       string `json:"key"`
		ContentID string `json:"contentId"`
		Record    string `json:"record"`
	} `json:"secrets"`
	Context struct {
		Secret  string `json:"secret"`
		Version uint64 `json:"version"`
		Hex     string `json:"hex"`
	} `json:"context"`
	Headers []struct {
		Height     uint32 `json:"height"`
		MerkleRoot string `json:"merkleRoot"`
	} `json:"headers"`
	Transactions []struct {
		Name string `json:"name"`
		Txid string `json:"txid"`
		BEEF string `json:"beef"`
		Kind string `json:"kind"`
	} `json:"transactions"`
}

func unhexT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readTS(t *testing.T) *tsFile {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../../testdata/ts", "ts-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f tsFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

// TestTSRecords decodes and re-encodes every record the TypeScript codec
// wrote, unknown keys kept, and draws the same crypt from the same bytes.
func TestTSRecords(t *testing.T) {
	f := readTS(t)
	crypt, err := secrec.NewCrypt(f.CryptDraw.Name, bytes.NewReader(unhexT(t, f.CryptDraw.Random)))
	if err != nil || crypt != f.CryptDraw.Crypt {
		t.Fatalf("crypt draw: %q %v, want %q", crypt, err, f.CryptDraw.Crypt)
	}
	if len(f.Vaults) != 3 || len(f.Secrets) != 4 {
		t.Fatalf("%d vault records, %d secrets", len(f.Vaults), len(f.Secrets))
	}
	extras := 0
	for i, h := range f.Vaults {
		raw := unhexT(t, h)
		v, err := secrec.DecodeVault(raw)
		if err != nil {
			t.Fatalf("vault %d: %v", i, err)
		}
		re, err := v.Encode()
		if err != nil || !bytes.Equal(re, raw) {
			t.Errorf("vault %d does not re-encode to itself (%v)", i, err)
		}
		if hex.EncodeToString(v.Vault[:]) != f.Vault || v.Crypt != f.Crypt {
			t.Errorf("vault %d names another vault or crypt", i)
		}
		extras += len(v.Extra)
	}
	for _, s := range f.Secrets {
		raw := unhexT(t, s.Record)
		rec, err := secrec.DecodeSecret(raw)
		if err != nil {
			t.Fatalf("%s@%d: %v", s.Name, s.Version, err)
		}
		re, err := rec.Encode()
		if err != nil || !bytes.Equal(re, raw) {
			t.Errorf("%s@%d does not re-encode to itself (%v)", s.Name, s.Version, err)
		}
		cid, err := rec.ContentID()
		if err != nil || hex.EncodeToString(cid[:]) != s.ContentID {
			t.Errorf("%s@%d: content id %x", s.Name, s.Version, cid)
		}
		id, err := secrec.SecretID(rec.Vault, s.Name)
		if err != nil || id != rec.ID {
			t.Errorf("%s@%d: the name does not hash to the id", s.Name, s.Version)
		}
		extras += len(rec.Extra)
	}
	if extras != 2 {
		t.Errorf("%d unknown keys kept, want one in a vault record and one in a secret record", extras)
	}
}

// TestTSSecretsOpen reads every secret the TypeScript side sealed and
// wrapped: through the owner's wallet, whose BRC-2 key the TypeScript SDK
// derived, and under the key of the epoch it names and no other.
func TestTSSecretsOpen(t *testing.T) {
	f := readTS(t)
	ctx := context.Background()
	used := secrec.NewCommitments()
	for _, s := range f.Secrets {
		rec, err := secrec.DecodeSecret(unhexT(t, s.Record))
		if err != nil {
			t.Fatal(err)
		}
		if rec.Inline == nil || rec.Epoch != s.Epoch {
			t.Fatalf("%s@%d: inline %v epoch %d", s.Name, s.Version, rec.Inline != nil, rec.Epoch)
		}
		if secrec.Commitment([32]byte(unhexT(t, s.Key))) != rec.Commitment {
			t.Errorf("%s@%d: the key is not the committed one", s.Name, s.Version)
		}
		if err := used.Use(rec.Commitment); err != nil {
			t.Errorf("%s@%d: %v", s.Name, s.Version, err)
		}
		p, err := secrec.ReadAsOwner(ctx, Org.Wallet(), rec, rec.Inline)
		if err != nil || p.Name != s.Name || string(p.Value) != s.Value {
			t.Errorf("%s@%d: the owner's wallet does not read it: %v", s.Name, s.Version, err)
		}
		if _, err := secrec.ReadAsOwner(ctx, Alice.Wallet(), rec, rec.Inline); secrec.Reason(err) != "undecryptable" {
			t.Errorf("%s@%d: another wallet: %v", s.Name, s.Version, err)
		}
		for _, e := range f.Epochs {
			if secrec.SymmetricKey([32]byte(unhexT(t, e.Key))) != [32]byte(unhexT(t, e.Symmetric)) {
				t.Errorf("epoch %d: symmetric key", e.Epoch)
			}
			p, err := secrec.ReadAsMember(rec, rec.Inline, [32]byte(unhexT(t, e.Symmetric)))
			switch {
			case e.Epoch == rec.Epoch && (err != nil || string(p.Value) != s.Value):
				t.Errorf("%s@%d: a member of epoch %d does not read it: %v", s.Name, s.Version, e.Epoch, err)
			case e.Epoch != rec.Epoch && secrec.Reason(err) != "undecryptable":
				t.Errorf("%s@%d under epoch %d's key: %v", s.Name, s.Version, e.Epoch, err)
			}
		}
		// A changed ciphertext reads hash, before any wrap is opened.
		bad := append([]byte(nil), rec.Inline...)
		bad[0] ^= 1
		if _, err := secrec.ReadAsMember(rec, bad, [32]byte{}); secrec.Reason(err) != "hash" {
			t.Errorf("%s@%d: a changed ciphertext: %v", s.Name, s.Version, err)
		}
	}
	if used.Use(used0(t, f)) == nil {
		t.Error("a commitment used twice is not refused")
	}
}

func used0(t *testing.T, f *tsFile) [32]byte {
	rec, err := secrec.DecodeSecret(unhexT(t, f.Secrets[0].Record))
	if err != nil {
		t.Fatal(err)
	}
	return rec.Commitment
}

// TestTSTransactions admits every transaction the TypeScript side built,
// rebuilds each token's BEEF byte for byte, walks the chain by spends as a
// host stores it, folds it, and checks the TypeScript inclusion context.
func TestTSTransactions(t *testing.T) {
	f := readTS(t)
	h := Headers{}
	for _, x := range f.Headers {
		r, err := chainhash.NewHashFromHex(x.MerkleRoot)
		if err != nil {
			t.Fatal(err)
		}
		h[x.Height] = *r
	}
	fold := secrec.NewVaultFold()
	var prevTx *transaction.Transaction
	var prevTok *secrec.VaultToken
	kinds := map[string]int{}
	for _, c := range f.Transactions {
		raw := unhexT(t, c.BEEF)
		a, err := secrec.Admit(context.Background(), raw, nil, secrec.Host{Crypt: f.Crypt, Headers: h})
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		if a.Kind.String() != c.Kind || chainhash.Hash(a.Txid).String() != c.Txid {
			t.Errorf("%s: admitted as %s %x", c.Name, a.Kind, a.Txid)
		}
		kinds[c.Kind]++
		if a.Token == nil {
			continue
		}
		b, err := transaction.NewBeefFromBytes(raw)
		if err != nil {
			t.Fatal(err)
		}
		if c.Name == "vault-1-same-block" && len(b.BUMPs) != 1 {
			t.Errorf("%s: %d BUMPs, want the one merged path", c.Name, len(b.BUMPs))
		}
		tok := b.FindTransaction(c.Txid)
		par := b.FindTransaction(chainhash.Hash(a.Parent).String())
		rebuilt, err := secrec.TokenBEEF(tok, par)
		if err != nil || !bytes.Equal(rebuilt, raw) {
			t.Errorf("%s: the Go TokenBEEF differs from the TypeScript one (%v)", c.Name, err)
		}
		// As a host stores it: alone, read without its parent.
		sb, err := tok.AtomicBEEF(false)
		if err != nil {
			t.Fatal(err)
		}
		tx, st, err := secrec.StoredToken(sb)
		if err != nil {
			t.Fatalf("%s: stored: %v", c.Name, err)
		}
		if prevTx == nil {
			if _, _, err := secrec.CheckFirstToken(tx); err != nil {
				t.Errorf("%s: %v", c.Name, err)
			}
		} else if _, err := secrec.CheckNextToken(prevTx, prevTok, tx); err != nil {
			t.Errorf("%s does not descend from the token before it: %v", c.Name, err)
		}
		if got := fold.Apply(st.Vault); got != secrec.StatusConsistent {
			t.Errorf("%s folds %s", c.Name, got)
		}
		prevTx, prevTok = tx, st
	}
	if kinds["secret"] != 4 || kinds["vault-token"] != 3 || kinds["sweep"] != 1 {
		t.Errorf("admitted %v", kinds)
	}
	if prevTok == nil || prevTok.Vault.Seq != 2 || fold.Stale() != 1 {
		t.Fatalf("the chain ends at %+v with %d stale", prevTok, fold.Stale())
	}
	// The TypeScript context takes the re-keyed record to the last token's
	// root, and names that token.
	path, err := secrec.DecodeContext(unhexT(t, f.Context.Hex))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := secrec.DecodeSecret(unhexT(t, f.Secrets[3].Record))
	if err != nil {
		t.Fatal(err)
	}
	if err := secrec.CheckInSet(prevTok.Vault, [32]byte(*prevTx.TxID()), rec, path); err != nil {
		t.Errorf("the TypeScript context: %v", err)
	}
	re, err := path.Encode()
	if err != nil || hex.EncodeToString(re) != f.Context.Hex {
		t.Errorf("the context does not re-encode to itself (%v)", err)
	}
	// The stale record, keyed under the earlier epoch, is in the set only
	// because the token counts it stale.
	stale, err := secrec.DecodeSecret(unhexT(t, f.Secrets[2].Record))
	if err != nil {
		t.Fatal(err)
	}
	sp, err := secrec.ProveSecret(2, [32]byte(*prevTx.TxID()), fold.Set(), stale.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := secrec.CheckInSet(prevTok.Vault, [32]byte(*prevTx.TxID()), stale, sp); err != nil {
		t.Errorf("the stale record: %v", err)
	}
}

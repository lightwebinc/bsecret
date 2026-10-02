package vectors

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/lightwebinc/bsecret/internal/borgread"
	"github.com/lightwebinc/bsecret/internal/secrec"
)

type storedTok struct {
	Name     string `json:"name"`
	Txid     string `json:"txid"`
	Stored   string `json:"stored"`
	Seq      uint64 `json:"seq"`
	Record   string `json:"record"`
	Parent   string `json:"parentTxid"`
	Spends   string `json:"spends"`
	Replayed string `json:"replayBeef"`
}

type txFile struct {
	Crypt          string         `json:"crypt"`
	MaxBEEF        int            `json:"maxBeef"`
	MaxSweepInputs int            `json:"maxSweepInputs"`
	Vault          string         `json:"vault"`
	Rows           map[string]int `json:"rows"`
	Headers        []struct {
		Height     uint32 `json:"height"`
		MerkleRoot string `json:"merkleRoot"`
	} `json:"headers"`
	Cases  []txJSON    `json:"cases"`
	Stored []storedTok `json:"stored"`
}

func readTxFile(t *testing.T) (*txFile, Headers) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "transaction-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f txFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	h := Headers{}
	for _, x := range f.Headers {
		r, err := chainhash.NewHashFromHex(x.MerkleRoot)
		if err != nil {
			t.Fatal(err)
		}
		h[x.Height] = *r
	}
	return &f, h
}

// TestTransactionFile replays transaction-v1.json from the file alone, as a
// second implementation would: every case admitted or refused with its
// reason, and every admission's instructions and records as written.
func TestTransactionFile(t *testing.T) {
	f, h := readTxFile(t)
	if len(f.Cases) < 130 {
		t.Fatalf("%d cases", len(f.Cases))
	}
	rows := map[string]int{}
	for _, c := range f.Cases {
		beef, _ := hex.DecodeString(c.BEEF)
		held := []int{}
		for _, coin := range c.Coins {
			held = append(held, coin.InputIndex)
		}
		if !c.Scripts {
			t.Errorf("%s: its scripts do not verify", c.Name)
		}
		a, err := secrec.Admit(context.Background(), beef, held, secrec.Host{Crypt: f.Crypt, Headers: h, MaxBEEF: f.MaxBEEF, MaxSweepInputs: c.MaxSweepInputs})
		if c.Verdict == "refuse" {
			if got := secrec.Reason(err); got != c.Reason {
				t.Errorf("%s: %q (%v), want %q", c.Name, got, err, c.Reason)
			}
			rows[c.Rule]++
			continue
		}
		if err != nil {
			t.Errorf("%s: refused: %v", c.Name, err)
			continue
		}
		got, _ := json.Marshal(admission(a))
		want, _ := json.Marshal(c.Admits)
		if string(got) != string(want) {
			t.Errorf("%s: admits %s, want %s", c.Name, got, want)
		}
	}
	// Every provisional row of the frozen list is pinned by refusals.
	for _, r := range []string{rowCarrier, rowToken, rowCanonical, rowSigs, rowOneClaim, rowSweep} {
		if rows[r] == 0 || rows[r] != f.Rows[r] {
			t.Errorf("row %q: %d refusals, the file says %d", r, rows[r], f.Rows[r])
		}
	}
}

// TestPreviousCoinsDecideNoVerdict admits every case with no previous
// coins, and with every input named as one: the verdict and the reason are
// the same, and only what is retained moves.
func TestPreviousCoinsDecideNoVerdict(t *testing.T) {
	f, h := readTxFile(t)
	for _, c := range f.Cases {
		beef, _ := hex.DecodeString(c.BEEF)
		raw, _ := hex.DecodeString(c.RawTx)
		tx, err := transaction.NewTransactionFromBytes(raw)
		if err != nil {
			t.Fatal(err)
		}
		all := []int{}
		for i := range tx.Inputs {
			all = append(all, i)
		}
		host := secrec.Host{Crypt: f.Crypt, Headers: h, MaxSweepInputs: c.MaxSweepInputs}
		for _, held := range [][]int{nil, all} {
			a, err := secrec.Admit(context.Background(), beef, held, host)
			if (err == nil) != (c.Verdict == "admit") || (err != nil && secrec.Reason(err) != c.Reason) {
				t.Errorf("%s with %d previous coins: %v", c.Name, len(held), err)
			}
			if err == nil && len(a.Retain) != len(held) {
				t.Errorf("%s: retains %v of %v", c.Name, a.Retain, held)
			}
		}
		// A previous coin that names no input is the engine's error, not a
		// verdict on the transaction.
		if _, err := secrec.Admit(context.Background(), beef, []int{len(tx.Inputs)}, host); c.Verdict == "admit" && secrec.Reason(err) != "other" {
			t.Errorf("%s: an out-of-range previous coin: %v", c.Name, err)
		}
	}
}

// TestStoredTokens reads each stored token without its parent, walks the
// chain by spends, and reassembles the BEEF each was admitted in.
func TestStoredTokens(t *testing.T) {
	f, _ := readTxFile(t)
	if len(f.Stored) != 4 {
		t.Fatalf("%d stored tokens", len(f.Stored))
	}
	var prevTx *transaction.Transaction
	var prevTok *secrec.VaultToken
	for i, s := range f.Stored {
		b, _ := hex.DecodeString(s.Stored)
		tx, tok, err := secrec.StoredToken(b)
		if err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
		if tok.Vault.Seq != s.Seq || hex.EncodeToString(tok.Record) != s.Record || hex.EncodeToString(tok.Vault.Vault[:]) != f.Vault {
			t.Errorf("%s: read seq %d", s.Name, tok.Vault.Seq)
		}
		if i == 0 {
			_, op, err := secrec.CheckFirstToken(tx)
			if err != nil || outpointString(op) != s.Spends {
				t.Errorf("%s: first token: %v %s", s.Name, err, outpointString(op))
			}
			if _, err := secrec.CheckNextToken(tx, tok, tx); err == nil {
				t.Errorf("%s descends from itself", s.Name)
			}
		} else {
			if _, err := secrec.CheckNextToken(prevTx, prevTok, tx); err != nil {
				t.Errorf("%s does not descend from the token before it: %v", s.Name, err)
			}
			if _, _, err := secrec.CheckFirstToken(tx); err == nil {
				t.Errorf("%s reads as a first token", s.Name)
			}
			replay, err := secrec.TokenBEEF(tx, prevTx)
			if err != nil || hex.EncodeToString(replay) != s.Replayed {
				t.Errorf("%s: replay differs (%v)", s.Name, err)
			}
		}
		if i >= 2 {
			// A token does not descend from the one two before it.
			pb, _ := hex.DecodeString(f.Stored[i-2].Stored)
			ptx, ptok, _ := secrec.StoredToken(pb)
			if _, err := secrec.CheckNextToken(ptx, ptok, tx); secrec.Reason(err) != "token-input" {
				t.Errorf("%s against seq %d: %v", s.Name, ptok.Vault.Seq, err)
			}
		}
		prevTx, prevTok = tx, tok
	}
}

// TestIndexFile recomputes index-v1.json from the file alone: which held
// tokens are rooted, the fold, the outpoint rows and every carrier's status.
func TestIndexFile(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(dir, "index-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Rooted []struct {
			Label  string   `json:"label"`
			Held   []string `json:"held"`
			Rooted []string `json:"rooted"`
		} `json:"rooted"`
		Chain []struct {
			Seq    uint64 `json:"seq"`
			Txid   string `json:"txid"`
			Stored string `json:"stored"`
			Status string `json:"status"`
			Count  uint64 `json:"count"`
			Stale  uint64 `json:"stale"`
		} `json:"chain"`
		Carriers []struct {
			Label      string `json:"label"`
			Record     string `json:"record"`
			Commitment string `json:"commitment"`
			Outpoint   string `json:"outpoint"`
			Status     string `json:"status"`
		} `json:"carriers"`
		Outpoints []struct {
			Outpoint string   `json:"outpoint"`
			Winner   string   `json:"winner"`
			Others   []string `json:"others"`
			Swept    bool     `json:"swept"`
		} `json:"outpoints"`
		Dropped struct {
			Added []string `json:"added"`
			Later string   `json:"later"`
			After struct {
				Winner     string   `json:"winner"`
				Superseded []string `json:"superseded"`
			} `json:"afterTheLater"`
		} `json:"dropped"`
		Bounded struct {
			Added  []string `json:"added"`
			Winner string   `json:"winner"`
			Others []string `json:"others"`
			More   uint64   `json:"more"`
		} `json:"bounded"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	// The fold and the listings, from the stored tokens.
	fold, l := secrec.NewVaultFold(), secrec.NewListings()
	var chain []*transaction.Transaction
	for _, c := range f.Chain {
		raw, _ := hex.DecodeString(c.Stored)
		tx, tok, err := secrec.StoredToken(raw)
		if err != nil {
			t.Fatal(err)
		}
		if st := fold.Apply(tok.Vault); st != c.Status || uint64(len(fold.Set())) != c.Count || fold.Stale() != c.Stale {
			t.Errorf("seq %d folds %s, %d in the set, %d stale", c.Seq, st, len(fold.Set()), fold.Stale())
		}
		l.Apply(tok.Vault)
		chain = append(chain, tx)
	}
	if r := secrec.Rooted(chain); len(r) != len(chain) {
		t.Errorf("%d of %d tokens rooted", len(r), len(chain))
	}
	if r := secrec.Rooted(chain[1:]); len(r) != 0 {
		t.Errorf("without seq 0, %d tokens rooted", len(r))
	}
	if len(f.Rooted) < 5 {
		t.Errorf("%d rooted cases", len(f.Rooted))
	}
	// The rows, and each carrier's status.
	rows := map[string]*secrec.OutpointRow{}
	for _, c := range f.Carriers {
		if rows[c.Outpoint] == nil {
			rows[c.Outpoint] = &secrec.OutpointRow{}
		}
		rows[c.Outpoint].Add(h32(c.Commitment))
	}
	for _, o := range f.Outpoints {
		r := rows[o.Outpoint]
		if r == nil {
			// A swept outpoint no carrier spent: a row with no winner.
			r = &secrec.OutpointRow{}
			rows[o.Outpoint] = r
		}
		winner := ""
		if r.Any {
			winner = hex.EncodeToString(r.Winner[:])
		}
		if winner != o.Winner || len(r.Others) != len(o.Others) {
			t.Errorf("row %s: %+v", o.Outpoint, r)
		}
		r.Swept = o.Swept
	}
	seen := map[string]bool{}
	for _, c := range f.Carriers {
		raw, _ := hex.DecodeString(c.Record)
		rec, err := secrec.DecodeSecret(raw)
		if err != nil {
			t.Fatal(err)
		}
		if st := secrec.CarrierStatus(rows[c.Outpoint], h32(c.Commitment), l, rec); st != c.Status {
			t.Errorf("%s: %s, want %s", c.Label, st, c.Status)
		}
		seen[c.Status] = true
	}
	for _, s := range []string{secrec.StatusRetracted, secrec.StatusSuperseded, secrec.StatusMismatched, secrec.StatusListed, secrec.StatusUnlisted} {
		if !seen[s] {
			t.Errorf("no carrier is %s", s)
		}
	}
	// The dropped row: nothing on the outpoint is answered again.
	dr := &secrec.OutpointRow{}
	for _, c := range f.Dropped.Added {
		dr.Add(h32(c))
	}
	dr.Dropped = true
	dr.Add(h32(f.Dropped.Later))
	if hex.EncodeToString(dr.Winner[:]) != f.Dropped.After.Winner || len(f.Dropped.After.Superseded) != 3 {
		t.Errorf("the dropped row's winner: %x", dr.Winner)
	}
	for _, c := range f.Dropped.After.Superseded {
		if st := dr.Status(h32(c)); st != secrec.StatusSuperseded {
			t.Errorf("the dropped row: %s is %q", c, st)
		}
	}
	// The bounded row, fed in the file's order and in reverse.
	for _, rev := range []bool{false, true} {
		r := &secrec.OutpointRow{}
		for i := range f.Bounded.Added {
			j := i
			if rev {
				j = len(f.Bounded.Added) - 1 - i
			}
			r.Add(h32(f.Bounded.Added[j]))
			r.Add(h32(f.Bounded.Added[j])) // a commitment offered twice is one
		}
		var others []string
		for _, o := range r.Others {
			others = append(others, hex.EncodeToString(o[:]))
		}
		if hex.EncodeToString(r.Winner[:]) != f.Bounded.Winner || strings.Join(others, ",") != strings.Join(f.Bounded.Others, ",") {
			t.Errorf("bounded row (reverse %v): winner %x", rev, r.Winner)
		}
	}
}

// TestAdmitSurvivesGarbage feeds truncations and bit flips of every case's
// BEEF to Admit: it refuses or admits, and never panics.
func TestAdmitSurvivesGarbage(t *testing.T) {
	f, h := readTxFile(t)
	host := secrec.Host{Crypt: f.Crypt, Headers: h}
	for _, c := range f.Cases {
		beef, _ := hex.DecodeString(c.BEEF)
		for _, cut := range []int{0, 1, 4, 36, len(beef) / 2, len(beef) - 1} {
			_, _ = secrec.Admit(context.Background(), beef[:cut], nil, host)
		}
		for i := 0; i < len(beef); i += 1 + len(beef)/64 {
			x := append([]byte(nil), beef...)
			x[i] ^= 0x5a
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s: flip at %d panics: %v", c.Name, i, r)
					}
				}()
				_, _ = secrec.Admit(context.Background(), x, nil, host)
			}()
		}
	}
}

// TestAdmitHostRules holds Admit to its host's configuration: a crypt that
// breaks the grammar is refused before anything is read, and a BEEF over
// the host's bound is refused as a BEEF.
func TestAdmitHostRules(t *testing.T) {
	f, h := readTxFile(t)
	beef, _ := hex.DecodeString(f.Cases[0].BEEF)
	if _, err := secrec.Admit(context.Background(), beef, nil, secrec.Host{Crypt: "Not A Crypt", Headers: h}); secrec.Reason(err) != "other" {
		t.Errorf("a host crypt that breaks the grammar: %v", err)
	}
	if _, err := secrec.Admit(context.Background(), beef, nil, secrec.Host{Crypt: f.Crypt, Headers: h, MaxBEEF: len(beef) - 1}); secrec.Reason(err) != "beef" {
		t.Errorf("a BEEF one byte over the bound: %v", err)
	}
	if _, err := secrec.Admit(context.Background(), beef, nil, secrec.Host{Crypt: f.Crypt, Headers: h, MaxBEEF: len(beef)}); err != nil {
		t.Errorf("a BEEF at the bound: %v", err)
	}
	// With no headers nothing is mined: a carrier is admitted, a token is
	// not.
	if _, err := secrec.Admit(context.Background(), beef, nil, secrec.Host{Crypt: f.Crypt}); err != nil {
		t.Errorf("a carrier with no headers: %v", err)
	}
	for _, c := range f.Cases {
		if c.Name != "vault-token-create" && c.Name != "sweep" {
			continue
		}
		b, _ := hex.DecodeString(c.BEEF)
		if _, err := secrec.Admit(context.Background(), b, nil, secrec.Host{Crypt: f.Crypt}); secrec.Reason(err) != "unmined" {
			t.Errorf("%s with no headers: %v", c.Name, err)
		}
	}
}

// TestGroupEpochsAreBorgs holds the scenario's group to borg's own golden
// vectors: the epochs the record vectors are keyed under are the ones the
// fold of borg's example group gives, and each key is the one a member's
// wallet opens from borg's wraps.
func TestGroupEpochsAreBorgs(t *testing.T) {
	fx := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("../borgread/testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var links []borgread.Link
	for i, name := range []string{"group-create.hex", "group-add.hex", "group-remove.hex", "group-rotate.hex"} {
		rec := fx(name)
		g, err := borgread.DecodeGroup(rec)
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 {
			links[i-1].Txid = g.Prev
		}
		if g.Hall != Hall || !bytes.Equal(g.Org, Org.Pub()) || g.Group != GroupID {
			t.Errorf("%s is not the scenario's group", name)
		}
		links = append(links, borgread.Link{Record: rec, Height: []uint32{1000, 1004, 1010, 1030}[i]})
	}
	v, err := borgread.Fold(links)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Epochs) != len(GroupEpochs) {
		t.Fatalf("%d epochs, the scenario has %d", len(v.Epochs), len(GroupEpochs))
	}
	var events []secrec.EpochEvent
	for i, e := range v.Epochs {
		g := GroupEpochs[i]
		if e.Epoch != g.Epoch || e.ID != g.EpochID || e.Commitment != g.Commitment || e.Height != g.Height || e.Removed != g.Removed {
			t.Errorf("epoch %d: borg gives %+v", i, e)
		}
		if secrec.Commitment(g.Key) != e.Commitment || secrec.SymmetricKey(g.Key) != g.Symmetric {
			t.Errorf("epoch %d: the scenario's key is not the committed one", i)
		}
		events = append(events, secrec.EpochEvent{Epoch: e.Epoch, EpochID: e.ID, Height: e.Height, Removed: e.Removed})
	}
	// Every token and record of the scenario names an epoch borg's chain
	// began, and the audit runs on borg's epochs.
	s, err := Build()
	if err != nil {
		t.Fatal(err)
	}
	var mined []secrec.Mined
	for i, tok := range s.Vaults {
		if err := secrec.CheckGroupEpoch(events, tok.Epoch, tok.EpochID); err != nil {
			t.Errorf("vault seq %d names an epoch borg's chain did not begin", i)
		}
		mined = append(mined, secrec.Mined{Vault: tok, Txid: s.VaultTxids[i], Height: s.Heights[i]})
	}
	for k, ver := range s.Versions {
		if err := secrec.CheckGroupEpoch(events, ver.Rec.Epoch, ver.Rec.EpochID); err != nil {
			t.Errorf("%s names an epoch borg's chain did not begin", k)
		}
	}
	if r := secrec.Audit(mined, events); !r.OK {
		t.Errorf("the audit on borg's epochs fails: %+v", r.Findings)
	}
	// A member opens epoch 1's key from borg's wrap and reads a version
	// keyed under it; the removed member's wallet opens nothing.
	w, err := borgread.DecodeWrap(fx("wrap-remove.hex"))
	if err != nil {
		t.Fatal(err)
	}
	k, err := borgread.Open(context.Background(), Alice.Wallet(), Alice.Pub(), links[2].Record, w)
	if err != nil || k != GroupEpochs[1].Key {
		t.Fatalf("alice does not open epoch 1's key: %v", err)
	}
	ver := s.Versions["db/password@2"]
	p, err := secrec.ReadAsMember(ver.Rec, ver.Cipher, secrec.SymmetricKey(k))
	if err != nil || p.Name != "db/password" {
		t.Errorf("alice does not read a version keyed under epoch 1: %v", err)
	}
	if _, err := borgread.Open(context.Background(), Bob.Wallet(), Bob.Pub(), links[2].Record, w); borgread.Reason(err) != "undecryptable" {
		t.Errorf("bob, removed, opens epoch 1's wrap: %v", err)
	}
}

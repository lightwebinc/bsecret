package vectors

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

const dir = "../../testdata/vectors"

// TestVectorsMatch regenerates every file and compares it byte for byte with
// the one checked in, and refuses a checked-in file nothing generates.
func TestVectorsMatch(t *testing.T) {
	files, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range Names(files) {
		have, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s: %v (run: GOWORK=off go run ./cmd/vectors)", name, err)
			continue
		}
		if !bytes.Equal(have, files[name]) {
			t.Errorf("%s differs from what the codec generates", name)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if _, ok := files[e.Name()]; !ok {
			t.Errorf("%s is checked in but nothing generates it", e.Name())
		}
	}
}

func readJSON(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestHexFilesDecode reads the checked-in hex files as a second
// implementation would, without the generator: each decodes and re-encodes
// to itself.
func TestHexFilesDecode(t *testing.T) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".hex") {
			continue
		}
		n++
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		b := mustHex(t, strings.TrimSpace(string(raw)))
		var re []byte
		switch {
		case strings.HasPrefix(e.Name(), "vault-"):
			r, err := secrec.DecodeVault(b)
			if err != nil {
				t.Errorf("%s: %v", e.Name(), err)
				continue
			}
			re, err = r.Encode()
			if err != nil {
				t.Errorf("%s: %v", e.Name(), err)
			}
		case strings.HasPrefix(e.Name(), "secret-"):
			r, err := secrec.DecodeSecret(b)
			if err != nil {
				t.Errorf("%s: %v", e.Name(), err)
				continue
			}
			re, err = r.Encode()
			if err != nil {
				t.Errorf("%s: %v", e.Name(), err)
			}
		default:
			t.Errorf("%s: no decoder", e.Name())
		}
		if !bytes.Equal(re, b) {
			t.Errorf("%s does not re-encode to itself", e.Name())
		}
	}
	if n != 17 {
		t.Errorf("%d hex files, want 17", n)
	}
}

// TestRefusalFile replays refusal-v1.json from the file alone.
func TestRefusalFile(t *testing.T) {
	var f struct {
		Refusals []refusalVec `json:"refusals"`
	}
	readJSON(t, "refusal-v1.json", &f)
	if len(f.Refusals) < 70 {
		t.Fatalf("%d refusals", len(f.Refusals))
	}
	for _, r := range f.Refusals {
		raw := mustHex(t, r.Hex)
		var err error
		switch r.Record {
		case "vault":
			_, err = secrec.DecodeVault(raw)
		case "secret":
			_, err = secrec.DecodeSecret(raw)
		case "payload":
			_, err = secrec.DecodePayload(raw)
		default:
			t.Fatalf("record %q", r.Record)
		}
		if got := secrec.Reason(err); err == nil || got != r.Reason {
			t.Errorf("%s %q: %q, want %q", r.Record, r.Label, got, r.Reason)
		}
	}
}

// TestQueryFile replays query-v1.json from the file alone.
func TestQueryFile(t *testing.T) {
	var f struct {
		Questions []struct {
			Question string `json:"question"`
			Class    string `json:"class"`
			Refused  bool   `json:"refused"`
		} `json:"questions"`
	}
	readJSON(t, "query-v1.json", &f)
	for _, q := range f.Questions {
		got, err := secrec.ParseQuery([]byte(q.Question))
		if q.Refused != (err != nil) || (err == nil && got.Class.Name != q.Class) {
			t.Errorf("%s: %v", q.Question, err)
		}
	}
}

// TestKeyedFile replays a member's read of keyed-v1.json from the file
// alone: each case's record, ciphertext and the epoch's key give its verdict,
// the two-fault cases among them, which pin the order of the checks.
func TestKeyedFile(t *testing.T) {
	var f struct {
		Record string `json:"record"`
		Sym    string `json:"epochSymmetricKey"`
		Cases  []struct {
			Label      string   `json:"label"`
			Faults     []string `json:"faults"`
			Record     string   `json:"record"`
			Ciphertext string   `json:"ciphertext"`
			Verdict    string   `json:"verdict"`
		} `json:"cases"`
	}
	readJSON(t, "keyed-v1.json", &f)
	var sym [32]byte
	copy(sym[:], mustHex(t, f.Sym))
	two := 0
	for _, c := range f.Cases {
		raw := f.Record
		if c.Record != "" {
			raw = c.Record
		}
		rec, err := secrec.DecodeSecret(mustHex(t, raw))
		if err != nil {
			t.Fatalf("%s: %v", c.Label, err)
		}
		_, err = secrec.ReadAsMember(rec, mustHex(t, c.Ciphertext), sym)
		got := "opens"
		if err != nil {
			got = secrec.Reason(err)
		}
		if got != c.Verdict {
			t.Errorf("%s: %s, want %s", c.Label, got, c.Verdict)
		}
		if len(c.Faults) == 2 {
			two++
		}
	}
	if two < 4 {
		t.Errorf("%d two-fault cases", two)
	}
}

// TestSecretFile replays secret-v1.json from the file alone: each record's
// content id, and each member opening it exactly with the key of an epoch it
// held.
func TestSecretFile(t *testing.T) {
	var f struct {
		Records []struct {
			File      string            `json:"file"`
			Epoch     uint64            `json:"epoch"`
			ContentID string            `json:"contentId"`
			Key       string            `json:"key"`
			Inline    bool              `json:"inline"`
			Opens     map[string]string `json:"opens"`
		} `json:"records"`
	}
	readJSON(t, "secret-v1.json", &f)
	var d struct {
		Group struct {
			Epochs []struct {
				Epoch     uint64   `json:"epoch"`
				Symmetric string   `json:"symmetricKey"`
				Holders   []string `json:"holders"`
			} `json:"epochs"`
		} `json:"group"`
	}
	readJSON(t, "derivation-v1.json", &d)
	for _, r := range f.Records {
		raw, err := os.ReadFile(filepath.Join(dir, r.File))
		if err != nil {
			t.Fatal(err)
		}
		rec, err := secrec.DecodeSecret(mustHex(t, strings.TrimSpace(string(raw))))
		if err != nil {
			t.Fatalf("%s: %v", r.File, err)
		}
		cid, err := rec.ContentID()
		if err != nil || hex.EncodeToString(cid[:]) != r.ContentID {
			t.Errorf("%s: content id", r.File)
		}
		if r.Inline != (rec.Inline != nil) {
			t.Errorf("%s: inline", r.File)
		}
		for _, name := range []string{"alice", "bob", "carol", "dave"} {
			opened := false
			for _, e := range d.Group.Epochs {
				held := false
				for _, h := range e.Holders {
					held = held || h == name
				}
				var sym [32]byte
				copy(sym[:], mustHex(t, e.Symmetric))
				k, err := secrec.UnwrapFromEpoch(sym, cid, rec.Wrap, rec.Commitment)
				if (err == nil) != (e.Epoch == r.Epoch) {
					t.Errorf("%s: epoch %d's key: %v", r.File, e.Epoch, err)
				}
				// A reader tries only the key of the epoch the record names.
				if e.Epoch != r.Epoch || !held || err != nil {
					continue
				}
				if hex.EncodeToString(k[:]) != r.Key {
					t.Errorf("%s: %s opened another key", r.File, name)
				}
				if rec.Inline != nil {
					if _, err := secrec.OpenSecret(rec, rec.Inline, k); err != nil {
						t.Errorf("%s: %s: %v", r.File, name, err)
					}
				}
				opened = true
			}
			if want := r.Opens[name] == "opens"; opened != want {
				t.Errorf("%s: %s opened=%v, the file says %q", r.File, name, opened, r.Opens[name])
			}
		}
	}
}

// TestVaultFile replays vault-v1.json from the file alone: every transition
// verdict against its predecessor, and every fold case's statuses.
func TestVaultFile(t *testing.T) {
	var f struct {
		Records []struct {
			File   string `json:"file"`
			Txid   string `json:"standInTxid"`
			Status string `json:"status"`
		} `json:"records"`
		Transitions []struct {
			Label   string `json:"label"`
			From    int    `json:"from"`
			To      string `json:"to"`
			Verdict string `json:"verdict"`
		} `json:"transitions"`
		Fold []struct {
			Label    string   `json:"label"`
			Records  []string `json:"records"`
			Statuses []string `json:"statuses"`
			After    []struct {
				Root  string `json:"root"`
				Count int    `json:"count"`
				Stale uint64 `json:"stale"`
			} `json:"after"`
		} `json:"fold"`
	}
	readJSON(t, "vault-v1.json", &f)
	var chain []*secrec.Vault
	var txids [][32]byte
	fold := secrec.NewVaultFold()
	for _, r := range f.Records {
		raw, err := os.ReadFile(filepath.Join(dir, r.File))
		if err != nil {
			t.Fatal(err)
		}
		v, err := secrec.DecodeVault(mustHex(t, strings.TrimSpace(string(raw))))
		if err != nil {
			t.Fatal(err)
		}
		if st := fold.Apply(v); st != r.Status {
			t.Errorf("%s folds %s, want %s", r.File, st, r.Status)
		}
		var id [32]byte
		copy(id[:], mustHex(t, r.Txid))
		chain, txids = append(chain, v), append(txids, id)
	}
	for _, tr := range f.Transitions {
		next, err := secrec.DecodeVault(mustHex(t, tr.To))
		if err != nil {
			t.Fatalf("%s: %v", tr.Label, err)
		}
		err = secrec.CheckVaultTransition(chain[tr.From], txids[tr.From], next)
		got := "admitted"
		if err != nil {
			got = secrec.Reason(err)
		}
		if got != tr.Verdict {
			t.Errorf("%s: %s, want %s", tr.Label, got, tr.Verdict)
		}
	}
	for _, c := range f.Fold {
		ff := secrec.NewVaultFold()
		for i, r := range c.Records {
			v, err := secrec.DecodeVault(mustHex(t, r))
			if err != nil {
				t.Fatalf("%s: %v", c.Label, err)
			}
			if st := ff.Apply(v); st != c.Statuses[i] {
				t.Errorf("%s token %d: %s, want %s", c.Label, i, st, c.Statuses[i])
			}
			// The fold is atomic: a record that breaks it leaves the set
			// of the record before it, which the file pins.
			if len(c.After) != len(c.Records) {
				t.Fatalf("%s: %d after-states for %d records", c.Label, len(c.After), len(c.Records))
			}
			root := secrec.SetRoot(ff.Set())
			if a := c.After[i]; hx(root[:]) != a.Root || len(ff.Set()) != a.Count || ff.Stale() != a.Stale {
				t.Errorf("%s token %d: the set after it is %x, %d secrets, %d stale; want %s, %d, %d", c.Label, i, root, len(ff.Set()), ff.Stale(), a.Root, a.Count, a.Stale)
			}
			if st := c.Statuses[i]; i > 0 && (st == secrec.StatusSetMismatch || st == secrec.StatusStaleMismatch) && c.After[i] != c.After[i-1] {
				t.Errorf("%s token %d: a %s token changed the set", c.Label, i, st)
			}
		}
	}
}

// TestBRC369File recomputes BRC-369's vectors from brc369-v1.json's inputs
// with the standard library alone, independently of the codec and of the
// generator, and compares with what the file says the document prints. With
// BRC369_MD set to the document's path it also checks that every printed
// value is in the document.
func TestBRC369File(t *testing.T) {
	var f struct {
		Labels     map[string]string `json:"labels"`
		ContentKey string            `json:"contentKey"`
		Plaintext  struct {
			Text string `json:"text"`
		} `json:"plaintext"`
		Ciphertext string `json:"ciphertext"`
		Descriptor string `json:"descriptor"`
		Reproduced []struct {
			Value    string `json:"value"`
			Printed  string `json:"printed"`
			Computed string `json:"computed"`
		} `json:"reproduced"`
		Substituted struct {
			Ciphertext string `json:"ciphertext"`
			Verdict    string `json:"verdict"`
		} `json:"substitutedKey"`
		NotReproduced []struct {
			Printed  string `json:"printed"`
			Computed string `json:"computed"`
		} `json:"notReproduced"`
	}
	readJSON(t, "brc369-v1.json", &f)
	if len(f.Reproduced) != 25 {
		t.Errorf("%d reproduced values, want 25", len(f.Reproduced))
	}
	printed := map[string]string{}
	for _, c := range f.Reproduced {
		if c.Printed != c.Computed || c.Printed == "" {
			t.Errorf("%s: printed %s, computed %s", c.Value, c.Printed, c.Computed)
		}
		printed[c.Value] = c.Printed
	}
	sum := func(parts ...[]byte) []byte {
		h := sha256.New()
		for _, p := range parts {
			h.Write(p)
		}
		return h.Sum(nil)
	}
	k := mustHex(t, f.ContentKey)
	symKey := sum([]byte("metanet keyed content symmetric v1"), k)
	want := map[string]string{
		"symmetric key":      hex.EncodeToString(symKey),
		"commitment digest":  hex.EncodeToString(sum([]byte("metanet keyed content commitment v1"), k)),
		"ciphertext sha-256": hex.EncodeToString(sum(mustHex(t, f.Ciphertext))),
		"content id":         hex.EncodeToString(sum([]byte(f.Descriptor))),
		"salt":               hex.EncodeToString(sum([]byte(f.Labels["salt"]))[:4]),
	}
	seal := func(key []byte, pt []byte) []byte {
		blk, err := aes.NewCipher(sum([]byte("metanet keyed content symmetric v1"), key))
		if err != nil {
			t.Fatal(err)
		}
		g, err := cipher.NewGCM(blk)
		if err != nil {
			t.Fatal(err)
		}
		var out []byte
		for i, off := 0, 0; off < len(pt); i, off = i+1, off+64 {
			end := off + 64
			if end > len(pt) {
				end = len(pt)
			}
			iv := append(mustHex(t, want["salt"]), 0, 0, 0, 0, 0, 0, 0, byte(i))
			out = g.Seal(out, iv, pt[off:end], nil)
		}
		return out
	}
	want["ciphertext"] = hex.EncodeToString(seal(k, []byte(f.Plaintext.Text)))
	fraud := seal(sum([]byte(f.Labels["substitutedKey"])), []byte(f.Plaintext.Text))
	want["fraud ciphertext sha-256"] = hex.EncodeToString(sum(fraud))
	for name, w := range want {
		if printed[name] != w {
			t.Errorf("%s: the file prints %s, recomputed %s", name, printed[name], w)
		}
	}
	if hex.EncodeToString(fraud) != f.Substituted.Ciphertext || f.Substituted.Verdict != "tag" {
		t.Error("the substituted-key ciphertext does not recompute, or its verdict is not tag")
	}
	if len(f.NotReproduced) == 0 || f.NotReproduced[0].Printed == f.NotReproduced[0].Computed {
		t.Error("the release payload's key is recorded as reproducing")
	}
	if path := os.Getenv("BRC369_MD"); path != "" {
		doc, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		flat := strings.Join(strings.Fields(string(doc)), "")
		for _, c := range f.Reproduced {
			for _, part := range strings.Fields(c.Printed) {
				if !strings.Contains(flat, part) {
					t.Errorf("%s: %s is not in the document", c.Value, part)
				}
			}
		}
	}
}

func readSecretFile(t *testing.T, name string) *secrec.Secret {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := secrec.DecodeSecret(mustHex(t, strings.TrimSpace(string(raw))))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return rec
}

// TestListingFile replays the listings and successors of secret-v1.json
// from the files alone.
func TestListingFile(t *testing.T) {
	var f struct {
		Listings []struct {
			Label   string `json:"label"`
			Record  string `json:"record"`
			Seq     int    `json:"tokenSeq"`
			Token   string `json:"token"`
			Verdict string `json:"verdict"`
		} `json:"listings"`
		Successors []struct {
			Label   string `json:"label"`
			Token   string `json:"token"`
			Prev    string `json:"prev"`
			Next    string `json:"next"`
			Verdict string `json:"verdict"`
		} `json:"successors"`
	}
	readJSON(t, "secret-v1.json", &f)
	var v struct {
		Records []struct {
			File string `json:"file"`
		} `json:"records"`
	}
	readJSON(t, "vault-v1.json", &v)
	if len(f.Listings) < 14 || len(f.Successors) < 5 {
		t.Fatalf("%d listings, %d successors", len(f.Listings), len(f.Successors))
	}
	for _, l := range f.Listings {
		hexToken := l.Token
		if hexToken == "" {
			raw, err := os.ReadFile(filepath.Join(dir, v.Records[l.Seq].File))
			if err != nil {
				t.Fatal(err)
			}
			hexToken = strings.TrimSpace(string(raw))
		}
		token, err := secrec.DecodeVault(mustHex(t, hexToken))
		if err != nil {
			t.Fatalf("%s: %v", l.Label, err)
		}
		got := "listed"
		if err := secrec.CheckListed(token, readSecretFile(t, l.Record)); err != nil {
			got = secrec.Reason(err)
		}
		if got != l.Verdict {
			t.Errorf("%s: %s, want %s", l.Label, got, l.Verdict)
		}
	}
	for _, s := range f.Successors {
		token, err := secrec.DecodeVault(mustHex(t, s.Token))
		if err != nil {
			t.Fatalf("%s: %v", s.Label, err)
		}
		prev, err := secrec.DecodeSecret(mustHex(t, s.Prev))
		if err != nil {
			t.Fatalf("%s: %v", s.Label, err)
		}
		next, err := secrec.DecodeSecret(mustHex(t, s.Next))
		if err != nil {
			t.Fatalf("%s: %v", s.Label, err)
		}
		got := "successor of it"
		if err := secrec.CheckSuccessor(token, prev, next); err != nil {
			got = secrec.Reason(err)
		}
		if got != s.Verdict {
			t.Errorf("%s: %s, want %s", s.Label, got, s.Verdict)
		}
	}
}

// TestInSetFile replays the in-set cases of vault-v1.json from the files
// alone: a record, a latest token and an inclusion path give the verdict.
func TestInSetFile(t *testing.T) {
	var f struct {
		Records []struct {
			File string `json:"file"`
			Txid string `json:"standInTxid"`
		} `json:"records"`
		InSet []struct {
			Label    string `json:"label"`
			Record   string `json:"record"`
			TokenSeq int    `json:"tokenSeq"`
			Token    string `json:"token"`
			Context  string `json:"context"`
			Verdict  string `json:"verdict"`
		} `json:"inSet"`
	}
	readJSON(t, "vault-v1.json", &f)
	if len(f.InSet) < 7 {
		t.Fatalf("%d in-set cases", len(f.InSet))
	}
	for _, c := range f.InSet {
		hexToken := c.Token
		if hexToken == "" {
			raw, err := os.ReadFile(filepath.Join(dir, f.Records[c.TokenSeq].File))
			if err != nil {
				t.Fatal(err)
			}
			hexToken = strings.TrimSpace(string(raw))
		}
		token, err := secrec.DecodeVault(mustHex(t, hexToken))
		if err != nil {
			t.Fatalf("%s: %v", c.Label, err)
		}
		path, err := secrec.DecodeContext(mustHex(t, c.Context))
		if err != nil {
			t.Fatalf("%s: %v", c.Label, err)
		}
		got := "in the set"
		var txid [32]byte
		copy(txid[:], mustHex(t, f.Records[c.TokenSeq].Txid))
		if err := secrec.CheckInSet(token, txid, readSecretFile(t, c.Record), path); err != nil {
			got = secrec.Reason(err)
		}
		if got != c.Verdict {
			t.Errorf("%s: %s, want %s", c.Label, got, c.Verdict)
		}
	}
}

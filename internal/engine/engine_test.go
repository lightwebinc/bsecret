package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/state"
)

func h32(s string) [32]byte { return sha256.Sum256([]byte(s)) }

// testOwner is a key that may own a vault: the generator doubled.
func testOwner(t *testing.T) []byte {
	t.Helper()
	b, _ := hex.DecodeString("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
	return b
}

// testWriter is a writer over a vault whose chain is one empty first
// token at epoch 0.
func testWriter(t *testing.T) *Writer {
	t.Helper()
	first := &secrec.Vault{Crypt: "example_crypt_hmqzvtkwrx", Org: testOwner(t), Vault: h32("vault"), Name: "ops", Hall: "example_hall_vkqzmtrwxp",
		EpochID: h32("epoch 0"), Labels: []string{"confidential", "internal"}, Root: secrec.SetRoot(nil), Created: 1}
	if _, err := first.Encode(); err != nil {
		t.Fatal(err)
	}
	f := secrec.NewVaultFold()
	if st := f.Apply(first); st != secrec.StatusConsistent {
		t.Fatal(st)
	}
	return &Writer{Vault: &state.Vault{ID: hex.EncodeToString(first.Vault[:])}, Recs: []*secrec.Vault{first}, Pred: first, Fold: f,
		Last: &state.Token{Txid: strings.Repeat("11", 32)}}
}

// advance applies a built record, as its mining would.
func advance(t *testing.T, w *Writer, rec *secrec.Vault) {
	t.Helper()
	if st := w.Fold.Apply(rec); st != secrec.StatusConsistent {
		t.Fatalf("seq %d folds %s", rec.Seq, st)
	}
	id := h32("txid " + string(rune('a'+rec.Seq)))
	w.Recs, w.Pred, w.Last = append(w.Recs, rec), rec, &state.Token{Txid: hex.EncodeToString(id[:])}
}

// minted is a version of name as mint would write it under an epoch.
func minted(w *Writer, name string, version, epoch uint64, epochID [32]byte) *Minted {
	id, _ := secrec.SecretID(w.Pred.Vault, name)
	rec := &secrec.Secret{Crypt: w.Pred.Crypt, Org: w.Pred.Org, Vault: w.Pred.Vault, ID: id, Version: version, Label: "confidential",
		Group: w.Pred.Group, Epoch: epoch, EpochID: epochID, Commitment: h32(name + string(rune('0'+version)) + "key"), Segment: 16384, Length: 272, Created: 1}
	cid, _ := rec.ContentID()
	return &Minted{Name: name, Record: rec, Entry: secrec.Entry{ID: id, Version: version, ContentID: cid, Commitment: rec.Commitment}}
}

// The tooling folds before it signs: a transition a host or an index would
// flag is refused here, unbuilt, and what it does build has the counts the
// fold gives.
func TestBuildRefusesWhatAHostOrAnIndexWouldFlag(t *testing.T) {
	w := testWriter(t)
	e0, e1 := w.Pred.EpochID, h32("epoch 1")
	a1, b1 := minted(w, "a", 1, 0, e0), minted(w, "b", 1, 0, e0)
	rec, raw, err := w.Build(Change{Create: []*Minted{b1, a1}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	back, err := secrec.DecodeVault(raw)
	if err != nil || back.Count != 2 || back.Stale != 0 || back.Seq != 1 || len(back.Create) != 2 {
		t.Fatalf("the first transition: %v %+v", err, back)
	}
	refuses := func(what string, c Change, has string) {
		t.Helper()
		_, _, err := w.Build(c, 3)
		if err == nil || !strings.Contains(err.Error(), has) {
			t.Errorf("%s: got %v, want an error with %q", what, err, has)
		}
	}
	// Before seq 1 is folded: nothing is in the set.
	refuses("an update of a secret the set does not hold", Change{Update: []*Minted{minted(w, "a", 2, 0, e0)}}, "is not in the vault's set")
	refuses("a retirement of a secret the set does not hold", Change{Retire: [][32]byte{a1.Entry.ID}}, "is not in the vault's set")
	advance(t, w, rec)
	refuses("a creation of a secret the set holds", Change{Create: []*Minted{minted(w, "a", 2, 0, e0)}}, "is in the vault's set already")
	refuses("a version that does not rise", Change{Update: []*Minted{minted(w, "a", 1, 0, e0)}}, "set-mismatch")
	reused := minted(w, "a", 2, 0, e0)
	reused.Record.Commitment, reused.Entry.Commitment = b1.Entry.Commitment, b1.Entry.Commitment
	reused.Entry.ContentID, _ = reused.Record.ContentID()
	refuses("a commitment an earlier token listed", Change{Update: []*Minted{reused}}, "commitment-reuse")
	refuses("a record keyed under another epoch than the token's", Change{Update: []*Minted{minted(w, "a", 2, 1, e1)}}, "mismatched")
	refuses("an epoch that goes back", Change{Epoch: &secrec.EpochEvent{Epoch: 0, EpochID: e0}}, "not later")

	// The acknowledgement: every secret is stale, and the first re-keying
	// rides with it.
	ep1 := &secrec.EpochEvent{Epoch: 1, EpochID: e1}
	a2 := minted(w, "a", 2, 1, e1)
	rec, _, err = w.Build(Change{Epoch: ep1, Update: []*Minted{a2}}, 3)
	if err != nil || rec.Stale != 1 || rec.Count != 2 || rec.Epoch != 1 {
		t.Fatalf("the acknowledgement: %v %+v", err, rec)
	}
	advance(t, w, rec)
	// In debt: nothing but the re-keying or retirement of what is stale.
	refuses("a creation while one is stale", Change{Create: []*Minted{minted(w, "c", 1, 1, e1)}}, "debt")
	refuses("a second update of a secret already re-keyed, counted as clearing debt", Change{Update: []*Minted{minted(w, "a", 3, 1, e1)}}, "debt")
	refuses("a retirement of a secret already re-keyed, counted as clearing debt", Change{Retire: [][32]byte{a1.Entry.ID}}, "debt")
	refuses("a transition that changes nothing", Change{}, "changes nothing")
	rec, _, err = w.Build(Change{Retire: [][32]byte{b1.Entry.ID}}, 4)
	if err != nil || rec.Stale != 0 || rec.Count != 1 {
		t.Fatalf("retiring the stale secret settles the vault: %v %+v", err, rec)
	}
	advance(t, w, rec)
	// A retired secret comes back above its last version only.
	refuses("a retired secret created again at its old version", Change{Create: []*Minted{minted(w, "b", 1, 1, e1)}}, "set-mismatch")
	if _, _, err := w.Build(Change{Create: []*Minted{minted(w, "b", 2, 1, e1)}}, 5); err != nil {
		t.Fatalf("a retired secret created again above its last version: %v", err)
	}
	// As many as the record holds, and one more.
	var many []*Minted
	for i := 0; i < secrec.MaxDelta+1; i++ {
		many = append(many, minted(w, "n/"+string(rune('a'+i/26))+string(rune('a'+i%26)), 1, 1, e1))
	}
	if rec, raw, err := w.Build(Change{Create: many[:secrec.MaxDelta]}, 5); err != nil || rec.Count != 65 || len(raw) > secrec.MaxVaultRecord {
		t.Fatalf("64 creations in one token: %v", err)
	}
	refuses("65 creations in one token", Change{Create: many}, "list")
	// Nothing Build refused reached the fold.
	if len(w.Fold.Set()) != 1 || w.Fold.Broken() != "" {
		t.Fatalf("a refused transition reached the fold: %d in the set, broken %q", len(w.Fold.Set()), w.Fold.Broken())
	}
}

func TestCoveredNeedsAChoiceForEverySecret(t *testing.T) {
	owes := []Stale{{ID: h32("a"), Name: "a"}, {ID: h32("b"), Name: "b"}, {ID: h32("c")}}
	unnamed := owes[2].Key()
	known := func(k string) bool { return k == "old" }
	for _, c := range []struct {
		what string
		plan map[string]Choice
		has  string
	}{
		{"nothing chosen", nil, "3 secret(s) have no choice"},
		{"one missing", map[string]Choice{"a": {Same: true}, unnamed: {Retire: true}}, "1 secret(s) have no choice: [b]"},
		{"two choices for one", map[string]Choice{"a": {Same: true, Retire: true}}, "more than one"},
		{"the same value of a secret known only by identifier", map[string]Choice{"a": {Same: true}, "b": {Same: true}, unnamed: {Same: true}}, "can only retire it"},
		{"a name the vault never held", map[string]Choice{"a": {Same: true}, "b": {Same: true}, unnamed: {Retire: true}, "typo": {Retire: true}}, "not a secret this vault ever held"},
	} {
		if _, err := Covered(owes, c.plan, known); err == nil || !strings.Contains(err.Error(), c.has) {
			t.Errorf("%s: %v", c.what, err)
		}
	}
	ignored, err := Covered(owes, map[string]Choice{"a": {Set: true, Value: []byte("x")}, "b": {Same: true}, unnamed: {Retire: true}, "old": {Same: true}}, known)
	if err != nil || len(ignored) != 1 || ignored[0] != "old" {
		t.Fatalf("a full plan with a choice for a secret already re-keyed: %v %v", ignored, err)
	}
}

func TestRetractable(t *testing.T) {
	v := &state.Vault{Versions: []state.SecretVersion{
		{ID: "a", Version: 1, Epoch: 0, Tree: "t1", Vout: 0, Listed: true, Ended: true}, // replaced by a re-keying
		{ID: "a", Version: 2, Epoch: 1, Tree: "t1", Vout: 1, Listed: true},              // current
		{ID: "b", Version: 1, Epoch: 1, Tree: "t1", Vout: 2, Listed: true, Ended: true}, // replaced under the same epoch
		{ID: "b", Version: 2, Epoch: 1, Tree: "t2", Vout: 0, Listed: true},              // current
		{ID: "c", Version: 1, Epoch: 1, Tree: "t2", Vout: 1, Listed: true, Ended: true}, // retired
		{ID: "d", Version: 1, Epoch: 1, Tree: "t2", Vout: 2},                            // never listed
		{ID: "e", Version: 1, Epoch: 0, Tree: "t2", Vout: 3, Listed: true, Ended: true, Swept: "x"},
	}}
	got := Retractable(v, 1, false, true, nil)
	if len(got) != 2 || len(got["t1"]) != 1 || got["t1"][0] != 0 || len(got["t2"]) != 2 || got["t2"][0] != 1 || got["t2"][1] != 2 {
		t.Fatalf("settled, per-version: %v", got)
	}
	// Keeping history: only what was never listed goes.
	if got := Retractable(v, 1, false, false, nil); len(got) != 1 || len(got["t2"]) != 1 || got["t2"][0] != 2 {
		t.Fatalf("history kept: %v", got)
	}
	// A retirement sweeps the retired secret's versions, and no other
	// secret's history.
	if got := Retractable(v, 1, false, false, map[string]bool{"c": true, "a": true}); len(got) != 1 || len(got["t2"]) != 2 || got["t2"][0] != 1 {
		t.Fatalf("a retirement: %v", got)
	}
	// An interval vault keeps an unlisted successor the listed version
	// links to, and retracts one below the listed version.
	iv := &state.Vault{Versions: []state.SecretVersion{
		{ID: "a", Version: 1, Tree: "t", Vout: 0, Listed: true, Ended: true},
		{ID: "a", Version: 2, Tree: "t", Vout: 1},
		{ID: "a", Version: 3, Tree: "t", Vout: 2, Listed: true},
		{ID: "a", Version: 4, Tree: "t", Vout: 3},
	}}
	if got := Retractable(iv, 0, true, true, nil); len(got["t"]) != 1 || got["t"][0] != 1 {
		t.Fatalf("interval: %v", got)
	}
}

func TestLostErrorSaysWhatToDo(t *testing.T) {
	err := &LostError{What: "vault x token seq 3", Txid: strings.Repeat("a", 64), By: strings.Repeat("b", 64)}
	if !strings.Contains(err.Error(), "bsecret sync") || !strings.Contains(err.Error(), "nothing it listed is listed") {
		t.Fatal(err)
	}
	var target *LostError
	if !errors.As(error(err), &target) {
		t.Fatal("not a LostError")
	}
	fee := &LostError{What: "x", Txid: strings.Repeat("a", 64), By: strings.Repeat("b", 64), Fee: true}
	if !strings.Contains(fee.Error(), "fee coin") {
		t.Fatal(fee)
	}
}

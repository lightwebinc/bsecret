package vread

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/lightwebinc/bcommon/hostset"
	"github.com/lightwebinc/bcommon/lookup"

	"github.com/lightwebinc/borg/reader"

	"github.com/lightwebinc/bsecret/internal/limits"
	"github.com/lightwebinc/bsecret/internal/secrec"
)

func TestStanding(t *testing.T) {
	id := func(s string) [32]byte { return sha256.Sum256([]byte(s)) }
	g := &Group{GroupView: &reader.GroupView{}, Epochs: []secrec.EpochEvent{{Epoch: 0, EpochID: id("e0"), Height: 10}, {Epoch: 1, EpochID: id("e1"), Height: 20, Removed: true}}}
	for _, c := range []struct {
		v                      secrec.Vault
		settled, behind, ahead bool
		says                   string
	}{
		{secrec.Vault{Epoch: 1, EpochID: id("e1")}, true, false, false, "settled at epoch 1"},
		{secrec.Vault{Epoch: 1, EpochID: id("e1"), Stale: 2}, false, false, false, "IN DEBT: 2 secret(s)"},
		{secrec.Vault{Epoch: 0, EpochID: id("e0")}, false, true, false, "BEHIND: it acknowledges epoch 0 and the group is at epoch 1"},
		{secrec.Vault{Epoch: 0, EpochID: id("e0"), Stale: 1}, false, true, false, "BEHIND and IN DEBT"},
		{secrec.Vault{Epoch: 2, EpochID: id("e2")}, false, false, true, "AHEAD"},
		{secrec.Vault{Epoch: 1, EpochID: id("e0")}, false, false, true, "AHEAD"},
	} {
		s := g.Stand(&c.v)
		if s.Settled() != c.settled || s.Behind != c.behind || s.Ahead != c.ahead || !contains(s.String(), c.says) {
			t.Errorf("epoch %d stale %d: %+v %q", c.v.Epoch, c.v.Stale, s, s)
		}
	}
	if e, ok := g.EpochAt(1); !ok || !e.Removed || g.Current().Epoch != 1 {
		t.Error("EpochAt")
	}
	if _, ok := g.EpochAt(2); ok {
		t.Error("an epoch the group did not begin")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// A content store: a writer stores by hash, a reader fetches within its
// budget and never past the record's length, from a directory or a URL.
func TestStore(t *testing.T) {
	dir := t.TempDir()
	ct := []byte("ciphertext bytes, public")
	hash := sha256.Sum256(ct)
	ctx := context.Background()
	if _, err := (&Store{}).Put(ct); err == nil {
		t.Fatal("a store with no directory took a ciphertext")
	}
	s := &Store{Sources: []string{dir}, Max: 1 << 20}
	p, err := s.Put(ct)
	if err != nil || filepath.Base(p) != hex.EncodeToString(hash[:]) {
		t.Fatalf("Put: %s %v", p, err)
	}
	if again, err := s.Put(ct); err != nil || again != p {
		t.Fatalf("a second Put: %s %v", again, err)
	}
	got, err := s.Get(ctx, hash, uint64(len(ct)))
	if err != nil || string(got) != string(ct) {
		t.Fatalf("Get: %q %v", got, err)
	}
	// Never past the record's length: one byte more is read, so a longer
	// file is seen as longer, and no more.
	if got, _ := s.Get(ctx, hash, 4); len(got) != 5 {
		t.Fatalf("read %d bytes for a length of 4", len(got))
	}
	// Over the budget: refused before anything is fetched.
	small := &Store{Sources: []string{dir}, Max: 8}
	if _, err := small.Get(ctx, hash, uint64(len(ct))); err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("over the budget: %v", err)
	}
	// By URL, after a directory that lacks it.
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()
	web := &Store{Sources: []string{t.TempDir(), srv.URL + "/"}, Max: 1 << 20}
	if got, err := web.Get(ctx, hash, uint64(len(ct))); err != nil || string(got) != string(ct) {
		t.Fatalf("Get by URL: %q %v", got, err)
	}
	if web.Dir() == "" || (&Store{Sources: []string{srv.URL}}).Dir() != "" {
		t.Fatal("Dir")
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if _, err := web.Get(ctx, hash, uint64(len(ct))); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("held by no source: %v", err)
	}
	var none *Store
	if _, err := none.Get(ctx, hash, 1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no store: %v", err)
	}
}

// The audit class is read page after page; a page that cannot be full is
// the last, so no further page is asked, or paid for.
func TestTrailPages(t *testing.T) {
	tok := func(seq uint64) *Tok {
		return &Tok{Txid: "tx" + strconv.FormatUint(seq, 10), Token: &secrec.VaultToken{Vault: &secrec.Vault{Seq: seq}}}
	}
	verify := func(b []byte) (*Tok, error) {
		if string(b) == "bad" {
			return nil, secrec.ErrUnmined
		}
		n, _ := strconv.ParseUint(string(b), 10, 64)
		return tok(n), nil
	}
	for _, c := range []struct{ total, asks int }{{0, 1}, {5, 1}, {56, 1}, {64, 2}, {130, 3}, {128, 3}} {
		asked := 0
		ask := func(q Query) ([]lookup.Output, error) {
			asked++
			from := uint64(0)
			if a, ok := q["after"]; ok {
				n, _ := strconv.ParseUint(a, 10, 64)
				from = n + 1
			}
			var outs []lookup.Output
			for s := from; s < uint64(c.total) && len(outs) < 64; s++ {
				outs = append(outs, lookup.Output{Beef: []byte(strconv.FormatUint(s, 10))})
			}
			return outs, nil
		}
		toks, err := Trail(Query{"crypt": "c"}, ask, verify)
		if err != nil || len(toks) != c.total || asked != c.asks {
			t.Errorf("%d tokens: read %d in %d question(s), want %d: %v", c.total, len(toks), asked, c.asks, err)
		}
	}
	// A host that fills a page with tokens of an earlier one, so that a
	// trail takes more pages, each one paid for, is refused at the first
	// such page: a page asked after a seq holds only tokens above it.
	asked := 0
	var re *Refusal
	padded := func(q Query) ([]lookup.Output, error) {
		asked++
		var outs []lookup.Output
		for s := 0; s < 63; s++ {
			outs = append(outs, lookup.Output{Beef: []byte(strconv.Itoa(s))})
		}
		return append(outs, lookup.Output{Beef: []byte(strconv.Itoa(62 + asked))}), nil
	}
	if _, err := Trail(Query{}, padded, verify); !errors.As(err, &re) || re.Reason != "page" || asked != 2 {
		t.Fatalf("a host that pads its pages: %d questions, %v", asked, err)
	}
	// A page of more outputs than a page holds is cut to one.
	asked = 0
	huge := func(Query) ([]lookup.Output, error) {
		asked++
		if asked > 1 {
			return nil, nil
		}
		var outs []lookup.Output
		for s := 0; s < 5000; s++ {
			outs = append(outs, lookup.Output{Beef: []byte(strconv.Itoa(s))})
		}
		return outs, nil
	}
	if toks, err := Trail(Query{}, huge, verify); err != nil || len(toks) != 64 {
		t.Fatalf("a page of 5000 tokens: %d taken, %v", len(toks), err)
	}
	// A token that does not verify ends the walk, naming it.
	bad := func(Query) ([]lookup.Output, error) { return []lookup.Output{{Beef: []byte("bad")}}, nil }
	if _, err := Trail(Query{}, bad, verify); !errors.As(err, &re) || re.Reason != "unmined" {
		t.Fatalf("a token that does not verify: %v", err)
	}
}

func TestIdentifiers(t *testing.T) {
	if _, err := Hex32("zz"); err == nil {
		t.Error("Hex32 took junk")
	}
	h := sha256.Sum256(nil)
	if got, err := Hex32(hex.EncodeToString(h[:])); err != nil || got != h {
		t.Error("Hex32")
	}
	if _, err := Hash("AB"); err == nil {
		t.Error("Hash took junk")
	}
	if Short("0123456789abcdef") != "0123456789ab" || Short("ab") != "ab" || JoinSeqs([]uint64{1, 2}) != "1, 2" {
		t.Error("Short, JoinSeqs")
	}
	f := &Failure{Label: "hash", Err: errors.New("x")}
	if f.Error() != "hash: x" || !errors.Is(f, f.Err) {
		t.Error("Failure")
	}
}

// A seq a token names never sizes anything: a chain is walked by spends
// from seq 0, so a stray token at an enormous seq is a fork, not an
// allocation.
func TestAHostileSeqAllocatesNothing(t *testing.T) {
	stray := &Tok{Txid: "stray", Token: &secrec.VaultToken{Vault: &secrec.Vault{Seq: 1 << 50}}}
	v, err := FromTokens("example_crypt_hmqzvtkwrx", nil, [32]byte{}, []*Tok{stray})
	if !errors.Is(err, ErrNoChain) || len(v.Tokens) != 0 || len(v.Forks) != 1 {
		t.Fatalf("a stray token at seq 2^50: %v, %d tokens, %d forks", err, len(v.Tokens), len(v.Forks))
	}
}

// A paged walk holds what the contract's pages hold and no more, whatever a
// host answers.
func TestPagesAreBounded(t *testing.T) {
	asked := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"output-list","outputs":[`))
		for i := 0; i < 5000; i++ {
			if i > 0 {
				_, _ = w.Write([]byte(","))
			}
			_, _ = w.Write([]byte(`{"beef":[1,2,3],"outputIndex":0}`))
		}
		_, _ = w.Write([]byte(`]}`))
	}))
	defer srv.Close()
	c := &Client{Hosts: []string{srv.URL}}
	org := "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	n := 0
	ho := c.Pages(context.Background(), srv.URL, Query{"crypt": "example_crypt_hmqzvtkwrx", "vaultsOf": org},
		func(lookup.Output) string {
			n++
			return hex.EncodeToString(sha256.New().Sum([]byte{byte(n), byte(n >> 8)}))[:64]
		},
		func(a, b string) bool { return a < b })
	if ho.Err != nil || !ho.Truncated || len(ho.Outputs) > pageOutputs || asked != 1 {
		t.Fatalf("a page of 5000 outputs: %d kept, truncated %v, %d page(s) asked, %v", len(ho.Outputs), ho.Truncated, asked, ho.Err)
	}
}

// history is a chain of three tokens: an empty first one, one that creates
// a secret, and one that updates it under the commitment the first version
// was listed with.
func history(t *testing.T) (*ChainView, *Car, *Car) {
	t.Helper()
	h := func(s string) [32]byte { return sha256.Sum256([]byte(s)) }
	org, _ := hex.DecodeString("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
	base := secrec.Vault{Crypt: "example_crypt_hmqzvtkwrx", Org: org, Vault: h("vault"), Name: "ops", Hall: "example_hall_vkqzmtrwxp",
		EpochID: h("epoch 0"), Labels: []string{"confidential"}, Created: 1}
	id, _ := secrec.SecretID(base.Vault, "db/password")
	car := func(version uint64, key string) (*Car, secrec.Entry) {
		rec := &secrec.Secret{Crypt: base.Crypt, Org: org, Vault: base.Vault, ID: id, Version: version, Label: "confidential",
			Epoch: 0, EpochID: base.EpochID, Commitment: h(key), Segment: 16384, Length: 272, Created: 1}
		cid, err := rec.ContentID()
		if err != nil {
			t.Fatal(err)
		}
		return &Car{Carrier: &secrec.Carrier{Secret: rec, ContentID: cid, Commitment: rec.Commitment}},
			secrec.Entry{ID: id, Version: version, ContentID: cid, Commitment: rec.Commitment}
	}
	one, e1 := car(1, "key")
	two, e2 := car(2, "key")
	v := &ChainView{Crypt: base.Crypt, Org: org, Vault: base.Vault, fold: secrec.NewVaultFold(), reused: map[[32]byte]bool{}}
	first, second, third := base, base, base
	first.Root = secrec.SetRoot(nil)
	second.Seq, second.Create, second.Count = 1, []secrec.Entry{e1}, 1
	second.Root = secrec.SetRoot([]secrec.Current{{ID: id, Version: 1, ContentID: e1.ContentID}})
	third.Seq, third.Update, third.Count = 2, []secrec.Entry{e2}, 1
	third.Root = secrec.SetRoot([]secrec.Current{{ID: id, Version: 2, ContentID: e2.ContentID}})
	for _, rec := range []*secrec.Vault{&first, &second, &third} {
		v.take(&Tok{Token: &secrec.VaultToken{Vault: rec}})
	}
	return v, one, two
}

// A version read as history is held to the token that listed it: one listed
// under a commitment an earlier token listed is refused, as it is when it
// is the current version, and one no token listed is refused.
func TestHistoryRefusesAReusedCommitment(t *testing.T) {
	v, one, two := history(t)
	if got := v.Statuses; len(got) != 3 || got[2] != secrec.StatusCommitmentReuse || v.Usable() != 3 {
		t.Fatalf("the chain folds %v, usable %d", got, v.Usable())
	}
	if seq, err := v.History(one); err != nil || seq != 1 {
		t.Fatalf("version 1 as history: seq %d, %v", seq, err)
	}
	var f *Failure
	if _, err := v.History(two); !errors.As(err, &f) || f.Label != "listing" || !contains(err.Error(), "commitment-reuse") {
		t.Fatalf("a version listed under a used commitment, read as history: %v", err)
	}
	other := *two.Carrier.Secret
	other.Length = 528
	cid, _ := other.ContentID()
	if _, err := v.History(&Car{Carrier: &secrec.Carrier{Secret: &other, ContentID: cid, Commitment: other.Commitment}}); !errors.As(err, &f) || f.Label != "listing" {
		t.Fatalf("another record at a listed version, read as history: %v", err)
	}
}

// A content source that serves other bytes, or cuts them, is passed over:
// the next source is tried, and the ciphertext is taken from the first that
// serves exactly what the record names.
func TestAWrongContentSourceIsPassedOver(t *testing.T) {
	ctx := context.Background()
	ct := []byte("ciphertext bytes, public")
	hash := sha256.Sum256(ct)
	name := hex.EncodeToString(hash[:])
	bad, cut, good := t.TempDir(), t.TempDir(), t.TempDir()
	for dir, b := range map[string][]byte{bad: []byte("ciphertext bytes, forged"), cut: ct[:8], good: ct} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := &Store{Sources: []string{bad, cut, good}, Max: 1 << 20}
	if got, err := s.Get(ctx, hash, uint64(len(ct))); err != nil || string(got) != string(ct) {
		t.Fatalf("the third source holds it: %q %v", got, err)
	}
	// With no source that serves it, the wrong bytes go to the reader's own
	// check, which names the failure.
	s = &Store{Sources: []string{bad, cut}, Max: 1 << 20}
	if got, err := s.Get(ctx, hash, uint64(len(ct))); err != nil || sha256.Sum256(got) == hash {
		t.Fatalf("only wrong sources: %q %v", got, err)
	}
}

// An answer is read up to a bound of the reader's own, whatever a host
// sends.
func TestAnAnswerIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"output-list","outputs":[],"pad":"`))
		chunk := bytes.Repeat([]byte("a"), 1<<20)
		for i := 0; i < limits.MaxAnswer>>20+1; i++ {
			_, _ = w.Write(chunk)
		}
		_, _ = w.Write([]byte(`"}`))
	}))
	defer srv.Close()
	c := &Client{Hosts: []string{srv.URL}}
	org := "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	_, err := c.Ask(context.Background(), srv.URL, Query{"crypt": "example_crypt_hmqzvtkwrx", "vaultsOf": org})
	if err == nil || !contains(err.Error(), hostset.ErrBodyTooLarge.Error()+" ("+strconv.Itoa(limits.MaxAnswer)+" bytes)") {
		t.Fatalf("an answer over the bound: %v", err)
	}
}

// A read's later checks name their culprit in words: a member that opened
// the key of the epoch a record names, and finds the wrap does not open
// under it, is told the owner wrapped under another key; a wrap that holds
// another key than the one committed to names the owner too.
func TestAFailedReadNamesItsCulprit(t *testing.T) {
	key := func(b byte) [32]byte { return sha256.Sum256([]byte{b}) }
	k, other, sym, old, salt := key(1), key(2), key(3), key(4), [secrec.SaltLen]byte{9}
	pt, err := (&secrec.Payload{Name: "a/b", Value: []byte("v")}).EncodePadded(256)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := secrec.Seal(k, salt, 16384, pt)
	if err != nil {
		t.Fatal(err)
	}
	vault := key(5)
	id, _ := secrec.SecretID(vault, "a/b")
	org, _ := hex.DecodeString("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
	rec := &secrec.Secret{Crypt: "a_abcdefghij", Org: org, Vault: vault, ID: id, Version: 1, Label: "internal", Epoch: 1,
		Commitment: secrec.Commitment(k), Hash: sha256.Sum256(ct), Length: uint64(len(ct)), Salt: salt, Segment: 16384, Created: 1,
		Self: make([]byte, secrec.WrapLen), Inline: ct}
	cid, err := rec.ContentID()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	keys := Keys{Epoch: func(context.Context, uint64) ([32]byte, error) { return sym, nil }}
	read := func(wrapKey, wrapped [32]byte) error {
		r := *rec
		if r.Wrap, err = secrec.WrapToEpoch(wrapKey, cid, wrapped, nil); err != nil {
			t.Fatal(err)
		}
		_, err := readValue(ctx, &r, ct, keys)
		return err
	}
	if err := read(sym, k); err != nil {
		t.Fatalf("a version wrapped under the named epoch's key: %v", err)
	}
	var f *Failure
	if err := read(old, k); !errors.As(err, &f) || f.Label != "undecryptable" || !contains(err.Error(), "the owner wrapped the content key under another key") {
		t.Errorf("a wrap under another epoch's key: %v", err)
	}
	if err := read(sym, other); !errors.As(err, &f) || f.Label != "commitment" || !contains(err.Error(), "the owner wrapped a key other than the one it committed to") {
		t.Errorf("another key wrapped: %v", err)
	}
	// A reader that holds no key of the named epoch says so, and blames
	// nobody.
	none := Keys{Epoch: func(context.Context, uint64) ([32]byte, error) {
		return [32]byte{}, errors.New("no wrap names this key")
	}}
	r := *rec
	r.Wrap, _ = secrec.WrapToEpoch(sym, cid, k, nil)
	if _, err := readValue(ctx, &r, ct, none); !errors.As(err, &f) || f.Label != "undecryptable" || contains(err.Error(), "the owner") {
		t.Errorf("a reader with no key of the epoch: %v", err)
	}
}

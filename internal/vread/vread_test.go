package vread

import (
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

	"github.com/lightwebinc/bcommon/lookup"

	"github.com/lightwebinc/borg/reader"

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
	// A host that answers the same page again ends the walk.
	asked := 0
	same := func(Query) ([]lookup.Output, error) {
		asked++
		var outs []lookup.Output
		for s := 0; s < 64; s++ {
			outs = append(outs, lookup.Output{Beef: []byte(strconv.Itoa(s))})
		}
		return outs, nil
	}
	if toks, err := Trail(Query{}, same, verify); err != nil || len(toks) != 64 || asked != 2 {
		t.Fatalf("a host that ignores the cursor: %d tokens, %d questions, %v", len(toks), asked, err)
	}
	// A token that does not verify ends the walk, naming it.
	bad := func(Query) ([]lookup.Output, error) { return []lookup.Output{{Beef: []byte("bad")}}, nil }
	var re *Refusal
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

package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTripAndModes(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(dir, "02aa")
	if err != nil {
		t.Fatal(err)
	}
	s.AddCrypt("example_abcdefghij")
	s.AddCrypt("example_abcdefghij")
	s.Vaults = append(s.Vaults, Vault{ID: "v1", Crypt: "example_abcdefghij", Name: "ops",
		Versions: []SecretVersion{{Name: "a", ID: "ia", Version: 1, ContentID: "c1", Listed: true, Ended: true}, {Name: "a", ID: "ia", Version: 2, ContentID: "c2", Listed: true}, {Name: "a", ID: "ia", Version: 3, ContentID: "c3"}}})
	s.Commit("k1")
	s.Commit("k1")
	s.Outbox = append(s.Outbox, Pending{Kind: KindSecret, Txid: "t1"}, Pending{Kind: KindToken, Txid: "t2"})
	s.See(Seen{Crypt: "c", Org: "o", Vault: "v", Seq: 4, Txid: "x4"})
	s.See(Seen{Crypt: "c", Org: "o", Vault: "v", Seq: 2, Txid: "x2"})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, File))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the state file's mode: %v %v", st.Mode(), err)
	}
	back, err := Load(dir, "02aa")
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Crypts) != 1 || len(back.Commitments) != 1 || !back.Committed("k1") || back.Committed("k2") || !back.Queued("t2", "") {
		t.Fatalf("%+v", back)
	}
	if x := back.SeenOf("c", "o", "v"); x == nil || x.Seq != 4 || x.Txid != "x4" {
		t.Fatalf("a vault moved backwards: %+v", x)
	}
	v := back.VaultByID("v1")
	if cur := v.VersionOf("ia", ""); cur == nil || cur.Version != 2 {
		t.Fatalf("the current version: %+v", cur)
	}
	if x := v.VersionOf("ia", "c3"); x == nil || x.Version != 3 || v.VersionOf("ia", "c9") != nil || v.VersionOf("ib", "") != nil {
		t.Fatal("VersionOf by content id")
	}
	back.Done("t1", "")
	if back.Queued("t1", "") || !back.Outbox[0].Mined() || (Pending{Kind: KindSecret}).Mined() || !(Pending{Kind: KindSweep}).Mined() {
		t.Fatal("the outbox")
	}
	back.Forget("c", "o", "v")
	if back.SeenOf("c", "o", "v") != nil {
		t.Fatal("Forget")
	}
	// Another identity's home, and another version, are refused.
	if _, err := Load(dir, "02bb"); err == nil {
		t.Fatal("a state of another identity loaded")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, File))
	if err := os.WriteFile(filepath.Join(dir, File), []byte(`{"version": 9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, "02aa"); err == nil {
		t.Fatal("a state of another version loaded")
	}
	_ = raw
}

func TestSweepsAndPayments(t *testing.T) {
	s := &State{Sweeps: []Sweep{{Txid: "a", Done: true}, {Txid: "b", Failed: "refused"}, {Txid: "c"}}}
	if sw := s.InFlight(); sw == nil || sw.Txid != "c" {
		t.Fatalf("%+v", sw)
	}
	s.Payments = []Payment{{Txid: "p1"}, {Txid: "p2"}}
	if !s.KeepPayments([]string{"p2"}) || s.PaymentOf("p1") != nil || s.PaymentOf("p2") == nil || s.KeepPayments([]string{"p2"}) {
		t.Fatal("KeepPayments")
	}
	s.Unsettleable = []Unsettleable{{Txid: "u"}}
	if !s.IsUnsettleable("u") || s.IsUnsettleable("v") {
		t.Fatal("IsUnsettleable")
	}
}

func TestLockIsExclusive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lock")
	unlock, err := Lock(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(p); !errors.Is(err, ErrLocked) {
		t.Fatalf("a second lock: %v", err)
	}
	unlock()
	again, err := Lock(p)
	if err != nil {
		t.Fatal(err)
	}
	again()
}

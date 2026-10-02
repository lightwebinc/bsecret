package testhost

import (
	"context"
	"net/http/httptest"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/lightwebinc/borg/borgrec"
	"github.com/lightwebinc/borg/reader"
)

// The stand-in organisation makes what borg's own reader accepts: a group
// chain it verifies and folds, and wraps a member opens by borg's checks.
func TestBorgStandInSatisfiesBorgsReader(t *testing.T) {
	chain := NewChain(700)
	cs := httptest.NewServer(chain)
	defer cs.Close()
	a, b := NewHost(chain), NewHost(chain)
	as, bs := httptest.NewServer(a), httptest.NewServer(b)
	defer as.Close()
	defer bs.Close()
	org, err := NewBorg(t.TempDir(), cs.URL, a, b)
	if err != nil {
		t.Fatal(err)
	}
	alice, _ := ec.NewPrivateKey()
	bob, _ := ec.NewPrivateKey()
	gid, err := org.CreateGroup("engineering", alice.PubKey().Compressed(), bob.PubKey().Compressed())
	if err != nil {
		t.Fatal(err)
	}
	if err := org.Remove(gid, bob.PubKey().Compressed()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rd := &reader.Client{Hosts: []string{as.URL, bs.URL}, Headers: chain}
	gv, err := rd.Group(ctx, org.Hall, org.Key(), gid)
	if err != nil {
		t.Fatal(err)
	}
	if len(gv.Tokens) != 2 || gv.Epoch() != 1 || !gv.Agree() || len(gv.Members) != 2 || len(gv.Begins) != 2 {
		t.Fatalf("group view: %d tokens, epoch %d, %d members, %d epochs", len(gv.Tokens), gv.Epoch(), len(gv.Members), len(gv.Begins))
	}
	open := func(k *ec.PrivateKey, epoch uint32) reader.Opened {
		w, err := wallet.NewCompletedProtoWallet(k)
		if err != nil {
			t.Fatal(err)
		}
		return rd.Open(ctx, w, k.PubKey().Compressed(), gv, epoch)
	}
	for e := uint32(0); e < 2; e++ {
		if op := open(alice, e); op.Label != "" || borgrec.Commitment(op.Key) != op.Commitment {
			t.Fatalf("alice epoch %d: %s %v", e, op.Label, op.Err)
		}
	}
	if op := open(bob, 0); op.Label != "" {
		t.Fatalf("bob epoch 0: %s %v", op.Label, op.Err)
	}
	if op := open(bob, 1); op.Label == "" {
		t.Fatal("bob opened the epoch that began with his removal")
	}
	// The organisation's signer key is a member, and opens both.
	orgKey, err := identityKey(org.Home)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := borgrec.SignerPrivate(orgKey)
	if err != nil {
		t.Fatal(err)
	}
	if op := open(sk, 1); op.Label != "" {
		t.Fatalf("the signer key: %s %v", op.Label, op.Err)
	}
}

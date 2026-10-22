package testhost

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/lightwebinc/bcommon/nodeapi"

	"github.com/lightwebinc/borg/borgrec"
	"github.com/lightwebinc/borg/reader"

	"github.com/lightwebinc/bsecret/internal/vread"
)

// The stand-in organization makes what borg's own reader accepts: a group
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
	// The organization's signer key is a member, and opens both.
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

// memFloor is a reader's Floor in memory that can forget a chain.
type memFloor struct {
	seq    map[string]uint64
	txid   map[string]string
	forgot int
}

func (m *memFloor) Seen(hall, org, chain string) (uint64, string, bool) {
	s, ok := m.seq[hall+org+chain]
	return s, m.txid[hall+org+chain], ok
}

func (m *memFloor) See(hall, org, chain string, seq uint64, txid string) {
	m.seq[hall+org+chain], m.txid[hall+org+chain] = seq, txid
}

func (m *memFloor) Forget(hall, org, chain string) {
	delete(m.seq, hall+org+chain)
	delete(m.txid, hall+org+chain)
	m.forgot++
}

// proofs is a chain source that answers every proof the same way.
type proofs struct{ err error }

func (p proofs) MerkleProof(context.Context, string) (*transaction.MerklePath, error) {
	return nil, p.err
}

// The group is held to the latest token a reader verified of it: a hall
// that answers the group without its latest token is refused (rollback),
// whatever a failing chain source says, and only the source's word that
// the remembered token is not mined makes the floor forget it.
func TestReadGroupHoldsTheFloor(t *testing.T) {
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
	id, err := reader.ParseGroup(gid)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	fl := &memFloor{seq: map[string]uint64{}, txid: map[string]string{}}
	rd := &reader.Client{Hosts: []string{as.URL, bs.URL}, Headers: chain, Floor: fl}
	g, err := vread.ReadGroup(ctx, rd, org.Hall, org.Key(), id)
	if err != nil || g.Current().Epoch != 1 {
		t.Fatalf("the group: %v", err)
	}
	removal := org.LatestToken(gid)
	if s, txid, ok := fl.Seen(org.Hall, hex.EncodeToString(org.Key()), gid); !ok || s != 1 || txid != removal {
		t.Fatalf("the floor after the read: seq %d %s %v", s, txid, ok)
	}
	a.ForgetHall(removal)
	b.ForgetHall(removal)
	rolled := func(what string) {
		t.Helper()
		_, err := vread.ReadGroup(ctx, rd, org.Hall, org.Key(), id)
		var f *vread.Failure
		if !errors.As(err, &f) || f.Label != vread.LabelRollback {
			t.Fatalf("%s: %v, want rollback", what, err)
		}
		if fl.forgot != 0 {
			t.Fatalf("%s: the floor was forgotten", what)
		}
	}
	rolled("no chain source")
	rd.Source = proofs{err: errors.New("down")}
	rolled("a chain source that fails")
	rd.Source = proofs{}
	rolled("a chain source that holds the token mined")
	// A reorganization displaced the removal: the node says it is not
	// mined, the floor forgets it, and the group is read as it now stands.
	rd.Source = proofs{err: nodeapi.ErrNotMined}
	g, err = vread.ReadGroup(ctx, rd, org.Hall, org.Key(), id)
	if err != nil || g.Current().Epoch != 0 || fl.forgot != 1 {
		t.Fatalf("after a reorganization: %v, forgot %d", err, fl.forgot)
	}
	if s, _, ok := fl.Seen(org.Hall, hex.EncodeToString(org.Key()), gid); !ok || s != 0 {
		t.Fatalf("the floor after the reorganization: seq %d %v", s, ok)
	}
}

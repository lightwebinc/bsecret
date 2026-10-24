package module

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/lightwebinc/bcommon/chaintoken"
	"github.com/lightwebinc/bcommon/guard"
	bmodule "github.com/lightwebinc/bcommon/module"
	"github.com/lightwebinc/bcommon/replay"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// peerOf asks a rig's lookup service as a peer's route answers: an error
// is the peer's refusal.
func peerOf(r *rig) bmodule.Ask {
	return func(ctx context.Context, q *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
		a, err := r.ls.Lookup(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", bmodule.ErrRefused, err)
		}
		return a, nil
	}
}

func (m *memStorage) isApplied(topic, txid string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applied[topic+"|"+txid]
}

type walked struct {
	calls, gaps int
	kinds       map[string]int
	notes       []string
}

// replayFrom runs whole walks of host into from until one is Done,
// submitting each answer's objects in order as the engine does and holding
// every token to its BEEF and its parent (the token and exactly its parent,
// the parent held or admitted earlier in the answer).
func replayFrom(t *testing.T, into, from *rig, maxQ, maxO int) walked {
	t.Helper()
	res := walked{kinds: map[string]int{}}
	var cursor any
	for {
		res.calls++
		if res.calls > 2000 {
			t.Fatal("the walk does not end")
		}
		a, err := into.ls.Replay(context.Background(), &bmodule.ReplayRequest{Topic: into.topic, Peer: "a", Ask: peerOf(from), Cursor: cursor,
			MaxQuestions: maxQ, MaxObjects: maxO,
			Applied: func(_ context.Context, txid chainhash.Hash) (bool, error) {
				return into.storage.isApplied(into.topic, txid.String()), nil
			}})
		if err != nil {
			t.Fatal(err)
		}
		if maxQ > 0 && a.Questions > maxQ || maxO > 0 && len(a.Objects) > maxO {
			t.Fatalf("a call asked %d and answered %d, bounds %d and %d", a.Questions, len(a.Objects), maxQ, maxO)
		}
		res.gaps += a.Gaps
		res.notes = append(res.notes, a.Notes...)
		admitted := map[chainhash.Hash]bool{}
		for _, o := range a.Objects {
			for _, dep := range o.After {
				if !admitted[dep] {
					t.Fatalf("%s %s submitted before %s, its After", o.Kind, o.Txid, dep)
				}
			}
			if o.Kind == replay.KindToken {
				wire, err := chaintoken.ReadWire(o.BEEF, 0)
				if err != nil {
					t.Fatal(err)
				}
				tx := wire.SubjectTx()
				parent, err := wire.Token(tx)
				if err != nil {
					t.Fatalf("token %s: %v", o.Txid, err)
				}
				tok, _ := secrec.ReadToken(tx)
				if tok.Vault.Seq > 0 && !into.storage.isApplied(into.topic, parent.Txid.String()) && !admitted[parent.Txid] {
					t.Fatalf("token %s (seq %d) submitted before its parent is held", o.Txid, tok.Vault.Seq)
				}
			}
			if into.storage.isApplied(into.topic, o.Txid.String()) {
				t.Fatalf("%s %s answered though applied", o.Kind, o.Txid)
			}
			if _, err := into.submit(o.BEEF); err == nil {
				admitted[o.Txid] = true
			}
			res.kinds[o.Kind]++
		}
		if a.Done {
			return res
		}
		cursor = a.Cursor
	}
}

type vectorWorld struct {
	f                          *txFile
	crypt, org, vault, second  string
	questions                  []map[string]string
	carriers, tokens           []string
	unreachable, unreachableQs map[string]bool
}

// world reads the vectors and the questions every class asks of them. The
// vectors hold four objects no free class leads a replayer to, which the
// comparisons leave out: the token on a parent that was never admissible
// (pending for good, so never a vault's latest and never listed), the
// funding tree published alone (a sweep of an outpoint no carrier spent),
// the ssh-key secret's one version (unlisted, of a secret no token lists),
// and the carrier that lost its funding outpoint to a lower commitment
// (superseded: kept as evidence, never answered). The answers do not
// depend on them: a host that holds the winner answers as one that holds
// both.
func readWorld(t *testing.T) *vectorWorld {
	t.Helper()
	f, _ := readTx(t)
	secondRec, _ := f.admits(t, "vault-token-second-vault")
	sv, err := secrec.DecodeVault(unhex(t, secondRec))
	if err != nil {
		t.Fatal(err)
	}
	vw := &vectorWorld{f: f, crypt: f.Crypt, org: hex.EncodeToString(sv.Org), vault: f.Vault, second: hexOf(sv.Vault),
		unreachable: map[string]bool{f.id("vault-token-on-unadmitted-parent"): true, f.id("funding-tree-alone"): true, f.id("secret-carrier-ssh-key-v1"): true}}
	// The loser of the equivocated outpoint: the higher of the two version-1
	// carriers of api-token.
	pair := sortedCopy([]string{f.id("secret-carrier-api-token-v1"), f.id("carrier-locktime-max")})
	vw.unreachable[pair[1]] = true
	q := func(extra ...string) map[string]string {
		m := map[string]string{"crypt": vw.crypt, "org": vw.org, "vault": vw.vault}
		for i := 0; i+1 < len(extra); i += 2 {
			m[extra[i]] = extra[i+1]
		}
		return m
	}
	_, spent := f.admits(t, "sweep")
	for _, x := range []map[string]string{
		q(), q("seq", "0"), q("seq", "1"), q("seq", "2"), q("seq", "3"),
		{"crypt": vw.crypt, "org": vw.org, "vault": vw.second}, {"crypt": vw.crypt, "org": vw.org, "vault": vw.second, "seq": "0"},
		{"crypt": vw.crypt, "vaultsOf": vw.org},
		{"crypt": vw.crypt, "org": vw.org, "secretsOf": vw.vault}, {"crypt": vw.crypt, "org": vw.org, "secretsOf": vw.second},
		{"crypt": vw.crypt, "spent": spent[0]}, {"crypt": vw.crypt, "spent": spent[1]},
		{"crypt": vw.crypt, "audit": vw.org, "vault": vw.vault},
	} {
		vw.questions = append(vw.questions, x)
	}
	for _, name := range []string{"tx/api-token", "tx/db-password", "tx/tls-key"} {
		id := sid(t, vw.vault, name)
		vw.questions = append(vw.questions, q("secret", id), q("pending", id), q("secret", id, "version", "1"), q("secret", id, "version", "2"),
			q("secret", id, "version", "3"), map[string]string{"crypt": vw.crypt, "history": vw.org, "vault": vw.vault, "secret": id})
	}
	for _, c := range f.Cases {
		if c.Verdict != "admit" || vw.unreachable[c.Txid] {
			continue
		}
		switch c.Admits.Kind {
		case "secret":
			vw.carriers = append(vw.carriers, hexOf(hashOf(c.Txid)))
		case "vault-token":
			vw.tokens = append(vw.tokens, c.Txid)
		}
	}
	return vw
}

// level reports how host b differs from host a: every question answered
// alike and every token's status alike, and every carrier's status alike
// but one a never answers (retracted or superseded), which b may lack.
func (vw *vectorWorld) level(t *testing.T, a, b *rig) string {
	t.Helper()
	var diff []string
	if x, y := snapshot(t, a, vw.questions, nil, vw.tokens), snapshot(t, b, vw.questions, nil, vw.tokens); x != y {
		diff = append(diff, "answers:\n"+y+"\nwant\n"+x)
	}
	ctx := context.Background()
	for _, c := range vw.carriers {
		sa, _ := a.ls.Status(ctx, c)
		sb, _ := b.ls.Status(ctx, c)
		if sa == sb || (sb == "" && (sa == secrec.StatusRetracted || sa == secrec.StatusSuperseded)) {
			continue
		}
		diff = append(diff, fmt.Sprintf("carrier %s: %q, want %q", c, sb, sa))
	}
	return strings.Join(diff, "\n")
}

// host is a host given the cases named, as the plane would have delivered
// them.
func (vw *vectorWorld) host(t *testing.T, names ...string) *rig {
	t.Helper()
	_, h := readTx(t)
	r := setup(t, vw.f, h, nil, nil)
	for _, n := range names {
		for _, c := range vw.f.Cases {
			if c.Name == n {
				if _, err := r.submit(unhex(t, c.BEEF)); err != nil {
					t.Fatalf("%s: %v", n, err)
				}
			}
		}
	}
	return r
}

func (vw *vectorWorld) utxos(r *rig) []string {
	var out []string
	for _, o := range r.storage.utxos(vw.f.Topic, false) {
		if !vw.unreachable[o.Outpoint.Txid.String()] {
			out = append(out, o.Outpoint.String())
		}
	}
	sort.Strings(out)
	return out
}

// TestReplayLevelsAHost: host B holds the vault's first token, the second
// vault and the first versions of two secrets; it missed three tokens (two
// of them at one seq, one mined in its parent's block), every later
// version, a retired secret and the sweep. One walk from host A, asking
// only the free classes, leaves both answering every class alike, with the
// same unspent outputs, tokens submitted in order on their parents; a
// second walk answers nothing, and A replaying from B finds nothing.
func TestReplayLevelsAHost(t *testing.T) {
	vw := readWorld(t)
	a, _ := vectorRig(t, nil, nil)
	b := vw.host(t, "vault-token-create", "vault-token-second-vault", "secret-carrier-api-token-v1", "secret-carrier-db-password-v1")
	want := snapshot(t, a, vw.questions, vw.carriers, vw.tokens)
	if snapshot(t, b, vw.questions, vw.carriers, vw.tokens) == want {
		t.Fatal("host B is level before any replay")
	}
	res := replayFrom(t, b, a, 0, 0)
	if got := snapshot(t, b, vw.questions, vw.carriers, vw.tokens); got != want {
		t.Fatalf("after the walk:\n%s\nwant\n%s\nnotes %v", got, want, res.notes)
	}
	if fmt.Sprint(vw.utxos(b)) != fmt.Sprint(vw.utxos(a)) {
		t.Fatalf("unspent outputs:\n%v\nwant\n%v", vw.utxos(b), vw.utxos(a))
	}
	if res.kinds["token"] != 4 || res.kinds["sweep"] != 1 || res.kinds["carrier"] != 4 || res.gaps != 0 {
		t.Fatalf("replayed %v, gaps %d, notes %v", res.kinds, res.gaps, res.notes)
	}
	if again := replayFrom(t, b, a, 0, 0); len(again.kinds) != 0 {
		t.Fatalf("a second walk replayed %v", again.kinds)
	}
	if back := replayFrom(t, a, b, 0, 0); len(back.kinds) != 0 {
		t.Fatalf("A replayed %v from B", back.kinds)
	}
}

// TestReplayBounded: two questions and one object a call, and the walks
// together level the host all the same.
func TestReplayBounded(t *testing.T) {
	vw := readWorld(t)
	a, _ := vectorRig(t, nil, nil)
	b := vw.host(t, "vault-token-create", "vault-token-second-vault", "secret-carrier-api-token-v1", "secret-carrier-db-password-v1")
	res := replayFrom(t, b, a, 2, 1)
	if d := vw.level(t, a, b); d != "" {
		t.Fatalf("after the bounded walk (%d calls): %s", res.calls, d)
	}
	if res.calls < 9 {
		t.Fatalf("%d calls for nine objects at one a call", res.calls)
	}
}

// TestReplayFirstToken: a host that holds nothing of the crypt but a
// carrier (from which it knows the organization) needs each first token's
// parent, the chain tree, which no host keeps: without a chain view both
// vaults are gaps and no token is answered; with one the crypt is
// levelled. The carrier it holds is the one the sweep retracts: a sweep is
// found through the carriers a host holds, and one of carriers it never
// held, which retracts nothing there, is not replayed.
func TestReplayFirstToken(t *testing.T) {
	vw := readWorld(t)
	a, _ := vectorRig(t, nil, nil)
	b := vw.host(t, "secret-carrier-db-password-v1")
	res := replayFrom(t, b, a, 0, 0)
	if res.kinds["token"] != 0 || res.gaps < 2 {
		t.Fatalf("with no chain view: %v, gaps %d", res.kinds, res.gaps)
	}
	trees := treesOf{}
	for _, n := range []string{"vault-token-create", "vault-token-second-vault"} {
		for _, c := range vw.f.Cases {
			if c.Name != n {
				continue
			}
			_, tx, _, err := guard.ParseBEEF(unhex(t, c.BEEF), guard.DefaultBound)
			if err != nil {
				t.Fatal(err)
			}
			for _, in := range tx.Inputs {
				if p := in.SourceTransaction; p != nil && p.MerklePath != nil {
					trees = append(trees, p)
				}
			}
		}
	}
	b.ls.trees = trees
	res = replayFrom(t, b, a, 0, 0)
	if d := vw.level(t, a, b); d != "" {
		t.Fatalf("with a chain view (%v, notes %v): %s", res.kinds, res.notes, d)
	}
}

// treesOf is a chain view holding the given transactions.
type treesOf []*transaction.Transaction

func (ts treesOf) TxRaw(_ context.Context, txid string) ([]byte, error) {
	for _, tx := range ts {
		if tx.TxID().String() == txid {
			return tx.Bytes(), nil
		}
	}
	return nil, errors.New("not known")
}

func (ts treesOf) Proof(_ context.Context, txid string) (*transaction.MerklePath, uint32, error) {
	for _, tx := range ts {
		if tx.TxID().String() == txid {
			return tx.MerklePath, tx.MerklePath.BlockHeight, nil
		}
	}
	return nil, 0, errors.New("not mined")
}

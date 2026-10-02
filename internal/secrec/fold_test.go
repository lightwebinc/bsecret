package secrec

import (
	"crypto/sha256"
	"testing"
)

func h32(s string) [32]byte { return sha256.Sum256([]byte(s)) }

// foldVault is a token whose count, stale and root are those the fold of
// set gives at epoch.
func foldVault(seq, epoch uint64, set []Current, create, update []Entry, retire [][32]byte) *Vault {
	var stale uint64
	for _, c := range set {
		if c.Epoch < epoch {
			stale++
		}
	}
	return &Vault{Seq: seq, Epoch: epoch, Create: create, Update: update, Retire: retire,
		Count: uint64(len(set)), Stale: stale, Root: SetRoot(set)}
}

// A token that breaks the fold changes nothing: the set, the last versions,
// the commitments and the trail stay those of the token before it. The
// TypeScript fold is the same (host/src/chain.ts), and vault-v1.json pins
// the set after every record of every fold case for both.
func TestVaultFoldIsAtomic(t *testing.T) {
	a, b := h32("a"), h32("b")
	ea := Entry{ID: a, Version: 1, ContentID: h32("a1"), Commitment: h32("ka1")}
	eb := Entry{ID: b, Version: 1, ContentID: h32("b1"), Commitment: h32("kb1")}
	set0 := []Current{{ID: a, Version: 1, ContentID: ea.ContentID}, {ID: b, Version: 1, ContentID: eb.ContentID}}
	for _, c := range []struct {
		name string
		bad  func() *Vault
		want string
	}{
		{"retires a, then updates a secret the set does not hold", func() *Vault {
			v := foldVault(1, 0, set0[1:], nil, []Entry{{ID: h32("c"), Version: 1, ContentID: h32("c1"), Commitment: h32("kc1")}}, [][32]byte{a})
			return v
		}, StatusSetMismatch},
		{"updates a to a new version and commitment, with a false root", func() *Vault {
			v := foldVault(1, 0, set0, nil, []Entry{{ID: a, Version: 2, ContentID: h32("a2"), Commitment: h32("ka2")}}, nil)
			v.Root = h32("elsewhere")
			return v
		}, StatusSetMismatch},
		{"re-keys a under epoch 1 and claims nothing is stale", func() *Vault {
			set := []Current{{ID: a, Version: 2, ContentID: h32("a2"), Epoch: 1}, set0[1]}
			v := foldVault(1, 1, set, nil, []Entry{{ID: a, Version: 2, ContentID: h32("a2"), Commitment: h32("ka2")}}, nil)
			v.Stale = 0
			return v
		}, StatusStaleMismatch},
	} {
		f := NewVaultFold()
		if st := f.Apply(foldVault(0, 0, set0, []Entry{ea, eb}, nil, nil)); st != StatusConsistent {
			t.Fatalf("%s: seq 0 folds %s", c.name, st)
		}
		root, stale, trail := SetRoot(f.Set()), f.Stale(), len(f.Trail())
		branch := f.Clone()
		if st := f.Apply(c.bad()); st != c.want {
			t.Fatalf("%s: folds %s, want %s", c.name, st, c.want)
		}
		if SetRoot(f.Set()) != root || len(f.Set()) != 2 || f.Stale() != stale || len(f.Trail()) != trail || f.Broken() != c.want {
			t.Errorf("%s: the breaking token changed the fold: %d in the set, %d stale, %d events", c.name, len(f.Set()), f.Stale(), len(f.Trail()))
		}
		for _, cur := range f.Set() {
			if cur.Version != 1 || cur.Epoch != 0 {
				t.Errorf("%s: the set holds version %d under epoch %d", c.name, cur.Version, cur.Epoch)
			}
		}
		// Sticky, and still nothing changes.
		if st := f.Apply(foldVault(2, 0, set0, nil, nil, nil)); st != c.want || SetRoot(f.Set()) != root {
			t.Errorf("%s: the status did not stick, or a later token changed the set", c.name)
		}
		// The commitments and last versions of the breaking token were not
		// recorded: a branch that never saw it and the broken fold agree
		// on what a2 would be.
		good := foldVault(1, 0, []Current{{ID: a, Version: 2, ContentID: h32("a2")}, set0[1]}, nil,
			[]Entry{{ID: a, Version: 2, ContentID: h32("a2"), Commitment: h32("ka2")}}, nil)
		if st := branch.Apply(good); st != StatusConsistent {
			t.Errorf("%s: the branch folds %s", c.name, st)
		}
		if len(f.Set()) != 2 || SetRoot(f.Set()) != root {
			t.Errorf("%s: the branch's token reached the fold it was cloned from", c.name)
		}
	}
}

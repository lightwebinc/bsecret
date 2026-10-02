package borgread

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/lightwebinc/bcommon/chaintoken"
	"github.com/lightwebinc/bcommon/guard"
	"github.com/lightwebinc/bcommon/pushdrop"
)

// Token statuses, as borg's index and readers report them.
const (
	StatusConsistent      = "consistent"
	StatusMembersMismatch = "members-mismatch"
	StatusCommitmentReuse = "commitment-reuse"
	StatusRejoinUnrotated = "rejoin-unrotated"
)

// Token is a group chain token read from its transaction.
type Token struct {
	Group *Group
	// Record is the record exactly as carried: the token's second field.
	Record []byte
	// Vout is the token output's index.
	Vout uint32
}

// claimsGroup reports a locking script whose first push is the group tag.
func claimsGroup(s []byte) bool {
	p, ok := pushdrop.FirstPush(s)
	return ok && bytes.Equal(p, TagGroup)
}

// ReadToken reads the one group token a transaction holds, well formed: a
// PushDrop of the tag, the record and a signature holding 1 satoshi, the
// canonical script under the key derived from the record's organisation,
// and a strict field signature that verifies under it. The caller checks the
// transaction's proof against its own headers.
func ReadToken(tx *transaction.Transaction) (*Token, error) {
	var found *Token
	for i, o := range tx.Outputs {
		if o == nil || o.LockingScript == nil || !claimsGroup(*o.LockingScript) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%w: two token outputs", ErrToken)
		}
		to, ok := chaintoken.ReadOutput(o, uint32(i), 2)
		if !ok {
			return nil, fmt.Errorf("%w: a token is two fields, a signature and 1 satoshi", ErrToken)
		}
		g, err := DecodeGroup(to.Fields[1])
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrToken, err)
		}
		org, err := guard.ParsePubKey(g.Org)
		if err != nil {
			return nil, ErrToken
		}
		key, err := GroupDerivation.ExpectedLockingKey(org)
		if err != nil {
			return nil, ErrToken
		}
		if !to.LockedTo(*o.LockingScript, key) || !to.SignedBy(key) {
			return nil, fmt.Errorf("%w: lock or field signature", ErrToken)
		}
		found = &Token{Group: g, Record: to.Fields[1], Vout: uint32(i)}
	}
	if found == nil {
		return nil, fmt.Errorf("%w: no token output", ErrToken)
	}
	return found, nil
}

// StoredToken reads a group token as a host stores and answers it: the
// token's transaction alone, with its proof.
func StoredToken(b []byte) (*transaction.Transaction, *Token, error) {
	tx, err := chaintoken.Stored(b, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrToken, err)
	}
	t, err := ReadToken(tx)
	return tx, t, err
}

// Link is one token of a group's chain as a reader holds it: its record, the
// txid of its transaction (hash byte order) and the height of its block.
type Link struct {
	Record []byte
	Txid   [32]byte
	Height uint32
}

// Epoch is one epoch a group's canonical chain began.
type Epoch struct {
	Epoch uint64
	// ID is SHA-256 of the record of the token that began the epoch.
	ID [32]byte
	// Commitment is the BRC-369 digest of the epoch's key.
	Commitment [32]byte
	// Seq, Txid and Height are that token's.
	Seq    uint64
	Txid   [32]byte
	Height uint32
	// Removed reports that the token removed a member.
	Removed bool
}

// View is a group's chain folded from seq 0.
type View struct {
	// Tokens are the records in chain order, and Statuses the fold's status
	// of each.
	Tokens   []*Group
	Statuses []string
	// Epochs are the epochs the usable chain began, ascending.
	Epochs  []Epoch
	members map[string]bool
}

// Fold folds a group's chain from seq 0, as borg's reader does: links are
// the tokens in chain order, each the successor by spend of the one before.
// It refuses a chain no borg host would have admitted (a record that does
// not decode, a first token that is not seq 0, a transition that breaks
// CheckTransition, a token mined below its predecessor), and reports per
// token what borg's index reports: members-mismatch (sticky: the chain is
// unusable from that token on), commitment-reuse, rejoin-unrotated,
// consistent. Epochs come only from the usable part.
func Fold(links []Link) (*View, error) {
	v := &View{members: map[string]bool{}}
	removed := map[string]bool{}
	commitments := map[[32]byte]bool{}
	broken := false
	for i, l := range links {
		g, err := DecodeGroup(l.Record)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			if g.Seq != 0 {
				return nil, fmt.Errorf("%w: the chain does not start at seq 0", ErrChain)
			}
		} else {
			if err := CheckTransition(v.Tokens[i-1], links[i-1].Txid, g); err != nil {
				return nil, err
			}
			if l.Height < links[i-1].Height {
				return nil, fmt.Errorf("%w: mined below its predecessor", ErrChain)
			}
		}
		v.Tokens = append(v.Tokens, g)
		if broken {
			v.Statuses = append(v.Statuses, StatusMembersMismatch)
			continue
		}
		rejoin := false
		if !g.BeginsEpoch() {
			for _, k := range g.Add {
				rejoin = rejoin || removed[string(k)]
			}
		}
		if foldMembers(v.members, g) != nil {
			broken = true
			v.Statuses = append(v.Statuses, StatusMembersMismatch)
			continue
		}
		for _, k := range g.Remove {
			removed[string(k)] = true
		}
		status := StatusConsistent
		if g.BeginsEpoch() {
			if commitments[g.Commitment] {
				status = StatusCommitmentReuse
			}
			commitments[g.Commitment] = true
			v.Epochs = append(v.Epochs, Epoch{Epoch: g.Epoch, ID: EpochID(l.Record), Commitment: g.Commitment,
				Seq: g.Seq, Txid: l.Txid, Height: l.Height, Removed: len(g.Remove) > 0})
		}
		if status == StatusConsistent && rejoin {
			status = StatusRejoinUnrotated
		}
		v.Statuses = append(v.Statuses, status)
	}
	return v, nil
}

func foldMembers(set map[string]bool, next *Group) error {
	for _, k := range next.Remove {
		if !set[string(k)] {
			return fmt.Errorf("%w: removes a non-member", ErrCount)
		}
		delete(set, string(k))
	}
	for _, k := range next.Add {
		if set[string(k)] {
			return fmt.Errorf("%w: adds a member", ErrCount)
		}
		set[string(k)] = true
	}
	if uint64(len(set)) != next.Count {
		return ErrCount
	}
	keys := make([][]byte, 0, len(set))
	for k := range set {
		keys = append(keys, []byte(k))
	}
	if MembersRoot(keys) != next.Members {
		return fmt.Errorf("%w: members root", ErrCount)
	}
	return nil
}

// Usable is how many tokens from seq 0 fold without a mismatch: a reader
// fails closed from the first mismatched token on.
func (v *View) Usable() int {
	for i, s := range v.Statuses {
		if s == StatusMembersMismatch {
			return i
		}
	}
	return len(v.Tokens)
}

// Latest is the last usable token, or nil.
func (v *View) Latest() *Group {
	if n := v.Usable(); n > 0 {
		return v.Tokens[n-1]
	}
	return nil
}

// Members is the member set after the last usable token, ascending.
func (v *View) Members() [][]byte {
	out := make([][]byte, 0, len(v.members))
	for k := range v.members {
		out = append(out, []byte(k))
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out
}

// EpochByNumber is the epoch e of the usable chain, if it began it.
func (v *View) EpochByNumber(e uint64) (Epoch, bool) {
	for _, x := range v.Epochs {
		if x.Epoch == e {
			return x, true
		}
	}
	return Epoch{}, false
}

package secrec

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// MaxOthers is how many commitments beside the winner an outpoint row keeps
// as evidence that the owner equivocated; the rest are counted.
const MaxOthers = 8

// OutpointRow is the index's row for one funding outpoint (docs/spec.md
// section 11.2): its winner, the lowest commitment of every carrier ever
// admitted on it, kept as a running minimum so that it does not depend on
// what was dropped; up to MaxOthers other commitments and a count of the
// rest; whether a winner of the outpoint was ever dropped, which nothing
// clears; and whether an admitted sweep the host holds spends the outpoint.
type OutpointRow struct {
	Winner  [32]byte
	Others  [][32]byte
	More    uint64
	Any     bool
	Dropped bool
	Swept   bool
}

func less(a, b [32]byte) bool { return bytes.Compare(a[:], b[:]) < 0 }

// Add records a carrier admitted on the outpoint. The winner is the lowest
// commitment, compared as 32 bytes in hash byte order; the others kept are
// the lowest of the rest, so which are kept does not depend on arrival.
func (r *OutpointRow) Add(c [32]byte) {
	if !r.Any {
		r.Winner, r.Any = c, true
		return
	}
	if c == r.Winner {
		return
	}
	for _, o := range r.Others {
		if o == c {
			return
		}
	}
	if less(c, r.Winner) {
		// Dropped stays as it is: once an outpoint's winner was dropped,
		// every carrier on it is superseded, a lower one that arrives
		// later included.
		c, r.Winner = r.Winner, c
	}
	at := len(r.Others)
	for i, o := range r.Others {
		if less(c, o) {
			at = i
			break
		}
	}
	r.Others = append(r.Others, [32]byte{})
	copy(r.Others[at+1:], r.Others[at:])
	r.Others[at] = c
	if len(r.Others) > MaxOthers {
		r.Others = r.Others[:MaxOthers]
		r.More++
	}
}

// Status is a carrier's status on its row, the first that applies:
// retracted, then superseded; "" when neither does, and the listing decides
// (Listings.Status). It depends on the admitted set and the row, never on
// arrival order.
func (r *OutpointRow) Status(c [32]byte) string {
	if r.Swept {
		return StatusRetracted
	}
	if !r.Any || r.Winner != c || r.Dropped {
		return StatusSuperseded
	}
	return ""
}

type versionKey struct {
	id      [32]byte
	version uint64
}

// Listings is what the rooted tokens of one branch of one vault list: for
// each identifier and version, the token that listed it. The index builds
// one per branch and takes a carrier's listed, mismatched or unlisted status
// from it (docs/spec.md section 11.2).
type Listings struct {
	first  *Vault
	listed map[versionKey]*Vault
	byCID  map[[32]byte]*Vault
}

// NewListings starts with no token.
func NewListings() *Listings {
	return &Listings{listed: map[versionKey]*Vault{}, byCID: map[[32]byte]*Vault{}}
}

// Apply records what a rooted token lists. The caller supplies a branch's
// tokens in seq order.
func (l *Listings) Apply(v *Vault) {
	if l.first == nil {
		l.first = v
	}
	for _, list := range [][]Entry{v.Create, v.Update} {
		for _, e := range list {
			l.listed[versionKey{e.ID, e.Version}] = v
			l.byCID[e.ContentID] = v
		}
	}
}

// Status is a carrier's status once its outpoint row gives none: mismatched
// when a rooted token lists its identifier and version with another content
// id or commitment, lists its content id under another epoch than the
// record's, or the record's label is not one of the vault's; listed when a
// rooted token lists its identifier, version, content id and commitment
// under the record's epoch; unlisted otherwise.
func (l *Listings) Status(rec *Secret) string {
	if l.first == nil {
		return StatusUnlisted
	}
	cid, err := rec.ContentID()
	if err != nil {
		return StatusMismatched
	}
	label := false
	for _, x := range l.first.Labels {
		label = label || x == rec.Label
	}
	if !label {
		return StatusMismatched
	}
	if t, ok := l.listed[versionKey{rec.ID, rec.Version}]; ok {
		if CheckListed(t, rec) != nil {
			return StatusMismatched
		}
		return StatusListed
	}
	if t, ok := l.byCID[cid]; ok && CheckListed(t, rec) != nil {
		return StatusMismatched
	}
	return StatusUnlisted
}

// CarrierStatus is a carrier's status, the first that applies of retracted,
// superseded, mismatched, listed and unlisted: row is its funding
// outpoint's row and l the listings of the branch an answer uses.
func CarrierStatus(row *OutpointRow, commitment [32]byte, l *Listings, rec *Secret) string {
	if s := row.Status(commitment); s != "" {
		return s
	}
	return l.Status(rec)
}

// ErrReuse is the owner's tooling's refusal of a content key commitment it
// has published or listed before (docs/spec.md section 6.2).
var ErrReuse = errors.New("secrec: this commitment was published or listed before")

// Commitments is the owner's tooling's record of every content key
// commitment it has published or listed, in any of its vaults. A content
// key and salt used twice give anyone the XOR of the two plaintexts and
// forgeable tags (docs/spec.md section 6.2), and hosts and the index see a
// repeat only within one vault, so the tooling refuses one before it
// publishes anything.
type Commitments struct{ seen map[[32]byte]bool }

// NewCommitments starts an empty record. An instance that catches up from
// the hosts (docs/spec.md section 8.5) calls Use for every commitment of
// every record and token it reads before it writes.
func NewCommitments() *Commitments { return &Commitments{seen: map[[32]byte]bool{}} }

// Use records a commitment, and refuses one recorded before as ErrReuse.
func (c *Commitments) Use(commitment [32]byte) error {
	if c.seen[commitment] {
		return ErrReuse
	}
	c.seen[commitment] = true
	return nil
}

// Seen reports whether a commitment was recorded.
func (c *Commitments) Seen(commitment [32]byte) bool { return c.seen[commitment] }

// CheckFirstToken is a reader's and the index's check on the first token of
// a vault's chain as a host stores it, without its parent (docs/spec.md
// sections 11.4 and 14): the transaction holds one well-formed vault token
// at seq 0, and an input's outpoint hashes to the vault identifier. An
// outpoint is spent by one mined transaction, so the token is the vault's
// one first token. It returns the token and the outpoint.
func CheckFirstToken(tx *transaction.Transaction) (*VaultToken, transaction.Outpoint, error) {
	t, err := ReadToken(tx)
	if err != nil {
		return nil, transaction.Outpoint{}, err
	}
	if t.Vault.Seq != 0 {
		return nil, transaction.Outpoint{}, fmt.Errorf("%w: seq %d is not a first token", ErrTokenInput, t.Vault.Seq)
	}
	for _, in := range tx.Inputs {
		if in.SourceTXID != nil && VaultID([32]byte(*in.SourceTXID), in.SourceTxOutIndex) == t.Vault.Vault {
			return t, transaction.Outpoint{Txid: *in.SourceTXID, Index: in.SourceTxOutIndex}, nil
		}
	}
	return nil, transaction.Outpoint{}, ErrVaultID
}

// CheckNextToken is the same check on a later token against the one before
// it, each as a host stores it: next holds one well-formed vault token,
// exactly one of its inputs spends a token output of prev and that output
// is prev's token, the two are of one crypt, owner and vault at successive
// seqs, and the transition rules of docs/spec.md section 4.2 hold. A token
// that passes from seq 0 on descends from the vault's first token.
func CheckNextToken(prev *transaction.Transaction, prevToken *VaultToken, next *transaction.Transaction) (*VaultToken, error) {
	t, err := ReadToken(next)
	if err != nil {
		return nil, err
	}
	vout, ok := PredecessorSpend(next, prev)
	ptxid := [32]byte(*prev.TxID())
	if !ok || vout != prevToken.Vout || t.Vault.Prev != ptxid || !samePredecessor(t.Vault, prevToken.Vault) {
		return nil, fmt.Errorf("%w: not a spend of the token before it", ErrTokenInput)
	}
	if err := CheckVaultTransition(prevToken.Vault, ptxid, t.Vault); err != nil {
		return nil, err
	}
	return t, nil
}

// Rooted reports which of the tokens a host holds, each as it stores it,
// are rooted (docs/spec.md section 11.2): a first token whose input's
// outpoint hashes to its vault identifier, and every token that descends
// from a rooted one by a spend of its token output under the transition
// rules. The result does not depend on the order of txs, and two rooted
// tokens may share a seq, each the tip of its own branch. A transaction
// that holds no well-formed token is not rooted.
func Rooted(txs []*transaction.Transaction) map[[32]byte]bool {
	type held struct {
		id  [32]byte
		tx  *transaction.Transaction
		tok *VaultToken
	}
	bySeq := map[uint64][]*held{}
	var seqs []uint64
	rooted := map[[32]byte]bool{}
	for _, tx := range txs {
		tok, err := ReadToken(tx)
		if err != nil {
			continue
		}
		h := &held{[32]byte(*tx.TxID()), tx, tok}
		if _, _, err := CheckFirstToken(tx); err == nil {
			rooted[h.id] = true
		}
		seq := tok.Vault.Seq
		if _, ok := bySeq[seq]; !ok {
			seqs = append(seqs, seq)
		}
		bySeq[seq] = append(bySeq[seq], h)
	}
	// A token is rooted by a rooted token at the seq before its own, so one
	// pass in seq order decides every token: by the time a seq is reached,
	// the seq before it is settled.
	slices.Sort(seqs)
	for _, s := range seqs {
		if s == 0 {
			continue
		}
		for _, h := range bySeq[s] {
			if rooted[h.id] {
				continue
			}
			for _, p := range bySeq[s-1] {
				if !rooted[p.id] {
					continue
				}
				if _, err := CheckNextToken(p.tx, p.tok, h.tx); err == nil {
					rooted[h.id] = true
					break
				}
			}
		}
	}
	return rooted
}

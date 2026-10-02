package secrec

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/lightwebinc/bcommon/commit"
)

// Token statuses the index, a reader and an auditor report (docs/spec.md
// section 11.2). They are never admission verdicts: each needs the chain,
// which a topic manager does not read while it admits.
const (
	StatusConsistent      = "consistent"
	StatusPending         = "pending"
	StatusSetMismatch     = "set-mismatch"
	StatusStaleMismatch   = "stale-mismatch"
	StatusCommitmentReuse = "commitment-reuse"
)

// Carrier statuses (docs/spec.md section 11.2), the first that applies.
const (
	StatusRetracted  = "retracted"
	StatusSuperseded = "superseded"
	StatusMismatched = "mismatched"
	StatusListed     = "listed"
	StatusUnlisted   = "unlisted"
)

// Current is one secret of a vault's current set.
type Current struct {
	ID        [32]byte
	Version   uint64
	ContentID [32]byte
	Epoch     uint64 // the epoch of the token that listed this version
	Seq       uint64 // the seq of that token
}

// SetRoot is the RFC 6962 root (bcommon commit) a vault record commits its
// current set to: one leaf datum per secret, Leaf(id, version, content id),
// in ascending order of the identifiers' bytes. The empty set's root is
// SHA-256 of nothing.
func SetRoot(set []Current) [32]byte {
	return commit.Root(setLeaves(set))
}

// sortSet returns a copy of set in ascending order of the identifiers.
func sortSet(set []Current) []Current {
	sorted := make([]Current, len(set))
	copy(sorted, set)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i].ID[:], sorted[j].ID[:]) < 0 })
	return sorted
}

func setLeaves(set []Current) [][32]byte {
	sorted := sortSet(set)
	leaves := make([][32]byte, len(sorted))
	for i, c := range sorted {
		leaves[i] = Leaf(c.ID, c.Version, c.ContentID)
	}
	return leaves
}

// Event is one line of a vault's trail: what one token did to one secret.
type Event struct {
	Seq       uint64
	Kind      string // "create", "update", "rekey" or "retire"
	ID        [32]byte
	Version   uint64   // the version entering the set; for a retire, the one leaving
	ContentID [32]byte // zero for a retire
	Epoch     uint64   // the epoch the version is keyed under; for a retire, the token's
	FromEpoch uint64   // for an update or a rekey: the epoch of the version it replaces
}

// VaultFold folds a vault's chain from seq 0: the current set after each
// token, the last version every identifier ever had, every commitment any
// token listed, and the trail. Once a token breaks the fold the chain is
// unusable from it on, and every later token reports the same status. A
// token that breaks the fold changes nothing: the set, the versions, the
// commitments and the trail stay those of the last token before it, which
// is the set a host goes on answering (docs/spec.md section 11.2).
type VaultFold struct {
	set         map[[32]byte]Current
	last        map[[32]byte]uint64
	commitments map[[32]byte]bool
	epoch       uint64
	broken      string
	trail       []Event
}

// NewVaultFold starts a fold before seq 0.
func NewVaultFold() *VaultFold {
	return &VaultFold{set: map[[32]byte]Current{}, last: map[[32]byte]uint64{}, commitments: map[[32]byte]bool{}}
}

// Clone is a fold that goes on from here on its own: a branch, or a
// transition tried before it is signed.
func (f *VaultFold) Clone() *VaultFold {
	c := &VaultFold{set: make(map[[32]byte]Current, len(f.set)), last: make(map[[32]byte]uint64, len(f.last)),
		commitments: make(map[[32]byte]bool, len(f.commitments)), epoch: f.epoch, broken: f.broken,
		trail: append([]Event(nil), f.trail...)}
	for k, v := range f.set {
		c.set[k] = v
	}
	for k, v := range f.last {
		c.last[k] = v
	}
	for k := range f.commitments {
		c.commitments[k] = true
	}
	return c
}

// Broken is the status that broke the fold, or "" while nothing has.
func (f *VaultFold) Broken() string { return f.broken }

// Apply folds the next token (the caller supplies them in seq order along
// spends) and returns its status, the first that applies:
//
//   - set-mismatch (sticky): it creates an identifier the set holds, updates
//     or retires one it does not, lists a version that is not above the last
//     one the identifier had, or does not reproduce count and root;
//   - stale-mismatch (sticky): its stale is not the number of secrets in the
//     set keyed under an epoch before its own;
//   - commitment-reuse: an entry's commitment is one an earlier token of the
//     vault listed;
//   - consistent.
//
// It is atomic: a token that breaks the fold is applied to a copy that is
// then discarded, so nothing of it reaches the set.
func (f *VaultFold) Apply(v *Vault) string {
	if f.broken != "" {
		return f.broken
	}
	fail := func(s string) string { f.broken = s; return s }
	set := make(map[[32]byte]Current, len(f.set)+len(v.Create))
	for k, c := range f.set {
		set[k] = c
	}
	last := map[[32]byte]uint64{}
	lastOf := func(id [32]byte) uint64 {
		if n, ok := last[id]; ok {
			return n
		}
		return f.last[id]
	}
	var trail []Event
	reuse := false
	for _, id := range v.Retire {
		c, ok := set[id]
		if !ok {
			return fail(StatusSetMismatch)
		}
		delete(set, id)
		trail = append(trail, Event{Seq: v.Seq, Kind: "retire", ID: id, Version: c.Version, Epoch: v.Epoch, FromEpoch: c.Epoch})
	}
	for _, e := range v.Update {
		c, ok := set[e.ID]
		if !ok || e.Version <= lastOf(e.ID) {
			return fail(StatusSetMismatch)
		}
		kind := "update"
		if c.Epoch < v.Epoch {
			kind = "rekey"
		}
		trail = append(trail, Event{Seq: v.Seq, Kind: kind, ID: e.ID, Version: e.Version, ContentID: e.ContentID, Epoch: v.Epoch, FromEpoch: c.Epoch})
		set[e.ID] = Current{ID: e.ID, Version: e.Version, ContentID: e.ContentID, Epoch: v.Epoch, Seq: v.Seq}
		last[e.ID] = e.Version
		reuse = reuse || f.commitments[e.Commitment]
	}
	for _, e := range v.Create {
		if _, ok := set[e.ID]; ok || e.Version <= lastOf(e.ID) {
			return fail(StatusSetMismatch)
		}
		trail = append(trail, Event{Seq: v.Seq, Kind: "create", ID: e.ID, Version: e.Version, ContentID: e.ContentID, Epoch: v.Epoch})
		set[e.ID] = Current{ID: e.ID, Version: e.Version, ContentID: e.ContentID, Epoch: v.Epoch, Seq: v.Seq}
		last[e.ID] = e.Version
		reuse = reuse || f.commitments[e.Commitment]
	}
	now := make([]Current, 0, len(set))
	var stale uint64
	for _, c := range set {
		now = append(now, c)
		if c.Epoch < v.Epoch {
			stale++
		}
	}
	if uint64(len(set)) != v.Count || SetRoot(now) != v.Root {
		return fail(StatusSetMismatch)
	}
	if stale != v.Stale {
		return fail(StatusStaleMismatch)
	}
	f.set, f.epoch = set, v.Epoch
	for id, n := range last {
		f.last[id] = n
	}
	for _, l := range [][]Entry{v.Create, v.Update} {
		for _, e := range l {
			f.commitments[e.Commitment] = true
		}
	}
	f.trail = append(f.trail, trail...)
	if reuse {
		return StatusCommitmentReuse
	}
	return StatusConsistent
}

// Set is the current set after the last token that did not break the fold,
// ascending by id.
func (f *VaultFold) Set() []Current {
	out := make([]Current, 0, len(f.set))
	for _, c := range f.set {
		out = append(out, c)
	}
	return sortSet(out)
}

// Stale is the number of secrets in the set keyed under an epoch before the
// one the last token that did not break the fold acknowledges.
func (f *VaultFold) Stale() uint64 {
	var n uint64
	for _, c := range f.set {
		if c.Epoch < f.epoch {
			n++
		}
	}
	return n
}

// Trail is every event folded so far, in order; a token that broke the
// fold adds none.
func (f *VaultFold) Trail() []Event { return f.trail }

// Mined is one vault token as an auditor holds it: its record, the txid of
// its transaction (hash byte order) and the height of the block its proof
// names, which the auditor checked against its own headers.
type Mined struct {
	Vault  *Vault
	Txid   [32]byte
	Height uint32
}

// EpochEvent is one epoch of the vault's group as an auditor holds it, from
// the canonical chain of the group the vault names: the height of the block
// that mined the group token that began it, and whether that token removed
// anyone.
type EpochEvent struct {
	Epoch   uint64
	EpochID [32]byte
	Height  uint32
	Removed bool
}

// Window is what an audit reports for one epoch the group began after the
// vault's first token's: when the group began it, how long the vault went
// on writing under an earlier one, when the vault's chain acknowledged it,
// when the fold shows nothing left under an earlier epoch, and what was
// still under one at the end of the trail.
type Window struct {
	Epoch        uint64
	Removed      bool
	Began        uint32 // height of the group token that began the epoch
	Late         uint64 // vault tokens mined above Began that still name an earlier epoch
	Acknowledged uint32 // height of the first vault token at this epoch or later; 0 when none
	Settled      uint32 // height of the first such token after which the fold holds nothing under an earlier epoch; 0 when none
	Stale        uint64 // secrets still under an earlier epoch at the end of the trail
}

// Problems an audit reports (docs/spec.md section 9.2). Any of them makes
// the audit fail.
const (
	AuditEmpty      = "empty"      // no token
	AuditFirst      = "first"      // the trail does not start at seq 0
	AuditTransition = "transition" // a token breaks section 4.2 against the one before it
	AuditHeight     = "height"     // a token is mined below the one it spends
	AuditStatus     = "status"     // a token's fold is not consistent
	AuditEpoch      = "epoch"      // a token names an epoch the group has not begun, another epoch id, or an epoch before the block that began it
	AuditGroup      = "group"      // the group's epochs are not distinct, consecutive and in height order
)

// Finding is one problem at one token.
type Finding struct {
	Seq     uint64
	Problem string
	Detail  string
}

// Report is an audit's result.
type Report struct {
	OK       bool
	Findings []Finding
	Statuses []string
	Windows  []Window
}

// Audit checks a vault's mined tokens, in seq order, against the epochs of
// its group, as section 9.2 steps 3 to 6 say: the trail starts at seq 0;
// every token meets the transition rules against the one before it, whose
// txid it names, and is mined at or above it; the fold is consistent at
// every token; and every token's epoch and epoch id are those of an epoch
// the group began at or below the token's height. It verifies no proof and
// no script: the caller has checked every token and every epoch against its
// own headers and passes the heights it found. It reports one window per
// epoch the group began after the vault's first token's. A report that is
// not OK says nothing reliable about windows.
func Audit(tokens []Mined, epochs []EpochEvent) Report {
	r := Report{OK: true}
	bad := func(seq uint64, problem, detail string) {
		r.OK = false
		r.Findings = append(r.Findings, Finding{Seq: seq, Problem: problem, Detail: detail})
	}
	if len(tokens) == 0 {
		bad(0, AuditEmpty, "")
		return r
	}
	byEpoch := map[uint64]EpochEvent{}
	for _, e := range epochs {
		byEpoch[e.Epoch] = e
	}
	sorted := make([]EpochEvent, len(epochs))
	copy(sorted, epochs)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Epoch < sorted[j].Epoch })
	// The group's epochs are one chain: each number once, consecutive, each
	// with its own id, none mined below the one before it.
	ids := map[[32]byte]bool{}
	for i, e := range sorted {
		if ids[e.EpochID] || (i > 0 && (e.Epoch != sorted[i-1].Epoch+1 || e.Height < sorted[i-1].Height)) {
			bad(0, AuditGroup, "")
			return r
		}
		ids[e.EpochID] = true
	}
	first := tokens[0].Vault.Epoch
	for _, e := range sorted {
		if e.Epoch > first {
			r.Windows = append(r.Windows, Window{Epoch: e.Epoch, Removed: e.Removed, Began: e.Height})
		}
	}
	if tokens[0].Vault.Seq != 0 {
		bad(tokens[0].Vault.Seq, AuditFirst, "")
	}
	f := NewVaultFold()
	for i, t := range tokens {
		v := t.Vault
		if i > 0 {
			p := tokens[i-1]
			if err := CheckVaultTransition(p.Vault, p.Txid, v); err != nil {
				bad(v.Seq, AuditTransition, Reason(err))
			}
			if t.Height < p.Height {
				bad(v.Seq, AuditHeight, "")
			}
		}
		st := f.Apply(v)
		r.Statuses = append(r.Statuses, st)
		if st != StatusConsistent {
			bad(v.Seq, AuditStatus, st)
		}
		e, known := byEpoch[v.Epoch]
		switch {
		case !known:
			bad(v.Seq, AuditEpoch, "an epoch the group has not begun")
		case e.EpochID != v.EpochID:
			bad(v.Seq, AuditEpoch, "another epoch id")
		case t.Height < e.Height:
			bad(v.Seq, AuditEpoch, "before the block that began the epoch")
		}
		for n := range r.Windows {
			w := &r.Windows[n]
			if v.Epoch < w.Epoch {
				if t.Height > w.Began {
					w.Late++
				}
				continue
			}
			if w.Acknowledged == 0 {
				w.Acknowledged = t.Height
			}
			if w.Settled == 0 && f.under(w.Epoch) == 0 {
				w.Settled = t.Height
			}
		}
	}
	for n := range r.Windows {
		r.Windows[n].Stale = f.under(r.Windows[n].Epoch)
	}
	return r
}

// under counts the secrets in the set keyed under an epoch before e.
func (f *VaultFold) under(e uint64) uint64 {
	var n uint64
	for _, c := range f.set {
		if c.Epoch < e {
			n++
		}
	}
	return n
}

// sameVault reports whether rec names the token's crypt, owner, vault and
// group and carries one of the vault's labels.
func sameVault(token *Vault, rec *Secret) bool {
	if rec.Crypt != token.Crypt || !bytes.Equal(rec.Org, token.Org) || rec.Vault != token.Vault || rec.Group != token.Group {
		return false
	}
	for _, l := range token.Labels {
		if l == rec.Label {
			return true
		}
	}
	return false
}

// CheckInSet is a reader's first check on a secret record a host answered
// for a vault's latest token, whose txid is latestTxid (docs/spec.md section
// 7.2): the inclusion path names that token and takes the leaf of the
// record's identifier, version and content id to its root; the record
// names the token's crypt, owner, vault and group and one of its labels; and
// it is keyed under the token's epoch, or, only while the token counts
// something stale, under an earlier one. A record keyed under an epoch
// before the token's in a vault that says nothing is stale was listed by a
// token that claimed a re-keying it did not make.
func CheckInSet(latest *Vault, latestTxid [32]byte, rec *Secret, path *InclusionContext) error {
	cid, err := rec.ContentID()
	if err != nil {
		return err
	}
	if path == nil || path.Seq != latest.Seq || path.Token != latestTxid || !path.VerifySecret(rec.ID, rec.Version, cid, latest.Root) {
		return ErrListing
	}
	if !sameVault(latest, rec) {
		return ErrListing
	}
	switch {
	case rec.Epoch > latest.Epoch:
		return ErrListing
	case rec.Epoch == latest.Epoch && rec.EpochID != latest.EpochID:
		return ErrListing
	case rec.Epoch < latest.Epoch && (latest.Stale == 0 || rec.EpochID == latest.EpochID):
		return ErrListing
	}
	return nil
}

// CheckListed is the check of a record against the token that listed it,
// which an index, an auditor and a reader that folds the chain make
// (docs/spec.md sections 9.3 and 11.2): the token creates or updates the
// record's identifier at the record's version, with the record's content id
// and commitment; the record names the token's crypt, owner, vault and
// group and one of its labels; and it is keyed under the token's epoch and
// epoch id. A token that lists a content id whose record is keyed under
// another epoch than the token's has claimed a re-keying it did not make.
func CheckListed(token *Vault, rec *Secret) error {
	cid, err := rec.ContentID()
	if err != nil {
		return err
	}
	var entry *Entry
	for _, l := range [][]Entry{token.Create, token.Update} {
		for i := range l {
			if l[i].ID == rec.ID {
				entry = &l[i]
			}
		}
	}
	if entry == nil || entry.Version != rec.Version || entry.ContentID != cid || entry.Commitment != rec.Commitment {
		return ErrListing
	}
	if !sameVault(token, rec) || rec.Epoch != token.Epoch || rec.EpochID != token.EpochID {
		return ErrListing
	}
	return nil
}

// CheckSuccessor is a reader's check on a version no token lists yet
// (docs/spec.md section 4.4). token is the vault's latest token and prev the
// version before next. The vault's anchor mode is interval; next is the
// version after prev of the same secret of the token's vault, names prev's
// content id as its previous, has another commitment than prev's and one of
// the vault's labels, and is keyed under the same group at an epoch that is
// neither before prev's nor before the token's. The same epoch has the same
// epoch id, and a later epoch another.
func CheckSuccessor(token *Vault, prev, next *Secret) error {
	cid, err := prev.ContentID()
	if err != nil {
		return err
	}
	if token.Anchor != AnchorInterval || !sameVault(token, next) || next.ID != prev.ID ||
		next.Version != prev.Version+1 || next.Previous != cid || next.Commitment == prev.Commitment ||
		next.Epoch < prev.Epoch || next.Epoch < token.Epoch ||
		(next.Epoch == prev.Epoch) != (next.EpochID == prev.EpochID) ||
		(next.Epoch == token.Epoch) != (next.EpochID == token.EpochID) {
		return ErrSuccessor
	}
	return nil
}

// CheckLinks is a reader's check on a run of unlisted versions (docs/spec.md
// section 4.4): listed is the version the token's set holds, and links are
// the records the reader holds above it, in any order. It returns the
// longest run that links to listed, successor by successor, lowest version
// first. It fails when two different records claim one version (the owner
// signed both), or when a commitment repeats anywhere in listed and the
// run. A record that does not link ends the run and is not in it.
func CheckLinks(token *Vault, listed *Secret, links []*Secret) ([]*Secret, error) {
	byVersion := map[uint64]*Secret{}
	ids := map[uint64][32]byte{}
	for _, l := range links {
		cid, err := l.ContentID()
		if err != nil {
			return nil, err
		}
		if have, ok := ids[l.Version]; ok && have != cid {
			return nil, fmt.Errorf("%w: two records at version %d", ErrSuccessor, l.Version)
		}
		ids[l.Version], byVersion[l.Version] = cid, l
	}
	seen := map[[32]byte]bool{listed.Commitment: true}
	var run []*Secret
	prev := listed
	for {
		next, ok := byVersion[prev.Version+1]
		if !ok || CheckSuccessor(token, prev, next) != nil {
			return run, nil
		}
		if seen[next.Commitment] {
			return nil, fmt.Errorf("%w: a commitment repeats at version %d", ErrSuccessor, next.Version)
		}
		seen[next.Commitment] = true
		run = append(run, next)
		prev = next
	}
}

// CheckGroupEpoch is a reader's check that an epoch and epoch id a vault
// token or a secret record names are those of an epoch the group's
// canonical chain began (docs/spec.md section 14). epochs is what the
// reader verified of the group's chain.
func CheckGroupEpoch(epochs []EpochEvent, epoch uint64, id [32]byte) error {
	for _, e := range epochs {
		if e.Epoch == epoch && e.EpochID == id {
			return nil
		}
	}
	return ErrListing
}

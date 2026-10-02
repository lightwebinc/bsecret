package secrec

import (
	"bytes"
	"fmt"

	"github.com/lightwebinc/bcommon/cbor"
	"github.com/lightwebinc/bcommon/record"
)

// Vault record keys.
const (
	VKMagic   = 0
	VKCrypt   = 1
	VKOrg     = 2
	VKVault   = 3
	VKSeq     = 4
	VKPrev    = 5
	VKName    = 6
	VKHall    = 7
	VKGroup   = 8
	VKEpoch   = 9
	VKEpochID = 10
	VKLabels  = 11
	VKAnchor  = 12
	VKCreate  = 13
	VKUpdate  = 14
	VKRetire  = 15
	VKCount   = 16
	VKStale   = 17
	VKRoot    = 18
	VKCreated = 19
	vkLast    = VKCreated
)

// Entry is one change a vault token lists: a version of a secret entering
// the vault's current set.
type Entry struct {
	ID         [32]byte // the secret's identifier
	Version    uint64   // 1 to MaxSafe
	ContentID  [32]byte // the content id of the version's secret record
	Commitment [32]byte // the version's content key commitment
}

// Vault is one vault record: the second field of a vault chain token. Each
// token is one transition of the vault's current set, and the chain of them
// is the vault's audit trail.
type Vault struct {
	Crypt   string           // key 1
	Org     []byte           // key 2, the owner
	Vault   [32]byte         // key 3, VaultID of the first token's funding outpoint
	Seq     uint64           // key 4
	Prev    [32]byte         // key 5, txid of the token at seq-1; zero at seq 0
	Name    string           // key 6, display name
	Hall    string           // key 7, the hall the group lives in
	Group   [GroupIDLen]byte // key 8, the group whose epochs key this vault
	Epoch   uint64           // key 9, the epoch every version this token lists is keyed under
	EpochID [32]byte         // key 10
	Labels  []string         // key 11, fixed at the first token
	Anchor  uint64           // key 12, fixed at the first token
	Create  []Entry          // key 13, secrets entering the set, ascending by id
	Update  []Entry          // key 14, new versions of secrets in the set, ascending by id
	Retire  [][32]byte       // key 15, secrets leaving the set, ascending
	Count   uint64           // key 16, secrets in the set after this transition
	Stale   uint64           // key 17, secrets in the set still keyed under an earlier epoch
	Root    [32]byte         // key 18, SetRoot after this transition
	Created uint64           // key 19, Unix seconds, a claim
	Extra   cbor.Map         // integer keys above 19, preserved and ignored
}

func checkEntries(a []Entry) error {
	if len(a) > MaxDelta {
		return ErrList
	}
	// Every entry's own rule first, then the order of the list, so that one
	// list has one reason.
	for _, e := range a {
		if e.Version < 1 || e.Version > MaxSafe {
			return ErrEntry
		}
	}
	for i := 1; i < len(a); i++ {
		if bytes.Compare(a[i-1].ID[:], a[i].ID[:]) >= 0 {
			return ErrList
		}
	}
	return nil
}

// Validate applies every rule that needs only the record itself.
func (v *Vault) Validate() error {
	if err := record.CheckExtra(v.Extra, vkLast, vkLast+1); err != nil {
		return err
	}
	if err := CheckCrypt(v.Crypt); err != nil {
		return err
	}
	if err := CheckOrgKey(v.Org); err != nil {
		return err
	}
	if err := record.InRange(v.Seq, 0, MaxSafe, "seq"); err != nil {
		return err
	}
	if err := checkName(v.Name); err != nil {
		return err
	}
	if err := CheckHall(v.Hall); err != nil {
		return err
	}
	if err := record.InRange(v.Epoch, 0, MaxEpoch, "epoch"); err != nil {
		return err
	}
	if err := CheckLabels(v.Labels); err != nil {
		return err
	}
	if err := record.InRange(v.Anchor, AnchorVersion, AnchorInterval, "anchor"); err != nil {
		return err
	}
	if err := checkEntries(v.Create); err != nil {
		return err
	}
	if err := checkEntries(v.Update); err != nil {
		return err
	}
	if len(v.Retire) > MaxDelta {
		return ErrList
	}
	if err := record.Ascending32(v.Retire); err != nil {
		return err
	}
	if err := record.InRange(v.Count, 0, MaxSecrets, "count"); err != nil {
		return err
	}
	if err := record.InRange(v.Stale, 0, MaxSecrets, "stale"); err != nil {
		return err
	}
	if err := record.InRange(v.Created, 1, MaxTime, "created"); err != nil {
		return err
	}
	return v.cross()
}

// cross is refusal step 7: the rules across fields.
func (v *Vault) cross() error {
	seen := map[[32]byte]bool{}
	keys := map[[32]byte]bool{}
	for _, l := range [][]Entry{v.Create, v.Update} {
		for _, e := range l {
			if seen[e.ID] {
				return fmt.Errorf("%w: a secret changed twice in one transition", ErrList)
			}
			seen[e.ID] = true
			if keys[e.Commitment] {
				return fmt.Errorf("%w: a commitment repeated in one transition", ErrList)
			}
			keys[e.Commitment] = true
		}
	}
	for _, id := range v.Retire {
		if seen[id] {
			return fmt.Errorf("%w: a secret changed twice in one transition", ErrList)
		}
		seen[id] = true
	}
	if (v.Seq == 0) != zero32(v.Prev[:]) {
		return ErrChain
	}
	if v.Seq == 0 && (len(v.Update) != 0 || len(v.Retire) != 0 || v.Count != uint64(len(v.Create))) {
		return ErrCount
	}
	if v.Stale > v.Count || (v.Seq == 0 && v.Stale != 0) || (v.Stale != 0 && len(v.Create) != 0) {
		return ErrDebt
	}
	return nil
}

func entryValues(a []Entry) []cbor.Value {
	out := make([]cbor.Value, len(a))
	for i, e := range a {
		out[i] = []cbor.Value{
			append([]byte(nil), e.ID[:]...), e.Version,
			append([]byte(nil), e.ContentID[:]...), append([]byte(nil), e.Commitment[:]...),
		}
	}
	return out
}

func labelValues(a []string) []cbor.Value {
	out := make([]cbor.Value, len(a))
	for i, l := range a {
		out[i] = l
	}
	return out
}

// Encode writes the vault record in canonical CBOR.
func (v *Vault) Encode() ([]byte, error) {
	if err := v.Validate(); err != nil {
		return nil, err
	}
	m := cbor.Map{
		{Key: uint64(VKMagic), Val: MagicVault},
		{Key: uint64(VKCrypt), Val: v.Crypt},
		{Key: uint64(VKOrg), Val: v.Org},
		{Key: uint64(VKVault), Val: append([]byte(nil), v.Vault[:]...)},
		{Key: uint64(VKSeq), Val: v.Seq},
		{Key: uint64(VKPrev), Val: append([]byte(nil), v.Prev[:]...)},
		{Key: uint64(VKName), Val: v.Name},
		{Key: uint64(VKHall), Val: v.Hall},
		{Key: uint64(VKGroup), Val: append([]byte(nil), v.Group[:]...)},
		{Key: uint64(VKEpoch), Val: v.Epoch},
		{Key: uint64(VKEpochID), Val: append([]byte(nil), v.EpochID[:]...)},
		{Key: uint64(VKLabels), Val: labelValues(v.Labels)},
		{Key: uint64(VKAnchor), Val: v.Anchor},
		{Key: uint64(VKCreate), Val: entryValues(v.Create)},
		{Key: uint64(VKUpdate), Val: entryValues(v.Update)},
		{Key: uint64(VKRetire), Val: record.Values32(v.Retire)},
		{Key: uint64(VKCount), Val: v.Count},
		{Key: uint64(VKStale), Val: v.Stale},
		{Key: uint64(VKRoot), Val: append([]byte(nil), v.Root[:]...)},
		{Key: uint64(VKCreated), Val: v.Created},
	}
	return record.Encode(m, v.Extra, MaxVaultRecord)
}

// entries decodes key k as a change list.
func (f *fields) entries(k uint64) ([]Entry, error) {
	a, err := f.Array(k, MaxDelta)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, len(a))
	for i, x := range a {
		e, ok := x.([]cbor.Value)
		if !ok || len(e) != 4 {
			return nil, fmt.Errorf("%w: key %d", ErrEntry, k)
		}
		id, ok1 := e[0].([]byte)
		ver, ok2 := e[1].(uint64)
		cid, ok3 := e[2].([]byte)
		com, ok4 := e[3].([]byte)
		if !ok1 || !ok2 || !ok3 || !ok4 || len(id) != 32 || len(cid) != 32 || len(com) != 32 {
			return nil, fmt.Errorf("%w: key %d", ErrEntry, k)
		}
		copy(out[i].ID[:], id)
		out[i].Version = ver
		copy(out[i].ContentID[:], cid)
		copy(out[i].Commitment[:], com)
	}
	if err := checkEntries(out); err != nil {
		return nil, fmt.Errorf("%w: key %d", err, k)
	}
	return out, nil
}

// labels decodes key k as a label set.
func (f *fields) labels(k uint64) ([]string, error) {
	v, err := f.Need(k)
	if err != nil {
		return nil, err
	}
	a, ok := v.([]cbor.Value)
	if !ok {
		return nil, fmt.Errorf("%w: key %d", ErrType, k)
	}
	if len(a) < 1 || len(a) > MaxLabels {
		return nil, ErrLabel
	}
	out := make([]string, len(a))
	for i, x := range a {
		s, ok := x.(string)
		if !ok {
			return nil, ErrLabel
		}
		out[i] = s
	}
	if err := CheckLabels(out); err != nil {
		return nil, err
	}
	return out, nil
}

// DecodeVault parses a vault record in the refusal order (docs/spec.md
// section 3.1).
func DecodeVault(p []byte) (*Vault, error) {
	f, err := decodeRecord(p, MaxVaultRecord, vkLast, MagicVault)
	if err != nil {
		return nil, err
	}
	v := &Vault{Extra: f.Extra}
	if v.Crypt, err = f.Text(VKCrypt); err != nil {
		return nil, err
	}
	if err := CheckCrypt(v.Crypt); err != nil {
		return nil, err
	}
	if v.Org, err = f.BytesN(VKOrg, -1); err != nil {
		return nil, err
	}
	if err := CheckOrgKey(v.Org); err != nil {
		return nil, err
	}
	b, err := f.BytesN(VKVault, 32)
	if err != nil {
		return nil, err
	}
	copy(v.Vault[:], b)
	if v.Seq, err = f.Uint(VKSeq, 0, MaxSafe); err != nil {
		return nil, err
	}
	if b, err = f.BytesN(VKPrev, 32); err != nil {
		return nil, err
	}
	copy(v.Prev[:], b)
	if v.Name, err = f.Text(VKName); err != nil {
		return nil, err
	}
	if err := checkName(v.Name); err != nil {
		return nil, err
	}
	if v.Hall, err = f.Text(VKHall); err != nil {
		return nil, err
	}
	if err := CheckHall(v.Hall); err != nil {
		return nil, err
	}
	if b, err = f.BytesN(VKGroup, GroupIDLen); err != nil {
		return nil, err
	}
	copy(v.Group[:], b)
	if v.Epoch, err = f.Uint(VKEpoch, 0, MaxEpoch); err != nil {
		return nil, err
	}
	if b, err = f.BytesN(VKEpochID, 32); err != nil {
		return nil, err
	}
	copy(v.EpochID[:], b)
	if v.Labels, err = f.labels(VKLabels); err != nil {
		return nil, err
	}
	if v.Anchor, err = f.Uint(VKAnchor, AnchorVersion, AnchorInterval); err != nil {
		return nil, err
	}
	if v.Create, err = f.entries(VKCreate); err != nil {
		return nil, err
	}
	if v.Update, err = f.entries(VKUpdate); err != nil {
		return nil, err
	}
	if v.Retire, err = f.List32(VKRetire, MaxDelta); err != nil {
		return nil, err
	}
	if v.Count, err = f.Uint(VKCount, 0, MaxSecrets); err != nil {
		return nil, err
	}
	if v.Stale, err = f.Uint(VKStale, 0, MaxSecrets); err != nil {
		return nil, err
	}
	if b, err = f.BytesN(VKRoot, 32); err != nil {
		return nil, err
	}
	copy(v.Root[:], b)
	if v.Created, err = f.Uint(VKCreated, 1, MaxTime); err != nil {
		return nil, err
	}
	if err := v.cross(); err != nil {
		return nil, err
	}
	return v, nil
}

func sameLabels(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Rekeys reports whether next acknowledges a later epoch than pred's.
func Rekeys(pred, next *Vault) bool { return next.Epoch > pred.Epoch }

// CheckVaultTransition applies the rules a host checks for a vault token
// against the one it spends (docs/spec.md section 4.2), in their order:
//
//  1. ErrTransition: crypt, org, vault, hall, group, labels and anchor equal
//     the predecessor's, seq is the predecessor's plus 1, and prev is the
//     txid of the predecessor's transaction;
//  2. ErrEpoch: the epoch never goes back; the same epoch keeps its epoch
//     id, and a later epoch has another;
//  3. ErrDebt: with a base of the predecessor's count when the transition
//     acknowledges a later epoch and of the predecessor's stale otherwise,
//     stale is the base less the secrets updated and retired while the base
//     is not zero, and zero while it is; nothing is created unless stale is
//     zero;
//  4. ErrCount: count is the predecessor's plus the secrets created less
//     those retired.
//
// Rule 3 is the property the application exists for: once a vault's chain
// acknowledges a new epoch, it admits nothing but the re-keying or the
// retirement of what it held until nothing is left under an earlier epoch.
func CheckVaultTransition(pred *Vault, predTxid [32]byte, next *Vault) error {
	if next.Crypt != pred.Crypt || !bytes.Equal(next.Org, pred.Org) || next.Vault != pred.Vault ||
		next.Hall != pred.Hall || next.Group != pred.Group || !sameLabels(next.Labels, pred.Labels) ||
		next.Anchor != pred.Anchor || next.Seq != pred.Seq+1 || next.Prev != predTxid {
		return ErrTransition
	}
	switch {
	case next.Epoch < pred.Epoch:
		return ErrEpoch
	case next.Epoch == pred.Epoch && next.EpochID != pred.EpochID:
		return ErrEpoch
	case next.Epoch > pred.Epoch && next.EpochID == pred.EpochID:
		return ErrEpoch
	}
	base := pred.Stale
	if Rekeys(pred, next) {
		base = pred.Count
	}
	cleared := uint64(len(next.Update) + len(next.Retire))
	switch {
	case base == 0 && next.Stale != 0:
		return ErrDebt
	case base != 0 && (cleared > base || next.Stale != base-cleared):
		return ErrDebt
	case next.Stale != 0 && len(next.Create) != 0:
		return ErrDebt
	}
	if uint64(len(next.Retire)) > pred.Count ||
		next.Count != pred.Count+uint64(len(next.Create))-uint64(len(next.Retire)) {
		return ErrCount
	}
	return nil
}

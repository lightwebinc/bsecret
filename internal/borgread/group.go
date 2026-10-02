package borgread

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"
	"unicode/utf8"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/lightwebinc/bcommon/cbor"
	"github.com/lightwebinc/bcommon/commit"
	"github.com/lightwebinc/bcommon/guard"
	"github.com/lightwebinc/bcommon/record"
)

// Group record keys.
const (
	gkHall         = 1
	gkOrg          = 2
	gkGroup        = 3
	gkSeq          = 4
	gkPrev         = 5
	gkName         = 6
	gkEpoch        = 7
	gkEpochSeq     = 8
	gkCommitment   = 9
	gkAdd          = 10
	gkRemove       = 11
	gkCount        = 12
	gkMembers      = 13
	gkRotateOnJoin = 14
	gkRotateEvery  = 15
	gkCreated      = 16
	gkLast         = gkCreated
)

// Group is one group record: the second field of a group chain token. A
// token that begins an epoch is that epoch's descriptor.
type Group struct {
	Hall         string
	Org          []byte
	Group        [GroupIDLen]byte
	Seq          uint64
	Prev         [32]byte
	Name         string
	Epoch        uint64
	EpochSeq     uint64   // seq of the token that began this epoch
	Commitment   [32]byte // BRC-369 digest of this epoch's key
	Add          [][]byte
	Remove       [][]byte
	Count        uint64
	Members      [32]byte
	RotateOnJoin bool
	RotateEvery  uint64
	Created      uint64
	Extra        cbor.Map
}

// BeginsEpoch reports whether this token began its epoch.
func (g *Group) BeginsEpoch() bool { return g.EpochSeq == g.Seq }

// EpochID is the identifier of an epoch: SHA-256 of the encoded group record
// of the token that began it.
func EpochID(groupRecord []byte) [32]byte { return sha256.Sum256(groupRecord) }

func checkIdentity(k []byte) error {
	if _, err := guard.ParsePubKey(k); err != nil {
		return ErrIdentity
	}
	return nil
}

// anyoneKey is BRC-43's anyone counterparty, the generator point.
func anyoneKey() []byte {
	one := make([]byte, 32)
	one[31] = 1
	k, _ := ec.PrivateKeyFromBytes(one)
	return k.PubKey().Compressed()
}

func isAnyone(k []byte) bool { return bytes.Equal(k, anyoneKey()) }

func checkOrgKey(k []byte) error {
	if checkIdentity(k) != nil || isAnyone(k) {
		return ErrIdentity
	}
	return nil
}

// CheckHall is borg's hall identifier grammar: a readable part of lowercase
// letters and single underscores, an underscore, and ten lowercase letters.
func CheckHall(s string) error {
	if len(s) < MinHall || len(s) > MaxHall {
		return ErrHall
	}
	cut := len(s) - SuffixLen - 1
	if s[cut] != '_' {
		return ErrHall
	}
	for i := cut + 1; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return ErrHall
		}
	}
	name := s[:cut]
	if len(name) == 0 || len(name) > MaxHallName {
		return ErrHall
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c == '_':
			if i == 0 || i == len(name)-1 || name[i-1] == '_' {
				return ErrHall
			}
		default:
			return ErrHall
		}
	}
	return nil
}

func listKeys(f *record.Fields, k uint64) ([][]byte, error) {
	a, err := f.Array(k, MaxDelta)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, len(a))
	for i, e := range a {
		b, ok := e.([]byte)
		if !ok {
			return nil, fmt.Errorf("%w: key %d", record.ErrList, k)
		}
		if err := checkIdentity(b); err != nil {
			return nil, err
		}
		out[i] = b
	}
	for i := 1; i < len(out); i++ {
		if bytes.Compare(out[i-1], out[i]) >= 0 {
			return nil, fmt.Errorf("%w: key %d", record.ErrList, k)
		}
	}
	return out, nil
}

func zero32(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// DecodeGroup parses a group record in borg's refusal order.
func DecodeGroup(p []byte) (*Group, error) {
	f, err := record.Decode(p, MaxGroupRecord, gkLast, MagicGroup)
	if err != nil {
		return nil, err
	}
	g := &Group{Extra: f.Extra}
	if g.Hall, err = f.Text(gkHall); err != nil {
		return nil, err
	}
	if err := CheckHall(g.Hall); err != nil {
		return nil, err
	}
	if g.Org, err = f.BytesN(gkOrg, -1); err != nil {
		return nil, err
	}
	if err := checkOrgKey(g.Org); err != nil {
		return nil, err
	}
	b, err := f.BytesN(gkGroup, GroupIDLen)
	if err != nil {
		return nil, err
	}
	copy(g.Group[:], b)
	if g.Seq, err = f.Uint(gkSeq, 0, MaxSafe); err != nil {
		return nil, err
	}
	if b, err = f.BytesN(gkPrev, 32); err != nil {
		return nil, err
	}
	copy(g.Prev[:], b)
	if g.Name, err = f.Text(gkName); err != nil {
		return nil, err
	}
	if len(g.Name) < 1 || len(g.Name) > MaxName || !utf8.ValidString(g.Name) {
		return nil, ErrName
	}
	if g.Epoch, err = f.Uint(gkEpoch, 0, MaxEpoch); err != nil {
		return nil, err
	}
	if g.EpochSeq, err = f.Uint(gkEpochSeq, 0, MaxSafe); err != nil {
		return nil, err
	}
	if b, err = f.BytesN(gkCommitment, 32); err != nil {
		return nil, err
	}
	copy(g.Commitment[:], b)
	if g.Add, err = listKeys(f, gkAdd); err != nil {
		return nil, err
	}
	if g.Remove, err = listKeys(f, gkRemove); err != nil {
		return nil, err
	}
	if g.Count, err = f.Uint(gkCount, 0, MaxMembers); err != nil {
		return nil, err
	}
	if b, err = f.BytesN(gkMembers, 32); err != nil {
		return nil, err
	}
	copy(g.Members[:], b)
	if g.RotateOnJoin, err = f.Bool(gkRotateOnJoin); err != nil {
		return nil, err
	}
	if g.RotateEvery, err = f.Uint(gkRotateEvery, 0, MaxEpoch); err != nil {
		return nil, err
	}
	if g.Created, err = f.Uint(gkCreated, 1, MaxTime); err != nil {
		return nil, err
	}
	return g, g.cross()
}

// cross is the rules across fields.
func (g *Group) cross() error {
	for _, a := range g.Add {
		for _, r := range g.Remove {
			if bytes.Equal(a, r) {
				return fmt.Errorf("%w: a member both added and removed", record.ErrList)
			}
		}
	}
	for _, a := range g.Add {
		if bytes.Equal(a, g.Org) || isAnyone(a) {
			return ErrMembers
		}
	}
	if (g.Seq == 0) != zero32(g.Prev[:]) {
		return fmt.Errorf("%w: prev is zero exactly at seq 0", ErrChain)
	}
	if g.EpochSeq > g.Seq {
		return fmt.Errorf("%w: epochSeq after seq", ErrChain)
	}
	if g.Seq == 0 && (g.Epoch != 0 || g.EpochSeq != 0) {
		return fmt.Errorf("%w: the first token begins epoch 0", ErrChain)
	}
	if g.Seq == 0 && (len(g.Remove) != 0 || g.Count != uint64(len(g.Add))) {
		return fmt.Errorf("%w: the first token adds its whole membership", ErrCount)
	}
	return nil
}

// CheckTransition is the rule a borg host admits a group token by, against
// the token it spends: the same hall, organisation and group at the next
// seq; a removal, or an addition while the predecessor asks for rotation on
// join, begins the next epoch with another commitment; no other transition
// changes the epoch's key; and the count follows the change lists.
func CheckTransition(prev *Group, prevTxid [32]byte, next *Group) error {
	if next.Seq == 0 {
		return fmt.Errorf("%w: seq 0 spends no token", ErrTransition)
	}
	if next.Hall != prev.Hall || !bytes.Equal(next.Org, prev.Org) || next.Group != prev.Group ||
		next.Seq != prev.Seq+1 || next.Prev != prevTxid {
		return fmt.Errorf("%w: not the successor of the token spent", ErrTransition)
	}
	mustRotate := len(next.Remove) > 0 || (prev.RotateOnJoin && len(next.Add) > 0)
	switch next.Epoch {
	case prev.Epoch:
		if mustRotate {
			return ErrRotation
		}
		if next.Commitment != prev.Commitment || next.EpochSeq != prev.EpochSeq {
			return fmt.Errorf("%w: the epoch's key changed without a new epoch", ErrRotation)
		}
	case prev.Epoch + 1:
		if next.Commitment == prev.Commitment {
			return fmt.Errorf("%w: a new epoch reuses the key", ErrRotation)
		}
		if next.EpochSeq != next.Seq {
			return fmt.Errorf("%w: a new epoch begins at this seq", ErrRotation)
		}
	default:
		return fmt.Errorf("%w: epoch skips", ErrTransition)
	}
	if prev.Count+uint64(len(next.Add)) < uint64(len(next.Remove)) ||
		prev.Count+uint64(len(next.Add))-uint64(len(next.Remove)) != next.Count {
		return ErrCount
	}
	return nil
}

// MembersRoot is the RFC 6962 root a group record commits its members to:
// the leaves are SHA-256 of each identity key, ascending by the keys' bytes.
func MembersRoot(keys [][]byte) [32]byte {
	sorted := make([][]byte, len(keys))
	copy(sorted, keys)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i], sorted[j]) < 0 })
	leaves := make([][32]byte, len(sorted))
	for i, k := range sorted {
		leaves[i] = sha256.Sum256(k)
	}
	return commit.Root(leaves)
}

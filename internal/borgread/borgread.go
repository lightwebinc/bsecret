// Package borgread reads what bsecret needs of borg's group contract: a group
// chain token and its record, the epoch each token begins and its id, the
// fold of a group's canonical chain into its epochs, and the wrap that
// releases an epoch's key to a member.
//
// Every rule here is borg's (borg docs/spec.md), not bsecret's: the group
// record's keys and bounds, the transition rules a borg host admits a token
// by, the members fold, and BRC-369 section 5.2's release in BRC-78
// serialization. The package is held to borg's own golden vectors under
// testdata, byte for byte, and nothing in bsecret's contract is defined
// here. It imports nothing else of bsecret, so that borg's own packages take
// its place without a change outside it.
//
// It reads only. A group's tokens and wraps are written by borg.
package borgread

import (
	"errors"

	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/lightwebinc/bcommon/keyed"
	"github.com/lightwebinc/bcommon/pushdrop"
	"github.com/lightwebinc/bcommon/record"
)

// borg's registry values, as bcommon's registry records them.
const (
	// ProtocolName is the BRC-43 protocol name of borg's public derivations,
	// at security level 1.
	ProtocolName = "borg organisation"
	// KeyGroup locks a group chain token and signs its fields.
	KeyGroup = "group"
	// ReleaseProtocolName is BRC-369 section 5.2's protocol for the release
	// of an epoch's key, at security level 2.
	ReleaseProtocolName = "keyed content release"
	// TopicPrefix is the prefix of a hall's topic.
	TopicPrefix = "tm_borg_"
)

var (
	// TagGroup is the first field of a group chain token.
	TagGroup = []byte{'b', 'o', 0x03}
	// MagicGroup is key 0 of a group record.
	MagicGroup = []byte{'b', 'o', 'g', 0x01}
	// MagicWrap is key 0 of a wrap record.
	MagicWrap = []byte{'b', 'o', 'w', 0x01}
	// WrapVersion is the BRC-78 version prefix borg writes and requires.
	WrapVersion = []byte{0x42, 0x42, 0x10, 0x33}

	// Protocol and GroupDerivation are the derivation a group token is
	// locked and signed under, counterparty anyone.
	Protocol        = wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: ProtocolName}
	GroupDerivation = pushdrop.Derivation{Protocol: Protocol, KeyID: KeyGroup}
	// ReleaseProtocol is the derivation protocol of a wrap.
	ReleaseProtocol = wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty, Protocol: ReleaseProtocolName}
)

// borg's bounds.
const (
	MaxSafe        = 1<<53 - 1
	MaxTime        = 253402300799
	MaxEpoch       = 1<<32 - 1
	SuffixLen      = 10
	MaxHall        = 50 - len(TopicPrefix)
	MaxHallName    = MaxHall - 1 - SuffixLen
	MinHall        = 1 + 1 + SuffixLen
	GroupIDLen     = 16
	MaxName        = 64
	MaxDelta       = 64
	MaxMembers     = 1024
	MaxEntries     = 16
	MaxGroupRecord = 8192
	MaxWrapRecord  = 4096
	// WrapLen is one wrap: version, sender, recipient, key id and the BRC-2
	// ciphertext of a 32-byte key.
	WrapLen = 4 + 33 + 33 + 32 + 80
)

// The refusals, with borg's labels (Reason).
var (
	ErrIdentity   = errors.New("borgread: identity key is not a canonical compressed key")
	ErrHall       = errors.New("borgread: hall identifier breaks the grammar")
	ErrName       = errors.New("borgread: name breaks its rule")
	ErrChain      = errors.New("borgread: seq, prev, epoch and epochSeq disagree")
	ErrMembers    = errors.New("borgread: the organisation or the anyone key is never a member")
	ErrCount      = errors.New("borgread: count or members disagree with the predecessor and the change lists")
	ErrTransition = errors.New("borgread: transition breaks the chain rules")
	ErrRotation   = errors.New("borgread: a removal without a new epoch, or an epoch whose key did not change")
	ErrEntry      = errors.New("borgread: wrap entry is not a release of this epoch's key by the organisation")
	ErrToken      = errors.New("borgread: not the well-formed group token that began this epoch")
	ErrReuse      = errors.New("borgread: an epoch begins with an earlier epoch's commitment")

	ErrScalar     = keyed.ErrScalar
	ErrCommitment = keyed.ErrCommitment
	ErrUnwrap     = keyed.ErrUnwrap
)

// Reason is borg's fixed label for a refusal.
func Reason(err error) string {
	for _, e := range []struct {
		err error
		s   string
	}{
		{ErrIdentity, "identity"}, {ErrHall, "hall"}, {ErrName, "name"}, {ErrChain, "chain"},
		{ErrMembers, "members"}, {ErrCount, "count"}, {ErrTransition, "transition"},
		{ErrRotation, "rotation"}, {ErrEntry, "entry"}, {ErrToken, "token"},
		{ErrReuse, "commitment-reuse"}, {ErrUnwrap, "undecryptable"}, {ErrScalar, "undecryptable"},
		{ErrCommitment, "commitment"},
	} {
		if errors.Is(err, e.err) {
			return e.s
		}
	}
	if s, ok := record.Reason(err); ok {
		return s
	}
	return "other"
}

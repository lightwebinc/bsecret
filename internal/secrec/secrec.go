// Package secrec is the byte-level contract of bsecret: the vault record that
// rides a mined chain token, the secret record that rides an unmined carrier,
// the payload a secret's ciphertext holds, the BRC-369 keyed content around
// it, the wrap of a content key under a group epoch's key and to the owner's
// own wallet, the crypt, label and name grammars, the vault fold, and the
// lookup question classes. docs/spec.md is the normative text; this package
// generates the golden vectors under testdata/vectors.
//
// Every record is canonical CBOR through bcommon's cbor package, so one value
// has one encoding a reader accepts. Every decoder bounds its input before the
// CBOR decoder runs, and the CBOR decoder bounds every declared length against
// the bytes present before it allocates.
//
// The content key, its commitment and BRC-2's symmetric form are bcommon's
// keyed package, and the record reader its record package (docs/spec.md
// section 16.1); keyed.go holds what only bsecret uses.
package secrec

import (
	"errors"

	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/lightwebinc/bcommon/keyed"
	"github.com/lightwebinc/bcommon/pushdrop"
	"github.com/lightwebinc/bcommon/record"
)

// Registry values (docs/frozen.md); frozen once the first record is
// published to a public host.
const (
	// ProtocolName is the BRC-43 protocol name of every public derivation,
	// at security level 1.
	ProtocolName = "bsecret"
	// SelfProtocolName is the BRC-43 protocol name of the self wrap, at
	// security level 2 with counterparty self.
	SelfProtocolName = "bsecret self"
	// KeyVault locks a vault chain token and signs its fields.
	KeyVault = "vault"
	// KeySecret locks a secret carrier's record output, signs its field, and
	// locks the outputs of the trees that fund secrets.
	KeySecret = "secret"
	// KeyChain locks the outputs of the trees that pay for a vault's first
	// token; no carrier is ever funded under it.
	KeyChain = "chain"
	// KeyFund is the embedded wallet's funding key.
	KeyFund = "fund"

	// TopicPrefix and LookupService are the overlay names (BRC-87).
	TopicPrefix   = "tm_bsecret_"
	LookupService = "ls_bsecret"

	// DomainSymmetric and DomainCommitment are BRC-369 section 2's domain
	// strings, adopted verbatim.
	DomainSymmetric  = keyed.DomainSymmetric
	DomainCommitment = keyed.DomainCommitment
	// DomainVaultID, DomainSecretID and DomainEpochWrap are bsecret's own
	// domain strings: each is hashed into an identifier or a key.
	DomainVaultID   = "bsecret vault id v1"
	DomainSecretID  = "bsecret secret id v1"
	DomainEpochWrap = "bsecret epoch wrap v1"
)

// Tags and magics. The tag prefix "se" belongs to bsecret.
var (
	TagPrefix = []byte("se")
	// TagVault is the first field of a vault chain token.
	TagVault = []byte{'s', 'e', 0x01}
	// TagFunding is the one field of a funding-tree output.
	TagFunding = []byte{'s', 'e', 0x02}
	// MagicVault is key 0 of a vault record: "se", 'v', version 1.
	MagicVault = []byte{'s', 'e', 'v', 0x01}
	// MagicSecret is key 0 of a secret record: "se", 's', version 1.
	MagicSecret = []byte{'s', 'e', 's', 0x01}
	// MagicPayload is key 0 of a payload, the plaintext a secret's
	// ciphertext holds: "se", 'p', version 1.
	MagicPayload = []byte{'s', 'e', 'p', 0x01}
)

// Derivations under [1, "bsecret"], each with counterparty anyone, so a
// reader derives the key from the identity key alone.
var (
	Protocol         = wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryApp, Protocol: ProtocolName}
	VaultDerivation  = pushdrop.Derivation{Protocol: Protocol, KeyID: KeyVault}
	SecretDerivation = pushdrop.Derivation{Protocol: Protocol, KeyID: KeySecret}
	ChainDerivation  = pushdrop.Derivation{Protocol: Protocol, KeyID: KeyChain}
	FundDerivation   = pushdrop.Derivation{Protocol: Protocol, KeyID: KeyFund}

	// SelfProtocol is the self wrap's derivation protocol.
	SelfProtocol = wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty, Protocol: SelfProtocolName}
)

// Bounds. A reader accepts every record within them; a later version may
// raise a bound but never lower it (docs/frozen.md).
const (
	// MaxSafe is 2^53 - 1.
	MaxSafe = 1<<53 - 1
	// MaxTime is 9999-12-31T23:59:59Z, the last second RFC 3339 can write.
	MaxTime = 253402300799
	// MaxEpoch is the largest epoch: BRC-369 section 5.2 writes the epoch as
	// four bytes.
	MaxEpoch = 1<<32 - 1
	// SuffixLen is the length of a crypt's random suffix.
	SuffixLen = 10
	// MaxCrypt is the longest crypt identifier: BRC-87 caps a name at 50
	// characters and the topic prefix takes 11.
	MaxCrypt = 50 - len(TopicPrefix)
	// MaxCryptName is the longest readable part of a crypt identifier.
	MaxCryptName = MaxCrypt - 1 - SuffixLen
	// MinCrypt is the shortest crypt identifier.
	MinCrypt = 1 + 1 + SuffixLen
	// MinHall and MaxHall bound the identifier of the hall the vault's
	// group lives in, as the group's own contract bounds it.
	MinHall = 12
	MaxHall = 42
	// GroupIDLen is the length of a group identifier.
	GroupIDLen = 16
	// MaxName bounds a vault's display name, in bytes.
	MaxName = 64
	// MaxSecretName bounds a secret's name, in bytes.
	MaxSecretName = 128
	// MaxLabels bounds a vault's label set; MaxLabel one label, in bytes.
	MaxLabels = 16
	MaxLabel  = 32
	// MaxDelta bounds each change list of one transition: secrets created,
	// updated or retired.
	MaxDelta = 64
	// MaxSecrets bounds the secrets a vault holds at once.
	MaxSecrets = 4096
	// MaxVaultRecord bounds an encoded vault record: 64 created and 64
	// updated entries and 64 retired identifiers take about 17 KiB.
	MaxVaultRecord = 20480
	// MaxInline bounds a ciphertext carried inside its secret record.
	MaxInline = 16384
	// MaxSecretRecord bounds an encoded secret record: the inline bound and
	// room for every other key.
	MaxSecretRecord = MaxInline + 1024
	// MaxLength bounds the ciphertext a secret record describes when it is
	// not carried inline: 2^27 bytes, the most a payload of MaxPayload bytes
	// produces at the smallest segment.
	MaxLength = 1 << 27
	// MinSegment and MaxSegment bound the plaintext bytes of one AES-256-GCM
	// segment (BRC-369 section 2.3).
	MinSegment = 16
	MaxSegment = 1 << 20
	// TagLen is the length of one segment's authentication tag.
	TagLen = 16
	// SaltLen is the length of the per-content salt (BRC-369 section 2.3).
	SaltLen = 4
	// WrapLen is the exact length of a wrapped content key: a 32-byte
	// scalar under BRC-2's symmetric form (32 + 32 + 16).
	WrapLen = 80
	// MaxKeys bounds the entries of a record map, unknown keys included.
	MaxKeys = 64
	// MaxType bounds a payload's media type, in bytes.
	MaxType = 128
	// MaxPayload bounds an encoded payload: a record whose length is one
	// that a larger plaintext produces is refused, so every admitted record
	// describes a ciphertext a conforming reader can open.
	MaxPayload = 1 << 26
)

// Anchor modes of a vault (docs/spec.md section 4.4), fixed at its first
// token.
const (
	// AnchorVersion: a reader takes only versions a mined token lists.
	AnchorVersion = 0
	// AnchorInterval: a reader may also take a version no token lists yet,
	// marked unanchored.
	AnchorInterval = 1
)

// DefaultLabels is the label set a vault gets unless its owner chooses
// another at creation.
var DefaultLabels = []string{"confidential", "internal", "public", "restricted"}

// The refusals. A host counts them by Reason.
var (
	ErrTooLarge   = record.ErrTooLarge
	ErrCBOR       = record.ErrCBOR
	ErrKeyType    = record.ErrKeyType
	ErrMagic      = record.ErrMagic
	ErrMissing    = record.ErrMissing
	ErrType       = record.ErrType
	ErrRange      = record.ErrRange
	ErrIdentity   = errors.New("secrec: identity key is not a canonical compressed key")
	ErrCrypt      = errors.New("secrec: crypt identifier breaks the grammar")
	ErrHall       = errors.New("secrec: hall identifier breaks the grammar")
	ErrName       = errors.New("secrec: name breaks its rule")
	ErrLabel      = errors.New("secrec: label breaks the grammar or the label set its rule")
	ErrList       = record.ErrList
	ErrEntry      = errors.New("secrec: change entry is not [id, version, content id, commitment]")
	ErrChain      = errors.New("secrec: seq, prev, version and previous disagree")
	ErrCount      = errors.New("secrec: count disagrees with the predecessor and the change lists")
	ErrDebt       = errors.New("secrec: stale count disagrees with the predecessor and the change lists, or a secret is created while one is stale")
	ErrContent    = errors.New("secrec: inline ciphertext does not match its length and hash")
	ErrTransition = errors.New("secrec: transition breaks the chain rules")
	ErrEpoch      = errors.New("secrec: epoch goes back, or epoch and epoch id disagree with the predecessor")
	ErrQuery      = errors.New("secrec: question is not one of the defined classes")

	// A reader's check labels (docs/spec.md section 7.2), never a host's.
	ErrListing    = errors.New("secrec: the token does not list this record as it is")
	ErrSuccessor  = errors.New("secrec: the record is not the next version of the one before it")
	ErrHash       = errors.New("secrec: ciphertext is not the one the record names")
	ErrUnwrap     = keyed.ErrUnwrap
	ErrScalar     = keyed.ErrScalar
	ErrCommitment = keyed.ErrCommitment
	ErrTag        = errors.New("secrec: a segment's authentication tag does not verify under the committed key")
	ErrPayload    = errors.New("secrec: plaintext is not a payload for this secret")
)

// Reason is the fixed label a host counts a refusal by, and a reader names a
// failed check by.
func Reason(err error) string {
	for _, e := range []struct {
		err error
		s   string
	}{
		{ErrTooLarge, "too-large"}, {ErrCBOR, "cbor"}, {ErrKeyType, "key-type"},
		{ErrMagic, "magic"}, {ErrMissing, "missing"}, {ErrType, "type"},
		{ErrRange, "range"}, {ErrIdentity, "identity"}, {ErrCrypt, "crypt"},
		{ErrHall, "hall"}, {ErrName, "name"}, {ErrLabel, "label"}, {ErrList, "list"},
		{ErrEntry, "entry"}, {ErrChain, "chain"}, {ErrCount, "count"}, {ErrDebt, "debt"},
		{ErrContent, "content"}, {ErrTransition, "transition"}, {ErrEpoch, "epoch"},
		{ErrQuery, "query"}, {ErrListing, "listing"}, {ErrSuccessor, "successor"}, {ErrHash, "hash"}, {ErrUnwrap, "undecryptable"},
		{ErrScalar, "undecryptable"}, {ErrCommitment, "commitment"}, {ErrTag, "tag"},
		{ErrPayload, "payload"},
	} {
		if errors.Is(err, e.err) {
			return e.s
		}
	}
	return "other"
}

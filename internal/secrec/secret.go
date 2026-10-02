package secrec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"unicode/utf8"

	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/lightwebinc/bcommon/cbor"
	"github.com/lightwebinc/bcommon/record"
)

// Secret record keys.
const (
	SKMagic      = 0
	SKCrypt      = 1
	SKOrg        = 2
	SKVault      = 3
	SKID         = 4
	SKVersion    = 5
	SKPrevious   = 6
	SKLabel      = 7
	SKGroup      = 8
	SKEpoch      = 9
	SKEpochID    = 10
	SKCommitment = 11
	SKHash       = 12
	SKLength     = 13
	SKSalt       = 14
	SKSegment    = 15
	SKCreated    = 16
	SKSelf       = 17
	SKWrap       = 18
	SKInline     = 19
	skLast       = SKInline
)

// Secret is one secret record: the payload of one secret carrier's output.
// It is one version of one secret: the BRC-369 description of its
// ciphertext, the content key wrapped to the owner and to the members of one
// epoch of the vault's group, and, when it is small, the ciphertext itself.
type Secret struct {
	Crypt      string           // key 1
	Org        []byte           // key 2, the owner, and the carrier's owner
	Vault      [32]byte         // key 3
	ID         [32]byte         // key 4, SecretID(vault, name)
	Version    uint64           // key 5, 1 for the first version
	Previous   [32]byte         // key 6, content id of version - 1; zero at version 1
	Label      string           // key 7, one of the vault's labels
	Group      [GroupIDLen]byte // key 8, the group whose epoch key wraps the content key
	Epoch      uint64           // key 9
	EpochID    [32]byte         // key 10
	Commitment [32]byte         // key 11, BRC-369 digest of the content key
	Hash       [32]byte         // key 12, SHA-256 of the complete ciphertext
	Length     uint64           // key 13, bytes of the complete ciphertext
	Salt       [SaltLen]byte    // key 14
	Segment    uint64           // key 15, plaintext bytes per segment
	Created    uint64           // key 16, Unix seconds, a claim
	Self       []byte           // key 17, the content key wrapped to the owner's wallet
	Wrap       []byte           // key 18, the content key wrapped under the epoch
	Inline     []byte           // key 19, optional: the ciphertext
	Extra      cbor.Map         // integer keys above 19, preserved and ignored
}

// checkContent is the rule of keys 13 and 19: a length some plaintext
// produces, within the bound of where the ciphertext lives, and an inline
// ciphertext of exactly that length that hashes to key 12.
func (s *Secret) checkContent() error {
	n, err := PlainLength(s.Length, s.Segment)
	if err != nil {
		return err
	}
	if n > MaxPayload {
		return fmt.Errorf("%w: a payload above the bound", ErrRange)
	}
	if s.Inline == nil {
		if s.Length > MaxLength {
			return fmt.Errorf("%w: length", ErrRange)
		}
		return nil
	}
	if len(s.Inline) == 0 || s.Length > MaxInline {
		return fmt.Errorf("%w: inline length", ErrRange)
	}
	if uint64(len(s.Inline)) != s.Length || sha256.Sum256(s.Inline) != s.Hash {
		return ErrContent
	}
	return nil
}

// Validate applies every rule that needs only the record itself.
func (s *Secret) Validate() error {
	if err := record.CheckExtra(s.Extra, skLast, skLast+1); err != nil {
		return err
	}
	if err := CheckCrypt(s.Crypt); err != nil {
		return err
	}
	if err := CheckOrgKey(s.Org); err != nil {
		return err
	}
	if err := record.InRange(s.Version, 1, MaxSafe, "version"); err != nil {
		return err
	}
	if err := CheckLabel(s.Label); err != nil {
		return err
	}
	if err := record.InRange(s.Epoch, 0, MaxEpoch, "epoch"); err != nil {
		return err
	}
	if err := record.InRange(s.Length, 1, MaxLength, "length"); err != nil {
		return err
	}
	if err := CheckSegment(s.Segment); err != nil {
		return err
	}
	if err := record.InRange(s.Created, 1, MaxTime, "created"); err != nil {
		return err
	}
	if len(s.Self) != WrapLen || len(s.Wrap) != WrapLen {
		return fmt.Errorf("%w: wrap", ErrRange)
	}
	return s.cross()
}

// cross is refusal step 7: the rules across fields.
func (s *Secret) cross() error {
	if (s.Version == 1) != zero32(s.Previous[:]) {
		return ErrChain
	}
	return s.checkContent()
}

// described is the record's map without the wraps and the inline
// ciphertext: what the content id hashes.
func (s *Secret) described() cbor.Map {
	return cbor.Map{
		{Key: uint64(SKMagic), Val: MagicSecret},
		{Key: uint64(SKCrypt), Val: s.Crypt},
		{Key: uint64(SKOrg), Val: s.Org},
		{Key: uint64(SKVault), Val: append([]byte(nil), s.Vault[:]...)},
		{Key: uint64(SKID), Val: append([]byte(nil), s.ID[:]...)},
		{Key: uint64(SKVersion), Val: s.Version},
		{Key: uint64(SKPrevious), Val: append([]byte(nil), s.Previous[:]...)},
		{Key: uint64(SKLabel), Val: s.Label},
		{Key: uint64(SKGroup), Val: append([]byte(nil), s.Group[:]...)},
		{Key: uint64(SKEpoch), Val: s.Epoch},
		{Key: uint64(SKEpochID), Val: append([]byte(nil), s.EpochID[:]...)},
		{Key: uint64(SKCommitment), Val: append([]byte(nil), s.Commitment[:]...)},
		{Key: uint64(SKHash), Val: append([]byte(nil), s.Hash[:]...)},
		{Key: uint64(SKLength), Val: s.Length},
		{Key: uint64(SKSalt), Val: append([]byte(nil), s.Salt[:]...)},
		{Key: uint64(SKSegment), Val: s.Segment},
		{Key: uint64(SKCreated), Val: s.Created},
	}
}

// ContentID is the identifier of one version: SHA-256 of the record's
// canonical encoding with keys 17 (self), 18 (wrap) and 19 (inline) left
// out and every other key, unknown ones included, kept. It takes the place
// of BRC-369 section 4.2 rule 3's content id: it is fixed before any key is
// wrapped, both wraps are bound to it, and a vault token lists it.
func (s *Secret) ContentID() ([32]byte, error) {
	if err := record.CheckExtra(s.Extra, skLast, skLast+1); err != nil {
		return [32]byte{}, err
	}
	b, err := cbor.Encode(append(s.described(), s.Extra...))
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrCBOR, err)
	}
	return sha256.Sum256(b), nil
}

// Encode writes the secret record in canonical CBOR.
func (s *Secret) Encode() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	m := s.described()
	m = append(m,
		cbor.Pair{Key: uint64(SKSelf), Val: append([]byte(nil), s.Self...)},
		cbor.Pair{Key: uint64(SKWrap), Val: append([]byte(nil), s.Wrap...)})
	if s.Inline != nil {
		m = append(m, cbor.Pair{Key: uint64(SKInline), Val: append([]byte(nil), s.Inline...)})
	}
	return record.Encode(m, s.Extra, MaxSecretRecord)
}

// DecodeSecret parses a secret record in the refusal order (docs/spec.md
// section 3.1).
func DecodeSecret(p []byte) (*Secret, error) {
	f, err := decodeRecord(p, MaxSecretRecord, skLast, MagicSecret)
	if err != nil {
		return nil, err
	}
	s := &Secret{Extra: f.Extra}
	if s.Crypt, err = f.Text(SKCrypt); err != nil {
		return nil, err
	}
	if err := CheckCrypt(s.Crypt); err != nil {
		return nil, err
	}
	if s.Org, err = f.BytesN(SKOrg, -1); err != nil {
		return nil, err
	}
	if err := CheckOrgKey(s.Org); err != nil {
		return nil, err
	}
	b, err := f.BytesN(SKVault, 32)
	if err != nil {
		return nil, err
	}
	copy(s.Vault[:], b)
	if b, err = f.BytesN(SKID, 32); err != nil {
		return nil, err
	}
	copy(s.ID[:], b)
	if s.Version, err = f.Uint(SKVersion, 1, MaxSafe); err != nil {
		return nil, err
	}
	if b, err = f.BytesN(SKPrevious, 32); err != nil {
		return nil, err
	}
	copy(s.Previous[:], b)
	if s.Label, err = f.Text(SKLabel); err != nil {
		return nil, err
	}
	if err := CheckLabel(s.Label); err != nil {
		return nil, err
	}
	if b, err = f.BytesN(SKGroup, GroupIDLen); err != nil {
		return nil, err
	}
	copy(s.Group[:], b)
	if s.Epoch, err = f.Uint(SKEpoch, 0, MaxEpoch); err != nil {
		return nil, err
	}
	if b, err = f.BytesN(SKEpochID, 32); err != nil {
		return nil, err
	}
	copy(s.EpochID[:], b)
	if b, err = f.BytesN(SKCommitment, 32); err != nil {
		return nil, err
	}
	copy(s.Commitment[:], b)
	if b, err = f.BytesN(SKHash, 32); err != nil {
		return nil, err
	}
	copy(s.Hash[:], b)
	if s.Length, err = f.Uint(SKLength, 1, MaxLength); err != nil {
		return nil, err
	}
	if b, err = f.BytesN(SKSalt, SaltLen); err != nil {
		return nil, err
	}
	copy(s.Salt[:], b)
	if s.Segment, err = f.Uint(SKSegment, MinSegment, MaxSegment); err != nil {
		return nil, err
	}
	if s.Created, err = f.Uint(SKCreated, 1, MaxTime); err != nil {
		return nil, err
	}
	if s.Self, err = f.BytesN(SKSelf, WrapLen); err != nil {
		return nil, err
	}
	if s.Wrap, err = f.BytesN(SKWrap, WrapLen); err != nil {
		return nil, err
	}
	if v, ok := f.Get(SKInline); ok {
		in, ok := v.([]byte)
		if !ok {
			return nil, fmt.Errorf("%w: key %d", ErrType, SKInline)
		}
		if len(in) < 1 || len(in) > MaxInline {
			return nil, fmt.Errorf("%w: key %d", ErrRange, SKInline)
		}
		s.Inline = in
	}
	if err := s.cross(); err != nil {
		return nil, err
	}
	return s, nil
}

// Payload keys.
const (
	PKMagic       = 0
	PKName        = 1
	PKValue       = 2
	PKType        = 3
	PKNotAfter    = 4
	PKRotateEvery = 5
	PKPad         = 6
	pkLast        = PKPad
)

// Payload is the plaintext a secret's ciphertext holds: the secret's name,
// its value, and what its owner says about the value. Nothing in it is
// visible to a host.
type Payload struct {
	Name        string   // key 1, the name the secret's id hashes
	Value       []byte   // key 2, the secret itself
	Type        string   // key 3, optional: a media type
	NotAfter    uint64   // key 4, optional: when the value stops being usable, Unix seconds
	RotateEvery uint64   // key 5, optional: seconds between the rotations its owner intends
	Pad         []byte   // key 6, optional: padding, ignored
	Extra       cbor.Map // integer keys above 6, preserved and ignored
}

// Encode writes the payload in canonical CBOR.
func (p *Payload) Encode() ([]byte, error) {
	if err := record.CheckExtra(p.Extra, pkLast, pkLast+1); err != nil {
		return nil, err
	}
	if err := CheckSecretName(p.Name); err != nil {
		return nil, err
	}
	if len(p.Type) > MaxType || !utf8.ValidString(p.Type) || p.NotAfter > MaxTime || p.RotateEvery > MaxEpoch {
		return nil, ErrRange
	}
	val := p.Value
	if val == nil {
		val = []byte{}
	}
	m := cbor.Map{
		{Key: uint64(PKMagic), Val: MagicPayload},
		{Key: uint64(PKName), Val: p.Name},
		{Key: uint64(PKValue), Val: val},
	}
	if p.Type != "" {
		m = append(m, cbor.Pair{Key: uint64(PKType), Val: p.Type})
	}
	if p.NotAfter != 0 {
		m = append(m, cbor.Pair{Key: uint64(PKNotAfter), Val: p.NotAfter})
	}
	if p.RotateEvery != 0 {
		m = append(m, cbor.Pair{Key: uint64(PKRotateEvery), Val: p.RotateEvery})
	}
	if len(p.Pad) != 0 {
		m = append(m, cbor.Pair{Key: uint64(PKPad), Val: p.Pad})
	}
	return record.Encode(m, p.Extra, MaxPayload)
}

// DecodePayload parses a payload. A reader calls it only on plaintext whose
// every segment tag verified.
func DecodePayload(b []byte) (*Payload, error) {
	f, err := decodeRecord(b, MaxPayload, pkLast, MagicPayload)
	if err != nil {
		return nil, err
	}
	p := &Payload{Extra: f.Extra}
	if p.Name, err = f.Text(PKName); err != nil {
		return nil, err
	}
	if err := CheckSecretName(p.Name); err != nil {
		return nil, err
	}
	if p.Value, err = f.BytesN(PKValue, -1); err != nil {
		return nil, err
	}
	if _, ok := f.Get(PKType); ok {
		if p.Type, err = f.Text(PKType); err != nil {
			return nil, err
		}
		if len(p.Type) < 1 || len(p.Type) > MaxType || !utf8.ValidString(p.Type) {
			return nil, fmt.Errorf("%w: key %d", ErrRange, PKType)
		}
	}
	if _, ok := f.Get(PKNotAfter); ok {
		if p.NotAfter, err = f.Uint(PKNotAfter, 1, MaxTime); err != nil {
			return nil, err
		}
	}
	if _, ok := f.Get(PKRotateEvery); ok {
		if p.RotateEvery, err = f.Uint(PKRotateEvery, 1, MaxEpoch); err != nil {
			return nil, err
		}
	}
	if _, ok := f.Get(PKPad); ok {
		if p.Pad, err = f.BytesN(PKPad, -1); err != nil {
			return nil, err
		}
		if len(p.Pad) == 0 {
			return nil, fmt.Errorf("%w: key %d", ErrRange, PKPad)
		}
	}
	return p, nil
}

// EncodePadded writes the payload padded to a multiple of block bytes: it
// leaves an encoding that is already a multiple alone, and otherwise sets
// Pad to the fewest zero bytes that reach one, re-encoding to find it (the
// padding key's own head and the map's head both grow with what they hold).
func (p *Payload) EncodePadded(block int) ([]byte, error) {
	p.Pad = nil
	b, err := p.Encode()
	if err != nil || block <= 1 || len(b)%block == 0 {
		return b, err
	}
	for pad := 1; pad <= 2*block; pad++ {
		p.Pad = make([]byte, pad)
		if b, err = p.Encode(); err != nil {
			return nil, err
		}
		if len(b)%block == 0 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("%w: no padding reaches a multiple of %d", ErrRange, block)
}

// CheckCiphertext is a reader's check 1 (docs/spec.md section 7.2): the
// ciphertext is exactly the record's length and hashes to the record's hash.
// It needs no key and comes before any wrap is opened.
func CheckCiphertext(s *Secret, ciphertext []byte) error {
	if uint64(len(ciphertext)) != s.Length || sha256.Sum256(ciphertext) != s.Hash {
		return ErrHash
	}
	return nil
}

// ReadAsMember is a member's read of one version, the checks of
// docs/spec.md section 7.2 from 1 on, in their order: the ciphertext's
// length and hash; the wrap, opened with the symmetric key of the epoch the
// record names and no other; the scalar and the commitment; every segment's
// tag; the payload and its name. The caller made check 0 and verified the
// epoch's key against the group's commitment.
func ReadAsMember(s *Secret, ciphertext []byte, epochSymmetric [32]byte) (*Payload, error) {
	if err := CheckCiphertext(s, ciphertext); err != nil {
		return nil, err
	}
	cid, err := s.ContentID()
	if err != nil {
		return nil, err
	}
	k, err := UnwrapFromEpoch(epochSymmetric, cid, s.Wrap, s.Commitment)
	if err != nil {
		return nil, err
	}
	return OpenSecret(s, ciphertext, k)
}

// ReadAsOwner is the owner's read of one version through its self wrap, in
// the same order as ReadAsMember.
func ReadAsOwner(ctx context.Context, w wallet.Interface, s *Secret, ciphertext []byte) (*Payload, error) {
	if err := CheckCiphertext(s, ciphertext); err != nil {
		return nil, err
	}
	cid, err := s.ContentID()
	if err != nil {
		return nil, err
	}
	k, err := UnwrapFromSelf(ctx, w, cid, s.Self, s.Commitment)
	if err != nil {
		return nil, err
	}
	return OpenSecret(s, ciphertext, k)
}

// OpenSecret is the checks on one version for a caller that already holds a
// candidate content key (docs/spec.md section 7.2): BRC-369 section 5.3's
// three checks in their order, then the payload, whose name must hash to the
// record's id. A reader that starts from a wrap uses ReadAsMember or
// ReadAsOwner, which check the ciphertext before they open the wrap.
// ciphertext is the record's inline ciphertext, or the bytes fetched for a
// record that carries none.
func OpenSecret(s *Secret, ciphertext []byte, k [32]byte) (*Payload, error) {
	pt, err := Checks(ciphertext, s.Hash, s.Length, k, s.Commitment, s.Salt, s.Segment)
	if err != nil {
		return nil, err
	}
	p, err := DecodePayload(pt)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPayload, err)
	}
	id, err := SecretID(s.Vault, p.Name)
	if err != nil || !bytes.Equal(id[:], s.ID[:]) {
		return nil, fmt.Errorf("%w: the name does not hash to the record's id", ErrPayload)
	}
	return p, nil
}

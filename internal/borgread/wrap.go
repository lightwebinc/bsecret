package borgread

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/lightwebinc/bcommon/cbor"
	"github.com/lightwebinc/bcommon/keyed"
	"github.com/lightwebinc/bcommon/record"
)

// Wrap record keys.
const (
	wkHall    = 1
	wkOrg     = 2
	wkGroup   = 3
	wkEpoch   = 4
	wkEpochID = 5
	wkEntries = 6
	wkLast    = wkEntries
)

// WrapRecord is one wrap record, the payload of a borg wrap carrier: one
// epoch's key released to up to MaxEntries members.
type WrapRecord struct {
	Hall    string
	Org     []byte
	Group   [GroupIDLen]byte
	Epoch   uint64
	EpochID [32]byte
	Entries [][]byte // WrapLen bytes each, ascending by recipient
	Extra   cbor.Map
}

// ReleaseKeyID is BRC-369 section 5.2's key id bytes:
// SHA-256(epoch id || epoch as four bytes big-endian).
func ReleaseKeyID(epochID [32]byte, epoch uint32) [32]byte {
	var e [4]byte
	binary.BigEndian.PutUint32(e[:], epoch)
	return sha256.Sum256(append(epochID[:], e[:]...))
}

func releaseArgs(epochID [32]byte, epoch uint32, counterparty *ec.PublicKey) wallet.EncryptionArgs {
	id := ReleaseKeyID(epochID, epoch)
	return wallet.EncryptionArgs{
		ProtocolID:   ReleaseProtocol,
		KeyID:        base64.StdEncoding.EncodeToString(id[:]),
		Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: counterparty},
	}
}

// Entry is a parsed wrap: the BRC-78 header and the ciphertext.
type Entry struct {
	Sender     []byte
	Recipient  []byte
	KeyID      [32]byte
	Ciphertext []byte
}

// CheckEntry is borg's rule for one wrap of a wrap record: exactly WrapLen
// bytes, the version, the organisation as sender, a canonical recipient
// that is neither the organisation nor the anyone key, and the key id
// BRC-369 derives for the record's epoch.
func CheckEntry(b, org []byte, epochID [32]byte, epoch uint32) (*Entry, error) {
	if len(b) != WrapLen || !bytes.Equal(b[:4], WrapVersion) {
		return nil, ErrEntry
	}
	e := &Entry{Sender: b[4:37], Recipient: b[37:70], Ciphertext: b[102:]}
	copy(e.KeyID[:], b[70:102])
	if !bytes.Equal(e.Sender, org) {
		return nil, fmt.Errorf("%w: sender is not the organisation", ErrEntry)
	}
	if checkIdentity(e.Recipient) != nil || bytes.Equal(e.Recipient, org) || isAnyone(e.Recipient) {
		return nil, fmt.Errorf("%w: recipient", ErrEntry)
	}
	if e.KeyID != ReleaseKeyID(epochID, epoch) {
		return nil, fmt.Errorf("%w: key id", ErrEntry)
	}
	return e, nil
}

// DecodeWrap parses a wrap record in borg's refusal order.
func DecodeWrap(p []byte) (*WrapRecord, error) {
	f, err := record.Decode(p, MaxWrapRecord, wkLast, MagicWrap)
	if err != nil {
		return nil, err
	}
	w := &WrapRecord{Extra: f.Extra}
	if w.Hall, err = f.Text(wkHall); err != nil {
		return nil, err
	}
	if err := CheckHall(w.Hall); err != nil {
		return nil, err
	}
	if w.Org, err = f.BytesN(wkOrg, -1); err != nil {
		return nil, err
	}
	if err := checkOrgKey(w.Org); err != nil {
		return nil, err
	}
	b, err := f.BytesN(wkGroup, GroupIDLen)
	if err != nil {
		return nil, err
	}
	copy(w.Group[:], b)
	if w.Epoch, err = f.Uint(wkEpoch, 0, MaxEpoch); err != nil {
		return nil, err
	}
	if b, err = f.BytesN(wkEpochID, 32); err != nil {
		return nil, err
	}
	copy(w.EpochID[:], b)
	a, err := f.Array(wkEntries, MaxEntries)
	if err != nil {
		return nil, err
	}
	if len(a) < 1 {
		return nil, fmt.Errorf("%w: entries", record.ErrList)
	}
	var last []byte
	for _, e := range a {
		eb, ok := e.([]byte)
		if !ok {
			return nil, fmt.Errorf("%w: entry", ErrEntry)
		}
		ent, err := CheckEntry(eb, w.Org, w.EpochID, uint32(w.Epoch))
		if err != nil {
			return nil, err
		}
		if last != nil && bytes.Compare(last, ent.Recipient) >= 0 {
			return nil, fmt.Errorf("%w: recipients not ascending", ErrEntry)
		}
		last = ent.Recipient
		w.Entries = append(w.Entries, eb)
	}
	return w, nil
}

// CheckEpochToken is a member's first check: the group record of the token
// that began the wrap's epoch hashes to the wrap's epoch id and names the
// same hall, organisation, group and epoch. The token's proof against the
// member's headers is the caller's.
func CheckEpochToken(groupRecord []byte, w *WrapRecord) (*Group, error) {
	g, err := DecodeGroup(groupRecord)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrToken, err)
	}
	if EpochID(groupRecord) != w.EpochID || !g.BeginsEpoch() || g.Epoch != w.Epoch ||
		g.Hall != w.Hall || !bytes.Equal(g.Org, w.Org) || g.Group != w.Group {
		return nil, ErrToken
	}
	return g, nil
}

// Unwrap is the member's side of BRC-369 sections 5.2 and 5.3: its own
// wallet decrypts its wrap (counterparty the organisation), a value that is
// not a scalar is refused, and the key is checked against the epoch's
// commitment before anything uses it.
func Unwrap(ctx context.Context, w wallet.Interface, wrap []byte, org *ec.PublicKey, epochID [32]byte, epoch uint32, commitment [32]byte) ([32]byte, error) {
	e, err := CheckEntry(wrap, org.Compressed(), epochID, epoch)
	if err != nil {
		return [32]byte{}, err
	}
	res, err := w.Decrypt(ctx, wallet.DecryptArgs{EncryptionArgs: releaseArgs(epochID, epoch, org), Ciphertext: e.Ciphertext}, "")
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	return keyed.CheckOpened(res.Plaintext, commitment)
}

// Open is a member's whole read of one epoch's key: the wrap record against
// the token that began the epoch (CheckEpochToken), then the member's own
// entry opened and held to the token's commitment (Unwrap). It returns the
// epoch's key; its BRC-369 symmetric key is keyed.SymmetricKey of it.
func Open(ctx context.Context, w wallet.Interface, me []byte, groupRecord []byte, wr *WrapRecord) ([32]byte, error) {
	g, err := CheckEpochToken(groupRecord, wr)
	if err != nil {
		return [32]byte{}, err
	}
	org, err := ec.PublicKeyFromBytes(wr.Org)
	if err != nil {
		return [32]byte{}, ErrIdentity
	}
	for _, e := range wr.Entries {
		if bytes.Equal(e[37:70], me) {
			return Unwrap(ctx, w, e, org, wr.EpochID, uint32(wr.Epoch), g.Commitment)
		}
	}
	return [32]byte{}, fmt.Errorf("%w: no entry for this member", ErrUnwrap)
}

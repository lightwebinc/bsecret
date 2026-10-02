package secrec

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/lightwebinc/bcommon/keyed"
)

// EpochWrapKey is the key a content key is wrapped under for the members of
// one epoch: SHA-256 of the domain string, the epoch's BRC-369 symmetric key
// and the content id of the secret version. It is derived from the epoch's
// symmetric key, never used as it: one wrapping key wraps one content key,
// and no other application's use of the epoch key meets it.
func EpochWrapKey(epochSymmetric, contentID [32]byte) [32]byte {
	b := append([]byte(DomainEpochWrap), epochSymmetric[:]...)
	return sha256.Sum256(append(b, contentID[:]...))
}

// WrapToEpoch wraps the content key k under EpochWrapKey in BRC-2's
// symmetric form: a 32-byte IV from r (crypto/rand.Reader when r is nil),
// the 32-byte ciphertext and the 16-byte tag, WrapLen bytes.
func WrapToEpoch(epochSymmetric, contentID, k [32]byte, r io.Reader) ([]byte, error) {
	if err := CheckScalar(k); err != nil {
		return nil, err
	}
	if r == nil {
		r = rand.Reader
	}
	var iv [32]byte
	if _, err := io.ReadFull(r, iv[:]); err != nil {
		return nil, err
	}
	w := EpochWrapKey(epochSymmetric, contentID)
	return keyed.SymmetricSeal(w[:], iv, k[:])
}

// UnwrapFromEpoch is a member's checks 2a and 2b. A reader runs check 1
// first (CheckCiphertext, or ReadAsMember, which does all of it in order).
// It opens the wrap with the key derived
// from the epoch's symmetric key, refuses a value that is not a scalar, and
// checks it against the commitment before anything else uses it. A holder of
// another epoch's key derives another wrapping key, and the wrap does not
// open (ErrUnwrap).
func UnwrapFromEpoch(epochSymmetric, contentID [32]byte, wrap []byte, commitment [32]byte) ([32]byte, error) {
	if len(wrap) != WrapLen {
		return [32]byte{}, fmt.Errorf("%w: length %d", ErrUnwrap, len(wrap))
	}
	w := EpochWrapKey(epochSymmetric, contentID)
	pt, err := keyed.SymmetricOpen(w[:], wrap)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	return keyed.CheckOpened(pt, commitment)
}

// SelfKeyID is the self wrap's BRC-43 key id: the standard padded base64 of
// the content id, so a wrap cannot be moved to another version.
func SelfKeyID(contentID [32]byte) string {
	return base64.StdEncoding.EncodeToString(contentID[:])
}

// SelfInvoice is the BRC-43 invoice number the self wrap is derived under.
func SelfInvoice(contentID [32]byte) string {
	return "2-" + SelfProtocolName + "-" + SelfKeyID(contentID)
}

func selfArgs(contentID [32]byte) wallet.EncryptionArgs {
	return wallet.EncryptionArgs{
		ProtocolID:   SelfProtocol,
		KeyID:        SelfKeyID(contentID),
		Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
	}
}

// WrapToSelf wraps the content key k to the owner's own wallet: a BRC-100
// encrypt under [2, "bsecret self"], the key id of SelfKeyID and
// counterparty self, WrapLen bytes. Only BRC-42 derivation touches the
// identity key; k itself is random.
func WrapToSelf(ctx context.Context, w wallet.Interface, contentID, k [32]byte) ([]byte, error) {
	if err := CheckScalar(k); err != nil {
		return nil, err
	}
	res, err := w.Encrypt(ctx, wallet.EncryptArgs{EncryptionArgs: selfArgs(contentID), Plaintext: k[:]}, "")
	if err != nil {
		return nil, err
	}
	if len(res.Ciphertext) != WrapLen {
		return nil, fmt.Errorf("%w: length %d", ErrUnwrap, len(res.Ciphertext))
	}
	return res.Ciphertext, nil
}

// WrapToSelfWithIV is WrapToSelf with a caller's 32-byte IV in place of a
// random one, for golden vectors only: the symmetric key is the one the
// wallet derives, and the result decrypts through any wallet's Decrypt.
func WrapToSelfWithIV(owner *ec.PrivateKey, contentID, k [32]byte, iv [32]byte) ([]byte, error) {
	sk, err := wallet.NewKeyDeriver(owner).DeriveSymmetricKey(SelfProtocol, SelfKeyID(contentID),
		wallet.Counterparty{Type: wallet.CounterpartyTypeSelf})
	if err != nil {
		return nil, err
	}
	return keyed.SymmetricSeal(sk.ToBytes(), iv, k[:])
}

// WrapToEpochWithIV is WrapToEpoch with a caller's IV, for golden vectors
// only.
func WrapToEpochWithIV(epochSymmetric, contentID, k [32]byte, iv [32]byte) ([]byte, error) {
	w := EpochWrapKey(epochSymmetric, contentID)
	return keyed.SymmetricSeal(w[:], iv, k[:])
}

// UnwrapFromSelf is the owner's side: its wallet decrypts the self wrap, and
// the same checks follow as for a member.
func UnwrapFromSelf(ctx context.Context, w wallet.Interface, contentID [32]byte, wrap []byte, commitment [32]byte) ([32]byte, error) {
	if len(wrap) != WrapLen {
		return [32]byte{}, fmt.Errorf("%w: length %d", ErrUnwrap, len(wrap))
	}
	res, err := w.Decrypt(ctx, wallet.DecryptArgs{EncryptionArgs: selfArgs(contentID), Ciphertext: wrap}, "")
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	return keyed.CheckOpened(res.Plaintext, commitment)
}

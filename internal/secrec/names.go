package secrec

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/lightwebinc/bcommon/guard"
)

// CheckIdentity refuses anything but a canonical compressed secp256k1 key
// (bcommon guard.ParsePubKey): 33 bytes, prefix 0x02 or 0x03, an x-coordinate
// below the field prime, and a point on the curve. Accepting an alias would
// let two byte strings name one organization.
func CheckIdentity(k []byte) error {
	if _, err := guard.ParsePubKey(k); err != nil {
		return ErrIdentity
	}
	return nil
}

// CheckOrgKey is the key rule for a vault's owner: a canonical identity key
// that is not the anyone key, whose private key everyone knows.
func CheckOrgKey(k []byte) error {
	if CheckIdentity(k) != nil || IsAnyone(k) {
		return ErrIdentity
	}
	return nil
}

// AnyoneKey is the public key of BRC-43's "anyone" counterparty, the
// generator point (private key 1).
func AnyoneKey() []byte {
	one := make([]byte, 32)
	one[31] = 1
	k, _ := ec.PrivateKeyFromBytes(one)
	return k.PubKey().Compressed()
}

// IsAnyone reports whether k is the anyone key.
func IsAnyone(k []byte) bool { return bytes.Equal(k, AnyoneKey()) }

// checkReadable applies the grammar of the readable part of a crypt or hall
// identifier: 1 to max bytes of lowercase ASCII letters and single
// underscores, starting and ending with a letter.
func checkReadable(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c == '_':
			if i == 0 || i == len(s)-1 || s[i-1] == '_' {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// checkSuffixed applies <name>_<suffix>: a readable part of at most maxName
// bytes and a suffix of exactly SuffixLen lowercase ASCII letters.
func checkSuffixed(s string, min, max, maxName int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	cut := len(s) - SuffixLen - 1
	if s[cut] != '_' {
		return false
	}
	for i := cut + 1; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return checkReadable(s[:cut], maxName)
}

// CheckCryptName applies the grammar of a crypt's readable part.
func CheckCryptName(s string) error {
	if !checkReadable(s, MaxCryptName) {
		return ErrCrypt
	}
	return nil
}

// CheckCrypt applies the crypt identifier grammar: <name>_<suffix>, where
// name meets CheckCryptName and suffix is exactly SuffixLen lowercase ASCII
// letters. TopicPrefix + crypt is then a BRC-87 topic manager name.
func CheckCrypt(s string) error {
	if !checkSuffixed(s, MinCrypt, MaxCrypt, MaxCryptName) {
		return ErrCrypt
	}
	return nil
}

// CheckHall applies the grammar of the identifier of the hall a vault's
// group lives in: the same shape as a crypt's, with the hall's own bounds.
func CheckHall(s string) error {
	if !checkSuffixed(s, MinHall, MaxHall, MaxHall-1-SuffixLen) {
		return ErrHall
	}
	return nil
}

// SplitCrypt returns a crypt identifier's readable part and suffix. The
// readable part alone never identifies a crypt.
func SplitCrypt(s string) (name, suffix string, err error) {
	if err := CheckCrypt(s); err != nil {
		return "", "", err
	}
	cut := len(s) - SuffixLen - 1
	return s[:cut], s[cut+1:], nil
}

// NewCrypt creates a crypt identifier for name: name, an underscore, and
// SuffixLen letters drawn uniformly at random from a to z by r
// (crypto/rand.Reader when r is nil). Whoever creates the crypt calls it
// once; the suffix never changes.
func NewCrypt(name string, r io.Reader) (string, error) {
	if err := CheckCryptName(name); err != nil {
		return "", err
	}
	if r == nil {
		r = rand.Reader
	}
	suffix := make([]byte, SuffixLen)
	var b [1]byte
	for i := 0; i < SuffixLen; {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		// 234 = 9 * 26: rejecting 234 to 255 keeps every letter equally
		// likely.
		if b[0] >= 234 {
			continue
		}
		suffix[i] = 'a' + b[0]%26
		i++
	}
	return name + "_" + string(suffix), nil
}

// Topic is the topic manager name of a crypt.
func Topic(crypt string) string { return TopicPrefix + crypt }

// CheckLabel applies the label grammar: 1 to MaxLabel bytes of lowercase
// ASCII letters, digits and single hyphens, starting with a letter and
// ending with a letter or a digit.
func CheckLabel(s string) error {
	if len(s) == 0 || len(s) > MaxLabel || s[0] < 'a' || s[0] > 'z' {
		return ErrLabel
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-':
			if i == len(s)-1 || s[i-1] == '-' {
				return ErrLabel
			}
		default:
			return ErrLabel
		}
	}
	return nil
}

// CheckLabels applies the label set rule: 1 to MaxLabels labels, each
// meeting CheckLabel, in strictly ascending byte order.
func CheckLabels(a []string) error {
	if len(a) < 1 || len(a) > MaxLabels {
		return ErrLabel
	}
	for i, l := range a {
		if err := CheckLabel(l); err != nil {
			return err
		}
		if i > 0 && a[i-1] >= l {
			return ErrLabel
		}
	}
	return nil
}

// CheckSecretName applies the grammar of a secret's name: 1 to
// MaxSecretName bytes of lowercase ASCII letters, digits, '.', '_', '-' and
// '/', with no empty path segment. One name has one spelling, so one name
// has one identifier.
func CheckSecretName(s string) error {
	if len(s) == 0 || len(s) > MaxSecretName || s[0] == '/' || s[len(s)-1] == '/' {
		return ErrName
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		case c == '/':
			if s[i-1] == '/' {
				return ErrName
			}
		default:
			return ErrName
		}
	}
	return nil
}

// VaultID is a vault's identifier: SHA-256 of the domain string and the
// outpoint the vault's first token spends from its chain tree, the txid in
// hash byte order and the output index as four bytes big-endian. An outpoint
// is spent by one mined transaction, so one identifier has one first token.
func VaultID(txid [32]byte, vout uint32) [32]byte {
	b := append([]byte(DomainVaultID), txid[:]...)
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], vout)
	return sha256.Sum256(append(b, v[:]...))
}

// SecretID is a secret's identifier, stable across its versions: SHA-256 of
// the domain string, the vault identifier and the name's bytes.
func SecretID(vault [32]byte, name string) ([32]byte, error) {
	if err := CheckSecretName(name); err != nil {
		return [32]byte{}, err
	}
	b := append([]byte(DomainSecretID), vault[:]...)
	return sha256.Sum256(append(b, name...)), nil
}

// Leaf is the leaf datum the vault's root commits one current secret by:
// SHA-256 of its identifier, its version as eight bytes big-endian, and its
// version's content id.
func Leaf(id [32]byte, version uint64, contentID [32]byte) [32]byte {
	b := append([]byte(nil), id[:]...)
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], version)
	b = append(b, v[:]...)
	return sha256.Sum256(append(b, contentID[:]...))
}

// BRC-369 keyed content: segmented AES-256-GCM (section 2.3), the three
// checks in their order (section 5.3) and the locator. The content key, its
// symmetric key and its commitment (sections 2.1 and 2.2) are bcommon's
// keyed package, checked here against BRC-369's own vectors (docs/spec.md
// section 16.1).

package secrec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"

	base58 "github.com/bsv-blockchain/go-sdk/compat/base58"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/lightwebinc/bcommon/keyed"
)

// SampleKey draws a content key: a scalar uniform in [1, n-1], never derived
// from anything (BRC-369 section 2.1 rule 1).
func SampleKey(r io.Reader) ([32]byte, error) { return keyed.SampleKey(r) }

// CheckScalar refuses a 32-byte big-endian value outside [1, n-1].
func CheckScalar(k [32]byte) error { return keyed.CheckScalar(k) }

// SymmetricKey is BRC-369 section 2.1 rule 3.
func SymmetricKey(k [32]byte) [32]byte { return keyed.SymmetricKey(k) }

// Commitment is BRC-369 section 2.2's digest form.
func Commitment(k [32]byte) [32]byte { return keyed.Commitment(k) }

// CommitmentPoint is BRC-369 section 2.2's point form, k * G compressed.
// bsecret never writes it; it is here to reproduce BRC-369's own vectors.
func CommitmentPoint(k [32]byte) []byte {
	_, pub := ec.PrivateKeyFromBytes(k[:])
	return pub.Compressed()
}

// SegmentIV is BRC-369 section 2.3 rule 2: the 4-byte salt followed by the
// segment index as eight bytes big-endian.
func SegmentIV(salt [SaltLen]byte, i uint64) [12]byte { return keyed.SegmentIV(salt, i) }

// CheckSegment bounds a segment size.
func CheckSegment(segment uint64) error {
	if segment < MinSegment || segment > MaxSegment {
		return fmt.Errorf("%w: segment", ErrRange)
	}
	return nil
}

// CipherLength is the ciphertext length of n plaintext bytes in segments of
// segment bytes: each segment is followed by its 16-byte tag.
func CipherLength(n, segment uint64) uint64 {
	segs := (n + segment - 1) / segment
	return n + segs*TagLen
}

// PlainLength reverses CipherLength. It refuses a length no plaintext of at
// least one byte produces: an empty ciphertext, or a last segment that is
// only a tag or less.
func PlainLength(length, segment uint64) (uint64, error) {
	if err := CheckSegment(segment); err != nil {
		return 0, err
	}
	full := length / (segment + TagLen)
	rem := length % (segment + TagLen)
	if length == 0 || (rem != 0 && rem <= TagLen) {
		return 0, fmt.Errorf("%w: length", ErrRange)
	}
	n := full * segment
	if rem != 0 {
		n += rem - TagLen
	}
	return n, nil
}

func gcmFor(k [32]byte) (cipher.AEAD, error) {
	sym := SymmetricKey(k)
	blk, err := aes.NewCipher(sym[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// Seal encrypts plaintext under the content key k as BRC-369 section 2.3
// writes it: fixed-size segments, each under AES-256-GCM with the symmetric
// key of section 2.1, the IV of SegmentIV and no associated data, each
// followed by its own tag. The salt MUST be fresh for every content key.
func Seal(k [32]byte, salt [SaltLen]byte, segment uint64, plaintext []byte) ([]byte, error) {
	if err := CheckScalar(k); err != nil {
		return nil, err
	}
	if err := CheckSegment(segment); err != nil {
		return nil, err
	}
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("%w: empty plaintext", ErrRange)
	}
	g, err := gcmFor(k)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, CipherLength(uint64(len(plaintext)), segment))
	for i, off := uint64(0), uint64(0); off < uint64(len(plaintext)); i, off = i+1, off+segment {
		end := off + segment
		if end > uint64(len(plaintext)) {
			end = uint64(len(plaintext))
		}
		iv := SegmentIV(salt, i)
		out = g.Seal(out, iv[:], plaintext[off:end], nil)
	}
	return out, nil
}

// OpenSegments decrypts a ciphertext Seal wrote, verifying every segment's
// tag before any plaintext is returned (BRC-369 section 2.3 rule 5). A tag
// that fails is ErrTag.
func OpenSegments(k [32]byte, salt [SaltLen]byte, segment uint64, ciphertext []byte) ([]byte, error) {
	n, err := PlainLength(uint64(len(ciphertext)), segment)
	if err != nil {
		return nil, err
	}
	g, err := gcmFor(k)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, n)
	step := segment + TagLen
	for i, off := uint64(0), uint64(0); off < uint64(len(ciphertext)); i, off = i+1, off+step {
		end := off + step
		if end > uint64(len(ciphertext)) {
			end = uint64(len(ciphertext))
		}
		iv := SegmentIV(salt, i)
		out, err = g.Open(out, iv[:], ciphertext[off:end], nil)
		if err != nil {
			return nil, fmt.Errorf("%w: segment %d", ErrTag, i)
		}
	}
	return out, nil
}

// Checks runs BRC-369 section 5.3's three checks in their order and stops at
// the first failure, so that each failure names its own culprit:
//
//  1. ErrHash: the ciphertext is not the one committed to (a host or a
//     store substituted bytes);
//  2. ErrScalar or ErrCommitment: the candidate key is not the committed one
//     (whoever wrapped it wrapped another);
//  3. ErrTag: the committed key does not open the committed ciphertext (the
//     publisher encrypted under a key it did not commit to).
func Checks(ciphertext []byte, hash [32]byte, length uint64, k, commitment [32]byte, salt [SaltLen]byte, segment uint64) ([]byte, error) {
	if uint64(len(ciphertext)) != length || sha256.Sum256(ciphertext) != hash {
		return nil, ErrHash
	}
	if err := CheckScalar(k); err != nil {
		return nil, err
	}
	if Commitment(k) != commitment {
		return nil, ErrCommitment
	}
	return OpenSegments(k, salt, segment, ciphertext)
}

// Locator is where a ciphertext that is not carried inline is found: the
// BRC-26 content address of its SHA-256 hash, written as a uhrp:// URL
// (Base58Check over the prefix ce00 and the hash). The record's hash alone
// determines it, so a record carries no locator.
func Locator(hash [32]byte) string {
	payload := append([]byte{0xce, 0x00}, hash[:]...)
	c := sha256.Sum256(payload)
	c = sha256.Sum256(c[:])
	return "uhrp://" + base58.Encode(append(payload, c[:4]...))
}

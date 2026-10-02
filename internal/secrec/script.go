package secrec

import (
	"bytes"
	"encoding/binary"
)

// Kind names what an output claims to be (docs/spec.md section 11.1,
// Classify).
type Kind string

const (
	KindNone    Kind = ""
	KindSecret  Kind = "secret"
	KindVault   Kind = "vault-token"
	KindFunding Kind = "funding"
)

// firstPush reads the push that follows a lock-before PushDrop's key and
// OP_CHECKSIG: an opcode 0x01 to 0x4b, or OP_PUSHDATA1, 2 or 4 with its
// little-endian length, every declared byte present. It allocates nothing.
func firstPush(s []byte) ([]byte, bool) {
	if len(s) < 36 || s[0] != 0x21 || s[34] != 0xac {
		return nil, false
	}
	p := s[35:]
	op := p[0]
	var n, off int
	switch {
	case op >= 0x01 && op <= 0x4b:
		n, off = int(op), 1
	case op == 0x4c && len(p) >= 2:
		n, off = int(p[1]), 2
	case op == 0x4d && len(p) >= 3:
		n, off = int(binary.LittleEndian.Uint16(p[1:3])), 3
	case op == 0x4e && len(p) >= 5:
		v := binary.LittleEndian.Uint32(p[1:5])
		if uint64(v) > uint64(len(p)) {
			return nil, false
		}
		n, off = int(v), 5
	default:
		return nil, false
	}
	if len(p) < off+n {
		return nil, false
	}
	return p[off : off+n], true
}

// claimsMagic looks for a definite-length map head (0xa0 to 0xbb), key 0,
// then a four-byte string equal to magic. Key 0 always sorts first in a
// canonical map with unsigned-integer keys.
func claimsMagic(p, magic []byte) bool {
	if len(p) < 1 || p[0]>>5 != 5 {
		return false
	}
	var i int
	switch ai := p[0] & 0x1f; {
	case ai < 24:
		i = 1
	case ai <= 27:
		i = 1 + 1<<(ai-24)
	default:
		return false
	}
	if len(p) < i+2+len(magic) || p[i] != 0x00 || p[i+1] != 0x44 {
		return false
	}
	return bytes.Equal(p[i+2:i+2+len(magic)], magic)
}

// Classify says what a locking script claims, reading nothing else of it. A
// script that claims something is then held to the exact script rebuilt from
// its fields (docs/spec.md section 11.1); this is only the first look.
func Classify(s []byte) Kind {
	p, ok := firstPush(s)
	if !ok {
		return KindNone
	}
	switch {
	case claimsMagic(p, MagicSecret):
		return KindSecret
	case bytes.Equal(p, TagVault):
		return KindVault
	case bytes.Equal(p, TagFunding) && len(s) == 35+4+1 && s[39] == 0x75:
		return KindFunding
	}
	return KindNone
}

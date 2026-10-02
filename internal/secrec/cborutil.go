package secrec

import (
	"unicode/utf8"

	"github.com/lightwebinc/bcommon/record"
)

// fields is a decoded record with this package's own readers beside the
// shared ones.
type fields struct{ *record.Fields }

func decodeRecord(b []byte, max int, last uint64, magic []byte) (*fields, error) {
	f, err := record.Decode(b, max, last, magic)
	if err != nil {
		return nil, err
	}
	return &fields{f}, nil
}

// checkName is the display-name rule (docs/spec.md section 3): 1 to MaxName
// bytes of UTF-8 text that is one line of plain text, holding no control
// character (U+0000 to U+001F, U+007F to U+009F) and no line or paragraph
// separator (U+2028, U+2029). The set is fixed code points, not a Unicode
// category looked up in a table, so every implementation refuses the same
// names whatever version of Unicode it ships.
func checkName(s string) error {
	if len(s) < 1 || len(s) > MaxName || !utf8.ValidString(s) {
		return ErrName
	}
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == 0x2028 || r == 0x2029 {
			return ErrName
		}
	}
	return nil
}

func zero32(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

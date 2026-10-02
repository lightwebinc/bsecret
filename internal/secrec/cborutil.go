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

// checkName is the display-name rule: 1 to MaxName bytes of UTF-8 text.
func checkName(s string) error {
	if len(s) < 1 || len(s) > MaxName || !utf8.ValidString(s) {
		return ErrName
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

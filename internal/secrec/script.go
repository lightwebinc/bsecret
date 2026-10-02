package secrec

import (
	"bytes"

	"github.com/lightwebinc/bcommon/pushdrop"
	"github.com/lightwebinc/bcommon/record"
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

// Classify says what a locking script claims, reading nothing else of it. A
// script that claims something is then held to the exact script rebuilt from
// its fields (docs/spec.md section 11.1); this is only the first look.
func Classify(s []byte) Kind {
	p, ok := pushdrop.FirstPush(s)
	if !ok {
		return KindNone
	}
	switch {
	case record.Claims(p, MagicSecret):
		return KindSecret
	case bytes.Equal(p, TagVault):
		return KindVault
	case bytes.Equal(p, TagFunding) && len(s) == 35+4+1 && s[39] == 0x75:
		return KindFunding
	}
	return KindNone
}

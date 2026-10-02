package secrec

import (
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/lightwebinc/bcommon/pushdrop"
)

// PushDropScript is the one canonical lock-before PushDrop for key, fields
// and an optional field signature (bcommon pushdrop.Script): the 33-byte
// key, OP_CHECKSIG, each field as one minimal push, the signature as one
// minimal push when there is one, and the fewest OP_2DROP then OP_DROP that
// clear them. Every script a host checks is compared byte for byte with it
// (docs/spec.md section 11.1).
func PushDropScript(key *ec.PublicKey, fields [][]byte, sig []byte) []byte {
	return pushdrop.Script(key, fields, sig)
}

// FundingScript is a funding output locked to key: `<key> OP_CHECKSIG
// <73 65 02> OP_DROP`, unsigned (docs/spec.md section 12.4).
func FundingScript(key *ec.PublicKey) []byte {
	return PushDropScript(key, [][]byte{TagFunding}, nil)
}

// IsFundingShape reports a funding-shaped script under any key: the whole
// script is 0x21, 33 bytes, 0xac, 03 73 65 02, 75 (Classify's funding).
func IsFundingShape(s []byte) bool { return Classify(s) == KindFunding }

// FundingScriptOf is the funding output script of an owner's tree under a
// derivation: SecretDerivation for a tree that funds carriers,
// ChainDerivation for one that pays for vaults' first tokens (docs/spec.md
// section 12.4). The key is derived from the identity key alone, as a
// reader derives it.
func FundingScriptOf(d pushdrop.Derivation, owner []byte) ([]byte, error) {
	if err := CheckOrgKey(owner); err != nil {
		return nil, err
	}
	return FundingScript(lockingKey(d, owner)), nil
}

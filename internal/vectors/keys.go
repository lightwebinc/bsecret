// Package vectors generates the golden vectors under testdata/vectors from
// the codec in internal/secrec. Every value is derived from fixed stand-ins
// (public test keys, hashes of labels for anything a client draws at
// random), so the files are reproducible byte for byte; every check the
// generator makes (a wallet opens what was wrapped to it, a member of
// another epoch does not, BRC-369's own vectors still reproduce) fails the
// run when it stops holding.
package vectors

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// Crypt is the vectors' crypt identifier; its suffix is a fixed example.
const Crypt = "example_crypt_hmqzvtkwrx"

// Hall is the identifier of the hall the vectors' group lives in.
const Hall = "example_hall_vkqzmtrwxp"

// Created is the vectors' fixed time, in Unix seconds.
const Created = 1798761600

// Party is one public test identity: 32 bytes of one value as the private
// key. Never for real use.
type Party struct {
	Name string
	Priv *ec.PrivateKey
}

func party(name string, b byte) Party {
	k, _ := ec.PrivateKeyFromBytes(bytes.Repeat([]byte{b}, 32))
	return Party{Name: name, Priv: k}
}

// The parties: the organisation that owns the vault, three members of its
// group, and a key that is never a member. They are the identities the
// group substrate's own vectors use, so the two vector sets describe one
// scenario.
var (
	Org   = party("org", 0x51)
	Alice = party("alice", 0x52)
	Bob   = party("bob", 0x53)
	Carol = party("carol", 0x54)
	Dave  = party("dave", 0x56)
)

// Pub is the party's compressed identity key.
func (p Party) Pub() []byte { return p.Priv.PubKey().Compressed() }

// Wallet is a BRC-100 wallet over the party's key.
func (p Party) Wallet() wallet.Interface {
	w, err := wallet.NewCompletedProtoWallet(p.Priv)
	if err != nil {
		panic(err)
	}
	return w
}

// label is the fixed stand-in for a random value: SHA-256 of a label.
func label(format string, a ...any) [32]byte {
	return sha256.Sum256([]byte("bsecret/vector/" + fmt.Sprintf(format, a...)))
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func h32(s string) [32]byte {
	var out [32]byte
	copy(out[:], unhex(s))
	return out
}

// displayHex writes a hash-byte-order txid in display order.
func displayHex(h [32]byte) string {
	r := make([]byte, 32)
	for i := range h {
		r[i] = h[31-i]
	}
	return hx(r)
}

// GroupEpoch is one epoch of the vectors' group, as the group substrate's
// own golden vectors give it: the key the organisation sampled, the BRC-369
// symmetric key and commitment it derives, and the epoch id. Holders is who
// was a member during the epoch and so holds its key.
type GroupEpoch struct {
	Epoch      uint64
	Key        [32]byte
	Symmetric  [32]byte
	Commitment [32]byte
	EpochID    [32]byte
	Began      string
	Holders    []string
	Height     uint32
	Removed    bool
}

// GroupID is the vectors' group identifier.
var GroupID = func() (id [16]byte) { copy(id[:], unhex("406504d3fbe1ae098f09a49dffa12222")); return }()

// GroupEpochs is the group's history: created with alice and bob, carol
// added within epoch 0, bob removed (epoch 1), a scheduled rotation
// (epoch 2). The heights are those the audit vector uses.
var GroupEpochs = []GroupEpoch{
	{0, h32("f32d56bd890f105f1e9731d9607b464078644b0ce1df8e7a87196589bd0266ca"),
		h32("3d67c0041301c203085c253fb02a70d5d86ebdbe411759a18c7e63a40af8bd35"),
		h32("ceeed5d6813b5155763f35d7209ce29228cd9625bb6527946fcdf6ee1b30f4ee"),
		h32("e1d5c36f56d10af0c71d27509e56b2f06695b781ac0459aa7705e8ba90e7ee27"),
		"the group is created with alice and bob; carol is added within the epoch", []string{"alice", "bob", "carol"}, 1000, false},
	{1, h32("2502fa9da5b7f889d8de37defbdda85531e2c6b20626a3e59efa6815aac06189"),
		h32("836a3cd360f7eb2a083d0fd085c537f6fb6d29df6fbca8b68835e48d07d62dc0"),
		h32("33446213fbf23b1a12c81c0b6679ff8cb4345db876f39affabc0050bb46604eb"),
		h32("a924a735de0a9c194206a271b3fa2ff19f55d87305f8716950d07c29037dc242"),
		"bob is removed", []string{"alice", "carol"}, 1010, true},
	{2, h32("ceebd5308ddfaee2f1fb4f5f2dc96b596b58f4ad1643136ec53eb35071587947"),
		h32("b73945e40061c4823d1d9cf528a76b2e7a33a2b97ef182828c6aaeca48fea003"),
		h32("16a5a7e954bc2b7400de9f24edd5d81c62e9d0c88557ee6cf2298e3dd39a62be"),
		h32("231dc3fd55fab180c2e241b22e235c106e99f39fe33fe270702091c3f9fda641"),
		"a scheduled rotation, no member change", []string{"alice", "carol"}, 1030, false},
}

// holds reports whether the named member holds the key of epoch e.
func holds(name string, e uint64) bool {
	for _, h := range GroupEpochs[e].Holders {
		if h == name {
			return true
		}
	}
	return false
}

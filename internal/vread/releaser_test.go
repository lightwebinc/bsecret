package vread

import (
	"context"
	"crypto/rand"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/lightwebinc/borg/borgrec"
)

// The organization's own wallet opens borg's wrap to its signer key, as the
// releaser, and gets the key the signer key's own wallet gets; it opens
// nothing else.
func TestTheReleaserOpensTheWrapToTheSignerKey(t *testing.T) {
	ctx := context.Background()
	orgKey, _ := ec.NewPrivateKey()
	org := orgKey.PubKey()
	orgWallet, err := wallet.NewCompletedProtoWallet(orgKey)
	if err != nil {
		t.Fatal(err)
	}
	signerW, signerPub, err := SignerWallet(orgKey)
	if err != nil {
		t.Fatal(err)
	}
	relW, relPub, err := ReleaserWallet(orgWallet, org.Compressed())
	if err != nil {
		t.Fatal(err)
	}
	if string(relPub) != string(signerPub) {
		t.Fatalf("the releaser names %x as the signer key, and borg derives %x", relPub, signerPub)
	}
	k, err := borgrec.SampleKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var epochID [32]byte
	copy(epochID[:], "an epoch id, thirty-two bytes...")
	sp, _ := ec.PublicKeyFromBytes(signerPub)
	wrap, err := borgrec.Wrap(ctx, orgWallet, org.Compressed(), sp, epochID, 3, k)
	if err != nil {
		t.Fatal(err)
	}
	commitment := borgrec.Commitment(k)
	for name, w := range map[string]wallet.Interface{"the signer key's wallet": signerW, "the releaser": relW} {
		got, err := borgrec.Unwrap(ctx, w, wrap, org, epochID, 3, commitment)
		if err != nil || got != k {
			t.Fatalf("%s: %x, %v", name, got, err)
		}
	}
	// A wrap to another member is not the signer key's: the releaser opens
	// only what the signer key could.
	other, _ := ec.NewPrivateKey()
	wrapOther, err := borgrec.Wrap(ctx, orgWallet, org.Compressed(), other.PubKey(), epochID, 3, k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := borgrec.Unwrap(ctx, relW, wrapOther, org, epochID, 3, commitment); err == nil {
		t.Fatal("the releaser opened a wrap to another member")
	}
	// A decryption for any other counterparty is refused.
	if _, err := relW.Decrypt(ctx, wallet.DecryptArgs{EncryptionArgs: wallet.EncryptionArgs{ProtocolID: wallet.Protocol{SecurityLevel: 2, Protocol: "bsecret self"},
		KeyID: "x", Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}}, Ciphertext: []byte{1}}, ""); err == nil {
		t.Fatal("the releaser decrypted for its own self")
	}
}

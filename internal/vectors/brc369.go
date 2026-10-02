package vectors

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"

	aesgcm "github.com/bsv-blockchain/go-sdk/primitives/aesgcm"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// The values BRC-369 prints under "Test Vectors".
const (
	brcPublisher = "02390d541cef55960403aed2ef478e5f8c67cdafd353366a46ee8f00c723e9743e"
	brcReleaser  = "03e69fe2022f968ea1bc233f6a97ab885d16965d747fdab152dc7e71675d856d69"
	brcRecipient = "02f409d574960001d82cfc470956b1c13aa60e98fb88101cdf69797d597745c3f7"
	brcScalar    = "0ff730f7b66f7bb6626229ca20c5b4c2c47ecc32248203a14cd247ef7ed298d8"
	brcSym       = "42dcb945809f42a6f827c8336affc7a04c284dfd6e4b65c6663f6e864240ad0e"
	brcDigest    = "2013064f87db545aa20f273b3abc8bdb470ddc69349cac55b7b397585af15797"
	brcPoint     = "02f340de300c8614f85771ed721b55637b8f729e59f50ff7edc475d5832c522372"
	brcSalt      = "4168fb26"
	brcSegment   = 64
	brcCipher    = "8866ea607a527c96ae4b7f3c6d33b7490f02117906fe18ec91398ba1481f31c5" +
		"0c08bd553b08a30f82d8a85c529e0643dfdec581b959ae72a663483fe1d12fef" +
		"3591b5c89b353d2ee894aee750f18cd76854e3398febb09eecc0a264ec1937eb" +
		"9b8d77a42422b909c9c1d59a038de392a197a21749c2ca3ccfa89fed5964b362" +
		"731af7ce106883f9948863c5268579040f3c54f880991cb25513efc18fb9724b" +
		"d0d22e75a4e177232243aee5bd797624e80320f04e50a1663da30ab3559b5c54"
	brcHash       = "00fdc251d4d520fe8e343c471e293dfbfd20ef352cdd6cbb7b1fc4d266c8988a"
	brcLocator    = "uhrp://XUSuDZnz4PW5xBBn68YkcJWxZhE22a1ZXraTHPpTLcxrZVXsiiE6"
	brcDescriptor = `{"author":"@crumbs@nexus.app","content":{"cipher":"aes-256-gcm","hash":"00fdc251d4d520fe8e343c471e293dfbfd20ef352cdd6cbb7b1fc4d266c8988a","length":192,"locator":["uhrp://XUSuDZnz4PW5xBBn68YkcJWxZhE22a1ZXraTHPpTLcxrZVXsiiE6"],"salt":"4168fb26","segment":64},"epoch":0,"key":{"digest":"2013064f87db545aa20f273b3abc8bdb470ddc69349cac55b7b397585af15797"},"metanetKeyedContent":"1.0","release":{"condition":"payment","on":"broadcast","payees":[{"handle":"@crumbs@nexus.app","share":9300},{"handle":"@fees@nexus.app","share":700}],"price":{"amount":"1.00","currency":"USD"},"releasers":[{"delegation":"d6e8f0c2a41b5937e2c8d1f4a70b6e35c9d2f81a4b7e0c63d5a9f2e841b7c06d_1","handle":"@keys@nexus.app"}]}}`
	brcCID        = "4506d4b11347776160524138f6711c7c747d65e6bf0ea2d3f5947b98dec25a97"
	brcSignature  = "3045022100f31abc7a941f4fb435cffd7208dce585d1f99d619b2179718858c8d6c897786302207db4f06e22d2bf0637d34915475777a74244a0e7fb7a6ae4ce511cd5e5aece34"
	brcInvoice    = "2-keyed content release-fFiOxZVLQfuY79OnswIQo8X5vER3fmI982XpY3x0s24="
	brcShared     = "873de6bc082794ae1de8390aec85b7641fb7dd88106cd0a3230468a8e9484547"
	brcPayload    = "3310424203e69fe2022f968ea1bc233f6a97ab885d16965d747fdab152dc7e71675d856d6902f409d574960001d82cfc470956b1c13aa60e98fb88101cdf69797d597745c3f77c588ec5954b41fb98efd3a7b30210a3c5f9bc44777e623df365e9637c74b36efef88a7d999ae66f952cc1cef07af27ea4538a999ec5cd15038dd7a8636899298eff7a4477ee7c62fbc7f177a189749f2a17a3f7c57d89bc78ba39f6b1143ed222f3a3d1a7a71e62206123f7e998f676"
	brcShare1     = "024eef7aee40a563602d32dd10e0347e75e90daa59d95eceed3430f11cd9c544a1"
	brcShare2     = "02cf2329e6bbfe531b4a7a790074c370cc231f0fa38ba5ab13dcbab3dcaba8922a"
	brcProofS     = "02d9f8c1eff274d6dd1a1387c7586c1c1435e085f2741d33083893ec35372f2255"
	brcProofR     = "0250dd7cd4de626292c56d587acefc75a650286805fc37438488e6f6ac8a168415"
	brcProofSp    = "025b9fa91ae7e4a067d81792027a5e3e3c07cad78a8bf6f8adfc41d7845374f1f0"
	brcProofZ     = "891fb36580433a49de271af6fa65723ffb4ea74f7236d25ca5b0da20099e0e96"
	brcFraudHash  = "9920f5113ce14452add1275a0ab200e148db49c9708a08d6eab707f664b16ccc"
	brcFraudCID   = "525bdd364e003f08322bbb5927be94b0be97983718aec1ffd43e90ef271d29a1"
	// brcPlaintext is not printed in BRC-369: it is what the printed
	// ciphertext opens to under the printed key.
	brcPlaintext = "The paywall we shipped put the restricted text in the same OP_RETURN as the preview. Anyone reading the chain read it for free. This is the fix."
)

// The document's test keys and draws are SHA-256 of these labels: they
// reproduce the printed identity keys, salt, signature, substituted-key case
// and proof. They are public test values.
const (
	brcLabelAuthor   = "BRC-369 author"
	brcLabelReleaser = "BRC-369 releaser"
	brcLabelReader   = "BRC-369 reader"
	brcLabelSalt     = "BRC-369 salt"
	brcLabelFraud    = "BRC-369 substituted key"
	brcLabelNonce    = "BRC-369 schnorr nonce"
)

func labelKey(l string) *ec.PrivateKey {
	d := sha256.Sum256([]byte(l))
	k, _ := ec.PrivateKeyFromBytes(d[:])
	return k
}

func pub(s string) *ec.PublicKey {
	k, err := ec.PublicKeyFromBytes(unhex(s))
	if err != nil {
		panic(err)
	}
	return k
}

// brc94 checks BRC-94's two equations for the prover key a, the
// counterparty key b, the revealed secret s and the proof (r, sp, z), with
// the challenge SHA-256(A || B || S || S' || R) reduced modulo the order.
func brc94(a, b, s, r, sp *ec.PublicKey, z *big.Int) bool {
	var m []byte
	for _, p := range []*ec.PublicKey{a, b, s, sp, r} {
		m = append(m, p.Compressed()...)
	}
	h := sha256.Sum256(m)
	c := ec.S256()
	e := new(big.Int).Mod(new(big.Int).SetBytes(h[:]), c.N)
	zgx, zgy := c.ScalarBaseMult(z.Bytes())
	eax, eay := c.ScalarMult(a.X, a.Y, e.Bytes())
	rx, ry := c.Add(r.X, r.Y, eax, eay)
	zbx, zby := c.ScalarMult(b.X, b.Y, z.Bytes())
	esx, esy := c.ScalarMult(s.X, s.Y, e.Bytes())
	qx, qy := c.Add(sp.X, sp.Y, esx, esy)
	return zgx.Cmp(rx) == 0 && zgy.Cmp(ry) == 0 && zbx.Cmp(qx) == 0 && zby.Cmp(qy) == 0
}

// genBRC369 recomputes the values BRC-369 prints under "Test Vectors" and
// writes each beside what the document prints. It fails when one stops
// matching. What does not reproduce is written as such.
func genBRC369(_ *Scenario, files map[string][]byte) error {
	type check struct {
		Section  string `json:"section"`
		Value    string `json:"value"`
		Printed  string `json:"printed"`
		Computed string `json:"computed"`
		Through  string `json:"through"`
		How      string `json:"how"`
	}
	var checks []check
	const codec, sdk = "this codec", "the SDK's primitives"
	pass := func(section, value, printed, computed, through, how string) error {
		if printed != computed {
			return fmt.Errorf("BRC-369 %s: %s no longer reproduces: %s", section, value, computed)
		}
		checks = append(checks, check{section, value, printed, computed, through, how})
		return nil
	}
	author, releaser, reader := labelKey(brcLabelAuthor), labelKey(brcLabelReleaser), labelKey(brcLabelReader)
	for _, c := range []struct {
		name, printed string
		k             *ec.PrivateKey
	}{{"publisher identity key", brcPublisher, author}, {"releaser identity key", brcReleaser, releaser}, {"recipient identity key", brcRecipient, reader}} {
		if err := pass("Parties", c.name, c.printed, hx(c.k.PubKey().Compressed()), sdk, "the public key of SHA-256 of the party's label"); err != nil {
			return err
		}
	}
	k := h32(brcScalar)
	sym, dig := secrec.SymmetricKey(k), secrec.Commitment(k)
	var salt [secrec.SaltLen]byte
	sl := sha256.Sum256([]byte(brcLabelSalt))
	copy(salt[:], sl[:])
	ct := unhex(brcCipher)
	if err := pass("Content key and commitment", "symmetric key", brcSym, hx(sym[:]), codec, "SHA-256(symmetric domain || k)"); err != nil {
		return err
	}
	if err := pass("Content key and commitment", "commitment digest", brcDigest, hx(dig[:]), codec, "SHA-256(commitment domain || k)"); err != nil {
		return err
	}
	if err := pass("Content key and commitment", "commitment point", brcPoint, hx(secrec.CommitmentPoint(k)), codec, "k * G, compressed"); err != nil {
		return err
	}
	if err := pass("Content key and commitment", "salt", brcSalt, hx(salt[:]), codec, "the first four bytes of SHA-256 of the salt's label"); err != nil {
		return err
	}
	for i, want := range []string{"4168fb260000000000000000", "4168fb260000000000000001", "4168fb260000000000000002"} {
		iv := secrec.SegmentIV(salt, uint64(i))
		if err := pass("Content key and commitment", fmt.Sprintf("segment %d iv", i), want, hx(iv[:]), codec, "salt || index as eight bytes big-endian"); err != nil {
			return err
		}
	}
	pt, err := secrec.OpenSegments(k, salt, brcSegment, ct)
	if err != nil || string(pt) != brcPlaintext || len(pt) != 144 {
		return fmt.Errorf("BRC-369 ciphertext no longer opens: %v", err)
	}
	again, err := secrec.Seal(k, salt, brcSegment, pt)
	if err != nil {
		return err
	}
	if err := pass("Ciphertext", "ciphertext", brcCipher, hx(again), codec, "the printed bytes open in three segments of 64, 64 and 16 to 144 bytes of plaintext, which sealed again give the printed bytes"); err != nil {
		return err
	}
	hash := sha256.Sum256(ct)
	if err := pass("Ciphertext", "ciphertext sha-256", brcHash, hx(hash[:]), codec, "SHA-256 of the 192 bytes"); err != nil {
		return err
	}
	if err := pass("Ciphertext", "uhrp locator", brcLocator, secrec.Locator(hash), codec, "Base58Check over ce00 and the hash"); err != nil {
		return err
	}
	if len(brcDescriptor) != 694 {
		return errors.New("the descriptor is not 694 bytes")
	}
	cid := sha256.Sum256([]byte(brcDescriptor))
	if err := pass("Descriptor", "content id", brcCID, hx(cid[:]), sdk, "SHA-256 of the 694-byte canonical form"); err != nil {
		return err
	}
	sig, err := author.Sign(cid[:])
	if err != nil {
		return err
	}
	if err := pass("Descriptor", "publisher signature", brcSignature, hx(sig.Serialize()), sdk,
		"deterministic ECDSA (RFC 6979) over the content id under the publisher's identity key"); err != nil {
		return err
	}
	if !sig.Verify(cid[:], pub(brcPublisher)) {
		return errors.New("the publisher signature does not verify")
	}
	kid := sha256.Sum256(append(append([]byte(nil), cid[:]...), 0, 0, 0, 0))
	keyID := base64.StdEncoding.EncodeToString(kid[:])
	if err := pass("Release payload", "invoice number", brcInvoice, "2-keyed content release-"+keyID, sdk,
		"2-keyed content release-base64(SHA-256(content id || epoch as four bytes))"); err != nil {
		return err
	}
	payload := unhex(brcPayload)
	if err := pass("Release payload", "payload header: sender, recipient, key id", hx(payload[4:102]),
		brcReleaser+brcRecipient+hx(kid[:]), sdk, "bytes 4 to 101 of the 182-byte payload"); err != nil {
		return err
	}
	// Section 5.3 in order, on the printed ciphertext with the printed key.
	if _, err := secrec.Checks(ct, hash, 192, k, dig, salt, brcSegment); err != nil {
		return fmt.Errorf("BRC-369 section 5.3: %w", err)
	}
	// The substituted key of section 5.4, as the document made it.
	fraudKey := sha256.Sum256([]byte(brcLabelFraud))
	fraudCT, err := secrec.Seal(fraudKey, salt, brcSegment, pt)
	if err != nil {
		return err
	}
	fraudHash := sha256.Sum256(fraudCT)
	if err := pass("The substituted key", "fraud ciphertext sha-256", brcFraudHash, hx(fraudHash[:]), codec,
		"the plaintext sealed under SHA-256 of the substituted key's label, the same salt"); err != nil {
		return err
	}
	fraudDesc := strings.Replace(strings.Replace(brcDescriptor, brcHash, hx(fraudHash[:]), 1), brcLocator, secrec.Locator(fraudHash), 1)
	fraudCID := sha256.Sum256([]byte(fraudDesc))
	if err := pass("The substituted key", "fraud content id", brcFraudCID, hx(fraudCID[:]), sdk,
		"SHA-256 of the printed descriptor with the hash and the locator replaced"); err != nil {
		return err
	}
	check1 := uint64(len(fraudCT)) == 192 && sha256.Sum256(fraudCT) == fraudHash
	check2 := secrec.Commitment(k) == dig
	_, tagErr := secrec.OpenSegments(k, salt, brcSegment, fraudCT)
	_, ferr := secrec.Checks(fraudCT, fraudHash, 192, k, dig, salt, brcSegment)
	if !check1 || !check2 || !errors.Is(tagErr, secrec.ErrTag) || secrec.Reason(ferr) != "tag" {
		return fmt.Errorf("the substituted key case: %v", ferr)
	}
	// Split key: the printed share commitments add to the commitment point.
	c := ec.S256()
	s1, s2 := pub(brcShare1), pub(brcShare2)
	sx, sy := c.Add(s1.X, s1.Y, s2.X, s2.Y)
	sum := &ec.PublicKey{Curve: c, X: sx, Y: sy}
	if err := pass("Split key", "sum of commitments", brcPoint, hx(sum.Compressed()), sdk, "point addition of the two printed share commitments"); err != nil {
		return err
	}
	// The BRC-94 proof, recomputed from the releaser's key and the nonce.
	nonce := labelKey(brcLabelNonce)
	rx, ry := c.ScalarMult(reader.PubKey().X, reader.PubKey().Y, releaser.Serialize())
	shared := &ec.PublicKey{Curve: c, X: rx, Y: ry}
	px, py := c.ScalarMult(reader.PubKey().X, reader.PubKey().Y, nonce.Serialize())
	sPrime := &ec.PublicKey{Curve: c, X: px, Y: py}
	var m []byte
	for _, p := range []*ec.PublicKey{releaser.PubKey(), reader.PubKey(), shared, sPrime, nonce.PubKey()} {
		m = append(m, p.Compressed()...)
	}
	eh := sha256.Sum256(m)
	e := new(big.Int).Mod(new(big.Int).SetBytes(eh[:]), c.N)
	z := new(big.Int).Mod(new(big.Int).Add(new(big.Int).SetBytes(nonce.Serialize()), new(big.Int).Mul(e, new(big.Int).SetBytes(releaser.Serialize()))), c.N)
	for _, x := range []struct{ name, printed, computed, how string }{
		{"S", brcProofS, hx(shared.Compressed()), "the releaser's key times the recipient's identity key"},
		{"R", brcProofR, hx(nonce.PubKey().Compressed()), "the nonce (SHA-256 of its label) times G"},
		{"S prime", brcProofSp, hx(sPrime.Compressed()), "the nonce times the recipient's identity key"},
		{"z", brcProofZ, fmt.Sprintf("%064x", z), "r + e*a mod n, e = SHA-256(A || B || S || S' || R) mod n"},
	} {
		if err := pass("Shared secret proof", x.name, x.printed, x.computed, sdk, x.how); err != nil {
			return err
		}
	}
	zp := new(big.Int).SetBytes(unhex(brcProofZ))
	if !brc94(pub(brcReleaser), pub(brcRecipient), pub(brcProofS), pub(brcProofR), pub(brcProofSp), zp) ||
		brc94(pub(brcPublisher), pub(brcRecipient), pub(brcProofS), pub(brcProofR), pub(brcProofSp), zp) {
		return errors.New("the BRC-94 equations")
	}
	// Payee division: 1.00 USD at 16.755 USD per BSV, half up, 9300 and
	// 700 basis points, the remainder to the first payee.
	total := new(big.Rat).SetFrac(big.NewInt(100000000*1000), big.NewInt(16755))
	sats := new(big.Int).Quo(new(big.Int).Add(new(big.Int).Mul(total.Num(), big.NewInt(2)), total.Denom()), new(big.Int).Mul(total.Denom(), big.NewInt(2))).Int64()
	a, b := sats*9300/10000, sats*700/10000
	a += sats - a - b
	if err := pass("Payee division", "satoshis: total, first payee, second payee", "5968368 5550583 417785", fmt.Sprintf("%d %d %d", sats, a, b), sdk,
		"half-up conversion, integer division, the remainder to the first payee"); err != nil {
		return err
	}

	// The release payload does NOT reproduce under the SDK. The value the
	// document lists as the shared secret opens the payload when used
	// directly as the AES-256-GCM key; the key the SDK derives for the
	// same parties, protocol and key id is another, and a wallet's decrypt
	// of the printed payload fails.
	proto := wallet.Protocol{SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty, Protocol: "keyed content release"}
	sdkKey, err := wallet.NewKeyDeriver(releaser).DeriveSymmetricKey(proto, keyID, wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: reader.PubKey()})
	if err != nil {
		return err
	}
	sdkKey2, err := wallet.NewKeyDeriver(reader).DeriveSymmetricKey(proto, keyID, wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: releaser.PubKey()})
	if err != nil || hx(sdkKey.ToBytes()) != hx(sdkKey2.ToBytes()) {
		return errors.New("the SDK derives different keys on the two sides")
	}
	body := payload[102:]
	released, err := aesgcm.AESGCMDecrypt(body[32:len(body)-16], unhex(brcShared), body[:32], []byte{}, body[len(body)-16:])
	if err != nil || hx(released) != brcScalar {
		return errors.New("the printed payload no longer opens under the printed value used as the key")
	}
	rw, err := wallet.NewCompletedProtoWallet(reader)
	if err != nil {
		return err
	}
	_, werr := rw.Decrypt(context.Background(), wallet.DecryptArgs{EncryptionArgs: wallet.EncryptionArgs{ProtocolID: proto, KeyID: keyID,
		Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeOther, Counterparty: releaser.PubKey()}}, Ciphertext: body}, "")
	if werr == nil || hx(sdkKey.ToBytes()) == brcShared {
		return errors.New("the SDK now opens BRC-369's release payload: update the vector file and the follow-up record")
	}

	// The epochs case is printed as commitments only; it is run on two epoch
	// keys of the scenario's group.
	e0, e1 := GroupEpochs[0], GroupEpochs[1]
	room := []byte("an epoch's content, readable by whoever held that epoch's key")
	c0, err := secrec.Seal(e0.Key, salt, brcSegment, room)
	if err != nil {
		return err
	}
	c1, err := secrec.Seal(e1.Key, salt, brcSegment, room)
	if err != nil {
		return err
	}
	_, on1 := secrec.OpenSegments(e0.Key, salt, brcSegment, c1)
	got0, on0 := secrec.OpenSegments(e0.Key, salt, brcSegment, c0)
	if !errors.Is(on1, secrec.ErrTag) || on0 != nil || !bytes.Equal(got0, room) {
		return errors.New("the epochs case")
	}
	return put(files, "brc369-v1.json", map[string]any{
		"note": "BRC-369's own test vectors. Every row of reproduced gives the value the document prints and the value recomputed here, " +
			"through this codec where the codec has the function and through the SDK's primitives otherwise; the generator fails if a row stops matching. " +
			"The document's keys and draws are SHA-256 of the labels under labels. notReproduced lists what does not match and why.",
		"labels": map[string]string{"publisher": brcLabelAuthor, "releaser": brcLabelReleaser, "recipient": brcLabelReader,
			"salt": brcLabelSalt, "substitutedKey": brcLabelFraud, "proofNonce": brcLabelNonce},
		"contentKey": brcScalar,
		"plaintext":  map[string]string{"text": brcPlaintext, "note": "not printed in the document: recovered by opening the printed ciphertext with the printed key"},
		"ciphertext": brcCipher,
		"descriptor": brcDescriptor,
		"payload":    brcPayload,
		"reproduced": checks,
		"verification": map[string]any{
			"note":            "section 5.3's three checks through this codec, on the printed ciphertext with the printed key",
			"ciphertextHash":  "passes",
			"keyCommitment":   "passes",
			"authentication":  "passes",
			"signatureVerify": true,
			"brc94Releaser":   true,
			"brc94Publisher":  false,
		},
		"substitutedKey": map[string]any{
			"note":           "section 5.4, as the document made it: the plaintext sealed under another scalar, the hash and locator updated; checked against the committed key",
			"scalar":         hx(fraudKey[:]),
			"ciphertext":     hx(fraudCT),
			"ciphertextHash": map[bool]string{true: "passes", false: "FAILS"}[check1],
			"keyCommitment":  map[bool]string{true: "passes", false: "FAILS"}[check2],
			"authentication": map[bool]string{true: "passes", false: "FAILS"}[tagErr == nil],
			"verdict":        secrec.Reason(ferr),
		},
		"notReproduced": []map[string]string{
			{"value": "the release payload's shared secret, and the payload itself",
				"printed":  brcShared,
				"computed": hx(sdkKey.ToBytes()),
				"why": "the SDK's BRC-2 key for the printed parties, protocol and key id (the same on both sides) is not the printed value, and a wallet's decrypt of the " +
					"printed payload under section 5.2's parameters fails. The printed value opens the payload to the content key when it is used directly as the " +
					"AES-256-GCM key; how the document derived it is not stated. The payload also starts 33104242 where the SDKs write 42421033"},
			{"value": "the epoch 0 and epoch 1 commitments and content ids", "why": "the document prints the commitments and not the epoch keys or descriptors, and no label reproduces them"},
			{"value": "the payload's 32-byte IV", "why": "a random draw; no label reproduces it"},
		},
		"releasePayload": map[string]any{
			"opensWithPrintedValueAsKey": hx(released),
			"sdkDerivedKey":              hx(sdkKey.ToBytes()),
			"sdkWalletDecrypt":           "fails",
			"printedHeader":              hx(payload[:4]),
			"sdkHeader":                  "42421033",
			"usedHere":                   "no: this application writes no such payload and reads none; epoch keys are released by the group substrate through the SDK",
		},
		"epochsSameShape": map[string]any{
			"note":         "section 8, on two epoch keys of the scenario's group used as BRC-369 content keys",
			"epoch0Key":    hx(e0.Key[:]),
			"epoch1Key":    hx(e1.Key[:]),
			"plaintext":    hx(room),
			"salt":         brcSalt,
			"segment":      brcSegment,
			"epoch0Cipher": hx(c0),
			"epoch1Cipher": hx(c1),
			"epoch0KeyOn1": map[bool]string{true: "reads", false: "FAILS"}[on1 == nil],
			"epoch0KeyOn0": map[bool]string{true: "reads", false: "FAILS"}[on0 == nil],
		},
	})
}

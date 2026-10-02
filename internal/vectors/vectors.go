package vectors

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/lightwebinc/bcommon/pushdrop"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// Names returns the file names in a stable order.
func Names(files map[string][]byte) []string {
	out := make([]string, 0, len(files))
	for n := range files {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func toJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Generate builds every vector file. It fails when a check stops holding.
func Generate() (map[string][]byte, error) {
	s, err := Build()
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, f := range []func(*Scenario, map[string][]byte) error{
		genDerivation, genBRC369, genKeyed, genSecret, genVault, genAudit, genRefusal, genQuery, genScript,
	} {
		if err := f(s, files); err != nil {
			return nil, err
		}
	}
	return files, nil
}

func put(files map[string][]byte, name string, v any) error {
	b, err := toJSON(v)
	if err != nil {
		return err
	}
	files[name] = b
	return nil
}

func putHex(files map[string][]byte, name string, b []byte) {
	files[name] = []byte(hx(b) + "\n")
}

// ---- derivation-v1.json ----

func genDerivation(s *Scenario, files map[string][]byte) error {
	ctx := context.Background()
	short := pushdrop.Derivation{Protocol: wallet.Protocol{SecurityLevel: 1, Protocol: "bsec"}, KeyID: secrec.KeyVault}
	refusal := short.Validate()
	if refusal == nil {
		return errors.New("go-sdk no longer refuses a protocol name under five characters")
	}
	derivations := []pushdrop.Derivation{secrec.VaultDerivation, secrec.SecretDerivation, secrec.ChainDerivation, secrec.FundDerivation}
	for _, d := range derivations {
		if err := d.Validate(); err != nil {
			return err
		}
	}
	type derivedKey struct {
		Party    string `json:"party"`
		Identity string `json:"identityKey"`
		Vault    string `json:"vault"`
		Secret   string `json:"secret"`
		Chain    string `json:"chain"`
	}
	type privKey struct {
		Party string `json:"party"`
		Priv  string `json:"privateKey"`
	}
	var keys []derivedKey
	var privs []privKey
	forSelf := true
	for _, p := range []Party{Org, Alice, Bob, Carol, Dave} {
		privs = append(privs, privKey{p.Name, hx(p.Priv.Serialize())})
		dk := derivedKey{Party: p.Name, Identity: hx(p.Pub())}
		for _, x := range []struct {
			d   pushdrop.Derivation
			out *string
		}{{secrec.VaultDerivation, &dk.Vault}, {secrec.SecretDerivation, &dk.Secret}, {secrec.ChainDerivation, &dk.Chain}} {
			k, err := x.d.ExpectedLockingKey(p.Priv.PubKey())
			if err != nil {
				return err
			}
			// The owner's own wallet derives the same key (forSelf).
			mine, err := p.Wallet().GetPublicKey(ctx, wallet.GetPublicKeyArgs{EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID: x.d.Protocol, KeyID: x.d.KeyID, Counterparty: pushdrop.Anyone()}, ForSelf: &forSelf}, "")
			if err != nil {
				return err
			}
			if !bytes.Equal(mine.PublicKey.Compressed(), k.Compressed()) {
				return fmt.Errorf("%s: owner and reader derive different %s keys", p.Name, x.d.KeyID)
			}
			*x.out = hx(k.Compressed())
		}
		keys = append(keys, dk)
	}
	// The self wrap's derivation: a wallet's own Encrypt and the vector
	// path with a fixed IV derive one key, and no other identity opens it.
	cid := label("content-id/derivation")
	k := label("key/derivation")
	fixed, err := secrec.WrapToSelfWithIV(Org.Priv, cid, k, label("iv/derivation"))
	if err != nil {
		return err
	}
	if got, err := secrec.UnwrapFromSelf(ctx, Org.Wallet(), cid, fixed, secrec.Commitment(k)); err != nil || got != k {
		return fmt.Errorf("the owner's wallet does not open a self wrap: %v", err)
	}
	if _, err := secrec.UnwrapFromSelf(ctx, Alice.Wallet(), cid, fixed, secrec.Commitment(k)); secrec.Reason(err) != "undecryptable" {
		return fmt.Errorf("another wallet opened a self wrap: %v", err)
	}
	live, err := secrec.WrapToSelf(ctx, Org.Wallet(), cid, k)
	if err != nil {
		return err
	}
	if got, err := secrec.UnwrapFromSelf(ctx, Org.Wallet(), cid, live, secrec.Commitment(k)); err != nil || got != k {
		return fmt.Errorf("a wallet's own self wrap does not open: %v", err)
	}
	if _, err := secrec.UnwrapFromSelf(ctx, Org.Wallet(), label("content-id/other"), fixed, secrec.Commitment(k)); secrec.Reason(err) != "undecryptable" {
		return errors.New("a self wrap opened under another content id")
	}
	// Crypts: one readable part, two suffixes; and one suffix drawn from
	// fixed bytes through the rejection rule.
	draw := bytes.NewReader(append([]byte{250, 251, 0, 25, 233, 234, 1, 2, 3, 4, 5, 6, 7}, make([]byte, 16)...))
	drawn, err := secrec.NewCrypt("example_crypt", draw)
	if err != nil {
		return err
	}
	return put(files, "derivation-v1.json", map[string]any{
		"note": "Public test identities, never for real use. Every key under derivedKeys is derived with counterparty anyone, " +
			"so a reader computes it from the identity key alone; the owner's wallet derives the same key with forSelf.",
		"registry": map[string]any{
			"protocol":         []any{1, secrec.ProtocolName},
			"keyIds":           []string{secrec.KeyVault, secrec.KeySecret, secrec.KeyChain, secrec.KeyFund},
			"invoices":         []string{"1-bsecret-vault", "1-bsecret-secret", "1-bsecret-chain", "1-bsecret-fund"},
			"selfProtocol":     []any{2, secrec.SelfProtocolName},
			"tagVault":         hx(secrec.TagVault),
			"tagFunding":       hx(secrec.TagFunding),
			"magicVault":       hx(secrec.MagicVault),
			"magicSecret":      hx(secrec.MagicSecret),
			"magicPayload":     hx(secrec.MagicPayload),
			"topicPrefix":      secrec.TopicPrefix,
			"lookupService":    secrec.LookupService,
			"domainVaultId":    secrec.DomainVaultID,
			"domainSecretId":   secrec.DomainSecretID,
			"domainEpochWrap":  secrec.DomainEpochWrap,
			"domainSymmetric":  secrec.DomainSymmetric,
			"domainCommitment": secrec.DomainCommitment,
			"defaultLabels":    secrec.DefaultLabels,
			"anyoneKey":        hx(secrec.AnyoneKey()),
		},
		"refusedProtocol": map[string]any{"protocol": []any{1, "bsec"}, "sdkError": refusal.Error(),
			"note": "a protocol name under five characters cannot derive; bsecret's own name is long enough to be its protocol name"},
		"identities":  privs,
		"derivedKeys": keys,
		"selfWrap": map[string]any{
			"contentId":    hx(cid[:]),
			"keyId":        secrec.SelfKeyID(cid),
			"invoice":      secrec.SelfInvoice(cid),
			"counterparty": "self",
			"key":          hx(k[:]),
			"iv":           hx(func() []byte { iv := label("iv/derivation"); return iv[:] }()),
			"wrap":         hx(fixed),
			"opens":        map[string]string{"org": "opens", "alice": "undecryptable", "org, another content id": "undecryptable"},
		},
		"ids": map[string]any{
			"genesisOutpoint": displayHex(s.Genesis) + ".0",
			"genesisTxid":     hx(s.Genesis[:]),
			"vaultId":         hx(s.VaultID[:]),
			"vaultIdRule":     "SHA-256(domainVaultId || txid in hash byte order || output index as four bytes big-endian)",
			"secretIdRule":    "SHA-256(domainSecretId || vault id || name)",
			"secrets": func() map[string]string {
				out := map[string]string{}
				for _, n := range []string{"db/password", "api/token", "tls/key", "ssh/deploy-key"} {
					id, _ := secrec.SecretID(s.VaultID, n)
					out[n] = hx(id[:])
				}
				return out
			}(),
		},
		"crypts": map[string]any{
			"vectors":       Crypt,
			"topic":         secrec.Topic(Crypt),
			"sameNameOther": "example_crypt_qzxkvbmwtr",
			"drawnFromBytes": map[string]any{
				"bytes":  "fafb0019e9ea01020304050607",
				"rule":   "a byte below 234 gives the letter a + byte mod 26; 234 to 255 is skipped",
				"result": drawn,
			},
		},
		"group": map[string]any{
			"note":  "The vault's group and its epochs, as the group substrate's own golden vectors give them. The keys are stand-ins for random draws.",
			"hall":  Hall,
			"group": hx(GroupID[:]),
			"epochs": func() []map[string]any {
				var out []map[string]any
				for _, e := range GroupEpochs {
					if secrec.SymmetricKey(e.Key) != e.Symmetric || secrec.Commitment(e.Key) != e.Commitment {
						panic("a group epoch's values no longer reproduce")
					}
					out = append(out, map[string]any{"epoch": e.Epoch, "key": hx(e.Key[:]), "symmetricKey": hx(e.Symmetric[:]),
						"commitment": hx(e.Commitment[:]), "epochId": hx(e.EpochID[:]), "began": e.Began, "holders": e.Holders})
				}
				return out
			}(),
		},
	})
}

// ---- keyed-v1.json: the three checks, case by case ----

func genKeyed(s *Scenario, files map[string][]byte) error {
	v := s.Versions["db/password@1"]
	rec := *v.Rec
	sym := GroupEpochs[0].Symmetric
	type cv struct {
		Label      string   `json:"label"`
		Faults     []string `json:"faults"`
		Record     string   `json:"record,omitempty"`
		Ciphertext string   `json:"ciphertext"`
		Verdict    string   `json:"verdict"`
		Names      string   `json:"names"`
	}
	var cases []cv
	// add reads r with ct as a member of epoch 0 does: check 1, the wrap,
	// the commitment, the tags, the payload, in that order.
	add := func(lbl string, faults []string, r *secrec.Secret, ct []byte, want, names string) error {
		_, err := secrec.ReadAsMember(r, ct, sym)
		got := "opens"
		if err != nil {
			got = secrec.Reason(err)
		}
		if got != want {
			return fmt.Errorf("keyed %q: got %q (%v), want %q", lbl, got, err, want)
		}
		c := cv{Label: lbl, Faults: faults, Ciphertext: hx(ct), Verdict: got, Names: names}
		if r != &rec {
			raw, err := r.Encode()
			if err != nil {
				return fmt.Errorf("keyed %q: %w", lbl, err)
			}
			c.Record = hx(raw)
		}
		cases = append(cases, c)
		return nil
	}
	// rewrap is the record with its epoch wrap replaced by a wrap of k.
	rewrap := func(base secrec.Secret, k [32]byte, tag string) (*secrec.Secret, error) {
		cid, err := base.ContentID()
		if err != nil {
			return nil, err
		}
		w, err := secrec.WrapToEpochWithIV(sym, cid, k, label("iv/keyed/%s", tag))
		if err != nil {
			return nil, err
		}
		base.Wrap = w
		return &base, nil
	}
	host := "the host or store that served the bytes"
	if err := add("the committed key wrapped, the committed ciphertext", []string{}, &rec, v.Cipher, "opens", "nobody"); err != nil {
		return err
	}
	flipped := append([]byte(nil), v.Cipher...)
	flipped[10] ^= 1
	if err := add("one ciphertext byte changed by whoever served it", []string{"ciphertext"}, &rec, flipped, "hash", host); err != nil {
		return err
	}
	if err := add("a ciphertext cut short by whoever served it", []string{"ciphertext"}, &rec, v.Cipher[:len(v.Cipher)-1], "hash", host); err != nil {
		return err
	}
	other := label("key/other")
	wrongKey, err := rewrap(rec, other, "other")
	if err != nil {
		return err
	}
	if err := add("another key wrapped than the committed one", []string{"wrap"}, wrongKey, v.Cipher, "commitment", "the owner, who wrapped it"); err != nil {
		return err
	}
	notScalar, err := rewrap(rec, [32]byte{}, "zero")
	if err != nil {
		return err
	}
	if err := add("a value wrapped that is not a scalar", []string{"wrap"}, notScalar, v.Cipher, "undecryptable", "the owner, who wrapped it"); err != nil {
		return err
	}
	// The substituted key (BRC-369 section 5.4): the owner encrypts under a
	// key other than the one it commits to and wraps, and the record is
	// otherwise consistent. Checks 1 and 2 pass and check 3 fails.
	fraudCT, err := secrec.Seal(other, rec.Salt, rec.Segment, v.Plain)
	if err != nil {
		return err
	}
	fraud := rec
	fraud.Inline, fraud.Length, fraud.Hash = fraudCT, uint64(len(fraudCT)), sha256sum(fraudCT)
	fraudRec, err := rewrap(fraud, v.Key, "fraud")
	if err != nil {
		return err
	}
	if err := add("the owner encrypted under a key it did not commit to", []string{"ciphertext key"}, fraudRec, fraudCT, "tag",
		"the owner, provably: anyone holding the key repeats the failure"); err != nil {
		return err
	}
	// A payload under another name: every check of BRC-369 passes and the
	// name does not hash to the record's id.
	wrongName := &secrec.Payload{Name: "db/other", Value: v.Payload.Value}
	wn, err := paddedPayload(wrongName)
	if err != nil {
		return err
	}
	wnCT, err := secrec.Seal(v.Key, rec.Salt, rec.Segment, wn)
	if err != nil {
		return err
	}
	named := rec
	named.Inline, named.Length, named.Hash = wnCT, uint64(len(wnCT)), sha256sum(wnCT)
	namedRec, err := rewrap(named, v.Key, "named")
	if err != nil {
		return err
	}
	if err := add("a payload whose name is not the one the id hashes", []string{"payload"}, namedRec, wnCT, "payload", "the owner"); err != nil {
		return err
	}
	// Two faults at once pin the order: the earlier check gives the verdict.
	if err := add("a changed ciphertext and another key wrapped: check 1 is decided first", []string{"ciphertext", "wrap"},
		wrongKey, flipped, "hash", host); err != nil {
		return err
	}
	if err := add("a changed ciphertext and a wrapped value that is not a scalar: check 1 is decided first", []string{"ciphertext", "wrap"},
		notScalar, flipped, "hash", host); err != nil {
		return err
	}
	fraudOther, err := rewrap(fraud, label("key/third"), "third")
	if err != nil {
		return err
	}
	if err := add("another key wrapped and a ciphertext under a key not committed to: check 2 is decided before check 3", []string{"wrap", "ciphertext key"},
		fraudOther, fraudCT, "commitment", "the owner, who wrapped it"); err != nil {
		return err
	}
	fraudNamed := named
	fraudNamedCT, err := secrec.Seal(other, rec.Salt, rec.Segment, wn)
	if err != nil {
		return err
	}
	fraudNamed.Inline, fraudNamed.Length, fraudNamed.Hash = fraudNamedCT, uint64(len(fraudNamedCT)), sha256sum(fraudNamedCT)
	fraudNamedRec, err := rewrap(fraudNamed, v.Key, "fraud-named")
	if err != nil {
		return err
	}
	if err := add("a ciphertext under a key not committed to, holding another name: check 3 is decided before the payload", []string{"ciphertext key", "payload"},
		fraudNamedRec, fraudNamedCT, "tag", "the owner, provably"); err != nil {
		return err
	}
	// Segments: a short multi-segment ciphertext written out, and segments
	// swapped by an owner who re-hashes.
	var salt [secrec.SaltLen]byte
	copy(salt[:], unhex("0a0b0c0d"))
	msg := []byte("forty bytes of plaintext, in 16s: 0123456")
	mk := label("key/segments")
	mct, err := secrec.Seal(mk, salt, 16, msg)
	if err != nil {
		return err
	}
	back, err := secrec.OpenSegments(mk, salt, 16, mct)
	if err != nil || !bytes.Equal(back, msg) {
		return errors.New("a segmented ciphertext does not open")
	}
	swapped := append(append(append([]byte(nil), mct[32:64]...), mct[:32]...), mct[64:]...)
	if _, err := secrec.OpenSegments(mk, salt, 16, swapped); secrec.Reason(err) != "tag" {
		return errors.New("swapped segments opened")
	}
	type lv struct {
		Length  uint64 `json:"length"`
		Segment uint64 `json:"segment"`
		Plain   uint64 `json:"plaintext,omitempty"`
		Verdict string `json:"verdict"`
	}
	var lengths []lv
	for _, c := range []struct{ length, segment uint64 }{{17, 16}, {32, 16}, {33, 16}, {48, 16}, {49, 16}, {64, 16}, {16, 16}, {0, 16}, {40, 15}, {272, 16384}} {
		n, err := secrec.PlainLength(c.length, c.segment)
		l := lv{Length: c.length, Segment: c.segment, Plain: n, Verdict: "accepted"}
		if err != nil {
			l.Verdict = secrec.Reason(err)
		}
		lengths = append(lengths, l)
	}
	msym := secrec.SymmetricKey(mk)
	ivs := []string{}
	for i := uint64(0); i < 3; i++ {
		iv := secrec.SegmentIV(salt, i)
		ivs = append(ivs, hx(iv[:]))
	}
	return put(files, "keyed-v1.json", map[string]any{
		"note": "A member's read of one version, in the order of spec section 7.2: the ciphertext's length and hash, the wrap under the named epoch's key, " +
			"the key against the commitment, every segment's tag, then the payload. The cases are the scenario's first version of db/password with one or two " +
			"things changed (faults); a case with a record carries the whole changed record, and a case without one uses record. Every case is read with epochSymmetricKey.",
		"record":            hx(v.Raw),
		"epochSymmetricKey": hx(sym[:]),
		"contentId":         hx(v.CID[:]),
		"commitment":        hx(rec.Commitment[:]),
		"cases":             cases,
		"segments": map[string]any{
			"key":          hx(mk[:]),
			"symmetricKey": hx(msym[:]),
			"salt":         hx(salt[:]),
			"segment":      16,
			"plaintext":    hx(msg),
			"ivs":          ivs,
			"ciphertext":   hx(mct),
			"layout":       "16 + 16, 16 + 16, 8 + 16 bytes: each segment's ciphertext then its tag",
			"swapped":      map[string]string{"ciphertext": hx(swapped), "verdict": "tag"},
		},
		"lengths": lengths,
	})
}

// ---- secret-v1.json ----

func genSecret(s *Scenario, files map[string][]byte) error {
	ctx := context.Background()
	type sv struct {
		Label      string            `json:"label"`
		File       string            `json:"file"`
		Length     int               `json:"recordLength"`
		Name       string            `json:"name"`
		ID         string            `json:"id"`
		Version    uint64            `json:"version"`
		Previous   string            `json:"previous"`
		SecLabel   string            `json:"secretLabel"`
		Epoch      uint64            `json:"epoch"`
		EpochID    string            `json:"epochId"`
		Key        string            `json:"key"`
		Symmetric  string            `json:"symmetricKey"`
		Commitment string            `json:"commitment"`
		Salt       string            `json:"salt"`
		Segment    uint64            `json:"segment"`
		Payload    string            `json:"payload,omitempty"`
		PayloadLen int               `json:"payloadLength"`
		Value      string            `json:"value,omitempty"`
		ValueNote  string            `json:"valueNote,omitempty"`
		Type       string            `json:"type"`
		Pad        int               `json:"padBytes"`
		Hash       string            `json:"hash"`
		CipherLen  uint64            `json:"length"`
		Inline     bool              `json:"inline"`
		Locator    string            `json:"locator,omitempty"`
		ContentID  string            `json:"contentId"`
		SelfKeyID  string            `json:"selfKeyId"`
		SelfIV     string            `json:"selfIv"`
		WrapKey    string            `json:"epochWrapKey"`
		WrapIV     string            `json:"epochWrapIv"`
		Opens      map[string]string `json:"opens"`
	}
	var out []sv
	for _, key := range s.Order {
		v := s.Versions[key]
		ge := GroupEpochs[v.Epoch]
		sym := secrec.SymmetricKey(v.Key)
		wk := secrec.EpochWrapKey(ge.Symmetric, v.CID)
		x := sv{
			Label: fmt.Sprintf("%s version %d, keyed under epoch %d", v.Name, v.Number, v.Epoch), File: v.File, Length: len(v.Raw),
			Name: v.Name, ID: hx(v.Rec.ID[:]), Version: v.Number, Previous: hx(v.Rec.Previous[:]), SecLabel: v.Rec.Label,
			Epoch: v.Epoch, EpochID: hx(ge.EpochID[:]), Key: hx(v.Key[:]), Symmetric: hx(sym[:]), Commitment: hx(v.Rec.Commitment[:]),
			Salt: hx(v.Rec.Salt[:]), Segment: v.Rec.Segment, PayloadLen: len(v.Plain), Type: v.Payload.Type, Pad: len(v.Payload.Pad),
			Hash: hx(v.Rec.Hash[:]), CipherLen: v.Rec.Length, Inline: v.Rec.Inline != nil, ContentID: hx(v.CID[:]),
			SelfKeyID: secrec.SelfKeyID(v.CID), SelfIV: hx(v.SelfIV[:]), WrapKey: hx(wk[:]), WrapIV: hx(v.WrapIV[:]), Opens: map[string]string{},
		}
		if v.Rec.Inline != nil {
			x.Payload, x.Value = hx(v.Plain), string(v.Payload.Value)
		} else {
			x.ValueNote = "1250 blocks of SHA-256(\"bsecret/vector/big/\" || i as four bytes big-endian), i from 0; the ciphertext is not carried and is found by its hash"
			x.Locator = secrec.Locator(v.Rec.Hash)
		}
		// Who opens it. The owner's wallet through the self wrap; each
		// member through the key of every epoch it holds. A member opens a
		// version exactly when it holds the key of the version's epoch.
		if _, err := secrec.ReadAsOwner(ctx, Org.Wallet(), v.Rec, v.Cipher); err != nil {
			return err
		}
		x.Opens["org (self wrap)"] = "opens"
		for _, m := range []Party{Alice, Bob, Carol, Dave} {
			// A member opens the wrap only with the key of the epoch the
			// record names; a member that never held it has nothing to try.
			verdict := "no key for the epoch"
			if holds(m.Name, v.Epoch) {
				if _, err := secrec.ReadAsMember(v.Rec, v.Cipher, ge.Symmetric); err != nil {
					return fmt.Errorf("%s: %s holds epoch %d's key and does not read it: %v", key, m.Name, v.Epoch, err)
				}
				verdict = "opens"
			}
			// No other epoch's key opens it either.
			for _, e := range GroupEpochs {
				if e.Epoch == v.Epoch {
					continue
				}
				if _, err := secrec.UnwrapFromEpoch(e.Symmetric, v.CID, v.Rec.Wrap, v.Rec.Commitment); secrec.Reason(err) != "undecryptable" {
					return fmt.Errorf("%s opened under epoch %d's key: %v", key, e.Epoch, err)
				}
			}
			x.Opens[m.Name] = verdict
			if _, err := secrec.UnwrapFromSelf(ctx, m.Wallet(), v.CID, v.Rec.Self, v.Rec.Commitment); err == nil {
				return fmt.Errorf("%s: %s opened the self wrap", key, m.Name)
			}
		}
		out = append(out, x)
		putHex(files, v.File, v.Raw)
	}
	// The wrap is bound to its version: moved to another version's record
	// it does not open, even under the same epoch's key.
	a, b := s.Versions["db/password@1"], s.Versions["api/token@1"]
	if _, err := secrec.UnwrapFromEpoch(GroupEpochs[0].Symmetric, b.CID, a.Rec.Wrap, a.Rec.Commitment); secrec.Reason(err) != "undecryptable" {
		return errors.New("a wrap opened under another version's content id")
	}
	// The content id leaves out the wraps and the inline ciphertext, and
	// covers everything else, an unknown key included.
	alt := *a.Rec
	alt.Self, alt.Wrap = b.Rec.Self, b.Rec.Wrap
	if cid, _ := alt.ContentID(); cid != a.CID {
		return errors.New("the content id depends on a wrap")
	}
	unk := mutate(a.Raw, 40, "a later version's field")
	u, err := secrec.DecodeSecret(unk)
	if err != nil {
		return err
	}
	re, err := u.Encode()
	if err != nil || !bytes.Equal(re, unk) {
		return errors.New("an unknown key was not preserved")
	}
	ucid, _ := u.ContentID()
	if ucid == a.CID {
		return errors.New("the content id ignores an unknown key")
	}
	// Listing: each version against the token that lists it, and what a
	// reader refuses.
	type lv struct {
		Label   string `json:"label"`
		Record  string `json:"record"`
		Token   int    `json:"tokenSeq,omitempty"`
		TokenTo string `json:"token,omitempty"`
		Verdict string `json:"verdict"`
	}
	var listings []lv
	listedAt := map[string]int{"db/password@1": 0, "api/token@1": 0, "api/token@2": 1, "tls/key@1": 2, "db/password@2": 3,
		"api/token@3": 4, "ssh/deploy-key@1": 5, "db/password@3": 6, "api/token@4": 6, "ssh/deploy-key@2": 6}
	for _, key := range s.Order {
		seq, ok := listedAt[key]
		if !ok {
			return fmt.Errorf("%s: no token lists it", key)
		}
		if err := secrec.CheckListed(s.Vaults[seq], s.Versions[key].Rec); err != nil {
			return fmt.Errorf("%s against seq %d: %w", key, seq, err)
		}
		listings = append(listings, lv{Label: key + " against the token that lists it", Record: s.Versions[key].File, Token: seq, Verdict: "listed"})
	}
	refuse := func(lbl string, token *secrec.Vault, rec *secrec.Secret, file string, seq int) error {
		if err := secrec.CheckListed(token, rec); secrec.Reason(err) != "listing" {
			return fmt.Errorf("listing %q: %v", lbl, err)
		}
		x := lv{Label: lbl, Record: file, Verdict: "listing"}
		if seq >= 0 {
			x.Token = seq
		} else {
			raw, err := token.Encode()
			if err != nil {
				return err
			}
			x.TokenTo = hx(raw)
		}
		listings = append(listings, x)
		return nil
	}
	db2, db3 := s.Versions["db/password@2"], s.Versions["db/password@3"]
	if err := refuse("an older version against a token that lists the next one", s.Vaults[6], db2.Rec, db2.File, 6); err != nil {
		return err
	}
	if err := refuse("a version against a token that does not change its secret", s.Vaults[5], db3.Rec, db3.File, 5); err != nil {
		return err
	}
	// A token that claims a re-keying it did not make: it acknowledges
	// epoch 2 and lists the content id of a record keyed under epoch 1.
	lying := *s.Vaults[6]
	lying.Update = append([]secrec.Entry(nil), s.Vaults[6].Update...)
	for i := range lying.Update {
		if lying.Update[i].ID == db2.Rec.ID {
			lying.Update[i] = entry(db2)
		}
	}
	if err := refuse("a token at epoch 2 that lists a record keyed under epoch 1", &lying, db2.Rec, db2.File, -1); err != nil {
		return err
	}
	relabel := *s.Vaults[0]
	relabel.Labels = []string{"internal", "public"}
	if err := refuse("a record whose label is not one of the vault's", &relabel, a.Rec, a.File, -1); err != nil {
		return err
	}
	// Successors: in an interval vault, the next version of the same secret
	// that no token lists yet, and what is not one. The scenario's records
	// are checked against interval twins of its tokens.
	interval := func(seq int) *secrec.Vault {
		v := clone(s.Vaults[seq])
		v.Anchor = secrec.AnchorInterval
		return v
	}
	type sv2 struct {
		Label   string `json:"label"`
		Token   string `json:"token"`
		Prev    string `json:"prev"`
		Next    string `json:"next"`
		Verdict string `json:"verdict"`
	}
	var successors []sv2
	sameKey := *db2.Rec
	sameKey.Commitment = a.Rec.Commitment
	sameKey.Epoch, sameKey.EpochID = 0, GroupEpochs[0].EpochID
	otherID := *db2.Rec
	otherID.EpochID = label("epoch-id/elsewhere")
	db1 := a
	for _, c := range []struct {
		lbl        string
		token      *secrec.Vault
		prev, next *secrec.Secret
		want       string
	}{
		{"version 2 after version 1, keyed under an epoch the vault has not acknowledged yet", interval(0), db1.Rec, db2.Rec, "successor of it"},
		{"version 2 after version 1, the vault at the successor's epoch", interval(3), db1.Rec, db2.Rec, "successor of it"},
		{"version 3 after version 2", interval(3), db2.Rec, db3.Rec, "successor of it"},
		{"the same, in a per-version vault", s.Vaults[0], db1.Rec, db2.Rec, "successor"},
		{"version 3 after version 1: a version is skipped", interval(0), db1.Rec, db3.Rec, "successor"},
		{"version 1 after version 2: the order reversed", interval(0), db2.Rec, db1.Rec, "successor"},
		{"another secret's version 2", interval(0), db1.Rec, s.Versions["api/token@2"].Rec, "successor"},
		{"a successor keyed under an epoch before the vault's", interval(6), db1.Rec, db2.Rec, "successor"},
		{"a successor with its predecessor's commitment", interval(0), db1.Rec, &sameKey, "successor"},
		{"a successor at the vault's epoch under another epoch id", interval(3), db1.Rec, &otherID, "successor"},
		{"a successor whose label is not one of the vault's", func() *secrec.Vault { v := interval(0); v.Labels = []string{"internal", "public"}; return v }(), db1.Rec, db2.Rec, "successor"},
	} {
		err := secrec.CheckSuccessor(c.token, c.prev, c.next)
		got := "successor of it"
		if err != nil {
			got = secrec.Reason(err)
		}
		if got != c.want {
			return fmt.Errorf("successor %q: %s", c.lbl, got)
		}
		traw, err := c.token.Encode()
		if err != nil {
			return err
		}
		praw, err := c.prev.Encode()
		if err != nil {
			return err
		}
		nraw, err := c.next.Encode()
		if err != nil {
			return fmt.Errorf("successor %q: %w", c.lbl, err)
		}
		successors = append(successors, sv2{c.lbl, hx(traw), hx(praw), hx(nraw), got})
	}
	// Runs of unlisted versions: the longest that links; two records at one
	// version; a commitment that repeats further back than its predecessor.
	run, err := secrec.CheckLinks(interval(0), db1.Rec, []*secrec.Secret{db3.Rec, db2.Rec})
	if err != nil || len(run) != 2 || run[1].Version != 3 {
		return fmt.Errorf("links: %v", err)
	}
	run, err = secrec.CheckLinks(interval(0), db1.Rec, []*secrec.Secret{db3.Rec})
	if err != nil || len(run) != 0 {
		return fmt.Errorf("a run with a missing link: %v", err)
	}
	twin := *db2.Rec
	twin.Created++
	if _, err := secrec.CheckLinks(interval(0), db1.Rec, []*secrec.Secret{db2.Rec, &twin}); secrec.Reason(err) != "successor" {
		return errors.New("two records at one version were accepted")
	}
	reuse := *db3.Rec
	reuse.Commitment = db1.Rec.Commitment
	if err := secrec.CheckSuccessor(interval(0), db2.Rec, &reuse); err != nil {
		return fmt.Errorf("the reuse case is refused pairwise: %w", err)
	}
	if _, err := secrec.CheckLinks(interval(0), db1.Rec, []*secrec.Secret{db2.Rec, &reuse}); secrec.Reason(err) != "successor" {
		return errors.New("a commitment reused two versions back was accepted")
	}
	// The group's epochs: a token or a record names one the group began.
	var known []secrec.EpochEvent
	for _, e := range GroupEpochs {
		known = append(known, secrec.EpochEvent{Epoch: e.Epoch, EpochID: e.EpochID, Height: e.Height, Removed: e.Removed})
	}
	if secrec.CheckGroupEpoch(known, 1, GroupEpochs[1].EpochID) != nil ||
		secrec.Reason(secrec.CheckGroupEpoch(known, 1, GroupEpochs[0].EpochID)) != "listing" ||
		secrec.Reason(secrec.CheckGroupEpoch(known, 3, GroupEpochs[2].EpochID)) != "listing" ||
		secrec.Reason(secrec.CheckGroupEpoch(known[:2], 2, GroupEpochs[2].EpochID)) != "listing" {
		return errors.New("group epoch check")
	}
	// A mis-keyed version: the record names epoch 1 and its wrap is made
	// under epoch 0's key. Every check a host, an index or an auditor can
	// make passes. Only a holder of epoch 1's key sees it, as a wrap that
	// does not open under the key of the epoch the record names; a removed
	// member who tries its old key opens it.
	mis := *db2.Rec
	misWrap, err := secrec.WrapToEpochWithIV(GroupEpochs[0].Symmetric, db2.CID, db2.Key, db2.WrapIV)
	if err != nil {
		return err
	}
	mis.Wrap = misWrap
	misRaw, err := mis.Encode()
	if err != nil {
		return err
	}
	misBack, err := secrec.DecodeSecret(misRaw)
	if err != nil {
		return err
	}
	if cid, _ := misBack.ContentID(); cid != db2.CID {
		return errors.New("a wrap changed a content id")
	}
	if err := secrec.CheckListed(s.Vaults[3], misBack); err != nil {
		return fmt.Errorf("the mis-keyed record is not listed: %w", err)
	}
	if _, err := secrec.UnwrapFromEpoch(GroupEpochs[1].Symmetric, db2.CID, misBack.Wrap, misBack.Commitment); secrec.Reason(err) != "undecryptable" {
		return errors.New("the mis-keyed record opened under the epoch it names")
	}
	if k, err := secrec.UnwrapFromEpoch(GroupEpochs[0].Symmetric, db2.CID, misBack.Wrap, misBack.Commitment); err != nil || k != db2.Key {
		return errors.New("the mis-keyed record does not open under the earlier epoch's key")
	}
	return put(files, "secret-v1.json", map[string]any{
		"note": "Content keys, salts and IVs are fixed stand-ins for random draws: SHA-256(\"bsecret/vector/key/<name>/<version>\"), " +
			"the first four bytes of SHA-256(\"bsecret/vector/salt/<name>/<version>\"), SHA-256(\"bsecret/vector/iv/self/<name>/<version>\") and " +
			"SHA-256(\"bsecret/vector/iv/epoch/<name>/<version>\"). Payloads are padded to a multiple of 256 bytes. " +
			"opens: the owner through the self wrap, and each member through the key of the epoch the record names, when it was a member of that epoch. bob was removed when epoch 1 began.",
		"vault":      hx(s.VaultID[:]),
		"records":    out,
		"listings":   listings,
		"successors": successors,
		"links": []map[string]string{
			{"held": "versions 2 and 3 above the listed version 1", "verdict": "both link: the reader takes version 3"},
			{"held": "version 3 only", "verdict": "nothing links: the reader takes the listed version and says a later one exists"},
			{"held": "two different records at version 2", "verdict": "successor: the owner signed both, and the reader takes neither"},
			{"held": "version 2, and a version 3 with version 1's commitment", "verdict": "successor: a commitment repeats in the run"},
		},
		"groupEpoch": []map[string]any{
			{"epoch": 1, "epochId": hx(GroupEpochs[1].EpochID[:]), "verdict": "an epoch the group began"},
			{"epoch": 1, "epochId": hx(GroupEpochs[0].EpochID[:]), "verdict": "listing"},
			{"epoch": 3, "epochId": hx(GroupEpochs[2].EpochID[:]), "verdict": "listing"},
		},
		"misKeyed": map[string]any{
			"note": "db/password version 2 with its wrap made under epoch 0's key while the record names epoch 1. The content id does not cover the wrap, " +
				"so the record is listed and every check that needs no key passes. A reader opens a wrap only with the key of the epoch the record names.",
			"record":                 hx(misRaw),
			"contentId":              hx(db2.CID[:]),
			"listed":                 true,
			"underTheEpochItNames":   "undecryptable",
			"underTheEarlierEpoch":   "opens, which a conforming reader never tries",
			"names":                  "the owner: the reader verified the named epoch's key against the group's commitment, and the wrap does not open under it",
			"visibleToHostOrAuditor": false,
		},
		"wrapMoved": map[string]string{"wrap": "db/password version 1's", "against": "api/token version 1's content id, epoch 0's key",
			"verdict": "undecryptable"},
		"contentId": map[string]any{
			"rule":           "SHA-256 of the record's canonical encoding without keys 17, 18 and 19",
			"unknownKeyKept": map[string]string{"hex": hx(unk), "key": "40", "contentId": hx(ucid[:])},
		},
	})
}

// ---- audit-v1.json ----

func genAudit(s *Scenario, files map[string][]byte) error {
	var tokens []secrec.Mined
	for i, v := range s.Vaults {
		tokens = append(tokens, secrec.Mined{Vault: v, Txid: s.VaultTxids[i], Height: s.Heights[i]})
	}
	var epochs []secrec.EpochEvent
	for _, e := range GroupEpochs {
		epochs = append(epochs, secrec.EpochEvent{Epoch: e.Epoch, EpochID: e.EpochID, Height: e.Height, Removed: e.Removed})
	}
	rep := secrec.Audit(tokens, epochs)
	if !rep.OK {
		return fmt.Errorf("the scenario's audit fails: %+v", rep.Findings)
	}
	want := []secrec.Window{
		{Epoch: 1, Removed: true, Began: 1010, Acknowledged: 1012, Settled: 1013},
		{Epoch: 2, Removed: false, Began: 1030, Acknowledged: 1031, Settled: 1031},
	}
	if len(rep.Windows) != len(want) {
		return errors.New("audit windows")
	}
	for i := range want {
		if rep.Windows[i] != want[i] {
			return fmt.Errorf("audit window %d: %+v", i, rep.Windows[i])
		}
	}
	f := secrec.NewVaultFold()
	for _, v := range s.Vaults {
		f.Apply(v)
	}
	names := map[[32]byte]string{}
	for _, v := range s.Versions {
		names[v.Rec.ID] = v.Name
	}
	type ev struct {
		Seq       uint64  `json:"seq"`
		Height    uint32  `json:"height"`
		Kind      string  `json:"kind"`
		Secret    string  `json:"secret"`
		ID        string  `json:"id"`
		Version   uint64  `json:"version"`
		ContentID string  `json:"contentId,omitempty"`
		Epoch     uint64  `json:"epoch"`
		FromEpoch *uint64 `json:"fromEpoch,omitempty"`
	}
	var trail []ev
	for _, e := range f.Trail() {
		x := ev{Seq: e.Seq, Height: s.Heights[e.Seq], Kind: e.Kind, Secret: names[e.ID], ID: hx(e.ID[:]), Version: e.Version, Epoch: e.Epoch}
		if e.Kind != "retire" {
			x.ContentID = hx(e.ContentID[:])
		}
		if e.Kind != "create" {
			from := e.FromEpoch
			x.FromEpoch = &from
		}
		trail = append(trail, x)
	}
	type tv struct {
		Seq    uint64 `json:"seq"`
		Txid   string `json:"standInTxid"`
		Height uint32 `json:"height"`
		Epoch  uint64 `json:"epoch"`
		Count  uint64 `json:"count"`
		Stale  uint64 `json:"stale"`
		Status string `json:"status"`
	}
	var toks []tv
	for i, v := range s.Vaults {
		toks = append(toks, tv{v.Seq, hx(s.VaultTxids[i][:]), s.Heights[i], v.Epoch, v.Count, v.Stale, rep.Statuses[i]})
	}
	type wv struct {
		Epoch        uint64 `json:"epoch"`
		Removed      bool   `json:"removedAMember"`
		Began        uint32 `json:"groupBeganAtHeight"`
		Late         uint64 `json:"vaultTokensStillUnderAnEarlierEpoch"`
		Acknowledged uint32 `json:"vaultAcknowledgedAtHeight"`
		Settled      uint32 `json:"nothingUnderAnEarlierEpochAtHeight"`
		Stale        uint64 `json:"underAnEarlierEpochAtEnd"`
	}
	windows := func(ws []secrec.Window) []wv {
		out := []wv{}
		for _, w := range ws {
			out = append(out, wv{w.Epoch, w.Removed, w.Began, w.Late, w.Acknowledged, w.Settled, w.Stale})
		}
		return out
	}
	// A trail cut short reports what is still under an earlier epoch.
	cut := secrec.Audit(tokens[:4], epochs)
	if !cut.OK || len(cut.Windows) != 2 || cut.Windows[0].Settled != 0 || cut.Windows[0].Stale != 2 || cut.Windows[1].Acknowledged != 0 {
		return fmt.Errorf("audit of a trail cut at seq 3: %+v", cut)
	}
	// An owner that goes on writing under epoch 0 after the group began
	// epoch 1: every host admits the tokens, and the audit counts them.
	lateSet := map[[32]byte]secrec.Current{}
	for _, c := range foldSet(s.Vaults[:3]) {
		lateSet[c.ID] = c
	}
	late1 := nextToken(s.Vaults[2], s.VaultTxids[2], lateSet, 0,
		[]secrec.Entry{{ID: label("id/late"), Version: 1, ContentID: label("content-id/late/1"), Commitment: label("commitment/late/1")}}, nil, nil)
	late2 := nextToken(late1, label("txid/late/1"), lateSet, 0, nil,
		[]secrec.Entry{{ID: label("id/late"), Version: 2, ContentID: label("content-id/late/2"), Commitment: label("commitment/late/2")}}, nil)
	lateTokens := append(append([]secrec.Mined(nil), tokens[:3]...),
		secrec.Mined{Vault: late1, Txid: label("txid/late/1"), Height: 1020}, secrec.Mined{Vault: late2, Txid: label("txid/late/2"), Height: 1500})
	lateRep := secrec.Audit(lateTokens, epochs)
	if !lateRep.OK || lateRep.Windows[0].Late != 2 || lateRep.Windows[0].Acknowledged != 0 || lateRep.Windows[0].Stale != 4 {
		return fmt.Errorf("audit of a vault that never acknowledges: %+v", lateRep)
	}
	// Trails an audit refuses.
	type rv struct {
		Label    string   `json:"label"`
		Problems []string `json:"problems"`
	}
	var refused []rv
	refuse := func(lbl string, toks []secrec.Mined, eps []secrec.EpochEvent, wantProblem string) error {
		r := secrec.Audit(toks, eps)
		if r.OK {
			return fmt.Errorf("an audit passed: %s", lbl)
		}
		x := rv{Label: lbl}
		found := false
		for _, f := range r.Findings {
			p := f.Problem
			if f.Detail != "" {
				p += ": " + f.Detail
			}
			x.Problems = append(x.Problems, fmt.Sprintf("seq %d: %s", f.Seq, p))
			found = found || f.Problem == wantProblem
		}
		if !found {
			return fmt.Errorf("audit %q: no %s among %v", lbl, wantProblem, x.Problems)
		}
		refused = append(refused, x)
		return nil
	}
	mined := func(v *secrec.Vault, txid [32]byte, h uint32) secrec.Mined {
		return secrec.Mined{Vault: v, Txid: txid, Height: h}
	}
	with := func(n int, m secrec.Mined) []secrec.Mined {
		out := append([]secrec.Mined(nil), tokens...)
		out[n] = m
		return out
	}
	bad := *s.Vaults[3]
	bad.EpochID = label("epoch-id/elsewhere")
	if err := refuse("a token whose epoch id is not the one the group gave that epoch", with(3, mined(&bad, s.VaultTxids[3], 1012))[:4], epochs, secrec.AuditEpoch); err != nil {
		return err
	}
	if err := refuse("a token that acknowledges an epoch at a height below the block that began it", with(3, mined(s.Vaults[3], s.VaultTxids[3], 1009))[:4], epochs, secrec.AuditEpoch); err != nil {
		return err
	}
	if err := refuse("a token that names an epoch the group has not begun", tokens, epochs[:2], secrec.AuditEpoch); err != nil {
		return err
	}
	disorder := append([]secrec.EpochEvent(nil), epochs...)
	disorder[2].Height = 1005
	if err := refuse("group epochs out of height order", tokens, disorder, secrec.AuditGroup); err != nil {
		return err
	}
	if err := refuse("a group epoch given twice", tokens, append(append([]secrec.EpochEvent(nil), epochs...), epochs[1]), secrec.AuditGroup); err != nil {
		return err
	}
	if err := refuse("a group epoch missing from the middle", tokens, []secrec.EpochEvent{epochs[0], epochs[2]}, secrec.AuditGroup); err != nil {
		return err
	}
	if err := refuse("no tokens", nil, epochs, secrec.AuditEmpty); err != nil {
		return err
	}
	if err := refuse("a trail that does not start at seq 0", tokens[1:], epochs, secrec.AuditFirst); err != nil {
		return err
	}
	if err := refuse("a token left out of the middle", append(append([]secrec.Mined(nil), tokens[:2]...), tokens[3:]...), epochs, secrec.AuditTransition); err != nil {
		return err
	}
	if err := refuse("a token whose prev is not the txid of the one before it", with(1, mined(s.Vaults[1], label("txid/elsewhere"), 1003)), epochs, secrec.AuditTransition); err != nil {
		return err
	}
	if err := refuse("a token mined below the one it spends", with(1, mined(s.Vaults[1], s.VaultTxids[1], 1000)), epochs, secrec.AuditHeight); err != nil {
		return err
	}
	// A secret already re-keyed is updated again while the vault is in
	// debt, and counted as clearing debt: a host admits it, the fold does
	// not, and the vault's claim that nothing is stale is not believed.
	dset := map[[32]byte]secrec.Current{}
	for _, c := range foldSet(s.Vaults[:4]) {
		dset[c.ID] = c
	}
	dbID, _ := secrec.SecretID(s.VaultID, "db/password")
	dbl := nextToken(s.Vaults[3], s.VaultTxids[3], dset, 1, nil,
		[]secrec.Entry{{ID: dbID, Version: 3, ContentID: label("content-id/double"), Commitment: label("commitment/double")}}, nil)
	dbl.Stale = 1
	if err := secrec.CheckVaultTransition(s.Vaults[3], s.VaultTxids[3], dbl); err != nil {
		return fmt.Errorf("the double re-keying is refused by a host: %w", err)
	}
	if err := refuse("a secret already re-keyed updated again while in debt and counted as clearing it", append(append([]secrec.Mined(nil), tokens[:4]...), mined(dbl, label("txid/double"), 1013)), epochs, secrec.AuditStatus); err != nil {
		return err
	}
	var eps []map[string]any
	for _, e := range GroupEpochs {
		eps = append(eps, map[string]any{"epoch": e.Epoch, "epochId": hx(e.EpochID[:]), "height": e.Height, "removedAMember": e.Removed, "began": e.Began})
	}
	var lateRecs []string
	for _, t := range lateTokens {
		raw, err := t.Vault.Encode()
		if err != nil {
			return err
		}
		lateRecs = append(lateRecs, hx(raw))
	}
	return put(files, "audit-v1.json", map[string]any{
		"note": "What an auditor derives from the vault's mined tokens and the group's, each checked against the auditor's own block headers (spec section 9). " +
			"Heights are those of the blocks the proofs name; here they are fixed examples. The auditor reads no secret record and no key. " +
			"A window's settled height comes from the fold of the change lists, never from a token's own stale count.",
		"groupEpochs": eps,
		"tokens":      toks,
		"trail":       trail,
		"windows":     windows(rep.Windows),
		"cutAtSeq3": map[string]any{"note": "the same trail ending at seq 3: epoch 1 is acknowledged and two secrets are still under epoch 0; epoch 2 is not acknowledged",
			"windows": windows(cut.Windows)},
		"neverAcknowledged": map[string]any{
			"note":    "the first three tokens, then two more that go on creating and updating under epoch 0 at heights 1020 and 1500, after the group began epoch 1 at 1010. Every host admits them. The audit passes its checks and reports them.",
			"records": lateRecs,
			"heights": []uint32{1001, 1003, 1005, 1020, 1500},
			"windows": windows(lateRep.Windows),
		},
		"refused": refused,
	})
}

// foldSet folds tokens and returns the current set after the last.
func foldSet(tokens []*secrec.Vault) []secrec.Current {
	f := secrec.NewVaultFold()
	for _, v := range tokens {
		f.Apply(v)
	}
	return f.Set()
}

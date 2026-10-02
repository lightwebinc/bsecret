package secrec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math/rand"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/lightwebinc/bcommon/cbor"
)

func key(b byte) [32]byte {
	return sha256.Sum256([]byte{b})
}

func testOrg() []byte {
	k, _ := ec.PrivateKeyFromBytes(bytes.Repeat([]byte{0x51}, 32))
	return k.PubKey().Compressed()
}

func TestSealOpenEveryShape(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	k := key(1)
	salt := [SaltLen]byte{1, 2, 3, 4}
	for _, segment := range []uint64{16, 17, 64, 1000, 16384} {
		for _, n := range []int{1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 999, 1000, 1001, 5000} {
			pt := make([]byte, n)
			rng.Read(pt)
			ct, err := Seal(k, salt, segment, pt)
			if err != nil {
				t.Fatal(err)
			}
			if uint64(len(ct)) != CipherLength(uint64(n), segment) {
				t.Fatalf("segment %d, %d bytes: ciphertext of %d", segment, n, len(ct))
			}
			back, err := PlainLength(uint64(len(ct)), segment)
			if err != nil || back != uint64(n) {
				t.Fatalf("segment %d, %d bytes: PlainLength gives %d, %v", segment, n, back, err)
			}
			got, err := OpenSegments(k, salt, segment, ct)
			if err != nil || !bytes.Equal(got, pt) {
				t.Fatalf("segment %d, %d bytes: %v", segment, n, err)
			}
			// Every single-bit change, at a few places, fails a tag.
			for _, at := range []int{0, len(ct) / 2, len(ct) - 1} {
				bad := append([]byte(nil), ct...)
				bad[at] ^= 0x80
				if _, err := OpenSegments(k, salt, segment, bad); !errors.Is(err, ErrTag) {
					t.Fatalf("segment %d, %d bytes: a changed byte at %d opened", segment, n, at)
				}
			}
			// Another key, another salt and another segment size fail.
			if _, err := OpenSegments(key(2), salt, segment, ct); !errors.Is(err, ErrTag) {
				t.Fatal("another key opened")
			}
			if _, err := OpenSegments(k, [SaltLen]byte{9}, segment, ct); !errors.Is(err, ErrTag) {
				t.Fatal("another salt opened")
			}
		}
	}
	if _, err := Seal(k, salt, 16, nil); err == nil {
		t.Error("an empty plaintext sealed")
	}
	if _, err := Seal([32]byte{}, salt, 16, []byte{1}); !errors.Is(err, ErrScalar) {
		t.Error("the zero key sealed")
	}
	if _, err := Seal(k, salt, 15, []byte{1}); err == nil {
		t.Error("a 15-byte segment sealed")
	}
}

// A truncation at a segment boundary is a shorter valid layout whose tags
// all verify: only the length and hash a record names catch it, which is why
// the hash check comes first.
func TestTruncationAtASegmentBoundary(t *testing.T) {
	k, salt := key(3), [SaltLen]byte{5, 6, 7, 8}
	pt := bytes.Repeat([]byte{7}, 48)
	ct, _ := Seal(k, salt, 16, pt)
	cut := ct[:64]
	if got, err := OpenSegments(k, salt, 16, cut); err != nil || len(got) != 32 {
		t.Fatalf("a boundary cut does not open as a shorter ciphertext: %v", err)
	}
	if _, err := Checks(cut, sha256.Sum256(ct), uint64(len(ct)), k, Commitment(k), salt, 16); !errors.Is(err, ErrHash) {
		t.Fatalf("a boundary cut passed the hash check: %v", err)
	}
}

func TestChecksOrder(t *testing.T) {
	k, salt := key(4), [SaltLen]byte{1}
	ct, _ := Seal(k, salt, 16, []byte("some plaintext to check"))
	h, n := sha256.Sum256(ct), uint64(len(ct))
	bad := append([]byte(nil), ct...)
	bad[0] ^= 1
	// Everything wrong at once is reported as the first check.
	if _, err := Checks(bad, h, n, key(5), Commitment(k), salt, 16); !errors.Is(err, ErrHash) {
		t.Errorf("hash first: %v", err)
	}
	if _, err := Checks(ct, h, n, key(5), Commitment(k), salt, 16); !errors.Is(err, ErrCommitment) {
		t.Errorf("commitment second: %v", err)
	}
	if _, err := Checks(ct, h, n, key(5), Commitment(key(5)), salt, 16); !errors.Is(err, ErrTag) {
		t.Errorf("tag third: %v", err)
	}
	if _, err := Checks(ct, h, n, k, Commitment(k), salt, 16); err != nil {
		t.Error(err)
	}
	if SymmetricKey(k) == Commitment(k) {
		t.Error("the symmetric key is the commitment")
	}
}

func TestSampleKey(t *testing.T) {
	seen := map[[32]byte]bool{}
	for i := 0; i < 64; i++ {
		k, err := SampleKey(nil)
		if err != nil || CheckScalar(k) != nil || seen[k] {
			t.Fatal("sample")
		}
		seen[k] = true
	}
	// A draw at or above the order, and the zero draw, are skipped.
	n := ec.S256().N.Bytes()
	r := bytes.NewReader(append(append(append([]byte(nil), n...), make([]byte, 32)...), bytes.Repeat([]byte{1}, 32)...))
	k, err := SampleKey(r)
	if err != nil || k != [32]byte(bytes.Repeat([]byte{1}, 32)) {
		t.Errorf("rejection sampling: %x %v", k, err)
	}
}

func TestEpochWrap(t *testing.T) {
	sym, cid, k := key(10), key(11), key(12)
	w, err := WrapToEpoch(sym, cid, k, nil)
	if err != nil || len(w) != WrapLen {
		t.Fatal(err)
	}
	w2, _ := WrapToEpoch(sym, cid, k, nil)
	if bytes.Equal(w, w2) {
		t.Error("two wraps share an IV")
	}
	if got, err := UnwrapFromEpoch(sym, cid, w, Commitment(k)); err != nil || got != k {
		t.Fatal(err)
	}
	if _, err := UnwrapFromEpoch(key(13), cid, w, Commitment(k)); Reason(err) != "undecryptable" {
		t.Errorf("another epoch's key: %v", err)
	}
	if _, err := UnwrapFromEpoch(sym, key(14), w, Commitment(k)); Reason(err) != "undecryptable" {
		t.Errorf("another content id: %v", err)
	}
	if _, err := UnwrapFromEpoch(sym, cid, w, Commitment(key(15))); !errors.Is(err, ErrCommitment) {
		t.Errorf("another commitment: %v", err)
	}
	if _, err := UnwrapFromEpoch(sym, cid, w[:79], Commitment(k)); Reason(err) != "undecryptable" {
		t.Errorf("a short wrap: %v", err)
	}
	// The wrapping key is neither the epoch's symmetric key nor derived
	// without the content id.
	if EpochWrapKey(sym, cid) == sym || EpochWrapKey(sym, cid) == EpochWrapKey(sym, key(14)) {
		t.Error("wrapping key")
	}
	if _, err := WrapToEpoch(sym, cid, [32]byte{}, nil); !errors.Is(err, ErrScalar) {
		t.Error("the zero key wrapped")
	}
}

func TestSelfWrap(t *testing.T) {
	ctx := context.Background()
	owner, _ := ec.PrivateKeyFromBytes(bytes.Repeat([]byte{0x51}, 32))
	other, _ := ec.PrivateKeyFromBytes(bytes.Repeat([]byte{0x52}, 32))
	ow, _ := wallet.NewCompletedProtoWallet(owner)
	xw, _ := wallet.NewCompletedProtoWallet(other)
	cid, k := key(20), key(21)
	w, err := WrapToSelf(ctx, ow, cid, k)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := UnwrapFromSelf(ctx, ow, cid, w, Commitment(k)); err != nil || got != k {
		t.Fatal(err)
	}
	if _, err := UnwrapFromSelf(ctx, xw, cid, w, Commitment(k)); Reason(err) != "undecryptable" {
		t.Errorf("another wallet: %v", err)
	}
	if _, err := UnwrapFromSelf(ctx, ow, key(22), w, Commitment(k)); Reason(err) != "undecryptable" {
		t.Errorf("another content id: %v", err)
	}
}

func TestNames(t *testing.T) {
	for s, ok := range map[string]bool{
		"a_abcdefghij": true, "example_crypt_hmqzvtkwrx": true, "a_b_abcdefghij": true,
		strings.Repeat("a", 28) + "_abcdefghij": true, strings.Repeat("a", 29) + "_abcdefghij": false,
		"_abcdefghij": false, "a__abcdefghij": false, "a_abcdefghi": false, "a_abcdefghi1": false, "A_abcdefghij": false,
		"a_abcdefghijk": false, // eleven letters after the underscore: the suffix is exactly ten
		"":              false,
	} {
		if got := CheckCrypt(s) == nil; got != ok {
			t.Errorf("crypt %q: %v", s, got)
		}
	}
	if len(TopicPrefix)+MaxCrypt != 50 {
		t.Error("a topic can pass BRC-87's 50 characters")
	}
	c, err := NewCrypt("vault_room", nil)
	if err != nil || CheckCrypt(c) != nil {
		t.Fatal(err)
	}
	if n, sfx, err := SplitCrypt(c); err != nil || n != "vault_room" || len(sfx) != SuffixLen {
		t.Error("split")
	}
	for s, ok := range map[string]bool{
		"db/password": true, "a": true, "a.b_c-d/e": true, "/a": false, "a/": false, "a//b": false, "A": false, "a b": false, "": false,
		strings.Repeat("a", 128): true, strings.Repeat("a", 129): false, "café": false,
	} {
		if got := CheckSecretName(s) == nil; got != ok {
			t.Errorf("name %q: %v", s, got)
		}
	}
	for s, ok := range map[string]bool{
		"public": true, "top-secret": true, "l2": true, "2l": false, "a-": false, "a--b": false, "a_b": false, "": false,
		strings.Repeat("a", 32): true, strings.Repeat("a", 33): false,
	} {
		if got := CheckLabel(s) == nil; got != ok {
			t.Errorf("label %q: %v", s, got)
		}
	}
	if CheckLabels(DefaultLabels) != nil {
		t.Error("the default labels break the rule")
	}
	if CheckLabels([]string{"b", "a"}) == nil || CheckLabels([]string{"a", "a"}) == nil || CheckLabels(nil) == nil {
		t.Error("label set")
	}
	v1, v2 := VaultID(key(1), 0), VaultID(key(1), 1)
	if v1 == v2 || v1 == VaultID(key(2), 0) {
		t.Error("vault ids collide")
	}
	a, _ := SecretID(v1, "db/password")
	b, _ := SecretID(v2, "db/password")
	c2, _ := SecretID(v1, "db/passwor")
	if a == b || a == c2 {
		t.Error("secret ids collide")
	}
}

func fullEntries(tag byte, n int) []Entry {
	out := make([]Entry, n)
	for i := range out {
		out[i] = Entry{ID: sha256.Sum256([]byte{tag, byte(i), 1}), Version: MaxSafe, ContentID: sha256.Sum256([]byte{tag, byte(i), 2}),
			Commitment: sha256.Sum256([]byte{tag, byte(i), 3})}
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && bytes.Compare(out[j-1].ID[:], out[j].ID[:]) > 0; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// The largest vault record this version allows fits its bound.
func TestLargestVaultRecordFits(t *testing.T) {
	labels := make([]string, MaxLabels)
	for i := range labels {
		labels[i] = string(rune('a'+i)) + strings.Repeat("z", MaxLabel-1)
	}
	retire := make([][32]byte, MaxDelta)
	for i := range retire {
		retire[i] = sha256.Sum256([]byte{9, byte(i)})
	}
	for i := 1; i < len(retire); i++ {
		for j := i; j > 0 && bytes.Compare(retire[j-1][:], retire[j][:]) > 0; j-- {
			retire[j-1], retire[j] = retire[j], retire[j-1]
		}
	}
	v := &Vault{
		Crypt: strings.Repeat("a", MaxCryptName) + "_abcdefghij", Org: testOrg(), Seq: MaxSafe, Prev: key(1),
		Name: strings.Repeat("n", MaxName), Hall: strings.Repeat("h", 31) + "_abcdefghij", Epoch: MaxEpoch, Labels: labels,
		Anchor: AnchorInterval, Create: fullEntries(1, MaxDelta), Update: fullEntries(2, MaxDelta), Retire: retire,
		Count: MaxSecrets, Stale: 0, Created: MaxTime,
	}
	b, err := v.Encode()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("largest vault record: %d bytes of %d", len(b), MaxVaultRecord)
	if _, err := DecodeVault(b); err != nil {
		t.Fatal(err)
	}
}

func TestLargestSecretRecordFits(t *testing.T) {
	k, salt := key(30), [SaltLen]byte{1}
	pt := bytes.Repeat([]byte{1}, MaxInline-TagLen)
	ct, _ := Seal(k, salt, 16384, pt)
	if len(ct) != MaxInline {
		t.Fatalf("ciphertext of %d", len(ct))
	}
	s := &Secret{Crypt: strings.Repeat("a", MaxCryptName) + "_abcdefghij", Org: testOrg(), Version: MaxSafe, Previous: key(1),
		Label: strings.Repeat("l", MaxLabel), Epoch: MaxEpoch, Commitment: Commitment(k), Hash: sha256.Sum256(ct), Length: uint64(len(ct)),
		Salt: salt, Segment: 16384, Created: MaxTime, Self: make([]byte, WrapLen), Wrap: make([]byte, WrapLen), Inline: ct}
	b, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("largest inline secret record: %d bytes of %d", len(b), MaxSecretRecord)
	if _, err := DecodeSecret(b); err != nil {
		t.Fatal(err)
	}
}

// Decoders refuse or accept; they never panic, whatever the bytes.
func TestDecodersNeverPanic(t *testing.T) {
	k, salt := key(40), [SaltLen]byte{1}
	ct, _ := Seal(k, salt, 64, []byte("seed plaintext for mutation"))
	s := &Secret{Crypt: "a_abcdefghij", Org: testOrg(), Version: 1, Label: "internal", Commitment: Commitment(k),
		Hash: sha256.Sum256(ct), Length: uint64(len(ct)), Salt: salt, Segment: 64, Created: 1, Self: make([]byte, WrapLen),
		Wrap: make([]byte, WrapLen), Inline: ct}
	sb, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	v := &Vault{Crypt: "a_abcdefghij", Org: testOrg(), Name: "n", Hall: "h_abcdefghij", Labels: DefaultLabels,
		Create: fullEntries(1, 2), Update: []Entry{}, Retire: [][32]byte{}, Count: 2, Created: 1}
	v.Root = SetRoot([]Current{{ID: v.Create[0].ID, Version: v.Create[0].Version, ContentID: v.Create[0].ContentID},
		{ID: v.Create[1].ID, Version: v.Create[1].Version, ContentID: v.Create[1].ContentID}})
	vb, err := v.Encode()
	if err != nil {
		t.Fatal(err)
	}
	p := &Payload{Name: "a/b", Value: []byte("v"), Type: "text/plain", NotAfter: 5, RotateEvery: 6, Pad: []byte{0}}
	pb, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	c := &InclusionContext{Seq: 1, Index: 0, Size: 2}
	cb, _ := c.Encode()
	for n, seed := range [][]byte{sb, vb, pb, cb} {
		rng := rand.New(rand.NewSource(int64(7 + n)))
		for i := 0; i < 15000; i++ {
			b := append([]byte(nil), seed...)
			for n := rng.Intn(4) + 1; n > 0; n-- {
				switch rng.Intn(3) {
				case 0:
					b[rng.Intn(len(b))] ^= byte(1 << rng.Intn(8))
				case 1:
					b = b[:rng.Intn(len(b))+1]
				default:
					at := rng.Intn(len(b))
					b = append(b[:at], append([]byte{byte(rng.Intn(256))}, b[at:]...)...)
				}
			}
			if r, err := DecodeSecret(b); err == nil {
				if re, err := r.Encode(); err != nil || !bytes.Equal(re, b) {
					t.Fatalf("an accepted secret does not re-encode to itself: %x", b)
				}
			}
			if r, err := DecodeVault(b); err == nil {
				if re, err := r.Encode(); err != nil || !bytes.Equal(re, b) {
					t.Fatalf("an accepted vault does not re-encode to itself: %x", b)
				}
			}
			if r, err := DecodePayload(b); err == nil {
				if re, err := r.Encode(); err != nil || !bytes.Equal(re, b) {
					t.Fatalf("an accepted payload does not re-encode to itself: %x", b)
				}
			}
			_, _ = DecodeContext(b)
			_ = Classify(b)
			_, _ = ParseQuery(b)
		}
	}
}

func TestEncodePadded(t *testing.T) {
	for value := 0; value < 1200; value++ {
		p := &Payload{Name: "a/b", Value: bytes.Repeat([]byte{1}, value)}
		b, err := p.EncodePadded(256)
		if err != nil || len(b)%256 != 0 {
			t.Fatalf("a value of %d bytes pads to %d: %v", value, len(b), err)
		}
		if back, err := DecodePayload(b); err != nil || !bytes.Equal(back.Value, p.Value) {
			t.Fatalf("a padded payload does not decode: %v", err)
		}
	}
	// A payload whose map head grows when the padding key is added: 23
	// pairs become 24.
	p := &Payload{Name: "a/b", Value: []byte("v")}
	for k := uint64(7); len(p.Extra) < 20; k++ {
		p.Extra = append(p.Extra, cbor.Pair{Key: k, Val: uint64(k)})
	}
	b, err := p.EncodePadded(256)
	if err != nil || len(b)%256 != 0 {
		t.Fatalf("a 23-pair payload pads to %d: %v", len(b), err)
	}
	if back, err := DecodePayload(b); err != nil || len(back.Extra) != 20 {
		t.Fatalf("a 24-pair payload does not decode: %v", err)
	}
}

// A record describes only ciphertexts a conforming reader can open.
func TestLengthBound(t *testing.T) {
	mk := func(length, segment uint64) error {
		s := &Secret{Crypt: "a_abcdefghij", Org: testOrg(), Version: 1, Label: "internal", Length: length, Segment: segment,
			Created: 1, Self: make([]byte, WrapLen), Wrap: make([]byte, WrapLen)}
		_, err := s.Encode()
		return err
	}
	if err := mk(CipherLength(MaxPayload, 16384), 16384); err != nil {
		t.Errorf("the largest payload: %v", err)
	}
	if err := mk(CipherLength(MaxPayload+1, 16384), 16384); Reason(err) != "range" {
		t.Errorf("one byte more: %v", err)
	}
	if err := mk(CipherLength(MaxPayload, 16), 16); err != nil || CipherLength(MaxPayload, 16) != MaxLength {
		t.Errorf("the largest ciphertext is not MaxLength: %v", err)
	}
	if err := mk(MaxLength+1, 1<<20); Reason(err) != "range" {
		t.Errorf("above MaxLength: %v", err)
	}
}

// The read entry points check the ciphertext before they open any wrap.
func TestReadOrder(t *testing.T) {
	k, other, sym, salt := key(60), key(61), key(62), [SaltLen]byte{9}
	p := &Payload{Name: "a/b", Value: []byte("v")}
	pt, _ := p.EncodePadded(256)
	ct, _ := Seal(k, salt, 16384, pt)
	vault := key(63)
	id, _ := SecretID(vault, "a/b")
	rec := &Secret{Crypt: "a_abcdefghij", Org: testOrg(), Vault: vault, ID: id, Version: 1, Label: "internal",
		Commitment: Commitment(k), Hash: sha256.Sum256(ct), Length: uint64(len(ct)), Salt: salt, Segment: 16384, Created: 1,
		Self: make([]byte, WrapLen), Inline: ct}
	cid, _ := rec.ContentID()
	rec.Wrap, _ = WrapToEpoch(sym, cid, k, nil)
	if got, err := ReadAsMember(rec, ct, sym); err != nil || got.Name != "a/b" {
		t.Fatal(err)
	}
	bad := append([]byte(nil), ct...)
	bad[3] ^= 1
	wrong := *rec
	wrong.Wrap, _ = WrapToEpochWithIV(sym, cid, other, key(64))
	if _, err := ReadAsMember(&wrong, bad, sym); Reason(err) != "hash" {
		t.Errorf("a changed ciphertext and a wrong key wrapped: %v", err)
	}
	if _, err := ReadAsMember(&wrong, ct, sym); Reason(err) != "commitment" {
		t.Errorf("a wrong key wrapped: %v", err)
	}
	if _, err := ReadAsMember(rec, ct, key(65)); Reason(err) != "undecryptable" {
		t.Errorf("another epoch's key: %v", err)
	}
}

func TestFoldAndTransitionAgreeOnAnHonestChain(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	org := testOrg()
	vault := VaultID(key(50), 0)
	set := map[[32]byte]Current{}
	last := map[[32]byte]uint64{}
	var pred *Vault
	var predTx [32]byte
	fold := NewVaultFold()
	epoch := uint64(0)
	n := 0
	fresh := func() [32]byte { n++; return sha256.Sum256([]byte{byte(n), byte(n >> 8), 77}) }
	for seq := uint64(0); seq < 200; seq++ {
		v := &Vault{Crypt: "a_abcdefghij", Org: org, Vault: vault, Seq: seq, Prev: predTx, Name: "n", Hall: "h_abcdefghij",
			Labels: DefaultLabels, Create: []Entry{}, Update: []Entry{}, Retire: [][32]byte{}, Created: 1}
		if seq > 0 && rng.Intn(6) == 0 {
			epoch++
		}
		v.Epoch = epoch
		v.EpochID = sha256.Sum256([]byte{byte(epoch), 88})
		stale := func() (out [][32]byte) {
			for _, c := range sortSet(values(set)) {
				if c.Epoch < epoch {
					out = append(out, c.ID)
				}
			}
			return out
		}
		st := stale()
		switch {
		case len(st) > 0:
			// In debt: re-key some stale secrets, retire at most one.
			take := rng.Intn(len(st)) + 1
			for i, id := range st[:take] {
				if i == 0 && rng.Intn(4) == 0 {
					delete(set, id)
					v.Retire = append(v.Retire, id)
					continue
				}
				last[id]++
				e := Entry{ID: id, Version: last[id], ContentID: fresh(), Commitment: fresh()}
				v.Update = append(v.Update, e)
				set[id] = Current{ID: id, Version: e.Version, ContentID: e.ContentID, Epoch: epoch, Seq: seq}
			}
		default:
			for i := rng.Intn(3); i >= 0 && len(set) < 40; i-- {
				id := fresh()
				last[id] = 1
				e := Entry{ID: id, Version: 1, ContentID: fresh(), Commitment: fresh()}
				v.Create = append(v.Create, e)
				set[id] = Current{ID: id, Version: 1, ContentID: e.ContentID, Epoch: epoch, Seq: seq}
			}
		}
		sortE := func(a []Entry) {
			for i := 1; i < len(a); i++ {
				for j := i; j > 0 && bytes.Compare(a[j-1].ID[:], a[j].ID[:]) > 0; j-- {
					a[j-1], a[j] = a[j], a[j-1]
				}
			}
		}
		sortE(v.Create)
		sortE(v.Update)
		v.Count = uint64(len(set))
		v.Stale = uint64(len(stale()))
		v.Root = SetRoot(values(set))
		raw, err := v.Encode()
		if err != nil {
			t.Fatalf("seq %d: %v", seq, err)
		}
		back, err := DecodeVault(raw)
		if err != nil {
			t.Fatalf("seq %d: %v", seq, err)
		}
		if pred != nil {
			if err := CheckVaultTransition(pred, predTx, back); err != nil {
				t.Fatalf("seq %d: an honest transition is refused: %v", seq, err)
			}
		}
		if st := fold.Apply(back); st != StatusConsistent {
			t.Fatalf("seq %d folds %s", seq, st)
		}
		pred, predTx = back, sha256.Sum256(raw)
	}
}

func values(m map[[32]byte]Current) []Current {
	out := make([]Current, 0, len(m))
	for _, c := range m {
		out = append(out, c)
	}
	return out
}

func TestContextRoundTrip(t *testing.T) {
	var set []Current
	for i := 0; i < 37; i++ {
		set = append(set, Current{ID: key(byte(i)), Version: uint64(i + 1), ContentID: key(byte(100 + i))})
	}
	root := SetRoot(set)
	for _, c := range set {
		ctx, err := ProveSecret(9, key(250), set, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		b, err := ctx.Encode()
		if err != nil {
			t.Fatal(err)
		}
		back, err := DecodeContext(b)
		if err != nil || !back.VerifySecret(c.ID, c.Version, c.ContentID, root) {
			t.Fatal("context")
		}
		if back.VerifySecret(c.ID, c.Version+1, c.ContentID, root) {
			t.Fatal("another version verified")
		}
	}
	if _, err := ProveSecret(9, key(250), set, key(200)); err == nil {
		t.Error("a secret outside the set was proven")
	}
	if SetRoot(nil) != sha256.Sum256(nil) {
		t.Error("the empty root is not SHA-256 of nothing")
	}
}

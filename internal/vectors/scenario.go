package vectors

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// Version is one version of one secret of the scenario.
type Version struct {
	Name    string
	Number  uint64
	Epoch   uint64
	Key     [32]byte
	Payload *secrec.Payload
	Plain   []byte // the encoded payload
	Cipher  []byte
	Rec     *secrec.Secret
	Raw     []byte
	CID     [32]byte
	SelfIV  [32]byte
	WrapIV  [32]byte
	File    string
}

// Scenario is the vectors' one vault: its secrets' versions and its chain
// of tokens.
type Scenario struct {
	VaultID    [32]byte
	Genesis    [32]byte // the stand-in txid of the chain tree the first token spends
	Versions   map[string]*Version
	Order      []string
	Vaults     []*secrec.Vault
	VaultRecs  [][]byte
	VaultTxids [][32]byte
	Heights    []uint32
	Labels     []string
	set        map[[32]byte]secrec.Current
}

func vkey(name string, n uint64) string { return fmt.Sprintf("%s@%d", name, n) }

// bigValue is the value of the scenario's large secret: n blocks of
// SHA-256("bsecret/vector/big/" || i as four bytes big-endian).
func bigValue(blocks int) []byte {
	out := make([]byte, 0, 32*blocks)
	for i := 0; i < blocks; i++ {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(i))
		h := sha256.Sum256(append([]byte("bsecret/vector/big/"), b[:]...))
		out = append(out, h[:]...)
	}
	return out
}

// PadBlock is the block the scenario pads payloads to.
const PadBlock = 256

func paddedPayload(p *secrec.Payload) ([]byte, error) {
	b, err := p.EncodePadded(PadBlock)
	if err != nil {
		return nil, err
	}
	if len(b)%PadBlock != 0 {
		return nil, fmt.Errorf("payload of %d bytes is not padded to %d", len(b), PadBlock)
	}
	return b, nil
}

func (s *Scenario) version(name string, n, epoch uint64, lbl string, value []byte, typ string, segment uint64, inline bool, created uint64) (*Version, error) {
	ctx := context.Background()
	id, err := secrec.SecretID(s.VaultID, name)
	if err != nil {
		return nil, err
	}
	v := &Version{Name: name, Number: n, Epoch: epoch, Key: label("key/%s/%d", name, n)}
	if err := secrec.CheckScalar(v.Key); err != nil {
		return nil, fmt.Errorf("%s: stand-in key: %w", vkey(name, n), err)
	}
	v.Payload = &secrec.Payload{Name: name, Value: value, Type: typ}
	if v.Plain, err = paddedPayload(v.Payload); err != nil {
		return nil, err
	}
	var salt [secrec.SaltLen]byte
	sl := label("salt/%s/%d", name, n)
	copy(salt[:], sl[:])
	if v.Cipher, err = secrec.Seal(v.Key, salt, segment, v.Plain); err != nil {
		return nil, err
	}
	ge := GroupEpochs[epoch]
	rec := &secrec.Secret{
		Crypt: Crypt, Org: Org.Pub(), Vault: s.VaultID, ID: id, Version: n, Label: lbl,
		Group: GroupID, Epoch: epoch, EpochID: ge.EpochID, Commitment: secrec.Commitment(v.Key),
		Hash: sha256.Sum256(v.Cipher), Length: uint64(len(v.Cipher)), Salt: salt, Segment: segment, Created: created,
	}
	if n > 1 {
		prev, ok := s.Versions[vkey(name, n-1)]
		if !ok {
			return nil, fmt.Errorf("%s: no version before it", vkey(name, n))
		}
		rec.Previous = prev.CID
	}
	if inline {
		rec.Inline = v.Cipher
	}
	if v.CID, err = rec.ContentID(); err != nil {
		return nil, err
	}
	v.SelfIV, v.WrapIV = label("iv/self/%s/%d", name, n), label("iv/epoch/%s/%d", name, n)
	if rec.Self, err = secrec.WrapToSelfWithIV(Org.Priv, v.CID, v.Key, v.SelfIV); err != nil {
		return nil, err
	}
	if rec.Wrap, err = secrec.WrapToEpochWithIV(ge.Symmetric, v.CID, v.Key, v.WrapIV); err != nil {
		return nil, err
	}
	if v.Raw, err = rec.Encode(); err != nil {
		return nil, fmt.Errorf("%s: %w", vkey(name, n), err)
	}
	back, err := secrec.DecodeSecret(v.Raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", vkey(name, n), err)
	}
	re, err := back.Encode()
	if err != nil || !bytes.Equal(re, v.Raw) {
		return nil, fmt.Errorf("%s does not round-trip", vkey(name, n))
	}
	if cid, _ := back.ContentID(); cid != v.CID {
		return nil, fmt.Errorf("%s: content id changes on decode", vkey(name, n))
	}
	v.Rec = back
	// The owner's wallet opens its own wrap, and the version reads.
	p, err := secrec.ReadAsOwner(ctx, Org.Wallet(), back, v.Cipher)
	if err != nil || p.Name != name || !bytes.Equal(p.Value, value) {
		return nil, fmt.Errorf("%s: the owner does not read it back: %v", vkey(name, n), err)
	}
	if p, err = secrec.ReadAsMember(back, v.Cipher, ge.Symmetric); err != nil || !bytes.Equal(p.Value, value) {
		return nil, fmt.Errorf("%s: a member of its epoch does not read it: %v", vkey(name, n), err)
	}
	// A stand-in key is used once.
	for _, o := range s.Versions {
		if o.Key == v.Key {
			return nil, errors.New("a content key repeats")
		}
	}
	v.File = fmt.Sprintf("secret-%s-v%d.hex", fileName(name), n)
	s.Versions[vkey(name, n)] = v
	s.Order = append(s.Order, vkey(name, n))
	return v, nil
}

func fileName(name string) string {
	out := []byte(name)
	for i, c := range out {
		if c == '/' || c == '.' || c == '_' {
			out[i] = '-'
		}
	}
	return string(out)
}

func entry(v *Version) secrec.Entry {
	return secrec.Entry{ID: v.Rec.ID, Version: v.Number, ContentID: v.CID, Commitment: v.Rec.Commitment}
}

func sortEntries(a []secrec.Entry) []secrec.Entry {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && bytes.Compare(a[j-1].ID[:], a[j].ID[:]) > 0; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
	return a
}

func sort32(a [][32]byte) [][32]byte {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && bytes.Compare(a[j-1][:], a[j][:]) > 0; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
	return a
}

// token appends the next token of the vault's chain: it applies the changes
// to the running set and writes the count, stale and root they give.
func (s *Scenario) token(epoch uint64, create, update []*Version, retire []string, height uint32) error {
	seq := uint64(len(s.Vaults))
	v := &secrec.Vault{
		Crypt: Crypt, Org: Org.Pub(), Vault: s.VaultID, Seq: seq, Name: "Example vault", Hall: Hall, Group: GroupID,
		Epoch: epoch, EpochID: GroupEpochs[epoch].EpochID, Labels: s.Labels, Anchor: secrec.AnchorVersion,
		Create: []secrec.Entry{}, Update: []secrec.Entry{}, Retire: [][32]byte{}, Created: Created + 600*seq,
	}
	if seq > 0 {
		v.Prev = s.VaultTxids[seq-1]
	}
	for _, name := range retire {
		id, _ := secrec.SecretID(s.VaultID, name)
		delete(s.set, id)
		v.Retire = append(v.Retire, id)
	}
	sort32(v.Retire)
	for _, list := range []struct {
		in  []*Version
		out *[]secrec.Entry
	}{{create, &v.Create}, {update, &v.Update}} {
		for _, x := range list.in {
			if x.Epoch != epoch {
				return fmt.Errorf("seq %d lists %s, keyed under epoch %d, at epoch %d", seq, vkey(x.Name, x.Number), x.Epoch, epoch)
			}
			*list.out = append(*list.out, entry(x))
			s.set[x.Rec.ID] = secrec.Current{ID: x.Rec.ID, Version: x.Number, ContentID: x.CID, Epoch: epoch, Seq: seq}
		}
		sortEntries(*list.out)
	}
	var set []secrec.Current
	for _, c := range s.set {
		set = append(set, c)
		if c.Epoch < epoch {
			v.Stale++
		}
	}
	v.Count, v.Root = uint64(len(set)), secrec.SetRoot(set)
	raw, err := v.Encode()
	if err != nil {
		return fmt.Errorf("vault seq %d: %w", seq, err)
	}
	back, err := secrec.DecodeVault(raw)
	if err != nil {
		return fmt.Errorf("vault seq %d: %w", seq, err)
	}
	if re, err := back.Encode(); err != nil || !bytes.Equal(re, raw) {
		return fmt.Errorf("vault seq %d does not round-trip", seq)
	}
	if seq > 0 {
		if err := secrec.CheckVaultTransition(s.Vaults[seq-1], s.VaultTxids[seq-1], back); err != nil {
			return fmt.Errorf("vault seq %d: %w", seq, err)
		}
	}
	s.Vaults = append(s.Vaults, back)
	s.VaultRecs = append(s.VaultRecs, raw)
	s.VaultTxids = append(s.VaultTxids, label("txid/vault/%d", seq))
	s.Heights = append(s.Heights, height)
	return nil
}

// Build makes the scenario: one vault of the organisation, keyed to the
// group's epochs, through a removal and a scheduled rotation.
func Build() (*Scenario, error) {
	s := &Scenario{Versions: map[string]*Version{}, set: map[[32]byte]secrec.Current{}, Labels: secrec.DefaultLabels}
	s.Genesis = label("txid/chain-tree")
	s.VaultID = secrec.VaultID(s.Genesis, 0)
	const seg = 16384
	mk := func(name string, n, epoch uint64, lbl, value, typ string) (*Version, error) {
		return s.version(name, n, epoch, lbl, []byte(value), typ, seg, true, Created+60*uint64(len(s.Order)))
	}
	// Epoch 0: the vault is created with two secrets, one is updated, and a
	// large one is added whose ciphertext is not carried inline.
	db1, err := mk("db/password", 1, 0, "confidential", "correct horse battery staple", "text/plain")
	if err != nil {
		return nil, err
	}
	api1, err := mk("api/token", 1, 0, "internal", "tok_0001_example", "text/plain")
	if err != nil {
		return nil, err
	}
	if err := s.token(0, []*Version{db1, api1}, nil, nil, 1001); err != nil {
		return nil, err
	}
	api2, err := mk("api/token", 2, 0, "internal", "tok_0002_example", "text/plain")
	if err != nil {
		return nil, err
	}
	if err := s.token(0, nil, []*Version{api2}, nil, 1003); err != nil {
		return nil, err
	}
	tls1, err := s.version("tls/key", 1, 0, "restricted", bigValue(1250), "application/octet-stream", seg, false, Created+60*uint64(len(s.Order)))
	if err != nil {
		return nil, err
	}
	if err := s.token(0, []*Version{tls1}, nil, nil, 1005); err != nil {
		return nil, err
	}
	// The group removes bob and begins epoch 1. The vault acknowledges it
	// and re-keys one secret; two are still under epoch 0.
	db2, err := mk("db/password", 2, 1, "confidential", "a new password after the removal", "text/plain")
	if err != nil {
		return nil, err
	}
	if err := s.token(1, nil, []*Version{db2}, nil, 1012); err != nil {
		return nil, err
	}
	// The debt is cleared: one more secret re-keyed, the large one retired.
	api3, err := mk("api/token", 3, 1, "internal", "tok_0003_example", "text/plain")
	if err != nil {
		return nil, err
	}
	if err := s.token(1, nil, []*Version{api3}, []string{"tls/key"}, 1013); err != nil {
		return nil, err
	}
	// Nothing is stale, so a secret can be created again.
	ssh1, err := mk("ssh/deploy-key", 1, 1, "restricted", "-----BEGIN EXAMPLE KEY-----\nnot a key\n-----END EXAMPLE KEY-----\n", "text/plain")
	if err != nil {
		return nil, err
	}
	if err := s.token(1, []*Version{ssh1}, nil, nil, 1020); err != nil {
		return nil, err
	}
	// A scheduled rotation of the group begins epoch 2; the vault re-keys
	// everything in one transition.
	db3, err := mk("db/password", 3, 2, "confidential", "a password for the third epoch", "text/plain")
	if err != nil {
		return nil, err
	}
	api4, err := mk("api/token", 4, 2, "internal", "tok_0004_example", "text/plain")
	if err != nil {
		return nil, err
	}
	ssh2, err := mk("ssh/deploy-key", 2, 2, "restricted", "-----BEGIN EXAMPLE KEY-----\nstill not a key\n-----END EXAMPLE KEY-----\n", "text/plain")
	if err != nil {
		return nil, err
	}
	if err := s.token(2, nil, []*Version{db3, api4, ssh2}, nil, 1031); err != nil {
		return nil, err
	}
	// The whole chain folds consistently.
	f := secrec.NewVaultFold()
	for i, v := range s.Vaults {
		if st := f.Apply(v); st != secrec.StatusConsistent {
			return nil, fmt.Errorf("vault seq %d folds %s", i, st)
		}
	}
	return s, nil
}

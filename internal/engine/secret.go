package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/lightwebinc/bcommon/guard"

	"github.com/lightwebinc/bsecret/internal/limits"
	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/state"
	"github.com/lightwebinc/bsecret/internal/vread"
)

// Item is one secret value to write.
type Item struct {
	Name  string
	Value []byte
	// Label is the classification; empty keeps the secret's last label, or
	// for a new secret takes the vault's default.
	Label string
	// Type, NotAfter and RotateEvery are the payload's optional claims.
	Type        string
	NotAfter    uint64
	RotateEvery uint64
}

// Minted is one version written: its record, as its carrier published it,
// and the entry a vault token lists it by.
type Minted struct {
	Name   string
	Record *secrec.Secret
	Entry  secrec.Entry
	// Txid is the carrier's txid; Stored where a ciphertext that is not
	// carried was written.
	Txid   string
	Stored string
}

// sample draws a content key and its salt.
func (e *Engine) sample() ([32]byte, [secrec.SaltLen]byte, error) {
	if e.Sample != nil {
		return e.Sample()
	}
	var salt [secrec.SaltLen]byte
	k, err := secrec.SampleKey(nil)
	if err != nil {
		return k, salt, err
	}
	_, err = rand.Read(salt[:])
	return k, salt, err
}

// history is what the home knows of a secret's versions: the highest
// version a token ever listed (a retired one's included), and the highest
// it published that is not swept, listed or not.
func history(v *state.Vault, id string) (listed, published *state.SecretVersion) {
	for i := range v.Versions {
		x := &v.Versions[i]
		if x.ID != id {
			continue
		}
		if x.Listed && (listed == nil || x.Version > listed.Version) {
			listed = x
		}
		if x.Swept == "" && (published == nil || x.Version > published.Version) {
			published = x
		}
	}
	return listed, published
}

// defaultLabel is the label a new secret takes when none is named:
// confidential when the vault has it, else the vault's only label.
func defaultLabel(labels []string) (string, error) {
	for _, l := range labels {
		if l == "confidential" {
			return l, nil
		}
	}
	if len(labels) == 1 {
		return labels[0], nil
	}
	return "", fmt.Errorf("name a label (-label): the vault's labels are %v", labels)
}

// mint writes one version of a secret under an epoch of the group, in the
// order of spec section 7.1: sample the content key and the salt; encode
// and pad the payload; seal it; build the record without its wraps; compute
// the content id; wrap the key to the owner and under the epoch; publish
// the carrier. Before anything is persisted the commitment is held to the
// home's record of every commitment it ever published (a repeat is
// refused), the version is opened again both ways, and the carrier is held
// to the host's rules.
func (e *Engine) mint(ctx context.Context, w *Writer, it Item, epoch secrec.EpochEvent, sym [32]byte, after *state.SecretVersion) (*Minted, error) {
	v := w.Vault
	// A version is published under evidence no older than the freshness
	// bound; the token that lists it retakes the evidence when it is built.
	if e.Now().Sub(w.At) > e.Opts.Freshness {
		if err := e.refresh(ctx, w); err != nil {
			return nil, err
		}
	}
	if err := secrec.CheckSecretName(it.Name); err != nil {
		return nil, fmt.Errorf("name %q: 1 to %d bytes of lowercase letters, digits, '.', '_', '-' and '/', with no empty path segment", it.Name, secrec.MaxSecretName)
	}
	vid := hex32(v.ID)
	id, err := secrec.SecretID(vid, it.Name)
	if err != nil {
		return nil, err
	}
	idHex := hex.EncodeToString(id[:])
	rec := &secrec.Secret{Crypt: v.Crypt, Org: e.OrgKey(), Vault: vid, ID: id, Version: 1, Label: it.Label,
		Group: w.Pred.Group, Epoch: epoch.Epoch, EpochID: epoch.EpochID, Segment: e.Opts.Segment, Created: e.created()}
	if after != nil {
		rec.Version, rec.Previous = after.Version+1, hex32(after.ContentID)
		if rec.Label == "" {
			rec.Label = after.Label
		}
	}
	if rec.Label == "" {
		if rec.Label, err = defaultLabel(v.Labels); err != nil {
			return nil, err
		}
	}
	if !contains(v.Labels, rec.Label) {
		return nil, fmt.Errorf("label %q is not one of the vault's labels %v, which were fixed at its first token", rec.Label, v.Labels)
	}
	payload := &secrec.Payload{Name: it.Name, Value: it.Value, Type: it.Type, NotAfter: it.NotAfter, RotateEvery: it.RotateEvery}
	plain, err := payload.EncodePadded(limits.PadBlock)
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	k, salt, err := e.sample()
	if err != nil {
		return nil, err
	}
	defer func() { k = [32]byte{} }()
	rec.Salt, rec.Commitment = salt, secrec.Commitment(k)
	// A content key and salt used twice break both versions without any
	// key (spec section 6.2): a commitment the home has published or
	// listed before is refused before anything is built on it.
	if e.St.Committed(hex.EncodeToString(rec.Commitment[:])) {
		return nil, fmt.Errorf("%w: refusing to publish %q under a content key this home has used", secrec.ErrReuse, it.Name)
	}
	ct, err := secrec.Seal(k, salt, rec.Segment, plain)
	if err != nil {
		return nil, err
	}
	rec.Hash, rec.Length = sha256.Sum256(ct), uint64(len(ct))
	if len(ct) <= secrec.MaxInline {
		rec.Inline = ct
	}
	cid, err := rec.ContentID()
	if err != nil {
		return nil, err
	}
	if rec.Self, err = secrec.WrapToSelf(ctx, e.Signer, cid, k); err != nil {
		return nil, fmt.Errorf("self wrap: %w", err)
	}
	if rec.Wrap, err = secrec.WrapToEpoch(sym, cid, k, nil); err != nil {
		return nil, fmt.Errorf("epoch wrap: %w", err)
	}
	raw, err := rec.Encode()
	if err != nil {
		return nil, fmt.Errorf("the secret record breaks its own rules (%s): %w", secrec.Reason(err), err)
	}
	// What a reader will do, done here first: both wraps open to the key
	// committed to, every tag verifies, and the payload is this secret's.
	for who, open := range map[string]func() (*secrec.Payload, error){
		"the owner":  func() (*secrec.Payload, error) { return secrec.ReadAsOwner(ctx, e.Signer, rec, ct) },
		"the member": func() (*secrec.Payload, error) { return secrec.ReadAsMember(rec, ct, sym) },
	} {
		p, err := open()
		if err != nil || p.Name != it.Name || !bytes.Equal(p.Value, it.Value) {
			return nil, fmt.Errorf("the version does not read back as %s would read it (%v); it is not published", who, err)
		}
	}
	m := &Minted{Name: it.Name, Record: rec, Entry: secrec.Entry{ID: id, Version: rec.Version, ContentID: cid, Commitment: rec.Commitment}}
	if rec.Inline == nil {
		if e.Legs.Content == nil {
			return nil, errors.New("the ciphertext is over the inline bound of 16384 bytes and no content directory is configured (config key content)")
		}
		if m.Stored, err = e.Legs.Content.Put(ct); err != nil {
			return nil, err
		}
	} else if e.Legs.Facade != nil && len(it.Value) > limits.InlineValueWarn {
		e.note("warning: %q is %d bytes; on the plane its carrier is more than 7 packets (docs/limits.md)", it.Name, len(it.Value))
	}
	tree, vout, err := e.spend(ctx, state.TreeSecret)
	if err != nil {
		return nil, err
	}
	a, tx, beef, err := e.carrierFor(ctx, v.Crypt, raw, tree, vout)
	if err != nil {
		return nil, err
	}
	if a.Carrier.ContentID != cid {
		return nil, errors.New("the carrier's content id is not the record's; it is not published")
	}
	m.Txid = vread.Txid(a.Txid)
	// Save before send: the funding output is marked used, the commitment
	// recorded and the carrier kept before anything leaves.
	e.markSpent(state.TreeSecret, tree, vout)
	e.St.Commit(hex.EncodeToString(rec.Commitment[:]))
	v.Versions = append(v.Versions, state.SecretVersion{Name: it.Name, ID: idHex, Version: rec.Version, ContentID: hex.EncodeToString(cid[:]),
		Commitment: hex.EncodeToString(rec.Commitment[:]), Epoch: rec.Epoch, Label: rec.Label, Txid: m.Txid, Tree: tree.TxID().String(), Vout: vout,
		Raw: tx.Hex(), Hash: hex.EncodeToString(rec.Hash[:]), Stored: rec.Inline == nil, Created: rec.Created,
		RotateEvery: it.RotateEvery, NotAfter: it.NotAfter})
	p := state.Pending{Kind: state.KindSecret, Crypt: v.Crypt, Txid: m.Txid, Beef: hex.EncodeToString(beef), Org: e.orgHex(), Vault: v.ID,
		Secret: idHex, Version: rec.Version}
	if err := e.queue(ctx, p); err != nil {
		return m, err
	}
	return m, nil
}

func contains(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}

// MaxChanges is the most secrets one token of this publisher creates,
// updates or retires: the record bound. A test lowers it so that a small
// vault takes several tokens.
var MaxChanges = secrec.MaxDelta

// PutResult is what a put did.
type PutResult struct {
	Minted *Minted
	// Created is set when the secret entered the set; Listed when a token
	// lists the version (false for a deferred version of an interval
	// vault).
	Created bool
	Listed  bool
	Seq     uint64
}

// Put writes a new version of each item and lists them in the vault's next
// token (spec section 8.1): in create for a secret the set does not hold,
// in update for one it does. With hold, in an interval vault, the versions
// are published and not listed: readers take them by their links, marked
// unanchored, until Anchor lists the latest of each (spec section 4.4).
//
// It refuses while the vault is behind its group or in debt: then the only
// transitions are the acknowledgement and the re-keying (Rotate).
func (e *Engine) Put(ctx context.Context, w *Writer, items []Item, hold bool) ([]PutResult, error) {
	if !w.Stand.Settled() {
		return nil, fmt.Errorf("vault %s is %s: the only transitions built are the acknowledgement of the group's epoch and the re-keying or retirement of what the vault holds (bsecret rotate)", vread.Short(w.Vault.ID), w.Stand)
	}
	if hold && w.Pred.Anchor != secrec.AnchorInterval {
		return nil, errors.New("-defer is for an interval vault: in a per-version vault a reader takes only versions a mined token lists")
	}
	if len(items) > MaxChanges {
		return nil, fmt.Errorf("one token lists at most %d secrets; put the rest in a second command", MaxChanges)
	}
	epoch := w.Group.Current()
	sym, err := e.EpochKey(ctx, w.Group, epoch.Epoch)
	if err != nil {
		return nil, err
	}
	var c Change
	var out []PutResult
	seen := map[string]bool{}
	for _, it := range items {
		if seen[it.Name] {
			return nil, fmt.Errorf("%q is named twice", it.Name)
		}
		seen[it.Name] = true
		id, err := secrec.SecretID(hex32(w.Vault.ID), it.Name)
		if err != nil {
			return nil, fmt.Errorf("name %q: 1 to %d bytes of lowercase letters, digits, '.', '_', '-' and '/', with no empty path segment", it.Name, secrec.MaxSecretName)
		}
		_, inSet := current(w, id)
		after, err := e.predecessor(w, id, inSet)
		if err != nil {
			return nil, err
		}
		if hold && !inSet {
			return nil, fmt.Errorf("%q is not in the vault's set: a reader takes an unlisted version only as the successor of a listed one, so a secret's first version is listed", it.Name)
		}
		m, err := e.mint(ctx, w, it, epoch, sym, after)
		if err != nil {
			return out, err
		}
		r := PutResult{Minted: m, Created: !inSet}
		if !hold {
			if inSet {
				c.Update = append(c.Update, m)
			} else {
				c.Create = append(c.Create, m)
			}
			r.Listed, r.Seq = true, w.Pred.Seq+1
		}
		out = append(out, r)
	}
	if hold {
		return out, nil
	}
	return out, e.transition(ctx, w, c)
}

func current(w *Writer, id [32]byte) (secrec.Current, bool) {
	for _, c := range w.Fold.Set() {
		if c.ID == id {
			return c, true
		}
	}
	return secrec.Current{}, false
}

// predecessor is the version a new version of id follows: in an interval
// vault the highest the home published and did not sweep, so that a run of
// unlisted versions links; otherwise the highest a token ever listed, a
// retired one's included, so that versions rise.
func (e *Engine) predecessor(w *Writer, id [32]byte, inSet bool) (*state.SecretVersion, error) {
	idHex := hex.EncodeToString(id[:])
	listed, published := history(w.Vault, idHex)
	if inSet && listed == nil {
		return nil, fmt.Errorf("secret %s is in the vault's set and this home holds no record of it: run `bsecret sync`", vread.Short(idHex))
	}
	if w.Pred.Anchor == secrec.AnchorInterval && published != nil && (listed == nil || published.Version > listed.Version) {
		return published, nil
	}
	return listed, nil
}

// Anchor lists, in an interval vault, the latest unlisted version of every
// secret that has one (spec section 4.4): one token, at an interval of the
// owner's choosing.
func (e *Engine) Anchor(ctx context.Context, w *Writer) (int, error) {
	if w.Pred.Anchor != secrec.AnchorInterval {
		return 0, errors.New("the vault is per-version: every version is listed when it is put")
	}
	if !w.Stand.Settled() {
		return 0, fmt.Errorf("vault %s is %s (bsecret rotate)", vread.Short(w.Vault.ID), w.Stand)
	}
	var c Change
	for _, cur := range w.Fold.Set() {
		_, published := history(w.Vault, hex.EncodeToString(cur.ID[:]))
		if published == nil || published.Version <= cur.Version || published.Listed {
			continue
		}
		m, err := mintedOf(published)
		if err != nil {
			return 0, err
		}
		c.Update = append(c.Update, m)
	}
	if len(c.Update) == 0 {
		return 0, nil
	}
	if len(c.Update) > MaxChanges {
		c.Update = c.Update[:MaxChanges]
	}
	return len(c.Update), e.transition(ctx, w, c)
}

// RecordOf is the secret record a version's kept carrier carries.
func RecordOf(x *state.SecretVersion) (*secrec.Secret, error) {
	if x.Raw == "" {
		return nil, fmt.Errorf("the carrier of %q version %d is not kept in this home (swept, or published by another instance)", x.Name, x.Version)
	}
	raw, err := hex.DecodeString(x.Raw)
	if err != nil {
		return nil, err
	}
	tx, err := guard.ParseTransaction(raw, limits.MaxBEEF)
	if err != nil || len(tx.Outputs) != 1 || tx.Outputs[0].LockingScript == nil {
		return nil, fmt.Errorf("the kept carrier of %q version %d does not parse", x.Name, x.Version)
	}
	return secrec.CarrierRecord(*tx.Outputs[0].LockingScript)
}

func mintedOf(x *state.SecretVersion) (*Minted, error) {
	rec, err := RecordOf(x)
	if err != nil {
		return nil, err
	}
	cid, err := rec.ContentID()
	if err != nil {
		return nil, err
	}
	return &Minted{Name: x.Name, Record: rec, Txid: x.Txid,
		Entry: secrec.Entry{ID: rec.ID, Version: rec.Version, ContentID: cid, Commitment: rec.Commitment}}, nil
}

// Choice is what a revoke does with one stale secret (docs/spec.md section
// 8.2): a new value, an explicit re-keying of the same value, or a
// retirement. There is no default: re-keying a credential without changing
// it leaves the removed reader holding a value that still works.
type Choice struct {
	// Value is the new value, when Set.
	Set   bool
	Value []byte
	// Same re-keys the value the secret holds.
	Same bool
	// Retire retires the secret.
	Retire bool
}

// Stale is one secret of the vault's set that a rotation owes a re-keying
// or a retirement: keyed under an epoch before the one the vault is to
// write under.
type Stale struct {
	ID      [32]byte
	Name    string
	Version uint64
	Epoch   uint64
}

// Key is how a choice names the secret: its name, or id:<hex> when this
// home does not know the name.
func (s Stale) Key() string {
	if s.Name != "" {
		return s.Name
	}
	return "id:" + hex.EncodeToString(s.ID[:])
}

// Owes lists the secrets of the vault's set keyed under an epoch before
// target, in ascending order of identifier.
func Owes(w *Writer, target uint64) []Stale {
	var out []Stale
	for _, c := range w.Fold.Set() {
		if c.Epoch >= target {
			continue
		}
		s := Stale{ID: c.ID, Version: c.Version, Epoch: c.Epoch}
		if x := w.Vault.VersionOf(hex.EncodeToString(c.ID[:]), hex.EncodeToString(c.ContentID[:])); x != nil {
			s.Name = x.Name
		}
		out = append(out, s)
	}
	return out
}

// Covered holds a plan to the rule that a revoke is never begun that
// cannot be finished: every stale secret has exactly one choice. A choice
// for a secret the rotation owes nothing (already under the new epoch, or
// retired) is returned as ignored, so that a rotation that stopped part way
// is finished by the same command; a choice for a name the vault never held
// is an error, since it is more likely a misspelling of one it does.
func Covered(owes []Stale, plan map[string]Choice, known func(key string) bool) (ignored []string, err error) {
	want := map[string]bool{}
	var missing []string
	for _, s := range owes {
		want[s.Key()] = true
		c, ok := plan[s.Key()]
		n := 0
		for _, b := range []bool{c.Set, c.Same, c.Retire} {
			if b {
				n++
			}
		}
		switch {
		case !ok || n == 0:
			missing = append(missing, s.Key())
		case n > 1:
			return nil, fmt.Errorf("%s is given more than one of a new value, a same-value re-keying and a retirement", s.Key())
		case (c.Same || c.Set) && s.Name == "":
			return nil, fmt.Errorf("%s: this home does not know the secret's name, so it can only retire it; run `bsecret sync` to read its name from the hosts", s.Key())
		}
	}
	var unknown []string
	for k := range plan {
		switch {
		case want[k]:
		case known != nil && known(k):
			ignored = append(ignored, k)
		default:
			unknown = append(unknown, k)
		}
	}
	sort.Strings(ignored)
	sort.Strings(unknown)
	if len(unknown) > 0 {
		return nil, fmt.Errorf("%v: not a secret this vault ever held", unknown)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%d secret(s) have no choice: %v. Each needs a new value (-set name=FILE), an explicit re-keying of the same value (-same name, or -same-all), or a retirement (-retire name): a credential re-keyed with its old value is still known to whoever was removed (spec section 8.2)", len(missing), missing)
	}
	return ignored, nil
}

// Known reports whether a vault ever held a secret by a choice's key.
func Known(v *state.Vault, key string) bool {
	for i := range v.Versions {
		x := &v.Versions[i]
		if (x.Name != "" && x.Name == key) || "id:"+x.ID == key {
			return true
		}
	}
	return false
}

// ErrUnwrapped is a new epoch whose key borg has not yet released to every
// member (spec section 8.3).
var ErrUnwrapped = errors.New("borg's wraps of the new epoch's key are not published for every member")

// RotateResult is what a rotation did.
type RotateResult struct {
	// Acknowledged is the epoch the vault acknowledged in this run, when it
	// did.
	Acknowledged *uint64
	Tokens       int
	Rekeyed      []string
	Retired      []string
	Swept        int
}

// valueOf is the value a secret holds, read through its self wrap from the
// carrier the home keeps.
func (e *Engine) valueOf(ctx context.Context, x *state.SecretVersion) (*secrec.Payload, error) {
	rec, err := RecordOf(x)
	if err != nil {
		return nil, err
	}
	ct := rec.Inline
	if ct == nil {
		if e.Legs.Content == nil {
			return nil, fmt.Errorf("%q is kept by its hash and no content source is configured (config key content)", x.Name)
		}
		if ct, err = e.Legs.Content.Get(ctx, rec.Hash, rec.Length); err != nil {
			return nil, err
		}
	}
	return secrec.ReadAsOwner(ctx, e.Signer, rec, ct)
}

// Rotate acknowledges the group's latest epoch and re-keys or retires
// everything the vault held under an earlier one (spec section 8.2), in as
// many tokens as it takes at 64 changes a token, one a block: the
// acknowledgement carries the first re-keyings. plan gives, by name, what
// becomes of each stale secret; it is held to Covered before anything is
// built, so a rotation is never begun that cannot be finished. ready
// gathers the writer's evidence again before each token.
//
// A version keyed under a new epoch is published only after the group
// token that began the epoch is mined in the publisher's own headers and
// borg's wraps of the epoch's key are published (spec section 8.3):
// unwrapped names the members still without a wrap, and the rotation
// refuses while there is one unless allow is set.
func (e *Engine) Rotate(ctx context.Context, w *Writer, plan map[string]Choice, allow bool) (*RotateResult, error) {
	res := &RotateResult{}
	target := w.Group.Current()
	owes := Owes(w, target.Epoch)
	if !w.Stand.Behind && len(owes) == 0 {
		return res, nil
	}
	ignored, err := Covered(owes, plan, func(k string) bool { return Known(w.Vault, k) })
	if err != nil {
		return nil, err
	}
	if len(ignored) > 0 {
		e.note("nothing is owed for %v (already under epoch %d, or no longer in the vault): left as they are", ignored, target.Epoch)
	}
	missing, err := vread.WrapsMissing(ctx, e.Legs.Groups, w.Group, target.Epoch)
	if err != nil {
		return nil, err
	}
	if len(missing) > 0 {
		var who []string
		for _, m := range missing {
			who = append(who, hex.EncodeToString(m))
		}
		if !allow {
			return nil, fmt.Errorf("%w: epoch %d, %d member(s) (%v): a version keyed under it now could not be opened by them; run a borg command so the organisation's home publishes them, or pass -unwrapped to go on (a member in rotation debt is never wrapped to)", ErrUnwrapped, target.Epoch, len(missing), who)
		}
		e.note("warning: %d member(s) hold no wrap of epoch %d and cannot open what is keyed under it: %v", len(missing), target.Epoch, who)
	}
	sym, err := e.EpochKey(ctx, w.Group, target.Epoch)
	if err != nil {
		return nil, err
	}
	vid := w.Vault.ID
	for {
		owes = Owes(w, target.Epoch)
		if !w.Stand.Behind && len(owes) == 0 {
			break
		}
		batch := owes
		if len(batch) > MaxChanges {
			batch = batch[:MaxChanges]
		}
		c := Change{}
		if w.Stand.Behind {
			ep := target
			c.Epoch = &ep
			c.What = fmt.Sprintf("vault %s token seq %d (acknowledge epoch %d)", vread.Short(vid), w.Pred.Seq+1, target.Epoch)
		}
		for _, s := range batch {
			ch := plan[s.Key()]
			if ch.Retire {
				c.Retire = append(c.Retire, s.ID)
				res.Retired = append(res.Retired, s.Key())
				continue
			}
			// The version the new one follows is also the one whose value
			// and label it carries on: in an interval vault that is the
			// latest deferred version, not the listed one, whose value a
			// same-value re-keying would otherwise bring back.
			after, err := e.predecessor(w, s.ID, true)
			if err != nil {
				return res, err
			}
			if after == nil {
				return res, fmt.Errorf("%s: this home holds no record of the version the set holds: run `bsecret sync`", s.Key())
			}
			it := Item{Name: s.Name, Value: ch.Value, Label: after.Label}
			if ch.Same {
				p, err := e.valueOf(ctx, after)
				if err != nil {
					return res, fmt.Errorf("%s: its value could not be read for a same-value re-keying: %w", s.Key(), err)
				}
				it.Value, it.Type, it.NotAfter, it.RotateEvery = p.Value, p.Type, p.NotAfter, p.RotateEvery
			}
			m, err := e.mint(ctx, w, it, target, sym, after)
			if err != nil {
				return res, err
			}
			c.Update = append(c.Update, m)
			res.Rekeyed = append(res.Rekeyed, s.Key())
		}
		if err := e.transition(ctx, w, c); err != nil {
			return res, err
		}
		res.Tokens++
		if c.Epoch != nil {
			ep := target.Epoch
			res.Acknowledged = &ep
		}
		v := e.St.VaultByID(vid)
		if w, err = e.Ready(ctx, v); err != nil {
			return res, err
		}
		if w.Group.Current().Epoch != target.Epoch {
			return res, fmt.Errorf("the group began epoch %d while the vault was re-keying under epoch %d: run `bsecret rotate` again, with a choice for every secret", w.Group.Current().Epoch, target.Epoch)
		}
	}
	return res, nil
}

// Retire retires secrets by name (spec section 8.1): one token that lists
// their identifiers in retire. While the vault is in debt only stale
// secrets may be retired, which the transition rules hold it to.
func (e *Engine) Retire(ctx context.Context, w *Writer, names []string) error {
	if w.Stand.Behind {
		return fmt.Errorf("vault %s is %s: the only transition built is the acknowledgement (bsecret rotate, with -retire for what is to go)", vread.Short(w.Vault.ID), w.Stand)
	}
	c := Change{}
	seen := map[[32]byte]bool{}
	for _, n := range names {
		id, err := secrec.SecretID(hex32(w.Vault.ID), n)
		if err != nil {
			return fmt.Errorf("name %q breaks the name grammar", n)
		}
		if _, ok := current(w, id); !ok {
			return fmt.Errorf("%q is not in the vault's set", n)
		}
		if seen[id] {
			return fmt.Errorf("%q is named twice", n)
		}
		seen[id] = true
		c.Retire = append(c.Retire, id)
	}
	c.What = fmt.Sprintf("vault %s token seq %d (retire %d)", vread.Short(w.Vault.ID), w.Pred.Seq+1, len(names))
	return e.transition(ctx, w, c)
}

// Retractable are the versions of a vault the owner retracts (spec sections
// 8.1, 8.2 and 8.4), by funding tree:
//
//   - always, in a per-version vault, every version published and never
//     listed (what a transition that lost its predecessor left behind); in
//     an interval vault an unlisted version only below the listed one, since
//     a version an unlisted successor still links through is kept (spec
//     section 4.4);
//   - every version of the secrets in retired that the set no longer holds;
//   - with ended, once the vault is settled, every version a later token
//     replaced or retired that is keyed under an epoch before the vault's
//     (which a removed member could open), and every version of any retired
//     secret.
func Retractable(v *state.Vault, epoch uint64, interval, ended bool, retired map[string]bool) map[string][]uint32 {
	out := map[string][]uint32{}
	live := map[string]bool{}
	top := map[string]uint64{}
	for i := range v.Versions {
		x := &v.Versions[i]
		if x.Listed && !x.Ended {
			live[x.ID] = true
			if x.Version > top[x.ID] {
				top[x.ID] = x.Version
			}
		}
	}
	for i := range v.Versions {
		x := &v.Versions[i]
		if x.Swept != "" || x.Tree == "" {
			continue
		}
		switch {
		case x.Listed && x.Ended && !live[x.ID] && (ended || retired[x.ID]):
		case x.Listed && x.Ended && ended && x.Epoch < epoch:
		case !x.Listed && !interval:
		case !x.Listed && interval && (!live[x.ID] || x.Version < top[x.ID]):
		default:
			continue
		}
		out[x.Tree] = append(out[x.Tree], x.Vout)
	}
	for t := range out {
		sort.Slice(out[t], func(i, j int) bool { return out[t][i] < out[t][j] })
	}
	return out
}

// SweepEnded retracts what Retractable names, one sweep a funding tree,
// and returns how many versions it retracted. It does nothing while the
// vault is in debt or a transition is in flight.
func (e *Engine) SweepEnded(ctx context.Context, v *state.Vault, ended bool, retired []string) (int, error) {
	recs, err := Records(v)
	if err != nil || len(recs) == 0 || v.Pending != nil {
		return 0, err
	}
	last := recs[len(recs)-1]
	if last.Stale != 0 {
		return 0, nil
	}
	ids := map[string]bool{}
	for _, n := range retired {
		if id, err := secrec.SecretID(hex32(v.ID), n); err == nil {
			ids[hex.EncodeToString(id[:])] = true
		}
	}
	todo := Retractable(v, last.Epoch, last.Anchor == secrec.AnchorInterval, ended, ids)
	trees := make([]string, 0, len(todo))
	for t := range todo {
		trees = append(trees, t)
	}
	sort.Strings(trees)
	n := 0
	for _, t := range trees {
		sw, err := e.Retract(ctx, v.Crypt, t, todo[t])
		if err != nil {
			return n, err
		}
		n += len(todo[t])
		e.note("sweep %s: %d version(s) on funding tree %s retracted at height %d", Short(sw.Txid), len(todo[t]), Short(t), sw.Height)
	}
	return n, nil
}

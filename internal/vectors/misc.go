package vectors

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strings"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"

	"github.com/lightwebinc/bcommon/cbor"
	"github.com/lightwebinc/bcommon/pushdrop"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

func sha256sum(b []byte) [32]byte { return sha256.Sum256(b) }

func asMap(rec []byte) cbor.Map {
	v, err := cbor.DecodeValue(rec)
	if err != nil {
		panic(err)
	}
	return v.(cbor.Map)
}

func setKey(m cbor.Map, k uint64, v cbor.Value) cbor.Map {
	out := make(cbor.Map, 0, len(m)+1)
	done := false
	for _, p := range m {
		if p.Key == k {
			if v != nil {
				out = append(out, cbor.Pair{Key: k, Val: v})
			}
			done = true
			continue
		}
		out = append(out, p)
	}
	if !done && v != nil {
		out = append(out, cbor.Pair{Key: k, Val: v})
	}
	return out
}

type deleted struct{}

// mutate re-encodes rec, canonically, with key k set to v or removed.
func mutate(rec []byte, k uint64, v cbor.Value) []byte {
	m := asMap(rec)
	if _, ok := v.(deleted); ok {
		m = setKey(m, k, nil)
	} else {
		m = setKey(m, k, v)
	}
	b, err := cbor.Encode(m)
	if err != nil {
		panic(err)
	}
	return b
}

func getKey(m cbor.Map, k uint64) cbor.Value {
	for _, p := range m {
		if p.Key == k {
			return p.Val
		}
	}
	return nil
}

// aliasKey is 02 || p+1: an x-coordinate above the field prime that some
// parsers reduce and accept.
func aliasKey() []byte {
	p := ec.S256().P
	x := new(big.Int).Add(p, big.NewInt(1)).Bytes()
	return append([]byte{0x02}, x...)
}

func clone(v *secrec.Vault) *secrec.Vault {
	c := *v
	c.Create = append([]secrec.Entry(nil), v.Create...)
	c.Update = append([]secrec.Entry(nil), v.Update...)
	c.Retire = append([][32]byte(nil), v.Retire...)
	c.Labels = append([]string(nil), v.Labels...)
	return &c
}

// nextToken builds the successor of pred from changes, applying them to
// set, with honest count, stale and root; a case overrides a field
// afterwards to make a token that lies.
func nextToken(pred *secrec.Vault, predTx [32]byte, set map[[32]byte]secrec.Current, epoch uint64, create, update []secrec.Entry, retire [][32]byte) *secrec.Vault {
	v := clone(pred)
	v.Seq, v.Prev, v.Epoch, v.EpochID = pred.Seq+1, predTx, epoch, GroupEpochs[epoch].EpochID
	v.Create, v.Update, v.Retire = sortEntries(create), sortEntries(update), sort32(retire)
	if v.Create == nil {
		v.Create = []secrec.Entry{}
	}
	if v.Update == nil {
		v.Update = []secrec.Entry{}
	}
	if v.Retire == nil {
		v.Retire = [][32]byte{}
	}
	for _, id := range retire {
		delete(set, id)
	}
	for _, e := range append(append([]secrec.Entry(nil), create...), update...) {
		set[e.ID] = secrec.Current{ID: e.ID, Version: e.Version, ContentID: e.ContentID, Epoch: epoch, Seq: v.Seq}
	}
	var cur []secrec.Current
	v.Stale = 0
	for _, c := range set {
		cur = append(cur, c)
		if c.Epoch < epoch {
			v.Stale++
		}
	}
	v.Count, v.Root, v.Created = uint64(len(cur)), secrec.SetRoot(cur), pred.Created+600
	return v
}

// otherTip labels the in-set case whose path names another token at the
// latest token's seq.
const otherTip = "the current version with a path that names another token at the same seq"

// ---- vault-v1.json ----

type entryVec struct {
	Secret     string `json:"secret"`
	ID         string `json:"id"`
	Version    uint64 `json:"version"`
	ContentID  string `json:"contentId"`
	Commitment string `json:"commitment"`
}

func genVault(s *Scenario, files map[string][]byte) error {
	names := map[[32]byte]string{}
	for _, v := range s.Versions {
		names[v.Rec.ID] = v.Name
	}
	ev := func(a []secrec.Entry) []entryVec {
		out := []entryVec{}
		for _, e := range a {
			out = append(out, entryVec{names[e.ID], hx(e.ID[:]), e.Version, hx(e.ContentID[:]), hx(e.Commitment[:])})
		}
		return out
	}
	type vv struct {
		Label   string     `json:"label"`
		File    string     `json:"file"`
		Length  int        `json:"length"`
		Seq     uint64     `json:"seq"`
		Prev    string     `json:"prev"`
		Epoch   uint64     `json:"epoch"`
		EpochID string     `json:"epochId"`
		Rekeys  bool       `json:"acknowledgesANewEpoch"`
		Create  []entryVec `json:"create"`
		Update  []entryVec `json:"update"`
		Retire  []string   `json:"retire"`
		Count   uint64     `json:"count"`
		Stale   uint64     `json:"stale"`
		Root    string     `json:"root"`
		SetOf   []string   `json:"setAfter"`
		Txid    string     `json:"standInTxid"`
		Height  uint32     `json:"height"`
		Status  string     `json:"status"`
	}
	labels := []string{
		"create the vault: two secrets, epoch 0",
		"update one secret, epoch 0",
		"create a large secret whose ciphertext is not carried, epoch 0",
		"acknowledge epoch 1 after a removal: one secret re-keyed, two still stale",
		"clear the debt: one more secret re-keyed, the large one retired",
		"nothing is stale, so a secret is created",
		"acknowledge epoch 2 after a scheduled rotation: every secret re-keyed at once",
	}
	files2 := []string{"vault-create.hex", "vault-update.hex", "vault-large.hex", "vault-rekey.hex", "vault-settle.hex", "vault-add.hex", "vault-rotate.hex"}
	var recs []vv
	f := secrec.NewVaultFold()
	var sets [][]secrec.Current
	for i, v := range s.Vaults {
		st := f.Apply(v)
		set := f.Set()
		sets = append(sets, set)
		x := vv{Label: labels[i], File: files2[i], Length: len(s.VaultRecs[i]), Seq: v.Seq, Prev: hx(v.Prev[:]), Epoch: v.Epoch,
			EpochID: hx(v.EpochID[:]), Rekeys: i > 0 && secrec.Rekeys(s.Vaults[i-1], v), Create: ev(v.Create), Update: ev(v.Update),
			Retire: []string{}, Count: v.Count, Stale: v.Stale, Root: hx(v.Root[:]), SetOf: []string{}, Txid: hx(s.VaultTxids[i][:]),
			Height: s.Heights[i], Status: st}
		for _, r := range v.Retire {
			x.Retire = append(x.Retire, hx(r[:]))
		}
		for _, c := range set {
			x.SetOf = append(x.SetOf, fmt.Sprintf("%s version %d (epoch %d)", names[c.ID], c.Version, c.Epoch))
		}
		recs = append(recs, x)
		putHex(files, files2[i], s.VaultRecs[i])
	}

	// Transitions a host refuses, each one change to an admitted one.
	type tv struct {
		Label   string `json:"label"`
		From    int    `json:"from"`
		To      string `json:"to"`
		Verdict string `json:"verdict"`
	}
	var transitions []tv
	for i := 1; i < len(s.Vaults); i++ {
		if err := secrec.CheckVaultTransition(s.Vaults[i-1], s.VaultTxids[i-1], s.Vaults[i]); err != nil {
			return err
		}
		transitions = append(transitions, tv{labels[i], i - 1, hx(s.VaultRecs[i]), "admitted"})
	}
	other := s.Versions["ssh/deploy-key@1"]
	otherID, _ := secrec.SecretID(s.VaultID, "another/secret")
	spare := secrec.Entry{ID: otherID, Version: 1, ContentID: label("content-id/spare"), Commitment: label("commitment/spare")}
	for _, c := range []struct {
		label  string
		from   int
		mutate func(v *secrec.Vault)
		want   error
	}{
		{"seq skips", 0, func(v *secrec.Vault) { v.Seq = 2 }, secrec.ErrTransition},
		{"prev names another transaction", 0, func(v *secrec.Vault) { v.Prev = label("txid/elsewhere") }, secrec.ErrTransition},
		{"another organisation", 0, func(v *secrec.Vault) { v.Org = Alice.Pub() }, secrec.ErrTransition},
		{"another crypt", 0, func(v *secrec.Vault) { v.Crypt = "example_crypt_qzxkvbmwtr" }, secrec.ErrTransition},
		{"another vault id", 0, func(v *secrec.Vault) { v.Vault = label("vault/other") }, secrec.ErrTransition},
		{"another group", 0, func(v *secrec.Vault) { v.Group[0] ^= 1 }, secrec.ErrTransition},
		{"another hall", 0, func(v *secrec.Vault) { v.Hall = "example_hall_qzxkvbmwtr" }, secrec.ErrTransition},
		{"a label added after the first token", 0, func(v *secrec.Vault) { v.Labels = append(append([]string(nil), v.Labels...), "secret") }, secrec.ErrTransition},
		{"the anchor mode changed after the first token", 0, func(v *secrec.Vault) { v.Anchor = secrec.AnchorInterval }, secrec.ErrTransition},
		{"the epoch goes back", 3, func(v *secrec.Vault) {
			v.Epoch, v.EpochID = 0, GroupEpochs[0].EpochID
			v.Stale = 0
		}, secrec.ErrEpoch},
		{"the same epoch under another epoch id", 0, func(v *secrec.Vault) { v.EpochID = GroupEpochs[1].EpochID }, secrec.ErrEpoch},
		{"a later epoch under the same epoch id", 2, func(v *secrec.Vault) { v.EpochID = GroupEpochs[0].EpochID }, secrec.ErrEpoch},
		{"a new epoch acknowledged and nothing counted stale", 2, func(v *secrec.Vault) { v.Stale = 0 }, secrec.ErrDebt},
		{"a new epoch acknowledged and too little counted stale", 2, func(v *secrec.Vault) { v.Stale = 1 }, secrec.ErrDebt},
		{"stale not reduced by a re-keying while in debt", 3, func(v *secrec.Vault) { v.Stale = 2 }, secrec.ErrDebt},
		{"more re-keyed and retired than were stale", 3, func(v *secrec.Vault) {
			v.Update = sortEntries(append(v.Update, entry(other)))
		}, secrec.ErrDebt},
		{"stale counted where nothing was stale", 0, func(v *secrec.Vault) { v.Stale = 1 }, secrec.ErrDebt},
		{"count disagrees", 0, func(v *secrec.Vault) { v.Count = 3 }, secrec.ErrCount},
		{"count not reduced by a retirement", 3, func(v *secrec.Vault) { v.Count = 3 }, secrec.ErrCount},
	} {
		next := clone(s.Vaults[c.from+1])
		c.mutate(next)
		if err := secrec.CheckVaultTransition(s.Vaults[c.from], s.VaultTxids[c.from], next); !errors.Is(err, c.want) {
			return fmt.Errorf("vault transition %q: got %v", c.label, err)
		}
		rec, err := next.Encode()
		if err != nil {
			return fmt.Errorf("vault transition %q: %w", c.label, err)
		}
		transitions = append(transitions, tv{c.label, c.from, hx(rec), secrec.Reason(c.want)})
	}
	// A secret created while one is stale is refused by the record's own
	// rule, before any predecessor is read: the record cannot be encoded.
	inDebt := clone(s.Vaults[3])
	inDebt.Create = []secrec.Entry{spare}
	inDebt.Count++
	if _, err := inDebt.Encode(); !errors.Is(err, secrec.ErrDebt) {
		return fmt.Errorf("a create in debt: %v", err)
	}

	// Fold: chains every host admits token by token and the index reports.
	// after is the fold's set once a record is applied: for a record that
	// breaks the fold, the set of the last token before it, unchanged.
	type after struct {
		Root  string `json:"root"`
		Count int    `json:"count"`
		Stale uint64 `json:"stale"`
	}
	type fv struct {
		Label    string   `json:"label"`
		Records  []string `json:"records"`
		Statuses []string `json:"statuses"`
		After    []after  `json:"after"`
	}
	afterOf := func(f *secrec.VaultFold) after {
		root := secrec.SetRoot(f.Set())
		return after{Root: hx(root[:]), Count: len(f.Set()), Stale: f.Stale()}
	}
	var folds []fv
	fold := func(lbl string, upTo int, build func(pred *secrec.Vault, set map[[32]byte]secrec.Current) *secrec.Vault, want string, more ...func(pred *secrec.Vault, set map[[32]byte]secrec.Current) *secrec.Vault) error {
		ff := secrec.NewVaultFold()
		x := fv{Label: lbl}
		for i := 0; i <= upTo; i++ {
			x.Statuses = append(x.Statuses, ff.Apply(s.Vaults[i]))
			x.Records = append(x.Records, hx(s.VaultRecs[i]))
			x.After = append(x.After, afterOf(ff))
		}
		pred, predTx := s.Vaults[upTo], s.VaultTxids[upTo]
		set := map[[32]byte]secrec.Current{}
		for _, c := range sets[upTo] {
			set[c.ID] = c
		}
		for n, b := range append([]func(*secrec.Vault, map[[32]byte]secrec.Current) *secrec.Vault{build}, more...) {
			next := b(pred, set)
			raw, err := next.Encode()
			if err != nil {
				return fmt.Errorf("fold %q: %w", lbl, err)
			}
			if err := secrec.CheckVaultTransition(pred, predTx, next); err != nil {
				return fmt.Errorf("fold %q: a host would refuse the token: %w", lbl, err)
			}
			before := afterOf(ff)
			st := ff.Apply(next)
			x.Statuses = append(x.Statuses, st)
			x.Records = append(x.Records, hx(raw))
			x.After = append(x.After, afterOf(ff))
			if (st == secrec.StatusSetMismatch || st == secrec.StatusStaleMismatch) && afterOf(ff) != before {
				return fmt.Errorf("fold %q: a token that broke the fold changed the set", lbl)
			}
			if n == 0 && st != want {
				return fmt.Errorf("fold %q: %s, want %s", lbl, st, want)
			}
			if n > 0 && st != want {
				return fmt.Errorf("fold %q: the status did not stick: %s", lbl, st)
			}
			pred, predTx = next, label("txid/fold/%s/%d", lbl, n)
		}
		folds = append(folds, x)
		return nil
	}
	next := nextToken
	db, _ := secrec.SecretID(s.VaultID, "db/password")
	api, _ := secrec.SecretID(s.VaultID, "api/token")
	fresh := func(id [32]byte, version uint64, tag string) secrec.Entry {
		return secrec.Entry{ID: id, Version: version, ContentID: label("content-id/fold/%s", tag), Commitment: label("commitment/fold/%s", tag)}
	}
	if err := fold("an update of a secret the set does not hold", 0, func(p *secrec.Vault, set map[[32]byte]secrec.Current) *secrec.Vault {
		v := next(p, s.VaultTxids[0], set, 0, nil, nil, nil)
		v.Update = []secrec.Entry{spare}
		return v
	}, secrec.StatusSetMismatch, func(p *secrec.Vault, set map[[32]byte]secrec.Current) *secrec.Vault {
		return next(p, label("txid/fold/an update of a secret the set does not hold/0"), set, 0, nil, []secrec.Entry{fresh(db, 2, "after-broken")}, nil)
	}); err != nil {
		return err
	}
	if err := fold("a secret created that the set already holds", 0, func(p *secrec.Vault, set map[[32]byte]secrec.Current) *secrec.Vault {
		v := next(p, s.VaultTxids[0], set, 0, nil, nil, nil)
		v.Create = []secrec.Entry{fresh(db, 2, "recreate")}
		v.Count = 3
		return v
	}, secrec.StatusSetMismatch); err != nil {
		return err
	}
	if err := fold("a version that does not rise", 0, func(p *secrec.Vault, set map[[32]byte]secrec.Current) *secrec.Vault {
		return next(p, s.VaultTxids[0], set, 0, nil, []secrec.Entry{fresh(db, 1, "same-version")}, nil)
	}, secrec.StatusSetMismatch); err != nil {
		return err
	}
	if err := fold("a root that the set does not give", 0, func(p *secrec.Vault, set map[[32]byte]secrec.Current) *secrec.Vault {
		v := next(p, s.VaultTxids[0], set, 0, nil, []secrec.Entry{fresh(db, 2, "bad-root")}, nil)
		v.Root = label("root/elsewhere")
		return v
	}, secrec.StatusSetMismatch); err != nil {
		return err
	}
	if err := fold("a retired secret created again below its last version", 4, func(p *secrec.Vault, set map[[32]byte]secrec.Current) *secrec.Vault {
		tls, _ := secrec.SecretID(s.VaultID, "tls/key")
		return next(p, s.VaultTxids[4], set, 1, []secrec.Entry{fresh(tls, 1, "recreate-low")}, nil, nil)
	}, secrec.StatusSetMismatch); err != nil {
		return err
	}
	if err := fold("while in debt, a secret already re-keyed is updated again and counted as clearing debt", 3, func(p *secrec.Vault, set map[[32]byte]secrec.Current) *secrec.Vault {
		v := next(p, s.VaultTxids[3], set, 1, nil, []secrec.Entry{fresh(db, 3, "double-rekey")}, nil)
		v.Stale = 1 // what admission requires; the fold counts 2 still stale
		return v
	}, secrec.StatusStaleMismatch); err != nil {
		return err
	}
	if err := fold("a commitment an earlier token listed", 0, func(p *secrec.Vault, set map[[32]byte]secrec.Current) *secrec.Vault {
		e := fresh(api, 2, "reuse")
		e.Commitment = s.Versions["db/password@1"].Rec.Commitment
		return next(p, s.VaultTxids[0], set, 0, nil, []secrec.Entry{e}, nil)
	}, secrec.StatusCommitmentReuse); err != nil {
		return err
	}
	if err := fold("a retired secret created again above its last version", 4, func(p *secrec.Vault, set map[[32]byte]secrec.Current) *secrec.Vault {
		tls, _ := secrec.SecretID(s.VaultID, "tls/key")
		return next(p, s.VaultTxids[4], set, 1, []secrec.Entry{fresh(tls, 2, "recreate")}, nil, nil)
	}, secrec.StatusConsistent); err != nil {
		return err
	}

	// The secret answer's inclusion context: db/password in the set of the
	// last token; it does not verify for another version or another root.
	last := len(s.Vaults) - 1
	cur := s.Versions["db/password@3"]
	ictx, err := secrec.ProveSecret(uint64(last), s.VaultTxids[last], sets[last], cur.Rec.ID)
	if err != nil {
		return err
	}
	ctxBytes, err := ictx.Encode()
	if err != nil {
		return err
	}
	back, err := secrec.DecodeContext(ctxBytes)
	if err != nil || !back.VerifySecret(cur.Rec.ID, 3, cur.CID, s.Vaults[last].Root) {
		return errors.New("the inclusion context does not verify")
	}
	old := s.Versions["db/password@2"]
	if back.VerifySecret(cur.Rec.ID, 2, old.CID, s.Vaults[last].Root) || back.VerifySecret(cur.Rec.ID, 3, cur.CID, s.Vaults[last-1].Root) {
		return errors.New("an inclusion context verified what it should not")
	}
	// A reader's first check: the record against the vault's latest token
	// and the inclusion path a host answered with it.
	type iv struct {
		Label    string `json:"label"`
		Record   string `json:"record"`
		TokenSeq int    `json:"tokenSeq"`
		Token    string `json:"token,omitempty"`
		Context  string `json:"context"`
		Verdict  string `json:"verdict"`
	}
	var inSet []iv
	check := func(lbl string, token *secrec.Vault, seq int, changed bool, key string, proveAt int, want string) error {
		v := s.Versions[key]
		c, err := secrec.ProveSecret(uint64(proveAt), s.VaultTxids[proveAt], sets[proveAt], v.Rec.ID)
		if lbl == otherTip {
			// A path that names another token at the same seq: the tip an
			// orphaned block held.
			c.Token = label("txid/orphaned-tip")
		}
		if err != nil {
			return fmt.Errorf("in-set %q: %w", lbl, err)
		}
		cb, err := c.Encode()
		if err != nil {
			return err
		}
		got := "in the set"
		if err := secrec.CheckInSet(token, s.VaultTxids[seq], v.Rec, c); err != nil {
			got = secrec.Reason(err)
		}
		if got != want {
			return fmt.Errorf("in-set %q: %s, want %s", lbl, got, want)
		}
		x := iv{Label: lbl, Record: v.File, TokenSeq: seq, Context: hx(cb), Verdict: got}
		if changed {
			raw, err := token.Encode()
			if err != nil {
				return err
			}
			x.Token = hx(raw)
		}
		inSet = append(inSet, x)
		return nil
	}
	noDebt := clone(s.Vaults[3])
	noDebt.Stale = 0
	otherLabels := clone(s.Vaults[6])
	otherLabels.Labels = []string{"internal", "public"}
	for _, c := range []struct {
		lbl     string
		token   *secrec.Vault
		seq     int
		changed bool
		key     string
		proveAt int
		want    string
	}{
		{"the current version against the latest token", s.Vaults[6], 6, false, "db/password@3", 6, "in the set"},
		{"a re-keyed version against a token that still counts others stale", s.Vaults[3], 3, false, "db/password@2", 3, "in the set"},
		{"a stale version, keyed under an earlier epoch, while the token counts it stale", s.Vaults[3], 3, false, "api/token@2", 3, "in the set"},
		{"an older version with the path of the current one", s.Vaults[6], 6, false, "db/password@2", 6, "listing"},
		{"the current version with a path for an earlier token's set", s.Vaults[6], 6, false, "db/password@3", 5, "listing"},
		{otherTip, s.Vaults[6], 6, false, "db/password@3", 6, "listing"},
		{"a version keyed under an earlier epoch in a vault that says nothing is stale", noDebt, 3, true, "api/token@2", 3, "listing"},
		{"a record whose label is not one of the vault's", otherLabels, 6, true, "db/password@3", 6, "listing"},
	} {
		if err := check(c.lbl, c.token, c.seq, c.changed, c.key, c.proveAt, c.want); err != nil {
			return err
		}
	}
	if err := secrec.CheckInSet(s.Vaults[6], s.VaultTxids[6], cur.Rec, nil); secrec.Reason(err) != "listing" {
		return errors.New("a record with no path passed the in-set check")
	}
	empty := secrec.SetRoot(nil)
	return put(files, "vault-v1.json", map[string]any{
		"note": "standInTxid is a fixed stand-in for the mined token's txid that the next token's prev names, in hash byte order; height is the " +
			"example block height the audit vector uses. Each refused transition is one change to an admitted one and is refused by a host against " +
			"the predecessor named in from. The fold cases are chains every host admits token by token and the index reports; after is the set the fold holds once each record is applied (its root, its size and how many of it are stale), and a record that breaks the fold leaves it as the record before left it.",
		"vault":       hx(s.VaultID[:]),
		"labels":      s.Labels,
		"anchor":      secrec.AnchorVersion,
		"emptyRoot":   hx(empty[:]),
		"leafRule":    "leaf datum SHA-256(id || version as eight bytes big-endian || content id); RFC 6962 over the leaves in ascending order of id",
		"records":     recs,
		"transitions": transitions,
		"createInDebt": map[string]string{"verdict": "debt",
			"note": "the token of seq 3 with one secret added to create: refused by the record's own rule, since its stale is not zero"},
		"fold":  folds,
		"inSet": inSet,
		"secretContext": map[string]any{
			"secret":   "db/password",
			"version":  3,
			"setOf":    last,
			"token":    hx(s.VaultTxids[last][:]),
			"layout":   "[seq, token txid in hash byte order, index, size, [[sibling, sibling is on the left], ...]]",
			"context":  hx(ctxBytes),
			"verifies": true,
			"refused":  "version 2's content id against the same context, and version 3's against the root of the token before",
		},
	})
}

// ---- refusal-v1.json ----

type refusalVec struct {
	Record string `json:"record"`
	Label  string `json:"label"`
	Hex    string `json:"hex"`
	Reason string `json:"reason"`
}

func genRefusal(s *Scenario, files map[string][]byte) error {
	decoders := map[string]func([]byte) error{
		"vault":   func(b []byte) error { _, err := secrec.DecodeVault(b); return err },
		"secret":  func(b []byte) error { _, err := secrec.DecodeSecret(b); return err },
		"payload": func(b []byte) error { _, err := secrec.DecodePayload(b); return err },
	}
	vault, rekey := s.VaultRecs[0], s.VaultRecs[3]
	sec := s.Versions["db/password@1"]
	sec2 := s.Versions["db/password@2"]
	big := bytes.Repeat([]byte{0}, secrec.MaxVaultRecord)
	entries := asMap(vault)
	create := getKey(entries, 13).([]cbor.Value)
	e0 := create[0].([]cbor.Value)
	sixtyFive := func() []cbor.Value {
		out := make([]cbor.Value, 65)
		for i := range out {
			id := label("id/many/%d", i)
			out[i] = []cbor.Value{id[:], uint64(1), id[:], id[:]}
		}
		return out
	}()
	type c struct {
		rec, label string
		b          []byte
		want       string
	}
	cases := []c{
		{"vault", "over the bound", mutate(vault, 40, big), "too-large"},
		{"vault", "trailing byte", append(append([]byte(nil), vault...), 0x00), "cbor"},
		{"vault", "an array, not a map", []byte{0x81, 0x00}, "cbor"},
		{"vault", "65 keys", func() []byte {
			m := asMap(vault)
			for k := uint64(20); len(m) < 65; k++ {
				m = append(m, cbor.Pair{Key: k, Val: uint64(0)})
			}
			b, _ := cbor.Encode(m)
			return b
		}(), "too-large"},
		{"vault", "a text key", func() []byte {
			b, _ := cbor.Encode(append(asMap(vault), cbor.Pair{Key: "x", Val: uint64(1)}))
			return b
		}(), "key-type"},
		{"vault", "the secret magic", mutate(vault, 0, secrec.MagicSecret), "magic"},
		{"vault", "crypt missing", mutate(vault, 1, deleted{}), "missing"},
		{"vault", "crypt as bytes", mutate(vault, 1, []byte(Crypt)), "type"},
		{"vault", "crypt without a suffix", mutate(vault, 1, "example_crypt"), "crypt"},
		{"vault", "crypt with a nine-letter suffix", mutate(vault, 1, "example_crypt_hmqzvtkwr"), "crypt"},
		{"vault", "owner key alias (02 || p+1)", mutate(vault, 2, aliasKey()), "identity"},
		{"vault", "the owner is the anyone key", mutate(vault, 2, secrec.AnyoneKey()), "identity"},
		{"vault", "vault id of 31 bytes", mutate(vault, 3, bytes.Repeat([]byte{7}, 31)), "range"},
		{"vault", "empty name", mutate(vault, 6, ""), "name"},
		{"vault", "a name of 65 bytes", mutate(vault, 6, strings.Repeat("a", 65)), "name"},
		{"vault", "a name with a line feed", mutate(vault, 6, "ops\nvault"), "name"},
		{"vault", "a name with a carriage return", mutate(vault, 6, "ops\rvault"), "name"},
		{"vault", "a name with a tab", mutate(vault, 6, "ops\tvault"), "name"},
		{"vault", "a name with an escape (U+001B)", mutate(vault, 6, "ops\x1b[2Jvault"), "name"},
		{"vault", "a name with a delete (U+007F)", mutate(vault, 6, "ops\x7fvault"), "name"},
		{"vault", "a name with a C1 control, next line (U+0085)", mutate(vault, 6, "ops\u0085vault"), "name"},
		{"vault", "a name with a line separator (U+2028)", mutate(vault, 6, "ops\u2028vault"), "name"},
		{"vault", "a name with a paragraph separator (U+2029)", mutate(vault, 6, "ops\u2029vault"), "name"},
		{"vault", "hall without a suffix", mutate(vault, 7, "example_hall"), "hall"},
		{"vault", "group id of 15 bytes", mutate(vault, 8, bytes.Repeat([]byte{7}, 15)), "range"},
		{"vault", "epoch above 2^32 - 1", mutate(vault, 9, uint64(1)<<32), "range"},
		{"vault", "no labels", mutate(vault, 11, []cbor.Value{}), "label"},
		{"vault", "labels not ascending", mutate(vault, 11, []cbor.Value{"internal", "confidential"}), "label"},
		{"vault", "a label in upper case", mutate(vault, 11, []cbor.Value{"Internal"}), "label"},
		{"vault", "17 labels", mutate(vault, 11, func() []cbor.Value {
			out := make([]cbor.Value, 17)
			for i := range out {
				out[i] = fmt.Sprintf("l%02d", i)
			}
			return out
		}()), "label"},
		{"vault", "an anchor mode this version does not define", mutate(vault, 12, uint64(2)), "range"},
		{"vault", "65 created", mutate(vault, 13, sixtyFive), "list"},
		{"vault", "created not ascending by id", mutate(vault, 13, []cbor.Value{create[1], create[0]}), "list"},
		{"vault", "an entry of three elements", mutate(vault, 13, []cbor.Value{[]cbor.Value{e0[0], e0[1], e0[2]}}), "entry"},
		{"vault", "an entry at version 0", mutate(vault, 13, []cbor.Value{[]cbor.Value{e0[0], uint64(0), e0[2], e0[3]}, create[1]}), "entry"},
		{"vault", "an entry at version 2^53", mutate(vault, 13, []cbor.Value{[]cbor.Value{e0[0], uint64(1) << 53, e0[2], e0[3]}, create[1]}), "entry"},
		{"vault", "entries out of order, the second at version 0: an entry's own rule is decided before the list's order", mutate(vault, 13,
			[]cbor.Value{create[1], []cbor.Value{e0[0], uint64(0), e0[2], e0[3]}}), "entry"},
		{"vault", "65 created, the first of three elements: the list's length is decided first", mutate(vault, 13,
			append([]cbor.Value{[]cbor.Value{e0[0], e0[1], e0[2]}}, sixtyFive[1:]...)), "list"},
		{"vault", "an entry whose content id is 31 bytes", mutate(vault, 13, []cbor.Value{[]cbor.Value{e0[0], e0[1], e0[2].([]byte)[:31], e0[3]}, create[1]}), "entry"},
		{"vault", "retire holds a 31-byte id", mutate(vault, 15, []cbor.Value{bytes.Repeat([]byte{1}, 31)}), "list"},
		{"vault", "count above the vault bound", mutate(vault, 16, uint64(secrec.MaxSecrets+1)), "range"},
		{"vault", "stale not an integer", mutate(vault, 17, "0"), "type"},
		{"vault", "root of 31 bytes", mutate(vault, 18, bytes.Repeat([]byte{1}, 31)), "range"},
		{"vault", "created 0", mutate(vault, 19, uint64(0)), "range"},
		{"vault", "a secret both created and retired", mutate(vault, 15, []cbor.Value{e0[0]}), "list"},
		{"vault", "one commitment for two entries", mutate(vault, 13, []cbor.Value{create[0],
			[]cbor.Value{create[1].([]cbor.Value)[0], uint64(1), create[1].([]cbor.Value)[2], e0[3]}}), "list"},
		{"vault", "seq 0 with a prev", mutate(vault, 5, bytes.Repeat([]byte{1}, 32)), "chain"},
		{"vault", "seq 1 without a prev", mutate(vault, 4, uint64(1)), "chain"},
		{"vault", "seq 0 whose count is not its create list", mutate(vault, 16, uint64(3)), "count"},
		{"vault", "seq 0 that updates", mutate(mutate(vault, 13, []cbor.Value{create[0]}), 14, []cbor.Value{create[1]}), "count"},
		{"vault", "seq 0 with something stale", mutate(vault, 17, uint64(1)), "debt"},
		{"vault", "stale above count", mutate(rekey, 17, uint64(4)), "debt"},
		{"vault", "a secret created while one is stale", mutate(mutate(rekey, 13, []cbor.Value{sixtyFive[0]}), 16, uint64(4)), "debt"},
		{"vault", "no crypt and a bad label set: key 1 is decided first", mutate(mutate(vault, 11, []cbor.Value{}), 1, deleted{}), "missing"},

		{"secret", "over the bound", mutate(sec.Raw, 40, bytes.Repeat([]byte{0}, secrec.MaxSecretRecord)), "too-large"},
		{"secret", "the vault magic", mutate(sec.Raw, 0, secrec.MagicVault), "magic"},
		{"secret", "owner key alias (02 || p+1)", mutate(sec.Raw, 2, aliasKey()), "identity"},
		{"secret", "id of 31 bytes", mutate(sec.Raw, 4, bytes.Repeat([]byte{1}, 31)), "range"},
		{"secret", "version 0", mutate(sec.Raw, 5, uint64(0)), "range"},
		{"secret", "a label with an underscore", mutate(sec.Raw, 7, "top_secret"), "label"},
		{"secret", "epoch above 2^32 - 1", mutate(sec.Raw, 9, uint64(1)<<32), "range"},
		{"secret", "commitment missing", mutate(sec.Raw, 11, deleted{}), "missing"},
		{"secret", "length 0", mutate(sec.Raw, 13, uint64(0)), "range"},
		{"secret", "salt of 12 bytes", mutate(sec.Raw, 14, bytes.Repeat([]byte{1}, 12)), "range"},
		{"secret", "segment of 15 bytes", mutate(sec.Raw, 15, uint64(15)), "range"},
		{"secret", "segment above 1 MiB", mutate(sec.Raw, 15, uint64(secrec.MaxSegment+1)), "range"},
		{"secret", "created 0", mutate(sec.Raw, 16, uint64(0)), "range"},
		{"secret", "self wrap of 79 bytes", mutate(sec.Raw, 17, sec.Rec.Self[:79]), "range"},
		{"secret", "epoch wrap of 182 bytes", mutate(sec.Raw, 18, bytes.Repeat([]byte{1}, 182)), "range"},
		{"secret", "inline as text", mutate(sec.Raw, 19, "ciphertext"), "type"},
		{"secret", "inline of no bytes", mutate(sec.Raw, 19, []byte{}), "range"},
		{"secret", "version 1 with a previous", mutate(sec.Raw, 6, bytes.Repeat([]byte{1}, 32)), "chain"},
		{"secret", "version 2 without a previous", mutate(sec2.Raw, 6, make([]byte, 32)), "chain"},
		{"secret", "a length no plaintext produces: one segment's tag and nothing else", mutate(mutate(sec.Raw, 13, uint64(16)), 19, deleted{}), "range"},
		{"secret", "a length that leaves a last segment of a tag alone", mutate(mutate(mutate(sec.Raw, 15, uint64(16)), 13, uint64(48)), 19, deleted{}), "range"},
		{"secret", "a length one byte above the longest ciphertext (2^27)", mutate(mutate(mutate(sec.Raw, 15, uint64(16)), 13, uint64(secrec.MaxLength+1)), 19, deleted{}), "range"},
		{"secret", "a length whose plaintext is one byte above the payload bound (2^26)", mutate(mutate(sec.Raw, 13, secrec.CipherLength(secrec.MaxPayload+1, 16384)), 19, deleted{}), "range"},
		{"secret", "inline of one byte less than length", mutate(sec.Raw, 19, sec.Cipher[:len(sec.Cipher)-1]), "content"},
		{"secret", "inline with one byte changed", func() []byte {
			ct := append([]byte(nil), sec.Cipher...)
			ct[0] ^= 1
			return mutate(sec.Raw, 19, ct)
		}(), "content"},
		{"secret", "an inline ciphertext above the inline bound", func() []byte {
			ct := bytes.Repeat([]byte{9}, secrec.MaxInline+32)
			h := sha256.Sum256(ct)
			return mutate(mutate(mutate(sec.Raw, 19, ct), 13, uint64(len(ct))), 12, h[:])
		}(), "range"},

		{"payload", "the secret magic", mutate(sec.Plain, 0, secrec.MagicSecret), "magic"},
		{"payload", "a name with an upper-case letter", mutate(sec.Plain, 1, "DB/password"), "name"},
		{"payload", "a name with an empty segment", mutate(sec.Plain, 1, "db//password"), "name"},
		{"payload", "a name that ends with a slash", mutate(sec.Plain, 1, "db/"), "name"},
		{"payload", "a name of 129 bytes", mutate(sec.Plain, 1, strings.Repeat("a", 129)), "name"},
		{"payload", "value missing", mutate(sec.Plain, 2, deleted{}), "missing"},
		{"payload", "value as text", mutate(sec.Plain, 2, "hunter2"), "type"},
		{"payload", "an empty media type", mutate(sec.Plain, 3, ""), "range"},
		{"payload", "notAfter 0", mutate(sec.Plain, 4, uint64(0)), "range"},
		{"payload", "padding of no bytes", mutate(sec.Plain, 6, []byte{}), "range"},
	}
	var out []refusalVec
	for _, x := range cases {
		err := decoders[x.rec](x.b)
		if got := secrec.Reason(err); err == nil || got != x.want {
			return fmt.Errorf("refusal %s %q: got %q (%v), want %q", x.rec, x.label, got, err, x.want)
		}
		out = append(out, refusalVec{x.rec, x.label, hx(x.b), x.want})
	}
	// The largest ciphertext a record may describe is accepted.
	largest := mutate(mutate(sec.Raw, 13, secrec.CipherLength(secrec.MaxPayload, 16384)), 19, deleted{})
	if _, err := secrec.DecodeSecret(largest); err != nil {
		return fmt.Errorf("the largest ciphertext is refused: %w", err)
	}
	// Unknown keys are preserved, not refused.
	withUnknown := mutate(vault, 30, "a later version's field")
	v, err := secrec.DecodeVault(withUnknown)
	if err != nil {
		return err
	}
	re, err := v.Encode()
	if err != nil || !bytes.Equal(re, withUnknown) {
		return errors.New("an unknown key was not preserved")
	}
	punk := mutate(sec.Plain, 30, "a later version's field")
	p, err := secrec.DecodePayload(punk)
	if err != nil {
		return err
	}
	if re, err = p.Encode(); err != nil || !bytes.Equal(re, punk) {
		return errors.New("an unknown payload key was not preserved")
	}
	return put(files, "refusal-v1.json", map[string]any{
		"note": "Each case is a valid scenario record, or a valid payload, with one change (two where the label says so), refused by the record's own rules " +
			"in the order of spec section 3.1.",
		"refusals": out,
		"largestAccepted": map[string]any{"record": "secret", "hex": hx(largest), "length": secrec.CipherLength(secrec.MaxPayload, 16384),
			"note": "a record without its ciphertext whose length is what a payload of 2^26 bytes produces at a segment of 16384"},
		"unknownKeyKept": []map[string]string{
			{"record": "vault", "hex": hx(withUnknown), "key": "30"},
			{"record": "payload", "hex": hx(punk), "key": "30"},
		},
	})
}

// ---- query-v1.json ----

func genQuery(s *Scenario, files map[string][]byte) error {
	o := hx(Org.Pub())
	vid := hx(s.VaultID[:])
	sid := hx(s.Versions["db/password@1"].Rec.ID[:])
	txid := displayHex(label("txid/funding"))
	type cv struct {
		Class   string   `json:"class"`
		Members []string `json:"members"`
		Price   string   `json:"price"`
		Limit   int      `json:"limit"`
	}
	var classes []cv
	for _, c := range secrec.Classes {
		price := "free"
		if !c.Free {
			price = "priceable"
		}
		classes = append(classes, cv{c.Name, c.Members, price, c.Limit})
	}
	// No priced class is a superset of a free class.
	for _, p := range secrec.Classes {
		if p.Free {
			continue
		}
		for _, f := range secrec.Classes {
			if !f.Free {
				continue
			}
			sub := true
			for _, m := range f.Members {
				if !contains(p.Members, m) {
					sub = false
				}
			}
			if sub {
				return fmt.Errorf("priced class %s is a superset of free class %s", p.Name, f.Name)
			}
		}
	}
	q := func(kv ...string) string {
		var b strings.Builder
		b.WriteString("{")
		for i := 0; i < len(kv); i += 2 {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, "%q:%q", kv[i], kv[i+1])
		}
		b.WriteString("}")
		return b.String()
	}
	c := Crypt
	cases := []struct{ json, class, why string }{
		{q("crypt", c, "org", o, "vault", vid), "vault", ""},
		{q("crypt", c, "org", o, "vault", vid, "seq", "0"), "vault-seq", ""},
		{q("crypt", c, "vaultsOf", o), "vaults", ""},
		{q("crypt", c, "vaultsOf", o, "after", vid), "vaults-after", ""},
		{q("crypt", c, "org", o, "vault", vid, "secret", sid), "secret", ""},
		{q("crypt", c, "org", o, "vault", vid, "secret", sid, "version", "2"), "version", ""},
		{q("crypt", c, "org", o, "vault", vid, "pending", sid), "pending", ""},
		{q("crypt", c, "org", o, "secretsOf", vid), "secrets", ""},
		{q("crypt", c, "org", o, "secretsOf", vid, "after", sid), "secrets-after", ""},
		{q("crypt", c, "org", o, "vault", vid, "label", "restricted"), "label", ""},
		{q("crypt", c, "org", o, "vault", vid, "label", "restricted", "after", sid), "label-after", ""},
		{q("crypt", c, "spent", txid+".0"), "sweep", ""},
		{q("crypt", c, "history", o, "vault", vid, "secret", sid), "history", ""},
		{q("crypt", c, "history", o, "vault", vid, "secret", sid, "after", "2"), "history-after", ""},
		{q("crypt", c, "audit", o, "vault", vid), "audit", ""},
		{q("crypt", c, "audit", o, "vault", vid, "after", "0"), "audit-after", ""},
		{`{"crypt":"` + c + `","org":"00","org":"` + o + `","vault":"` + vid + `"}`, "vault", "a repeated member takes its last value"},
		{q("crypt", c, "org", o, "vault", vid, "extra", "1"), "", "a member no class defines"},
		{q("org", o, "vault", vid), "", "crypt missing"},
		{q("crypt", "example_crypt", "org", o, "vault", vid), "", "a crypt without its suffix"},
		{q("crypt", c, "org", strings.ToUpper(o), "vault", vid), "", "upper-case hex"},
		{q("crypt", c, "org", hx(aliasKey()), "vault", vid), "", "a key alias"},
		{q("crypt", c, "org", hx(secrec.AnyoneKey()), "vault", vid), "", "the anyone key"},
		{q("crypt", c, "org", o, "vault", vid[:62]), "", "a vault id of 31 bytes"},
		{q("crypt", c, "org", o, "vault", vid, "seq", "01"), "", "a leading zero"},
		{q("crypt", c, "org", o, "vault", vid, "secret", sid, "version", "0"), "", "version 0"},
		{q("crypt", c, "org", o, "vault", vid, "label", "Restricted"), "", "a label outside the grammar"},
		{q("crypt", c, "org", o, "history", o, "vault", vid, "secret", sid), "", "a free class's members and a priceable one's together"},
		{q("crypt", c, "org", o, "audit", o, "vault", vid), "", "a free class's members and a priceable one's together"},
		{q("crypt", c, "vaultsOf", o, "after", "12"), "", "a vaults cursor is a vault id"},
		{q("crypt", c, "audit", o, "vault", vid, "after", vid), "", "an audit cursor is a seq"},
		{q("crypt", c, "spent", txid+":0"), "", "an outpoint with a colon"},
		{q("crypt", c, "spent", txid+".00"), "", "an output index with a leading zero"},
		{`{"crypt":"` + c + `","org":"` + o + `","vault":"` + vid + `","seq":0}`, "", "a number where a string is required"},
		{`{"crypt":"` + c + `","org":null,"vault":"` + vid + `"}`, "", "a null member"},
		{`["crypt","` + c + `"]`, "", "not an object"},
		{`null`, "", "not an object"},
	}
	type qv struct {
		Question string `json:"question"`
		Class    string `json:"class,omitempty"`
		Refused  bool   `json:"refused"`
		Why      string `json:"why,omitempty"`
	}
	var qs []qv
	for _, x := range cases {
		got, err := secrec.ParseQuery([]byte(x.json))
		if x.class == "" {
			if err == nil {
				return fmt.Errorf("query %s was not refused", x.json)
			}
			qs = append(qs, qv{Question: x.json, Refused: true, Why: x.why})
			continue
		}
		if err != nil || got.Class.Name != x.class {
			return fmt.Errorf("query %s: %v", x.json, err)
		}
		qs = append(qs, qv{Question: x.json, Class: x.class, Why: x.why})
	}
	return put(files, "query-v1.json", map[string]any{
		"note":      "A question carries exactly the members of one class, every one a string. txids are in display order.",
		"classes":   classes,
		"questions": qs,
	})
}

func contains(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}

// ---- script-v1.json ----

func genScript(s *Scenario, files map[string][]byte) error {
	ctx := context.Background()
	w := Org.Wallet()
	type sv struct {
		Label  string `json:"label"`
		Script string `json:"script"`
		Claims string `json:"claims"`
	}
	var out []sv
	add := func(lbl string, sc *script.Script, want secrec.Kind) error {
		got := secrec.Classify(*sc)
		if got != want {
			return fmt.Errorf("script %q classified %q, want %q", lbl, got, want)
		}
		claim := string(got)
		if claim == "" {
			claim = "none"
		}
		out = append(out, sv{lbl, hx(*sc), claim})
		return nil
	}
	sec := s.Versions["db/password@1"]
	big := s.Versions["tls/key@1"]
	steps := []struct {
		label  string
		d      pushdrop.Derivation
		fields [][]byte
		sign   bool
		want   secrec.Kind
	}{
		{"vault token: tag, record, signature", secrec.VaultDerivation, [][]byte{secrec.TagVault, s.VaultRecs[0]}, true, secrec.KindVault},
		{"secret carrier output: record with its ciphertext inline, signature", secrec.SecretDerivation, [][]byte{sec.Raw}, true, secrec.KindSecret},
		{"secret carrier output: record without its ciphertext, signature", secrec.SecretDerivation, [][]byte{big.Raw}, true, secrec.KindSecret},
		{"funding output for secrets: the tag alone, unsigned", secrec.SecretDerivation, [][]byte{secrec.TagFunding}, false, secrec.KindFunding},
		{"funding output for a vault's first token", secrec.ChainDerivation, [][]byte{secrec.TagFunding}, false, secrec.KindFunding},
		{"funding tag signed: not a funding output", secrec.SecretDerivation, [][]byte{secrec.TagFunding}, true, secrec.KindNone},
		{"a vault record as a carrier's one field: claims nothing", secrec.SecretDerivation, [][]byte{s.VaultRecs[0]}, true, secrec.KindNone},
		{"a payload as a carrier's one field: claims nothing", secrec.SecretDerivation, [][]byte{sec.Plain}, true, secrec.KindNone},
		{"another application's funding tag (bo 0x02)", secrec.SecretDerivation, [][]byte{{'b', 'o', 0x02}}, false, secrec.KindNone},
		{"the tag prefix with an unassigned type byte (se 0x03)", secrec.VaultDerivation, [][]byte{{'s', 'e', 0x03}, s.VaultRecs[0]}, true, secrec.KindNone},
	}
	for _, st := range steps {
		sc, err := st.d.Lock(ctx, w, "", st.fields, st.sign)
		if err != nil {
			return err
		}
		if err := add(st.label, sc, st.want); err != nil {
			return err
		}
	}
	addr, _ := script.NewAddressFromPublicKey(Org.Priv.PubKey(), false)
	pk, _ := p2pkh.Lock(addr)
	if err := add("pay to public key hash", pk, secrec.KindNone); err != nil {
		return err
	}
	trunc := script.Script(append([]byte{0x21}, append(Org.Pub(), 0xac, 0x4c, 0xff, 0xa1)...))
	if err := add("a push that declares more bytes than are present", &trunc, secrec.KindNone); err != nil {
		return err
	}
	bare := script.Script(append([]byte{0x21}, append(Org.Pub(), 0xac)...))
	if err := add("a key and OP_CHECKSIG with nothing after", &bare, secrec.KindNone); err != nil {
		return err
	}
	return put(files, "script-v1.json", map[string]any{
		"note":    "Real locking scripts from bcommon's PushDrop under the owner's derivations. Classification reads only the key push, OP_CHECKSIG and the first push.",
		"scripts": out,
	})
}

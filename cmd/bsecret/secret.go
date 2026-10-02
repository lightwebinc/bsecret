package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/lightwebinc/bcommon/termsafe"

	"github.com/lightwebinc/bsecret/internal/engine"
	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/state"
	"github.com/lightwebinc/bsecret/internal/vread"
)

// ownVault is the vault of this home's a writing command works on: the
// -vault flag or config key (an identifier or a display name), else the
// home's only vault in the configured crypt.
func (g *global) ownVault(st *state.State) (*state.Vault, error) {
	var match []*state.Vault
	for i := range st.Vaults {
		v := &st.Vaults[i]
		if g.cfg.Crypt != "" && v.Crypt != g.cfg.Crypt {
			continue
		}
		if g.cfg.Vault == "" || v.ID == g.cfg.Vault || v.Name == g.cfg.Vault {
			match = append(match, v)
		}
	}
	switch {
	case len(match) == 1:
		return match[0], nil
	case len(match) == 0 && len(st.Vaults) == 0:
		return nil, usage("this home owns no vault (bsecret vault create, or bsecret sync on a new machine)")
	case len(match) == 0:
		return nil, usage("this home owns no vault %q in crypt %q", termsafe.Abbrev(g.cfg.Vault), g.cfg.Crypt)
	}
	var ids []string
	for _, v := range match {
		ids = append(ids, v.ID)
	}
	return nil, usage("this home owns %d vaults that match; name one by its identifier (-vault): %v", len(match), ids)
}

// ready opens a writer on this home's vault and gathers the evidence the
// contract asks for before any transition.
func (g *global) ready(ctx context.Context, w *writer) (*engine.Writer, error) {
	v, err := g.ownVault(w.h.st)
	if err != nil {
		return nil, err
	}
	wr, err := w.eng.Ready(ctx, v)
	if err != nil {
		return nil, werr(err)
	}
	return wr, nil
}

// werr puts a publisher's refusals in the command's exit codes: evidence
// that failed closed, a content key used before and a transition another
// beat to the chain are refused (exit 1); wraps not yet published are
// incomplete (exit 3).
func werr(err error) error {
	var lost *engine.LostError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, engine.ErrStale), errors.Is(err, secrec.ErrReuse), errors.As(err, &lost):
		return refused("%v", err)
	case errors.Is(err, engine.ErrUnwrapped):
		return incomplete("%v", err)
	}
	return err
}

// readValue reads a secret's value from a file, or from standard input.
func (g *global) readValue(file string) ([]byte, error) {
	var b []byte
	var err error
	if file != "" && file != "-" {
		b, err = os.ReadFile(file) //nolint:gosec // the operator's own path
	} else {
		b, err = io.ReadAll(io.LimitReader(g.stdin, secrec.MaxPayload+1))
	}
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, usage("no value: give it on standard input, or name a file (-file)")
	}
	if len(b) > secrec.MaxPayload-1024 {
		return nil, usage("the value is %d bytes; a payload holds at most %d", len(b), secrec.MaxPayload)
	}
	return b, nil
}

const putHelp = `usage: bsecret put <name> [-file FILE] [-label L] [-type T] [-not-after TIME] [-rotate-every DUR] [-defer]

Write the next version of a secret (spec sections 7.1 and 8.1). The value
is read from standard input, or from -file; it is never an argument, so it
is in no process list and no shell history. <name> is 1 to 128 bytes of
lowercase letters, digits, '.', '_', '-' and '/'.

The version gets a content key and salt of its own, drawn at random; its
payload is padded to a multiple of 256 bytes and sealed; the key is wrapped
to the owner's wallet and under the group's current epoch; and its carrier
is published, then listed in the vault's next token (one block): in create
for a secret the vault does not hold, in update for one it does. A
ciphertext of up to 16384 bytes rides in the record; a larger one is
written to the content directory (config key content) under its hash, to be
served under BRC-26, and the record names it by that hash.

Before anything is signed the token is applied to a copy of the fold of the
vault's own chain and held to the rules every host checks: a token either
would flag is refused here and never built. A content key this home has
ever published under is refused.

It refuses while the vault is behind its group or in debt: then the only
transitions are the acknowledgement and the re-keying (bsecret rotate).

-defer, in an interval vault, publishes the version and lists nothing:
readers take it by its link to the listed version, marked unanchored, until
'bsecret anchor' lists the latest.

A re-keyed credential must be given a new value where it is accepted:
bsecret stores and distributes the value; changing it at the service that
takes it is the owner's.`

func cmdPut(ctx context.Context, g *global, args []string) error {
	fs := g.flagSet("put", putHelp)
	file := fs.String("file", "", "read the value from this file instead of standard input")
	label := fs.String("label", "", "the secret's classification, one of the vault's labels (default: its last label, or confidential)")
	typ := fs.String("type", "", "a media type, kept inside the ciphertext")
	notAfter := fs.String("not-after", "", "when the value stops being usable, RFC 3339; a claim, kept inside the ciphertext")
	rotateEvery := fs.Duration("rotate-every", 0, "how often the owner intends to rotate the value; a claim, reported by bsecret due")
	hold := fs.Bool("defer", false, "an interval vault: publish the version and list nothing yet")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usage("put <name>, the value on standard input or in -file")
	}
	it := engine.Item{Name: pos[0], Label: *label, Type: *typ}
	if secrec.CheckSecretName(it.Name) != nil {
		return usage("name %q: 1 to %d bytes of lowercase letters, digits, '.', '_', '-' and '/', with no empty path segment", termsafe.Abbrev(it.Name), secrec.MaxSecretName)
	}
	if *label != "" && secrec.CheckLabel(*label) != nil {
		return usage("-label %q breaks the label grammar", termsafe.Abbrev(*label))
	}
	if len(*typ) > secrec.MaxType {
		return usage("-type is at most %d bytes", secrec.MaxType)
	}
	if *notAfter != "" {
		at, err := time.Parse(time.RFC3339, *notAfter)
		if err != nil || at.Unix() < 1 || at.Unix() > secrec.MaxTime {
			return usage("-not-after %q is not an RFC 3339 time", termsafe.Abbrev(*notAfter))
		}
		it.NotAfter = uint64(at.Unix()) //nolint:gosec // checked above
	}
	if *rotateEvery < 0 || rotateEvery.Seconds() > secrec.MaxEpoch {
		return usage("-rotate-every is a duration of 0 to %d seconds", uint64(secrec.MaxEpoch))
	}
	it.RotateEvery = uint64(rotateEvery.Seconds())
	if it.Value, err = g.readValue(*file); err != nil {
		return err
	}
	w, err := g.openWriter(ctx)
	if err != nil {
		return err
	}
	defer w.close(ctx, g)
	wr, err := g.ready(ctx, w)
	if err != nil {
		return err
	}
	res, err := w.eng.Put(ctx, wr, []engine.Item{it}, *hold)
	for _, r := range res {
		m := r.Minted
		what := "updated"
		if r.Created {
			what = "created"
		}
		fmt.Fprintf(g.stdout, "secret  %s version %d label %s epoch %d: carrier %s (%s)\n", m.Name, m.Record.Version, m.Record.Label, m.Record.Epoch, m.Txid, what)
		if m.Stored != "" {
			fmt.Fprintf(g.stdout, "stored  %s (%d bytes of ciphertext; serve it under %s)\n", m.Stored, m.Record.Length, secrec.Locator(m.Record.Hash))
		}
	}
	if err != nil {
		return werr(err)
	}
	v := w.h.st.VaultByID(wr.Vault.ID)
	if *hold {
		fmt.Fprintf(g.stdout, "deferred: published and not listed; readers take it unanchored until `bsecret anchor`\n")
		return nil
	}
	if err := g.printTip(v); err != nil {
		return err
	}
	// What a transition that lost its predecessor left published and
	// unlisted is retracted here (spec section 8.4).
	swept, err := w.eng.SweepEnded(ctx, v, false, nil)
	if swept > 0 {
		fmt.Fprintf(g.stdout, "swept   %d version(s) published earlier and never listed\n", swept)
	}
	return err
}

// printTip prints a vault's latest token.
func (g *global) printTip(v *state.Vault) error {
	last := state.Latest(v.Tokens)
	rec, err := secrec.DecodeVault(mustHex(last.Record))
	if err != nil {
		return err
	}
	fmt.Fprintf(g.stdout, "token   seq %d %s mined at height %d: %d secret(s), %d stale, epoch %d\n", rec.Seq, last.Txid, last.Height, rec.Count, rec.Stale, rec.Epoch)
	return nil
}

const anchorHelp = `usage: bsecret anchor

In an interval vault, list the latest unlisted version of every secret that
has one (spec section 4.4): one token. Versions that came and went between
two tokens were reachable only through the links of the version listed, and
are then retracted.`

func cmdAnchor(ctx context.Context, g *global, args []string) error {
	fs := g.flagSet("anchor", anchorHelp)
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return usage("anchor takes no arguments")
	}
	w, err := g.openWriter(ctx)
	if err != nil {
		return err
	}
	defer w.close(ctx, g)
	wr, err := g.ready(ctx, w)
	if err != nil {
		return err
	}
	n, err := w.eng.Anchor(ctx, wr)
	if err != nil {
		return werr(err)
	}
	if n == 0 {
		fmt.Fprintln(g.stdout, "nothing to anchor: every version published is listed")
		return nil
	}
	v := w.h.st.VaultByID(wr.Vault.ID)
	fmt.Fprintf(g.stdout, "anchored %d secret(s)\n", n)
	if err := g.printTip(v); err != nil {
		return err
	}
	swept, err := w.eng.SweepEnded(ctx, v, false, nil)
	if swept > 0 {
		fmt.Fprintf(g.stdout, "swept   %d version(s) that came and went between two tokens\n", swept)
	}
	return err
}

const retireHelp = `usage: bsecret retire <name>... [-keep]

Retire secrets (spec section 8.1): one token that lists their identifiers
in retire, and then a sweep of the funding outputs of every version of them
this home published, so that honest hosts stop answering them. -keep leaves
the versions answered, until a later rotation sweeps what it ended. A sweep
is not erasure: a copy anyone kept stays a copy, and whoever could read a
version still knows its value.

While the vault is in debt only stale secrets can be retired; while it is
behind its group nothing is, outside 'bsecret rotate -retire'.`

func cmdRetire(ctx context.Context, g *global, args []string) error {
	fs := g.flagSet("retire", retireHelp)
	keep := fs.Bool("keep", false, "do not sweep the retired secrets' versions")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return usage("retire <name>...")
	}
	w, err := g.openWriter(ctx)
	if err != nil {
		return err
	}
	defer w.close(ctx, g)
	wr, err := g.ready(ctx, w)
	if err != nil {
		return err
	}
	if err := w.eng.Retire(ctx, wr, pos); err != nil {
		return werr(err)
	}
	v := w.h.st.VaultByID(wr.Vault.ID)
	for _, n := range pos {
		fmt.Fprintf(g.stdout, "retired %s\n", n)
	}
	if err := g.printTip(v); err != nil {
		return err
	}
	var names []string
	if !*keep {
		names = pos
	}
	swept, err := w.eng.SweepEnded(ctx, v, false, names)
	if swept > 0 {
		fmt.Fprintf(g.stdout, "swept   %d version(s): retracted at every honest host\n", swept)
	}
	return err
}

// keysFor is how this home opens a content key: as the owner through the
// self wrap, or as a member through the key of the epoch a record names.
func (g *global) keysFor(o *opened) (vread.Keys, string, error) {
	e, err := g.openWallet()
	if err != nil {
		return vread.Keys{}, "", usage("reading a value needs this identity's key: %v", err)
	}
	s := e.Signer()
	if o.t.orgHex == s.IdentityHex() {
		return vread.Keys{Owner: s}, "the owner", nil
	}
	me := s.Identity.Compressed()
	cache := map[uint64][32]byte{}
	return vread.Keys{Epoch: func(ctx context.Context, epoch uint64) ([32]byte, error) {
		if k, ok := cache[epoch]; ok {
			return k, nil
		}
		k, err := vread.OpenEpoch(ctx, o.t.groups, s, me, o.group, epoch)
		if err == nil {
			cache[epoch] = k
		}
		return k, err
	}}, "a member", nil
}

const getHelp = `usage: bsecret get <name> [-show] [-version N] [-strict]

Read a secret's value (spec sections 7.2 and 14). Everything is checked
against this home's own headers, in the signed order, and the first check
that fails stops the read and names its culprit:

  the vault's chain  walked from its first token by spends, every
                     transition held to the rules, folded; never below the
                     token this home verified before (rollback)
  listing            the set this command folded holds this version, the
                     token that listed it lists this record, under the
                     record's epoch, and the group's chain began that epoch
  retracted          no mined sweep spends the record's funding output
  hash               the ciphertext is the length and hash the record
                     names, before any wrap is opened
  undecryptable      the wrap opens under the key of the epoch the record
                     names, and no other (the owner: its self wrap)
  commitment         the key is the one committed to
  tag                every segment's tag verifies
  payload            the plaintext is this secret's payload

The value is written raw to standard output, and only when standard output
is not a terminal, or with -show: a secret is not left in a scrollback by
default. Everything else goes to standard error: the vault's state
(settled, in debt, behind, ahead), whether the version is anchored, and
whether it is current or EXPOSED (keyed under an epoch before the group's
latest, so that someone the group has since removed can open it).

-strict refuses (exit 1) an exposed value or a vault that is not settled,
and is incomplete (exit 3) when no spend source says the token read is the
vault's latest. -version N reads version N as the host still holds it,
checked against the token that listed it; it is history, never current.

Exit 0 read; 1 a check failed; 3 no host held what was needed, or the
hosts disagree.`

func cmdGet(ctx context.Context, g *global, args []string) error {
	fs := g.flagSet("get", getHelp)
	show := fs.Bool("show", false, "write the value to standard output although it is a terminal")
	version := fs.Uint64("version", 0, "read this version, as history")
	strict := fs.Bool("strict", false, "refuse an exposed value, a vault not settled, or a state that may be stale")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usage("get <name>")
	}
	name := pos[0]
	if secrec.CheckSecretName(name) != nil {
		return usage("name %q breaks the name grammar", termsafe.Abbrev(name))
	}
	t, err := g.readTarget(ctx, true)
	if err != nil {
		return err
	}
	// The home is locked when there is one, so that the highest seq
	// verified is remembered.
	var st *state.State
	if h, err := g.openHome(); err == nil {
		defer h.close()
		st = h.st
		defer func() { _ = st.Save() }()
	}
	o, err := g.open(ctx, t, st)
	if err != nil {
		return err
	}
	if o.stand.Ahead {
		return refused("vault %s is %s: its owner wrote a token no honest tooling writes, and nothing is taken from it", vread.Short(t.vaultHex()), o.stand)
	}
	if o.chain.Broken() != "" {
		return refused("vault %s is broken from seq %d on (%s): its owner signed a false count; nothing is taken from it", vread.Short(t.vaultHex()), o.chain.Usable(), o.chain.Broken())
	}
	id, _ := secrec.SecretID(t.vault, name)
	keys, who, err := g.keysFor(o)
	if err != nil {
		return err
	}
	car, anchored, later, err := g.pick(ctx, o, id, name, *version)
	if err != nil {
		return err
	}
	rd, err := t.rd.Open(ctx, o.chain, o.group, car, anchored, keys, g.content())
	if err != nil {
		return failure(err)
	}
	head := o.chain.Head().Token.Vault
	fmt.Fprintf(g.stderr, "vault   %s %s seq %d: %s\n", t.vaultHex(), termsafe.Text(head.Name), head.Seq, o.stand)
	word, fresh, lerr := g.latest(ctx, o)
	if lerr != nil {
		return lerr
	}
	fmt.Fprintf(g.stderr, "latest  %s\n", word)
	rec := car.Carrier.Secret
	state := "anchored"
	switch {
	case *version != 0:
		state = "history: a token of the vault listed it, and it is not the vault's current version"
	case !rd.Anchored:
		state = "UNANCHORED (no mined token lists it yet; taken by its link to the listed version)"
	}
	switch {
	case *version != 0:
	case rd.Exposed:
		state += fmt.Sprintf(", EXPOSED: keyed under epoch %d and the group is at epoch %d, so a key the group has since removed or rotated away from opens it", rec.Epoch, o.group.Current().Epoch)
	case fresh:
		state += ", current"
	default:
		state += ", not known to be current"
	}
	fmt.Fprintf(g.stderr, "secret  %s version %d label %s epoch %d, read as %s: %s\n", termsafe.Text(rd.Payload.Name), rec.Version, termsafe.Text(rec.Label), rec.Epoch, who, state)
	if later {
		g.say("a later version exists that does not link to the listed one; the highest that links is read")
	}
	if p := rd.Payload; p.Type != "" || p.NotAfter != 0 {
		line := "claims "
		if p.Type != "" {
			line += " type " + termsafe.Text(p.Type)
		}
		if p.NotAfter != 0 {
			line += " not after " + time.Unix(int64(p.NotAfter), 0).UTC().Format(time.RFC3339) //nolint:gosec // bounded by the record
		}
		fmt.Fprintln(g.stderr, line)
	}
	if *strict {
		switch {
		case rd.Exposed || !o.stand.Settled():
			return refused("-strict: the value is exposed or the vault is not settled (%s); it is not written", o.stand)
		case !fresh:
			return incomplete("-strict: nothing says the token read is the vault's latest; the value is not written")
		}
	}
	if g.terminal && !*show {
		g.say("value   %d bytes, not written: standard output is a terminal (pipe it, or pass -show)", len(rd.Payload.Value))
	} else if _, err := g.stdout.Write(rd.Payload.Value); err != nil {
		return err
	}
	return o.problem
}

// pick finds the carrier to read for a secret: the listed version, or in
// an interval vault the highest version that links to it, or the version
// asked for.
func (g *global) pick(ctx context.Context, o *opened, id [32]byte, name string, version uint64) (car *vread.Car, anchored, later bool, err error) {
	t := o.t
	cur, inSet := o.chain.Current(id)
	notHeld := func(what string, errs map[string]error) error {
		for h, e := range errs {
			g.say("host %s: NOT ASKED: %s", h, firstLine(e.Error()))
		}
		return incomplete("%s: an empty answer proves nothing; ask another host, or bsecret fill", what)
	}
	if version != 0 {
		cars, refusedCars, errs := t.rd.Version(ctx, o.chain, id, version)
		g.reportRefused(refusedCars)
		var why error
		for _, c := range cars {
			if _, herr := o.chain.History(c); herr != nil {
				why = herr
				g.say("host %s: answered a carrier of version %d that is not read: %v", c.Host, version, herr)
				continue
			}
			return c, false, false, nil
		}
		if why != nil {
			return nil, false, false, failure(why)
		}
		return nil, false, false, notHeld(fmt.Sprintf("no host answers a carrier of %s version %d that a token of the vault listed", name, version), errs)
	}
	if !inSet {
		return nil, false, false, refused("the vault's set, folded here from its chain, holds no secret named %s", name)
	}
	cars, refusedCars, errs := t.rd.Secret(ctx, o.chain, id)
	g.reportRefused(refusedCars)
	var listed *vread.Car
	var why error
	for _, c := range cars {
		if _, lerr := o.chain.Listed(c); lerr != nil {
			why = lerr
			g.say("host %s: answered a carrier that is not the version the vault lists: %v", c.Host, lerr)
			continue
		}
		listed = c
		break
	}
	if listed == nil {
		if why != nil {
			return nil, false, false, failure(why)
		}
		return nil, false, false, notHeld(fmt.Sprintf("the vault lists %s at version %d, and no host answers its carrier", name, cur.Version), errs)
	}
	if o.chain.Head().Token.Vault.Anchor != secrec.AnchorInterval {
		return listed, true, false, nil
	}
	// An interval vault: the versions above the listed one, each fetched,
	// and the highest that links successor by successor.
	pending, refusedCars, _ := t.rd.Pending(ctx, o.chain, id)
	g.reportRefused(refusedCars)
	have := map[uint64]bool{}
	var top uint64
	links := append([]*vread.Car(nil), pending...)
	for _, c := range pending {
		have[c.Carrier.Secret.Version] = true
		if v := c.Carrier.Secret.Version; v > top {
			top = v
		}
	}
	for n := cur.Version + 1; n < top; n++ {
		if have[n] {
			continue
		}
		more, r, _ := t.rd.Version(ctx, o.chain, id, n)
		g.reportRefused(r)
		links = append(links, more...)
	}
	run, more, lerr := o.chain.Linked(listed, links)
	if lerr != nil {
		return nil, false, false, failure(lerr)
	}
	if len(run) == 0 {
		return listed, true, more, nil
	}
	return run[len(run)-1], false, more, nil
}

func (g *global) reportRefused(rs []vread.Refusal) {
	for _, r := range rs {
		g.say("host %s: REFUSED carrier %s (%s): %v", r.Host, termsafe.Abbrev(r.Txid), r.Reason, r.Err)
	}
}

const listHelp = `usage: bsecret list

The secrets of a vault (spec section 14): the set this command folded from
the vault's chain, each host's answer to the secrets class compared with
it (a host whose answer does not reproduce the root withheld or added a
record), and each secret's name, read from inside its ciphertext with this
home's key. A name is someone else's text: it is printed only once the
payload's checks pass, and it meets the name grammar. A secret this key
cannot open is listed by its identifier. No value is printed.

Exit 3 when no host's answer reproduces the set's root.`

func cmdList(ctx context.Context, g *global, args []string) error {
	fs := g.flagSet("list", listHelp)
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return usage("list takes no arguments")
	}
	t, err := g.readTarget(ctx, true)
	if err != nil {
		return err
	}
	var st *state.State
	if h, err := g.openHome(); err == nil {
		defer h.close()
		st = h.st
		defer func() { _ = st.Save() }()
	}
	o, err := g.open(ctx, t, st)
	if err != nil {
		return err
	}
	if o.stand.Ahead || o.chain.Broken() != "" {
		return refused("vault %s is not usable (%s): nothing is taken from it", vread.Short(t.vaultHex()), o.stand)
	}
	keys, _, err := g.keysFor(o)
	if err != nil {
		return err
	}
	problem := o.problem
	best := map[[32]byte]*vread.Car{}
	matched := false
	for _, sa := range t.rd.Secrets(ctx, o.chain) {
		switch {
		case sa.Err != nil:
			g.say("host %s: NOT ASKED: %s", sa.Host, firstLine(sa.Err.Error()))
		case sa.Matches:
			matched = true
			g.say("host %s: %d secret(s), the set's root reproduced", sa.Host, len(o.chain.Set()))
		default:
			g.say("host %s: its answer DOES NOT REPRODUCE the set's root: it withheld or added a record", sa.Host)
		}
		g.reportRefused(sa.Refused)
		for _, c := range sa.Cars {
			if _, lerr := o.chain.Listed(c); lerr == nil && best[c.Carrier.Secret.ID] == nil {
				best[c.Carrier.Secret.ID] = c
			}
		}
	}
	content := g.content()
	type row struct{ name, line string }
	var rows []row
	for _, cur := range o.chain.Set() {
		id := hex.EncodeToString(cur.ID[:])
		c := best[cur.ID]
		if c == nil {
			rows = append(rows, row{"~" + id, fmt.Sprintf("id:%s  version %d epoch %d: no host answers its carrier", id, cur.Version, cur.Epoch)})
			continue
		}
		rec := c.Carrier.Secret
		tail := fmt.Sprintf("version %d label %s epoch %d", rec.Version, termsafe.Text(rec.Label), rec.Epoch)
		if rec.Epoch < o.group.Current().Epoch {
			tail += " EXPOSED"
		}
		rd, err := t.rd.Open(ctx, o.chain, o.group, c, true, keys, content)
		if err != nil {
			var f *vread.Failure
			label := "unreadable"
			if errors.As(err, &f) {
				label = f.Label
			}
			rows = append(rows, row{"~" + id, fmt.Sprintf("id:%s  %s: %s", id, tail, label)})
			continue
		}
		// The name met the name grammar when the payload was decoded; it
		// is someone else's text all the same, and is filtered like any.
		rows = append(rows, row{rd.Payload.Name, fmt.Sprintf("%s  %s", termsafe.Text(rd.Payload.Name), tail)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	for _, r := range rows {
		fmt.Fprintln(g.stdout, r.line)
	}
	g.say("vault %s seq %d: %d secret(s); %s", vread.Short(t.vaultHex()), o.chain.Head().Seq(), len(o.chain.Set()), o.stand)
	if !matched && len(o.chain.Set()) > 0 {
		return incomplete("no host's answer reproduces the set's root")
	}
	return problem
}

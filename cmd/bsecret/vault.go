package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/lightwebinc/bcommon/guard"

	"github.com/lightwebinc/bcommon/termsafe"

	"github.com/lightwebinc/borg/borgrec"
	"github.com/lightwebinc/borg/reader"

	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/vread"
)

func parseTx(raw []byte, txid string) (*transaction.Transaction, error) {
	tx, err := guard.ParseTransaction(raw, guard.DefaultBound)
	if err != nil {
		return nil, err
	}
	if tx.TxID().String() != txid {
		return nil, fmt.Errorf("the source answered other bytes than %s", txid)
	}
	return tx, nil
}

const vaultHelp = `usage: bsecret vault create <group> -name NAME [-hall HALL] [-anchor version|interval] [-labels a,b,c]
       bsecret vault list
       bsecret vault show

create makes a vault keyed to a group of the organisation this home's
identity key is (spec section 8.1). <group> is the group's identifier (32
hex digits) or its name in the hall, which is the configured one (config
key hall) or -hall. The vault is bound to that group for good: its members
at each epoch are the vault's readers, and a removal from the group begins
an epoch the vault must then acknowledge and re-key under (bsecret rotate).
It names the group's current epoch, a label set (default confidential,
internal, public, restricted) and an anchor mode, all three fixed at the
first token:

  -anchor version   a reader takes only versions a mined token lists
                    (the default; for secrets people manage)
  -anchor interval  a reader also takes a linked version no token lists
                    yet, marked unanchored (for credentials machines rotate
                    faster than blocks; put -defer, then anchor)

The organisation must hold the epoch's key, which it does through its
signer key: run 'borg org signer' once in the organisation's borg home.
The first token spends an output of a chain tree, which gives the vault its
identifier, is waited for until it mines (one block), and is published with
the chain tree in its BEEF.

list prints the owner's vaults the hosts answer. show prints one vault's
chain token by token as this command verified it, its standing against its
group, and its set.`

func cmdVault(ctx context.Context, g *global, args []string) error {
	fs := g.flagSet("vault", vaultHelp)
	name := fs.String("name", "", "create: the vault's display name, 1 to 64 bytes")
	hall := fs.String("hall", "", "create: the borg hall the group lives in (default the configured hall)")
	anchor := fs.String("anchor", "version", "create: version or interval")
	labels := fs.String("labels", strings.Join(secrec.DefaultLabels, ","), "create: the vault's label set, comma separated")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	switch {
	case len(pos) == 2 && pos[0] == "create":
		return g.vaultCreate(ctx, pos[1], *name, *hall, *anchor, *labels)
	case len(pos) == 1 && pos[0] == "list":
		return g.vaultList(ctx)
	case len(pos) == 1 && pos[0] == "show":
		return g.vaultShow(ctx)
	}
	return usage("vault create <group> -name NAME | vault list | vault show")
}

// resolveGroup names a group of org in hall by its identifier or, through
// the hall's hosts, by its name.
func (g *global) resolveGroup(ctx context.Context, rd *reader.Client, hall string, org []byte, name string) ([secrec.GroupIDLen]byte, error) {
	if gid, err := reader.ParseGroup(name); err == nil {
		return gid, nil
	}
	ids, errs := rd.GroupsAll(ctx, hall, org)
	for h, e := range errs {
		if errors.Is(e, reader.ErrTruncated) {
			g.say("hall host %s: TRUNCATED: its answer of the groups is over borg's bound, and what it answered past the bound is not read: %v", h, e)
			continue
		}
		g.say("hall host %s: NOT ASKED for the groups: %s", h, firstLine(e.Error()))
	}
	var match []string
	for _, id := range ids {
		gv, err := rd.Group(ctx, hall, org, id)
		if err == nil && gv.Token.Name == name {
			match = append(match, id)
		}
	}
	switch len(match) {
	case 1:
		return reader.ParseGroup(match[0])
	case 0:
		if len(errs) > 0 {
			// A host not asked, or whose walk was cut at borg's bound
			// (reader.ErrTruncated), may hold the group: an empty answer
			// proves nothing.
			return [secrec.GroupIDLen]byte{}, incomplete("no group named %q of this organisation is answered in hall %s, and %d hall host(s) did not answer in full; name it by its identifier", termsafe.Abbrev(name), hall, len(errs))
		}
		return [secrec.GroupIDLen]byte{}, usage("no group named %q of this organisation is answered in hall %s; name it by its identifier", termsafe.Abbrev(name), hall)
	}
	return [secrec.GroupIDLen]byte{}, usage("%d groups are named %q; name one by its identifier: %v", len(match), termsafe.Abbrev(name), match)
}

func (g *global) vaultCreate(ctx context.Context, group, name, hall, anchor, labels string) error {
	if hall == "" {
		hall = g.cfg.Hall
	}
	if hall == "" || borgrec.CheckHall(hall) != nil {
		return usage("no hall: set hall (or -hall) to the borg hall identifier <name>_<suffix> the group lives in")
	}
	if g.cfg.Crypt == "" {
		return usage("no crypt: set crypt (or -crypt) to the crypt identifier <name>_<suffix> (bsecret crypt new prints one)")
	}
	if name == "" || len(name) > secrec.MaxName {
		return usage("-name: the vault's display name, 1 to %d bytes", secrec.MaxName)
	}
	// The record refuses a line break and every control character (spec
	// section 3). This tooling refuses more: whatever a terminal filter
	// would strip, so a name every reader can print as it is.
	if field(name) != name {
		return usage("-name holds a line break or a character a terminal would act on; a display name is one line of plain text")
	}
	var mode uint64
	switch anchor {
	case "version":
		mode = secrec.AnchorVersion
	case "interval":
		mode = secrec.AnchorInterval
	default:
		return usage("-anchor is version or interval")
	}
	var set []string
	for _, l := range strings.Split(labels, ",") {
		if l = strings.TrimSpace(l); l != "" {
			set = append(set, l)
		}
	}
	sort.Strings(set)
	if err := secrec.CheckLabels(set); err != nil {
		return usage("-labels: 1 to %d distinct labels, each 1 to %d bytes of lowercase letters, digits and single hyphens, starting with a letter", secrec.MaxLabels, secrec.MaxLabel)
	}
	w, err := g.openWriter(ctx)
	if err != nil {
		return err
	}
	defer w.close(ctx, g)
	gid, err := g.resolveGroup(ctx, w.eng.Legs.Groups, hall, w.eng.OrgKey(), group)
	if err != nil {
		return err
	}
	v, err := w.eng.CreateVault(ctx, g.cfg.Crypt, name, hall, gid, set, mode)
	if err != nil {
		return werr(err)
	}
	last := v.Tokens[len(v.Tokens)-1]
	rec, err := secrec.DecodeVault(mustHex(last.Record))
	if err != nil {
		return err
	}
	fmt.Fprintf(g.stdout, "vault   %s\nname    %s\ncrypt   %s\ngroup   %s in hall %s\nepoch   %d\nanchor  %s\nlabels  %s\ntoken   seq 0 %s mined at height %d\n",
		v.ID, field(v.Name), v.Crypt, v.Group, v.Hall, rec.Epoch, anchor, strings.Join(v.Labels, ","), last.Txid, last.Height)
	return nil
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func anchorName(a uint64) string {
	if a == secrec.AnchorInterval {
		return "interval"
	}
	return "version"
}

func (g *global) vaultList(ctx context.Context) error {
	t, err := g.readTarget(ctx, false)
	if err != nil {
		return err
	}
	toks, errs := t.rd.Vaults(ctx, t.crypt, t.org)
	var problem error
	for h, e := range errs {
		g.say("host %s: NOT ASKED: %s", h, firstLine(e.Error()))
		problem = incomplete("a host could not be asked")
	}
	ids := make([]string, 0, len(toks))
	for id := range toks {
		ids = append(ids, hex.EncodeToString(id[:]))
	}
	sort.Strings(ids)
	for _, id := range ids {
		key, _ := vread.Hex32(id)
		v := toks[key].Token.Vault
		fmt.Fprintf(g.stdout, "%s  %s  seq %d epoch %d, %d secret(s), %d stale, %s\n", id, field(v.Name), v.Seq, v.Epoch, v.Count, v.Stale, anchorName(v.Anchor))
	}
	g.say("%d vault(s) of %s answered in crypt %s; an answer here is a host's claim, and a vault is verified when it is read", len(ids), t.orgHex, t.crypt)
	return problem
}

func (g *global) vaultShow(ctx context.Context) error {
	t, err := g.readTarget(ctx, true)
	if err != nil {
		return err
	}
	o, err := g.open(ctx, t, nil)
	if err != nil {
		return err
	}
	head := o.chain.Head().Token.Vault
	out := g.stdout
	fmt.Fprintf(out, "vault   %s\nname    %s\nowner   %s\ncrypt   %s\ngroup   %s in hall %s\nanchor  %s\nlabels  %s\n", t.vaultHex(), field(head.Name), t.orgHex, t.crypt,
		reader.GroupHex(head.Group), head.Hall, anchorName(head.Anchor), strings.Join(head.Labels, ","))
	for i, tok := range o.chain.Tokens {
		v := tok.Token.Vault
		fmt.Fprintf(out, "token   seq %d %s height %d epoch %d +%d ~%d -%d: %d secret(s), %d stale: %s\n", v.Seq, tok.Txid, tok.Height, v.Epoch,
			len(v.Create), len(v.Update), len(v.Retire), v.Count, v.Stale, o.chain.Statuses[i])
	}
	fmt.Fprintf(out, "state   %s\n", o.stand)
	word, _, lerr := g.latest(ctx, o)
	if lerr != nil {
		return lerr
	}
	fmt.Fprintf(out, "latest  %s\n", word)
	for _, c := range o.chain.Set() {
		line := fmt.Sprintf("secret  %s version %d epoch %d (listed at seq %d)", hex.EncodeToString(c.ID[:]), c.Version, c.Epoch, c.Seq)
		if c.Epoch < o.group.Current().Epoch {
			line += ": EXPOSED"
		}
		fmt.Fprintln(out, line)
	}
	if o.chain.Broken() != "" || o.stand.Ahead {
		return refused("the vault is not usable as its owner left it")
	}
	return o.problem
}

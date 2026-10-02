package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/lightwebinc/bcommon/termsafe"

	"github.com/lightwebinc/borg/borgrec"
	"github.com/lightwebinc/borg/reader"

	"github.com/lightwebinc/bsecret/internal/config"
	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/state"
	"github.com/lightwebinc/bsecret/internal/vread"
)

// target is what a reading command reads: a crypt, an owner and usually a
// vault, with the readers over the configured hosts and headers.
type target struct {
	rd     *vread.Client
	groups *reader.Client
	crypt  string
	org    []byte
	orgHex string
	vault  [32]byte
	// own is set when this home's identity is the owner.
	own bool
	// st is this home's state as it was read, without the lock; nil when
	// there is no home.
	st *state.State
}

func (t *target) vaultHex() string { return hex.EncodeToString(t.vault[:]) }

// readTarget resolves the crypt, the owner (the -org flag or config key,
// else this home's identity when it owns a vault) and, when needVault, the
// vault (the -vault flag or config key: an identifier, or a display name
// that names one vault; else the owner's only vault).
func (g *global) readTarget(ctx context.Context, needVault bool) (*target, error) {
	rd, err := g.reader()
	if err != nil {
		return nil, err
	}
	gr, err := g.groups()
	if err != nil {
		return nil, err
	}
	t := &target{rd: rd, groups: gr, crypt: g.cfg.Crypt, orgHex: g.cfg.Org, st: g.peekState()}
	if t.st != nil && (t.orgHex == "" || t.orgHex == t.st.Identity) && (len(t.st.Vaults) > 0 || t.orgHex != "") {
		t.orgHex, t.own = t.st.Identity, true
	}
	if t.orgHex == "" {
		return nil, usage("no owner: set org (or -org) to the identity key of the organisation that owns the vault")
	}
	if t.org, err = parseKey("org", t.orgHex); err != nil {
		return nil, err
	}
	if t.crypt == "" && t.own {
		crypts := map[string]bool{}
		for i := range t.st.Vaults {
			crypts[t.st.Vaults[i].Crypt] = true
		}
		if len(crypts) == 1 {
			for c := range crypts {
				t.crypt = c
			}
		}
	}
	if t.crypt == "" {
		return nil, usage("no crypt: set crypt (or -crypt) to the crypt identifier <name>_<suffix> (bsecret crypt new prints one)")
	}
	if !needVault {
		return t, nil
	}
	return t, g.resolveVault(ctx, t)
}

// resolveVault names the vault a command reads.
func (g *global) resolveVault(ctx context.Context, t *target) error {
	want := g.cfg.Vault
	if config.IsHex32(want) {
		t.vault, _ = vread.Hex32(want)
		return nil
	}
	// By name, or the only one: first in this home's own record, then
	// among the vaults the hosts answer for the owner.
	names := map[string]string{}
	if t.own {
		for i := range t.st.Vaults {
			if v := &t.st.Vaults[i]; v.Crypt == t.crypt && len(v.Tokens) > 0 {
				names[v.ID] = v.Name
			}
		}
	}
	if len(names) == 0 || (want != "" && !hasName(names, want)) {
		toks, errs := t.rd.Vaults(ctx, t.crypt, t.org)
		for h, e := range errs {
			g.say("host %s: NOT ASKED for the vaults: %s", h, firstLine(e.Error()))
		}
		for id, tok := range toks {
			names[hex.EncodeToString(id[:])] = tok.Token.Vault.Name
		}
	}
	var match []string
	for id, n := range names {
		if want == "" || n == want {
			match = append(match, id)
		}
	}
	sort.Strings(match)
	switch {
	case len(match) == 1:
		t.vault, _ = vread.Hex32(match[0])
		return nil
	case len(match) == 0 && want == "":
		return incomplete("no vault of %s is answered in crypt %s: an empty answer proves nothing; name the vault by its identifier (-vault)", t.orgHex, t.crypt)
	case len(match) == 0:
		return usage("no vault named %q is known for %s in crypt %s; name it by its identifier (-vault)", termsafe.Abbrev(want), t.orgHex, t.crypt)
	case want == "":
		return usage("the owner has %d vaults in crypt %s; name one (-vault, by identifier or display name): %v", len(match), t.crypt, match)
	}
	return usage("%d vaults are named %q: a display name identifies nothing; name one by its identifier (-vault): %v", len(match), termsafe.Abbrev(want), match)
}

func hasName(names map[string]string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// reportChain prints how the hosts' answers compare with the canonical
// chain, and returns a problem when they disagree or one refused.
func (g *global) reportChain(v *vread.ChainView) error {
	var problem error
	for h, err := range v.HostErr {
		g.say("host %s: NOT ASKED: %s", h, firstLine(err.Error()))
		problem = incomplete("%d of %d host(s) answered about the vault", len(g.cfg.Hosts)-len(v.HostErr), len(g.cfg.Hosts))
	}
	for _, r := range v.Refused {
		g.say("host %s: REFUSED token %s (%s): %v", r.Host, termsafe.Abbrev(r.Txid), r.Reason, r.Err)
		// A host that answers what does not verify is a host at fault, not
		// a check that failed on what is read: the vault is read from what
		// verified, and the command is incomplete.
		problem = incomplete("a host answered a token that does not verify; it is not used")
	}
	hosts := make([]string, 0, len(v.Lacks))
	for h := range v.Lacks {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		if len(v.Lacks[h]) == 0 {
			continue
		}
		g.say("host %s: DISAGREES: it does not answer seq %s of the vault's chain, which another host answered", h, vread.JoinSeqs(v.Lacks[h]))
		if problem == nil {
			problem = incomplete("the hosts disagree about the vault's chain; it is read from those that answer it")
		}
	}
	for _, f := range v.Forks {
		g.say("token %s at seq %d verifies but does not descend from the vault's first token along the chain read (a fork, an orphan, or a token built on a parent no host admits); it is not used", f.Txid, f.Seq())
	}
	if beyond := v.Beyond(); len(beyond) > 0 {
		top := beyond[0]
		for _, t := range beyond {
			if t.Seq() > top.Seq() {
				top = t
			}
		}
		g.say("WITHHELD: %d verified token(s) of the vault exist above seq %d, the last this command could link (the highest at seq %d, %s): a token between is withheld, or its owner signed a stray one. What is read may be an older state", len(beyond), v.Latest().Seq(), top.Seq(), top.Txid)
		if problem == nil {
			problem = incomplete("verified tokens of the vault exist above the chain read; ask other hosts")
		}
	}
	if b := v.Broken(); b != "" {
		g.say("the vault's chain folds to %s at seq %d: its owner signed a token whose counts its own change lists do not give. It is UNUSABLE from that token on (fail closed)", b, v.Usable())
	}
	for i, s := range v.Statuses {
		if s == secrec.StatusCommitmentReuse {
			g.say("the vault's chain is INCONSISTENT at seq %d: %s; the version it lists under a used commitment is refused", i, s)
		}
	}
	return problem
}

// ratchet holds a vault to the latest token this home verified before
// (spec section 14, no going back): a host may not answer an older state
// as the latest. A host whose latest token is below the one remembered is
// named; when every host that answered is, the answer is refused
// (rollback), and when only some are it is left open, and the vault is
// read from the token this home holds and the hosts that are not behind.
func (g *global) ratchet(st *state.State, t *target, v *vread.ChainView) (problem, fatal error) {
	if st == nil {
		return nil, nil
	}
	if s := st.SeenOf(t.crypt, t.orgHex, t.vaultHex()); s != nil {
		behind, level := 0, 0
		hosts := make([]string, 0, len(v.HostLatest))
		for h := range v.HostLatest {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		for _, h := range hosts {
			if latest := v.HostLatest[h]; latest < s.Seq {
				behind++
				g.say("host %s: answers the vault to seq %d as its latest, and this home verified seq %d (%s): an older state", h, latest, s.Seq, s.Txid)
			} else {
				level++
			}
		}
		rolled := &vread.Failure{Label: vread.LabelRollback, Err: fmt.Errorf("every host that answered gives an older state of the vault than this home verified (seq %d, %s); ask other hosts", s.Seq, s.Txid)}
		switch {
		case uint64(len(v.Tokens)) <= s.Seq, behind > 0 && level == 0:
			return nil, rolled
		case behind > 0:
			problem = incomplete("a host answers an older state of the vault than this home verified; the vault is read from the others")
		}
		if v.Tokens[s.Seq].Txid != s.Txid {
			g.say("the token at seq %d is %s, and this home verified %s: a reorganisation displaced it, or the hosts answer a fork", s.Seq, v.Tokens[s.Seq].Txid, s.Txid)
		}
	}
	last := v.Latest()
	st.See(state.Seen{Crypt: t.crypt, Org: t.orgHex, Vault: t.vaultHex(), Seq: last.Seq(), Txid: last.Txid})
	return problem, nil
}

// opened is a vault established for reading: its chain, its group and its
// standing.
type opened struct {
	t     *target
	chain *vread.ChainView
	group *vread.Group
	stand vread.Standing
	// problem is what the hosts' answers left open: they disagree, or one
	// refused.
	problem error
}

// open establishes the vault's chain and its group, and holds the vault to
// what this home verified before. st is the home's state when the command
// holds its lock, so that what it verified is remembered; nil remembers
// nothing.
func (g *global) open(ctx context.Context, t *target, st *state.State) (*opened, error) {
	// With the home's lock held, the chain this home verified before is
	// where the walk starts; otherwise it is walked from seq 0.
	var known []*vread.Tok
	if st != nil {
		kept := state.LoadChain(g.cfg.Home, t.crypt, t.orgHex, t.vaultHex())
		var mem vread.Memory
		known, mem = vread.Remembered(ctx, kept, t.crypt, t.org, t.vault, t.rd.Headers, t.rd.Source)
		switch mem {
		case vread.MemoryUnknown:
			// Nothing is forgotten because a source failed: the seq this
			// home verified stays the floor.
			g.say("whether the token this home remembered of the vault is still mined could not be settled (the header source or the node did not answer for it): the chain is read again from its first token, and what this home verified stays its floor")
		case vread.MemoryCorrupt:
			g.say("the copy of the vault's chain this home kept does not read back; it is dropped and the chain is read again from its first token. What this home verified stays its floor")
			state.DropChain(g.cfg.Home, t.crypt, t.orgHex, t.vaultHex())
		case vread.MemoryDisplaced:
			g.say("the token this home remembered of the vault no longer verifies against the header source, and the node says it is not mined: a reorganisation displaced it. It is forgotten, and the chain is read again from its first token")
			state.DropChain(g.cfg.Home, t.crypt, t.orgHex, t.vaultHex())
			st.Forget(t.crypt, t.orgHex, t.vaultHex())
		}
	}
	cv, err := t.rd.Chain(ctx, t.crypt, t.org, t.vault, known...)
	if err != nil {
		if errors.Is(err, vread.ErrNoChain) {
			return nil, incomplete("vault %s: %v: an empty answer proves nothing", vread.Short(t.vaultHex()), err)
		}
		return nil, err
	}
	if st != nil && len(cv.Tokens) > len(known) {
		beefs := make([][]byte, len(cv.Tokens))
		for i, tok := range cv.Tokens {
			beefs[i] = tok.Beef
		}
		if err := state.SaveChain(g.cfg.Home, t.crypt, t.orgHex, t.vaultHex(), beefs); err != nil {
			g.say("the chain verified could not be kept in the home: %v", err)
		}
	}
	o := &opened{t: t, chain: cv, problem: g.reportChain(cv)}
	held := st
	if held == nil {
		held = t.st
	}
	rolled, fatal := g.ratchet(held, t, cv)
	if fatal != nil {
		return nil, failure(fatal)
	}
	if rolled != nil && o.problem == nil {
		o.problem = rolled
	}
	head := cv.Head()
	if head == nil {
		return nil, refused("vault %s: its first token breaks the fold (%s): nothing is taken from it", vread.Short(t.vaultHex()), cv.Statuses[0])
	}
	rec := head.Token.Vault
	// The group is held to the latest token of it this home verified, as
	// the vault is.
	hold(t.groups, held)
	if o.group, err = vread.ReadGroup(ctx, t.groups, rec.Hall, t.org, rec.Group); err != nil {
		var f *vread.Failure
		if errors.As(err, &f) {
			return nil, failure(err)
		}
		if errors.Is(err, reader.ErrNoChain) {
			return nil, incomplete("the vault's group %s in hall %s: %v", reader.GroupHex(rec.Group), rec.Hall, err)
		}
		return nil, fmt.Errorf("the vault's group %s in hall %s: %w", reader.GroupHex(rec.Group), rec.Hall, err)
	}
	if p := g.reportGroup(o.group); p != nil && o.problem == nil {
		o.problem = p
	}
	o.stand = o.group.Stand(rec)
	// Every epoch the vault's tokens name is one the group's chain began.
	for _, tok := range cv.Tokens[:cv.Usable()] {
		if secrec.CheckGroupEpoch(o.group.Epochs, tok.Token.Vault.Epoch, tok.Token.Vault.EpochID) != nil {
			o.stand.Ahead = true
		}
	}
	return o, nil
}

// reportGroup prints how the hall's hosts compare on the group's chain.
func (g *global) reportGroup(gr *vread.Group) error {
	var problem error
	for h, err := range gr.HostErr {
		g.say("hall host %s: NOT ASKED: %s", h, firstLine(err.Error()))
		problem = incomplete("a host of the group's hall could not be asked")
	}
	for _, r := range gr.Refused {
		g.say("hall host %s: REFUSED group token %s (%s): %v", r.Host, termsafe.Abbrev(r.Txid), r.Reason, r.Err)
		problem = incomplete("a host answered a group token that does not verify; it is not used")
	}
	for h, seqs := range gr.Lacks {
		if len(seqs) > 0 {
			g.say("hall host %s: DISAGREES: it does not answer seq %s of the group's chain", h, reader.JoinSeqs(seqs))
			if problem == nil {
				problem = incomplete("the hosts disagree about the group's chain; it is read from those that answer it")
			}
		}
	}
	if u := gr.Usable(); u < len(gr.Tokens) {
		g.say("the group's chain folds to %s at seq %d: unusable from that token on", gr.Statuses[u], u)
	}
	for i, s := range gr.Statuses {
		if s == borgrec.StatusCommitmentReuse || s == borgrec.StatusRejoinUnrotated {
			g.say("the group's chain is INCONSISTENT at seq %d: %s", i, s)
		}
	}
	return problem
}

// failure puts a reader's failed check in the command's exit codes: a
// check that names a culprit is refused, exit 1.
func failure(err error) error {
	var f *vread.Failure
	if errors.As(err, &f) {
		return refused("%s: %v", f.Label, f.Err)
	}
	if errors.Is(err, vread.ErrUnavailable) || errors.Is(err, vread.ErrNoWrap) {
		return incomplete("%v", err)
	}
	return err
}

// latest is the evidence that the head token is the vault's latest: its
// output unspent per the node. It returns a word for the report, and
// whether the evidence is positive.
func (g *global) latest(ctx context.Context, o *opened) (string, bool, error) {
	head := o.chain.Latest()
	sp := g.spends()
	if sp == nil {
		return fmt.Sprintf("seq %d is the highest any host asked answers; no spend source says it is the latest (config key asset), so this may be stale", head.Seq()), false, nil
	}
	by, err := sp.Spender(ctx, head.Txid, head.Token.Vout)
	if err != nil {
		return fmt.Sprintf("the node could not say whether seq %d is the latest (%s), so this may be stale", head.Seq(), firstLine(err.Error())), false, nil
	}
	if by == "" {
		return fmt.Sprintf("seq %d is the latest: its output is unspent per the node", head.Seq()), true, nil
	}
	raw, err := sp.TxRaw(ctx, by)
	if err != nil {
		return "", false, incomplete("the vault's token at seq %d is spent by %s, which the node could not show (%s): a later token exists, or the vault is terminated; what the hosts answer is not known to be the latest", head.Seq(), by, firstLine(err.Error()))
	}
	if tx, perr := parseTx(raw, by); perr == nil {
		if next, rerr := secrec.ReadToken(tx); rerr == nil && next.Vault.Vault == o.t.vault && bytes.Equal(next.Vault.Org, o.t.org) && next.Vault.Seq == head.Seq()+1 {
			return "", false, incomplete("the vault's token at seq %d is spent by its next token %s, which no host asked answers yet (not mined, not yet published, or withheld): what the hosts answer is not the latest", head.Seq(), by)
		}
	}
	return "", false, refused("the vault is TERMINATED: its latest token's output is spent by %s, which is not the vault's next token; nothing new is taken from it", by)
}

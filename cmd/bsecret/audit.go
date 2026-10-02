package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lightwebinc/bcommon/lookup"
	"github.com/lightwebinc/bcommon/termsafe"

	"github.com/lightwebinc/borg/reader"

	"github.com/lightwebinc/bsecret/internal/limits"
	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/vread"
)

const auditHelp = `usage: bsecret audit [-free] [-at URL] [-max-sats N] [-json]

Verify a vault's trail from block headers alone and report what it shows
(spec section 9). An auditor holds no key and reads no secret, and needs no
home: only the header source, the hosts and the vault's owner and
identifier. For every token of the vault's chain it checks that it is
mined (its proof against this command's headers), the owner's (its lock
and field signature), linked (it spends the token before it, from the
first token, whose input's outpoint hashes to the vault identifier), lawful
(the transition rules), consistent (the fold reproduces every count, root
and stale, versions rise, no commitment repeats) and keyed to the group
(its epoch and epoch id are those of a token that began that epoch on the
group's own chain, mined at or below it). The group's chain is read from
its hall's hosts by borg's own reader.

It then reports, for every epoch the group began after the vault's first
token: the height the group began it and whether it removed anyone; how
many vault tokens mined above that height still named an earlier epoch;
the height of the acknowledgement; the height after which nothing was left
under an earlier epoch; and the EXPOSURE WINDOW between the first and the
last, in blocks: how long the owner's own signed statements say a secret
stayed listed under an epoch a removed member held. Each secret's own
re-keying or retirement is listed with its height.

The tokens come from the priced audit class when a paid host is named (-at,
or the configured paid_host): the question is asked over BRC-104, the 402
is paid from this home's pool (BRC-105) up to -max-sats a page, and that
needs a home with coin. Otherwise, or with -free, they are read token by
token through the free vault-seq class from every host, which needs no
home and pays nothing.

What it does not prove (spec section 9.3): that the token it ends at is
the latest (it says which token that is, and what the node says of it);
that a listed version's record is what the token says; which key a wrap is
under; that a value changed; who read what.

Exit 0 the trail verifies; 1 the audit fails; 3 the hosts disagree or one
could not be asked.`

type auditToken struct {
	Seq    uint64 `json:"seq"`
	Txid   string `json:"txid"`
	Height uint32 `json:"height"`
	Epoch  uint64 `json:"epoch"`
	Create int    `json:"create"`
	Update int    `json:"update"`
	Retire int    `json:"retire"`
	Count  uint64 `json:"count"`
	Stale  uint64 `json:"stale"`
	Status string `json:"status"`
}

type auditWindow struct {
	Epoch        uint64 `json:"epoch"`
	Removed      bool   `json:"removed"`
	Began        uint32 `json:"began"`
	Late         uint64 `json:"late"`
	Acknowledged uint32 `json:"acknowledged,omitempty"`
	Settled      uint32 `json:"settled,omitempty"`
	// Exposure is Settled less Began, in blocks; Open is set when the
	// trail ends before the vault settled, and Exposure is then measured
	// to the trail's last token.
	Exposure uint32 `json:"exposureBlocks"`
	Open     bool   `json:"open"`
	Stale    uint64 `json:"stale"`
}

type auditEvent struct {
	Secret    string `json:"secret"`
	Kind      string `json:"kind"`
	Seq       uint64 `json:"seq"`
	Height    uint32 `json:"height"`
	Version   uint64 `json:"version"`
	Epoch     uint64 `json:"epoch"`
	FromEpoch uint64 `json:"fromEpoch"`
	// Exposure is the blocks between the group beginning Epoch and this
	// event.
	Exposure uint32 `json:"exposureBlocks"`
}

type auditFinding struct {
	Seq     uint64 `json:"seq"`
	Problem string `json:"problem"`
	Detail  string `json:"detail,omitempty"`
}

type auditReport struct {
	OK       bool           `json:"ok"`
	Vault    string         `json:"vault"`
	Owner    string         `json:"owner"`
	Crypt    string         `json:"crypt"`
	Name     string         `json:"name"`
	Group    string         `json:"group"`
	Hall     string         `json:"hall"`
	Anchor   string         `json:"anchor"`
	Tokens   []auditToken   `json:"tokens"`
	Windows  []auditWindow  `json:"windows"`
	Events   []auditEvent   `json:"events"`
	Findings []auditFinding `json:"findings"`
	// Forks are tokens that verified and do not continue the chain: an
	// orphan, or a token built on a parent no host admits.
	Forks []string `json:"forks,omitempty"`
	// EndsAt is the token the trail ends at; the audit covers nothing
	// after it. Latest is what a spend source said of it.
	EndsAt auditToken `json:"endsAt"`
	Latest string     `json:"latest"`
}

func cmdAudit(ctx context.Context, g *global, args []string) error {
	fs := g.flagSet("audit", auditHelp)
	free := fs.Bool("free", false, "read the trail token by token through the free class, paying nothing")
	at := fs.String("at", "", "the host's terms route base URL (default paid_host)")
	maxSats := fs.Uint64("max-sats", limits.DefaultMaxPrice, "the most one page of the priced class is paid")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return usage("audit takes no arguments")
	}
	t, err := g.readTarget(ctx, true)
	if err != nil {
		return err
	}
	var cv *vread.ChainView
	var problem error
	base := *at
	if base == "" {
		base = g.cfg.PaidHost
	}
	if *free || base == "" {
		if cv, err = t.rd.Chain(ctx, t.crypt, t.org, t.vault); err != nil {
			if errors.Is(err, vread.ErrNoChain) {
				return incomplete("vault %s: %v: an empty answer proves nothing", vread.Short(t.vaultHex()), err)
			}
			return err
		}
		problem = g.reportChain(cv)
	} else {
		if cv, err = g.paidTrail(ctx, t, base, *maxSats); err != nil {
			return err
		}
	}
	first := cv.Tokens[0].Token.Vault
	group, err := vread.ReadGroup(ctx, t.groups, first.Hall, t.org, first.Group)
	if err != nil {
		if errors.Is(err, reader.ErrNoChain) {
			return incomplete("the vault's group %s in hall %s: %v", reader.GroupHex(first.Group), first.Hall, err)
		}
		return fmt.Errorf("the vault's group: %w", err)
	}
	if p := g.reportGroup(group); p != nil && problem == nil {
		problem = p
	}
	var mined []secrec.Mined
	for _, tok := range cv.Tokens {
		mined = append(mined, secrec.Mined{Vault: tok.Token.Vault, Txid: tok.Hash(), Height: tok.Height})
	}
	rep := secrec.Audit(mined, group.Epochs)
	out := auditReport{OK: rep.OK, Vault: t.vaultHex(), Owner: t.orgHex, Crypt: t.crypt, Name: first.Name,
		Group: reader.GroupHex(first.Group), Hall: first.Hall, Anchor: anchorName(first.Anchor)}
	for i, tok := range cv.Tokens {
		v := tok.Token.Vault
		out.Tokens = append(out.Tokens, auditToken{Seq: v.Seq, Txid: tok.Txid, Height: tok.Height, Epoch: v.Epoch,
			Create: len(v.Create), Update: len(v.Update), Retire: len(v.Retire), Count: v.Count, Stale: v.Stale, Status: rep.Statuses[i]})
	}
	out.EndsAt = out.Tokens[len(out.Tokens)-1]
	for _, f := range rep.Findings {
		out.Findings = append(out.Findings, auditFinding{Seq: f.Seq, Problem: f.Problem, Detail: f.Detail})
	}
	for _, f := range cv.Forks {
		out.Forks = append(out.Forks, fmt.Sprintf("seq %d %s", f.Seq(), f.Txid))
	}
	end := out.EndsAt.Height
	for _, w := range rep.Windows {
		aw := auditWindow{Epoch: w.Epoch, Removed: w.Removed, Began: w.Began, Late: w.Late, Acknowledged: w.Acknowledged, Settled: w.Settled, Stale: w.Stale}
		switch {
		case w.Settled != 0:
			aw.Exposure = w.Settled - w.Began
		case end > w.Began:
			aw.Exposure, aw.Open = end-w.Began, true
		default:
			aw.Open = true
		}
		out.Windows = append(out.Windows, aw)
	}
	began := map[uint64]uint32{}
	for _, e := range group.Epochs {
		began[e.Epoch] = e.Height
	}
	for _, ev := range cv.Trail() {
		if ev.Kind != "rekey" && !(ev.Kind == "retire" && ev.FromEpoch < ev.Epoch) {
			continue
		}
		h := cv.Tokens[ev.Seq].Height
		ae := auditEvent{Secret: hex.EncodeToString(ev.ID[:]), Kind: ev.Kind, Seq: ev.Seq, Height: h, Version: ev.Version, Epoch: ev.Epoch, FromEpoch: ev.FromEpoch}
		// A secret was exposed from the first epoch after the one it was
		// keyed under.
		if b, ok := began[ev.FromEpoch+1]; ok && h > b {
			ae.Exposure = h - b
		}
		out.Events = append(out.Events, ae)
	}
	if sp := g.spends(); sp == nil {
		out.Latest = "no spend source says whether the trail's last token is the vault's latest (config key asset)"
	} else if by, serr := sp.Spender(ctx, cv.Latest().Txid, cv.Latest().Token.Vout); serr != nil {
		out.Latest = "the node could not say whether the trail's last token is the vault's latest"
	} else if by == "" {
		out.Latest = "the trail's last token is unspent per the node: it is the vault's latest"
	} else {
		out.Latest = "the trail's last token is SPENT by " + termsafe.Text(by) + ": the trail is cut short, or the vault is terminated"
		if problem == nil {
			problem = incomplete("the trail does not reach the vault's latest token")
		}
	}
	if *asJSON {
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Fprintln(g.stdout, string(b))
	} else {
		g.printAudit(&out)
	}
	if !out.OK {
		return refused("the audit FAILS: %d finding(s); from the first of them on the vault's own counts are not believed", len(out.Findings))
	}
	return problem
}

func (g *global) printAudit(r *auditReport) {
	o := g.stdout
	fmt.Fprintf(o, "vault   %s %s\nowner   %s\ncrypt   %s\ngroup   %s in hall %s\nanchor  %s\n", r.Vault, termsafe.Text(r.Name), r.Owner, r.Crypt, r.Group, r.Hall, r.Anchor)
	for _, t := range r.Tokens {
		fmt.Fprintf(o, "token   seq %d %s height %d epoch %d +%d ~%d -%d: %d secret(s), %d stale: %s\n", t.Seq, t.Txid, t.Height, t.Epoch, t.Create, t.Update, t.Retire, t.Count, t.Stale, t.Status)
	}
	for _, w := range r.Windows {
		why := "a rotation, nobody removed"
		if w.Removed {
			why = "a member removed"
		}
		line := fmt.Sprintf("epoch   %d began at height %d (%s)", w.Epoch, w.Began, why)
		switch {
		case w.Acknowledged == 0:
			line += fmt.Sprintf(": NEVER ACKNOWLEDGED in this trail; %d token(s) written after it under an earlier epoch", w.Late)
		default:
			line += fmt.Sprintf(": acknowledged at height %d", w.Acknowledged)
			if w.Late > 0 {
				line += fmt.Sprintf(", after %d token(s) written under an earlier epoch", w.Late)
			}
			if w.Settled != 0 {
				line += fmt.Sprintf(", settled at height %d", w.Settled)
			}
		}
		fmt.Fprintln(o, line)
		if w.Open {
			fmt.Fprintf(o, "window  epoch %d: OPEN, %d block(s) so far: %d secret(s) still listed under an earlier epoch at the end of the trail\n", w.Epoch, w.Exposure, w.Stale)
		} else {
			fmt.Fprintf(o, "window  epoch %d: %d block(s) from the block that began it to the token after which nothing was listed under an earlier epoch\n", w.Epoch, w.Exposure)
		}
	}
	for _, e := range r.Events {
		what := "re-keyed"
		if e.Kind == "retire" {
			what = "retired"
		}
		fmt.Fprintf(o, "secret  %s %s at seq %d, height %d: listed under epoch %d until then, %d block(s) exposed\n", e.Secret, what, e.Seq, e.Height, e.FromEpoch, e.Exposure)
	}
	for _, f := range r.Findings {
		fmt.Fprintf(o, "finding seq %d: %s %s\n", f.Seq, f.Problem, termsafe.Text(f.Detail))
	}
	for _, f := range r.Forks {
		fmt.Fprintf(o, "fork    %s verifies and does not continue the chain; it is not part of the trail\n", f)
	}
	fmt.Fprintf(o, "ends    seq %d %s height %d: the audit covers nothing after it; %s\n", r.EndsAt.Seq, r.EndsAt.Txid, r.EndsAt.Height, r.Latest)
	if r.OK {
		fmt.Fprintf(o, "audit   OK: %d token(s) mined, the owner's, linked from the first, lawful, consistent and keyed to the group\n", len(r.Tokens))
	} else {
		fmt.Fprintln(o, "audit   FAILED")
	}
}

// paidTrail reads the vault's whole chain through the priced audit class,
// page after page, each page one paid question, and establishes the chain
// from the tokens answered.
func (g *global) paidTrail(ctx context.Context, t *target, base string, maxSats uint64) (*vread.ChainView, error) {
	if err := checkOrigin(base); err != nil {
		return nil, err
	}
	h, err := g.openHome()
	if err != nil {
		return nil, usage("the priced audit class is paid from a home's pool: %v; or pass -free to read the trail token by token at no price", err)
	}
	defer h.close()
	q := vread.Query{"crypt": t.crypt, "audit": t.orgHex, "vault": t.vaultHex()}
	toks, err := vread.Trail(q, func(q vread.Query) ([]lookup.Output, error) {
		return g.ask(ctx, h, t.rd.Headers, base, q, maxSats)
	}, func(beef []byte) (*vread.Tok, error) {
		return vread.VerifyToken(ctx, beef, t.crypt, t.org, &t.vault, t.rd.Headers)
	})
	if err != nil {
		var re *vread.Refusal
		if errors.As(err, &re) {
			g.say("REFUSED an answered token (%s): %v", re.Reason, re.Err)
			return nil, refused("the host answered a token that does not verify")
		}
		return nil, err
	}
	if len(toks) == 0 {
		return nil, incomplete("%s answers no token of vault %s: an empty answer proves nothing", base, vread.Short(t.vaultHex()))
	}
	cv, err := vread.FromTokens(t.crypt, t.org, t.vault, toks)
	if err != nil {
		return nil, refused("the tokens %s answered do not form the vault's chain from its first token: %v", base, err)
	}
	return cv, nil
}

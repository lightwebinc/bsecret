package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/lightwebinc/bcommon/nodeapi"

	"github.com/lightwebinc/borg/reader"

	"github.com/lightwebinc/bsecret/internal/config"
	"github.com/lightwebinc/bsecret/internal/engine"
	"github.com/lightwebinc/bsecret/internal/limits"
	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/state"
	"github.com/lightwebinc/bsecret/internal/vread"
)

const doctorHelp = `usage: bsecret doctor

Report the home (identity, pool, funding trees, the vaults it owns, any
transition in flight, what is persisted and not yet published) and whether
the configured node, header source, hosts, hall hosts and priced host
answer. Reads only: it publishes nothing and spends nothing. What a vault
owes its group is 'bsecret due'.`

func cmdDoctor(ctx context.Context, g *global, args []string) error {
	fs := g.flagSet("doctor", doctorHelp)
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return usage("doctor takes no arguments")
	}
	out := g.stdout
	fmt.Fprintf(out, "home        %s\n", g.cfg.Home)
	fmt.Fprintf(out, "network     %s\n", g.cfg.Network)
	if g.cfg.Crypt != "" {
		fmt.Fprintf(out, "crypt       %s\n", field(g.cfg.Crypt))
	} else {
		fmt.Fprintln(out, "crypt       not configured")
	}
	var tip uint32
	if g.cfg.Asset != "" {
		if h, err := (&nodeapi.Asset{Base: g.cfg.Asset}).BestHeader(ctx); err != nil {
			fmt.Fprintf(out, "node        %s: %v\n", g.cfg.Asset, firstLine(err.Error()))
		} else {
			tip = h.Height
			fmt.Fprintf(out, "node        %s tip %d\n", g.cfg.Asset, h.Height)
		}
	} else {
		fmt.Fprintln(out, "node        not configured (asset): no spend source, so no writer evidence, and a reader cannot say a token is the latest")
	}
	if e, err := g.openWallet(); err != nil {
		fmt.Fprintf(out, "identity    absent (%v)\n", err)
	} else {
		fmt.Fprintf(out, "identity    %s\n", e.Signer().IdentityHex())
		fmt.Fprintf(out, "pool        %d output(s), %d sat", e.Pool.Count(), e.Pool.Balance())
		if tip > 0 {
			fmt.Fprintf(out, ", %d immature", len(e.Pool.Immature(tip)))
		}
		if n := len(e.Pool.UnprovenTxids()); n > 0 {
			fmt.Fprintf(out, ", change from %d transaction(s) held until mined", n)
		}
		fmt.Fprintln(out)
		if st, err := state.Load(g.cfg.Home, e.Signer().IdentityHex()); err != nil {
			fmt.Fprintf(out, "state       UNREADABLE: %v\n", err)
		} else {
			doctorState(out, st)
		}
	}
	if g.cfg.HeaderURL == "" {
		fmt.Fprintln(out, "headers     NOT CONFIGURED (nothing can be verified)")
	} else if hc, err := g.headerClient(); err == nil {
		if n, err := hc.CurrentHeight(ctx); err != nil {
			fmt.Fprintf(out, "headers     %s: %v\n", g.cfg.HeaderURL, firstLine(err.Error()))
		} else {
			fmt.Fprintf(out, "headers     %s tip %d\n", g.cfg.HeaderURL, n)
		}
	}
	switch {
	case g.cfg.Mode == config.ModeUnicast:
		need, err := config.Need(g.cfg.Quorum, len(g.cfg.Hosts))
		if err != nil {
			fmt.Fprintf(out, "mode        unicast: %v\n", err)
		} else {
			fmt.Fprintf(out, "mode        unicast: every object to each of %d host(s); a carrier published once %d take it (quorum %s), a token or sweep once all do\n", len(g.cfg.Hosts), need, g.cfg.Quorum)
		}
	case g.cfg.Facade != "":
		fmt.Fprintf(out, "mode        plane\nfacade      %s\n", g.cfg.Facade)
	default:
		fmt.Fprintln(out, "mode        plane\nfacade      not configured")
	}
	if g.cfg.Settle != "" {
		fmt.Fprintf(out, "settle      %s\n", g.cfg.Settle)
	} else {
		fmt.Fprintln(out, "settle      not configured")
	}
	if len(g.cfg.Content) > 0 {
		fmt.Fprintf(out, "content     %s (a reader fetches at most %d bytes)\n", strings.Join(g.cfg.Content, ", "), g.cfg.MaxFetch)
	} else {
		fmt.Fprintf(out, "content     not configured: a secret over the inline bound of %d bytes of ciphertext can be neither written nor read\n", secrec.MaxInline)
	}
	for _, h := range g.cfg.Hosts {
		fmt.Fprintf(out, "host        %s %s\n", h, ping(ctx, h, g.cfg.Timeout))
	}
	for _, h := range g.cfg.HallHosts {
		fmt.Fprintf(out, "hall host   %s %s\n", h, pingHall(ctx, g, h))
	}
	if g.cfg.PaidHost != "" {
		t, err := vread.FetchTerms(ctx, termsClient(g.cfg.Timeout), g.cfg.PaidHost)
		switch {
		case errors.Is(err, vread.ErrNoTerms):
			fmt.Fprintf(out, "paid host   %s prices nothing\n", g.cfg.PaidHost)
		case err != nil:
			fmt.Fprintf(out, "paid host   %s: %v\n", g.cfg.PaidHost, firstLine(err.Error()))
		default:
			fmt.Fprintf(out, "paid host   %s serves terms (%d priced class(es))\n", g.cfg.PaidHost, len(t.Classes))
		}
	}
	return nil
}

// pingHall asks a hall's host a question it must refuse.
func pingHall(ctx context.Context, g *global, base string) string {
	c := &reader.Client{Timeout: g.cfg.Timeout, HTTP: httpClient}
	_, err := c.Ask(ctx, base, reader.Query{})
	switch {
	case err == nil || errors.Is(err, reader.ErrHost):
		return "answering"
	case strings.Contains(err.Error(), "status 5"):
		return "answering with an ERROR (" + firstLine(err.Error()) + ")"
	}
	return "NOT ANSWERING: " + firstLine(err.Error())
}

// doctorState reports the home's state.
func doctorState(out io.Writer, st *state.State) {
	for _, kind := range state.TreeKinds {
		ts := st.Trees[kind]
		if ts == nil || ts.Tree == nil {
			fmt.Fprintf(out, "tree        %s: none yet\n", kind)
			continue
		}
		fmt.Fprintf(out, "tree        %s: %s %d of %d left\n", kind, ts.Tree.Txid, ts.Tree.Remaining(), ts.Tree.Count)
	}
	for i := range st.Vaults {
		v := &st.Vaults[i]
		line := fmt.Sprintf("vault       %s %s in %s: ", v.ID, field(v.Name), v.Crypt)
		if recs, err := engine.Records(v); err != nil || len(recs) == 0 {
			line += "no token yet"
		} else {
			last := recs[len(recs)-1]
			line += fmt.Sprintf("seq %d, epoch %d, %d secret(s), %d stale, %s", last.Seq, last.Epoch, last.Count, last.Stale, anchorName(last.Anchor))
			if last.Stale > 0 {
				line += "; IN DEBT (bsecret rotate)"
			}
		}
		unlisted := 0
		for j := range v.Versions {
			if x := &v.Versions[j]; !x.Listed && x.Swept == "" {
				unlisted++
			}
		}
		if unlisted > 0 {
			line += fmt.Sprintf("; %d version(s) published and not listed", unlisted)
		}
		fmt.Fprintln(out, line)
		if p := v.Pending; p != nil {
			fmt.Fprintf(out, "transition  %s %s persisted and not yet mined; the next command finishes it\n", field(p.What), p.Txid)
		}
	}
	for _, p := range st.Outbox {
		fmt.Fprintf(out, "outbox      %s %s persisted and not confirmed published; the next command publishes it\n", p.Kind, p.Txid)
	}
	if sw := st.InFlight(); sw != nil {
		fmt.Fprintf(out, "sweep       %s in flight; the next command finishes it\n", sw.Txid)
	}
	for _, sw := range st.Sweeps {
		if sw.Failed != "" {
			fmt.Fprintf(out, "sweep       %s FAILED: %s; it retracts nothing\n", sw.Txid, field(sw.Failed))
		}
	}
	if n := len(st.Commitments); n > 0 {
		fmt.Fprintf(out, "commitments %d content key commitment(s) recorded: none is ever published again\n", n)
	}
	if n := len(st.Payments); n > 0 {
		fmt.Fprintf(out, "payments    the change of %d unmined payment(s) of this home's is spendable by its next payment, up to %d unmined in a row\n", n, limits.MaxUnminedPayments)
	}
}

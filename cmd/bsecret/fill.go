package main

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/lightwebinc/bcommon/termsafe"

	"github.com/lightwebinc/bsecret/internal/engine"
	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/unicast"
	"github.com/lightwebinc/bsecret/internal/vread"
)

const fillHelp = `usage: bsecret fill

Fills every host in hosts that lacks something another host answered (spec
sections 11.6 and 13, "Filling a host that missed something"), for one
vault: its chain, the carriers of its set, and the sweeps of those
carriers' funding outputs. Each token is replayed in the BEEF a host
admits, assembled here from the token and its parent (the token at seq - 1,
or at seq 0 the chain tree, read from the node: config key asset); each
carrier and sweep is submitted as another host answered it, once it
verifies here. Everything is checked against this home's headers before it
is sent, and each fill is confirmed by a lookup at the host it was sent to.
It needs no coin and signs nothing: anyone who reads the crypt can fill a
host.

Exit 0 when every host holds everything any host answered (or now does),
3 when a host could not be asked or a fill was not confirmed.`

type filler struct {
	g           *global
	t           *target
	asset       *spendSource
	filled      int
	hostsFilled map[string]bool
	problem     bool
}

func cmdFill(ctx context.Context, g *global, args []string) error {
	fs := g.flagSet("fill", fillHelp)
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return usage("fill takes no arguments (name the vault with -vault)")
	}
	t, err := g.readTarget(ctx, true)
	if err != nil {
		return err
	}
	f := &filler{g: g, t: t, asset: g.spends(), hostsFilled: map[string]bool{}}
	cv, err := t.rd.Chain(ctx, t.crypt, t.org, t.vault)
	if err != nil {
		if errors.Is(err, vread.ErrNoChain) {
			return incomplete("vault %s: %v", vread.Short(t.vaultHex()), err)
		}
		return err
	}
	f.chain(ctx, cv)
	f.set(ctx, cv)
	fmt.Fprintf(g.stdout, "filled  %d object(s) at %d host(s)\n", f.filled, len(f.hostsFilled))
	if f.problem {
		return incomplete("a host could not be asked, or a fill was not confirmed")
	}
	return nil
}

// send submits beef to one host and confirms it by q answering txid.
func (f *filler) send(ctx context.Context, host, what, txid string, beef []byte, q vread.Query) bool {
	set := &unicast.Set{Hosts: []string{host}, Need: 1, Retries: engine.Retries, HTTP: httpClient, Note: f.g.say, Verbose: f.g.verbose}
	confirm := func(ctx context.Context, h string) (bool, error) { return f.t.rd.Held(ctx, h, q, txid) }
	if err := set.Send(ctx, what, secrec.Topic(f.t.crypt), beef, 1, confirm).Err(); err != nil {
		f.problem = true
		f.g.say("host %s: %s NOT FILLED: %v", host, what, err)
		return false
	}
	if ok, err := f.t.rd.Held(ctx, host, q, txid); err != nil || !ok {
		f.problem = true
		f.g.say("host %s: %s sent, and the host does not answer it", host, what)
		return false
	}
	f.hostsFilled[host] = true
	f.filled++
	fmt.Fprintf(f.g.stdout, "filled  %s at %s\n", what, host)
	return true
}

// chain replays every canonical token a host lacks, in seq order, each in
// the BEEF a host admits.
func (f *filler) chain(ctx context.Context, v *vread.ChainView) {
	for h, e := range v.HostErr {
		f.problem = true
		f.g.say("host %s: NOT ASKED about the vault: %s", h, firstLine(e.Error()))
	}
	hosts := make([]string, 0, len(v.Lacks))
	for h := range v.Lacks {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	base := vread.Query{"crypt": v.Crypt, "org": f.t.orgHex, "vault": f.t.vaultHex()}
	for _, h := range hosts {
		for _, s := range v.Lacks[h] {
			tok := v.Tokens[s]
			beef, err := f.tokenBEEF(ctx, v, s)
			if err != nil {
				f.problem = true
				f.g.say("vault token seq %d %s: cannot assemble its BEEF: %v", s, tok.Txid, err)
				continue
			}
			q := vread.Query{"seq": vread.Seq(s)}
			for k, val := range base {
				q[k] = val
			}
			f.send(ctx, h, fmt.Sprintf("vault token seq %d %s", s, vread.Short(tok.Txid)), tok.Txid, beef, q)
		}
	}
}

// tokenBEEF assembles the BEEF of the canonical token at seq s: the token
// and its parent, each with its minimal proof, held to the host's rules.
func (f *filler) tokenBEEF(ctx context.Context, v *vread.ChainView, s uint64) ([]byte, error) {
	tok := v.Tokens[s]
	if s > 0 {
		return engine.TokenBEEF(ctx, v.Crypt, tok.Tx, v.Tokens[s-1].Tx, f.t.rd.Headers)
	}
	// The chain tree: the transaction the first token's chain input
	// spends, which no host keeps; read from the node with its proof.
	if f.asset == nil {
		return nil, errors.New("the first token's parent is its chain tree, which no host keeps: it is read from the node (config key asset)")
	}
	_, op, err := secrec.CheckFirstToken(tok.Tx)
	if err != nil {
		return nil, err
	}
	id := op.Txid.String()
	raw, err := f.asset.TxRaw(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("the chain tree %s: %w", id, err)
	}
	tree, err := parseTx(raw, id)
	if err != nil {
		return nil, err
	}
	var mp *transaction.MerklePath
	if mp, err = f.asset.MerkleProof(ctx, id); err != nil {
		return nil, fmt.Errorf("the chain tree %s: its proof: %w", id, err)
	}
	tree.MerklePath = mp
	return engine.TokenBEEF(ctx, v.Crypt, tok.Tx, tree, f.t.rd.Headers)
}

// set submits each carrier of the vault's set to every host that did not
// answer it, as the host that did answered it, and each sweep of a
// carrier's funding output to every host that does not answer it.
func (f *filler) set(ctx context.Context, v *vread.ChainView) {
	rd := f.t.rd
	answered := map[string]map[string]bool{}
	cars := map[string]*vread.Car{}
	for _, sa := range rd.Secrets(ctx, v) {
		if sa.Err != nil || sa.Truncated {
			f.problem = true
			f.g.say("host %s: NOT ASKED for the whole set: %v", sa.Host, sa.Err)
			continue
		}
		for _, r := range sa.Refused {
			f.g.say("host %s: REFUSED carrier %s (%s): %v", r.Host, termsafe.Abbrev(r.Txid), r.Reason, r.Err)
		}
		answered[sa.Host] = map[string]bool{}
		for _, c := range sa.Cars {
			if _, err := v.Listed(c); err != nil {
				continue
			}
			answered[sa.Host][c.Txid] = true
			if cars[c.Txid] == nil {
				cars[c.Txid] = c
			}
		}
	}
	ids := make([]string, 0, len(cars))
	for id := range cars {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, h := range rd.Hosts {
		have, ok := answered[h]
		if !ok {
			continue
		}
		for _, id := range ids {
			c := cars[id]
			// A host that holds the sweep of the carrier's funding output
			// rightly does not answer it; the sweep is what the others lack.
			if have[id] || f.sweep(ctx, h, c) {
				continue
			}
			rec := c.Carrier.Secret
			q := vread.Query{"crypt": v.Crypt, "org": f.t.orgHex, "vault": f.t.vaultHex(), "secret": fmt.Sprintf("%x", rec.ID), "version": vread.Seq(rec.Version)}
			f.send(ctx, h, "secret "+vread.Short(id), id, c.Beef, q)
		}
	}
}

// sweep reports whether host answers a sweep of the carrier's funding
// output; when it does, every host that does not is filled with it.
func (f *filler) sweep(ctx context.Context, host string, c *vread.Car) bool {
	rd := f.t.rd
	q := vread.Query{"crypt": f.t.crypt, "spent": c.Carrier.Funding.String()}
	outs, err := rd.Ask(ctx, host, q)
	if err != nil {
		return false
	}
	for _, o := range outs {
		spent, txid, err := rd.Sweep(ctx, o.Beef, f.t.crypt)
		if err != nil {
			continue
		}
		for _, op := range spent {
			if op != c.Carrier.Funding {
				continue
			}
			for _, other := range rd.Hosts {
				if other == host {
					continue
				}
				if held, err := rd.Held(ctx, other, q, txid); err == nil && !held {
					f.send(ctx, other, "sweep "+vread.Short(txid), txid, o.Beef, q)
				}
			}
			return true
		}
	}
	return false
}

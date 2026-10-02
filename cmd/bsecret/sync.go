package main

import (
	"context"
	"fmt"
	"time"

	"github.com/lightwebinc/bcommon/termsafe"

	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/state"
)

const syncHelp = `usage: bsecret sync

Rebuild this home's record of the vaults its identity owns in the crypt,
from the hosts (spec section 8.5): each vault's chain from its first token,
verified against this home's headers and folded; every current secret's
record, and its name through its self wrap, which needs only the identity
key; every commitment any token listed; and the funding tree of every
carrier a host answers, recorded as spent, so that a sweep or the kill
switch reaches versions another instance published. It is how a home made
around the organisation's key on a new machine comes to write, and how a
home catches up after another instance changed a vault.

What it cannot bring back: a version published and not yet listed whose
carrier no host kept, and another instance's unpublished objects.`

func cmdSync(ctx context.Context, g *global, args []string) error {
	fs := g.flagSet("sync", syncHelp)
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return usage("sync takes no arguments")
	}
	if g.cfg.Crypt == "" {
		return usage("no crypt: set crypt (or -crypt) to the crypt identifier <name>_<suffix>")
	}
	w, err := g.openWriter(ctx)
	if err != nil {
		return err
	}
	defer w.close(ctx, g)
	rep, err := w.eng.Sync(ctx, g.cfg.Crypt)
	if rep != nil {
		fmt.Fprintf(g.stdout, "synced  %d vault(s) (%d new), %d token(s), %d version(s) read, %d name(s) opened, %d funding tree(s) recorded\n",
			rep.Vaults, rep.NewVaults, rep.Tokens, rep.Versions, rep.Named, rep.Trees)
		for _, b := range rep.Broken {
			fmt.Fprintf(g.stdout, "broken  %s: nothing is built on it\n", b)
		}
		for _, a := range rep.Ahead {
			fmt.Fprintf(g.stdout, "ahead   %s: this home holds its chain further than any host answered; its own tokens are kept\n", a)
		}
		for _, u := range rep.Unreadable {
			fmt.Fprintf(g.stdout, "unnamed id:%s: no host answers its carrier, so its name is not known here; it can be retired\n", u)
		}
	}
	return err
}

// dueWindow is how far ahead due looks for a value its owner said stops
// being usable.
const dueWindow = 30 * 24 * time.Hour

const dueHelp = `usage: bsecret due [-within DUR]

What a vault owes (spec section 8.2, rotation debt), computed from the two
chains by anyone who reads them: whether the vault is behind its group (the
group began an epoch the vault has not acknowledged), in debt (it
acknowledged and has not re-keyed everything), and which secrets are still
keyed under an earlier epoch, each by identifier. For the owner's own home
it also lists, by name, the secrets whose rotate-every has elapsed since
the version was written and those whose not-after falls within -within
(default 720h): claims the owner made when it put them.

Exit 3 when anything is due now. It builds nothing: a rotation needs a
choice for every secret (bsecret rotate).`

func cmdDue(ctx context.Context, g *global, args []string) error {
	fs := g.flagSet("due", dueHelp)
	within := fs.Duration("within", dueWindow, "list values that stop being usable within this long")
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return usage("due takes no arguments")
	}
	if *within < 0 {
		return usage("-within is a duration of 0 or more")
	}
	t, err := g.readTarget(ctx, true)
	if err != nil {
		return err
	}
	o, err := g.open(ctx, t, nil)
	if err != nil {
		return err
	}
	due := 0
	latest := o.group.Current()
	head := o.chain.Head().Token.Vault
	fmt.Fprintf(g.stdout, "vault   %s %s seq %d: %s\n", t.vaultHex(), termsafe.Text(head.Name), head.Seq, o.stand)
	if o.stand.Ahead || o.chain.Broken() != "" {
		return refused("the vault is not usable as its owner left it")
	}
	var own *state.Vault
	if t.own {
		own = t.st.VaultByID(t.vaultHex())
	}
	name := func(c secrec.Current) string {
		id := fmt.Sprintf("%x", c.ID)
		if own != nil {
			if x := own.VersionOf(id, fmt.Sprintf("%x", c.ContentID)); x != nil && x.Name != "" {
				return x.Name
			}
		}
		return "id:" + id
	}
	if o.stand.Behind {
		due++
		what := "a rotation"
		if latest.Removed {
			what = "a removal"
		}
		fmt.Fprintf(g.stdout, "due     the group began epoch %d at height %d (%s) and the vault still acknowledges epoch %d: every value it holds is open to whoever held an earlier epoch's key (bsecret rotate)\n",
			latest.Epoch, latest.Height, what, head.Epoch)
	}
	for _, c := range o.chain.Set() {
		if c.Epoch < latest.Epoch {
			due++
			fmt.Fprintf(g.stdout, "due     %s version %d is keyed under epoch %d: re-key or retire it (bsecret rotate)\n", name(c), c.Version, c.Epoch)
		}
	}
	now := time.Now()
	if own != nil {
		for i := range own.Versions {
			x := &own.Versions[i]
			if !x.Listed || x.Ended || x.Name == "" {
				continue
			}
			if x.RotateEvery > 0 {
				at := time.Unix(int64(x.Created), 0).Add(time.Duration(x.RotateEvery) * time.Second) //nolint:gosec // bounded by the record
				if !now.Before(at) {
					due++
					fmt.Fprintf(g.stdout, "due     %s version %d: its rotate-every of %s elapsed %s ago (bsecret put %s)\n", x.Name, x.Version,
						time.Duration(x.RotateEvery)*time.Second, now.Sub(at).Round(time.Minute), x.Name)
				}
			}
			if x.NotAfter > 0 {
				at := time.Unix(int64(x.NotAfter), 0) //nolint:gosec // bounded by the record
				switch {
				case !now.Before(at):
					due++
					fmt.Fprintf(g.stdout, "due     %s version %d: its value stopped being usable %s\n", x.Name, x.Version, at.UTC().Format(time.RFC3339))
				case at.Sub(now) <= *within:
					fmt.Fprintf(g.stdout, "soon    %s version %d: its value stops being usable %s\n", x.Name, x.Version, at.UTC().Format(time.RFC3339))
				}
			}
		}
	}
	if due > 0 {
		return incomplete("%d thing(s) due", due)
	}
	fmt.Fprintln(g.stdout, "nothing is due")
	return o.problem
}

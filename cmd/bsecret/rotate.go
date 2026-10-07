package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/lightwebinc/bcommon/termsafe"

	"github.com/lightwebinc/bsecret/internal/engine"
	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/vread"
)

const rotateHelp = `usage: bsecret rotate [-set NAME=FILE]... [-same NAME]... [-same-all] [-retire NAME]... [-keep] [-check] [-unwrapped]

Finish a revoke (spec section 8.2). The removal itself is borg's: the
organization removes the reader's key from the vault's group, which begins
a new epoch whose key the removed member never receives. This command does
the other two parts: it acknowledges the new epoch in the vault's next
token, and re-keys or retires everything the vault held under an earlier
one, 64 secrets a token, one token a block, until nothing is stale. From
the acknowledgement on, every host refuses anything else on the vault's
chain.

Every stale secret needs exactly one of:

  -set NAME=FILE  a new value, read from FILE ('-' is standard input)
  -same NAME      the same value under a new content key and the new epoch
  -retire NAME    retirement

There is no default, because re-keying is not enough for a credential: the
removed reader could read the old value, so a password, a token or a key
must be given a NEW value and the old one disabled where it was accepted.
-same is for a value that cannot change; the removed reader still knows it.
-same-all gives -same to every stale secret not named otherwise, and is
the explicit choice it reads as. Nothing is built until every stale secret
has a choice: a revoke that cannot be finished is not begun. A secret this
home knows only by identifier is named id:<64 hex digits> and can only be
retired.

-check builds nothing and says whether the choices given would finish a
revoke: run it before the removal, with the group still at the vault's
epoch, and it is held against every secret the vault holds. Exit 0 ready,
1 not.

A version keyed under the new epoch is published only once borg's wraps of
that epoch's key are published for the group's members, or they could not
open it; -unwrapped goes on regardless (a member in rotation debt is never
wrapped to). Once the vault is settled, the versions keyed under epochs
that have ended are swept, so honest hosts stop answering what the removed
member can still open; -keep keeps them answered, as history, until a
later rotation without it. Neither reaches a copy the removed member kept.

A run that stops part way is finished by running the same command again.`

// choices reads the plan the flags give.
func (g *global) choices(set, same, retire listFlag) (map[string]engine.Choice, error) {
	plan := map[string]engine.Choice{}
	dup := func(n string) error {
		if _, ok := plan[n]; ok {
			return usage("%q is given more than one of -set, -same and -retire", termsafe.Abbrev(n))
		}
		return nil
	}
	stdin := false
	for _, s := range set {
		name, file, ok := strings.Cut(s, "=")
		if !ok || name == "" || file == "" {
			return nil, usage("-set %q is not NAME=FILE", termsafe.Abbrev(s))
		}
		if err := dup(name); err != nil {
			return nil, err
		}
		if file == "-" {
			if stdin {
				return nil, usage("only one -set may read standard input")
			}
			stdin = true
		}
		v, err := g.readValue(file)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, usage("-set %s: %v", termsafe.Abbrev(name), err)
			}
			return nil, err
		}
		plan[name] = engine.Choice{Set: true, Value: v}
	}
	for _, n := range same {
		if err := dup(n); err != nil {
			return nil, err
		}
		plan[n] = engine.Choice{Same: true}
	}
	for _, n := range retire {
		if err := dup(n); err != nil {
			return nil, err
		}
		plan[n] = engine.Choice{Retire: true}
	}
	return plan, nil
}

func cmdRotate(ctx context.Context, g *global, args []string) error {
	fs := g.flagSet("rotate", rotateHelp)
	var set, same, retire listFlag
	fs.Var(&set, "set", "NAME=FILE: a new value for a stale secret (repeatable)")
	fs.Var(&same, "same", "NAME: re-key a stale secret with the value it holds (repeatable)")
	fs.Var(&retire, "retire", "NAME: retire a stale secret (repeatable)")
	sameAll := fs.Bool("same-all", false, "re-key every stale secret not named otherwise with the value it holds")
	keep := fs.Bool("keep", false, "do not sweep the versions keyed under epochs that have ended")
	check := fs.Bool("check", false, "build nothing: say whether these choices would finish a revoke")
	unwrapped := fs.Bool("unwrapped", false, "go on although some member holds no wrap of the new epoch's key")
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return usage("rotate takes no arguments: name secrets with -set, -same and -retire")
	}
	plan, err := g.choices(set, same, retire)
	if err != nil {
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
	target := wr.Group.Current().Epoch
	owes := engine.Owes(wr, target)
	hypothetical := *check && !wr.Stand.Behind && len(owes) == 0
	if hypothetical {
		// Before a removal: every secret the vault holds would be stale.
		owes = engine.Owes(wr, math.MaxUint64)
	}
	if *sameAll {
		for _, s := range owes {
			if _, ok := plan[s.Key()]; !ok && s.Name != "" {
				plan[s.Key()] = engine.Choice{Same: true}
			}
		}
	}
	vid := wr.Vault.ID
	if *check {
		_, err := engine.Covered(owes, plan, func(k string) bool { return engine.Known(wr.Vault, k) })
		if err != nil {
			return refused("not ready: %v", err)
		}
		if err := w.eng.Readable(ctx, wr, owes, plan); err != nil {
			return refused("not ready: %v", err)
		}
		when := fmt.Sprintf("the group is at epoch %d and the vault at epoch %d", target, wr.Pred.Epoch)
		if hypothetical {
			when = "were the group to begin a new epoch now"
		}
		fmt.Fprintf(g.stdout, "ready   %d secret(s) owe a re-keying or a retirement (%s), and each has a choice: a revoke can be finished in %d token(s)\n",
			len(owes), when, max(1, (len(owes)+secrec.MaxDelta-1)/secrec.MaxDelta))
		return nil
	}
	if !wr.Stand.Behind && len(owes) == 0 {
		fmt.Fprintf(g.stdout, "vault   %s is %s: nothing to rotate\n", vread.Short(vid), wr.Stand)
		if len(plan) > 0 {
			g.say("the choices given were not used: nothing in the vault is under an earlier epoch")
		}
		return g.sweepEnded(ctx, w, vid, *keep)
	}
	before := len(wr.Vault.Tokens)
	res, err := w.eng.Rotate(ctx, wr, plan, *unwrapped)
	if res != nil {
		v := w.h.st.VaultByID(vid)
		if res.Acknowledged != nil {
			ev, _ := wr.Group.EpochAt(*res.Acknowledged)
			what := "a rotation"
			if ev.Removed {
				what = "a removal"
			}
			fmt.Fprintf(g.stdout, "epoch   %d acknowledged: the group began it at height %d (%s)\n", *res.Acknowledged, ev.Height, what)
		}
		for _, n := range res.Rekeyed {
			how := "the same value"
			if plan[n].Set {
				how = "a new value"
			}
			fmt.Fprintf(g.stdout, "rekeyed %s: %s under epoch %d\n", n, how, target)
		}
		for _, n := range res.Retired {
			fmt.Fprintf(g.stdout, "retired %s\n", n)
		}
		for i := before; i < len(v.Tokens); i++ {
			t := v.Tokens[i]
			rec, derr := secrec.DecodeVault(mustHex(t.Record))
			if derr != nil {
				return derr
			}
			fmt.Fprintf(g.stdout, "token   seq %d %s mined at height %d: %d secret(s), %d stale, epoch %d\n", rec.Seq, t.Txid, t.Height, rec.Count, rec.Stale, rec.Epoch)
		}
	}
	if err != nil {
		return werr(err)
	}
	if err := g.sweepEnded(ctx, w, vid, *keep); err != nil {
		return err
	}
	fmt.Fprintf(g.stdout, "vault   %s settled at epoch %d\n", vread.Short(vid), target)
	return nil
}

// sweepEnded retracts the versions a settled vault no longer needs
// answered, unless the owner keeps history.
func (g *global) sweepEnded(ctx context.Context, w *writer, vid string, keep bool) error {
	v := w.h.st.VaultByID(vid)
	if keep {
		g.say("the versions keyed under earlier epochs stay answered (-keep): a removed member can still fetch and open them")
	}
	n, err := w.eng.SweepEnded(ctx, v, !keep, nil)
	if n > 0 {
		fmt.Fprintf(g.stdout, "swept   %d version(s) keyed under epochs that have ended, or never listed: retracted at every honest host\n", n)
		g.say("a sweep is not erasure: a copy anyone kept stays a copy, and what a removed member read stays read")
	}
	return werr(err)
}

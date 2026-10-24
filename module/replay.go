package module

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"

	bmodule "github.com/lightwebinc/bcommon/module"
	"github.com/lightwebinc/bcommon/replay"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// Ordered replay (bcommon module.Replayer): how this host repairs a gap on
// a crypt's topic from a sibling host, as spec section 11.6 says a host is
// given a chain ("by replay, from the publisher or from anyone who reads a
// sibling host ... A replayer assembles each token's BEEF itself: the token
// from the vault-seq answer at seq, and its parent from the answer at
// seq - 1; at seq 0 the parent is the chain tree, which no host keeps, so it
// comes from the publisher or from a chain source by its txid, with its
// proof") and section 13 says a host that missed something is filled, never
// by an unordered synchronization of unspent outputs. The questions are the
// free classes of section 10.2, asked of the peer's ls_bsecret; everything
// answered is admitted here through the host's ordinary path, so every rule
// of section 11.1 holds.
//
// A walk is six phases, each finished before the next reads the index:
//
//  1. vaults: for each organization the host knows in the crypt (from the
//     tokens and carriers it holds), the peer's vaults pages (vaults,
//     vaults-after); a vault the host holds no token of is kept for the
//     next phases;
//  2. tokens: for every vault the host holds a token of or phase 1 found,
//     the peer's latest (vault), then each seq below it the host holds no
//     token at (vault-seq), each token in the BEEF of the token and its
//     parent with minimal paths, held to section 11.1 before it is
//     answered, parents first; a first token takes its parent, the chain
//     tree, from the chain view (BSECRET_ASSET_URL or BSECRET_CHAIN);
//  3. listed: for each of those vaults, the peer's listed carriers of the
//     current set (secrets, secrets-after);
//  4. versions: every version of the current set, or listed by a token
//     first seen inside the retention floor less a day, whose carrier the
//     host does not hold (version): a version only older tokens list has
//     left every host by its floor;
//  5. pending: for every secret of the current set or of a held carrier,
//     its unlisted versions above the listed one (pending);
//  6. sweeps: the sweeps of each held carrier's funding outpoint (sweep).
//
// A dropped carrier's admission stays recorded (section 11.3), so the walk
// never offers back what the host dropped. What no free class leads to is
// not replayed: a version of a secret no held token lists and no held
// carrier names, a token that is not rooted at the peer, and a sweep that
// spends nothing a held carrier spends.

// KindsReplayed are the kinds a walk answers objects as.
var KindsReplayed = []string{replay.KindToken, "carrier", "sweep"}

var _ bmodule.Replayer = (*Service)(nil)

// Replay implements bcommon module.Replayer for tm_bsecret_ topics.
func (s *Service) Replay(ctx context.Context, r *bmodule.ReplayRequest) (*bmodule.ReplayAnswer, error) {
	crypt, ok := s.cryptOf(r.Topic)
	if !ok {
		return nil, bmodule.ErrNoReplay
	}
	if !s.Restored() {
		return nil, errors.New("ls_bsecret: the index is not restored yet")
	}
	w := replay.New(r)
	return w.Run(ctx, s.replayVaults(crypt), s.replayTokens(crypt), s.replayListed(crypt), s.replayVersions(crypt), s.replayPending(crypt),
		s.replaySweeps(crypt))
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// ---- phase 1: the peer's vaults of the organizations the host knows

func (s *Service) replayVaults(crypt string) replay.Phase {
	return replay.Phase{Name: "vaults",
		Items: func(context.Context, *replay.Walk) ([]string, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			orgs := map[string]bool{}
			for _, v := range s.vaults {
				if v.crypt == crypt {
					orgs[v.org] = true
				}
			}
			for _, e := range s.carriers {
				if e.crypt == crypt {
					orgs[hex.EncodeToString(e.rec.Org)] = true
				}
			}
			return sortedKeys(orgs), nil
		},
		Do: func(ctx context.Context, w *replay.Walk, org string, page *string) (bool, error) {
			for {
				q := map[string]string{"crypt": crypt, "vaultsOf": org}
				if *page != "" {
					q["after"] = *page
				}
				outs, err := w.Ask(ctx, secrec.LookupService, q)
				if err != nil {
					return false, err
				}
				last := ""
				for _, o := range outs {
					t, err := secrec.ReadToken(o.Tx)
					if err != nil || t.Vault.Crypt != crypt || hex.EncodeToString(t.Vault.Org) != org {
						continue
					}
					v := hexOf(t.Vault.Vault)
					if v > last {
						last = v
					}
					w.Find("vault|" + org + "|" + v)
				}
				if last == "" || last <= *page {
					return true, nil
				}
				*page = last
			}
		}}
}

// ---- phase 2: tokens

// vaultItems are the vaults the host holds a token of, and those the walk
// found, as org|vault.
func (s *Service) vaultItems(crypt string, w *replay.Walk) []string {
	s.mu.Lock()
	keys := map[string]bool{}
	for _, v := range s.vaults {
		if v.crypt == crypt {
			keys[v.org+"|"+v.vault] = true
		}
	}
	s.mu.Unlock()
	for _, k := range w.Found("vault|") {
		keys[strings.TrimPrefix(k, "vault|")] = true
	}
	return sortedKeys(keys)
}

func (s *Service) replayTokens(crypt string) replay.Phase {
	return replay.Phase{Name: "tokens",
		Items: func(_ context.Context, w *replay.Walk) ([]string, error) { return s.vaultItems(crypt, w), nil },
		Do: func(ctx context.Context, w *replay.Walk, item string, page *string) (bool, error) {
			org, vault, _ := strings.Cut(item, "|")
			key := vaultKey(crypt, org, vault)
			q := map[string]string{"crypt": crypt, "org": org, "vault": vault}
			c := &replay.Chain{
				Name:    "crypt " + crypt + " vault " + short(org) + "/" + short(vault),
				LatestQ: func() (string, map[string]string) { return secrec.LookupService, q },
				AtSeq: func(seq uint64) (string, map[string]string) {
					at := map[string]string{"seq": strconv.FormatUint(seq, 10)}
					for k, v := range q {
						at[k] = v
					}
					return secrec.LookupService, at
				},
				Held:  func(seq uint64) []chainhash.Hash { return s.heldTokens(key, seq) },
				Local: s.localToken,
				Read:  func(tx *transaction.Transaction) (*replay.Token, error) { return readVaultToken(tx, crypt, org, vault) },
				Trees: s.trees,
				Check: func(ctx context.Context, beef []byte) error {
					a, err := secrec.Admit(ctx, beef, nil, secrec.Host{Crypt: crypt, Headers: s.headers, MaxBEEF: s.maxBEEF, MaxSweepInputs: s.maxSweep})
					if err != nil {
						return fmt.Errorf("%s: %w", secrec.Reason(err), err)
					}
					if a.Kind != secrec.TxVaultToken {
						return fmt.Errorf("it would be admitted as a %s", a.Kind)
					}
					return nil
				},
			}
			return w.Tokens(ctx, c, page)
		}}
}

// heldTokens are the txids of the tokens the host holds of a vault at seq.
func (s *Service) heldTokens(key string, seq uint64) []chainhash.Hash {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.vaults[key]
	if v == nil {
		return nil
	}
	var out []chainhash.Hash
	for _, t := range v.bySeq[seq] {
		if h, err := chainhash.NewHashFromHex(t.txid); err == nil {
			out = append(out, *h)
		}
	}
	return out
}

// localToken is a token the host holds, as the engine stores it: alone,
// with its proof (section 11.4).
func (s *Service) localToken(ctx context.Context, txid chainhash.Hash) (*transaction.Transaction, error) {
	s.mu.Lock()
	storage := s.storage
	var vout uint32
	found := false
	if k, ok := s.tokenVault[txid.String()]; ok {
		if t := s.vaults[k].byTxid[txid.String()]; t != nil {
			vout, found = t.vout, true
		}
	}
	s.mu.Unlock()
	if !found || storage == nil {
		return nil, nil
	}
	o, err := storage.FindOutput(ctx, &transaction.Outpoint{Txid: txid, Index: vout}, "")
	if err != nil || o == nil || o.Beef == nil {
		return nil, err
	}
	return parse(o.Beef)
}

// readVaultToken reads a token of one vault from its transaction alone: its
// seq, the token it spends, and at seq 0 the outpoint that hashes to the
// vault identifier, the chain tree's (section 14's first-token check).
func readVaultToken(tx *transaction.Transaction, crypt, org, vault string) (*replay.Token, error) {
	t, err := secrec.ReadToken(tx)
	if err != nil {
		return nil, err
	}
	rec := t.Vault
	if rec.Crypt != crypt || hex.EncodeToString(rec.Org) != org || hexOf(rec.Vault) != vault {
		return nil, errors.New("ls_bsecret: a token of another vault")
	}
	if rec.Seq > 0 {
		return &replay.Token{Seq: rec.Seq, Prev: chainhash.Hash(rec.Prev)}, nil
	}
	_, op, err := secrec.CheckFirstToken(tx)
	if err != nil {
		return nil, err
	}
	return &replay.Token{Tree: op}, nil
}

// ---- phases 3 to 5: carriers

func (s *Service) replayListed(crypt string) replay.Phase {
	return replay.Phase{Name: "listed",
		Items: func(_ context.Context, w *replay.Walk) ([]string, error) { return s.vaultItems(crypt, w), nil },
		Do: func(ctx context.Context, w *replay.Walk, item string, page *string) (bool, error) {
			org, vault, _ := strings.Cut(item, "|")
			for {
				q := map[string]string{"crypt": crypt, "org": org, "secretsOf": vault}
				if *page != "" {
					q["after"] = *page
				}
				outs, err := w.Each(ctx, "carrier", secrec.LookupService, q, nil)
				if err != nil {
					return false, err
				}
				last := ""
				for _, o := range outs {
					if rec, err := secrec.CarrierRecord(*o.Tx.Outputs[o.Vout].LockingScript); err == nil && hexOf(rec.ID) > last {
						last = hexOf(rec.ID)
					}
				}
				if last == "" || last <= *page {
					return true, nil
				}
				*page = last
			}
		}}
}

// listedVersions are, as org|vault|id|version, the versions of crypt's
// vaults whose carrier the host does not hold among those it still keeps:
// the current set's, and those a token first seen inside the retention
// floor less a day lists; and, with versions false, as org|vault|id, the
// secrets of the current sets and of the held carriers. A version only
// older tokens list was replaced longer ago than any host keeps it, so
// asking for it every walk would ask for nothing, ever more often.
func (s *Service) listedVersions(ctx context.Context, crypt string, versions bool) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := map[string]bool{}
	cutoff := s.unix() - int64((s.retention-24*time.Hour)/time.Second)
	for _, v := range s.vaults {
		if v.crypt != crypt {
			continue
		}
		want := map[string]map[uint64]bool{}
		add := func(id string, version uint64) {
			if want[id] == nil {
				want[id] = map[uint64]bool{}
			}
			want[id][version] = true
		}
		if b := s.answerBranch(ctx, v); b != nil {
			for _, cur := range b.fold.Set() {
				add(hexOf(cur.ID), cur.Version)
			}
		}
		for _, t := range v.byTxid {
			if seen, ok := s.tokenSeen[t.txid]; !ok || seen.at < cutoff {
				continue
			}
			for _, list := range [][]secrec.Entry{t.rec.Create, t.rec.Update} {
				for _, e := range list {
					add(hexOf(e.ID), e.Version)
				}
			}
		}
		for id, vs := range want {
			if !versions {
				keys[v.org+"|"+v.vault+"|"+id] = true
				continue
			}
			for version := range vs {
				if len(s.versions[v.key+"|"+id][version]) == 0 {
					keys[v.org+"|"+v.vault+"|"+id+"|"+strconv.FormatUint(version, 10)] = true
				}
			}
		}
	}
	if !versions {
		for _, e := range s.carriers {
			if e.crypt == crypt {
				keys[hex.EncodeToString(e.rec.Org)+"|"+hexOf(e.rec.Vault)+"|"+e.id] = true
			}
		}
	}
	return sortedKeys(keys)
}

func (s *Service) replayVersions(crypt string) replay.Phase {
	return replay.Phase{Name: "versions",
		Items: func(ctx context.Context, _ *replay.Walk) ([]string, error) {
			return s.listedVersions(ctx, crypt, true), nil
		},
		Do: func(ctx context.Context, w *replay.Walk, item string, _ *string) (bool, error) {
			p := strings.Split(item, "|")
			q := map[string]string{"crypt": crypt, "org": p[0], "vault": p[1], "secret": p[2], "version": p[3]}
			_, err := w.Each(ctx, "carrier", secrec.LookupService, q, nil)
			return err == nil, err
		}}
}

func (s *Service) replayPending(crypt string) replay.Phase {
	return replay.Phase{Name: "pending",
		Items: func(ctx context.Context, _ *replay.Walk) ([]string, error) {
			return s.listedVersions(ctx, crypt, false), nil
		},
		Do: func(ctx context.Context, w *replay.Walk, item string, _ *string) (bool, error) {
			p := strings.Split(item, "|")
			q := map[string]string{"crypt": crypt, "org": p[0], "vault": p[1], "pending": p[2]}
			_, err := w.Each(ctx, "carrier", secrec.LookupService, q, nil)
			return err == nil, err
		}}
}

// ---- phase 6: sweeps

func (s *Service) replaySweeps(crypt string) replay.Phase {
	return replay.Phase{Name: "sweeps",
		Items: func(context.Context, *replay.Walk) ([]string, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			ops := map[string]bool{}
			for _, e := range s.carriers {
				if e.crypt == crypt {
					ops[e.op] = true
				}
			}
			return sortedKeys(ops), nil
		},
		Do: func(ctx context.Context, w *replay.Walk, op string, _ *string) (bool, error) {
			_, err := w.Each(ctx, "sweep", secrec.LookupService, map[string]string{"crypt": crypt, "spent": op}, nil)
			return err == nil, err
		}}
}

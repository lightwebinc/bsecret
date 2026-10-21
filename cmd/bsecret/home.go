package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	clients "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	base58 "github.com/bsv-blockchain/go-sdk/compat/base58"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/lightwebinc/bcommon/bwallet"
	"github.com/lightwebinc/bcommon/feepolicy"
	"github.com/lightwebinc/bcommon/guard"
	"github.com/lightwebinc/bcommon/mint"
	"github.com/lightwebinc/bcommon/nodeapi"
	"github.com/lightwebinc/bcommon/payee"
	"github.com/lightwebinc/bcommon/publish"
	"github.com/lightwebinc/bcommon/termsafe"

	"github.com/lightwebinc/borg/reader"

	"github.com/lightwebinc/bcommon/unicast"
	"github.com/lightwebinc/bsecret/internal/config"
	"github.com/lightwebinc/bsecret/internal/engine"
	"github.com/lightwebinc/bsecret/internal/limits"
	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/state"
	"github.com/lightwebinc/bsecret/internal/vread"
)

// httpClient is the client for everything but submissions, which
// bcommon's facade makes itself.
var httpClient *http.Client

// sampleHook, when a test sets it, draws content keys in place of the
// random source.
var sampleHook func() ([32]byte, [secrec.SaltLen]byte, error)

// poll paces proof waits; tests shorten it.
var poll = 2 * time.Second

// openWallet opens the home's embedded wallet.
func (g *global) openWallet() (*bwallet.Embedded, error) {
	e, err := bwallet.Open(g.cfg.Home, engine.Profile)
	if err != nil {
		return nil, fmt.Errorf("open the home %s: %w (run `bsecret init`)", g.cfg.Home, err)
	}
	e.Originator = g.cfg.Originator
	e.Mainnet = g.cfg.Network == "main"
	return e, nil
}

// lockHome takes the home's lock: one command that spends from the pool or
// writes the state at a time.
func (g *global) lockHome() (func(), error) {
	unlock, err := state.Lock(filepath.Join(g.cfg.Home, "lock"))
	if errors.Is(err, state.ErrLocked) {
		return nil, usage("another bsecret command is using the home %s (one at a time)", g.cfg.Home)
	}
	return unlock, err
}

// home is an open, locked home: its wallet and its state.
type home struct {
	e     *bwallet.Embedded
	st    *state.State
	close func()
}

// lockedWallet takes the home's lock and only then opens its wallet. The
// order matters: the wallet's coin pool is read into memory when it is
// opened and written back whole when it changes, so a pool read before the
// lock is one another command may change in between, and saving it would
// put back coins that command spent.
func (g *global) lockedWallet() (*bwallet.Embedded, func(), error) {
	if _, err := os.Stat(filepath.Join(g.cfg.Home, "identity.json")); err != nil {
		return nil, nil, fmt.Errorf("open the home %s: %w (run `bsecret init`)", g.cfg.Home, err)
	}
	unlock, err := g.lockHome()
	if err != nil {
		return nil, nil, err
	}
	e, err := g.openWallet()
	if err != nil {
		unlock()
		return nil, nil, err
	}
	return e, unlock, nil
}

// openHome locks the home, opens its wallet and loads its state.
func (g *global) openHome() (*home, error) {
	e, unlock, err := g.lockedWallet()
	if err != nil {
		return nil, err
	}
	st, err := state.Load(g.cfg.Home, e.Signer().IdentityHex())
	if err != nil {
		unlock()
		return nil, err
	}
	return &home{e: e, st: st, close: unlock}, nil
}

// readerHome is the home of a command that reads, opened and locked when
// there is one, so that what it verifies is remembered; nil when there is
// no home, and an error when there is one that cannot be opened (another
// command is using it, or it does not read).
func (g *global) readerHome() (*home, error) {
	if _, err := os.Stat(filepath.Join(g.cfg.Home, "identity.json")); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return g.openHome()
}

// peekState reads the home's state without the lock, for a command that
// only reads it; nil when there is no home.
func (g *global) peekState() *state.State {
	e, err := g.openWallet()
	if err != nil {
		return nil
	}
	st, err := state.Load(g.cfg.Home, e.Signer().IdentityHex())
	if err != nil {
		return nil
	}
	return st
}

// identityKey is the home's identity private key: an organisation's when
// this home owns vaults, from which its signer key is derived.
func (g *global) identityKey() (*ec.PrivateKey, error) {
	return payee.HomeKey(g.cfg.Home, "bsecret")
}

// node is the configured node, for coinbase on a regtest chain you run:
// its JSON-RPC and asset API.
func (g *global) node(needRPC bool) (*nodeapi.RPC, *nodeapi.Asset, error) {
	asset := g.cfg.AssetURL()
	if asset == "" || (needRPC && g.cfg.RPC == "") {
		if needRPC {
			return nil, nil, usage("rpc and a node must be configured (config keys rpc, and chain = asset:<URL>)")
		}
		return nil, nil, usage("a node must be configured (config key chain = asset:<URL>)")
	}
	var rpc *nodeapi.RPC
	if g.cfg.RPC != "" {
		rpc = &nodeapi.RPC{URL: g.cfg.RPC, User: g.cfg.RPCUser, Pass: g.cfg.RPCPass, ID: "bsecret"}
	}
	return rpc, &nodeapi.Asset{Base: asset, Client: httpClient}, nil
}

// chainView is the configured chain view (config key chain): where
// transactions, proofs and spends are read, every proof checked against
// the header source. Without one it is a usage error naming the key.
func (g *global) chainView() (*nodeapi.Sources, error) {
	if g.cfg.Chain == "" {
		return nil, usage("no chain view: set chain (or -chain), such as woc:main or asset:<URL>; transactions, proofs and spends are read from it")
	}
	hc, err := g.headerClient()
	if err != nil {
		return nil, err
	}
	c, err := nodeapi.ParseChain(g.cfg.Chain, nodeapi.ChainOptions{WoCKey: g.cfg.WoCKey, WoCRate: g.cfg.WoCRate, Client: httpClient, Headers: hc})
	if err != nil {
		return nil, usage("chain %s: %v", g.cfg.Chain, err)
	}
	return c, nil
}

// spendSource is the chain view as the readers take it: which outputs are
// spent, with what the source named left out of an error's text and a
// spender held to a transaction id in lower case (what a source names is
// printed, compared and asked for again, and a source is somebody else's
// server), and a transaction's bytes and current proof.
type spendSource struct{ nodeapi.Chain }

// Spender is the source's answer, refused unless it is a transaction id.
func (s spendSource) Spender(ctx context.Context, txid string, vout uint32) (string, error) {
	by, err := s.Chain.Spender(ctx, txid, vout)
	if err != nil {
		return "", reader.QuietSpend(err)
	}
	by = strings.ToLower(by)
	if by != "" && !config.IsHex32(by) {
		return "", fmt.Errorf("the chain view names a spender of %s.%d that is not a transaction id", txid, vout)
	}
	return by, nil
}

// MerkleProof is the source's current proof of txid.
func (s spendSource) MerkleProof(ctx context.Context, txid string) (*transaction.MerklePath, error) {
	mp, _, err := s.Proof(ctx, txid)
	return mp, err
}

// spends is the configured chain view as a spend source, or nil when none
// is configured.
func (g *global) spends() *spendSource {
	c, err := g.chainView()
	if err != nil {
		return nil
	}
	return &spendSource{c}
}

// settler is the configured settlement leg (config key settle), with an
// arcade's verdict held to the chain view's spends.
func (g *global) settler() (publish.Settler, *publish.Arcade, error) {
	if g.cfg.Settle == "" {
		return nil, nil, usage("no settlement leg: set settle to arcade:<URL>, arc:<URL>, rpc:<URL> or tcp:<host:port> (a regtest chain has no default)")
	}
	opt := publish.SettleOptions{Key: g.cfg.ArcadeKey, RPCUser: g.cfg.RPCUser, RPCPass: g.cfg.RPCPass, RPCID: "bsecret", Note: g.say}
	if sp := g.spends(); sp != nil {
		opt.Spends = sp
	}
	s, a, err := publish.ParseSettler(g.cfg.Settle, opt)
	if err != nil {
		return nil, nil, usage("settle %s: %v (config key settle)", g.cfg.Settle, err)
	}
	return s, a, nil
}

// fees is the miner fee policy (the fee_* keys) over mint.DefaultFees. A
// live policy (fee_source = arc) is asked of fee_policy_urls, else of the
// settlement leg when it is an arcade or ARC.
func (g *global) fees(ctx context.Context, arcade *publish.Arcade) (mint.Fees, error) {
	f, _, err := g.feesFrom(ctx, arcade)
	return f, err
}

// feesFrom is fees, and where they came from: static, or what a live
// policy source used (arc, cache or static) and why.
func (g *global) feesFrom(ctx context.Context, arcade *publish.Arcade) (mint.Fees, string, error) {
	fc := g.cfg.Fee
	if fc.Source == feepolicy.SourceARC && len(fc.PolicyURLs) == 0 {
		if arcade == nil {
			return mint.Fees{}, "", usage("fee_source arc reads a broadcaster's policy: set fee_policy_urls, or settle through an arcade or ARC")
		}
		fc.PolicyURLs = []string{arcade.Base}
	}
	src, err := fc.Build(mint.DefaultFees)
	if err != nil {
		return mint.Fees{}, "", usage("%v (config keys fee_*)", err)
	}
	a, live := src.(*feepolicy.ARC)
	if live {
		a.Key, a.Note = g.cfg.ArcadeKey, g.say
	}
	f, err := src.Fees(ctx)
	if err != nil {
		return mint.Fees{}, "", usage("%v (config keys fee_*)", err)
	}
	from := feepolicy.SourceStatic
	if live {
		st := a.Status()
		from = "policy of " + strings.Join(fc.PolicyURLs, ", ") + ": " + st.Source
		if st.Err != nil {
			from += " (" + st.Err.Error() + ")"
		}
	}
	return f, from, nil
}

// feeRate is a fee policy's rate as SATS/BYTES.
func feeRate(f mint.Fees) string {
	r := f.Rate
	if r.IsZero() {
		r = mint.Rate{Sats: f.SatPerByte, Bytes: 1}
	}
	return fmt.Sprintf("%d/%d sat/bytes", r.Sats, r.Bytes)
}

// reader is a reader over the crypt's hosts and the header source.
func (g *global) reader() (*vread.Client, error) {
	hc, err := g.headerClient()
	if err != nil {
		return nil, err
	}
	if len(g.cfg.Hosts) == 0 {
		return nil, usage("no overlay host configured (config key hosts, or -hosts)")
	}
	rd := &vread.Client{Hosts: g.cfg.Hosts, Headers: hc, Timeout: g.cfg.Timeout, HTTP: httpClient}
	if sp := g.spends(); sp != nil {
		rd.Source = sp
	}
	if g.cfg.LookupAuth {
		if rd.Auth, err = g.lookupAuth(); err != nil {
			return nil, err
		}
	}
	return rd, nil
}

// lookupAuth is how a reader asks a private crypt's hosts (config key
// lookup_auth): every question over BRC-104 as this home's identity, with
// the SDK's AuthFetch. A question is never paid for here: a host that
// answers one 402 is refused.
func (g *global) lookupAuth() (func(ctx context.Context, url string, body []byte) (int, []byte, error), error) {
	e, err := g.openWallet()
	if err != nil {
		return nil, usage("lookup_auth asks the hosts as this home's identity: %v", err)
	}
	af := clients.New(noPay{e.Signer()}, clients.WithoutLogging(), clients.WithHttpClient(&http.Client{Timeout: g.cfg.Timeout, Transport: httpTransport()}))
	return func(ctx context.Context, url string, body []byte) (int, []byte, error) {
		resp, err := af.Fetch(ctx, url, &clients.SimplifiedFetchRequestOptions{
			Method: http.MethodPost, Headers: map[string]string{"content-type": "application/json"}, Body: body})
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(io.LimitReader(resp.Body, limits.MaxAnswer+1))
		return resp.StatusCode, b, err
	}, nil
}

// noPay is a wallet that makes no payment: a lookup asked over BRC-104 is
// free, and a host that prices it is answered with a refusal.
type noPay struct{ *bwallet.Signer }

func (noPay) CreateAction(context.Context, wallet.CreateActionArgs, string) (*wallet.CreateActionResult, error) {
	return nil, errors.New("a free question is not paid for")
}

// httpTransport is the transport of httpClient, or the default one.
func httpTransport() http.RoundTripper {
	if httpClient != nil && httpClient.Transport != nil {
		return httpClient.Transport
	}
	return http.DefaultTransport
}

// groups is borg's reader over the hosts of the group's hall and the same
// header source.
func (g *global) groups() (*reader.Client, error) {
	hc, err := g.headerClient()
	if err != nil {
		return nil, err
	}
	hosts := g.cfg.GroupHosts()
	if len(hosts) == 0 {
		return nil, usage("no overlay host configured for the group's hall (config key hall_hosts, or hosts)")
	}
	rd := &reader.Client{Hosts: hosts, Headers: hc, Timeout: g.cfg.Timeout, HTTP: httpClient}
	// The node, when one is configured, gives the current proof of a group
	// token whose stored proof no longer verifies, and says whether a
	// token this home remembered is still mined.
	if sp := g.spends(); sp != nil {
		rd.Source = sp
	}
	return rd, nil
}

// content is where ciphertexts that are not carried are kept, or nil.
func (g *global) content() *vread.Store {
	if len(g.cfg.Content) == 0 {
		return nil
	}
	hc := httpClient
	if hc == nil {
		hc = &http.Client{Timeout: g.cfg.Timeout}
	}
	return &vread.Store{Sources: g.cfg.Content, Max: g.cfg.MaxFetch, HTTP: hc}
}

// parseKey reads an identity key from 66 lowercase hex digits.
func parseKey(what, s string) ([]byte, error) {
	if !config.IsKeyHex(s) {
		return nil, usage("%s %q is not an identity key (66 lowercase hex digits)", what, termsafe.Abbrev(s))
	}
	b, _ := hex.DecodeString(s)
	return b, nil
}

// legs are the endpoints a publisher publishes and settles through. None
// has a default.
func (g *global) legs() (engine.Legs, error) {
	var l engine.Legs
	chain, err := g.chainView()
	if err != nil {
		return l, err
	}
	l.Chain = chain
	if l.Settler, l.Arcade, err = g.settler(); err != nil {
		return l, err
	}
	hc, err := g.headerClient()
	if err != nil {
		return l, err
	}
	l.Headers = hc
	// A publisher confirms every object at every host named by lookup
	// (spec section 13), so it needs the hosts.
	if l.Reader, err = g.reader(); err != nil {
		return l, err
	}
	if l.Groups, err = g.groups(); err != nil {
		return l, err
	}
	l.Content = g.content()
	switch g.cfg.Mode {
	case config.ModeUnicast:
		if g.cfg.Facade != "" {
			return l, usage("facade is for mode plane; mode unicast submits to every host in hosts, so leave facade unset")
		}
		need, err := config.Need(g.cfg.Quorum, len(g.cfg.Hosts))
		if err != nil {
			return l, usage("%v (config key quorum)", err)
		}
		l.Hosts = &unicast.Set{Hosts: g.cfg.Hosts, Need: need, Retries: engine.Retries, HTTP: httpClient, Note: g.say, Verbose: g.verbose}
	default:
		if g.cfg.Facade == "" {
			return l, usage("facade must be configured (config key facade): the overlay host a publisher submits to on the plane (or set mode = unicast to submit to every host in hosts)")
		}
		l.Facade = &publish.Facade{Base: g.cfg.Facade, HTTP: httpClient}
		var direct []string
		for _, h := range g.cfg.Hosts {
			if strings.TrimRight(h, "/") != strings.TrimRight(g.cfg.Facade, "/") {
				direct = append(direct, h)
			}
		}
		if len(direct) > 0 {
			l.Direct = &unicast.Set{Hosts: direct, Need: len(direct), Retries: engine.Retries, HTTP: httpClient, Note: g.say, Verbose: g.verbose}
		}
	}
	return l, nil
}

// writer is an open home with its publisher.
type writer struct {
	h   *home
	eng *engine.Engine
}

// close ends a publisher's run: a tree minted ahead is collected, the
// per-host tallies printed, and the home unlocked.
func (w *writer) close(ctx context.Context, g *global) {
	if w.eng != nil {
		if err := w.eng.Close(ctx); err != nil {
			g.say("closing: %v", err)
		}
		g.tallies(w.eng)
	}
	w.h.close()
}

// openWriter opens the home and a publisher over it, and finishes whatever
// a previous run left.
func (g *global) openWriter(ctx context.Context) (*writer, error) {
	return g.openWriterFor(ctx, false)
}

// openWriterFor is openWriter; with lenient set, work a previous run left
// that cannot be finished now is reported and left for the next command,
// and the publisher is returned all the same. The kill switch runs so: an
// object that cannot reach a host, or a transition that cannot finish, must
// not keep a retraction from the chain.
func (g *global) openWriterFor(ctx context.Context, lenient bool) (*writer, error) {
	h, err := g.openHome()
	if err != nil {
		return nil, err
	}
	w := &writer{h: h}
	legs, err := g.legs()
	if err != nil {
		h.close()
		return nil, err
	}
	// A writer holds the group to what this home verified before: a hall
	// that answers the group without its latest removal would have it
	// write under an epoch that has ended.
	hold(legs.Groups, h.st)
	p := limits.Publisher{Plane: g.cfg.Mode == config.ModePlane, Hosts: len(g.cfg.Hosts), TreeCount: g.cfg.TreeCount,
		ChainTreeCount: g.cfg.ChainTreeCount, ObjectBound: g.cfg.ObjectBound}
	need, err := config.Need(g.cfg.Quorum, len(g.cfg.Hosts))
	if err != nil {
		h.close()
		return nil, usage("%v (config key quorum)", err)
	}
	if g.cfg.Mode == config.ModeUnicast {
		p.Need = need
	}
	warnings, err := p.Check()
	if err != nil {
		h.close()
		return nil, usage("%v", err)
	}
	for _, x := range warnings {
		g.say("warning: %s", x)
	}
	fees, err := g.fees(ctx, legs.Arcade)
	if err != nil {
		h.close()
		return nil, err
	}
	o := engine.Options{TreeCount: g.cfg.TreeCount, ChainTreeCount: g.cfg.ChainTreeCount, TreeSats: limits.DefaultTreeSats,
		Ahead: limits.DefaultAhead, Fees: fees, ObjectBound: g.cfg.ObjectBound, Poll: poll, Wait: 10 * time.Minute,
		Delay: g.cfg.Delay, Freshness: g.cfg.Freshness, PlaneNeed: need}
	if uint32(o.TreeCount) <= o.Ahead { //nolint:gosec // bounded by the limits
		o.Ahead = uint32(o.TreeCount / 2) //nolint:gosec // bounded by the limits
	}
	eng, err := engine.New(h.st, h.e.Signer(), h.e.Pool, legs, o)
	if err != nil {
		h.close()
		return nil, err
	}
	eng.Note, eng.Verbose, eng.Sample = g.say, g.verbose, sampleHook
	w.eng = eng
	if eng.Key, err = g.identityKey(); err != nil {
		w.close(ctx, g)
		return nil, err
	}
	if err := eng.Start(ctx); err != nil {
		var lost *engine.LostError
		switch {
		case errors.As(err, &lost):
			// A transition a previous command left was beaten to the
			// chain; this command goes on from what the home holds.
			g.say("%v", lost)
		case lenient && ctx.Err() == nil:
			g.say("work an earlier command left is not finished, and is left for the next command: %v", err)
		default:
			w.close(ctx, g)
			return nil, err
		}
	}
	return w, nil
}

// tallies prints, in mode unicast, each host's count of what it took and
// what it missed.
func (g *global) tallies(eng *engine.Engine) {
	if eng == nil || eng.Legs.Hosts == nil {
		return
	}
	for _, t := range eng.Legs.Hosts.Tallies() {
		line := fmt.Sprintf("host %s: took %d object(s), missed %d", t.Host, t.Took, t.Missed)
		if t.Missed > 0 {
			line += ": " + strings.Join(t.MissedWhat, ", ")
		}
		fmt.Fprintln(g.stdout, line)
	}
}

const initHelp = `usage: bsecret init [-from FILE | -borg DIR]

Create the home (mode 0700): an identity key and an empty coin pool. Print
the identity key and the fund address for the configured network. A home
that exists is left alone and printed.

A vault's owner is a borg organization: the key that signs every token and
every carrier is the organization's identity key. So an owner's home is
made around that key: -borg DIR takes it from the borg home DIR (its
identity.json), and -from FILE from an identity file carried by hand.
Nothing else of the borg home is read, then or later: the group's chain and
its epoch keys are read from the hall's hosts, and the two homes keep
separate coin pools, state and locks. The file is the organization's key:
carry it as the secret it is.

A member's home is made the same way around the key the group names, which
is the member's borg home's; or, for a key that is in no borg home, with a
plain init.`

// adoptIdentity copies an identity file into a home that has none.
func adoptIdentity(home, from string) error {
	raw, err := os.ReadFile(from) //nolint:gosec // the operator's own path
	if err != nil {
		return err
	}
	var id struct {
		WIF string `json:"wif"`
	}
	if err := json.Unmarshal(raw, &id); err != nil {
		return usage("%s is not an identity file: %v", from, err)
	}
	if _, err := ec.PrivateKeyFromWif(id.WIF); err != nil {
		return usage("%s holds no identity key: %v", from, err)
	}
	dst := filepath.Join(home, "identity.json")
	if _, err := os.Stat(dst); err == nil {
		return usage("the home %s has an identity already; -from and -borg make a new home", home)
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	return state.WriteAtomic(dst, raw, 0o600)
}

func cmdInit(_ context.Context, g *global, args []string) error {
	fs := g.flagSet("init", initHelp)
	from := fs.String("from", "", "an identity.json: make this home around that identity key")
	borg := fs.String("borg", "", "a borg home: make this home around its identity key")
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return usage("init takes no arguments")
	}
	if *from != "" && *borg != "" {
		return usage("-from and -borg are exclusive")
	}
	if *borg != "" {
		*from = filepath.Join(*borg, "identity.json")
	}
	if *from != "" {
		if err := adoptIdentity(g.cfg.Home, *from); err != nil {
			return err
		}
		fmt.Fprintln(g.stdout, "created", g.cfg.Home, "around the identity in", *from)
	}
	// The lock is taken before the wallet is made or opened: a home that
	// exists may be in use.
	if err := os.MkdirAll(g.cfg.Home, 0o700); err != nil {
		return err
	}
	unlock, err := g.lockHome()
	if err != nil {
		return err
	}
	defer unlock()
	e, err := bwallet.Create(g.cfg.Home, engine.Profile)
	if errors.Is(err, bwallet.ErrIdentityExists) {
		if e, err = g.openWallet(); err != nil {
			return err
		}
		if *from == "" {
			g.say("the home %s exists; left as it is", g.cfg.Home)
		} else if err := e.Pool.Save(); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		fmt.Fprintln(g.stdout, "created", g.cfg.Home)
	}
	if err := os.Chmod(g.cfg.Home, 0o700); err != nil {
		return err
	}
	e.Mainnet = g.cfg.Network == "main"
	addr, err := e.FundAddress(e.Mainnet)
	if err != nil {
		return err
	}
	fmt.Fprintf(g.stdout, "identity     %s\nfund address %s (%s)\n", e.Signer().IdentityHex(), addr, g.cfg.Network)
	return nil
}

const fundHelp = `usage: bsecret fund -txid TXID
       bsecret fund -beef FILE|- [-refuse-unmined]
       bsecret fund [-blocks N] [-batch N] [-rescan]

Fund the home's pool from a payment you sent to the fund address init
printed, from a wallet of your own. This is how a home on mainnet or
testnet is funded, and it needs no node:

-txid imports a mined payment: it is read with its proof from the chain
view (config key chain; WhatsOnChain by default), the proof is checked
against the header source, and every output paying the fund address is
added to the pool. Wait for one confirmation first.

-beef imports the payment as the BEEF your wallet hands over (a file, or -
for standard input), with no lookup at all. A mined payment's proof is
checked against the header source. One not mined yet is taken when every
parent it spends is proven and it verifies against them; its outputs are
held back until it mines, and spent only after that. -refuse-unmined (or
config key fund_unmined = refuse) takes only a mined one.

Without -txid or -beef (coinbase: only on a regtest chain you run, for
development and tests): mine coinbase to the fund address through the
node's generatetoaddress. Coinbase can be spent 100 blocks after it is
mined, so the first fund mines 101 or more. -rescan re-reads recent
blocks for coinbase the pool lacks. Refused on network main.

The fund address is bsecret's own, under its own protocol: a borg home's
coin is not this home's, even when both are made around one identity key.`

// addressNetwork is the network a base58 P2PKH address is for.
func addressNetwork(addr string) (string, error) {
	b, err := base58.Decode(addr)
	if err != nil || len(b) != 25 {
		return "", fmt.Errorf("fund address %q does not decode", addr)
	}
	switch b[0] {
	case 0x00:
		return "main", nil
	case 0x6f:
		return "test", nil
	}
	return "", fmt.Errorf("fund address %q has version byte 0x%02x", addr, b[0])
}

// checkFundAddress refuses an address for another network than the
// configured one: above all a mainnet address on a test network.
func checkFundAddress(addr, network string) error {
	n, err := addressNetwork(addr)
	if err != nil {
		return err
	}
	if (n == "main") != (network == "main") {
		return usage("the fund address %s is a %s address and network is %s; refusing to mine to it", addr, n, network)
	}
	return nil
}

func cmdFund(ctx context.Context, g *global, args []string) error {
	fs := g.flagSet("fund", fundHelp)
	blocks := fs.Int("blocks", 101, "coinbase: only on a regtest chain you run (development and tests); blocks to mine to the fund address")
	batch := fs.Int("batch", bwallet.DefaultFundBatch, "coinbase: only on a regtest chain you run (development and tests); blocks per generatetoaddress call")
	rescan := fs.Bool("rescan", false, "coinbase: only on a regtest chain you run (development and tests); re-read the last -blocks blocks for coinbase the pool lacks instead of mining")
	txid := fs.String("txid", "", "import this mined payment you sent to the fund address (mainnet, testnet)")
	beef := fs.String("beef", "", "import the payment your wallet handed over as BEEF: a file, or - for standard input")
	refuseUnmined := fs.Bool("refuse-unmined", g.cfg.FundUnmined == "refuse", "with -beef, take only a mined payment (config key fund_unmined)")
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return usage("fund takes no arguments")
	}
	if *txid != "" || *beef != "" {
		if *rescan {
			return usage("-txid and -beef do not take -rescan")
		}
		if *txid != "" && *beef != "" {
			return usage("-txid and -beef are exclusive")
		}
		return g.importPayment(ctx, *txid, *beef, *refuseUnmined)
	}
	if *blocks < 1 {
		return usage("-blocks must be at least 1")
	}
	if g.cfg.Network == "main" {
		return usage("fund without -txid or -beef mines coinbase, which only a chain you run does; on network main, import a payment with fund -txid or fund -beef")
	}
	e, unlock, err := g.lockedWallet()
	if err != nil {
		return err
	}
	defer unlock()
	addr, err := e.FundAddress(e.Mainnet)
	if err != nil {
		return err
	}
	if err := checkFundAddress(addr, g.cfg.Network); err != nil {
		return err
	}
	rpc, asset, err := g.node(true)
	if err != nil {
		return err
	}
	tip, err := asset.BestHeader(ctx)
	if err != nil {
		return fmt.Errorf("node tip: %w", err)
	}
	fmt.Fprintf(g.stdout, "pool before: %d output(s), %d sat; node tip %d; fund address %s\n", e.Pool.Count(), e.Pool.Balance(), tip.Height, addr)
	var added int
	if *rescan {
		from := uint32(0)
		if uint32(*blocks) < tip.Height { //nolint:gosec // a flag value
			from = tip.Height - uint32(*blocks) //nolint:gosec // a flag value
		}
		added, err = bwallet.Rescan(ctx, e.Signer(), e.Pool, asset, from, tip.Height)
	} else {
		added, _, err = bwallet.FundFromCoinbase(ctx, e.Signer(), e.Pool, rpc, asset, *blocks, *batch)
	}
	if err != nil {
		return err
	}
	h := tip.Height
	if t2, err := asset.BestHeader(ctx); err == nil {
		h = t2.Height
	}
	fmt.Fprintf(g.stdout, "pool after:  %d output(s), %d sat (+%d); immature %d; node tip %d\n",
		e.Pool.Count(), e.Pool.Balance(), added, len(e.Pool.Immature(h)), h)
	return nil
}

// readBEEF reads a BEEF from a file, or from standard input for "-": hex
// or binary, at most the guard's bound.
func (g *global) readBEEF(path string) ([]byte, error) {
	var r io.Reader
	if path == "-" {
		r = g.stdin
	} else {
		f, err := os.Open(path) //nolint:gosec // the operator's own path
		if err != nil {
			return nil, usage("-beef %s: %v", path, err)
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, 2*int64(guard.DefaultBound)+2))
	if err != nil {
		return nil, err
	}
	if t := bytes.TrimSpace(b); len(t) > 0 && len(t)%2 == 0 {
		if raw, herr := hex.DecodeString(string(t)); herr == nil {
			return raw, nil
		}
	}
	return b, nil
}

// importPayment adds the outputs a payment pays to the fund address to
// the pool: by txid, mined, from the chain view; or from the BEEF the
// user's wallet handed over. Every proof is checked against the header
// source. An unmined payment's outputs are held back until it mines.
func (g *global) importPayment(ctx context.Context, txid, beefPath string, refuseUnmined bool) error {
	if txid != "" {
		if h, err := chainhash.NewHashFromHex(txid); err != nil || h.String() != txid {
			return usage("-txid %q is not a transaction id (64 lowercase hex characters)", termsafe.Abbrev(txid))
		}
	}
	var beef []byte
	if beefPath != "" {
		var err error
		if beef, err = g.readBEEF(beefPath); err != nil {
			return err
		}
	}
	e, unlock, err := g.lockedWallet()
	if err != nil {
		return err
	}
	defer unlock()
	hc, err := g.headerClient()
	if err != nil {
		return err
	}
	fund, err := e.Signer().FundScript()
	if err != nil {
		return err
	}
	addr, _ := e.FundAddress(e.Mainnet)
	var im *bwallet.Import
	if txid != "" {
		chain, cerr := g.chainView()
		if cerr != nil {
			return usage("fund -txid reads the payment from the chain view: %v", cerr)
		}
		im, err = bwallet.ImportTxid(ctx, txid, fund, chain, hc)
	} else {
		im, err = bwallet.ImportBEEF(ctx, beef, fund, hc, bwallet.ImportOptions{RefuseUnmined: refuseUnmined})
	}
	switch {
	case errors.Is(err, bwallet.ErrPaysNothing):
		return usage("the payment pays nothing to the fund address %s", addr)
	case txid != "" && nodeapi.IsNotFound(err):
		return incomplete("payment %s is not known to the chain view %s yet: run fund -txid again once it has one confirmation, or hand over your wallet's BEEF with fund -beef", txid, g.cfg.Chain)
	case errors.Is(err, bwallet.ErrUnmined) && txid != "":
		return incomplete("payment %s has not mined yet: run fund -txid again once it has one confirmation, or hand over your wallet's BEEF with fund -beef", txid)
	case errors.Is(err, bwallet.ErrUnmined):
		return refused("the payment has not mined yet, and unmined payments are refused (-refuse-unmined, config key fund_unmined); import it once it has, or allow it")
	case errors.Is(err, nodeapi.ErrProofRefused):
		return refused("%v: its proof does not hold against the header source %s", err, g.cfg.HeaderURL)
	case err != nil:
		return err
	}
	added, err := e.Pool.Add(im.Outputs...)
	if err != nil {
		return err
	}
	if im.Mined {
		// An earlier import of the same payment, before it mined, is
		// held back; its proof is this one.
		if _, err := e.Pool.Prove(im.Txid, im.Outputs[0].Bump, im.Height); err != nil {
			return err
		}
		fmt.Fprintf(g.stdout, "imported %d of %d output(s) paying %s, %d sat, mined at height %d; pool %d output(s), %d sat\n",
			added, len(im.Outputs), addr, im.Sats, im.Height, e.Pool.Count(), e.Pool.Balance())
	} else {
		fmt.Fprintf(g.stdout, "imported %d of %d output(s) paying %s, %d sat, from %s, not mined yet: held back until it mines; pool %d output(s), %d sat\n",
			added, len(im.Outputs), addr, im.Sats, im.Txid, e.Pool.Count(), e.Pool.Balance())
		g.broadcastImport(ctx, im)
	}
	if added < len(im.Outputs) {
		g.say("note: %d output(s) were in the pool already", len(im.Outputs)-added)
	}
	return nil
}

// broadcastImport sends an unmined payment to the settlement leg, in case
// the wallet that made it did not. A leg that refuses it, or none, is a
// note: the wallet may have sent it already, and a later command collects
// its proof once it mines either way.
func (g *global) broadcastImport(ctx context.Context, im *bwallet.Import) {
	s, _, err := g.settler()
	if err != nil {
		g.say("payment %s: not broadcast here (%v); it is spent once it mines", im.Txid, err)
		return
	}
	if err := s.Submit(ctx, im.Tx); err != nil {
		g.say("payment %s: the settlement leg answered %v; if your wallet broadcast it, that is expected", im.Txid, err)
		return
	}
	g.say("payment %s: broadcast through %s", im.Txid, s.Name())
}

const cryptHelp = `usage: bsecret crypt new <name>
       bsecret crypt list

new draws the crypt's 10-letter suffix uniformly at random and prints the
crypt identifier <name>_<suffix>, its topic, and the line a host's
BSECRET_CRYPTS takes to carry it. <name> is 1 to 28 lowercase letters and
single underscores, starting and ending with a letter. The suffix is not a
secret and not an access control: it keeps unrelated crypts off each
other's topic. Many organizations may share one crypt. When a home exists,
the crypt is recorded in it, and list prints the crypts recorded.`

func cmdCrypt(_ context.Context, g *global, args []string) error {
	fs := g.flagSet("crypt", cryptHelp)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	switch {
	case len(pos) == 2 && pos[0] == "new":
		if secrec.CheckCryptName(pos[1]) != nil {
			return usage("crypt name %q: 1 to %d lowercase letters and single underscores, starting and ending with a letter", termsafe.Abbrev(pos[1]), secrec.MaxCryptName)
		}
		crypt, err := secrec.NewCrypt(pos[1], rand.Reader)
		if err != nil {
			return err
		}
		if _, serr := os.Stat(filepath.Join(g.cfg.Home, "identity.json")); serr == nil {
			e, unlock, err := g.lockedWallet()
			if err != nil {
				return err
			}
			defer unlock()
			st, err := state.Load(g.cfg.Home, e.Signer().IdentityHex())
			if err != nil {
				return err
			}
			st.AddCrypt(crypt)
			if err := st.Save(); err != nil {
				return err
			}
		}
		fmt.Fprintf(g.stdout, "crypt %s\ntopic %s\nhost  BSECRET_CRYPTS=%s\n", crypt, secrec.Topic(crypt), crypt)
		return nil
	case len(pos) == 1 && pos[0] == "list":
		st := g.peekState()
		if st == nil {
			return usage("no home at %s (run `bsecret init`)", g.cfg.Home)
		}
		for _, c := range st.Crypts {
			fmt.Fprintln(g.stdout, c)
		}
		return nil
	}
	return usage("crypt new <name> | crypt list")
}

// ping asks a host a question it must refuse: the host is up and runs the
// service.
func ping(ctx context.Context, base string, timeout time.Duration) string {
	c := &vread.Client{Timeout: timeout, HTTP: httpClient}
	err := c.Ping(ctx, base)
	switch {
	case err == nil:
		return "answering"
	case strings.Contains(err.Error(), "status 5"):
		return "answering with an ERROR (" + firstLine(err.Error()) + ")"
	}
	return "NOT ANSWERING: " + firstLine(err.Error())
}

func termsClient(timeout time.Duration) *http.Client {
	if httpClient != nil {
		return httpClient
	}
	return &http.Client{Timeout: timeout}
}

// firstLine is the first line of a message, at most 160 bytes, filtered
// for the terminal: a host's error text is someone else's.
func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return termsafe.Text(s)
}

// field is someone else's text that fills one field of a line this command
// prints (a vault's display name, a class name, a media type): filtered for
// the terminal, and held to that line. A record refuses a display name with
// a line break (spec section 3); other text a host or an owner wrote is
// held to no such rule, and a line break in it would otherwise write lines
// of its own in a report, in this command's voice.
func field(s string) string {
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t', '\v', '\f', 0x85, 0x2028, 0x2029:
			return ' '
		}
		return r
	}, s)
	return termsafe.Text(s)
}

// jsonSafe makes marshalled JSON safe to print: every control and format
// character above ASCII (the C1 controls, the bidirectional controls, the
// line and paragraph separators), which encoding/json writes as it is, is
// written as its escape. The document decodes to the same values.
func jsonSafe(b []byte) []byte {
	var out []byte
	for _, r := range string(b) {
		if r >= 0x80 && (unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 || unicode.Is(unicode.Co, r)) {
			if r > 0xffff {
				hi, lo := utf16.EncodeRune(r)
				out = fmt.Appendf(out, "\\u%04x\\u%04x", hi, lo)
			} else {
				out = fmt.Appendf(out, "\\u%04x", r)
			}
			continue
		}
		out = utf8.AppendRune(out, r)
	}
	return out
}

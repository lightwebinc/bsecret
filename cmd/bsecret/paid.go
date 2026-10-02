package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	clients "github.com/bsv-blockchain/go-sdk/auth/clients/authhttp"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"
	"github.com/bsv-blockchain/go-sdk/wallet"

	"github.com/lightwebinc/bcommon/bwallet"
	"github.com/lightwebinc/bcommon/funding"
	"github.com/lightwebinc/bcommon/lookup"
	"github.com/lightwebinc/bcommon/mint"
	"github.com/lightwebinc/bcommon/producer"
	"github.com/lightwebinc/bcommon/purse"
	"github.com/lightwebinc/bcommon/termsafe"

	"github.com/lightwebinc/bsecret/internal/engine"
	"github.com/lightwebinc/bsecret/internal/limits"
	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/state"
	"github.com/lightwebinc/bsecret/internal/vread"
)

// purse is the home's wallet with the pool's payer, the settlement leg and
// the header source: what a priced question and payee settle pay and take
// through.
func (g *global) purse(ctx context.Context, h *home, hc chaintracker.ChainTracker, maxPay uint64) (*purse.Purse, error) {
	_, asset, err := g.node(false)
	if err != nil {
		return nil, err
	}
	settler, _, err := g.settler()
	if err != nil {
		return nil, err
	}
	tip, err := asset.BestHeader(ctx)
	if err != nil {
		return nil, fmt.Errorf("node tip: %w", err)
	}
	engine.CollectChange(ctx, h.e.Pool, asset)
	if h.st.KeepPayments(h.e.Pool.UnprovenTxids()) {
		if err := h.st.Save(); err != nil {
			return nil, err
		}
	}
	s := h.e.Signer()
	// The change of this home's own unmined payment is spendable by its
	// next payment, which carries that payment in its BEEF: a payer with
	// one coin is not held to one priced question per block.
	kept := &producer.Kept{Load: func(txid string) (*transaction.Transaction, error) {
		if p := h.st.PaymentOf(txid); p != nil {
			return funding.Rebuild("", "", p.Beef)
		}
		return nil, fmt.Errorf("transaction %s is not a payment this home keeps", txid)
	}}
	allow := func() []string {
		var ids []string
		for _, p := range h.st.Payments {
			// A payment and the unmined payments under it: the next one
			// would carry them all.
			if tx, err := kept.Tx(p.Txid); err == nil && len(purse.Unmined(tx))+1 < limits.MaxUnminedPayments {
				ids = append(ids, p.Txid)
			}
		}
		return ids
	}
	newPayer := func() *producer.Payer {
		return &producer.Payer{Pool: h.e.Pool, Tip: tip.Height, Keys: map[string]*bwallet.Signer{s.IdentityHex(): s},
			Kept: kept, Allow: allow, Settler: settler, Asset: asset, Fees: mint.DefaultFees, Poll: poll, Note: g.say}
	}
	return &purse.Purse{Embedded: h.e, NewPayer: newPayer, Fees: mint.DefaultFees, MaxPay: maxPay,
		Settler: settler, Asset: asset, Headers: hc, Wait: 10 * time.Minute, Poll: poll}, nil
}

// recordPayment records a payment this home made, so the next payment can
// spend its change before it mines. It is recorded before it is sent: from
// the moment it leaves this process the host holds a valid transaction
// that spends the coin, and a home that did not record it would not know
// its own coin was spent, or where its change is.
func recordPayment(h *home, tx *transaction.Transaction) error {
	beef, err := funding.BEEF(tx)
	if err != nil {
		return err
	}
	h.st.Payments = append(h.st.Payments, state.Payment{Txid: tx.TxID().String(), Beef: hex.EncodeToString(beef)})
	return h.st.Save()
}

// broadcastPayment hands a payment this home made to the settlement leg: it
// is this home's own transaction, and once it mines its change is an
// ordinary coin whenever the payee settles. A leg that does not take it
// changes nothing: the payee broadcasts the same bytes.
func (g *global) broadcastPayment(ctx context.Context, p *purse.Purse, tx *transaction.Transaction) {
	if p.Settler == nil {
		return
	}
	if err := p.Settler.Submit(ctx, tx); err != nil && !strings.Contains(strings.ToLower(err.Error()), "already") {
		g.say("payment %s: not broadcast from here (%s); the payee broadcasts it when it settles", vread.Short(tx.TxID().String()), firstLine(err.Error()))
	}
}

// paidBase is the host a priced question goes to: -at, else paid_host.
func (g *global) paidBase(at string) (string, error) {
	base := at
	if base == "" {
		base = g.cfg.PaidHost
	}
	if base == "" {
		return "", usage("no host to ask: set paid_host (or -at) to the host's terms route base URL")
	}
	return base, checkOrigin(base)
}

// ask asks a host's terms route one question of a priced class (spec
// section 10.3): over BRC-104, answered 402 with the price, and asked again
// with a BRC-29 payment to the host from this home's pool (BRC-105) as
// output 0, which the host records and its payee settles. A price over
// maxSats is not paid; a host that prices nothing answers at no price. It
// returns what was paid, answered or not: a payment that left this process
// is made.
func (g *global) ask(ctx context.Context, h *home, hc chaintracker.ChainTracker, base string, q vread.Query, maxSats uint64) ([]lookup.Output, uint64, error) {
	return g.askWithin(ctx, h, hc, base, q, maxSats, "-max-sats")
}

// askWithin is ask for a caller whose bound on this question may be another
// flag's: bound names it, for the refusal of a price over maxSats.
func (g *global) askWithin(ctx context.Context, h *home, hc chaintracker.ChainTracker, base string, q vread.Query, maxSats uint64, bound string) ([]lookup.Output, uint64, error) {
	raw, _ := json.Marshal(q)
	qq, err := secrec.ParseQuery(raw)
	if err != nil {
		return nil, 0, usage("the question breaks the class rules: %v", err)
	}
	if qq.Class.Free {
		return nil, 0, usage("%s is a free class: it is never asked at a price", qq.Class.Name)
	}
	p, err := g.purse(ctx, h, hc, maxSats)
	if err != nil {
		return nil, 0, err
	}
	// The pool is recorded before a coin is taken from it, and a coin a
	// run that stopped took and never recorded goes back (engine.Journal).
	engine.Journal(h.st, h.e.Pool, engine.Reconcile(ctx, h.st, h.e.Pool, p.Asset, g.say))
	if err := h.st.Save(); err != nil {
		return nil, 0, err
	}
	defer func() {
		engine.Unjournal(h.st)
		_ = h.st.Save()
	}()
	once := &oncePurse{Purse: p, record: func(tx *transaction.Transaction) error { return recordPayment(h, tx) }}
	body, _ := json.Marshal(lookup.Question{Service: secrec.LookupService, Query: q})
	af := clients.New(once, clients.WithoutLogging(), clients.WithHttpClient(&http.Client{Timeout: g.cfg.Timeout}))
	resp, ferr := af.Fetch(ctx, strings.TrimRight(base, "/")+"/lookup", &clients.SimplifiedFetchRequestOptions{
		Method: http.MethodPost, Headers: map[string]string{"content-type": "application/json"}, Body: body})
	var ans []byte
	status, paid, payee := 0, "", ""
	if ferr == nil {
		defer resp.Body.Close()
		status, paid, payee = resp.StatusCode, resp.Header.Get("x-bsv-payment-satoshis-paid"), resp.Header.Get("x-bsv-auth-identity-key")
		ans, ferr = io.ReadAll(io.LimitReader(resp.Body, limits.MaxAnswer+1))
		if ferr == nil && len(ans) > limits.MaxAnswer {
			ferr = fmt.Errorf("the answer is over %d bytes and is not read", limits.MaxAnswer)
		}
	}
	answered := ferr == nil && status == http.StatusOK
	switch {
	case once.tx == nil:
		// No payment was made: there is nothing to keep.
	case answered && paid != "":
		fmt.Fprintf(g.stdout, "paid %s sat to %s in %s for %s, recorded by the host for its payee to settle\n", termsafe.Abbrev(paid),
			termsafe.Abbrev(payee), once.tx.TxID(), qq.Class.Name)
		g.broadcastPayment(ctx, p, once.tx)
	default:
		// A payment was handed to the host and the host did not answer for
		// it. Its coins are NOT given back to the pool: the host holds a
		// valid transaction that spends them, and a coin spent again would
		// make this home's next transaction a double spend. The payment is
		// kept as made.
		g.say("a payment of this home's, %s, was sent to %s and the question was not answered: it left this process, so it is kept as made and its coins are not reused; the host's payee can still settle it", once.tx.TxID(), base)
		g.broadcastPayment(ctx, p, once.tx)
	}
	switch {
	case errors.Is(ferr, errPaidOnce) || (ferr == nil && status == http.StatusPaymentRequired && once.tx != nil):
		return nil, once.sats, refused("%s at %s: the host asked for a payment again after one was sent; one question is paid for once", qq.Class.Name, base)
	case ferr != nil:
		return nil, once.sats, fmt.Errorf("%s at %s: %w", qq.Class.Name, base, payWords(ferr, maxSats, bound))
	case status != http.StatusOK:
		return nil, once.sats, fmt.Errorf("%s at %s: status %d: %s", qq.Class.Name, base, status, termsafe.Abbrev(firstLine(string(ans))))
	}
	var a lookup.Answer
	if err := json.Unmarshal(ans, &a); err != nil || a.Type != lookup.TypeOutputList {
		return nil, once.sats, fmt.Errorf("%s at %s: the answer is not an output-list", qq.Class.Name, base)
	}
	return a.Outputs, once.sats, nil
}

// errPaidOnce refuses a second payment for one question.
var errPaidOnce = errors.New("one question is paid for once")

// oncePurse is a purse that pays once, and records what it pays before it
// is sent. The SDK's AuthFetch answers every 402 with a new payment,
// several times over: a host that keeps answering 402 would be handed a
// signed payment each time, and each is a transaction it can broadcast.
// One question is one payment. And the SDK sends a payment as soon as the
// wallet returns it, so the wallet is where it must be recorded: once the
// action returns, the payment is made, its coin spent and its change in the
// pool, whatever the host then answers.
type oncePurse struct {
	*purse.Purse
	record func(tx *transaction.Transaction) error
	// tx is the payment made, and sats what it pays the host.
	tx   *transaction.Transaction
	sats uint64
}

// CreateAction makes the one payment and records it, and refuses any after
// it.
func (o *oncePurse) CreateAction(ctx context.Context, args wallet.CreateActionArgs, originator string) (*wallet.CreateActionResult, error) {
	if o.tx != nil {
		return nil, errPaidOnce
	}
	res, err := o.Purse.CreateAction(ctx, args, originator)
	if err != nil {
		return nil, err
	}
	tx := o.Purse.Settle()
	if tx == nil {
		return nil, errors.New("the wallet made no payment")
	}
	if err := o.record(tx); err != nil {
		return nil, fmt.Errorf("the payment %s could not be recorded in the home, and is not sent: %w", tx.TxID(), err)
	}
	o.tx, o.sats = tx, args.Outputs[0].Satoshis
	return res, nil
}

// budget is what a command that asks several priced questions may pay: at
// most per for one question, and at most total for all of them. A host
// sets its own prices and its own pages; the command sets what they may
// add up to.
type budget struct {
	per, total, spent uint64
}

// next is the most the next question may be paid, or an error once the
// total is spent.
func (b *budget) next() (uint64, error) {
	if b.spent >= b.total {
		return 0, fmt.Errorf("this command has paid %d sat, its budget (-budget): it pays for no further question", b.spent)
	}
	return min(b.per, b.total-b.spent), nil
}

// bound names the flag that sets what next answers: the price of one
// question, or what is left of the budget when that is less.
func (b *budget) bound() string {
	if b.total-min(b.spent, b.total) < b.per {
		return "what is left of -budget"
	}
	return "-max-sats"
}

func (b *budget) paid(sats uint64) { b.spent += sats }

// checkOrigin refuses a terms base that is not an origin (spec section
// 10.3): the terms document, the BRC-104 handshake and the priced /lookup
// all sit at the root of the origin.
func checkOrigin(base string) error {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return usage("%q is not an origin: the terms route is at the root of its own origin, where BRC-104 shakes hands (docs/host.md)", termsafe.Abbrev(base))
	}
	return nil
}

// payWords puts a refusal of the purse in this command's words. The library
// names no flag and no config key; the command that set them does.
func payWords(err error, maxSats uint64, bound string) error {
	switch {
	case errors.Is(err, purse.ErrOverMaxPay):
		return fmt.Errorf("%w: more than the %d this command may pay (%s)", err, maxSats, bound)
	case errors.Is(err, purse.ErrNoNode):
		return fmt.Errorf("%w (config key asset)", err)
	case errors.Is(err, purse.ErrNoSettler):
		return fmt.Errorf("%w (config key settle)", err)
	case errors.Is(err, purse.ErrNotMined):
		return fmt.Errorf("%w; run the command again to take it into the pool once it is", err)
	}
	return err
}

const termsHelp = `usage: bsecret terms [URL]

Fetch and print a host's terms document (spec section 10.3) from the base
URL of its ls_bsecret, an origin with no path (default the configured
paid_host): the classes it prices and the price of one question of each. A
host that serves none charges for nothing. The document is informative: the
402 is what a client pays against, and a free class is never paid for,
whatever a document says.`

func cmdTerms(ctx context.Context, g *global, args []string) error {
	fs := g.flagSet("terms", termsHelp)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return usage("terms [URL]")
	}
	at := ""
	if len(pos) == 1 {
		at = pos[0]
	}
	base, err := g.paidBase(at)
	if err != nil {
		return err
	}
	t, err := vread.FetchTerms(ctx, termsClient(g.cfg.Timeout), base)
	if errors.Is(err, vread.ErrNoTerms) {
		fmt.Fprintf(g.stdout, "%s serves no terms document: it charges for nothing\n", base)
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(g.stdout, "service %s, terms %d\n", field(t.Service), t.Terms)
	for _, c := range t.Classes {
		cls := slices.IndexFunc(secrec.Classes, func(x secrec.Class) bool { return x.Name == c.Class })
		switch {
		case cls < 0:
			continue
		case secrec.Classes[cls].Free:
			fmt.Fprintf(g.stdout, "%-14s FREE CLASS WITH A PRICE (%d sat): outside the specification; never paid\n", c.Class, c.Satoshis)
		default:
			fmt.Fprintf(g.stdout, "%-14s %d sat a question\n", c.Class, c.Satoshis)
		}
	}
	return nil
}

const historyHelp = `usage: bsecret history <name> [-after VERSION] [-at URL] [-max-sats N]

Ask a host the priced history question (spec section 10.3): the carriers
it holds for every version of a secret, one page. It is asked at the host's
terms route (-at, default the configured paid_host) over BRC-104
authentication; the host answers 402 with its price, and the question is
asked again with a BRC-29 payment to the host from this home's pool
(BRC-105). The payment's change is spendable by this home's next payment at
once, up to 16 unmined in a row. A price over -max-sats is not paid. Every
carrier answered is verified against this home's headers, and held to the
token of the vault that listed it. The free version class gives the same
carriers one version at a time (bsecret get -version N).

A version listed here is one the host still holds: it is what a member of
that version's epoch, removed since or not, can still fetch and open.`

func cmdHistory(ctx context.Context, g *global, args []string) error {
	fs := g.flagSet("history", historyHelp)
	at := fs.String("at", "", "the host's terms route base URL (default paid_host)")
	after := fs.String("after", "", "the page after this version")
	maxSats := fs.Uint64("max-sats", limits.DefaultMaxPrice, "the most one question is paid")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || secrec.CheckSecretName(pos[0]) != nil {
		return usage("history <name>")
	}
	base, err := g.paidBase(*at)
	if err != nil {
		return err
	}
	t, err := g.readTarget(ctx, true)
	if err != nil {
		return err
	}
	h, err := g.openHome()
	if err != nil {
		return err
	}
	defer h.close()
	o, err := g.open(ctx, t, h.st)
	if err != nil {
		return err
	}
	id, _ := secrec.SecretID(t.vault, pos[0])
	q := vread.Query{"crypt": t.crypt, "history": t.orgHex, "vault": t.vaultHex(), "secret": hex.EncodeToString(id[:])}
	if *after != "" {
		q["after"] = *after
	}
	outs, _, err := g.ask(ctx, h, t.rd.Headers, base, q, *maxSats)
	if err != nil {
		return err
	}
	var bad error
	for _, out := range outs {
		car, err := t.rd.Carrier(ctx, out.Beef, t.crypt)
		if err == nil && (car.Carrier.Secret.ID != id || car.Carrier.Secret.Vault != t.vault) {
			err = errors.New("another secret's carrier")
		}
		if err != nil {
			g.say("REFUSED an answered carrier (%s): %v", secrec.Reason(err), err)
			bad = refused("the host answered a carrier that does not verify; it is not shown")
			continue
		}
		rec := car.Carrier.Secret
		listed := "not listed by any token of the vault"
		for _, tok := range o.chain.Tokens[:o.chain.Usable()] {
			if secrec.CheckListed(tok.Token.Vault, rec) == nil {
				listed = fmt.Sprintf("listed at seq %d, height %d", tok.Seq(), tok.Height)
			}
		}
		fmt.Fprintf(g.stdout, "version %d  %s  epoch %d  label %s  %d bytes: %s\n", rec.Version, car.Txid, rec.Epoch, rec.Label, rec.Length, listed)
	}
	g.say("%d carrier(s) of %s held by %s", len(outs), pos[0], base)
	if bad != nil {
		return bad
	}
	return h.st.Save()
}

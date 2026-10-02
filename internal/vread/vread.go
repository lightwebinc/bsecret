// Package vread asks overlay hosts the ls_bsecret questions and checks
// every answer itself (docs/spec.md sections 10.2, 13 and 14): a vault
// token's record, lock and field signature, its proof against the reader's
// own headers and its descent by spends from the vault's first token; a
// secret carrier by the host's own admission rules and by SPV through its
// funding parent; a sweep by its proof. A host is trusted for nothing: an
// answer is verified here or reported as refused, naming the host. An empty
// answer means only that the host holds nothing that answers.
//
// A reader that asks several hosts compares their answers and reports a
// difference as such, never merging it silently: a host can withhold a
// token or a record, and only a comparison (or a root) shows it.
//
// The vault's group is borg's. Its chain, its epochs and a member's epoch
// keys are read by borg's own reader package (group.go), never by a copy of
// its rules.
package vread

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/spv"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"

	"github.com/lightwebinc/bcommon/guard"
	"github.com/lightwebinc/bcommon/hostset"
	"github.com/lightwebinc/bcommon/lookup"

	"github.com/lightwebinc/borg/reader"

	"github.com/lightwebinc/bsecret/internal/limits"
	"github.com/lightwebinc/bsecret/internal/secrec"
)

// Client asks hosts and checks their answers.
type Client struct {
	// Hosts are the overlay hosts' base URLs, asked in order.
	Hosts []string
	// Headers is the reader's own header source. It is required: an answer
	// is only as good as the headers it is checked against.
	Headers chaintracker.ChainTracker
	// Timeout bounds each request; HTTP, when set, is the client used.
	Timeout time.Duration
	HTTP    *http.Client
	// MaxPages bounds the pages one question reads per host.
	MaxPages int
	// Source, when set, is a chain source that indexes spends: a sweep is
	// also looked for there (Swept), by its proof.
	Source ChainSource
}

// ChainSource is a node's view of what spends an output, with the
// spender's bytes and proof: nodeapi.Asset is one. An answer of "" with no
// error is "unspent".
type ChainSource interface {
	Spender(ctx context.Context, txid string, vout uint32) (string, error)
	TxRaw(ctx context.Context, txid string) ([]byte, error)
	MerkleProof(ctx context.Context, txid string) (*transaction.MerklePath, error)
}

// Query is one ls_bsecret question: its members, every one a string.
type Query map[string]string

// ErrHost is a host that answered with an error: its words travel with it.
var ErrHost = errors.New("vread: the host refused the question")

// ErrNoHeaders refuses to verify against no header source.
var ErrNoHeaders = errors.New("vread: no header source; refusing to verify against a default")

// ErrNoHosts is a reader with no host to ask.
var ErrNoHosts = errors.New("no overlay host configured (config key hosts, or -hosts)")

// Ask asks one host one question and returns the outputs it answered. The
// question is held to the class rules first, so a question no host could
// answer is never sent.
func (c *Client) Ask(ctx context.Context, host string, q Query) ([]lookup.Output, error) {
	raw, _ := json.Marshal(q)
	if _, err := secrec.ParseQuery(raw); err != nil {
		return nil, err
	}
	hs := &hostset.Client{Timeout: c.Timeout, HTTP: c.HTTP, MaxBody: limits.MaxAnswer}
	res, err := lookup.Query(ctx, hs, host, lookup.Question{Service: secrec.LookupService, Query: q})
	if err != nil {
		if strings.Contains(err.Error(), "answered status 4") {
			return nil, fmt.Errorf("%w: %v", ErrHost, err)
		}
		return nil, err
	}
	var out []lookup.Output
	for _, r := range res {
		out = append(out, r.Answer.Outputs...)
	}
	return out, nil
}

// Ping asks a host a question no class answers, which a live ls_bsecret
// refuses with an error: the host is up and runs the service.
func (c *Client) Ping(ctx context.Context, host string) error {
	hs := &hostset.Client{Timeout: c.Timeout, HTTP: c.HTTP, MaxBody: limits.MaxAnswer}
	_, err := lookup.Query(ctx, hs, host, lookup.Question{Service: secrec.LookupService, Query: Query{}})
	if err != nil && strings.Contains(err.Error(), "answered status 4") {
		return nil
	}
	return err
}

// SubjectID is the txid of a BEEF's subject.
func SubjectID(beef []byte) string { return reader.SubjectID(beef) }

// Held asks whether host answers a question with an output whose subject is
// txid: a publisher's confirmation that a host holds the object (spec
// section 13).
func (c *Client) Held(ctx context.Context, host string, q Query, txid string) (bool, error) {
	outs, err := c.Ask(ctx, host, q)
	if err != nil {
		return false, err
	}
	for _, o := range outs {
		if SubjectID(o.Beef) == txid {
			return true, nil
		}
	}
	return false, nil
}

// Refusal is an answered output that did not verify.
type Refusal struct {
	Host   string
	Txid   string
	Reason string
	Err    error
}

// Tok is one answered vault token that verified.
type Tok struct {
	Txid string
	Tx   *transaction.Transaction
	// Token is the token output, its record decoded.
	Token *secrec.VaultToken
	// Height and Pos place it: its block and its offset in the block.
	Height uint32
	Pos    uint64
	// Beef is the token as answered (the engine's stored form).
	Beef []byte
}

// Seq is the token's seq.
func (t *Tok) Seq() uint64 { return t.Token.Vault.Seq }

// Hash is the token's txid in hash byte order.
func (t *Tok) Hash() [32]byte { return [32]byte(*t.Tx.TxID()) }

// Before reports whether t was mined before u: lower height, then lower
// position in its block, then lower txid.
func (t *Tok) Before(u *Tok) bool {
	if t.Height != u.Height {
		return t.Height < u.Height
	}
	if t.Pos != u.Pos {
		return t.Pos < u.Pos
	}
	return t.Txid < u.Txid
}

// VerifyToken checks one answered token as a reader does (spec section 14):
// the transaction holds exactly one well-formed vault token (its record,
// its lock derived from the record's owner, its field signature), of crypt
// and owner org and, when vault is not nil, of that vault, and its proof
// verifies against headers. Descent from the vault's first token is the
// chain's (Chain).
func VerifyToken(ctx context.Context, beef []byte, crypt string, org []byte, vault *[32]byte, headers chaintracker.ChainTracker) (*Tok, error) {
	if headers == nil {
		return nil, ErrNoHeaders
	}
	if len(beef) > limits.MaxBEEF {
		return nil, fmt.Errorf("%w: %d bytes", secrec.ErrBEEF, len(beef))
	}
	tx, tok, err := secrec.StoredToken(beef)
	if err != nil {
		return nil, err
	}
	v := tok.Vault
	if v.Crypt != crypt {
		return nil, fmt.Errorf("%w: the token names crypt %q", secrec.ErrCrypt, v.Crypt)
	}
	if org != nil && !bytes.Equal(v.Org, org) {
		return nil, errors.New("vread: the token is another owner's")
	}
	if vault != nil && v.Vault != *vault {
		return nil, errors.New("vread: the token is another vault's")
	}
	if !secrec.IsMined(ctx, tx, headers) {
		return nil, secrec.ErrUnmined
	}
	t := &Tok{Txid: tx.TxID().String(), Tx: tx, Token: tok, Height: tx.MerklePath.BlockHeight, Beef: beef}
	for _, l := range tx.MerklePath.Path[0] {
		if l.Hash != nil && *l.Hash == *tx.TxID() {
			t.Pos = l.Offset
		}
	}
	return t, nil
}

// Car is one answered secret carrier that verified.
type Car struct {
	Txid string
	Beef []byte
	Tx   *transaction.Transaction
	// Carrier is the carrier by the host's own rules: its record, owner,
	// content id, commitment and funding outpoint.
	Carrier *secrec.Carrier
	// Context is the BRC-24 context the host answered with it.
	Context []byte
	// Host is the first host that answered it.
	Host string
}

// VerifyCarrier checks one answered secret carrier: the host's admission
// rules for crypt (every carrier rule and the record's own, the inline
// ciphertext's length and hash among them), and SPV through its funding
// parent against headers.
func VerifyCarrier(ctx context.Context, beef []byte, crypt string, headers chaintracker.ChainTracker) (*Car, error) {
	if headers == nil {
		return nil, ErrNoHeaders
	}
	_, tx, txid, err := guard.ParseBEEF(beef, limits.MaxBEEF)
	if err != nil || tx == nil {
		return nil, fmt.Errorf("%w: %v", secrec.ErrBEEF, err)
	}
	a, err := secrec.Admit(ctx, beef, nil, secrec.Host{Crypt: crypt, Headers: headers, MaxBEEF: limits.MaxBEEF})
	if err != nil {
		return nil, err
	}
	if a.Kind != secrec.TxSecret || a.Carrier == nil {
		return nil, fmt.Errorf("vread: the answer is a %s, not a secret", a.Kind)
	}
	if ok, err := spv.Verify(ctx, tx, headers, nil); err != nil || !ok {
		return nil, fmt.Errorf("vread: SPV of the carrier through its funding parent: %v", err)
	}
	return &Car{Txid: txid.String(), Beef: beef, Tx: tx, Carrier: a.Carrier}, nil
}

// VerifySweep checks an answered sweep: admitted by the host's rules (a
// mined transaction whose output 0 is funding-shaped) against the reader's
// own headers, and returns the outpoints it spends.
func VerifySweep(ctx context.Context, beef []byte, crypt string, headers chaintracker.ChainTracker) ([]transaction.Outpoint, string, error) {
	if headers == nil {
		return nil, "", ErrNoHeaders
	}
	a, err := secrec.Admit(ctx, beef, nil, secrec.Host{Crypt: crypt, Headers: headers, MaxBEEF: limits.MaxBEEF})
	if err != nil {
		return nil, "", err
	}
	if a.Kind != secrec.TxSweep {
		return nil, "", fmt.Errorf("vread: the answer is a %s, not a sweep", a.Kind)
	}
	return a.Spent, chainhash.Hash(a.Txid).String(), nil
}

// pageOutputs is the most outputs taken from one page (the contract's
// largest page is 64 tokens; a page of carriers never splits a secret's, so
// it may pass 16 by a few), and walkBytes the most bytes one paged walk
// holds from one host.
const (
	pageOutputs = 128
	walkBytes   = 256 << 20
)

// A host stores an object with the proof it was given, and cannot take a
// new one: after a reorganisation the stored proof may name a block that is
// no longer in the best chain, although the same transaction was mined
// again elsewhere (spec section 11.5). A reader then fetches the
// transaction's current proof from a chain source by its txid, and verifies
// that against its own headers. The three methods below do it for a token,
// a carrier's funding tree and a sweep; without a chain source they are the
// plain checks.

// current is the chain source's proof of tx, cut to the minimal one, when
// the proof tx carries does not verify against the reader's headers and the
// source's does.
func (c *Client) current(ctx context.Context, tx *transaction.Transaction) bool {
	if c.Source == nil || tx == nil || c.Headers == nil {
		return false
	}
	if tx.MerklePath != nil {
		if ok, err := tx.MerklePath.Verify(ctx, tx.TxID(), c.Headers); err != nil || ok {
			return false
		}
	}
	mp, err := c.Source.MerkleProof(ctx, tx.TxID().String())
	if err != nil || mp == nil {
		return false
	}
	if mp, err = secrec.MinimalPath(mp, tx.TxID()); err != nil {
		return false
	}
	if ok, err := mp.Verify(ctx, tx.TxID(), c.Headers); err != nil || !ok {
		return false
	}
	tx.MerklePath = mp
	return true
}

// Token is VerifyToken, with a stale stored proof replaced by the chain
// source's current one.
func (c *Client) Token(ctx context.Context, beef []byte, crypt string, org []byte, vault *[32]byte) (*Tok, error) {
	t, err := VerifyToken(ctx, beef, crypt, org, vault, c.Headers)
	if !errors.Is(err, secrec.ErrUnmined) || len(beef) > limits.MaxBEEF {
		return t, err
	}
	tx, _, perr := secrec.StoredToken(beef)
	if perr != nil || !c.current(ctx, tx) {
		return nil, err
	}
	again, perr := tx.AtomicBEEF(false)
	if perr != nil {
		return nil, err
	}
	return VerifyToken(ctx, again, crypt, org, vault, c.Headers)
}

// Carrier is VerifyCarrier, with a stale proof of the carrier's funding
// tree replaced by the chain source's current one.
func (c *Client) Carrier(ctx context.Context, beef []byte, crypt string) (*Car, error) {
	car, err := VerifyCarrier(ctx, beef, crypt, c.Headers)
	if err == nil || c.Source == nil {
		return car, err
	}
	_, tx, _, perr := guard.ParseBEEF(beef, limits.MaxBEEF)
	if perr != nil || tx == nil || len(tx.Inputs) != 1 || !c.current(ctx, tx.Inputs[0].SourceTransaction) {
		return nil, err
	}
	again, perr := tx.AtomicBEEF(false)
	if perr != nil {
		return nil, err
	}
	return VerifyCarrier(ctx, again, crypt, c.Headers)
}

// Sweep is VerifySweep, with a stale stored proof replaced by the chain
// source's current one.
func (c *Client) Sweep(ctx context.Context, beef []byte, crypt string) ([]transaction.Outpoint, string, error) {
	spent, txid, err := VerifySweep(ctx, beef, crypt, c.Headers)
	if !errors.Is(err, secrec.ErrUnmined) {
		return spent, txid, err
	}
	_, tx, _, perr := guard.ParseBEEF(beef, limits.MaxBEEF)
	if perr != nil || tx == nil || !c.current(ctx, tx) {
		return nil, "", err
	}
	again, perr := tx.AtomicBEEF(false)
	if perr != nil {
		return nil, "", err
	}
	return VerifySweep(ctx, again, crypt, c.Headers)
}

// HostOutputs is what one host answered to one question, all pages.
type HostOutputs struct {
	Host      string
	Outputs   []lookup.Output
	Err       error
	Truncated bool
}

// Pages asks one host a paged class, page after page, until a page is
// empty: a page never splits one secret's or one seq's outputs, so a page
// short of the limit is not thereby the last. cursor gives the -after
// member for an output, or "" when it has none; the highest cursor of a
// page (by less) asks for the next. A host that answers nothing past the
// cursor it was given ends the walk.
func (c *Client) Pages(ctx context.Context, host string, q Query, cursor func(lookup.Output) string, less func(a, b string) bool) HostOutputs {
	ho := HostOutputs{Host: host}
	maxPages := c.MaxPages
	if maxPages <= 0 {
		maxPages = limits.MaxPages
	}
	page := Query{}
	for k, v := range q {
		page[k] = v
	}
	held := 0
	for n := 0; ; n++ {
		if n == maxPages {
			ho.Truncated = true
			return ho
		}
		outs, err := c.Ask(ctx, host, page)
		if err != nil {
			ho.Err = err
			return ho
		}
		if len(outs) == 0 {
			return ho
		}
		// What one page and one walk may hold is bounded here, whatever a
		// host answers: a page of this contract is at most 64 outputs, and
		// a hostile one is cut, and said to be cut, not accumulated.
		if len(outs) > pageOutputs {
			outs, ho.Truncated = outs[:pageOutputs], true
		}
		for _, o := range outs {
			held += len(o.Beef) + len(o.Context)
		}
		if held > walkBytes {
			ho.Truncated = true
			return ho
		}
		ho.Outputs = append(ho.Outputs, outs...)
		if ho.Truncated {
			return ho
		}
		last := ""
		for _, o := range outs {
			if k := cursor(o); k != "" && (last == "" || less(last, k)) {
				last = k
			}
		}
		if prev, ok := page["after"]; last == "" || (ok && !less(prev, last)) {
			return ho
		}
		page["after"] = last
	}
}

// Hash is a display txid as a hash (hash byte order).
func Hash(txid string) ([32]byte, error) {
	h, err := chainhash.NewHashFromHex(txid)
	if err != nil || h.String() != txid {
		return [32]byte{}, fmt.Errorf("%q is not a transaction id (64 lowercase hex characters)", txid)
	}
	return [32]byte(*h), nil
}

// Hex32 reads 64 lowercase hex digits: a vault or secret identifier.
func Hex32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 || hex.EncodeToString(b) != s {
		return out, fmt.Errorf("%q is not an identifier (64 lowercase hex digits)", s)
	}
	copy(out[:], b)
	return out, nil
}

// Seq is a seq or a version as a question writes it.
func Seq(n uint64) string { return strconv.FormatUint(n, 10) }

// Short is a txid's or an identifier's first 12 digits, for notes.
func Short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// JoinSeqs words a list of seqs.
func JoinSeqs(s []uint64) string {
	parts := make([]string, len(s))
	for i, n := range s {
		parts[i] = Seq(n)
	}
	return strings.Join(parts, ", ")
}

// Terms is a host's terms document (spec section 10.3).
type Terms struct {
	Service string `json:"service"`
	Terms   int    `json:"terms"`
	Classes []struct {
		Class    string `json:"class"`
		Satoshis uint64 `json:"satoshis"`
	} `json:"classes"`
}

// ErrNoTerms is a host that serves no terms document: it charges for
// nothing.
var ErrNoTerms = errors.New("vread: the host serves no terms document, so it charges for nothing")

// FetchTerms reads <base>/ls_bsecret/terms. Members and classes a client
// does not know are ignored; a free class with a price is reported, and a
// client never pays for one.
func FetchTerms(ctx context.Context, hc *http.Client, base string) (*Terms, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/"+secrec.LookupService+"/terms", nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrNoTerms
	default:
		return nil, fmt.Errorf("terms: status %d", resp.StatusCode)
	}
	var t Terms
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, fmt.Errorf("terms: not the terms document: %w", err)
	}
	if t.Service != secrec.LookupService || t.Terms != 1 {
		return nil, fmt.Errorf("terms: service %q version %d, not %s version 1", t.Service, t.Terms, secrec.LookupService)
	}
	return &t, nil
}

func firstErr(m map[string]error) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return nil
	}
	return fmt.Errorf("%s: %w", keys[0], m[keys[0]])
}

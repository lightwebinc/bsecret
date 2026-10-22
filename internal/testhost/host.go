// Package testhost is the local stand-ins this module's tests run against:
// an overlay host that carries bsecret crypts and borg halls, a plane, a
// terms route, and an organization's borg tooling reduced to what a vault
// needs of it. Nothing here is for real use.
package testhost

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
	"sync"

	"github.com/bsv-blockchain/go-sdk/spv"
	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/lightwebinc/bcommon/guard"
	bc "github.com/lightwebinc/bcommon/testchain"

	"github.com/lightwebinc/borg/borgrec"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// Chain is the shared local chain.
type Chain = bc.Chain

// NewChain is a chain whose tip is at height start.
func NewChain(start uint32) *Chain { return bc.New(start) }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// Host is a stand-in overlay host carrying bsecret crypts and borg halls.
// For a crypt, /submit runs the engine's SPV and the bsecret topic manager
// (secrec.Admit) over the topic's previous coins, and /lookup answers the
// ls_bsecret classes from an index that keeps only rooted tokens as a
// vault's chain, folds it, and keeps one outpoint row per funding outpoint
// (docs/spec.md sections 10.2, 11.1 and 11.2). For a hall it admits by
// borg's own rules (borgrec.Admit) and answers the ls_borg classes a vault's
// reader asks. A refusal is recorded nowhere, so the same transaction
// offered again is decided afresh. The priced classes are refused on
// /lookup when Priced is set, as a host that sells them refuses them
// there. Retention, restore and the bounded tables are the real module's
// and are not modelled.
type Host struct {
	mu      sync.Mutex
	chain   *Chain
	crypts  map[string]bool
	halls   map[string]bool
	applied map[string]bool
	tokens  map[string]*tokRow
	cars    map[string]*carRow
	sweeps  map[string]*sweepRow
	borg    *borgIndex
	// gen counts admitted and forgotten objects; views caches each vault's
	// view until it moves.
	gen   int
	views map[string]*vaultView
	// coins are the outputs the host holds, by outpoint, with the topic.
	coins map[transaction.Outpoint]string
	// Down answers every request with 503.
	Down bool
	// Priced refuses the priceable classes on /lookup.
	Priced bool
	// Private are the crypts whose questions /lookup refuses: they are
	// asked over BRC-104 at a route (NewPrivate).
	Private map[string]bool
	// Drop, when set, is asked about each submission; true discards it
	// unseen, as a plane that lost the object would.
	Drop func(tx *transaction.Transaction) bool
	// Substitute, when set, rewrites a carrier's answered BEEF: a host
	// that serves other bytes.
	Substitute func(beef []byte) []byte
	// Rewrite, when set, rewrites the answer to an ls_bsecret question: a
	// host that withholds, adds or repeats outputs.
	Rewrite func(q *secrec.Question, outs []Output) []Output
	// RewriteBorg, when set, rewrites the answer to an ls_borg question: a
	// hall's host that withholds a wrap, or serves other bytes for one.
	RewriteBorg func(q *borgrec.Question, outs []Output) []Output
	// Stale answers every token, carrier and sweep under a proof that names
	// another block than the one the chain mined it in: a host whose stored
	// proofs a reorganization left behind.
	Stale bool
	// Submits counts submissions; Refused counts refusals by reason; Asked
	// counts the ls_bsecret questions answered, by class.
	Submits int
	Refused map[string]int
	Asked   map[string]int
}

type tokRow struct {
	txid   string
	crypt  string
	org    string
	vault  string
	seq    uint64
	stored []byte
	tx     *transaction.Transaction
	tok    *secrec.VaultToken
}

type carRow struct {
	txid  string
	crypt string
	beef  []byte
	c     *secrec.Carrier
}

type sweepRow struct {
	txid  string
	crypt string
	beef  []byte
	spent []string
}

func (h *Host) isPrivate(crypt string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.Private[crypt]
}

// NewHost is a host whose engine checks proofs against chain.
func NewHost(chain *Chain) *Host {
	return &Host{chain: chain, crypts: map[string]bool{}, halls: map[string]bool{}, applied: map[string]bool{},
		tokens: map[string]*tokRow{}, cars: map[string]*carRow{}, sweeps: map[string]*sweepRow{},
		coins: map[transaction.Outpoint]string{}, Refused: map[string]int{}, Asked: map[string]int{}, borg: newBorgIndex()}
}

// Carry adds a crypt.
func (h *Host) Carry(crypt string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.crypts[crypt] = true
}

// CarryHall adds a borg hall.
func (h *Host) CarryHall(hall string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.halls[hall] = true
}

// SetDown takes the host down or brings it back.
func (h *Host) SetDown(down bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Down = down
}

// Holds reports whether the host holds a bsecret object with txid.
func (h *Host) Holds(txid string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.tokens[txid] != nil || h.cars[txid] != nil {
		return true
	}
	for _, s := range h.sweeps {
		if s.txid == txid {
			return true
		}
	}
	return false
}

// Forget drops an object, as a host that lost it would: an honest host
// does not, but a test makes one that did.
func (h *Host) Forget(txid string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.tokens, txid)
	delete(h.cars, txid)
	for k, s := range h.sweeps {
		if s.txid == txid {
			delete(h.sweeps, k)
		}
	}
	for k := range h.applied {
		if strings.HasSuffix(k, "/"+txid) {
			delete(h.applied, k)
		}
	}
	h.gen++
}

// ForgetHall drops a borg object, as a hall's host that lost it, or
// withholds it, would.
func (h *Host) ForgetHall(txid string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.borg.tokens, txid)
	delete(h.borg.wraps, txid)
	for k := range h.applied {
		if strings.HasSuffix(k, "/"+txid) {
			delete(h.applied, k)
		}
	}
}

// Questions is how many ls_bsecret questions of a class the host answered.
func (h *Host) Questions(class string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.Asked[class]
}

// Txids are the txids of the bsecret objects the host holds of a kind:
// "secret", "token" or "sweep", sorted.
func (h *Host) Txids(kind string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	switch kind {
	case "secret":
		for id := range h.cars {
			out = append(out, id)
		}
	case "token":
		for id := range h.tokens {
			out = append(out, id)
		}
	case "sweep":
		seen := map[string]bool{}
		for _, s := range h.sweeps {
			if !seen[s.txid] {
				seen[s.txid] = true
				out = append(out, s.txid)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (h *Host) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	down := h.Down
	h.mu.Unlock()
	if down {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/submit":
		h.submit(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/lookup":
		h.lookup(w, r)
	default:
		http.NotFound(w, r)
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func cloneTx(tx *transaction.Transaction) *transaction.Transaction {
	cp, err := transaction.NewTransactionFromBytes(tx.Bytes())
	if err != nil {
		panic(err)
	}
	cp.MerklePath = tx.MerklePath
	return cp
}

func (h *Host) submit(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "body")
		return
	}
	topic := r.Header.Get("x-topics")
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Submits++
	crypt, isCrypt := strings.CutPrefix(topic, secrec.TopicPrefix)
	hall, isHall := strings.CutPrefix(topic, borgrec.TopicPrefix)
	if !(isCrypt && h.crypts[crypt]) && !(isHall && h.halls[hall]) {
		writeError(w, http.StatusBadRequest, "topic not carried")
		return
	}
	_, tx, txid, err := guard.ParseBEEF(body, 8<<20)
	if err != nil || tx == nil {
		writeError(w, http.StatusBadRequest, "not a BEEF")
		return
	}
	steak := func(admit []int, retain []int) {
		if admit == nil {
			admit = []int{}
		}
		if retain == nil {
			retain = []int{}
		}
		writeJSON(w, map[string]any{topic: map[string]any{"outputsToAdmit": admit, "coinsToRetain": retain}})
	}
	if h.Drop != nil && h.Drop(tx) {
		steak(nil, nil)
		return
	}
	id := txid.String()
	if h.applied[topic+"/"+id] {
		steak(nil, nil)
		return
	}
	ok, verr := spv.Verify(context.Background(), tx, h.chain, nil)
	if verr != nil || !ok {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("SPV: %v", verr))
		return
	}
	var prev []int
	for i, in := range tx.Inputs {
		if h.coins[transaction.Outpoint{Txid: *in.SourceTXID, Index: in.SourceTxOutIndex}] == topic {
			prev = append(prev, i)
		}
	}
	var outs, retain []int
	if isHall {
		a, err := borgrec.Admit(context.Background(), body, prev, borgrec.Host{Hall: hall, Headers: h.chain})
		if err != nil {
			h.Refused[borgrec.Reason(err)]++
			steak(nil, nil)
			return
		}
		h.borg.admit(hall, id, body, tx, a)
		outs, retain = a.Outputs, a.Retain
	} else {
		a, err := secrec.Admit(context.Background(), body, prev, secrec.Host{Crypt: crypt, Headers: h.chain})
		if err != nil {
			// Raised, as the topic manager raises: the engine records
			// nothing and answers the submitter that nothing was admitted.
			h.Refused[secrec.Reason(err)]++
			steak(nil, nil)
			return
		}
		switch a.Kind {
		case secrec.TxSecret:
			h.cars[id] = &carRow{txid: id, crypt: crypt, beef: body, c: a.Carrier}
		case secrec.TxVaultToken:
			alone := cloneTx(tx)
			stored, err := alone.AtomicBEEF(false)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			v := a.Token.Vault
			h.tokens[id] = &tokRow{txid: id, crypt: crypt, org: hex.EncodeToString(v.Org), vault: hex.EncodeToString(v.Vault[:]),
				seq: v.Seq, stored: stored, tx: alone, tok: a.Token}
		case secrec.TxSweep:
			row := &sweepRow{txid: id, crypt: crypt, beef: body}
			for _, op := range a.Spent {
				row.spent = append(row.spent, op.String())
			}
			// A sweep is held per crypt: a host learns of a spend only
			// from a sweep admitted in the crypt's own topic.
			h.sweeps[crypt+"/"+id] = row
		}
		outs, retain = a.Outputs, a.Retain
	}
	h.applied[topic+"/"+id] = true
	h.gen++
	for _, i := range outs {
		h.coins[transaction.Outpoint{Txid: *txid, Index: uint32(i)}] = topic //nolint:gosec // an output index
	}
	steak(outs, retain)
}

func (h *Host) lookup(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Service string          `json:"service"`
		Query   json.RawMessage `json:"query"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&q); err != nil {
		writeError(w, http.StatusBadRequest, "not a question")
		return
	}
	var outs []Output
	switch q.Service {
	case secrec.LookupService:
		qq, err := secrec.ParseQuery(q.Query)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.mu.Lock()
		priced := h.Priced
		private := h.Private[qq.Members["crypt"]]
		h.mu.Unlock()
		if private {
			writeError(w, http.StatusBadRequest, "ls_bsecret: ask over BRC-104: crypt "+qq.Members["crypt"]+" is private on this host")
			return
		}
		if !qq.Class.Free && priced {
			writeError(w, http.StatusBadRequest, qq.Class.Name+" is priced; ask it at the host's terms route")
			return
		}
		if outs, err = h.Answer(qq); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.mu.Lock()
		rewrite := h.Rewrite
		h.mu.Unlock()
		if rewrite != nil {
			outs = rewrite(qq, outs)
		}
	case borgrec.LookupService:
		qq, err := borgrec.ParseQuery(q.Query)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.mu.Lock()
		carried := h.halls[qq.Members["hall"]]
		if carried {
			outs, err = h.borg.answer(qq)
		}
		rewrite := h.RewriteBorg
		h.mu.Unlock()
		if rewrite != nil && err == nil {
			outs = rewrite(qq, outs)
		}
		if !carried {
			err = errors.New("this host does not carry the hall")
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "no such lookup service")
		return
	}
	writeJSON(w, map[string]any{"type": "output-list", "outputs": outs})
}

// Output is one answered output.
type Output struct {
	Beef        []byte `json:"beef"`
	OutputIndex int    `json:"outputIndex"`
	Context     []byte `json:"context,omitempty"`
}

func limit[T any](a []T, n int) []T {
	if len(a) > n {
		return a[:n]
	}
	return a
}

// vaultView is one vault's chain as the index holds it: the rooted tokens
// by seq, the branch an answer uses folded to the highest token at or below
// which nothing broke, and what that branch lists.
type vaultView struct {
	rooted map[uint64][]*tokRow
	held   map[uint64][]*tokRow
	// head is the token whose set answers use; nil when the vault has no
	// rooted token.
	head     *tokRow
	set      []secrec.Current
	listings *secrec.Listings
	gen      int
}

func (h *Host) view(crypt, org, vault string) *vaultView {
	key := crypt + "/" + org + "/" + vault
	if v := h.views[key]; v != nil && v.gen == h.gen {
		return v
	}
	v := h.fold(crypt, org, vault)
	v.gen = h.gen
	if h.views == nil {
		h.views = map[string]*vaultView{}
	}
	h.views[key] = v
	return v
}

func (h *Host) fold(crypt, org, vault string) *vaultView {
	v := &vaultView{rooted: map[uint64][]*tokRow{}, held: map[uint64][]*tokRow{}, listings: secrec.NewListings()}
	var rows []*tokRow
	var txs []*transaction.Transaction
	for _, t := range h.tokens {
		if t.crypt == crypt && t.org == org && t.vault == vault {
			rows = append(rows, t)
			txs = append(txs, t.tx)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].txid < rows[j].txid })
	rooted := secrec.Rooted(txs)
	for _, t := range rows {
		v.held[t.seq] = append(v.held[t.seq], t)
		if rooted[[32]byte(*t.tx.TxID())] {
			v.rooted[t.seq] = append(v.rooted[t.seq], t)
		}
	}
	// One branch: at each seq the lowest txid that spends the token before
	// it (every proof here verifies, so the tie-break is the txid).
	fold := secrec.NewVaultFold()
	var prev *tokRow
	for s := uint64(0); ; s++ {
		var next *tokRow
		for _, t := range v.rooted[s] {
			if prev != nil {
				if _, err := secrec.CheckNextToken(prev.tx, prev.tok, t.tx); err != nil {
					continue
				}
			}
			next = t
			break
		}
		if next == nil {
			break
		}
		st := fold.Apply(next.tok.Vault)
		if st == secrec.StatusSetMismatch || st == secrec.StatusStaleMismatch {
			break
		}
		v.listings.Apply(next.tok.Vault)
		v.head, v.set, prev = next, fold.Set(), next
	}
	return v
}

// row is the outpoint row of a carrier's funding outpoint.
func (h *Host) row(c *carRow) *secrec.OutpointRow {
	r := &secrec.OutpointRow{}
	op := c.c.Funding.String()
	for _, o := range h.cars {
		if o.crypt == c.crypt && o.c.Funding.String() == op {
			r.Add(o.c.Commitment)
		}
	}
	for _, s := range h.sweeps {
		if s.crypt != c.crypt {
			continue
		}
		for _, x := range s.spent {
			if x == op {
				r.Swept = true
			}
		}
	}
	return r
}

func (h *Host) status(v *vaultView, c *carRow) string {
	return secrec.CarrierStatus(h.row(c), c.c.Commitment, v.listings, c.c.Secret)
}

// Status is the status of a carrier the host holds, or "".
func (h *Host) Status(txid string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.cars[txid]
	if c == nil {
		return ""
	}
	s := c.c.Secret
	return h.status(h.view(c.crypt, hex.EncodeToString(s.Org), hex.EncodeToString(s.Vault[:])), c)
}

func latestOf(rows map[uint64][]*tokRow) []*tokRow {
	var top uint64
	found := false
	for s := range rows {
		if !found || s > top {
			top, found = s, true
		}
	}
	if !found {
		return nil
	}
	return rows[top]
}

func idHex(c *carRow) string { return hex.EncodeToString(c.c.Secret.ID[:]) }

func sortCars(rs []*carRow) {
	sort.Slice(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if idHex(a) != idHex(b) {
			return idHex(a) < idHex(b)
		}
		if a.c.Secret.Version != b.c.Secret.Version {
			return a.c.Secret.Version < b.c.Secret.Version
		}
		return a.txid < b.txid
	})
}

// page cuts rs, already ordered, to at most n without splitting a run of
// equal keys; a run longer than n is answered whole.
func page[T any](rs []T, n int, key func(T) string) []T {
	if len(rs) <= n {
		return rs
	}
	cut := n
	for cut > 0 && key(rs[cut-1]) == key(rs[cut]) {
		cut--
	}
	if cut == 0 {
		cut = n
		for cut < len(rs) && key(rs[cut-1]) == key(rs[cut]) {
			cut++
		}
	}
	return rs[:cut]
}

// Answer answers a validated ls_bsecret question.
func (h *Host) Answer(q *secrec.Question) ([]Output, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := q.Members
	crypt := m["crypt"]
	if !h.crypts[crypt] {
		return nil, errors.New("this host does not carry the crypt")
	}
	h.Asked[q.Class.Name]++
	n := q.Class.Limit
	toks := func(rs []*tokRow) []Output {
		out := []Output{}
		for _, t := range rs {
			out = append(out, Output{Beef: h.stale(t.stored, false)})
		}
		return out
	}
	serve := func(c *carRow) []byte {
		if h.Substitute != nil {
			return h.Substitute(c.beef)
		}
		return h.stale(c.beef, true)
	}
	cars := func(rs []*carRow) []Output {
		out := []Output{}
		for _, c := range rs {
			out = append(out, Output{Beef: serve(c)})
		}
		return out
	}
	// The carriers of a vault, by a status test.
	of := func(v *vaultView, org, vault string, keep func(c *carRow, status string) bool) []*carRow {
		var rs []*carRow
		for _, c := range h.cars {
			s := c.c.Secret
			if c.crypt != crypt || hex.EncodeToString(s.Org) != org || hex.EncodeToString(s.Vault[:]) != vault {
				continue
			}
			if keep(c, h.status(v, c)) {
				rs = append(rs, c)
			}
		}
		sortCars(rs)
		return rs
	}
	inSet := func(v *vaultView, c *carRow) bool {
		for _, cur := range v.set {
			if cur.ID == c.c.Secret.ID {
				return cur.Version == c.c.Secret.Version && cur.ContentID == c.c.ContentID
			}
		}
		return false
	}
	withPath := func(v *vaultView, rs []*carRow) []Output {
		out := []Output{}
		for _, c := range rs {
			o := Output{Beef: serve(c)}
			if ic, err := secrec.ProveSecret(v.head.seq, [32]byte(*v.head.tx.TxID()), v.set, c.c.Secret.ID); err == nil {
				o.Context, _ = ic.Encode()
			}
			out = append(out, o)
		}
		return out
	}
	switch q.Class.Name {
	case "vault":
		return toks(limit(latestOf(h.view(crypt, m["org"], m["vault"]).rooted), n)), nil
	case "vault-seq":
		s, _ := strconv.ParseUint(m["seq"], 10, 64)
		return toks(limit(h.view(crypt, m["org"], m["vault"]).held[s], n)), nil
	case "vaults", "vaults-after":
		vaults := map[string]bool{}
		for _, t := range h.tokens {
			if t.crypt == crypt && t.org == m["vaultsOf"] {
				vaults[t.vault] = true
			}
		}
		ids := make([]string, 0, len(vaults))
		for id := range vaults {
			if a := m["after"]; a == "" || id > a {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		out := []Output{}
		for _, id := range ids {
			if rs := latestOf(h.view(crypt, m["vaultsOf"], id).rooted); len(rs) > 0 && len(out) < n {
				out = append(out, Output{Beef: rs[0].stored})
			}
		}
		return out, nil
	case "secret":
		v := h.view(crypt, m["org"], m["vault"])
		if v.head == nil {
			return []Output{}, nil
		}
		rs := of(v, m["org"], m["vault"], func(c *carRow, st string) bool {
			return idHex(c) == m["secret"] && st == secrec.StatusListed && inSet(v, c)
		})
		return withPath(v, limit(rs, n)), nil
	case "version":
		ver, _ := strconv.ParseUint(m["version"], 10, 64)
		v := h.view(crypt, m["org"], m["vault"])
		rs := of(v, m["org"], m["vault"], func(c *carRow, st string) bool {
			return idHex(c) == m["secret"] && c.c.Secret.Version == ver &&
				(st == secrec.StatusListed || st == secrec.StatusUnlisted || st == secrec.StatusMismatched)
		})
		return cars(limit(rs, n)), nil
	case "pending":
		v := h.view(crypt, m["org"], m["vault"])
		var have uint64
		for _, cur := range v.set {
			if hex.EncodeToString(cur.ID[:]) == m["pending"] {
				have = cur.Version
			}
		}
		rs := of(v, m["org"], m["vault"], func(c *carRow, st string) bool {
			return idHex(c) == m["pending"] && st == secrec.StatusUnlisted && c.c.Secret.Version > have
		})
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].c.Secret.Version > rs[j].c.Secret.Version })
		return cars(limit(rs, n)), nil
	case "secrets", "secrets-after", "label", "label-after":
		org, vault := m["org"], m["secretsOf"]
		if vault == "" {
			vault = m["vault"]
		}
		v := h.view(crypt, org, vault)
		if v.head == nil {
			return []Output{}, nil
		}
		rs := of(v, org, vault, func(c *carRow, st string) bool {
			if st != secrec.StatusListed || !inSet(v, c) {
				return false
			}
			if l, ok := m["label"]; ok && c.c.Secret.Label != l {
				return false
			}
			return m["after"] == "" || idHex(c) > m["after"]
		})
		return withPath(v, page(rs, n, idHex)), nil
	case "sweep":
		out := []Output{}
		for _, s := range h.sweeps {
			if s.crypt != crypt {
				continue
			}
			for _, x := range s.spent {
				if x == m["spent"] {
					out = append(out, Output{Beef: h.stale(s.beef, false)})
				}
			}
		}
		return limit(out, n), nil
	case "history", "history-after":
		after, _ := strconv.ParseUint(m["after"], 10, 64)
		v := h.view(crypt, m["history"], m["vault"])
		rs := of(v, m["history"], m["vault"], func(c *carRow, st string) bool {
			return idHex(c) == m["secret"] && c.c.Secret.Version > after &&
				(st == secrec.StatusListed || st == secrec.StatusUnlisted || st == secrec.StatusMismatched)
		})
		return cars(page(rs, n, func(c *carRow) string { return strconv.FormatUint(c.c.Secret.Version, 10) })), nil
	case "audit", "audit-after":
		v := h.view(crypt, m["audit"], m["vault"])
		var rs []*tokRow
		for s, ts := range v.rooted {
			if a, ok := m["after"]; ok {
				if after, _ := strconv.ParseUint(a, 10, 64); s <= after {
					continue
				}
			}
			rs = append(rs, ts...)
		}
		sort.Slice(rs, func(i, j int) bool {
			if rs[i].seq != rs[j].seq {
				return rs[i].seq < rs[j].seq
			}
			return rs[i].txid < rs[j].txid
		})
		return toks(page(rs, n, func(t *tokRow) string { return strconv.FormatUint(t.seq, 10) })), nil
	}
	return nil, fmt.Errorf("class %s is not answered here", q.Class.Name)
}

// stale rewrites a stored BEEF's proof to name another block when Stale is
// set: the subject's own proof, or with parent its funding parent's.
func (h *Host) stale(beef []byte, parent bool) []byte {
	if !h.Stale {
		return beef
	}
	_, tx, _, err := guard.ParseBEEF(beef, 8<<20)
	if err != nil || tx == nil {
		return beef
	}
	target := tx
	if parent {
		if len(tx.Inputs) == 0 || tx.Inputs[0].SourceTransaction == nil {
			return beef
		}
		target = tx.Inputs[0].SourceTransaction
	}
	if target.MerklePath == nil {
		return beef
	}
	mp := *target.MerklePath
	mp.BlockHeight += 3
	target.MerklePath = &mp
	out, err := tx.AtomicBEEF(false)
	if err != nil {
		return beef
	}
	return out
}

// Plane stands in for the multicast plane: a facade that delivers each
// submission to every host subscribed to the topic, answering with the
// first host's answer. Lookups go to the first host, the facade's own.
type Plane struct {
	Hosts []http.Handler
	// Lost, when set, is asked per host and submission; true loses the
	// object on the way to that host.
	Lost func(host int, tx []byte) bool
}

func (p *Plane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/submit" {
		p.Hosts[0].ServeHTTP(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, "body", http.StatusBadRequest)
		return
	}
	var first *recorder
	for i, h := range p.Hosts {
		if p.Lost != nil && p.Lost(i, body) {
			continue
		}
		rec := &recorder{header: http.Header{}, code: http.StatusOK}
		req := r.Clone(r.Context())
		req.Body = io.NopCloser(bytes.NewReader(body))
		h.ServeHTTP(rec, req)
		if first == nil {
			first = rec
		}
	}
	if first == nil {
		http.Error(w, "lost", http.StatusServiceUnavailable)
		return
	}
	for k, v := range first.header {
		w.Header()[k] = v
	}
	w.WriteHeader(first.code)
	_, _ = w.Write(first.body.Bytes())
}

type recorder struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func (r *recorder) Header() http.Header         { return r.header }
func (r *recorder) WriteHeader(c int)           { r.code = c }
func (r *recorder) Write(b []byte) (int, error) { return r.body.Write(b) }

func newSubmit(topic string, beef []byte) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost, "/submit", bytes.NewReader(beef))
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-topics", topic)
	return req, nil
}

package module

import (
	"container/list"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"

	"github.com/lightwebinc/bcommon/guard"
	bmodule "github.com/lightwebinc/bcommon/module"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// The index's bounds (spec section 11.2).
const (
	// MaxPerSeq is how many tokens are kept at one seq of one vault: rooted
	// before others, then the lowest txids.
	MaxPerSeq = 8
	// RecentTurned is how many commitments turned away are remembered, in
	// memory, to count each once.
	RecentTurned = 4096
	// PerVersion is how many carriers are answered for one version of one
	// secret.
	PerVersion = 8
	// ChoiceTTL is how long a choice between two rooted tokens at one seq
	// is reused.
	ChoiceTTL = time.Minute
)

// TokenStatuses are the token statuses the index reports, each counted.
var TokenStatuses = []string{secrec.StatusConsistent, secrec.StatusPending, secrec.StatusSetMismatch, secrec.StatusStaleMismatch, secrec.StatusCommitmentReuse}

// Deleter is a storage that can delete an output: what retention and the
// outpoint rows need beyond the contract's RestoreStorage. A host whose
// storage cannot delete keeps what the index dropped, unanswered.
type Deleter interface {
	DeleteOutput(ctx context.Context, outpoint *transaction.Outpoint, topic string) error
}

// Access refuses, by an error, a question about a crypt that is not served
// to the asker in ctx (private crypts); nil serves every crypt the host
// carries to everyone.
type Access func(ctx context.Context, crypt string) error

// Options build a Service.
type Options struct {
	Crypts  []string
	Host    bmodule.Host
	Journal Journal
	// Priced are the priceable classes this host prices: asked through the
	// engine, they are refused.
	Priced map[string]bool
	// RetentionDays is how long a host keeps a carrier it no longer
	// answers; UnheldHours the same for a carrier of a vault the host holds
	// no rooted chain of; SpendTable the bound on spends of outpoints no
	// carrier used. The floors are held where an operator sets them.
	RetentionDays int
	UnheldHours   int
	SpendTable    int
	// Headers are the host's block headers: they choose between two rooted
	// tokens at one seq.
	Headers chaintracker.ChainTracker
	// Now is the host's clock; time.Now when nil.
	Now    func() time.Time
	Access Access
}

// tokenEntry is a vault token the host holds.
type tokenEntry struct {
	txid string
	vout uint32
	seq  uint64
	// prev is the predecessor's txid in display order; empty at seq 0.
	prev   string
	rec    *secrec.Vault
	inputs []string
	// first: at seq 0, an input's outpoint hashes to the vault identifier.
	first bool
	// height and root are its stored proof: the block's height and the root
	// the path gives; root nil when it has none.
	height uint32
	root   *chainhash.Hash
	rooted bool
	status string
}

// branch is one branch of a vault's rooted chain, folded: the state after
// its last token.
type branch struct {
	fold     *secrec.VaultFold
	listings *secrec.Listings
	// good is the last token on the branch at or below which nothing broke
	// the fold.
	good *tokenEntry
	// contexts caches the inclusion context of each id in good's set.
	contexts map[[32]byte][]byte
}

type choice struct {
	among string
	txid  string
	at    time.Time
}

// vaultIdx is one vault's tokens.
type vaultIdx struct {
	key, crypt, org, vault string
	bySeq                  map[uint64][]*tokenEntry
	byTxid                 map[string]*tokenEntry
	// children: prev txid -> the txids of tokens naming it.
	children map[string]map[string]bool
	// branches, by the txid of each branch's last rooted token.
	branches map[string]*branch
	// top is the highest seq a rooted token holds; -1 when none is rooted.
	top int64
	// turned are tokens a full seq turned away while they were pending, by
	// the txid they name as their predecessor: txid -> output. They stay in
	// the engine's storage, and are read again once that predecessor is
	// rooted.
	turned map[string]map[string]uint32
	choice *choice
}

// carrierEntry is a secret carrier the host holds.
type carrierEntry struct {
	c       string
	cb      [32]byte
	txid    string
	crypt   string
	vkey    string
	id      string
	version uint64
	op      string
	at      int64
	rec     *secrec.Secret
}

// sweepEntry is a sweep tombstone the host holds.
type sweepEntry struct {
	txid string
	// crypts are every crypt the sweep was admitted in.
	crypts map[string]bool
	spent  []string
	height uint32
	offset uint64
	score  float64
}

type spend struct {
	crypt string
	h     int64
	at    int64
}

// row is one funding outpoint's row, for the host's life.
type row struct {
	row *secrec.OutpointRow
	// sweeps are admitted sweeps that spend it, in the order seen.
	sweeps map[string]spend
	order  []string
	// gone are commitments the row keeps whose carriers the host dropped.
	gone map[string]bool
}

type seenCarrier struct {
	op, crypt string
	at        int64
}

type seenToken struct {
	vout  uint32
	crypt string
	at    int64
}

type pendingDelete struct {
	txid  string
	vout  uint32
	topic string
}

// tableEntry is one outpoint of the bounded table: its spends, oldest
// first.
type tableEntry struct {
	op     string
	spends map[string]spend
	order  []string
}

// Service is ls_bsecret: one lookup service for every crypt a host carries
// (spec sections 10.2, 11.2 to 11.5). Two stores back it. The engine's
// storage holds the outputs the host keeps: vault tokens, secret carriers
// and sweep tombstones, which the service indexes in memory and rebuilds
// from storage on start. The journal holds what the host keeps for its
// life beside them: one row per funding outpoint any admitted carrier
// spent, and the first sight of every token. Spends of outpoints no
// carrier used live only in a bounded table, oldest dropped first.
//
// Every status is a function of what the host holds, never of arrival
// order, with the one exception the contract states (a sweep that left the
// bounded table before its carrier arrived).
type Service struct {
	crypts    map[string]bool
	host      bmodule.Host
	journal   Journal
	priced    map[string]bool
	retention time.Duration
	unheld    time.Duration
	tableCap  int
	headers   chaintracker.ChainTracker
	now       func() time.Time
	access    Access

	mu sync.Mutex
	// What the journal holds.
	rows      map[string]*row
	seen      map[string]seenCarrier
	tokenSeen map[string]seenToken
	// What the host holds, from storage.
	vaults      map[string]*vaultIdx
	vaultsByOrg map[string]map[string]bool
	tokenVault  map[string]string
	carriers    map[string]*carrierEntry
	// versions: vault key | secret id -> version -> commitments.
	versions   map[string]map[uint64]map[string]bool
	sweeps     map[string]*sweepEntry
	sweepsByOp map[string]map[string]bool
	// table: spends of outpoints no carrier used, oldest outpoint first.
	table          *list.List
	tableAt        map[string]*list.Element
	spentSweeps    map[string]map[string]bool
	recentTurned   map[string]bool
	turnedOrder    []string
	reread         []pendingDelete
	pending        map[string]pendingDelete
	storage        bmodule.RestoreStorage
	restoring      bool
	warnedNoDelete bool
}

var (
	_ bmodule.LookupService     = (*Service)(nil)
	_ bmodule.RetentionListener = (*Service)(nil)
	_ bmodule.Restorer          = (*Service)(nil)
)

// NewService builds ls_bsecret and loads the journal.
func NewService(o Options) (*Service, error) {
	if o.RetentionDays == 0 {
		o.RetentionDays = FloorDays
	}
	if o.RetentionDays < FloorDays {
		return nil, fmt.Errorf("ls_bsecret: retention of %d days is under the %d-day floor", o.RetentionDays, FloorDays)
	}
	if o.UnheldHours == 0 {
		o.UnheldHours = FloorUnheldHours
	}
	if o.UnheldHours < FloorUnheldHours {
		return nil, fmt.Errorf("ls_bsecret: %d hours for a carrier of a vault not held is under the %d-hour floor", o.UnheldHours, FloorUnheldHours)
	}
	if o.SpendTable == 0 {
		o.SpendTable = MinSpendTable
	}
	if o.SpendTable < 1 {
		return nil, fmt.Errorf("ls_bsecret: a spend table of %d", o.SpendTable)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Journal == nil {
		o.Journal = &MemoryJournal{}
	}
	s := &Service{crypts: map[string]bool{}, host: o.Host, journal: o.Journal, priced: o.Priced, retention: time.Duration(o.RetentionDays) * 24 * time.Hour,
		unheld: time.Duration(o.UnheldHours) * time.Hour, tableCap: o.SpendTable, headers: o.Headers, now: o.Now, access: o.Access}
	for _, c := range o.Crypts {
		s.crypts[c] = true
	}
	if s.priced == nil {
		s.priced = map[string]bool{}
	}
	s.clear()
	lines, err := s.journal.Load()
	if err != nil {
		return nil, err
	}
	for i := range lines {
		s.apply(&lines[i])
	}
	return s, nil
}

func (s *Service) clear() {
	s.rows = map[string]*row{}
	s.seen = map[string]seenCarrier{}
	s.tokenSeen = map[string]seenToken{}
	s.vaults = map[string]*vaultIdx{}
	s.vaultsByOrg = map[string]map[string]bool{}
	s.tokenVault = map[string]string{}
	s.carriers = map[string]*carrierEntry{}
	s.versions = map[string]map[uint64]map[string]bool{}
	s.sweeps = map[string]*sweepEntry{}
	s.sweepsByOp = map[string]map[string]bool{}
	s.table = list.New()
	s.tableAt = map[string]*list.Element{}
	s.spentSweeps = map[string]map[string]bool{}
	s.recentTurned = map[string]bool{}
	s.turnedOrder = nil
	s.reread = nil
	s.pending = map[string]pendingDelete{}
}

func (s *Service) unix() int64 { return s.now().Unix() }

// ---- gauges

// Counts are the gauges' values.
type Counts struct {
	Vaults, Tokens, PendingTokens, Carriers, Sweeps, Rows, Table, PendingDeletes int
}

// Counts reads the gauges.
func (s *Service) Counts() Counts {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := Counts{Vaults: len(s.vaults), Tokens: len(s.tokenVault), Carriers: len(s.carriers), Sweeps: len(s.sweeps), Rows: len(s.rows), Table: s.table.Len(), PendingDeletes: len(s.pending)}
	for _, v := range s.vaults {
		for _, t := range v.byTxid {
			if !t.rooted {
				c.PendingTokens++
			}
		}
	}
	return c
}

// ---- the journal, and the outpoint rows it rebuilds (spec section 11.2)

func (s *Service) rowOf(op string) *row {
	r := s.rows[op]
	if r == nil {
		r = &row{row: &secrec.OutpointRow{}, sweeps: map[string]spend{}, gone: map[string]bool{}}
		s.rows[op] = r
	}
	return r
}

func h32(hexs string) [32]byte {
	var out [32]byte
	b, _ := hex.DecodeString(hexs)
	copy(out[:], b)
	return out
}

// addRow records c on the row and returns the commitment the row stopped
// keeping, if any.
func addRow(r *secrec.OutpointRow, c [32]byte) ([32]byte, bool) {
	before := map[[32]byte]bool{}
	if r.Any {
		before[r.Winner] = true
	}
	for _, o := range r.Others {
		before[o] = true
	}
	if r.Any && before[c] {
		return [32]byte{}, false
	}
	r.Add(c)
	after := map[[32]byte]bool{r.Winner: true}
	for _, o := range r.Others {
		after[o] = true
	}
	if !after[c] {
		return c, true
	}
	for k := range before {
		if !after[k] {
			return k, true
		}
	}
	return [32]byte{}, false
}

func (s *Service) apply(l *Line) {
	switch l.K {
	case "c":
		r := s.rowOf(l.Op)
		out, gone := addRow(r.row, h32(l.C))
		s.seen[l.C] = seenCarrier{op: l.Op, crypt: l.Crypt, at: *l.At}
		if gone {
			s.unkept(hexOf(out))
		}
	case "m":
		s.rowOf(l.Op).row.More++
	case "d":
		r := s.rowOf(l.Op)
		r.gone[l.C] = true
		if *l.W {
			r.row.Dropped = true
		}
	case "s":
		r := s.rowOf(l.Op)
		if _, ok := r.sweeps[l.S]; !ok {
			r.sweeps[l.S] = spend{crypt: l.Crypt, h: *l.H, at: *l.At}
			r.order = append(r.order, l.S)
		}
		r.row.Swept = true
	case "t":
		if _, ok := s.tokenSeen[l.Txid]; !ok {
			s.tokenSeen[l.Txid] = seenToken{vout: uint32(*l.Vout), crypt: l.Crypt, at: *l.At} //nolint:gosec // validated non-negative
		}
	case "w":
		if s.spentSweeps[l.Txid] == nil {
			s.spentSweeps[l.Txid] = map[string]bool{}
		}
		s.spentSweeps[l.Txid][l.Crypt] = true
	}
}

func (s *Service) queueDelete(txid string, vout uint32, crypt string) {
	t := secrec.Topic(crypt)
	s.pending[fmt.Sprintf("%s|%s.%d", t, txid, vout)] = pendingDelete{txid: txid, vout: vout, topic: t}
}

func (s *Service) turnedAway(c string) {
	if s.recentTurned[c] {
		return
	}
	s.recentTurned[c] = true
	s.turnedOrder = append(s.turnedOrder, c)
	if len(s.turnedOrder) > RecentTurned {
		delete(s.recentTurned, s.turnedOrder[0])
		s.turnedOrder = s.turnedOrder[1:]
	}
}

// write appends a journal line and applies it. The time Append takes is
// spent under the service's lock (bsecret_journal_wait_seconds_total): the
// write, and the fsync too when the journal syncs every line.
func (s *Service) write(l Line) {
	start := time.Now()
	err := s.journal.Append(l)
	m := s.host.Metrics()
	m.Inc("bsecret_journal_wait_seconds_total", nil, time.Since(start).Seconds())
	m.Inc("bsecret_journal_lines_total", nil, 1)
	if err != nil {
		// A line that is not on disk is still applied: the host keeps
		// answering as it decided, and says so.
		s.host.Log("ls_bsecret could not write the journal", map[string]any{"err": err.Error()})
	}
	s.apply(&l)
}

// unkept is a commitment its row stopped keeping: its carrier leaves the
// index and storage, and its commitment goes with it.
func (s *Service) unkept(c string) {
	crypt := s.seen[c].crypt
	delete(s.seen, c)
	e := s.carriers[c]
	if e == nil {
		return
	}
	s.forgetCarrier(e)
	s.turnedAway(c)
	if crypt == "" {
		crypt = e.crypt
	}
	s.queueDelete(e.txid, 0, crypt)
	s.host.Metrics().Inc("bsecret_dropped_total", map[string]string{"why": "evidence"}, 1)
}

// OutpointRowView is the outpoint row of op as the contract describes it.
type OutpointRowView struct {
	Winner  string
	Others  []string
	More    uint64
	Dropped bool
	Sweeps  []string
}

// OutpointRow is the row of op, when the host has one.
func (s *Service) OutpointRow(op string) (OutpointRowView, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rows[op]
	if r == nil {
		return OutpointRowView{}, false
	}
	v := OutpointRowView{More: r.row.More, Dropped: r.row.Dropped, Sweeps: append([]string(nil), r.order...), Others: []string{}}
	if r.row.Any {
		v.Winner = hexOf(r.row.Winner)
	}
	for _, o := range r.row.Others {
		v.Others = append(v.Others, hexOf(o))
	}
	return v, true
}

// ---- the vault's chain (spec section 11.2)

func vaultKey(crypt, org, vault string) string { return crypt + "|" + org + "|" + vault }

func hashOf(display string) [32]byte {
	h, err := chainhash.NewHashFromHex(display)
	if err != nil {
		return [32]byte{}
	}
	return [32]byte(*h)
}

func outpoint(txid string, vout uint32) string { return fmt.Sprintf("%s.%d", txid, vout) }

func good(st string) bool { return st == secrec.StatusConsistent || st == secrec.StatusCommitmentReuse }

// descends is whether next descends from prev by a spend of its token
// output, under the transition rules (on what the index keeps).
func descends(prev, next *tokenEntry) bool {
	spent := 0
	for _, op := range next.inputs {
		if op == outpoint(prev.txid, prev.vout) {
			spent++
		}
	}
	if spent != 1 || next.prev != prev.txid || prev.seq+1 != next.seq {
		return false
	}
	return secrec.CheckVaultTransition(prev.rec, hashOf(prev.txid), next.rec) == nil
}

func newBranch() *branch {
	return &branch{fold: secrec.NewVaultFold(), listings: secrec.NewListings()}
}

// rebuild is the branch after t, folded again from seq 0: a second token on
// one predecessor begins a branch of its own.
func (s *Service) rebuild(v *vaultIdx, t *tokenEntry) *branch {
	var path []*tokenEntry
	for cur := t; cur != nil; {
		path = append(path, cur)
		if cur.seq == 0 {
			break
		}
		cur = v.byTxid[cur.prev]
	}
	b := newBranch()
	for i := len(path) - 1; i >= 0; i-- {
		s.fold(b, path[i])
	}
	return b
}

// fold folds t onto its branch and returns its status. A token that breaks
// the fold lists nothing, and nor does any after it.
func (s *Service) fold(b *branch, t *tokenEntry) string {
	st := b.fold.Apply(t.rec)
	if good(st) {
		b.listings.Apply(t.rec)
		b.good = t
		b.contexts = nil
	}
	return st
}

// rootFrom roots t if it descends from the vault's first token, and then
// every held token that descends from it.
func (s *Service) rootFrom(v *vaultIdx, t *tokenEntry, count bool) {
	work := []*tokenEntry{t}
	for len(work) > 0 {
		x := work[len(work)-1]
		work = work[:len(work)-1]
		if x.rooted {
			continue
		}
		var b *branch
		if x.seq == 0 {
			if !x.first {
				continue
			}
			b = newBranch()
		} else {
			p := v.byTxid[x.prev]
			if p == nil || !p.rooted || !descends(p, x) {
				continue
			}
			if held := v.branches[p.txid]; held != nil {
				delete(v.branches, p.txid)
				b = held
			} else {
				b = s.rebuild(v, p)
			}
		}
		x.rooted = true
		x.status = s.fold(b, x)
		v.branches[x.txid] = b
		if int64(x.seq) > v.top { //nolint:gosec // a seq is far below 2^63
			v.top = int64(x.seq) //nolint:gosec // a seq is far below 2^63
		}
		v.choice = nil
		if count {
			s.counted(v, x)
		}
		// Tokens a full seq turned away before this one was rooted are read again.
		for txid, vout := range v.turned[x.txid] {
			s.reread = append(s.reread, pendingDelete{txid: txid, vout: vout, topic: v.crypt})
		}
		delete(v.turned, x.txid)
		for c := range v.children[x.txid] {
			if child := v.byTxid[c]; child != nil {
				work = append(work, child)
			}
		}
	}
}

func (s *Service) counted(v *vaultIdx, t *tokenEntry) {
	s.host.Metrics().Inc("bsecret_token_status_total", map[string]string{"status": t.status}, 1)
	if t.status != secrec.StatusConsistent && t.status != secrec.StatusPending {
		s.host.Log("ls_bsecret token status", map[string]any{"crypt": v.crypt, "org": v.org, "vault": v.vault, "seq": t.seq, "txid": t.txid, "status": t.status})
	}
}

// reroot decides every token of the vault again: after one that others
// descend from left the index.
func (s *Service) reroot(v *vaultIdx) {
	v.branches = map[string]*branch{}
	v.top = -1
	v.choice = nil
	for _, t := range v.byTxid {
		t.rooted = false
		t.status = secrec.StatusPending
	}
	for _, t := range v.bySeq[0] {
		s.rootFrom(v, t, false)
	}
}

// bound holds a seq to its bound: rooted tokens before others, then the
// lowest txids.
func (s *Service) bound(v *vaultIdx, seq uint64) {
	at := v.bySeq[seq]
	if len(at) <= MaxPerSeq {
		return
	}
	order := append([]*tokenEntry(nil), at...)
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].rooted != order[j].rooted {
			return order[i].rooted
		}
		return order[i].txid < order[j].txid
	})
	again := false
	for _, t := range order[MaxPerSeq:] {
		s.host.Log("ls_bsecret kept no more tokens at this seq", map[string]any{"crypt": v.crypt, "vault": v.vault, "txid": t.txid, "seq": seq})
		again = again || t.rooted
		if !t.rooted && t.prev != "" {
			if v.turned[t.prev] == nil {
				v.turned[t.prev] = map[string]uint32{}
			}
			v.turned[t.prev][t.txid] = t.vout
		}
		s.forgetToken(v, t, false)
	}
	if again {
		s.reroot(v)
	}
}

// TokenStatus is the status of the token with txid (display order), when
// the host holds it.
func (s *Service) TokenStatus(txid string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.tokenVault[txid]
	if !ok {
		return "", false
	}
	t := s.vaults[key].byTxid[txid]
	if t == nil {
		return "", false
	}
	return t.status, true
}

// Rooted is whether the token with txid (display order) is rooted.
func (s *Service) Rooted(txid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.tokenVault[txid]
	if !ok {
		return false
	}
	t := s.vaults[key].byTxid[txid]
	return t != nil && t.rooted
}

// answerBranch is the branch an answer uses: that of the highest rooted
// token at or below which nothing broke the fold; of two at that seq, the
// one whose proof verifies against the host's headers, else the lowest
// txid.
func (s *Service) answerBranch(ctx context.Context, v *vaultIdx) *branch {
	if v == nil {
		return nil
	}
	var best []*branch
	for _, b := range v.branches {
		if b.good == nil {
			continue
		}
		switch {
		case len(best) == 0 || b.good.seq > best[0].good.seq:
			best = []*branch{b}
		case b.good.seq == best[0].good.seq:
			dup := false
			for _, x := range best {
				dup = dup || x.good == b.good
			}
			if !dup {
				best = append(best, b)
			}
		}
	}
	if len(best) == 0 {
		return nil
	}
	if len(best) == 1 {
		return best[0]
	}
	sort.Slice(best, func(i, j int) bool { return best[i].good.txid < best[j].good.txid })
	names := make([]string, len(best))
	for i, b := range best {
		names[i] = b.good.txid
	}
	among := strings.Join(names, ",")
	now := s.now()
	if v.choice != nil && v.choice.among == among && now.Sub(v.choice.at) < ChoiceTTL {
		for _, b := range best {
			if b.good.txid == v.choice.txid {
				return b
			}
		}
	}
	pick := best[0]
	if s.headers != nil {
		for _, b := range best {
			t := b.good
			if t.root == nil {
				continue
			}
			if ok, err := s.headers.IsValidRootForHeight(ctx, t.root, t.height); err == nil && ok {
				pick = b
				break
			}
		}
	}
	v.choice = &choice{among: among, txid: pick.good.txid, at: now}
	return pick
}

// ---- carrier statuses (spec section 11.2)

// Status is the status of the carrier with commitment c (hash byte order
// hex), when the host holds it.
func (s *Service) Status(ctx context.Context, c string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.carriers[c]
	if e == nil {
		return "", false
	}
	return s.statusOf(e, s.answerBranch(ctx, s.vaults[e.vkey])), true
}

func (s *Service) statusOf(e *carrierEntry, b *branch) string {
	if st := s.rows[e.op].row.Status(e.cb); st != "" {
		return st
	}
	if b == nil {
		return secrec.StatusUnlisted
	}
	return b.listings.Status(e.rec)
}

// Holds is whether the host holds the carrier with commitment c.
func (s *Service) Holds(c string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.carriers[c]
	return ok
}

// ---- admission

// AdmissionMode implements module.LookupService: the whole transaction,
// because a carrier's funding outpoint, a token's predecessor and a sweep's
// spends are its inputs.
func (*Service) AdmissionMode() bmodule.AdmissionMode { return bmodule.AdmitWholeTx }

// SpendNotificationMode implements module.LookupService: spends are read
// from admitted transactions, never from the engine's notices.
func (*Service) SpendNotificationMode() bmodule.SpendNotificationMode { return bmodule.SpendNone }

func (s *Service) cryptOf(topic string) (string, bool) {
	if !strings.HasPrefix(topic, secrec.TopicPrefix) {
		return "", false
	}
	c := topic[len(secrec.TopicPrefix):]
	return c, s.crypts[c]
}

// parse reads an Atomic BEEF as the engine hands or stores it: its subject
// transaction.
func parse(raw []byte) (*transaction.Transaction, error) {
	_, tx, _, err := guard.ParseBEEF(raw, guard.DefaultBound)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, errors.New("no subject transaction")
	}
	return tx, nil
}

// OutputAdmittedByTopic implements module.LookupService: it indexes an
// admitted output, then reads back tokens whose predecessor is rooted now
// and deletes what was dropped from storage.
func (s *Service) OutputAdmittedByTopic(ctx context.Context, p *bmodule.OutputAdmittedByTopic) error {
	if p.Mode != bmodule.AdmitWholeTx {
		return nil
	}
	crypt, ok := s.cryptOf(p.Topic)
	if !ok {
		return nil
	}
	tx, err := parse(p.AtomicBEEF)
	if err != nil {
		s.host.Log("ls_bsecret ignored an admission whose BEEF did not parse", map[string]any{"topic": p.Topic})
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.index(crypt, tx, p.Outpoint.Index, 0)
	s.enforceTable()
	s.drain(ctx)
	s.flush(ctx)
	return nil
}

// drain reads back, as the engine stores them, the tokens a full seq
// turned away whose predecessor has since been rooted.
func (s *Service) drain(ctx context.Context) {
	if s.storage == nil {
		return
	}
	for len(s.reread) > 0 {
		r := s.reread[0]
		s.reread = s.reread[1:]
		if _, held := s.tokenVault[r.txid]; held {
			continue
		}
		h, err := chainhash.NewHashFromHex(r.txid)
		if err != nil {
			continue
		}
		o, err := s.storage.FindOutput(ctx, &transaction.Outpoint{Txid: *h, Index: r.vout}, secrec.Topic(r.topic))
		if err != nil || o == nil || o.Beef == nil {
			continue
		}
		tx, err := parse(o.Beef)
		if err != nil {
			s.host.Log("ls_bsecret could not read a token again", map[string]any{"txid": r.txid, "err": err.Error()})
			continue
		}
		s.index(r.topic, tx, r.vout, o.Score)
	}
}

// OutputEvicted implements module.LookupService.
func (s *Service) OutputEvicted(_ context.Context, outpoint *transaction.Outpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forget(outpoint.Txid.String(), outpoint.Index, "")
	return nil
}

// OutputNoLongerRetainedInHistory implements module.RetentionListener.
func (s *Service) OutputNoLongerRetainedInHistory(_ context.Context, outpoint *transaction.Outpoint, topic string) error {
	crypt, ok := s.cryptOf(topic)
	if !ok {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forget(outpoint.Txid.String(), outpoint.Index, crypt)
	return nil
}

func srcTxid(in *transaction.TransactionInput) string {
	if in.SourceTXID != nil {
		return in.SourceTXID.String()
	}
	if in.SourceTransaction != nil {
		return in.SourceTransaction.TxID().String()
	}
	return ""
}

// index indexes output vout of an admitted transaction on crypt, writing
// its rows the first time it is seen. A carrier its row does not keep, or
// says was dropped, is not indexed, and its output is deleted. It returns
// whether it indexed.
func (s *Service) index(crypt string, tx *transaction.Transaction, vout uint32, score float64) bool {
	if int(vout) >= len(tx.Outputs) || tx.Outputs[vout] == nil || tx.Outputs[vout].LockingScript == nil {
		return false
	}
	// A held sweep whose tombstone this transaction spends leaves the
	// unspent rows storage hands a restore: the journal names it from now on.
	for _, in := range tx.Inputs {
		src := srcTxid(in)
		if src == "" || in.SourceTxOutIndex != 0 {
			continue
		}
		if sw := s.sweeps[src]; sw != nil && sw.crypts[crypt] && !s.spentSweeps[src][crypt] {
			s.write(Line{K: "w", Txid: src, Crypt: crypt})
		}
	}
	script := []byte(*tx.Outputs[vout].LockingScript)
	switch secrec.Classify(script) {
	case secrec.KindSecret:
		return s.indexCarrier(crypt, tx, script)
	case secrec.KindVault:
		return s.indexToken(crypt, tx, vout)
	}
	if vout == 0 && secrec.IsFundingShape(script) {
		return s.indexSweep(crypt, tx, score)
	}
	s.host.Log("ls_bsecret indexed an output of no known kind", map[string]any{"crypt": crypt, "txid": tx.TxID().String(), "vout": vout})
	return false
}

func (s *Service) indexCarrier(crypt string, tx *transaction.Transaction, script []byte) bool {
	if len(tx.Inputs) == 0 {
		return false
	}
	in := tx.Inputs[0]
	src := srcTxid(in)
	if src == "" {
		return false
	}
	op := outpoint(src, in.SourceTxOutIndex)
	txid := tx.TxID()
	cb := [32]byte(*txid)
	c := hexOf(cb)
	if _, held := s.carriers[c]; held {
		return true
	}
	rec, err := secrec.CarrierRecord(script)
	if err != nil {
		s.host.Log("ls_bsecret could not read a carrier", map[string]any{"crypt": crypt, "txid": txid.String(), "err": err.Error()})
		return false
	}
	if _, known := s.rows[op]; !known {
		// Spends seen before any carrier used the outpoint join its row.
		if el := s.tableAt[op]; el != nil {
			early := el.Value.(*tableEntry)
			s.table.Remove(el)
			delete(s.tableAt, op)
			for _, sid := range early.order {
				sp := early.spends[sid]
				s.write(Line{K: "s", Op: op, S: sid, Crypt: sp.crypt, H: i64(sp.h), At: i64(sp.at)})
				s.host.Metrics().Inc("bsecret_retractions_total", nil, 1)
			}
		}
	}
	r := s.rowOf(op)
	if !r.row.Any || (r.row.Winner != cb && !containsC(r.row.Others, cb)) {
		if !s.restoring && !s.recentTurned[c] && r.row.Any {
			s.host.Metrics().Inc("bsecret_equivocations_total", nil, 1)
		}
		// The row keeps the lowest nine ever admitted, so one it stopped
		// keeping is above its highest. A carrier below that is new to the
		// row, whatever else storage and the journal say: its line was lost.
		full := len(r.row.Others) >= secrec.MaxOthers
		takes := !full || lessC(cb, r.row.Others[secrec.MaxOthers-1])
		if !takes {
			// Counted once: not again for a repeat the engine lets through,
			// and not while restoring a row that already counts what it
			// turned away.
			if !s.recentTurned[c] && !(s.restoring && r.row.More > 0) {
				s.write(Line{K: "m", Op: op})
				s.host.Metrics().Inc("bsecret_dropped_total", map[string]string{"why": "evidence"}, 1)
			}
			s.turnedAway(c)
			s.queueDelete(txid.String(), 0, crypt)
			return false
		}
		s.write(Line{K: "c", Op: op, C: c, Crypt: crypt, At: i64(s.unix())})
	}
	if r.gone[c] {
		s.queueDelete(txid.String(), 0, crypt)
		return false
	}
	vkey := vaultKey(crypt, hex.EncodeToString(rec.Org), hexOf(rec.Vault))
	at := s.unix()
	if sc, ok := s.seen[c]; ok {
		at = sc.at
	}
	e := &carrierEntry{c: c, cb: cb, txid: txid.String(), crypt: crypt, vkey: vkey, id: hexOf(rec.ID), version: rec.Version, op: op, at: at, rec: rec}
	s.carriers[c] = e
	k := vkey + "|" + e.id
	if s.versions[k] == nil {
		s.versions[k] = map[uint64]map[string]bool{}
	}
	if s.versions[k][e.version] == nil {
		s.versions[k][e.version] = map[string]bool{}
	}
	s.versions[k][e.version][c] = true
	return true
}

func containsC(a [][32]byte, c [32]byte) bool {
	for _, x := range a {
		if x == c {
			return true
		}
	}
	return false
}

func lessC(a, b [32]byte) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func (s *Service) forgetCarrier(e *carrierEntry) {
	delete(s.carriers, e.c)
	k := e.vkey + "|" + e.id
	if byVersion := s.versions[k]; byVersion != nil {
		delete(byVersion[e.version], e.c)
		if len(byVersion[e.version]) == 0 {
			delete(byVersion, e.version)
		}
		if len(byVersion) == 0 {
			delete(s.versions, k)
		}
	}
}

// place is a proof's block height, the txid's position in its block, and
// the root the path gives.
func place(tx *transaction.Transaction) (uint32, uint64, *chainhash.Hash) {
	mp := tx.MerklePath
	if mp == nil {
		return 0, 0, nil
	}
	txid := tx.TxID()
	var offset uint64
	if len(mp.Path) > 0 {
		for _, l := range mp.Path[0] {
			if l != nil && l.Txid != nil && *l.Txid && l.Hash != nil && l.Hash.IsEqual(txid) {
				offset = l.Offset
			}
		}
	}
	root, err := mp.ComputeRoot(txid)
	if err != nil {
		root = nil
	}
	return mp.BlockHeight, offset, root
}

func (s *Service) indexToken(crypt string, tx *transaction.Transaction, vout uint32) bool {
	txid := tx.TxID().String()
	t, err := secrec.ReadToken(tx)
	if err != nil || t.Vout != vout || t.Vault.Crypt != crypt {
		s.host.Log("ls_bsecret could not read a token", map[string]any{"crypt": crypt, "txid": txid, "vout": vout})
		return false
	}
	rec := t.Vault
	org := hex.EncodeToString(rec.Org)
	vault := hexOf(rec.Vault)
	key := vaultKey(crypt, org, vault)
	v := s.vaults[key]
	if v == nil {
		v = &vaultIdx{key: key, crypt: crypt, org: org, vault: vault, bySeq: map[uint64][]*tokenEntry{}, byTxid: map[string]*tokenEntry{},
			children: map[string]map[string]bool{}, branches: map[string]*branch{}, top: -1, turned: map[string]map[string]uint32{}}
		s.vaults[key] = v
		ok := crypt + "|" + org
		if s.vaultsByOrg[ok] == nil {
			s.vaultsByOrg[ok] = map[string]bool{}
		}
		s.vaultsByOrg[ok][vault] = true
	}
	if _, ok := s.tokenSeen[txid]; !ok {
		s.write(Line{K: "t", Txid: txid, Vout: i64(int64(vout)), Crypt: crypt, At: i64(s.unix())})
	}
	if _, held := v.byTxid[txid]; held {
		return true
	}
	var inputs []string
	first := false
	for _, in := range tx.Inputs {
		src := srcTxid(in)
		if src == "" {
			continue
		}
		inputs = append(inputs, outpoint(src, in.SourceTxOutIndex))
		if rec.Seq == 0 && secrec.VaultID(hashOf(src), in.SourceTxOutIndex) == rec.Vault {
			first = true
		}
	}
	height, _, root := place(tx)
	prev := ""
	if rec.Seq != 0 {
		prev = chainhash.Hash(rec.Prev).String()
	}
	e := &tokenEntry{txid: txid, vout: vout, seq: rec.Seq, prev: prev, rec: rec, inputs: inputs, first: first, height: height, root: root, status: secrec.StatusPending}
	v.bySeq[rec.Seq] = append(v.bySeq[rec.Seq], e)
	sort.Slice(v.bySeq[rec.Seq], func(i, j int) bool { return v.bySeq[rec.Seq][i].txid < v.bySeq[rec.Seq][j].txid })
	v.byTxid[txid] = e
	s.tokenVault[txid] = key
	if prev != "" {
		if v.children[prev] == nil {
			v.children[prev] = map[string]bool{}
		}
		v.children[prev][txid] = true
	}
	if s.restoring {
		return true
	}
	s.rootFrom(v, e, true)
	if !e.rooted {
		s.counted(v, e)
	}
	s.bound(v, rec.Seq)
	_, kept := v.byTxid[txid]
	return kept
}

// forgetToken takes a token out of the index; reroot decides the rest again
// when others descended from it.
func (s *Service) forgetToken(v *vaultIdx, t *tokenEntry, reroot bool) {
	delete(v.byTxid, t.txid)
	delete(s.tokenVault, t.txid)
	list := v.bySeq[t.seq][:0:0]
	for _, x := range v.bySeq[t.seq] {
		if x.txid != t.txid {
			list = append(list, x)
		}
	}
	if len(list) == 0 {
		delete(v.bySeq, t.seq)
	} else {
		v.bySeq[t.seq] = list
	}
	if t.prev != "" {
		delete(v.children[t.prev], t.txid)
		if len(v.children[t.prev]) == 0 {
			delete(v.children, t.prev)
		}
	}
	if reroot && t.rooted {
		s.reroot(v)
	}
}

func (s *Service) indexSweep(crypt string, tx *transaction.Transaction, score float64) bool {
	txid := tx.TxID().String()
	e := s.sweeps[txid]
	if e == nil {
		height, offset, _ := place(tx)
		var spent []string
		for _, in := range tx.Inputs {
			src := srcTxid(in)
			if src == "" {
				continue
			}
			op := outpoint(src, in.SourceTxOutIndex)
			spent = append(spent, op)
			if r := s.rows[op]; r != nil {
				if _, ok := r.sweeps[txid]; !ok {
					s.write(Line{K: "s", Op: op, S: txid, Crypt: crypt, H: i64(int64(height)), At: i64(s.unix())})
					s.host.Metrics().Inc("bsecret_retractions_total", nil, 1)
				}
			} else {
				el := s.tableAt[op]
				if el == nil {
					el = s.table.PushBack(&tableEntry{op: op, spends: map[string]spend{}})
					s.tableAt[op] = el
				}
				te := el.Value.(*tableEntry)
				if _, ok := te.spends[txid]; !ok {
					te.spends[txid] = spend{crypt: crypt, h: int64(height), at: s.unix()}
					te.order = append(te.order, txid)
				}
			}
		}
		e = &sweepEntry{txid: txid, crypts: map[string]bool{}, spent: spent, height: height, offset: offset, score: score}
		s.sweeps[txid] = e
	}
	// The same mined sweep admitted in another crypt answers there too.
	if !e.crypts[crypt] {
		e.crypts[crypt] = true
		for _, op := range e.spent {
			k := crypt + "|" + op
			if s.sweepsByOp[k] == nil {
				s.sweepsByOp[k] = map[string]bool{}
			}
			s.sweepsByOp[k][txid] = true
		}
	}
	return true
}

// sweepLive is whether a held sweep still records a spend: a row's, or one
// in the table.
func (s *Service) sweepLive(e *sweepEntry) bool {
	for _, op := range e.spent {
		if r := s.rows[op]; r != nil {
			if _, ok := r.sweeps[e.txid]; ok {
				return true
			}
		}
		if el := s.tableAt[op]; el != nil {
			if _, ok := el.Value.(*tableEntry).spends[e.txid]; ok {
				return true
			}
		}
	}
	return false
}

// enforceTable keeps the table at its bound, oldest outpoint first. A sweep
// that then records no spend at all is dropped and deleted from storage.
func (s *Service) enforceTable() {
	for s.table.Len() > s.tableCap {
		el := s.table.Front()
		te := el.Value.(*tableEntry)
		s.table.Remove(el)
		delete(s.tableAt, te.op)
		for _, sid := range te.order {
			e := s.sweeps[sid]
			if e == nil || s.sweepLive(e) {
				continue
			}
			for c := range e.crypts {
				s.queueDelete(sid, 0, c)
			}
			s.forget(sid, 0, "")
			s.host.Metrics().Inc("bsecret_dropped_total", map[string]string{"why": "table"}, 1)
		}
	}
}

// forget removes a held output from the index, in one crypt or in all; its
// rows stay.
func (s *Service) forget(txid string, vout uint32, crypt string) {
	if vout == 0 {
		if e := s.carriers[hexOf(hashOf(txid))]; e != nil && (crypt == "" || e.crypt == crypt) {
			s.forgetCarrier(e)
		}
		if sw := s.sweeps[txid]; sw != nil {
			var crypts []string
			if crypt == "" {
				for c := range sw.crypts {
					crypts = append(crypts, c)
				}
			} else {
				crypts = []string{crypt}
			}
			for _, c := range crypts {
				if !sw.crypts[c] {
					continue
				}
				delete(sw.crypts, c)
				for _, op := range sw.spent {
					k := c + "|" + op
					delete(s.sweepsByOp[k], txid)
					if len(s.sweepsByOp[k]) == 0 {
						delete(s.sweepsByOp, k)
					}
				}
			}
			if len(sw.crypts) == 0 {
				delete(s.sweeps, txid)
			}
		}
	}
	if key, ok := s.tokenVault[txid]; ok {
		v := s.vaults[key]
		if t := v.byTxid[txid]; t != nil && t.vout == vout && (crypt == "" || v.crypt == crypt) {
			s.forgetToken(v, t, true)
		}
	}
}

// ---- drops and retention (spec section 11.3)

// drop drops a held carrier: marks its row, takes it out of every answer,
// and queues its output for deletion.
func (s *Service) drop(e *carrierEntry, why string) {
	r := s.rows[e.op]
	winner := r.row.Any && r.row.Winner == e.cb
	s.write(Line{K: "d", Op: e.op, C: e.c, W: boolp(winner)})
	s.forgetCarrier(e)
	s.queueDelete(e.txid, 0, e.crypt)
	s.host.Metrics().Inc("bsecret_dropped_total", map[string]string{"why": why}, 1)
	s.host.Log("ls_bsecret dropped a carrier", map[string]any{"txid": e.txid, "outpoint": e.op, "why": why, "winner": winner})
}

// Prune applies retention at the host's time and deletes what was dropped
// from storage. Kept for the host's life: tokens, outpoint rows and the
// sweeps they record. A listed carrier is kept while the answered set
// holds its version, and for the retention period after the host first
// saw the token that replaced or retired it. Any other carrier is kept for
// the retention period after the host first saw it (after the sweep, for a
// retracted one) where the host holds the vault's rooted chain, and for
// the shorter period where it does not. Dropping an outpoint's winner
// closes the outpoint: nothing on it is answered again. It returns how
// many carriers were dropped.
func (s *Service) Prune(ctx context.Context) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.unix()
	n := 0
	branches := map[string]*branch{}
	have := map[string]bool{}
	paths := map[*branch]map[uint64]string{}
	entries := make([]*carrierEntry, 0, len(s.carriers))
	for _, e := range s.carriers {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].txid < entries[j].txid })
	for _, e := range entries {
		r := s.rows[e.op]
		v := s.vaults[e.vkey]
		if !have[e.vkey] {
			branches[e.vkey] = s.answerBranch(ctx, v)
			have[e.vkey] = true
		}
		b := branches[e.vkey]
		st := s.statusOf(e, b)
		from := e.at
		period := s.unheld
		if v != nil && v.top >= 0 {
			period = s.retention
		}
		switch {
		case st == secrec.StatusRetracted:
			earliest := int64(-1)
			for _, sp := range r.sweeps {
				if earliest < 0 || sp.at < earliest {
					earliest = sp.at
				}
			}
			if earliest >= 0 && earliest > from {
				from = earliest
			}
		case st == secrec.StatusListed && b != nil && v != nil:
			if cur, ok := b.fold.Current(h32(e.id)); ok && cur.Version == e.version {
				continue
			}
			if seq, ok := b.fold.EndedAt(h32(e.id), e.version); ok {
				path := paths[b]
				if path == nil {
					path = map[uint64]string{}
					paths[b] = path
					for t := b.good; t != nil; {
						path[t.seq] = t.txid
						if t.seq == 0 {
							break
						}
						t = v.byTxid[t.prev]
					}
				}
				at := now
				if ts, ok := s.tokenSeen[path[seq]]; ok {
					at = ts.at
				}
				if at > from {
					from = at
				}
			}
		}
		if time.Duration(now-from)*time.Second >= period {
			s.drop(e, "retention")
			n++
		}
	}
	s.flush(ctx)
	return n
}

// flush deletes dropped outputs from storage. It runs after every admission
// and after retention, so a dropped output is gone at once. A store that
// cannot delete keeps what was dropped; the queue is not kept for it.
func (s *Service) flush(ctx context.Context) {
	if s.storage == nil || len(s.pending) == 0 {
		return
	}
	del, ok := s.storage.(Deleter)
	if !ok {
		if !s.warnedNoDelete {
			s.host.Log("ls_bsecret cannot delete dropped outputs: the storage has no DeleteOutput", nil)
		}
		s.warnedNoDelete = true
		s.pending = map[string]pendingDelete{}
		return
	}
	keys := make([]string, 0, len(s.pending))
	for k := range s.pending {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := s.pending[k]
		h, err := chainhash.NewHashFromHex(p.txid)
		if err != nil {
			delete(s.pending, k)
			continue
		}
		if err := del.DeleteOutput(ctx, &transaction.Outpoint{Txid: *h, Index: p.vout}, p.topic); err != nil {
			s.host.Log("ls_bsecret could not delete a dropped output", map[string]any{"txid": p.txid, "err": err.Error()})
			continue
		}
		delete(s.pending, k)
	}
}

// Restored is whether the index was rebuilt from storage.
func (s *Service) Restored() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.storage != nil
}

// GetDocumentation implements module.LookupService.
func (*Service) GetDocumentation() string {
	return strings.Join([]string{
		"# ls_bsecret",
		"",
		"Answers every crypt this host carries (spec section 10.2). Free classes: `vault`",
		"(a vault's latest rooted tokens), `vault-seq` (every token held at one seq),",
		"`vaults`, `vaults-after` (the latest rooted token of each of an owner's vaults),",
		"`secret` (the carriers of the version the set holds, each with its inclusion",
		"path as context), `version`, `pending`, `secrets`, `secrets-after`, `label`,",
		"`label-after` (the set, 16 carriers a page, each with its path) and `sweep`",
		"(sweeps spending an outpoint). Priceable: `history`, `history-after` (every",
		"version of a secret) and `audit`, `audit-after` (every token of a vault's",
		"chain, by seq). A question must carry exactly the members of one class;",
		"anything else is refused with an error. An empty answer means only that this",
		"host holds nothing that answers.",
	}, "\n")
}

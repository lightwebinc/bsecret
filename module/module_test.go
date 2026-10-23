package module

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/lightwebinc/bcommon/guard"
	bmodule "github.com/lightwebinc/bcommon/module"
	"github.com/lightwebinc/bcommon/termsroute"

	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/vectors"
)

const dir = "../testdata/vectors"

// fakeHost records what the module counts and logs.
type fakeHost struct {
	mu       sync.Mutex
	counters map[string]float64
	gauges   map[string]func() float64
	lines    []string
}

func newFakeHost() *fakeHost {
	return &fakeHost{counters: map[string]float64{}, gauges: map[string]func() float64{}}
}

func mkey(name string, labels map[string]string) string {
	ks := make([]string, 0, len(labels))
	for k := range labels {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	parts := make([]string, 0, len(ks))
	for _, k := range ks {
		parts = append(parts, fmt.Sprintf("%s=%q", k, labels[k]))
	}
	if len(parts) == 0 {
		return name
	}
	return name + "{" + strings.Join(parts, ",") + "}"
}

func (h *fakeHost) Log(msg string, _ map[string]any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lines = append(h.lines, msg)
}
func (h *fakeHost) Metrics() bmodule.Metrics { return h }
func (h *fakeHost) Inc(name string, labels map[string]string, by float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.counters[mkey(name, labels)] += by
}
func (h *fakeHost) Preset(name string, labels map[string]string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.counters[mkey(name, labels)]; !ok {
		h.counters[mkey(name, labels)] = 0
	}
}
func (h *fakeHost) Gauge(name string, fn func() float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.gauges[name] = fn
}
func (h *fakeHost) count(name string, labels map[string]string) float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.counters[mkey(name, labels)]
}

// txFile is transaction-v1.json as the tests read it.
type txFile struct {
	Crypt          string `json:"crypt"`
	Topic          string `json:"topic"`
	MaxBEEF        int    `json:"maxBeef"`
	MaxSweepInputs int    `json:"maxSweepInputs"`
	Vault          string `json:"vault"`
	Headers        []struct {
		Height     uint32 `json:"height"`
		MerkleRoot string `json:"merkleRoot"`
	} `json:"headers"`
	Cases []struct {
		Name  string `json:"name"`
		Txid  string `json:"txid"`
		BEEF  string `json:"beef"`
		Coins []struct {
			InputIndex int `json:"inputIndex"`
		} `json:"previousCoins"`
		MaxSweepInputs int    `json:"maxSweepInputs"`
		Verdict        string `json:"verdict"`
		Reason         string `json:"reason"`
		Admits         *struct {
			Kind           string   `json:"kind"`
			OutputsToAdmit []uint32 `json:"outputsToAdmit"`
			CoinsToRetain  []uint32 `json:"coinsToRetain"`
			Record         string   `json:"record"`
			Spent          []string `json:"spent"`
		} `json:"admits"`
	} `json:"cases"`
	Stored []struct {
		Name   string `json:"name"`
		Txid   string `json:"txid"`
		Stored string `json:"stored"`
		Seq    uint64 `json:"seq"`
	} `json:"stored"`
}

func readTx(t *testing.T) (*txFile, vectors.Headers) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "transaction-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f txFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	h := vectors.Headers{}
	for _, x := range f.Headers {
		r, err := chainhash.NewHashFromHex(x.MerkleRoot)
		if err != nil {
			t.Fatal(err)
		}
		h[x.Height] = *r
	}
	return &f, h
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// atomicOf is raw as an Atomic BEEF of its subject.
func atomicOf(t *testing.T, raw []byte) []byte {
	t.Helper()
	if len(raw) >= 4 && raw[0] == 1 && raw[1] == 1 && raw[2] == 1 && raw[3] == 1 {
		return raw
	}
	_, tx, txid, err := guard.ParseBEEF(raw, guard.DefaultBound)
	if err != nil || tx == nil || txid == nil {
		t.Fatalf("not a BEEF: %v", err)
	}
	out := append([]byte{1, 1, 1, 1}, txid[:]...)
	return append(out, raw...)
}

// memStorage is an in-memory engine storage with the engine's admission
// seam beside it: submit runs the topic manager over the previous coins,
// marks spent, inserts outputs with their BEEF and notifies the service.
type memStorage struct {
	mu      sync.Mutex
	outputs map[string]*bmodule.Output
	applied map[string]bool
	score   float64
}

func newMemStorage() *memStorage {
	return &memStorage{outputs: map[string]*bmodule.Output{}, applied: map[string]bool{}}
}

func skey(topic string, op *transaction.Outpoint) string { return topic + "|" + op.String() }

func (m *memStorage) FindOutput(_ context.Context, op *transaction.Outpoint, topic string) (*bmodule.Output, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.outputs {
		if o.Outpoint == *op && (topic == "" || o.Topic == topic) {
			c := *o
			return &c, nil
		}
	}
	return nil, nil
}

func (m *memStorage) DeleteOutput(_ context.Context, op *transaction.Outpoint, topic string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.outputs, skey(topic, op))
	return nil
}

// utxos are the unspent rows of topic, in insertion order.
func (m *memStorage) utxos(topic string, beef bool) []bmodule.Output {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []bmodule.Output
	for _, o := range m.outputs {
		if o.Topic == topic && !o.Spent {
			c := *o
			if !beef {
				c.Beef = nil
			}
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Score < out[j].Score })
	return out
}

func (m *memStorage) has(txid string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.outputs {
		if o.Outpoint.Txid.String() == txid {
			return true
		}
	}
	return false
}

// rig is the module over the stand-in storage.
type rig struct {
	t       *testing.T
	host    *fakeHost
	m       *Mounted
	ls      *Service
	tm      *TopicManager
	storage *memStorage
	journal *MemoryJournal
	topic   string
	crypt   string
}

func setup(t *testing.T, f *txFile, h vectors.Headers, journal *MemoryJournal, now func() time.Time) *rig {
	t.Helper()
	host := newFakeHost()
	if journal == nil {
		journal = &MemoryJournal{}
	}
	c := &Config{Crypts: []string{f.Crypt}, StateDir: "/nonexistent", HeadersURL: "http://127.0.0.1:1", RetentionDays: FloorDays, UnheldHours: FloorUnheldHours,
		MaxBEEF: f.MaxBEEF, MaxSweepInputs: f.MaxSweepInputs, SpendTable: MinSpendTable, Prices: map[string]uint64{}}
	m, err := Mount(host, c, []string{f.Topic}, journal, h, now)
	if err != nil {
		t.Fatal(err)
	}
	st := newMemStorage()
	r := &rig{t: t, host: host, m: m, ls: m.LS, tm: m.Module.Topics[f.Topic].(*TopicManager), storage: st, journal: journal, topic: f.Topic, crypt: f.Crypt}
	if _, err := m.LS.Restore(context.Background(), nil, st); err != nil {
		t.Fatal(err)
	}
	return r
}

// submit is the engine's admission path: the outputs admitted, or an error
// when the manager refused.
func (r *rig) submit(raw []byte) ([]uint32, error) {
	ctx := bmodule.WithSubmission(context.Background(), raw)
	beef, tx, txid, err := guard.ParseBEEF(raw, guard.DefaultBound)
	if err != nil || tx == nil {
		return nil, fmt.Errorf("the engine refused the BEEF: %v", err)
	}
	st := r.storage
	st.mu.Lock()
	if st.applied[r.topic+"|"+txid.String()] {
		st.mu.Unlock()
		return []uint32{}, nil
	}
	var coins []uint32
	held := map[uint32]*bmodule.Output{}
	for i, in := range tx.Inputs {
		for _, o := range st.outputs {
			if o.Topic == r.topic && o.Outpoint.Txid == *in.SourceTXID && o.Outpoint.Index == in.SourceTxOutIndex {
				coins = append(coins, uint32(i)) //nolint:gosec // test
				held[uint32(i)] = o              //nolint:gosec // test
			}
		}
	}
	st.mu.Unlock()
	ai, err := r.tm.IdentifyAdmissibleOutputs(ctx, beef, txid, coins)
	if err != nil {
		return nil, err
	}
	atomic, err := beef.AtomicBytes(txid)
	if err != nil {
		return nil, err
	}
	st.mu.Lock()
	retain := map[uint32]bool{}
	for _, c := range ai.CoinsToRetain {
		retain[c] = true
	}
	for vin, o := range held {
		if retain[vin] {
			o.Spent = true
			o.ConsumedBy = append(o.ConsumedBy, &transaction.Outpoint{Txid: *txid, Index: 0})
		} else {
			delete(st.outputs, skey(r.topic, &o.Outpoint))
		}
	}
	for _, vout := range ai.OutputsToAdmit {
		st.score++
		op := transaction.Outpoint{Txid: *txid, Index: vout}
		st.outputs[skey(r.topic, &op)] = &bmodule.Output{Outpoint: op, Topic: r.topic, Beef: atomic, Score: st.score, OutputScript: tx.Outputs[vout].LockingScript, Satoshis: tx.Outputs[vout].Satoshis}
	}
	st.applied[r.topic+"|"+txid.String()] = true
	st.mu.Unlock()
	for _, vout := range ai.OutputsToAdmit {
		if err := r.ls.OutputAdmittedByTopic(ctx, &bmodule.OutputAdmittedByTopic{Mode: bmodule.AdmitWholeTx, Outpoint: transaction.Outpoint{Txid: *txid, Index: vout}, Topic: r.topic, AtomicBEEF: atomic}); err != nil {
			return nil, err
		}
	}
	if ai.OutputsToAdmit == nil {
		return []uint32{}, nil
	}
	return ai.OutputsToAdmit, nil
}

// answered is the txids an engine lookup answers, with each output's
// context and transaction.
type answered struct {
	txid    string
	context []byte
	tx      *transaction.Transaction
}

func (r *rig) outputs(q map[string]string) ([]answered, error) {
	raw, _ := json.Marshal(q)
	a, err := r.ls.Lookup(context.Background(), &lookup.LookupQuestion{Service: secrec.LookupService, Query: raw})
	if err != nil {
		return nil, err
	}
	outs, ok := a.Result.([]bmodule.HydratedOutput)
	if !ok || len(outs) != len(a.Outputs) {
		return nil, errors.New("the answer carries no hydrated outputs")
	}
	var out []answered
	for _, o := range outs {
		_, tx, _, err := guard.ParseBEEF(o.Beef, guard.DefaultBound)
		if err != nil || tx == nil {
			return nil, fmt.Errorf("an answered BEEF does not parse: %v", err)
		}
		out = append(out, answered{txid: tx.TxID().String(), context: o.Context, tx: tx})
	}
	return out, nil
}

func (r *rig) answer(q map[string]string) []string {
	r.t.Helper()
	outs, err := r.outputs(q)
	if err != nil {
		r.t.Fatalf("%v: %v", q, err)
	}
	ids := []string{}
	for _, o := range outs {
		ids = append(ids, o.txid)
	}
	return ids
}

func want(t *testing.T, what string, got, want []string) {
	t.Helper()
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if string(g) != string(w) {
		t.Errorf("%s: %s, want %s", what, g, w)
	}
}

func sortedCopy(a []string) []string {
	out := append([]string(nil), a...)
	sort.Strings(out)
	return out
}

// TestTransactionVectorsThroughTheManager admits or refuses every vector
// through the topic manager exactly as the vectors say, raising, and
// counts each admission once.
func TestTransactionVectorsThroughTheManager(t *testing.T) {
	f, h := readTx(t)
	host := newFakeHost()
	managers := map[int]*TopicManager{}
	admitted, refused := 0, 0
	distinct := map[string]map[string]bool{}
	refusedBy := map[string]int{}
	for _, c := range f.Cases {
		bound := c.MaxSweepInputs
		if bound == 0 {
			bound = f.MaxSweepInputs
		}
		tm := managers[bound]
		if tm == nil {
			var err error
			if tm, err = NewTopicManager(f.Topic, host, h, f.MaxBEEF, bound); err != nil {
				t.Fatal(err)
			}
			managers[bound] = tm
		}
		held := []int{}
		for _, coin := range c.Coins {
			held = append(held, coin.InputIndex)
		}
		ai, err := tm.Admit(context.Background(), unhex(t, c.BEEF), held)
		if c.Verdict == "admit" {
			if err != nil {
				t.Errorf("%s: refused: %v", c.Name, err)
				continue
			}
			got, _ := json.Marshal(map[string]any{"o": ai.OutputsToAdmit, "c": ai.CoinsToRetain})
			w, _ := json.Marshal(map[string]any{"o": c.Admits.OutputsToAdmit, "c": c.Admits.CoinsToRetain})
			if string(got) != string(w) {
				t.Errorf("%s: %s, want %s", c.Name, got, w)
			}
			admitted++
			k := fmt.Sprintf("%d|%s", bound, c.Admits.Kind)
			if distinct[k] == nil {
				distinct[k] = map[string]bool{}
			}
			distinct[k][c.Txid] = true
			continue
		}
		var rf *Refused
		if !errors.As(err, &rf) || rf.Reason != c.Reason {
			t.Errorf("%s: %v, want %s", c.Name, err, c.Reason)
			continue
		}
		refused++
		refusedBy[c.Reason]++
	}
	if len(f.Cases) != 139 || admitted != 21 || refused != 118 {
		t.Errorf("%d cases, %d admitted, %d refused", len(f.Cases), admitted, refused)
	}
	for _, kind := range AdmitKinds {
		wantN, all := 0, 0
		for k, s := range distinct {
			if strings.HasSuffix(k, "|"+kind) {
				wantN += len(s)
			}
		}
		for _, c := range f.Cases {
			if c.Verdict == "admit" && c.Admits.Kind == kind {
				all++
			}
		}
		if got := host.count("bsecret_admitted_total", map[string]string{"kind": kind}); got != float64(wantN) {
			t.Errorf("%s: %v admitted, want %d", kind, got, wantN)
		}
		if got := host.count("bsecret_admitted_repeats_total", map[string]string{"kind": kind}); got != float64(all-wantN) {
			t.Errorf("%s: %v repeats, want %d", kind, got, all-wantN)
		}
	}
	if host.count("bsecret_admitted_total", map[string]string{"kind": "secret"}) != 8 || host.count("bsecret_admitted_total", map[string]string{"kind": "vault-token"}) != 7 || host.count("bsecret_admitted_total", map[string]string{"kind": "sweep"}) != 3 {
		t.Error("distinct admissions")
	}
	for reason, n := range refusedBy {
		if got := host.count("bsecret_refused_total", map[string]string{"reason": reason}); got != float64(n) {
			t.Errorf("%s: %v refused, want %d", reason, got, n)
		}
	}
	if host.count("bsecret_refused_total", map[string]string{"reason": "beef"}) != 19 {
		t.Error("beef refusals")
	}
	// Without the submission's bytes the manager refuses the host, not the object.
	tm := managers[f.MaxSweepInputs]
	if _, err := tm.IdentifyAdmissibleOutputs(context.Background(), nil, nil, nil); !errors.Is(err, ErrNoSubmission) {
		t.Errorf("no submission: %v", err)
	}
}

// TestIndexRooted roots the same tokens as the Go codec says, in the order
// given and the reverse, through the service alone.
func TestIndexRooted(t *testing.T) {
	f, _ := readTx(t)
	b, err := os.ReadFile(filepath.Join(dir, "index-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var index struct {
		Rooted []struct {
			Label  string   `json:"label"`
			Held   []string `json:"held"`
			Rooted []string `json:"rooted"`
		} `json:"rooted"`
	}
	if err := json.Unmarshal(b, &index); err != nil {
		t.Fatal(err)
	}
	named := func(label string) (string, []byte) {
		var seq int
		if n, _ := fmt.Sscanf(label, "seq %d", &seq); n == 1 && label == fmt.Sprintf("seq %d", seq) && seq < len(f.Stored) {
			s := f.Stored[seq]
			return s.Txid, atomicOf(t, unhex(t, s.Stored))
		}
		name := "vault-token-on-unadmitted-parent"
		if label == "second vault seq 0" {
			name = "vault-token-second-vault"
		}
		for _, c := range f.Cases {
			if c.Name == name {
				return c.Txid, atomicOf(t, unhex(t, c.BEEF))
			}
		}
		t.Fatalf("no case %s", name)
		return "", nil
	}
	if len(index.Rooted) != 5 {
		t.Fatalf("%d rooted cases", len(index.Rooted))
	}
	for _, c := range index.Rooted {
		orders := [][]string{c.Held, nil}
		for i := len(c.Held) - 1; i >= 0; i-- {
			orders[1] = append(orders[1], c.Held[i])
		}
		for _, order := range orders {
			ls, err := NewService(Options{Crypts: []string{f.Crypt}, Host: newFakeHost()})
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, label := range order {
				txid, beef := named(label)
				h, _ := chainhash.NewHashFromHex(txid)
				if err := ls.OutputAdmittedByTopic(context.Background(), &bmodule.OutputAdmittedByTopic{Mode: bmodule.AdmitWholeTx, Outpoint: transaction.Outpoint{Txid: *h}, Topic: f.Topic, AtomicBEEF: beef}); err != nil {
					t.Fatal(err)
				}
			}
			for _, label := range order {
				txid, _ := named(label)
				if ls.Rooted(txid) {
					got = append(got, txid)
				}
			}
			var w []string
			for _, label := range c.Rooted {
				txid, _ := named(label)
				w = append(w, txid)
			}
			want(t, c.Label, sortedCopy(got), sortedCopy(w))
		}
	}
}

// vectorRig admits every transaction vector through the engine's path.
func vectorRig(t *testing.T, journal *MemoryJournal, now func() time.Time) (*rig, *txFile) {
	t.Helper()
	f, h := readTx(t)
	r := setup(t, f, h, journal, now)
	for _, c := range f.Cases {
		_, err := r.submit(unhex(t, c.BEEF))
		if c.Verdict == "admit" {
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			if !r.storage.has(c.Txid) {
				t.Fatalf("%s: not applied", c.Name)
			}
		}
	}
	return r, f
}

func (f *txFile) id(name string) string {
	for _, c := range f.Cases {
		if c.Name == name {
			return c.Txid
		}
	}
	return "no such case: " + name
}

func (f *txFile) admits(t *testing.T, name string) (record string, spent []string) {
	t.Helper()
	for _, c := range f.Cases {
		if c.Name == name && c.Admits != nil {
			return c.Admits.Record, c.Admits.Spent
		}
	}
	t.Fatalf("no admitted case %s", name)
	return "", nil
}

func sid(t *testing.T, vault, name string) string {
	t.Helper()
	id, err := secrec.SecretID(h32(vault), name)
	if err != nil {
		t.Fatal(err)
	}
	return hexOf(id)
}

// TestVectorsThroughTheEngine admits every vector as the engine admits
// them, then holds the index to index-v1.json and answers every class as
// the TypeScript module does.
func TestVectorsThroughTheEngine(t *testing.T) {
	r, f := vectorRig(t, nil, nil)
	ctx := context.Background()
	b, _ := os.ReadFile(filepath.Join(dir, "index-v1.json"))
	var index struct {
		Carriers []struct {
			Label      string `json:"label"`
			Commitment string `json:"commitment"`
			Status     string `json:"status"`
		} `json:"carriers"`
		Chain []struct {
			Txid   string `json:"txid"`
			Status string `json:"status"`
		} `json:"chain"`
		Outpoints []struct {
			Outpoint string   `json:"outpoint"`
			Winner   string   `json:"winner"`
			Others   []string `json:"others"`
			More     uint64   `json:"more"`
			Dropped  bool     `json:"dropped"`
			Swept    bool     `json:"swept"`
		} `json:"outpoints"`
	}
	if err := json.Unmarshal(b, &index); err != nil {
		t.Fatal(err)
	}
	for _, c := range index.Chain {
		st, _ := r.ls.TokenStatus(c.Txid)
		if st != c.Status || !r.ls.Rooted(c.Txid) {
			t.Errorf("%s: %s rooted %v", c.Txid, st, r.ls.Rooted(c.Txid))
		}
	}
	checked := 0
	for _, k := range index.Carriers {
		if !r.ls.Holds(k.Commitment) {
			continue
		}
		if st, _ := r.ls.Status(ctx, k.Commitment); st != k.Status {
			t.Errorf("%s: %s, want %s", k.Label, st, k.Status)
		}
		checked++
	}
	if checked != 8 {
		t.Errorf("%d carriers checked", checked)
	}
	for _, o := range index.Outpoints {
		row, ok := r.ls.OutpointRow(o.Outpoint)
		if !ok {
			continue
		}
		others := o.Others
		if others == nil {
			others = []string{}
		}
		if row.Winner != o.Winner || strings.Join(row.Others, ",") != strings.Join(others, ",") || row.More != o.More || row.Dropped != o.Dropped || (len(row.Sweeps) > 0) != o.Swept {
			t.Errorf("row %s: %+v", o.Outpoint, row)
		}
	}
	unadmitted := f.id("vault-token-on-unadmitted-parent")
	if st, _ := r.ls.TokenStatus(unadmitted); st != "pending" || r.ls.Rooted(unadmitted) {
		t.Error("the token on the unadmitted parent")
	}
	if r.host.count("bsecret_token_status_total", map[string]string{"status": "consistent"}) != 6 || r.host.count("bsecret_token_status_total", map[string]string{"status": "pending"}) != 1 || r.host.gauges["bsecret_tokens_pending"]() != 1 {
		t.Error("token status counts")
	}

	crypt, org, vault := f.Crypt, "", f.Vault
	secondRec, _ := f.admits(t, "vault-token-second-vault")
	sv, err := secrec.DecodeVault(unhex(t, secondRec))
	if err != nil {
		t.Fatal(err)
	}
	org = hex.EncodeToString(sv.Org)
	tip := sortedCopy([]string{f.id("vault-token-settle"), f.id("vault-token-spends-parent-change-too")})
	q := func(extra ...string) map[string]string {
		m := map[string]string{"crypt": crypt, "org": org, "vault": vault}
		for i := 0; i+1 < len(extra); i += 2 {
			m[extra[i]] = extra[i+1]
		}
		return m
	}
	want(t, "vault", r.answer(q()), tip)
	want(t, "seq 0", r.answer(q("seq", "0")), []string{f.id("vault-token-create")})
	want(t, "seq 8", r.answer(q("seq", "8")), []string{unadmitted})
	second := hexOf(sv.Vault)
	both := sortedCopy([]string{second, vault})
	latestOf := func(v string) []string {
		if v == second {
			return []string{f.id("vault-token-second-vault")}
		}
		return tip
	}
	want(t, "vaults", r.answer(map[string]string{"crypt": crypt, "vaultsOf": org}), append(append([]string{}, latestOf(both[0])...), latestOf(both[1])...))
	want(t, "vaults-after", r.answer(map[string]string{"crypt": crypt, "vaultsOf": org, "after": both[0]}), latestOf(both[1]))
	want(t, "vaults-after end", r.answer(map[string]string{"crypt": crypt, "vaultsOf": org, "after": both[1]}), []string{})

	// secret: the version the set holds, with a context a reader's first check accepts.
	api, err := r.outputs(q("secret", sid(t, vault, "tx/api-token")))
	if err != nil || len(api) != 1 || api[0].txid != f.id("secret-carrier-api-token-v3") {
		t.Fatalf("secret: %v %v", api, err)
	}
	cx, err := secrec.DecodeContext(api[0].context)
	if err != nil || cx.Seq != 3 || chainhash.Hash(cx.Token).String() != tip[0] || cx.Size != 2 {
		t.Fatalf("context: %+v %v", cx, err)
	}
	latestRec, _ := f.admits(t, "vault-token-settle")
	latest, _ := secrec.DecodeVault(unhex(t, latestRec))
	rec, err := secrec.CarrierRecord(*api[0].tx.Outputs[0].LockingScript)
	if err != nil {
		t.Fatal(err)
	}
	if err := secrec.CheckInSet(latest, hashOf(tip[0]), rec, cx); err != nil {
		t.Errorf("in set: %v", err)
	}
	want(t, "retired", r.answer(q("secret", sid(t, vault, "tx/tls-key"))), []string{})
	want(t, "never listed", r.answer(q("secret", sid(t, vault, "tx/ssh-key"))), []string{})

	apiV1 := sortedCopy([]string{f.id("secret-carrier-api-token-v1"), f.id("carrier-locktime-max")})[0]
	want(t, "version winner", r.answer(q("secret", sid(t, vault, "tx/api-token"), "version", "1")), []string{apiV1})
	want(t, "version swept", r.answer(q("secret", sid(t, vault, "tx/db-password"), "version", "1")), []string{})
	want(t, "version retired", r.answer(q("secret", sid(t, vault, "tx/tls-key"), "version", "1")), []string{f.id("secret-carrier-tls-key-v1")})
	want(t, "version unlisted", r.answer(q("secret", sid(t, vault, "tx/ssh-key"), "version", "1")), []string{f.id("secret-carrier-ssh-key-v1")})
	want(t, "pending", r.answer(q("pending", sid(t, vault, "tx/ssh-key"))), []string{f.id("secret-carrier-ssh-key-v1")})
	want(t, "pending none", r.answer(q("pending", sid(t, vault, "tx/api-token"))), []string{})

	type pair struct{ id, txid string }
	set := []pair{{sid(t, vault, "tx/api-token"), f.id("secret-carrier-api-token-v3")}, {sid(t, vault, "tx/db-password"), f.id("secret-carrier-db-password-v2")}}
	sort.Slice(set, func(i, j int) bool { return set[i].id < set[j].id })
	all, err := r.outputs(map[string]string{"crypt": crypt, "org": org, "secretsOf": vault})
	if err != nil {
		t.Fatal(err)
	}
	var allIDs []string
	labels := map[string]string{}
	for _, o := range all {
		allIDs = append(allIDs, o.txid)
		rec, err := secrec.CarrierRecord(*o.tx.Outputs[0].LockingScript)
		if err != nil {
			t.Fatal(err)
		}
		cx, err := secrec.DecodeContext(o.context)
		if err != nil {
			t.Fatal(err)
		}
		if err := secrec.CheckInSet(latest, hashOf(tip[0]), rec, cx); err != nil {
			t.Errorf("secrets in set: %v", err)
		}
		labels[o.txid] = rec.Label
	}
	want(t, "secrets", allIDs, []string{set[0].txid, set[1].txid})
	want(t, "secrets-after", r.answer(map[string]string{"crypt": crypt, "org": org, "secretsOf": vault, "after": set[0].id}), []string{set[1].txid})
	want(t, "secrets-after end", r.answer(map[string]string{"crypt": crypt, "org": org, "secretsOf": vault, "after": set[1].id}), []string{})
	seenLabels := map[string]bool{}
	for _, l := range labels {
		if seenLabels[l] {
			continue
		}
		seenLabels[l] = true
		var w []string
		for _, p := range set {
			if labels[p.txid] == l {
				w = append(w, p.txid)
			}
		}
		want(t, "label "+l, r.answer(q("label", l)), w)
	}
	want(t, "no such label", r.answer(q("label", "no-such-label")), []string{})
	want(t, "label-after end", r.answer(q("label", labels[set[0].txid], "after", set[1].id)), []string{})

	_, spent := f.admits(t, "sweep")
	want(t, "sweep 0", r.answer(map[string]string{"crypt": crypt, "spent": spent[0]}), []string{f.id("sweep")})
	want(t, "sweep 1", r.answer(map[string]string{"crypt": crypt, "spent": spent[1]}), []string{f.id("sweep")})
	_, alone := f.admits(t, "funding-tree-alone")
	want(t, "sweep alone", r.answer(map[string]string{"crypt": crypt, "spent": alone[0]}), []string{f.id("funding-tree-alone")})
	want(t, "sweep none", r.answer(map[string]string{"crypt": crypt, "spent": strings.Repeat("00", 32) + ".0"}), []string{})

	hq := map[string]string{"crypt": crypt, "history": org, "vault": vault, "secret": sid(t, vault, "tx/api-token")}
	want(t, "history", r.answer(hq), []string{apiV1, f.id("secret-carrier-api-token-v2"), f.id("secret-carrier-api-token-v3")})
	hq["after"] = "1"
	want(t, "history-after", r.answer(hq), []string{f.id("secret-carrier-api-token-v2"), f.id("secret-carrier-api-token-v3")})
	hq["after"] = "3"
	want(t, "history-after end", r.answer(hq), []string{})
	aq := map[string]string{"crypt": crypt, "audit": org, "vault": vault}
	trail := append([]string{f.id("vault-token-create"), f.id("vault-token-update"), f.id("vault-token-rekey-same-block")}, tip...)
	want(t, "audit", r.answer(aq), trail)
	aq["after"] = "1"
	want(t, "audit-after", r.answer(aq), trail[2:])
	aq["after"] = "3"
	want(t, "audit-after end", r.answer(aq), []string{})
	if _, err := r.outputs(q("extra", "x")); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("extra member: %v", err)
	}
	if _, err := r.outputs(map[string]string{"crypt": "other_crypt_abcdefghij", "vaultsOf": org}); err == nil || !strings.Contains(err.Error(), "does not carry") {
		t.Errorf("another crypt: %v", err)
	}
	for _, cls := range []string{"vault", "vault-seq", "vaults", "vaults-after", "secret", "version", "pending", "secrets", "secrets-after", "label", "label-after", "sweep", "history", "history-after", "audit", "audit-after"} {
		if r.host.count("bsecret_lookups_total", map[string]string{"class": cls}) == 0 {
			t.Errorf("%s was not asked", cls)
		}
	}
	// Through the route: hydrated JSON with byte arrays, the context on a secret answer.
	ra := RouteAnswerer{LS: r.ls}
	raw, _ := json.Marshal(q("secret", sid(t, vault, "tx/api-token")))
	ans, err := ra.Answer(ctx, termsroute.Question{Service: secrec.LookupService, Query: raw})
	if err != nil {
		t.Fatal(err)
	}
	js, _ := json.Marshal(ans)
	if !strings.HasPrefix(string(js), `{"type":"output-list","outputs":[{"beef":[1,1,1,1,`) || !strings.Contains(string(js), `"context":[`) {
		t.Errorf("route answer: %.120s", js)
	}
}

// snapshot is every question's answer and every status, to compare a
// restore with the live index.
func snapshot(t *testing.T, r *rig, questions []map[string]string, carriers, tokens []string) string {
	t.Helper()
	var sb strings.Builder
	for _, q := range questions {
		ids := r.answer(q)
		sb.WriteString(strings.Join(ids, ",") + "\n")
	}
	for _, c := range carriers {
		st, _ := r.ls.Status(context.Background(), c)
		sb.WriteString(st + "\n")
	}
	for _, tx := range tokens {
		st, _ := r.ls.TokenStatus(tx)
		sb.WriteString(fmt.Sprintf("%s %v\n", st, r.ls.Rooted(tx)))
	}
	return sb.String()
}

// TestRestore rebuilds the index from the engine's rows in any order, with
// or without their BEEF, and reaches the same answers and statuses.
func TestRestore(t *testing.T) {
	r, f := vectorRig(t, nil, nil)
	secondRec, _ := f.admits(t, "vault-token-second-vault")
	sv, _ := secrec.DecodeVault(unhex(t, secondRec))
	org := hex.EncodeToString(sv.Org)
	crypt, vault := f.Crypt, f.Vault
	_, spent := f.admits(t, "sweep")
	_, alone := f.admits(t, "funding-tree-alone")
	questions := []map[string]string{
		{"crypt": crypt, "org": org, "vault": vault},
		{"crypt": crypt, "org": org, "vault": vault, "seq": "1"},
		{"crypt": crypt, "vaultsOf": org},
		{"crypt": crypt, "org": org, "vault": vault, "secret": sid(t, vault, "tx/api-token")},
		{"crypt": crypt, "org": org, "vault": vault, "secret": sid(t, vault, "tx/api-token"), "version": "1"},
		{"crypt": crypt, "org": org, "vault": vault, "pending": sid(t, vault, "tx/ssh-key")},
		{"crypt": crypt, "org": org, "secretsOf": vault},
		{"crypt": crypt, "spent": spent[0]},
		{"crypt": crypt, "history": org, "vault": vault, "secret": sid(t, vault, "tx/api-token")},
		{"crypt": crypt, "audit": org, "vault": vault},
		{"crypt": crypt, "spent": alone[0]},
	}
	var carriers, tokens []string
	for _, c := range f.Cases {
		if c.Verdict != "admit" {
			continue
		}
		switch c.Admits.Kind {
		case "secret":
			carriers = append(carriers, hexOf(hashOf(c.Txid)))
		case "vault-token":
			tokens = append(tokens, c.Txid)
		}
	}
	w := snapshot(t, r, questions, carriers, tokens)
	rows := r.storage.utxos(f.Topic, true)
	for _, o := range rows {
		if o.Outpoint.Txid.String() == f.id("vault-token-create") {
			t.Fatal("a token its successor spent is among the unspent rows")
		}
	}
	reversed := make([]bmodule.Output, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		reversed = append(reversed, rows[i])
	}
	noTokens := &MemoryJournal{}
	for _, l := range r.journal.Lines {
		if l.K != "t" {
			noTokens.Lines = append(noTokens.Lines, l)
		}
	}
	_, h := readTx(t)
	for _, c := range []struct {
		label   string
		order   []bmodule.Output
		journal *MemoryJournal
	}{
		{"as stored", rows, r.journal},
		{"reversed", reversed, r.journal},
		{"without BEEF", r.storage.utxos(f.Topic, false), r.journal},
		{"nothing handed over", nil, r.journal},
		{"without the token rows", rows, noTokens},
	} {
		again := setup(t, f, h, &MemoryJournal{Lines: append([]Line(nil), c.journal.Lines...)}, nil)
		again.storage = r.storage
		n, err := again.ls.Restore(context.Background(), c.order, r.storage)
		if err != nil || n == 0 {
			t.Fatalf("%s: restored %d: %v", c.label, n, err)
		}
		got := snapshot(t, again, questions, carriers, tokens)
		if c.order == nil {
			// The bounded table is never journaled, so a restore handed
			// nothing has only the unmatched spends of the sweeps the
			// journal names: here the secret tree, read back by name
			// because a later carrier spent its tombstone (a `w` line).
			if got != w {
				t.Errorf("%s:\n%s\nwant\n%s", c.label, got, w)
			}
			continue
		}
		if got != w {
			t.Errorf("%s:\n%s\nwant\n%s", c.label, got, w)
		}
		if again.host.count("bsecret_token_status_total", map[string]string{"status": "consistent"}) != 6 || again.host.count("bsecret_token_status_total", map[string]string{"status": "pending"}) != 1 {
			t.Errorf("%s: folded once every token is read", c.label)
		}
	}
}

// TestJournalFile holds the file journal to the TypeScript module's bytes
// and rules: rows survive a restart, a last line cut short is cut off, and
// any other bad line stops the load.
func TestJournalFile(t *testing.T) {
	d := t.TempDir()
	j, err := NewFileJournal(d)
	if err != nil {
		t.Fatal(err)
	}
	op := strings.Repeat("ab", 32) + ".3"
	lines := []Line{
		{K: "c", Op: op, C: strings.Repeat("cd", 32), Crypt: "example_crypt_hmqzvtkwrx", At: i64(1700000000)},
		{K: "m", Op: op},
		{K: "d", Op: op, C: strings.Repeat("cd", 32), W: boolp(true)},
		{K: "s", Op: op, S: strings.Repeat("ef", 32), Crypt: "example_crypt_hmqzvtkwrx", H: i64(7), At: i64(1700000001)},
		{K: "t", Txid: strings.Repeat("12", 32), Vout: i64(0), Crypt: "example_crypt_hmqzvtkwrx", At: i64(1700000002)},
		{K: "w", Txid: strings.Repeat("ef", 32), Crypt: "example_crypt_hmqzvtkwrx"},
	}
	for _, l := range lines {
		if err := j.Append(l); err != nil {
			t.Fatal(err)
		}
	}
	_ = j.Close()
	text, _ := os.ReadFile(filepath.Join(d, JournalFile))
	wantText := `{"k":"c","op":"` + op + `","c":"` + strings.Repeat("cd", 32) + `","crypt":"example_crypt_hmqzvtkwrx","at":1700000000}` + "\n" +
		`{"k":"m","op":"` + op + `"}` + "\n" +
		`{"k":"d","op":"` + op + `","c":"` + strings.Repeat("cd", 32) + `","w":true}` + "\n" +
		`{"k":"s","op":"` + op + `","s":"` + strings.Repeat("ef", 32) + `","crypt":"example_crypt_hmqzvtkwrx","h":7,"at":1700000001}` + "\n" +
		`{"k":"t","txid":"` + strings.Repeat("12", 32) + `","vout":0,"crypt":"example_crypt_hmqzvtkwrx","at":1700000002}` + "\n" +
		`{"k":"w","txid":"` + strings.Repeat("ef", 32) + `","crypt":"example_crypt_hmqzvtkwrx"}` + "\n"
	if string(text) != wantText {
		t.Errorf("journal bytes:\n%s\nwant\n%s", text, wantText)
	}
	// A cut line is dropped; the rest survive.
	_ = os.WriteFile(filepath.Join(d, JournalFile), append(text, []byte(`{"k":"c","op":"`)...), 0o600)
	j2, _ := NewFileJournal(d)
	got, err := j2.Load()
	if err != nil || len(got) != 6 || got[0].K != "c" || *got[0].At != 1700000000 || got[2].W == nil || !*got[2].W {
		t.Fatalf("load: %d %v", len(got), err)
	}
	after, _ := os.ReadFile(filepath.Join(d, JournalFile))
	if string(after) != wantText {
		t.Error("the cut line was not cut off")
	}
	// Any other bad line stops the load.
	_ = os.WriteFile(filepath.Join(d, JournalFile), append(text, []byte("{\"k\":\"x\"}\n")...), 0o600)
	if _, err := j2.Load(); err == nil || !strings.Contains(err.Error(), "line 7 is not a bsecret row") {
		t.Errorf("bad line: %v", err)
	}
	_ = os.WriteFile(filepath.Join(d, JournalFile), append(text, []byte("nope\n")...), 0o600)
	if _, err := j2.Load(); err == nil || !strings.Contains(err.Error(), "line 7 is not JSON") {
		t.Errorf("not JSON: %v", err)
	}
}

// TestConfig refuses every mistake and takes the floors and defaults.
func TestConfig(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	base := map[string]string{"BSECRET_CRYPTS": "example_crypt_hmqzvtkwrx", "BSECRET_STATE_DIR": "/var/lib/bsecret", "BSECRET_HEADERS_URL": "http://127.0.0.1:9178"}
	c, err := ParseConfig(env(base))
	if err != nil || c.RetentionDays != FloorDays || c.UnheldHours != FloorUnheldHours || c.SpendTable != MinSpendTable || c.MaxBEEF != secrec.DefaultMaxBEEF || c.Sessions.Max != termsroute.DefaultMaxSessions || c.Budget != termsroute.DefaultBudget {
		t.Fatalf("%+v %v", c, err)
	}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range base {
			m[a] = b
		}
		m[k] = v
		return m
	}
	for k, v := range map[string]string{
		"BSECRET_CRYPTS": "", "BSECRET_STATE_DIR": "relative", "BSECRET_RETENTION_DAYS": "30", "BSECRET_UNHELD_HOURS": "23", "BSECRET_SPEND_TABLE": "100",
		"BSECRET_PRICES": "history=5", "BSECRET_LISTEN": "nope", "BSECRET_PAYEE_KEY": "xyz", "BSECRET_PRIVATE": "other_crypt_abcdefghij=02" + strings.Repeat("ab", 32),
		"BSECRET_HANDSHAKES_PER_SEC": "0", "BSECRET_SESSIONS": "0",
	} {
		if _, err := ParseConfig(env(with(k, v))); err == nil {
			t.Errorf("%s=%q accepted", k, v)
		}
	}
	if _, err := ParseConfig(env(with("BSECRET_PRICES", "history=5,history-after=5"))); err == nil || !strings.Contains(err.Error(), "BSECRET_LISTEN and BSECRET_PAYEE_KEY are required") {
		t.Errorf("a price without its route: %v", err)
	}
	m := with("BSECRET_PRICES", "history=5,history-after=5,audit=20,audit-after=20")
	m["BSECRET_LISTEN"] = "0.0.0.0:8292"
	m["BSECRET_PAYEE_KEY"] = strings.Repeat("07", 32)
	c, err = ParseConfig(env(m))
	if err != nil || c.Prices["audit"] != 20 || c.Listen != "0.0.0.0:8292" || c.PayeeKey == nil {
		t.Fatalf("%+v %v", c, err)
	}
	if err := CheckNoSync("tm_bsecret_x_abcdefghij=http://x"); err == nil {
		t.Error("sync peers")
	}
	if _, err := Mount(newFakeHost(), c, []string{"tm_bsecret_other_abcdefghij"}, &MemoryJournal{}, vectors.Headers{}, nil); err == nil || !strings.Contains(err.Error(), "BSECRET_CRYPTS does not configure it") {
		t.Errorf("an unconfigured topic: %v", err)
	}
}

// TestPricedClassRefusedThroughTheEngine: a class the host prices is
// refused through the engine and answered by the route's answerer.
func TestPricedClassRefusedThroughTheEngine(t *testing.T) {
	f, h := readTx(t)
	host := newFakeHost()
	c := &Config{Crypts: []string{f.Crypt}, StateDir: t.TempDir(), HeadersURL: "http://127.0.0.1:1", RetentionDays: FloorDays, UnheldHours: FloorUnheldHours,
		MaxBEEF: f.MaxBEEF, MaxSweepInputs: f.MaxSweepInputs, SpendTable: MinSpendTable, Prices: map[string]uint64{"audit": 20, "audit-after": 20}}
	m, err := Mount(host, c, nil, &MemoryJournal{}, h, nil)
	if err != nil {
		t.Fatal(err)
	}
	st := newMemStorage()
	if _, err := m.LS.Restore(context.Background(), nil, st); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{"crypt": f.Crypt, "audit": "02" + strings.Repeat("ab", 32), "vault": f.Vault})
	_, err = m.LS.Lookup(context.Background(), &lookup.LookupQuestion{Service: secrec.LookupService, Query: raw})
	if err == nil || !strings.Contains(err.Error(), "priced on this host") {
		t.Errorf("priced through the engine: %v", err)
	}
	if _, err := m.LS.Lookup(context.Background(), &lookup.LookupQuestion{Service: "ls_other", Query: raw}); err == nil {
		t.Error("another service")
	}
	ans, err := (RouteAnswerer{LS: m.LS}).Answer(context.Background(), termsroute.Question{Service: secrec.LookupService, Query: raw})
	if err != nil {
		t.Fatal(err)
	}
	if js, _ := json.Marshal(ans); string(js) != `{"type":"output-list","outputs":[]}` {
		t.Errorf("route: %s", js)
	}
}

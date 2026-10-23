package module

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/transaction"

	bmodule "github.com/lightwebinc/bcommon/module"
	"github.com/lightwebinc/bcommon/termsroute"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// Formula is one output an answer names, with its context when the class
// gives one.
type Formula struct {
	Txid    string
	Vout    uint32
	Context []byte
}

// Classified is a question, validated, and whether this host prices it.
type Classified struct {
	Q      *secrec.Question
	Priced bool
}

// Classify validates a question and names its class, as the terms route
// and the engine ask it. A question for another service, one no class has,
// one naming a crypt the host does not carry, or one about a private crypt
// the asker is not served is an error.
func (s *Service) Classify(ctx context.Context, service string, query []byte) (*Classified, error) {
	if service != secrec.LookupService {
		return nil, fmt.Errorf("ls_bsecret: this service is %s, not %s", secrec.LookupService, service)
	}
	q, err := secrec.ParseQuery(query)
	if err != nil {
		return nil, errors.New("ls_bsecret: refused: " + strings.TrimPrefix(err.Error(), "secrec: "))
	}
	crypt := q.Members["crypt"]
	if !s.crypts[crypt] {
		return nil, fmt.Errorf("ls_bsecret: this host does not carry crypt %s", crypt)
	}
	if s.access != nil {
		if err := s.access(ctx, crypt); err != nil {
			return nil, err
		}
	}
	return &Classified{Q: q, Priced: !q.Class.Free && s.priced[q.Class.Name]}, nil
}

// HallsOf are the halls the rooted tokens of org's vaults in crypt name,
// ascending.
func (s *Service) HallsOf(crypt, org string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	halls := map[string]bool{}
	for id := range s.vaultsByOrg[crypt+"|"+org] {
		v := s.vaults[vaultKey(crypt, org, id)]
		if v == nil {
			continue
		}
		for _, ts := range v.bySeq {
			for _, t := range ts {
				if t.rooted {
					halls[t.rec.Hall] = true
				}
			}
		}
	}
	out := make([]string, 0, len(halls))
	for h := range halls {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// held are the carriers held for one version of one secret whose status is
// one of want, by txid, at most PerVersion.
func (s *Service) held(vkey, id string, version uint64, b *branch, want ...string) []*carrierEntry {
	var out []*carrierEntry
	for c := range s.versions[vkey+"|"+id][version] {
		e := s.carriers[c]
		if e == nil {
			continue
		}
		st := s.statusOf(e, b)
		for _, w := range want {
			if st == w {
				out = append(out, e)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].txid < out[j].txid })
	if len(out) > PerVersion {
		out = out[:PerVersion]
	}
	return out
}

// context is the inclusion context of the secret id in the set of the
// branch's token.
func (s *Service) context(b *branch, id [32]byte) ([]byte, error) {
	if b.contexts == nil {
		b.contexts = map[[32]byte][]byte{}
	}
	if c, ok := b.contexts[id]; ok {
		return c, nil
	}
	ic, err := secrec.ProveSecret(b.good.seq, hashOf(b.good.txid), b.fold.Set(), id)
	if err != nil {
		return nil, err
	}
	enc, err := ic.Encode()
	if err != nil {
		return nil, err
	}
	b.contexts[id] = enc
	return enc, nil
}

func (s *Service) latest(v *vaultIdx) []*tokenEntry {
	if v == nil || v.top < 0 {
		return nil
	}
	var out []*tokenEntry
	for _, t := range v.bySeq[uint64(v.top)] {
		if t.rooted {
			out = append(out, t)
		}
	}
	return out
}

func tok(t *tokenEntry) Formula   { return Formula{Txid: t.txid, Vout: t.vout} }
func car(e *carrierEntry) Formula { return Formula{Txid: e.txid} }
func limitF(a []Formula, n int) []Formula {
	if len(a) > n {
		return a[:n]
	}
	return a
}

// Answer answers a validated question. paid says the question was paid
// for (or asked where no payment is due); a class this host prices is
// refused otherwise.
func (s *Service) Answer(ctx context.Context, c *Classified, paid bool) ([]Formula, error) {
	if c.Priced && !paid {
		return nil, fmt.Errorf("ls_bsecret: %s is priced on this host; ask its terms route's /lookup over BRC-104", c.Q.Class.Name)
	}
	s.host.Metrics().Inc("bsecret_lookups_total", map[string]string{"class": c.Q.Class.Name}, 1)
	s.mu.Lock()
	defer s.mu.Unlock()
	m := c.Q.Members
	crypt := m["crypt"]
	limit := c.Q.Class.Limit
	vaultOf := func(org, vault string) *vaultIdx { return s.vaults[vaultKey(crypt, org, vault)] }
	num := func(k string) uint64 { n, _ := strconv.ParseUint(m[k], 10, 64); return n }
	out := []Formula{}
	switch c.Q.Class.Name {
	case "vault":
		for _, t := range s.latest(vaultOf(m["org"], m["vault"])) {
			out = append(out, tok(t))
		}
		return limitF(out, limit), nil
	case "vault-seq":
		if v := vaultOf(m["org"], m["vault"]); v != nil {
			for _, t := range v.bySeq[num("seq")] {
				out = append(out, tok(t))
			}
		}
		return limitF(out, limit), nil
	case "vaults", "vaults-after":
		org := m["vaultsOf"]
		after, hasAfter := m["after"]
		var ids []string
		for id := range s.vaultsByOrg[crypt+"|"+org] {
			if !hasAfter || id > after {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			ts := s.latest(vaultOf(org, id))
			// A page never splits one vault's latest tokens, so the cursor loses nothing.
			if len(out) > 0 && len(out)+len(ts) > limit {
				break
			}
			for _, t := range ts {
				out = append(out, tok(t))
			}
		}
		return out, nil
	case "secret":
		v := vaultOf(m["org"], m["vault"])
		b := s.answerBranch(ctx, v)
		if v == nil || b == nil {
			return out, nil
		}
		id := h32(m["secret"])
		cur, ok := b.fold.Current(id)
		if !ok {
			return out, nil
		}
		cx, err := s.context(b, id)
		if err != nil {
			return nil, err
		}
		for _, e := range s.held(v.key, m["secret"], cur.Version, b, secrec.StatusListed) {
			f := car(e)
			f.Context = cx
			out = append(out, f)
		}
		return limitF(out, limit), nil
	case "version":
		v := vaultOf(m["org"], m["vault"])
		vkey := vaultKey(crypt, m["org"], m["vault"])
		for _, e := range s.held(vkey, m["secret"], num("version"), s.answerBranch(ctx, v), secrec.StatusListed, secrec.StatusUnlisted, secrec.StatusMismatched) {
			out = append(out, car(e))
		}
		return limitF(out, limit), nil
	case "pending":
		v := vaultOf(m["org"], m["vault"])
		vkey := vaultKey(crypt, m["org"], m["vault"])
		b := s.answerBranch(ctx, v)
		var above uint64
		if b != nil {
			if cur, ok := b.fold.Current(h32(m["pending"])); ok {
				above = cur.Version
			}
		}
		var versions []uint64
		for n := range s.versions[vkey+"|"+m["pending"]] {
			if n > above {
				versions = append(versions, n)
			}
		}
		sort.Slice(versions, func(i, j int) bool { return versions[i] > versions[j] })
		for _, n := range versions {
			for _, e := range s.held(vkey, m["pending"], n, b, secrec.StatusUnlisted) {
				out = append(out, car(e))
			}
			if len(out) >= limit {
				break
			}
		}
		return limitF(out, limit), nil
	case "secrets", "secrets-after", "label", "label-after":
		vault := m["secretsOf"]
		if vault == "" {
			vault = m["vault"]
		}
		v := vaultOf(m["org"], vault)
		b := s.answerBranch(ctx, v)
		if v == nil || b == nil {
			return out, nil
		}
		after, hasAfter := m["after"]
		label, hasLabel := m["label"]
		for _, cur := range b.fold.Set() {
			id := hexOf(cur.ID)
			if hasAfter && id <= after {
				continue
			}
			var es []*carrierEntry
			for _, e := range s.held(v.key, id, cur.Version, b, secrec.StatusListed) {
				if !hasLabel || e.rec.Label == label {
					es = append(es, e)
				}
			}
			if len(es) == 0 {
				continue
			}
			// A page never splits one secret's carriers, so the cursor loses nothing.
			if len(out) > 0 && len(out)+len(es) > limit {
				break
			}
			cx, err := s.context(b, cur.ID)
			if err != nil {
				return nil, err
			}
			for _, e := range es {
				f := car(e)
				f.Context = cx
				out = append(out, f)
			}
		}
		return out, nil
	case "sweep":
		op := m["spent"]
		var sws []*sweepEntry
		for sid := range s.sweepsByOp[crypt+"|"+op] {
			live := false
			if r := s.rows[op]; r != nil {
				_, live = r.sweeps[sid]
			}
			if !live {
				if el := s.tableAt[op]; el != nil {
					_, live = el.Value.(*tableEntry).spends[sid]
				}
			}
			if e := s.sweeps[sid]; live && e != nil {
				sws = append(sws, e)
			}
		}
		sort.Slice(sws, func(i, j int) bool {
			a, b := sws[i], sws[j]
			if a.height != b.height {
				return a.height < b.height
			}
			if a.offset != b.offset {
				return a.offset < b.offset
			}
			return a.txid < b.txid
		})
		for _, e := range sws {
			out = append(out, Formula{Txid: e.txid})
		}
		return limitF(out, limit), nil
	case "history", "history-after":
		vkey := vaultKey(crypt, m["history"], m["vault"])
		b := s.answerBranch(ctx, s.vaults[vkey])
		var after uint64
		if a, ok := m["after"]; ok {
			after, _ = strconv.ParseUint(a, 10, 64)
		}
		var versions []uint64
		for n := range s.versions[vkey+"|"+m["secret"]] {
			if n > after {
				versions = append(versions, n)
			}
		}
		sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
		for _, n := range versions {
			es := s.held(vkey, m["secret"], n, b, secrec.StatusListed, secrec.StatusUnlisted, secrec.StatusMismatched)
			if len(es) == 0 {
				continue
			}
			// A page never splits one version's carriers.
			if len(out) > 0 && len(out)+len(es) > limit {
				break
			}
			for _, e := range es {
				out = append(out, car(e))
			}
		}
		return out, nil
	case "audit", "audit-after":
		v := vaultOf(m["audit"], m["vault"])
		if v == nil {
			return out, nil
		}
		after := int64(-1)
		if a, ok := m["after"]; ok {
			n, _ := strconv.ParseInt(a, 10, 64)
			after = n
		}
		var seqs []uint64
		for seq := range v.bySeq {
			if int64(seq) > after { //nolint:gosec // a seq is far below 2^63
				seqs = append(seqs, seq)
			}
		}
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
		for _, seq := range seqs {
			var ts []*tokenEntry
			for _, t := range v.bySeq[seq] {
				if t.rooted {
					ts = append(ts, t)
				}
			}
			if len(ts) == 0 {
				continue
			}
			// A page never splits a seq, so the cursor loses nothing.
			if len(out) > 0 && len(out)+len(ts) > limit {
				break
			}
			for _, t := range ts {
				out = append(out, tok(t))
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("ls_bsecret: no answer for class %s", c.Q.Class.Name)
}

// Hydrate is an answer with each output's BEEF, as the engine hydrates one,
// read from the host's storage. A context rides along.
func (s *Service) Hydrate(ctx context.Context, formulas []Formula) ([]bmodule.HydratedOutput, error) {
	s.mu.Lock()
	storage := s.storage
	s.mu.Unlock()
	if storage == nil {
		return nil, errors.New("ls_bsecret: storage is not restored yet")
	}
	out := make([]bmodule.HydratedOutput, 0, len(formulas))
	for _, f := range formulas {
		h, err := chainhash.NewHashFromHex(f.Txid)
		if err != nil {
			continue
		}
		o, err := storage.FindOutput(ctx, &transaction.Outpoint{Txid: *h, Index: f.Vout}, "")
		if err != nil {
			return nil, err
		}
		if o == nil || o.Beef == nil {
			continue
		}
		out = append(out, bmodule.HydratedOutput{Beef: o.Beef, OutputIndex: f.Vout, Context: f.Context})
	}
	return out, nil
}

// Lookup implements module.LookupService: asked through the engine, a
// class the host prices is refused here. The answer is hydrated here and
// carries each output's context (bcommon module.HydratedOutput).
func (s *Service) Lookup(ctx context.Context, q *lookup.LookupQuestion) (*lookup.LookupAnswer, error) {
	c, err := s.Classify(ctx, q.Service, q.Query)
	if err != nil {
		return nil, err
	}
	formulas, err := s.Answer(ctx, c, false)
	if err != nil {
		return nil, err
	}
	outs, err := s.Hydrate(ctx, formulas)
	if err != nil {
		return nil, err
	}
	ans := &lookup.LookupAnswer{Type: lookup.AnswerTypeOutputList, Outputs: make([]*lookup.OutputListItem, 0, len(outs)), Result: outs}
	for _, o := range outs {
		ans.Outputs = append(ans.Outputs, &lookup.OutputListItem{Beef: o.Beef, OutputIndex: o.OutputIndex})
	}
	return ans, nil
}

// GetMetaData implements module.LookupService.
func (*Service) GetMetaData() *overlay.MetaData {
	return &overlay.MetaData{Name: secrec.LookupService, Description: "Answers bsecret vaults, secrets and sweeps by crypt."}
}

// byteArray writes bytes as a JSON array of numbers, as the TypeScript
// route writes a number[].
type byteArray []byte

func (b byteArray) MarshalJSON() ([]byte, error) {
	var sb strings.Builder
	sb.WriteByte('[')
	for i, c := range b {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(strconv.Itoa(int(c)))
	}
	sb.WriteByte(']')
	return []byte(sb.String()), nil
}

type outputJSON struct {
	Beef        byteArray `json:"beef"`
	OutputIndex uint32    `json:"outputIndex"`
	Context     byteArray `json:"context,omitempty"`
}

// OutputList is the engine's lookup answer as JSON.
type OutputList struct {
	Type    string       `json:"type"`
	Outputs []outputJSON `json:"outputs"`
}

// RouteAnswerer is ls_bsecret as the terms route asks its questions: a
// priced answer is hydrated as the engine hydrates one.
type RouteAnswerer struct{ LS *Service }

var _ termsroute.Answerer = RouteAnswerer{}

// Restored implements termsroute.Answerer.
func (r RouteAnswerer) Restored() bool { return r.LS.Restored() }

// Classify implements termsroute.Answerer: the asker's identity, when the
// route verified one, is in ctx, so a private crypt refuses before any
// price.
func (r RouteAnswerer) Classify(ctx context.Context, q termsroute.Question) (string, error) {
	c, err := r.LS.Classify(ctx, q.Service, q.Query)
	if err != nil {
		return "", err
	}
	return c.Q.Class.Name, nil
}

// Answer implements termsroute.Answerer: the asker's identity, when the
// route verified one, is in ctx.
func (r RouteAnswerer) Answer(ctx context.Context, q termsroute.Question) (any, error) {
	c, err := r.LS.Classify(ctx, q.Service, q.Query)
	if err != nil {
		return nil, err
	}
	formulas, err := r.LS.Answer(ctx, c, true)
	if err != nil {
		return nil, err
	}
	outs, err := r.LS.Hydrate(ctx, formulas)
	if err != nil {
		return nil, err
	}
	list := OutputList{Type: "output-list", Outputs: make([]outputJSON, 0, len(outs))}
	for _, o := range outs {
		list.Outputs = append(list.Outputs, outputJSON{Beef: o.Beef, OutputIndex: o.OutputIndex, Context: o.Context})
	}
	return list, nil
}

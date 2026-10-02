package vectors

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/lightwebinc/bcommon/carrier"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// genTransaction writes transaction-v1.json, every case admitted or refused
// exactly as it says, and index-v1.json, the chain and outpoint rules an
// index applies to what was admitted.
func genTransaction(s *Scenario, files map[string][]byte) error {
	e, err := newTxEnv(s)
	if err != nil {
		return err
	}
	cases, err := e.cases()
	if err != nil {
		return err
	}
	host := func(c txCase) secrec.Host {
		return secrec.Host{Crypt: Crypt, Headers: e.c.headers, MaxSweepInputs: c.maxSweep}
	}
	var list []txJSON
	seen := map[string]bool{}
	rows := map[string]int{}
	for _, c := range cases {
		if seen[c.name] {
			return fmt.Errorf("%s: two cases of one name", c.name)
		}
		seen[c.name] = true
		beef := c.beef
		if beef == nil {
			if beef, err = c.tx.AtomicBEEF(false); err != nil {
				return fmt.Errorf("%s: beef: %w", c.name, err)
			}
		}
		held := c.held
		if held == nil {
			held = e.heldInputs(c.tx)
		}
		a, err := secrec.Admit(e.ctx, beef, held, host(c))
		j := txJSON{Name: c.name, Note: c.note, Rule: c.rule, Txid: c.tx.TxID().String(), RawTx: c.tx.Hex(),
			BEEF: hx(beef), Coins: []coinJSON{}, MaxSweepInputs: c.maxSweep, Scripts: scriptsVerify(e.ctx, c.tx)}
		for _, i := range held {
			in := c.tx.Inputs[i]
			j.Coins = append(j.Coins, coinJSON{InputIndex: i, Txid: in.SourceTXID.String(), Vout: in.SourceTxOutIndex})
		}
		if !j.Scripts {
			return fmt.Errorf("%s: its own scripts do not verify", c.name)
		}
		switch {
		case c.reason == "" && err != nil:
			return fmt.Errorf("%s: refused: %w", c.name, err)
		case c.reason != "" && err == nil:
			return fmt.Errorf("%s: admitted, want %s", c.name, c.reason)
		case c.reason != "" && secrec.Reason(err) != c.reason:
			return fmt.Errorf("%s: reason %s, want %s (%v)", c.name, secrec.Reason(err), c.reason, err)
		case c.reason != "" && c.rule == "":
			return fmt.Errorf("%s: a refusal names the frozen row it pins", c.name)
		case err == nil:
			if a.Txid != [32]byte(*c.tx.TxID()) {
				return fmt.Errorf("%s: admitted another subject", c.name)
			}
			j.Verdict, j.Admits = "admit", admission(a)
		default:
			j.Verdict, j.Reason = "refuse", c.reason
			rows[c.rule]++
		}
		list = append(list, j)
	}
	for _, r := range []string{rowCarrier, rowToken, rowCanonical, rowSigs, rowOneClaim, rowSweep} {
		if rows[r] == 0 {
			return fmt.Errorf("no refusal pins the row %q", r)
		}
	}
	var headers []map[string]any
	for ht := uint32(801); ht <= e.c.height; ht++ {
		headers = append(headers, map[string]any{"height": ht, "merkleRoot": e.c.headers[ht].String()})
	}

	// Stored and replayed: each admitted token as the engine stores it (an
	// Atomic BEEF of the token alone), read back without its parent, and the
	// BEEF a replayer assembles from two stored tokens (or the chain tree at
	// seq 0), byte for byte the BEEF the token was first admitted in. Each
	// stored token is also held to the one before it, as a reader walks a
	// chain by spends.
	type storedJSON struct {
		Name     string `json:"name"`
		Txid     string `json:"txid"`
		Stored   string `json:"stored"`
		Seq      uint64 `json:"seq"`
		Record   string `json:"record"`
		Parent   string `json:"parentTxid"`
		Spends   string `json:"spends"`
		Replayed string `json:"replayBeef"`
	}
	var stored []storedJSON
	var prevTx *transaction.Transaction
	var prevTok *secrec.VaultToken
	for i, name := range []string{"vault-token-create", "vault-token-update", "vault-token-rekey-same-block", "vault-token-settle"} {
		sb, err := e.tokens[i].AtomicBEEF(false)
		if err != nil {
			return err
		}
		tx, tok, err := secrec.StoredToken(sb)
		if err != nil {
			return fmt.Errorf("%s: stored: %w", name, err)
		}
		ptx := e.tree // the chain tree, from the publisher or a chain source
		var spends transaction.Outpoint
		if i == 0 {
			if _, spends, err = secrec.CheckFirstToken(tx); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		} else {
			ptx = prevTx
			if _, err := secrec.CheckNextToken(prevTx, prevTok, tx); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			spends = transaction.Outpoint{Txid: *prevTx.TxID(), Index: prevTok.Vout}
		}
		replay, err := secrec.TokenBEEF(tx, ptx)
		if err != nil {
			return err
		}
		var want string
		for _, j := range list {
			if j.Name == name {
				want = j.BEEF
			}
		}
		if hx(replay) != want {
			return fmt.Errorf("%s: the replayed BEEF is not the one admitted", name)
		}
		stored = append(stored, storedJSON{Name: name, Txid: tx.TxID().String(), Stored: hx(sb), Seq: tok.Vault.Seq,
			Record: hx(tok.Record), Parent: ptx.TxID().String(), Spends: outpointString(spends), Replayed: hx(replay)})
		prevTx, prevTok = tx, tok
	}
	if err := put(files, "transaction-v1.json", map[string]any{
		"description": "Transactions admitted or refused by the topic manager's rules (docs/spec.md section 11.1), in the order given there. " +
			"Each case is the transaction as raw hex and the BEEF submitted (Atomic BEEF unless the case says otherwise: an unmined carrier's with its funding tree, a mined sweep's with its own proof; a vault token's is BEEF V1 of its parent then the token, as the codec's TokenBEEF writes it), " +
			"and the previous coins it is admitted with: the inputs that spend an output the topic holds once the admitted cases are admitted (inputIndex), each with the outpoint it spends (txid in display order). They decide what is retained and no verdict. " +
			"Admission runs against the crypt and the headers below, with a BEEF bound of maxBeef bytes and a sweep input bound of maxSweepInputs unless a case names its own. " +
			"A refusal is raised, never answered with empty instructions. admits lists the admittance instructions (outputsToAdmit, coinsToRetain) and what the lookup service records: a carrier's commitment (hash byte order), record, owner, content id and funding outpoint; a token's seq, record, parent txid (display order), its predecessor's seq and the outpoint its predecessor input (at seq 0, its funding input) spends; a sweep's spent outpoints. " +
			"scriptsVerify says every input of the transaction passes the script interpreter against the output it spends, so each refusal is made by the rule the case names and by no earlier one. rule names the row of docs/frozen.md section 2 a refusal pins, and rows counts the refusals of each. Cases named \"-before-\" break two rules and are refused for the earlier. Signatures are deterministic (RFC 6979). " +
			"stored is each admitted token of the vault as the engine stores it, the token alone with its proof, read without its parent and held to the token before it by its spend; a replayer assembles replayBeef from two stored tokens (at seq 0, the token and its chain tree), byte for byte the BEEF the token was first admitted in.",
		"crypt":          Crypt,
		"topic":          secrec.Topic(Crypt),
		"maxBeef":        secrec.DefaultMaxBEEF,
		"maxSweepInputs": secrec.DefaultMaxSweepInputs,
		"vault":          hx(e.v.VaultID[:]),
		"rows":           rows,
		"headers":        headers,
		"cases":          list,
		"stored":         stored,
	}); err != nil {
		return err
	}
	return genIndex(e, files)
}

// genIndex writes index-v1.json: which held tokens are rooted, the mined
// vault's chain folded, outpoint rows, and each carrier's status.
func genIndex(e *txEnv, files map[string][]byte) error {
	// Rooted: what a host holds, and which of it is the vault's chain.
	type heldJSON struct {
		Label  string   `json:"label"`
		Held   []string `json:"held"`
		Rooted []string `json:"rooted"`
	}
	stored := func(t *transaction.Transaction) *transaction.Transaction {
		b, err := t.AtomicBEEF(false)
		if err != nil {
			panic(err)
		}
		tx, _, err := secrec.StoredToken(b)
		if err != nil {
			panic(err)
		}
		return tx
	}
	names := map[*transaction.Transaction]string{e.tokens[0]: "seq 0", e.tokens[1]: "seq 1", e.tokens[2]: "seq 2", e.tokens[3]: "seq 3",
		e.second: "second vault seq 0", e.onLoose: "seq 8 on an unadmitted parent"}
	var helds []heldJSON
	for _, h := range []struct {
		label  string
		txs    []*transaction.Transaction
		rooted int
	}{
		{"the whole chain, in order", e.tokens, 4},
		{"the whole chain, latest first", []*transaction.Transaction{e.tokens[3], e.tokens[2], e.tokens[1], e.tokens[0]}, 4},
		{"seq 1 missing: seq 2 and 3 are pending", []*transaction.Transaction{e.tokens[0], e.tokens[2], e.tokens[3]}, 1},
		{"seq 0 missing: nothing is rooted", e.tokens[1:], 0},
		{"two vaults and a token on an unadmitted parent: the last is never rooted", []*transaction.Transaction{e.onLoose, e.second, e.tokens[0], e.tokens[1]}, 3},
	} {
		var txs []*transaction.Transaction
		j := heldJSON{Label: h.label, Rooted: []string{}}
		for _, t := range h.txs {
			txs = append(txs, stored(t))
			j.Held = append(j.Held, names[t])
		}
		r := secrec.Rooted(txs)
		for _, t := range h.txs {
			if r[[32]byte(*t.TxID())] {
				j.Rooted = append(j.Rooted, names[t])
			}
		}
		if len(j.Rooted) != h.rooted {
			return fmt.Errorf("rooted %q: %d rooted, want %d", h.label, len(j.Rooted), h.rooted)
		}
		helds = append(helds, j)
	}

	// The chain folded, and what its tokens list.
	type tokJSON struct {
		Seq    uint64 `json:"seq"`
		Txid   string `json:"txid"`
		Stored string `json:"stored"`
		Status string `json:"status"`
		Count  uint64 `json:"count"`
		Stale  uint64 `json:"stale"`
	}
	f, l := secrec.NewVaultFold(), secrec.NewListings()
	var toks []tokJSON
	for i, v := range e.v.Vaults {
		st := f.Apply(v)
		if st != secrec.StatusConsistent {
			return fmt.Errorf("vault seq %d: %s", i, st)
		}
		l.Apply(v)
		sb, err := e.tokens[i].AtomicBEEF(false)
		if err != nil {
			return err
		}
		toks = append(toks, tokJSON{v.Seq, e.tokens[i].TxID().String(), hx(sb), st, uint64(len(f.Set())), f.Stale()})
	}

	// Carriers: each admitted carrier's status against the chain's listings
	// and its outpoint's row. The sweep spends output 1; output 0 holds two
	// carriers of one record.
	type carJSON struct {
		Label      string `json:"label"`
		Record     string `json:"record"`
		Commitment string `json:"commitment"`
		Outpoint   string `json:"outpoint"`
		Status     string `json:"status"`
	}
	type rowJSON struct {
		Outpoint string   `json:"outpoint"`
		Winner   string   `json:"winner"`
		Others   []string `json:"others"`
		More     uint64   `json:"more"`
		Dropped  bool     `json:"dropped"`
		Swept    bool     `json:"swept"`
	}
	rows := map[uint32]*secrec.OutpointRow{}
	row := func(vout uint32) *secrec.OutpointRow {
		if rows[vout] == nil {
			rows[vout] = &secrec.OutpointRow{}
		}
		return rows[vout]
	}
	second := e.secondCarrier()
	type car struct {
		label string
		tx    *transaction.Transaction
		rec   *secrec.Secret
		raw   []byte
		vout  uint32
		want  string
	}
	var cars []car
	for _, k := range e.v.Order {
		v := e.v.Versions[k]
		cars = append(cars, car{label: k, tx: e.carriers[k], rec: v.Rec, raw: v.Raw, vout: e.funded[k]})
	}
	a1 := e.v.Versions["tx/api-token@1"]
	cars = append(cars, car{label: "tx/api-token@1, a second carrier on the same funding outpoint", tx: second, rec: a1.Rec, raw: a1.Raw, vout: 0})
	// A record at a listed identifier and version with another commitment,
	// and one whose label is not the vault's.
	a3 := e.v.Versions["tx/api-token@3"]
	alt := *a3.Rec
	alt.Commitment = label("commitment/another")
	altRaw, err := alt.Encode()
	if err != nil {
		return err
	}
	altRec, err := secrec.DecodeSecret(altRaw)
	if err != nil {
		return err
	}
	altTx, err := carrier.Mint(e.ctx, e.o.w, "", params(secrec.SecretDerivation), altRaw, e.sec, 13)
	if err != nil {
		return err
	}
	cars = append(cars, car{label: "tx/api-token@3 with another commitment than the one listed", tx: altTx, rec: altRec, raw: altRaw, vout: 13})
	odd := *e.unlisted.Rec
	odd.Label = "elsewhere"
	oddRaw, err := odd.Encode()
	if err != nil {
		return err
	}
	oddRec, err := secrec.DecodeSecret(oddRaw)
	if err != nil {
		return err
	}
	oddTx, err := carrier.Mint(e.ctx, e.o.w, "", params(secrec.SecretDerivation), oddRaw, e.sec, 14)
	if err != nil {
		return err
	}
	cars = append(cars, car{label: "tx/ssh-key@1 under a label that is not one of the vault's", tx: oddTx, rec: oddRec, raw: oddRaw, vout: 14})
	for _, c := range cars {
		if _, err := secrec.Admit(e.ctx, mustAtomic(c.tx), nil, secrec.Host{Crypt: Crypt, Headers: e.c.headers}); err != nil {
			return fmt.Errorf("index carrier %q: %w", c.label, err)
		}
		row(c.vout).Add(carrier.Commitment(c.tx))
	}
	for _, in := range e.sweep.Inputs {
		if in.SourceTXID.IsEqual(e.sec.TxID()) {
			row(in.SourceTxOutIndex).Swept = true
		}
	}
	want := map[string]string{
		"tx/api-token@1": "", "tx/db-password@1": secrec.StatusRetracted, "tx/api-token@2": secrec.StatusListed,
		"tx/tls-key@1": secrec.StatusListed, "tx/db-password@2": secrec.StatusListed, "tx/api-token@3": secrec.StatusListed,
		"tx/ssh-key@1": secrec.StatusUnlisted,
		"tx/api-token@1, a second carrier on the same funding outpoint": "",
		"tx/api-token@3 with another commitment than the one listed":    secrec.StatusMismatched,
		"tx/ssh-key@1 under a label that is not one of the vault's":     secrec.StatusMismatched,
	}
	var carJ []carJSON
	winners := 0
	for _, c := range cars {
		cm := carrier.Commitment(c.tx)
		st := secrec.CarrierStatus(row(c.vout), cm, l, c.rec)
		if w := want[c.label]; w != "" && st != w {
			return fmt.Errorf("index carrier %q: %s, want %s", c.label, st, w)
		}
		if c.vout == 0 && st == secrec.StatusListed {
			winners++
		}
		carJ = append(carJ, carJSON{Label: c.label, Record: hx(c.raw), Commitment: hx(cm[:]),
			Outpoint: fmt.Sprintf("%s.%d", e.sec.TxID().String(), c.vout), Status: st})
	}
	if winners != 1 {
		return fmt.Errorf("output 0 answers %d carriers, want one", winners)
	}
	var rowJ []rowJSON
	for vout := uint32(0); vout < 16; vout++ {
		r, ok := rows[vout]
		if !ok {
			continue
		}
		j := rowJSON{Outpoint: fmt.Sprintf("%s.%d", e.sec.TxID().String(), vout), Others: []string{},
			More: r.More, Dropped: r.Dropped, Swept: r.Swept}
		if r.Any {
			j.Winner = hx(r.Winner[:])
		}
		for _, o := range r.Others {
			j.Others = append(j.Others, hx(o[:]))
		}
		rowJ = append(rowJ, j)
	}

	// A row past its bound: twelve commitments in an order that is not
	// ascending, the lowest the winner, the eight next kept, three counted.
	big := &secrec.OutpointRow{}
	var fed []string
	for i := 0; i < 12; i++ {
		c := label("commitment/row/%d", (i*5)%12)
		big.Add(c)
		fed = append(fed, hx(c[:]))
	}
	if len(big.Others) != secrec.MaxOthers || big.More != 3 {
		return fmt.Errorf("the bounded row keeps %d and counts %d", len(big.Others), big.More)
	}
	bigJ := map[string]any{"added": fed, "winner": hx(big.Winner[:]), "others": func() []string {
		var out []string
		for _, o := range big.Others {
			out = append(out, hx(o[:]))
		}
		return out
	}(), "more": big.More}

	// A row whose winner the host dropped: every carrier on the outpoint is
	// superseded, and a lower commitment that arrives later is too.
	hi, mid, lo := label("commitment/row/dropped/c"), label("commitment/row/dropped/b"), label("commitment/row/dropped/a")
	three := [][32]byte{hi, mid, lo}
	sort32(three)
	lo, mid, hi = three[0], three[1], three[2]
	dr := &secrec.OutpointRow{}
	dr.Add(hi)
	dr.Add(mid)
	before := []string{dr.Status(mid), dr.Status(hi)}
	dr.Dropped = true
	dropped := []string{dr.Status(mid), dr.Status(hi)}
	dr.Add(lo)
	after := []string{dr.Status(lo), dr.Status(mid), dr.Status(hi)}
	if before[0] != "" || dropped[0] != secrec.StatusSuperseded || after[0] != secrec.StatusSuperseded || dr.Winner != lo {
		return fmt.Errorf("the dropped row: %v %v %v", before, dropped, after)
	}
	droppedJ := map[string]any{"added": []string{hx(hi[:]), hx(mid[:])}, "winner": hx(mid[:]), "superseded": []string{hx(hi[:])},
		"afterTheDrop":  map[string]any{"superseded": []string{hx(mid[:]), hx(hi[:])}},
		"later":         hx(lo[:]),
		"afterTheLater": map[string]any{"winner": hx(lo[:]), "dropped": true, "superseded": []string{hx(lo[:]), hx(mid[:]), hx(hi[:])}}}

	return put(files, "index-v1.json", map[string]any{
		"description": "What the index computes from admitted objects (docs/spec.md section 11.2), never at admission. " +
			"rooted is sets of tokens a host holds, each as it stores it (the stored hex under chain, and in transaction-v1.json): a first token is rooted by the outpoint its input spends, and a later one when the host holds the token it spends, back to the first; the result does not depend on order. " +
			"chain is the transaction vectors' vault folded from seq 0, each token consistent, with the size of the set and the number stale the fold gives. " +
			"carriers are admitted carriers on secret-tree outputs, each with the status the chain's listings and its outpoint's row give, the first that applies of retracted, superseded, mismatched, listed, unlisted. " +
			"outpoints are those rows, and the row of a swept outpoint no carrier spent, which has no winner: the winner is the lowest commitment in hash byte order, kept as a running minimum; others are the lowest of the rest, at most 8, and more counts what was not kept. bounded is one row fed twelve commitments out of order. dropped is a row of two carriers whose winner the host then drops, and a lower commitment admitted afterwards: nothing on the outpoint is answered again.",
		"vault":     hx(e.v.VaultID[:]),
		"rooted":    helds,
		"chain":     toks,
		"carriers":  carJ,
		"outpoints": rowJ,
		"bounded":   bigJ,
		"dropped":   droppedJ,
	})
}

func mustAtomic(tx *transaction.Transaction) []byte {
	b, err := tx.AtomicBEEF(false)
	if err != nil {
		panic(err)
	}
	return b
}

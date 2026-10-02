package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/lightwebinc/bcommon/carrier"

	"github.com/lightwebinc/bsecret/internal/engine"
	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/state"
	"github.com/lightwebinc/bsecret/internal/testhost"
	"github.com/lightwebinc/bsecret/internal/unicast"
	"github.com/lightwebinc/bsecret/internal/vread"
)

// An audit that stops before it folds anything (the group's epochs are not
// one chain) gives no status per token; the report lists the tokens all the
// same, and says they were not folded.
func TestAnAuditThatStopsEarlyListsItsTokens(t *testing.T) {
	rec := &secrec.Vault{Seq: 0, Root: secrec.SetRoot(nil)}
	toks := []*vread.Tok{{Txid: "aa", Token: &secrec.VaultToken{Vault: rec}}}
	rep := secrec.Audit([]secrec.Mined{{Vault: rec}}, []secrec.EpochEvent{{Epoch: 0}, {Epoch: 2, EpochID: [32]byte{1}}})
	if rep.OK || len(rep.Statuses) != 0 {
		t.Fatalf("epochs 0 and 2 are not one chain: ok %v, statuses %v", rep.OK, rep.Statuses)
	}
	got := auditTokens(toks, rep.Statuses)
	if len(got) != 1 || got[0].Status != "not folded" {
		t.Fatalf("tokens of an audit that stopped early: %+v", got)
	}
}

// sweepVersion retracts one version of the organisation's only vault, as
// its owner: a sweep of the funding output its carrier spent.
func (h *harness) sweepVersion(version uint64) { h.sweepVersionAs("org", version) }

// sweepVersionAs is sweepVersion from the home name.
func (h *harness) sweepVersionAs(name string, version uint64) {
	h.t.Helper()
	ctx := context.Background()
	g, _, errb := h.global(name)
	w, err := g.openWriter(ctx)
	if err != nil {
		h.t.Fatalf("%v\n%s", err, errb)
	}
	defer w.close(ctx, g)
	v := &w.h.st.Vaults[0]
	for i := range v.Versions {
		if x := &v.Versions[i]; x.Version == version {
			if _, err := w.eng.Retract(ctx, v.Crypt, x.Tree, []uint32{x.Vout}); err != nil {
				h.t.Fatalf("sweep of version %d: %v\n%s", version, err, errb)
			}
			return
		}
	}
	h.t.Fatalf("the home holds no version %d", version)
}

// forgetSweeps makes both hosts lose every sweep they hold, so that they
// answer what it retracted again and only the chain source shows the spend.
func (h *harness) forgetSweeps() {
	for _, host := range []*testhost.Host{h.a, h.b} {
		for _, id := range host.Txids("sweep") {
			host.Forget(id)
		}
	}
}

// In an interval vault a retracted version is not a link: a reader takes
// the highest version it can link below it, and says a later one exists.
func TestNothingLinksThroughARetractedVersion(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault("-anchor", "interval")
	h.put("svc/token", "t1")
	h.put("svc/token", "t2", "-defer")
	h.put("svc/token", "t3", "-defer")
	h.put("svc/token", "t4", "-defer")
	// The top link is retracted, and the hosts lost the sweep: the reader
	// falls back to the highest version that is not.
	h.sweepVersion(4)
	h.forgetSweeps()
	r := h.must("alice", "get", "svc/token")
	if r.stdout != "t3" || !strings.Contains(r.stderr, "version 4 is retracted") || !strings.Contains(r.stderr, "a later version exists") {
		t.Fatalf("a retracted top link: %q\n%s", r.stdout, r.stderr)
	}
	// A link in the middle: nothing above it is reached through it.
	h.sweepVersion(2)
	h.forgetSweeps()
	r = h.must("alice", "get", "svc/token")
	if r.stdout != "t1" || !strings.Contains(r.stderr, "version 2 is retracted") || !strings.Contains(r.stderr, "anchored") || strings.Contains(r.stderr, "UNANCHORED") {
		t.Fatalf("a retracted link in the middle: %q\n%s", r.stdout, r.stderr)
	}
}

// Hosts that withhold a token in the middle of a vault's chain cannot hide
// that later ones exist: the tokens they answer above the gap verify and
// do not link, and a reader with no memory is told so (exit 3).
func TestWithheldTokensAreNotANote(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	h.put("db/user", "two")
	h.put("db/host", "three")
	withhold := func(q *secrec.Question, outs []testhost.Output) []testhost.Output {
		if q.Class.Name == "vault-seq" && q.Members["seq"] == "2" {
			return nil
		}
		return outs
	}
	h.a.Rewrite, h.b.Rewrite = withhold, withhold
	// With no chain source nothing else says a later token exists.
	delete(h.env, "BSECRET_ASSET")
	r := h.run("alice", "", "get", "db/password")
	if r.code != exitIncomplete || r.stdout != "one" || !strings.Contains(r.stderr, "WITHHELD: 1 verified token(s) of the vault exist above seq 1") {
		t.Fatalf("a reader with no memory, a token withheld: exit %d %q\n%s", r.code, r.stdout, r.stderr)
	}
	if r := h.run("carol", "", "audit", "-free"); r.code != exitIncomplete || !strings.Contains(r.stderr, "WITHHELD") {
		t.Fatalf("an audit, a token withheld: exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	h.a.Rewrite, h.b.Rewrite = nil, nil
	h.env["BSECRET_ASSET"] = h.chainS.URL
	if r := h.must("alice", "get", "db/host"); r.stdout != "three" || strings.Contains(r.stderr, "WITHHELD") {
		t.Fatalf("with nothing withheld: %q\n%s", r.stdout, r.stderr)
	}
}

// A host that answers a token that does not verify is at fault, and is
// named; the read stands on what verified, and is incomplete, not refused:
// one hostile host cannot make every read of a vault fail a check.
func TestAHostAnsweringJunkDoesNotFailTheRead(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	h.b.Rewrite = func(q *secrec.Question, outs []testhost.Output) []testhost.Output {
		if q.Class.Name == "vault" {
			return append(outs, testhost.Output{Beef: []byte{1, 2, 3}})
		}
		return outs
	}
	r := h.run("alice", "", "get", "db/password")
	if r.code != exitIncomplete || r.stdout != "one" || !strings.Contains(r.stderr, "REFUSED token") {
		t.Fatalf("one host answers junk: exit %d %q\n%s", r.code, r.stdout, r.stderr)
	}
}

// A second home of the organisation learns, by sync, the versions an
// interval vault's other home published and did not list yet: its next
// version follows them, and is not a second record at a version they hold.
func TestSyncLearnsUnlistedVersions(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault("-anchor", "interval")
	h.put("svc/token", "t1")
	h.put("svc/token", "t2", "-defer")
	h.identity("org2", true, "-borg", h.borg.Home)
	if r := h.must("org2", "sync"); !strings.Contains(r.stdout, "unlisted 1 version(s)") {
		t.Fatalf("sync:\n%s\n%s", r.stdout, r.stderr)
	}
	if r := h.mustIn("org2", "t3", "put", "svc/token", "-defer"); !strings.Contains(r.stdout, "svc/token version 3") {
		t.Fatalf("put from the second home:\n%s\n%s", r.stdout, r.stderr)
	}
	if r := h.must("alice", "get", "svc/token"); r.stdout != "t3" || !strings.Contains(r.stderr, "version 3") {
		t.Fatalf("alice: %q\n%s", r.stdout, r.stderr)
	}
	// The second home lists the latest, and sweeps what came and went.
	if r := h.must("org2", "anchor"); !strings.Contains(r.stdout, "anchored 1 secret(s)") {
		t.Fatalf("anchor from the second home:\n%s\n%s", r.stdout, r.stderr)
	}
	if r := h.must("alice", "get", "svc/token"); r.stdout != "t3" || !strings.Contains(r.stderr, "anchored, current") {
		t.Fatalf("alice after the anchor: %q\n%s", r.stdout, r.stderr)
	}
}

// strayVersion publishes, as the vault's owner, a carrier of svc/token at a
// version far above anything the vault holds: a record its owner signed
// that links to nothing.
func (h *harness) strayVersion(version uint64) {
	h.t.Helper()
	ctx := context.Background()
	g, _, errb := h.global("org")
	w, err := g.openWriter(ctx)
	if err != nil {
		h.t.Fatalf("%v\n%s", err, errb)
	}
	defer w.close(ctx, g)
	v := &w.h.st.Vaults[0]
	last := &v.Versions[len(v.Versions)-1]
	old, err := transaction.NewTransactionFromHex(last.Raw)
	if err != nil {
		h.t.Fatal(err)
	}
	rec, err := secrec.CarrierRecord(*old.Outputs[0].LockingScript)
	if err != nil {
		h.t.Fatal(err)
	}
	rec.Version = version
	payload, err := rec.Encode()
	if err != nil {
		h.t.Fatal(err)
	}
	ts := w.h.st.Set(state.TreeSecret).Tree
	tree, err := w.eng.Tx(ts.Txid)
	if err != nil {
		h.t.Fatal(err)
	}
	if tree.MerklePath, err = engine.Minimal(tree.MerklePath, tree.TxID()); err != nil {
		h.t.Fatal(err)
	}
	signer := w.h.e.Signer()
	car, err := carrier.Mint(ctx, signer, signer.Originator, engine.Params(state.TreeSecret), payload, tree, ts.Count-1)
	if err != nil {
		h.t.Fatal(err)
	}
	beef, err := car.AtomicBEEF(false)
	if err != nil {
		h.t.Fatal(err)
	}
	set := &unicast.Set{Hosts: []string{h.aS.URL, h.bS.URL}, Need: 2}
	if err := set.Send(ctx, "stray", secrec.Topic(v.Crypt), beef, 2, nil).Err(); err != nil {
		h.t.Fatalf("the hosts did not take the stray carrier: %v", err)
	}
}

// A version a carrier claims never sets how far a reader walks: the
// versions above the listed one are asked for one by one, only while they
// are answered in a row.
func TestAStrayVersionIsNotWalkedTo(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault("-anchor", "interval")
	h.put("svc/token", "t1")
	h.put("svc/token", "t2", "-defer")
	h.strayVersion(1 << 40)
	before := h.a.Questions("version")
	r := h.must("alice", "get", "svc/token")
	if r.stdout != "t2" || !strings.Contains(r.stderr, "a later version exists") {
		t.Fatalf("with a stray version above: %q\n%s", r.stdout, r.stderr)
	}
	if asked := h.a.Questions("version") - before; asked > 4 {
		t.Fatalf("the reader asked the version class %d times", asked)
	}
}

// A page's cursor comes only from what verified as the vault's own: a host
// that adds another vault's carriers to its answers does not walk the
// reader through pages of its choosing.
func TestAForeignCarrierMovesNoCursor(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	one := h.vault()
	r := h.must("org", "vault", "create", h.group, "-name", "other")
	m := vaultLine.FindStringSubmatch(r.stdout)
	if m == nil {
		t.Fatalf("a second vault:\n%s", r.stdout)
	}
	other := m[1]
	h.mustIn("org", "one", "-vault", one, "put", "db/password")
	otherID, _ := vread.Hex32(other)
	// The other vault's carriers, by identifier.
	type foreign struct {
		id  string
		out testhost.Output
	}
	var drip []foreign
	for _, name := range []string{"a", "b", "c", "d", "e", "f"} {
		h.mustIn("org", "x", "-vault", other, "put", name)
		id, _ := secrec.SecretID(otherID, name)
		q, err := secrec.ParseQuery([]byte(fmt.Sprintf(`{"crypt":%q,"org":%q,"vault":%q,"secret":%q}`, h.crypt, h.env["BSECRET_ORG"], other, hex.EncodeToString(id[:]))))
		if err != nil {
			t.Fatal(err)
		}
		outs, err := h.a.Answer(q)
		if err != nil || len(outs) != 1 {
			t.Fatalf("the other vault's carrier of %s: %d %v", name, len(outs), err)
		}
		drip = append(drip, foreign{hex.EncodeToString(id[:]), outs[0]})
	}
	sort.Slice(drip, func(i, j int) bool { return drip[i].id < drip[j].id })
	// Host a adds, to every page of the first vault's set, the next of the
	// other vault's carriers past the cursor it was given.
	h.a.Rewrite = func(q *secrec.Question, outs []testhost.Output) []testhost.Output {
		if q.Members["secretsOf"] != one {
			return outs
		}
		for _, f := range drip {
			if f.id > q.Members["after"] {
				return append(outs, f.out)
			}
		}
		return outs
	}
	before := h.a.Questions("secrets") + h.a.Questions("secrets-after")
	r = h.run("alice", "", "-vault", one, "list")
	if !strings.Contains(r.stdout, "db/password  version 1") || !strings.Contains(r.stderr, "another owner or vault") {
		t.Fatalf("list: exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	if asked := h.a.Questions("secrets") + h.a.Questions("secrets-after") - before; asked != 2 {
		t.Fatalf("the host walked the reader through %d pages", asked)
	}
}

// The kill switch reaches every crypt: a funding tree is the identity's,
// and funds versions in every crypt the identity publishes in.
func TestKillReachesEveryCrypt(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	one := h.vault()
	h.put("db/password", "one")
	first := h.crypt
	m := cryptLine.FindStringSubmatch(h.must("org", "crypt", "new", "example").stdout)
	if m == nil {
		t.Fatal("a second crypt")
	}
	second := m[1]
	h.a.Carry(second)
	h.b.Carry(second)
	r := h.must("org", "-crypt", second, "vault", "create", h.group, "-name", "other")
	other := vaultLine.FindStringSubmatch(r.stdout)[1]
	h.mustIn("org", "two", "-crypt", second, "-vault", other, "put", "api/token")
	if r := h.must("alice", "-crypt", second, "-vault", other, "get", "api/token"); r.stdout != "two" {
		t.Fatalf("alice in the second crypt: %q\n%s", r.stdout, r.stderr)
	}
	r = h.must("org", "kill", "-confirm", "KILL", "-yes")
	if !strings.Contains(r.stdout, "killed  ") {
		t.Fatalf("kill:\n%s\n%s", r.stdout, r.stderr)
	}
	// The hosts of both crypts hold the sweep: neither answers a carrier.
	h.want(h.run("alice", "", "-crypt", first, "-vault", one, "get", "db/password"), exitIncomplete, "no host answers its carrier")
	h.want(h.run("alice", "", "-crypt", second, "-vault", other, "get", "api/token"), exitIncomplete, "no host answers its carrier")
}

// An output of a tree that another instance of the tooling already swept
// does not make the kill switch's sweep of the rest fail for good: it is
// left out, and the transaction that spends it is taken as its sweep.
func TestKillPassesOverASpentOutput(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	h.put("api/token", "tok")
	copyHome(t, filepath.Join(h.dir, "org"), filepath.Join(h.dir, "org2"))
	h.sweepVersionAs("org2", 1)
	r := h.must("org", "kill", "-confirm", "KILL", "-yes")
	if !strings.Contains(r.stdout, "killed  ") || !strings.Contains(r.stderr, "already spent by") || !strings.Contains(r.stderr, "taken as their sweep") {
		t.Fatalf("kill with an output already swept:\n%s\n%s", r.stdout, r.stderr)
	}
	h.want(h.run("alice", "", "get", "api/token"), exitIncomplete, "no host answers its carrier")
	if r := h.must("org", "kill", "-confirm", "KILL"); !strings.Contains(r.stdout, "0 tree(s) to sweep") {
		t.Fatalf("after the kill:\n%s", r.stdout)
	}
}

// Work an earlier command left unfinished does not stop the kill switch.
func TestKillIsNotBlockedByOldWork(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	carrier := func(tx *transaction.Transaction) bool { return tx.LockTime != 0 }
	h.a.Drop, h.b.Drop = carrier, carrier
	h.want(h.run("org", "two", "put", "db/password"), exitUsage, "it is persisted")
	r := h.must("org", "kill", "-confirm", "KILL", "-yes")
	if !strings.Contains(r.stdout, "killed  ") || !strings.Contains(r.stderr, "is left for the next command") {
		t.Fatalf("kill behind an object no host takes:\n%s\n%s", r.stdout, r.stderr)
	}
	h.want(h.run("alice", "", "get", "db/password"), exitIncomplete, "no host answers its carrier")
}

// tipOf is the txid of the latest token of a vault, as its owner shows it.
func (h *harness) tipOf(vault string) string {
	h.t.Helper()
	tip := ""
	for _, l := range strings.Split(h.must("org", "-vault", vault, "vault", "show").stdout, "\n") {
		if strings.HasPrefix(l, "token   seq ") {
			tip = strings.Fields(l)[3]
		}
	}
	if tip == "" {
		h.t.Fatal("vault show printed no token")
	}
	return tip
}

// A transition of one vault that was beaten to the chain does not keep the
// rest of what the home owes from being finished: a token of another vault
// that is mined and not yet published is published by the same run.
func TestALostTransitionDoesNotStopOtherWork(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	one := h.vault()
	other := vaultLine.FindStringSubmatch(h.must("org", "vault", "create", h.group, "-name", "other").stdout)[1]
	h.mustIn("org", "one", "-vault", one, "put", "db/password")
	h.mustIn("org", "tok", "-vault", other, "put", "api/token")
	// A second home of the organisation, with coin and funding trees of
	// its own, caught up by sync.
	h.identity("org2", true, "-borg", h.borg.Home)
	h.must("org2", "sync")
	tipA, tipB := h.tipOf(one), h.tipOf(other)
	// The first home's transition of the first vault is persisted and not
	// taken by the node; the second home's then takes the vault's tip.
	h.chain.Refuse = func(tx *transaction.Transaction) string {
		for _, in := range tx.Inputs {
			if in.SourceTXID != nil && in.SourceTXID.String() == tipA {
				return "txn-mempool-conflict"
			}
		}
		return ""
	}
	h.want(h.run("org", "ours", "-vault", one, "put", "db/password"), exitUsage, "it is persisted; the next command sends it again")
	h.chain.Refuse = nil
	h.mustIn("org2", "theirs", "-vault", one, "put", "db/password")
	// The second vault's latest token is mined, and no host holds it: the
	// home owes it.
	path := filepath.Join(h.dir, "org", state.File)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	toks := st["vaults"].([]any)[1].(map[string]any)["tokens"].([]any)
	delete(toks[len(toks)-1].(map[string]any), "published")
	out, _ := json.Marshal(st)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	h.a.Forget(tipB)
	h.b.Forget(tipB)
	r := h.run("org", "", "sync")
	if !strings.Contains(r.stderr, "lost: its predecessor is spent by") {
		t.Fatalf("the lost transition: exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	if !h.a.Holds(tipB) || !h.b.Holds(tipB) {
		t.Fatalf("the token the home owed was not published by the run that found a transition lost:\n%s\n%s", r.stdout, r.stderr)
	}
}

// What a command that asks several priced questions pays is bounded in
// all, whatever a host's pages and prices add up to.
func TestABudgetBoundsEveryPage(t *testing.T) {
	b := &budget{per: 20, total: 50}
	for i, want := range []uint64{20, 20, 10} {
		got, err := b.next()
		if err != nil || got != want {
			t.Fatalf("question %d may be paid %d, want %d: %v", i, got, want, err)
		}
		b.paid(got)
	}
	if _, err := b.next(); err == nil || !strings.Contains(err.Error(), "has paid 50 sat") {
		t.Fatalf("past the budget: %v", err)
	}
}

// The audit's budget bounds its first page too, and nothing is paid over
// it.
func TestAnAuditOverItsBudgetPaysNothing(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	h.identity("payee", false)
	h.startPaid("payee", map[string]uint64{"audit": 20})
	h.identity("auditor", true)
	r := h.run("auditor", "", "audit", "-budget", "10")
	if r.code != exitUsage || !strings.Contains(r.stderr, "more than the 10 this command may pay") || strings.Contains(r.stdout, "paid ") {
		t.Fatalf("an audit whose page costs more than its budget: exit %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	if r := h.must("auditor", "audit", "-budget", "20"); !strings.Contains(r.stdout, "paid 20 sat") || !strings.Contains(r.stdout, "audit   OK") {
		t.Fatalf("an audit within its budget:\n%s\n%s", r.stdout, r.stderr)
	}
}

// A coin a run took from the pool and never recorded a spend of (the run
// stopped in between) is found by the next command and put back, when the
// node shows it unspent.
func TestACoinARunTookAndNeverSpentGoesBack(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	// The home as a run that stopped left it: the state records the pool
	// with a coin, and the pool's own file no longer holds it.
	statePath := filepath.Join(h.dir, "org", state.File)
	poolPath := filepath.Join(h.dir, "org", "wallet.json")
	var pool struct {
		Outputs []json.RawMessage `json:"outputs"`
	}
	raw, err := os.ReadFile(poolPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &pool); err != nil || len(pool.Outputs) < 2 {
		t.Fatalf("the pool: %d coins, %v", len(pool.Outputs), err)
	}
	var st map[string]any
	raw, _ = os.ReadFile(statePath)
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	st["taking"] = pool.Outputs
	out, _ := json.Marshal(st)
	if err := os.WriteFile(statePath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	before := len(pool.Outputs)
	pool.Outputs = pool.Outputs[1:]
	out, _ = json.Marshal(pool)
	if err := os.WriteFile(poolPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	r := h.put("db/password", "two")
	if !strings.Contains(r.stderr, "is back in the pool: a run stopped between taking it and recording what spent it") {
		t.Fatalf("the next command:\n%s\n%s", r.stdout, r.stderr)
	}
	raw, _ = os.ReadFile(poolPath)
	if err := json.Unmarshal(raw, &pool); err != nil || len(pool.Outputs) < before {
		t.Fatalf("the pool after: %d coins, %d before the run that stopped, %v", len(pool.Outputs), before, err)
	}
	// A command that ended leaves nothing recorded as being taken.
	raw, _ = os.ReadFile(statePath)
	if strings.Contains(string(raw), `"taking"`) {
		t.Fatal("the journal outlived the command")
	}
}

// A payment is recorded in the home before it is sent: when it reaches the
// host, the payer's state already holds it.
func TestAPaymentIsRecordedBeforeItIsSent(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "one")
	h.identity("payee", false)
	h.startPaid("payee", map[string]uint64{"audit": 20})
	h.identity("auditor", true)
	recorded := -1
	h.paid.OnPayment = func() {
		raw, err := os.ReadFile(filepath.Join(h.dir, "auditor", state.File))
		if err != nil {
			recorded = 0
			return
		}
		var st struct {
			Payments []json.RawMessage `json:"payments"`
		}
		_ = json.Unmarshal(raw, &st)
		recorded = len(st.Payments)
	}
	if r := h.must("auditor", "audit"); !strings.Contains(r.stdout, "paid 20 sat") {
		t.Fatalf("audit:\n%s\n%s", r.stdout, r.stderr)
	}
	if recorded != 1 {
		t.Fatalf("when the payment reached the host the payer's home recorded %d payment(s)", recorded)
	}
}

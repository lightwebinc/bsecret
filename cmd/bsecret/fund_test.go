package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/p2pkh"
)

var fundLine = regexp.MustCompile(`(?m)^fund address (\S+) `)

// TestFundImportsAPayment: a payment from a wallet of the user's own is
// imported by its BEEF before it mines (held back), by txid once it has,
// and a payment that pays someone else is refused.
func TestFundImportsAPayment(t *testing.T) {
	h := newHarness(t)
	r := h.must("bob", "init")
	m := fundLine.FindStringSubmatch(r.stdout)
	if m == nil {
		t.Fatalf("init printed no fund address:\n%s", r.stdout)
	}
	fundAddr, err := script.NewAddressFromString(m[1])
	if err != nil {
		t.Fatal(err)
	}
	fund, err := p2pkh.Lock(fundAddr)
	if err != nil {
		t.Fatal(err)
	}

	// The user's own wallet: a key with a mature coin.
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	own, err := script.NewAddressFromPublicKey(key.PubKey(), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.chain.Generate(1, own.AddressString); err != nil {
		t.Fatal(err)
	}
	var coin *transaction.Transaction
	for _, id := range h.chain.Txids() {
		if tx := h.chain.Tx(id); tx.IsCoinbase() && tx.Outputs[0].LockingScript.Equals(mustLock(t, own)) {
			coin = tx
		}
	}
	if coin == nil {
		t.Fatal("no coinbase to the wallet's key")
	}
	other, _ := ec.NewPrivateKey()
	otherAddr, _ := script.NewAddressFromPublicKey(other.PubKey(), false)
	if _, err := h.chain.Generate(100, otherAddr.AddressString); err != nil {
		t.Fatal(err)
	}
	mp, _, _ := h.chain.Proof(coin.TxID().String())
	coin.MerklePath = mp

	pay := transaction.NewTransaction()
	unlock, err := p2pkh.Unlock(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pay.AddInputFrom(coin.TxID().String(), 0, coin.Outputs[0].LockingScript.String(), coin.Outputs[0].Satoshis, unlock); err != nil {
		t.Fatal(err)
	}
	pay.Inputs[0].SourceTransaction = coin
	pay.AddOutput(&transaction.TransactionOutput{Satoshis: 100000, LockingScript: fund})
	pay.AddOutput(&transaction.TransactionOutput{Satoshis: coin.Outputs[0].Satoshis - 100000 - 1000, LockingScript: mustLock(t, otherAddr)})
	if err := pay.Sign(); err != nil {
		t.Fatal(err)
	}
	beef, err := pay.BEEFHex()
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(h.dir, "payment.beef")
	if err := os.WriteFile(file, []byte(beef), 0o600); err != nil {
		t.Fatal(err)
	}
	payID := pay.TxID().String()

	// Not mined yet: the chain holds it back from a block.
	h.chain.SetHold(true)
	h.want(h.run("bob", "", "fund", "-txid", payID), exitIncomplete, "is not known to the chain view")
	h.want(h.run("bob", "", "fund", "-beef", file, "-refuse-unmined"), exitRefused, "has not mined yet")
	h.env["BSECRET_FUND_UNMINED"] = "refuse"
	h.want(h.run("bob", "", "fund", "-beef", file), exitRefused, "unmined payments are refused")
	delete(h.env, "BSECRET_FUND_UNMINED")
	r = h.run("bob", beef, "fund", "-beef", "-")
	h.want(r, exitOK, "not mined yet: held back until it mines")
	if !strings.Contains(r.stdout, "100000 sat") || h.chain.Mined(payID) || h.chain.Waiting() != 1 || !strings.Contains(r.stderr, "broadcast through rpc:") {
		t.Fatalf("fund -beef:\n%s\n%s", r.stdout, r.stderr)
	}
	h.want(h.run("bob", "", "fund", "-txid", payID), exitIncomplete, "has not mined yet")
	if r := h.must("bob", "doctor"); !strings.Contains(r.stdout, "change from 1 transaction(s) held until mined") {
		t.Fatalf("doctor:\n%s", r.stdout)
	}
	h.chain.Mine()

	// Mined: by txid, and the outputs held back are proven.
	r = h.must("bob", "fund", "-txid", payID)
	if !strings.Contains(r.stdout, "mined at height") || !strings.Contains(r.stderr, "were in the pool already") {
		t.Fatalf("fund -txid:\n%s\n%s", r.stdout, r.stderr)
	}
	if r := h.must("bob", "doctor"); strings.Contains(r.stdout, "held until mined") || !strings.Contains(r.stdout, "pool        1 output(s), 100000 sat") {
		t.Fatalf("doctor after the import:\n%s", r.stdout)
	}

	// A mined payment to somebody else pays nothing to the fund address.
	h.want(h.run("bob", "", "fund", "-txid", coin.TxID().String()), exitUsage, "pays nothing to the fund address")
}

func mustLock(t *testing.T, a *script.Address) *script.Script {
	t.Helper()
	s, err := p2pkh.Lock(a)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The fee policy is the network rate unless configured, and a live policy
// needs a broadcaster to ask.
func TestFeePolicyIsConfigured(t *testing.T) {
	h := newHarness(t)
	h.must("bob", "init")
	if r := h.must("bob", "doctor"); !strings.Contains(r.stdout, "fee         100/1000 sat/bytes, floor 250 sat (static)") {
		t.Fatalf("doctor:\n%s", r.stdout)
	}
	if r := h.must("bob", "-fee-rate", "1/1", "-fee-floor", "1", "doctor"); !strings.Contains(r.stdout, "fee         1/1 sat/bytes, floor 1 sat (static)") {
		t.Fatalf("doctor -fee-rate:\n%s", r.stdout)
	}
	if r := h.must("bob", "-fee-source", "arc", "doctor"); !strings.Contains(r.stdout, "fee         arc policy: fee_source arc reads a broadcaster's policy") {
		t.Fatalf("doctor -fee-source arc:\n%s", r.stdout)
	}
	h.want(h.run("bob", "", "-fee-rate", "fast", "doctor"), exitUsage, "is not a rate SATS/BYTES")
}

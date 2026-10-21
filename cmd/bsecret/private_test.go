package main

import (
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/lightwebinc/bsecret/internal/testhost"
)

// A private crypt: its hosts answer every question about it only over
// BRC-104, to the organization and its group's members. A member reads and
// the owner writes with lookup_auth on; without it, or as a stranger,
// nothing is answered.
func TestPrivateCryptIsAskedOverBRC104(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.put("db/password", "hunter2")
	allowed := map[string]bool{h.env["BSECRET_ORG"]: true}
	for _, m := range []string{"alice", "bob", "carol"} {
		allowed[hex.EncodeToString(h.keys[m])] = true
	}
	serve := func(host *testhost.Host, seed byte) string {
		k, _ := ec.PrivateKeyFromBytes([]byte{seed, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31})
		s := httptest.NewServer(testhost.NewPrivate(host, k, h.crypt, func(_, id string) bool { return allowed[id] }))
		t.Cleanup(s.Close)
		return s.URL
	}
	pa, pb := serve(h.a, 0x41), serve(h.b, 0x42)
	// The group's hall stays on the hosts' own lookup; the crypt's
	// questions go to the routes.
	h.env["BSECRET_HALL_HOSTS"] = h.aS.URL + "," + h.bS.URL
	h.env["BSECRET_HOSTS"] = pa + "," + pb

	// Without BRC-104 the hosts refuse every question about the crypt.
	h.want(h.run("alice", "", "get", "db/password"), exitIncomplete, "ask over BRC-104: crypt")

	h.env["BSECRET_LOOKUP_AUTH"] = "on"
	if r := h.must("alice", "get", "db/password"); r.stdout != "hunter2" || !strings.Contains(r.stderr, "anchored, current") {
		t.Fatalf("a member over BRC-104: %q\n%s", r.stdout, r.stderr)
	}
	// The owner writes: every confirmation at the hosts is asked over
	// BRC-104 as the organization.
	h.put("db/password", "hunter3")
	if r := h.must("bob", "get", "db/password"); r.stdout != "hunter3" {
		t.Fatalf("bob: %q\n%s", r.stdout, r.stderr)
	}
	// A key the hosts do not serve the crypt to.
	h.identity("mallory", false)
	h.want(h.run("mallory", "", "get", "db/password"), exitIncomplete, "not served to this key")
	h.want(h.run("mallory", "", "audit", "-free"), exitIncomplete, "not served to this key")
	// lookup_auth asks as the home's identity: a reader with no home has none.
	r := h.run("nobody", "", "-vault", strings.Repeat("ab", 32), "get", "db/password")
	h.want(r, exitUsage, "lookup_auth asks the hosts as this home's identity")
	h.env["BSECRET_LOOKUP_AUTH"] = "sometimes"
	h.want(h.run("alice", "", "get", "db/password"), exitUsage, "lookup_auth must be on or off")
}

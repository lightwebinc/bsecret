package main

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lightwebinc/bcommon/bwallet"
	"github.com/lightwebinc/bcommon/wirewallet"

	"github.com/lightwebinc/bsecret/internal/engine"
)

// serveWallet serves the embedded wallet of the home name over the wallet
// wire, as a hardware module's or a remote signer's local endpoint would,
// and returns the wallet setting that names it.
func (h *harness) serveWallet(name string) string {
	h.t.Helper()
	e, err := bwallet.Open(filepath.Join(h.dir, name), engine.Profile)
	if err != nil {
		h.t.Fatal(err)
	}
	s := httptest.NewServer(wirewallet.Serve(e))
	h.t.Cleanup(s.Close)
	return "wire:" + s.URL
}

// The organization's key in a wallet of its own: a home that holds no key
// creates a vault, writes, rotates after a removal (the new epoch's key
// opened through the wallet, as the releaser of borg's wrap to the signer
// key) and reads as the owner, every signature and decryption asked of the
// wallet over the wire.
func TestTheOrganizationKeyInAWalletOfItsOwn(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	org := h.organization()
	for _, m := range []string{"alice", "bob", "carol"} {
		h.identity(m, false)
	}
	gid, err := h.borg.CreateGroup("engineering", h.keys["alice"], h.keys["bob"], h.keys["carol"])
	if err != nil {
		t.Fatal(err)
	}
	h.group = gid
	w := h.serveWallet("org")
	hsm := func(args ...string) []string { return append([]string{"-wallet", w}, args...) }

	r := h.must("hsm", hsm("init")...)
	if !strings.Contains(r.stdout, "identity     "+org) || !strings.Contains(r.stdout, "around the identity key of the wallet at") {
		t.Fatalf("init:\n%s\n%s", r.stdout, r.stderr)
	}
	h.must("hsm", hsm("fund", "-blocks", "102")...)
	if r := h.must("hsm", hsm("doctor")...); !strings.Contains(r.stdout, "wallet      ") || !strings.Contains(r.stdout, "identity    "+org) {
		t.Fatalf("doctor:\n%s", r.stdout)
	}
	r = h.must("hsm", hsm("vault", "create", gid, "-name", "ops")...)
	if vaultLine.FindStringSubmatch(r.stdout) == nil {
		t.Fatalf("vault create:\n%s\n%s", r.stdout, r.stderr)
	}
	h.mustIn("hsm", "hunter2", hsm("put", "db/password")...)
	h.mustIn("hsm", "tok-1", hsm("put", "api/token")...)
	if r := h.must("alice", "get", "db/password"); r.stdout != "hunter2" {
		t.Fatalf("alice: %q\n%s", r.stdout, r.stderr)
	}
	if r := h.must("hsm", hsm("get", "api/token")...); r.stdout != "tok-1" || !strings.Contains(r.stderr, "read as the owner") {
		t.Fatalf("the owner's read: %q\n%s", r.stdout, r.stderr)
	}
	// A removal, and the rotation: the new epoch's key comes through the
	// wallet.
	if err := h.borg.Remove(h.group, h.keys["bob"]); err != nil {
		t.Fatal(err)
	}
	r = h.must("hsm", hsm("rotate", "-set", "db/password="+h.file("new", "correct horse"), "-same-all")...)
	if !strings.Contains(r.stdout, "epoch   1 acknowledged") || !strings.Contains(r.stdout, "settled at epoch 1") {
		t.Fatalf("rotate:\n%s\n%s", r.stdout, r.stderr)
	}
	if r := h.must("carol", "get", "db/password"); r.stdout != "correct horse" {
		t.Fatalf("carol after the rotation: %q\n%s", r.stdout, r.stderr)
	}
	h.want(h.run("bob", "", "get", "db/password"), exitRefused, "undecryptable")

	// The home is held to the identity it was made around.
	h.want(h.run("hsm", "", "-wallet", h.serveWallet("alice"), "doctor"), exitOK, "it is not this home's wallet")
	h.want(h.run("hsm", "x", "-wallet", h.serveWallet("alice"), "put", "db/password"), exitRefused, "it is not this home's wallet")
	// Without the setting, the home says where its key is.
	h.want(h.run("hsm", "x", "put", "db/password"), exitUsage, "keeps its key in a wallet of its own")
	// A wallet that is not on this machine, and a key copied in, are refused.
	h.want(h.run("hsm", "", "-wallet", "wire:http://192.0.2.1:3321", "doctor"), exitUsage, "must be loopback")
	h.want(h.run("other", "", "-wallet", w, "init", "-borg", h.borg.Home), exitUsage, "a home's key is in one place")
	h.want(h.run("org", "", "-wallet", w, "init"), exitUsage, "holds an embedded key")
	// The priced classes pay through an embedded wallet.
	h.want(h.run("hsm", "", "-wallet", w, "-org", org, "history", "db/password", "-at", "http://127.0.0.1:1"), exitUsage, "a wallet of its own")
}

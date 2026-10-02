package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/lightwebinc/bsecret/internal/config"
	"github.com/lightwebinc/bsecret/internal/engine"
	"github.com/lightwebinc/bsecret/internal/limits"
	"github.com/lightwebinc/bsecret/internal/testhost"
)

func init() {
	poll = 5 * time.Millisecond
	engine.Retries = []time.Duration{time.Millisecond}
	limits.Retries = engine.Retries
	limits.PlaneWait = []time.Duration{time.Millisecond}
	// A token changes at most 8 secrets here, so that a vault of a few
	// takes several tokens; the record bound of 64 is held by the engine's
	// and the codec's own tests.
	engine.MaxChanges = 8
}

// harness is a local chain, two stand-in hosts behind a stand-in plane, a
// stand-in organisation's borg tooling, and the environment that points
// the command at them. Each identity is a home of its own.
type harness struct {
	t      *testing.T
	dir    string
	chain  *testhost.Chain
	a, b   *testhost.Host
	chainS *httptest.Server
	aS, bS *httptest.Server
	planeS *httptest.Server
	plane  *testhost.Plane
	paid   *testhost.Paid
	paidS  *httptest.Server
	borg   *testhost.Borg
	env    map[string]string
	crypt  string
	group  string
	keys   map[string][]byte

	mu sync.Mutex
	// onSend, when set, runs once, before the chain takes the next
	// transaction a client sends.
	onSend func()
}

// serveChain is the chain, with the onSend hook in front of it.
func (h *harness) serveChain(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/rpc" {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		h.mu.Lock()
		hook := h.onSend
		if hook != nil && bytes.Contains(body, []byte("sendrawtransaction")) {
			h.onSend = nil
		} else {
			hook = nil
		}
		h.mu.Unlock()
		if hook != nil {
			hook()
		}
	}
	h.chain.ServeHTTP(w, r)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, dir: t.TempDir(), chain: testhost.NewChain(700), keys: map[string][]byte{}}
	h.a, h.b = testhost.NewHost(h.chain), testhost.NewHost(h.chain)
	h.chainS = httptest.NewServer(http.HandlerFunc(h.serveChain))
	h.aS, h.bS = httptest.NewServer(h.a), httptest.NewServer(h.b)
	h.plane = &testhost.Plane{Hosts: []http.Handler{h.a, h.b}}
	h.planeS = httptest.NewServer(h.plane)
	for _, s := range []*httptest.Server{h.chainS, h.aS, h.bS, h.planeS} {
		t.Cleanup(s.Close)
	}
	h.env = map[string]string{
		"BSECRET_NETWORK":    "regtest",
		"BSECRET_ASSET":      h.chainS.URL,
		"BSECRET_RPC":        h.chainS.URL + "/rpc",
		"BSECRET_SETTLE":     "rpc:" + h.chainS.URL + "/rpc",
		"BSECRET_FACADE":     h.planeS.URL,
		"BSECRET_HOSTS":      h.aS.URL + "," + h.bS.URL,
		"BSECRET_HEADER_URL": h.chainS.URL,
		"BSECRET_DELAY":      "0s",
		"BSECRET_TREE_COUNT": "8",
		"BSECRET_CONTENT":    filepath.Join(h.dir, "content"),
		"LANG":               "C.UTF-8",
	}
	return h
}

type result struct {
	code           int
	stdout, stderr string
}

// run runs the command as the identity whose home is name.
func (h *harness) run(name, stdin string, args ...string) result {
	h.t.Helper()
	var out, errb bytes.Buffer
	env := func(k string) string {
		if k == "BSECRET_HOME" {
			return filepath.Join(h.dir, name)
		}
		return h.env[k]
	}
	t0 := time.Now()
	code := run(context.Background(), args, strings.NewReader(stdin), &out, &errb, env)
	if os.Getenv("BSECRET_TEST_TIMING") != "" {
		h.t.Logf("%8s %s %v", time.Since(t0).Round(time.Millisecond), name, args)
	}
	return result{code, out.String(), errb.String()}
}

// must runs a command that must exit 0.
func (h *harness) must(name string, args ...string) result {
	h.t.Helper()
	return h.mustIn(name, "", args...)
}

// mustIn is must with standard input.
func (h *harness) mustIn(name, stdin string, args ...string) result {
	h.t.Helper()
	r := h.run(name, stdin, args...)
	if r.code != 0 {
		h.t.Fatalf("%s: bsecret %s: exit %d\nstdout:\n%s\nstderr:\n%s", name, strings.Join(args, " "), r.code, r.stdout, r.stderr)
	}
	return r
}

func (h *harness) want(r result, code int, has string) {
	h.t.Helper()
	if r.code != code || !strings.Contains(r.stderr+r.stdout, has) {
		h.t.Fatalf("exit %d, want %d with %q\nstdout:\n%s\nstderr:\n%s", r.code, code, has, r.stdout, r.stderr)
	}
}

var (
	identityLine = regexp.MustCompile(`(?m)^identity     ([0-9a-f]{66})$`)
	cryptLine    = regexp.MustCompile(`(?m)^crypt ([a-z_]+)$`)
	vaultLine    = regexp.MustCompile(`(?m)^vault   ([0-9a-f]{64})$`)
)

// identity initialises a home, funds it when fund is set, and returns its
// identity key.
func (h *harness) identity(name string, fund bool, args ...string) string {
	h.t.Helper()
	r := h.must(name, append([]string{"init"}, args...)...)
	id := identityLine.FindStringSubmatch(r.stdout)
	if id == nil {
		h.t.Fatalf("init printed no identity:\n%s", r.stdout)
	}
	if fund {
		h.must(name, "fund", "-blocks", "102")
	}
	k, _ := hex.DecodeString(id[1])
	h.keys[name] = k
	return id[1]
}

// organisation makes the organisation: its borg home (the stand-in
// tooling, which funds itself and creates the hall), and the bsecret home
// "org" made around that home's identity; then a crypt both hosts carry.
func (h *harness) organisation() string {
	h.t.Helper()
	borg, err := testhost.NewBorg(filepath.Join(h.dir, "borg-org"), h.chainS.URL, h.a, h.b)
	if err != nil {
		h.t.Fatal(err)
	}
	h.borg = borg
	org := h.identity("org", true, "-borg", borg.Home)
	if org != borg.Identity() {
		h.t.Fatalf("the bsecret home's identity %s is not the borg home's %s", org, borg.Identity())
	}
	r := h.must("org", "crypt", "new", "example")
	m := cryptLine.FindStringSubmatch(r.stdout)
	if m == nil || !strings.Contains(r.stdout, "host  BSECRET_CRYPTS="+m[1]) {
		h.t.Fatalf("crypt new:\n%s", r.stdout)
	}
	h.crypt = m[1]
	h.a.Carry(h.crypt)
	h.b.Carry(h.crypt)
	h.env["BSECRET_CRYPT"] = h.crypt
	h.env["BSECRET_HALL"] = borg.Hall
	h.env["BSECRET_ORG"] = org
	return org
}

// vault makes the organisation, three members (alice, bob, carol) in one
// group, and a vault keyed to it, and returns the vault's identifier.
func (h *harness) vault(args ...string) string {
	h.t.Helper()
	h.organisation()
	for _, m := range []string{"alice", "bob", "carol"} {
		h.identity(m, false)
	}
	gid, err := h.borg.CreateGroup("engineering", h.keys["alice"], h.keys["bob"], h.keys["carol"])
	if err != nil {
		h.t.Fatal(err)
	}
	h.group = gid
	r := h.must("org", append([]string{"vault", "create", gid, "-name", "ops"}, args...)...)
	m := vaultLine.FindStringSubmatch(r.stdout)
	if m == nil {
		h.t.Fatalf("vault create:\n%s\n%s", r.stdout, r.stderr)
	}
	return m[1]
}

// put writes a secret as the organisation.
func (h *harness) put(name, value string, args ...string) result {
	h.t.Helper()
	return h.mustIn("org", value, append([]string{"put", name}, args...)...)
}

// startPaid serves host a's terms route, paid to the home name's identity,
// with the priceable classes priced, and configures paid_host.
func (h *harness) startPaid(name string, prices map[string]uint64) {
	h.t.Helper()
	keyFile := filepath.Join(h.dir, name+".payee")
	h.must(name, "payee", "key", "-out", keyFile)
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		h.t.Fatal(err)
	}
	k, err := ec.PrivateKeyFromHex(strings.TrimSpace(strings.TrimPrefix(string(raw), "BSECRET_PAYEE_KEY=")))
	if err != nil {
		h.t.Fatal(err)
	}
	h.a.Priced = true
	h.paid = testhost.NewPaid(h.a, k, prices)
	h.paidS = httptest.NewServer(h.paid)
	h.t.Cleanup(h.paidS.Close)
	h.env["BSECRET_PAID_HOST"] = h.paidS.URL
}

// file writes a file in the harness's directory and returns its path.
func (h *harness) file(name, content string) string {
	h.t.Helper()
	p := filepath.Join(h.dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		h.t.Fatal(err)
	}
	return p
}

// global is the command's resolved settings for the home name, for a test
// that drives a command function or the engine directly.
func (h *harness) global(name string) (*global, *bytes.Buffer, *bytes.Buffer) {
	h.t.Helper()
	env := func(k string) string {
		if k == "BSECRET_HOME" {
			return filepath.Join(h.dir, name)
		}
		return h.env[k]
	}
	cfg, err := config.Load(config.Path("", env), env)
	if err != nil {
		h.t.Fatal(err)
	}
	var out, errb bytes.Buffer
	return &global{cfg: cfg, stdin: strings.NewReader(""), stdout: &out, stderr: &errb, getenv: env}, &out, &errb
}

func bare(t *testing.T, env map[string]string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, strings.NewReader(""), &out, &errb, func(k string) string { return env[k] })
	return result{code, out.String(), errb.String()}
}

func TestUsageAndExitCodes(t *testing.T) {
	t.Parallel()
	home := filepath.Join(t.TempDir(), "home")
	env := map[string]string{"BSECRET_HOME": home, "BSECRET_NETWORK": "regtest"}
	if r := bare(t, env); r.code != exitUsage || !strings.Contains(r.stderr, "usage: bsecret") {
		t.Fatalf("no command: %d\n%s", r.code, r.stderr)
	}
	if r := bare(t, env, "help"); r.code != exitOK || !strings.Contains(r.stdout, "rotate") || !strings.Contains(r.stdout, "Exit codes: 0 done or") {
		t.Fatalf("help: %d\n%s", r.code, r.stdout)
	}
	for _, args := range [][]string{{"-version"}, {"version"}} {
		if r := bare(t, env, args...); r.code != exitOK || r.stdout != "bsecret dev\n" {
			t.Fatalf("%v: %d %q", args, r.code, r.stdout)
		}
	}
	if r := bare(t, env, "frobnicate\x1b[2J"); r.code != exitUsage || !strings.Contains(r.stderr, "unknown command") || strings.Contains(r.stderr, "\x1b") {
		t.Fatalf("an unknown command: %d %q", r.code, r.stderr)
	}
	// Every command has help, and help exits 0.
	for name := range commands {
		if r := bare(t, env, name, "-h"); r.code != exitOK || !strings.Contains(r.stderr, "usage: bsecret "+name) {
			t.Errorf("%s -h: exit %d\n%s", name, r.code, r.stderr)
		}
		if !strings.Contains(usageText, "\n  "+name) {
			t.Errorf("the usage text lacks %s", name)
		}
	}
	// No deployment address has a default: a command that needs one says
	// which, and asks nobody.
	org := "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	vault := strings.Repeat("ab", 32)
	for _, c := range []struct {
		args []string
		has  string
	}{
		{[]string{"get", "x"}, "no header source"},
		{[]string{"-header-url", "http://192.0.2.1", "get", "x"}, "no overlay host configured"},
		{[]string{"-header-url", "http://192.0.2.1", "-hosts", "http://192.0.2.1", "get", "x"}, "no owner"},
		{[]string{"-header-url", "http://192.0.2.1", "-hosts", "http://192.0.2.1", "-org", org, "get", "x"}, "no crypt"},
		{[]string{"-header-url", "woc:main", "get", "x"}, "is the main network but network is regtest"},
		{[]string{"-crypt", "nosuffix", "get", "x"}, "is not a crypt identifier"},
		{[]string{"-org", "zz", "get", "x"}, "is not an identity key"},
		{[]string{"-mode", "multicast", "get", "x"}, "mode must be plane or unicast"},
		{[]string{"put", "x"}, "no value"},
		{[]string{"anchor"}, "bsecret init"},
		{[]string{"terms", "http://192.0.2.1/path"}, "is not an origin"},
		{[]string{"terms"}, "no host to ask"},
		{[]string{"kill"}, "-confirm KILL"},
		{[]string{"vault"}, "vault create <group>"},
		{[]string{"crypt", "new", "Bad_Name"}, "lowercase letters"},
		{[]string{"-header-url", "http://192.0.2.1", "-hosts", "http://192.0.2.1", "-org", org, "-crypt", "example_abcdefghij", "-vault", vault, "get", "Bad Name"}, "breaks the name grammar"},
		{[]string{"rotate", "-set", "noequals"}, "is not NAME=FILE"},
		{[]string{"rotate", "-same", "a", "-retire", "a"}, "more than one of -set, -same and -retire"},
		{[]string{"payee", "key"}, "name a file with -out"},
		{[]string{"sync"}, "no crypt"},
	} {
		if r := bare(t, env, c.args...); r.code != exitUsage || !strings.Contains(r.stderr, c.has) {
			t.Errorf("%v: exit %d, want 2 with %q\n%s", c.args, r.code, c.has, r.stderr)
		}
	}
	// A config file with a key the grammar does not define is refused.
	cfg := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(cfg, []byte("hsots = http://192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := bare(t, env, "-config", cfg, "doctor"); r.code != exitUsage || !strings.Contains(r.stderr, "unknown key") {
		t.Fatalf("a misspelt config key: %d\n%s", r.code, r.stderr)
	}
}

// A home is made around a borg home's identity; nothing else of the borg
// home is read, and the two keep separate coin.
func TestInitAroundABorgHome(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	org := h.organisation()
	r := h.must("org", "init")
	if !strings.Contains(r.stdout, "identity     "+org) || !strings.Contains(r.stderr, "exists; left as it is") {
		t.Fatalf("a second init:\n%s\n%s", r.stdout, r.stderr)
	}
	h.want(h.run("org", "", "init", "-borg", h.borg.Home), exitUsage, "has an identity already")
	h.want(h.run("fresh", "", "init", "-borg", h.borg.Home, "-from", "x"), exitUsage, "exclusive")
	h.want(h.run("fresh", "", "init", "-borg", filepath.Join(h.dir, "nowhere")), exitUsage, "no such file")
	// The home holds an identity file of mode 0600 in a directory of 0700.
	for name, mode := range map[string]os.FileMode{"": 0o700, "identity.json": 0o600} {
		st, err := os.Stat(filepath.Join(h.dir, "org", name))
		if err != nil || st.Mode().Perm() != mode {
			t.Errorf("%q: %v %v", name, st.Mode(), err)
		}
	}
	// The borg home is not written by bsecret: it holds what it held.
	entries, err := os.ReadDir(h.borg.Home)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "identity.json" && e.Name() != "wallet.json" {
			t.Errorf("the borg home holds %s", e.Name())
		}
	}
	// Mining coinbase is for a chain you run.
	h.env["BSECRET_NETWORK"] = "main"
	h.want(h.run("org", "", "fund"), exitUsage, "import a payment with fund -txid")
	h.env["BSECRET_NETWORK"] = "regtest"
	h.want(h.run("org", "", "fund", "-txid", "zz"), exitUsage, "is not a transaction id")
	r = h.must("org", "crypt", "list")
	if strings.TrimSpace(r.stdout) != h.crypt {
		t.Fatalf("crypt list: %q", r.stdout)
	}
	r = h.must("org", "doctor")
	for _, want := range []string{"identity    " + org, "tree        secret: none yet", "mode        plane", "host        " + h.aS.URL + " answering", "crypt       " + h.crypt} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("doctor lacks %q:\n%s", want, r.stdout)
		}
	}
	// A host that is down is said so, and doctor still exits 0.
	h.b.SetDown(true)
	if r := h.must("org", "doctor"); !strings.Contains(r.stdout, h.bS.URL+" answering with an ERROR") {
		t.Fatalf("doctor with a host down:\n%s", r.stdout)
	}
	// The payee key is written once, at mode 0600, and never over a file.
	keyFile := filepath.Join(h.dir, "payee.env")
	h.must("org", "payee", "key", "-out", keyFile)
	if st, err := os.Stat(keyFile); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the payee key file: %v %v", st, err)
	}
	h.want(h.run("org", "", "payee", "key", "-out", keyFile), exitUsage, "never writes over a file")
}

// The organisation writes only once it holds the epoch's key, which it has
// through its signer key: without `borg org signer` the vault is not
// created.
func TestTheOwnerNeedsItsSignerKey(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.organisation()
	h.identity("alice", false)
	h.borg.NoSigner = true
	gid, err := h.borg.CreateGroup("engineering", h.keys["alice"])
	if err != nil {
		t.Fatal(err)
	}
	r := h.run("org", "", "vault", "create", gid, "-name", "ops")
	h.want(r, exitUsage, "borg org signer")
	if len(h.a.Txids("token")) != 0 {
		t.Fatal("a vault was created under an epoch whose key the owner does not hold")
	}
	// By name, once the signer key is a member.
	if err := h.borg.Add(gid, h.borg.Signer()); err != nil {
		t.Fatal(err)
	}
	r = h.must("org", "vault", "create", "engineering", "-name", "ops", "-labels", "prod,staging")
	if !strings.Contains(r.stdout, "labels  prod,staging") || !strings.Contains(r.stdout, "group   "+gid) {
		t.Fatalf("vault create by group name:\n%s", r.stdout)
	}
	h.want(h.run("org", "", "vault", "create", "nosuchgroup", "-name", "x"), exitUsage, "no group named")
	h.want(h.run("org", "", "vault", "create", gid, "-name", "x", "-anchor", "sometimes"), exitUsage, "-anchor is version or interval")
	h.want(h.run("org", "", "vault", "create", gid, "-name", "x", "-labels", "Bad"), exitUsage, "-labels")
	h.want(h.run("org", "", "vault", "create", gid), exitUsage, "-name")
	// Two vaults: a command names one.
	h.must("org", "vault", "create", gid, "-name", "second")
	h.want(h.run("org", "v", "put", "a"), exitUsage, "owns 2 vaults that match")
	h.mustIn("org", "v", "-vault", "second", "put", "a")
	h.want(h.run("alice", "", "get", "a"), exitUsage, "the owner has 2 vaults")
	if r := h.must("alice", "-vault", "second", "get", "a"); r.stdout != "v" {
		t.Fatalf("get from the second vault: %q", r.stdout)
	}
	// The default label of a vault with several labels and no
	// "confidential" must be named.
	h.want(h.run("org", "v", "-vault", "ops", "put", "b"), exitUsage, "name a label")
	h.mustIn("org", "v", "-vault", "ops", "put", "b", "-label", "prod")
}

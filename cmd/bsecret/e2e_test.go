//go:build e2e

package main

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lightwebinc/bsecret/internal/testhost"
)

// The client end to end: the bsecret command and the borg command against
// two local reference overlay hosts, each loading the borg host module and
// the bsecret host module, over a local chain (bcommon's testchain: the
// node's RPC and asset API, and the header source the hosts and both
// commands check proofs against). Nothing leaves the machine.
//
//	make e2e-client REFERENCE_HOST=/path/to/reference-host BORG_MODULE=/path/to/borg-module.js NODE=/path/to/node24
//
// It needs Docker for the hosts' MySQL.

const e2ePassword = "bsecret-e2e"

type refHost struct {
	t     *testing.T
	dir   string
	node  string
	name  string
	env   []string
	proc  *exec.Cmd
	out   *bytes.Buffer
	url   string
	terms string
	state string
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func mysql(t *testing.T) int {
	t.Helper()
	id := docker(t, "run", "-d", "--rm", "-e", "MYSQL_ROOT_PASSWORD="+e2ePassword, "-e", "MYSQL_DATABASE=overlay_a",
		"-p", "127.0.0.1::3306", "--tmpfs", "/var/lib/mysql", "mysql:9")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
	port := docker(t, "port", id, "3306/tcp")
	port = strings.Split(port, "\n")[0]
	p, _ := strconv.Atoi(port[strings.LastIndex(port, ":")+1:])
	for i := 0; i < 120; i++ {
		if exec.Command("docker", "exec", id, "mysql", "-h127.0.0.1", "-uroot", "-p"+e2ePassword, "-e", "create database if not exists overlay_b").Run() == nil {
			return p
		}
		time.Sleep(time.Second)
	}
	t.Fatal("MySQL did not come up")
	return 0
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func (h *refHost) start() {
	h.t.Helper()
	h.out = &bytes.Buffer{}
	h.proc = exec.Command(h.node, filepath.Join(h.dir, "dist", "index.js"))
	h.proc.Env = h.env
	h.proc.Stdout, h.proc.Stderr = h.out, h.out
	if err := h.proc.Start(); err != nil {
		h.t.Fatal(err)
	}
	for i := 0; i < 120; i++ {
		if resp, err := http.Get(h.url + "/readyz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	h.stop()
	h.t.Fatalf("host %s did not become ready:\n%s", h.name, h.out)
}

func (h *refHost) stop() {
	if h.proc == nil || h.proc.Process == nil {
		return
	}
	_ = h.proc.Process.Signal(syscall.SIGTERM)
	_ = h.proc.Wait()
	h.proc = nil
}

// refHosts stages both bundles as a deployment places them (in a modules/
// directory whose only node_modules is the reference host's), starts one
// MySQL and a reference host per name, each carrying the hall and the
// crypt, each with a bsecret terms route pricing the audit and history
// classes, paid to payeeKey, and returns them by name.
func refHosts(t *testing.T, chainURL, hall, crypt, payeeKey string, names ...string) map[string]*refHost {
	t.Helper()
	dir := os.Getenv("BSECRET_E2E_REFERENCE_HOST")
	node := os.Getenv("BSECRET_E2E_NODE")
	if node == "" {
		node = "node"
	}
	staging := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "node_modules"), filepath.Join(staging, "node_modules")); err != nil {
		t.Fatal(err)
	}
	stage := func(name, from string) string {
		raw, err := os.ReadFile(from)
		if err != nil {
			t.Fatalf("the %s host module bundle is not built: %v", name, err)
		}
		module := filepath.Join(staging, "modules", name, name+"-module.js")
		if err := os.MkdirAll(filepath.Dir(module), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(module, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		return module
	}
	borgModule := stage("borg", os.Getenv("BSECRET_E2E_BORG_MODULE"))
	bsecretModule := stage("bsecret", "../../host/bundle/bsecret-module.js")
	db := mysql(t)
	hosts := map[string]*refHost{}
	for _, name := range names {
		port, terms := freePort(t), freePort(t)
		st := filepath.Join(staging, "state-"+name)
		rh := &refHost{t: t, dir: dir, node: node, name: name, url: fmt.Sprintf("http://127.0.0.1:%d", port),
			terms: fmt.Sprintf("http://127.0.0.1:%d", terms), state: st}
		rh.env = []string{
			"PATH=" + os.Getenv("PATH"),
			"OVERLAY_TOPICS=tm_borg_" + hall + ",tm_bsecret_" + crypt,
			"OVERLAY_MODULES=" + borgModule + "," + bsecretModule,
			fmt.Sprintf("OVERLAY_KNEX_URL=mysql://root:%s@127.0.0.1:%d/overlay_%s", e2ePassword, db, name),
			"OVERLAY_CHAIN_TRACKER_URL=" + chainURL,
			"OVERLAY_ADMIN_TOKEN=bsecret-e2e",
			"OVERLAY_LISTEN=127.0.0.1",
			"OVERLAY_PORT=" + strconv.Itoa(port),
			"BORG_HALLS=" + hall,
			"BORG_STATE_DIR=" + filepath.Join(st, "borg"),
			"BSECRET_CRYPTS=" + crypt,
			"BSECRET_STATE_DIR=" + filepath.Join(st, "bsecret"),
			fmt.Sprintf("BSECRET_LISTEN=127.0.0.1:%d", terms),
			"BSECRET_PRICES=history=5,history-after=5,audit=20,audit-after=20",
			"BSECRET_PAYEE_KEY=" + payeeKey,
			"BSECRET_SESSIONS=64",
			"BSECRET_ARCADE_URL=" + chainURL + "/arcade",
			"BSECRET_ASSET_URL=" + chainURL,
		}
		rh.start()
		t.Cleanup(rh.stop)
		hosts[name] = rh
	}
	return hosts
}

// proxy is a reverse proxy to a host, for the plane stand-in.
func proxy(t *testing.T, base string) http.Handler {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	return httputil.NewSingleHostReverseProxy(u)
}

// borgTool runs the borg command, built from the module go.mod pins, each
// identity in a borg home of its own beside its bsecret home.
type borgTool struct {
	t   *testing.T
	bin string
	dir string
	env map[string]string
}

func (b *borgTool) home(name string) string { return filepath.Join(b.dir, "borg-"+name) }

func (b *borgTool) run(name string, args ...string) result {
	b.t.Helper()
	cmd := exec.Command(b.bin, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "BORG_HOME=" + b.home(name)}
	for k, v := range b.env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		b.t.Fatalf("borg %s: %v", strings.Join(args, " "), err)
	}
	return result{code, out.String(), errb.String()}
}

func (b *borgTool) must(name string, args ...string) result {
	b.t.Helper()
	r := b.run(name, args...)
	if r.code != 0 {
		b.t.Fatalf("%s: borg %s: exit %d\nstdout:\n%s\nstderr:\n%s", name, strings.Join(args, " "), r.code, r.stdout, r.stderr)
	}
	return r
}

var (
	borgHallLine  = regexp.MustCompile(`(?m)^hall  ([a-z_]+)$`)
	borgGroupLine = regexp.MustCompile(`(?m)^group   ([0-9a-f]{32})$`)
	paidAudit     = regexp.MustCompile(`(?m)^paid 20 sat to \S+ in ([0-9a-f]{64}) for audit,`)
	windowLine    = regexp.MustCompile(`(?m)^window  epoch (\d+): (\d+) block\(s\) from`)
)

func TestClientE2E(t *testing.T) {
	if os.Getenv("BSECRET_E2E_REFERENCE_HOST") == "" || os.Getenv("BSECRET_E2E_BORG_MODULE") == "" {
		t.Skip("set BSECRET_E2E_REFERENCE_HOST and BSECRET_E2E_BORG_MODULE (make e2e-client REFERENCE_HOST=... BORG_MODULE=...)")
	}
	bin := os.Getenv("BSECRET_E2E_BORG")
	if bin == "" {
		bin = filepath.Join(t.TempDir(), "borg")
		if out, err := exec.Command("go", "build", "-o", bin, "github.com/lightwebinc/borg/cmd/borg").CombinedOutput(); err != nil {
			t.Fatalf("building the borg command from the module go.mod pins: %v\n%s", err, out)
		}
	}
	h := newHarness(t)
	n := 0
	step := func(what string) { n++; t.Logf("ok %2d  %s", n, what) }
	borg := &borgTool{t: t, bin: bin, dir: h.dir, env: map[string]string{
		"BORG_NETWORK": "regtest", "BORG_ASSET": h.chainS.URL, "BORG_RPC": h.chainS.URL + "/rpc", "BORG_SETTLE": "rpc:" + h.chainS.URL + "/rpc",
		"BORG_HEADER_URL": h.chainS.URL, "BORG_DELAY": "0s", "BORG_TREE_COUNT": "8", "LANG": "C.UTF-8"}}

	// Identities: each a borg home, and a bsecret home made around it.
	keys := map[string]string{}
	for _, name := range []string{"org", "alice", "bob", "carol"} {
		r := borg.must(name, "init")
		keys[name] = identityLine.FindStringSubmatch(r.stdout)[1]
		if got := h.identity(name, name == "org", "-borg", borg.home(name)); got != keys[name] {
			t.Fatalf("%s: the bsecret home's identity %s is not the borg home's %s", name, got, keys[name])
		}
	}
	borg.must("org", "fund", "-blocks", "102")
	h.identity("payee", false)
	h.identity("auditor", true)
	hall := borgHallLine.FindStringSubmatch(borg.must("org", "hall", "new", "example").stdout)[1]
	r := h.must("org", "crypt", "new", "example")
	crypt := cryptLine.FindStringSubmatch(r.stdout)[1]
	keyFile := filepath.Join(h.dir, "payee.env")
	h.must("payee", "payee", "key", "-out", keyFile)
	rawKey, _ := os.ReadFile(keyFile)
	payeeKey := strings.TrimSpace(strings.TrimPrefix(string(rawKey), "BSECRET_PAYEE_KEY="))
	step("init: four borg homes and a bsecret home around each identity; a payee and an auditor; hall " + hall + ", crypt " + crypt)

	hosts := refHosts(t, h.chainS.URL, hall, crypt, payeeKey, "a", "b")
	a, b := hosts["a"], hosts["b"]
	for _, want := range []string{"borg module mounted", "bsecret module mounted"} {
		if !strings.Contains(a.out.String(), want) {
			t.Fatalf("host a did not log %q:\n%s", want, a.out)
		}
	}
	plane := httptest.NewServer(&testhost.Plane{Hosts: []http.Handler{proxy(t, a.url), proxy(t, b.url)}})
	t.Cleanup(plane.Close)
	both := a.url + "," + b.url
	for k, v := range map[string]string{"BORG_FACADE": plane.URL, "BORG_HOSTS": both, "BORG_HALL": hall, "BORG_ORG": keys["org"]} {
		borg.env[k] = v
	}
	for k, v := range map[string]string{"BSECRET_FACADE": plane.URL, "BSECRET_HOSTS": both, "BSECRET_CRYPT": crypt, "BSECRET_HALL": hall,
		"BSECRET_ORG": keys["org"], "BSECRET_PAID_HOST": a.terms} {
		h.env[k] = v
	}
	step("two reference hosts, each loading the borg module and the bsecret module, each carrying the hall and the crypt, each pricing audit and history")

	// The organisation and the group are borg's.
	r = borg.must("org", "org", "create", "Example Organisation", "-member", keys["alice"], "-member", keys["bob"], "-member", keys["carol"])
	if strings.Count(r.stdout, "grant   ") != 3 {
		t.Fatalf("borg org create:\n%s\n%s", r.stdout, r.stderr)
	}
	r = borg.must("org", "group", "create", "engineering", "-member", keys["alice"], "-member", keys["bob"], "-member", keys["carol"])
	group := borgGroupLine.FindStringSubmatch(r.stdout)[1]
	// Without the signer key the organisation's tooling holds no epoch key.
	h.want(h.run("org", "", "vault", "create", group, "-name", "ops"), exitUsage, "borg org signer")
	borg.must("org", "org", "signer")
	step("borg: org create, three grants; group create; org signer, so the organisation's tooling opens each epoch's key")

	r = h.must("org", "vault", "create", "engineering", "-name", "ops")
	vault := vaultLine.FindStringSubmatch(r.stdout)[1]
	if !strings.Contains(r.stdout, "group   "+group) || !strings.Contains(r.stdout, "epoch   0") {
		t.Fatalf("vault create:\n%s\n%s", r.stdout, r.stderr)
	}
	step("plane: vault create on the group, named by its name; the first token carries its chain tree")

	values := map[string]string{"db/password": "hunter2", "api/token": "tok-1", "tls/key": "-----BEGIN KEY-----"}
	for name, value := range values {
		r := h.put(name, value)
		if !strings.Contains(r.stdout, "secret  "+name+" version 1") || !strings.Contains(r.stdout, "0 stale, epoch 0") {
			t.Fatalf("put %s:\n%s\n%s", name, r.stdout, r.stderr)
		}
	}
	for _, m := range []string{"alice", "bob", "carol", "org"} {
		for name, value := range values {
			r := h.must(m, "get", name)
			if r.stdout != value || !strings.Contains(r.stderr, "anchored, current") || strings.Contains(r.stderr, "DISAGREES") {
				t.Fatalf("%s get %s: %q\n%s", m, name, r.stdout, r.stderr)
			}
		}
		r := h.must(m, "list")
		if strings.Count(r.stdout, "version 1 label confidential epoch 0") != 3 || strings.Count(r.stderr, "the set's root reproduced") != 2 {
			t.Fatalf("%s list:\n%s\n%s", m, r.stdout, r.stderr)
		}
	}
	step("three secrets put; every member and the owner read each, every check in order; the set's root reproduced at both hosts")

	// Revoke: the removal is borg's, and begins a new epoch.
	h.must("org", "rotate", "-check", "-same-all")
	r = borg.must("org", "org", "remove", keys["bob"], "-group", group)
	if !strings.Contains(r.stdout, "epoch 1 (a new epoch") {
		t.Fatalf("borg org remove:\n%s\n%s", r.stdout, r.stderr)
	}
	r = h.must("alice", "get", "db/password")
	if !strings.Contains(r.stderr, "BEHIND") || !strings.Contains(r.stderr, "EXPOSED") {
		t.Fatalf("a vault behind its group:\n%s", r.stderr)
	}
	h.want(h.run("alice", "", "due"), exitIncomplete, "the group began epoch 1")
	h.want(h.run("org", "x", "put", "db/password"), exitUsage, "BEHIND")
	h.want(h.run("org", "", "rotate"), exitUsage, "3 secret(s) have no choice")
	step("borg removes bob: epoch 1; every reader reports the vault behind and its values exposed; the owner's tooling builds nothing but the acknowledgement, and not without a choice for every secret")

	newPass := h.file("new-password", "correct horse battery staple")
	r = h.must("org", "rotate", "-set", "db/password="+newPass, "-same", "tls/key", "-same", "api/token", "-keep")
	for _, want := range []string{"epoch   1 acknowledged", "rekeyed db/password: a new value", "rekeyed tls/key: the same value", "0 stale, epoch 1", "settled at epoch 1"} {
		if !strings.Contains(r.stdout, want) {
			t.Fatalf("rotate lacks %q:\n%s\n%s", want, r.stdout, r.stderr)
		}
	}
	for _, m := range []string{"alice", "carol", "org"} {
		r := h.must(m, "get", "db/password")
		if r.stdout != "correct horse battery staple" || !strings.Contains(r.stderr, "version 2") || !strings.Contains(r.stderr, "anchored, current") {
			t.Fatalf("%s after the rotation: %q\n%s", m, r.stdout, r.stderr)
		}
	}
	// The removed member: none of the new versions, and still the old ones
	// (kept as history here), which it held the key of.
	for name := range values {
		r := h.run("bob", "", "get", name)
		h.want(r, exitRefused, "undecryptable")
		if r.stdout != "" {
			t.Fatalf("bob read the new %s: %q", name, r.stdout)
		}
	}
	r = h.must("bob", "get", "db/password", "-version", "1")
	if r.stdout != "hunter2" || !strings.Contains(r.stderr, "history: a token of the vault listed it") {
		t.Fatalf("bob and the old version: %q\n%s", r.stdout, r.stderr)
	}
	step("acknowledge and re-key (a new value, two same-value re-keyings): alice and carol read the new versions; bob reads none of them, and still reads the old ones the owner kept")

	// A retirement: the retired secret's versions are swept, and no other
	// secret's history.
	r = h.must("org", "retire", "api/token")
	if !strings.Contains(r.stdout, "retired api/token") || !strings.Contains(r.stdout, "swept   2 version(s)") {
		t.Fatalf("retire:\n%s\n%s", r.stdout, r.stderr)
	}
	h.want(h.run("alice", "", "get", "api/token"), exitRefused, "holds no secret named api/token")
	h.want(h.run("bob", "", "get", "api/token", "-version", "1"), exitIncomplete, "no host answers a carrier")
	if r := h.must("bob", "get", "db/password", "-version", "1"); r.stdout != "hunter2" {
		t.Fatalf("the history of another secret was swept: %q\n%s", r.stdout, r.stderr)
	}
	step("a retirement: both hosts retract every version of the retired secret, which bob can no longer fetch; the history the owner kept of the others stays")

	// The audit: paid, verified from headers, the exposure window reported.
	r = h.must("auditor", "terms")
	if !strings.Contains(r.stdout, "audit          20 sat a question") {
		t.Fatalf("terms:\n%s", r.stdout)
	}
	r = h.must("auditor", "audit")
	pm := paidAudit.FindStringSubmatch(r.stdout)
	win := windowLine.FindStringSubmatch(r.stdout)
	if pm == nil || win == nil || win[1] != "1" || win[2] == "0" || !strings.Contains(r.stdout, "(a member removed): acknowledged at height") ||
		!strings.Contains(r.stdout, "audit   OK: 6 token(s) mined") || strings.Count(r.stdout, "re-keyed at seq 4") != 3 {
		t.Fatalf("audit:\n%s\n%s", r.stdout, r.stderr)
	}
	free := h.must("nobody", "-org", keys["org"], "-vault", vault, "audit", "-free")
	if !strings.Contains(free.stdout, win[0]) || strings.Contains(free.stdout, "paid ") || strings.Contains(free.stderr, "DISAGREES") {
		t.Fatalf("audit -free with no home:\n%s\n%s", free.stdout, free.stderr)
	}
	r = h.must("auditor", "history", "db/password")
	if !strings.Contains(r.stdout, "paid 5 sat to ") || !strings.Contains(r.stdout, "version 2 ") {
		t.Fatalf("history:\n%s\n%s", r.stdout, r.stderr)
	}
	r = h.must("payee", "payee", "settle", filepath.Join(a.state, "bsecret", "payments.jsonl"))
	if !strings.Contains(r.stdout, "2 payment(s) settled, 25 sat") || !h.chain.Mined(pm[1]) {
		t.Fatalf("payee settle:\n%s\n%s", r.stdout, r.stderr)
	}
	step("the audit class paid through its 402 (BRC-104, BRC-105): the trail verified from headers, the exposure window of epoch 1 reported as " + win[2] + " block(s); the same window free, with no home; history paid; the payee settles both")

	// Both hosts agree.
	r = h.must("alice", "list")
	if strings.Count(r.stderr, "the set's root reproduced") != 2 || strings.Contains(r.stderr, "DISAGREES") || strings.Count(r.stdout, "epoch 1") != 2 {
		t.Fatalf("list at both hosts:\n%s\n%s", r.stdout, r.stderr)
	}
	if r := h.must("alice", "fill"); !strings.Contains(r.stdout, "filled  0 object(s) at 0 host(s)") {
		t.Fatalf("fill found the hosts differ:\n%s\n%s", r.stdout, r.stderr)
	}
	show := h.must("alice", "vault", "show")
	if strings.Count(show.stdout, ": consistent") != 6 || !strings.Contains(show.stdout, "state   settled at epoch 1") {
		t.Fatalf("vault show:\n%s\n%s", show.stdout, show.stderr)
	}
	step("both hosts agree: the chain, the set's root reproduced at each, nothing to fill")

	// Restart and restore: host a from its storage and its rows.
	a.stop()
	a.start()
	if strings.Count(a.out.String(), "restored from storage") < 2 {
		t.Fatalf("no restore lines:\n%s", a.out)
	}
	if again := h.must("alice", "vault", "show"); again.stdout != show.stdout || strings.Contains(again.stderr, "DISAGREES") {
		t.Fatalf("after the restart:\n%s\n%s", again.stdout, again.stderr)
	}
	if r := h.must("carol", "get", "db/password"); r.stdout != "correct horse battery staple" {
		t.Fatalf("carol after the restart: %q\n%s", r.stdout, r.stderr)
	}
	h.want(h.run("bob", "", "get", "db/password"), exitRefused, "undecryptable")
	h.want(h.run("bob", "", "get", "api/token", "-version", "1"), exitIncomplete, "no host answers a carrier")
	r = h.must("auditor", "audit")
	if !strings.Contains(r.stdout, win[0]) || !strings.Contains(r.stdout, "audit   OK") {
		t.Fatalf("the audit after the restart:\n%s\n%s", r.stdout, r.stderr)
	}
	step("host a restarted: both modules restored; the same chain and set; the swept versions stay swept; the audit paid and verified again")

	// Unicast: every object to each host.
	h.env["BSECRET_MODE"] = "unicast"
	delete(h.env, "BSECRET_FACADE")
	r = h.put("deploy/key", "unicast-1")
	if strings.Count(r.stdout, "missed 0") != 2 {
		t.Fatalf("unicast tallies:\n%s\n%s", r.stdout, r.stderr)
	}
	if r := h.must("alice", "get", "deploy/key"); r.stdout != "unicast-1" || strings.Contains(r.stderr, "DISAGREES") {
		t.Fatalf("alice in unicast: %q\n%s", r.stdout, r.stderr)
	}
	b.stop()
	h.want(h.run("org", "unicast-2", "put", "deploy/key"), exitUsage, "1 of 2 host(s) took it and the quorum is 2")
	b.start()
	if r := h.must("org", "doctor"); !strings.Contains(r.stdout, "outbox      ") {
		t.Fatalf("doctor:\n%s", r.stdout)
	}
	r = h.put("deploy/key", "unicast-3")
	if !strings.Contains(r.stderr, "publishing what a previous run persisted") {
		t.Fatalf("resume:\n%s\n%s", r.stdout, r.stderr)
	}
	for _, m := range []string{"alice", "carol"} {
		if r := h.must(m, "get", "deploy/key"); r.stdout != "unicast-3" || strings.Contains(r.stderr, "DISAGREES") {
			t.Fatalf("%s after b came back: %q\n%s", m, r.stdout, r.stderr)
		}
	}
	h.want(h.run("bob", "", "get", "deploy/key"), exitRefused, "undecryptable")
	step("unicast: a put reaches both hosts; with b down the carrier stays persisted (exit 2); b back: the next command publishes it first; both agree")

	// A second removal and rotation, in unicast, with the default sweep.
	r = borg.must("org", "org", "remove", keys["carol"], "-group", group)
	if !strings.Contains(r.stdout, "(a new epoch") {
		t.Fatalf("borg org remove carol:\n%s\n%s", r.stdout, r.stderr)
	}
	r = h.must("org", "rotate", "-same-all")
	if !strings.Contains(r.stdout, "acknowledged") || !strings.Contains(r.stdout, "swept   ") {
		t.Fatalf("the second rotation:\n%s\n%s", r.stdout, r.stderr)
	}
	if r := h.must("alice", "get", "db/password"); r.stdout != "correct horse battery staple" || !strings.Contains(r.stderr, "anchored, current") {
		t.Fatalf("alice after the second rotation: %q\n%s", r.stdout, r.stderr)
	}
	h.want(h.run("carol", "", "get", "db/password"), exitRefused, "undecryptable")
	// What the first rotation kept as history is swept now: the removed
	// members can no longer fetch what they could open.
	h.want(h.run("bob", "", "get", "db/password", "-version", "1"), exitIncomplete, "no host answers a carrier")
	h.want(h.run("carol", "", "get", "db/password", "-version", "2"), exitIncomplete, "no host answers a carrier")
	r = h.must("nobody", "-org", keys["org"], "-vault", vault, "audit", "-free")
	if len(windowLine.FindAllString(r.stdout, -1)) != 2 || !strings.Contains(r.stdout, "audit   OK") {
		t.Fatalf("the audit of two removals:\n%s\n%s", r.stdout, r.stderr)
	}
	step("a second removal (carol) and rotation in unicast, swept by default: alice reads, carol does not, and neither removed member can fetch an old version any more; the audit reports a window for each removal")
	t.Logf("e2e client: PASS (%d steps)", n)
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// serveAddrs carries each running daemon's address to the test that
// started it, by home.
var serveAddrs sync.Map

func init() {
	serveReady = func(home, addr string) {
		if ch, ok := serveAddrs.Load(home); ok {
			ch.(chan string) <- addr
		}
	}
}

// daemon is a running bsecret serve.
type daemon struct {
	t      *testing.T
	base   string
	token  string
	cancel context.CancelFunc
	done   chan result
}

// serve starts bsecret serve as the home name and waits until it listens.
func (h *harness) serve(name, token string, args ...string) *daemon {
	h.t.Helper()
	ready := make(chan string, 1)
	home := filepath.Join(h.dir, name)
	serveAddrs.Store(home, ready)
	env := func(k string) string {
		if k == "BSECRET_HOME" {
			return home
		}
		return h.env[k]
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &daemon{t: h.t, token: token, cancel: cancel, done: make(chan result, 1)}
	argv := append([]string{"serve", "-listen", "127.0.0.1:0", "-interval", "1s"}, args...)
	if token != "" {
		argv = append(argv, "-token-file", h.file(name+".token", token+"\n"))
	}
	go func() {
		var out, errb lockedBuffer
		code := run(ctx, argv, strings.NewReader(""), &out, &errb, env)
		d.done <- result{code, out.String(), errb.String()}
	}()
	select {
	case addr := <-ready:
		d.base = "http://" + addr
	case r := <-d.done:
		h.t.Fatalf("serve exited %d before it listened:\n%s\n%s", r.code, r.stdout, r.stderr)
	case <-time.After(30 * time.Second):
		h.t.Fatal("serve did not listen")
	}
	h.t.Cleanup(func() { d.stop() })
	return d
}

// stop stops the daemon and returns how it exited.
func (d *daemon) stop() result {
	d.cancel()
	select {
	case r := <-d.done:
		d.done <- r
		return r
	case <-time.After(30 * time.Second):
		d.t.Fatal("serve did not stop")
		return result{}
	}
}

func (d *daemon) do(method, path string, hdr map[string]string) (int, map[string]any, string) {
	d.t.Helper()
	req, err := http.NewRequest(method, d.base+path, nil)
	if err != nil {
		d.t.Fatal(err)
	}
	if d.token != "" && hdr == nil {
		req.Header.Set("Authorization", "Bearer "+d.token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		d.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return res.StatusCode, m, string(b)
}

// until polls cond until it holds.
func (d *daemon) until(what string, cond func() bool) {
	d.t.Helper()
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if cond() {
			return
		}
	}
	d.t.Fatalf("serve: %s did not happen", what)
}

// lockedBuffer is a buffer two goroutines may use.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func standingOfBody(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	st, ok := m["standing"].(map[string]any)
	if !ok {
		t.Fatalf("no standing in %v", m)
	}
	return st
}

// The daemon serves what it verified, as JSON and in the KV version 2
// shape, to whoever holds its token; it follows the vault on its interval,
// and refuses what get -strict refuses once the group removes a member.
func TestServeServesVerifiedValues(t *testing.T) {
	h := newHarness(t)
	id := h.vault()
	h.put("db/password", "hunter2", "-label", "restricted")
	h.put("api/token", "tok-1")
	h.mustIn("org", "\xff\x00binary", "put", "tls/key")
	d := h.serve("alice", "0123456789abcdef0123")
	d.until("the first walk", func() bool { c, _, _ := d.do("GET", "/healthz", map[string]string{}); return c == http.StatusOK })

	// The token is required, from either header.
	if c, _, _ := d.do("GET", "/secrets/db/password", map[string]string{}); c != http.StatusUnauthorized {
		t.Fatalf("no token: %d", c)
	}
	if c, _, _ := d.do("GET", "/secrets/db/password", map[string]string{"Authorization": "Bearer wrong-token-wrong-token"}); c != http.StatusUnauthorized {
		t.Fatalf("a wrong token: %d", c)
	}
	c, m, body := d.do("GET", "/secrets/db/password", nil)
	if c != http.StatusOK || m["value"] != "hunter2" || m["label"] != "restricted" || m["version"] != float64(1) || m["vault_id"] != id {
		t.Fatalf("JSON: %d %s", c, body)
	}
	if st := standingOfBody(t, m); st["vault"] != "settled" || st["current"] != true || st["anchored"] != true || st["exposed"] != false || st["latest"] != true {
		t.Fatalf("standing: %s", body)
	}
	c, m, body = d.do("GET", "/v1/secret/data/api/token", map[string]string{"X-Vault-Token": d.token})
	data, _ := m["data"].(map[string]any)
	inner, _ := data["data"].(map[string]any)
	meta, _ := data["metadata"].(map[string]any)
	if c != http.StatusOK || inner["value"] != "tok-1" || meta["version"] != float64(1) || meta["destroyed"] != false {
		t.Fatalf("KV version 2: %d %s", c, body)
	}
	if cm, _ := meta["custom_metadata"].(map[string]any); cm["vault_standing"] != "settled" || cm["exposed"] != "false" {
		t.Fatalf("KV custom metadata: %s", body)
	}
	// What a Vault client asks first: the mount is KV version 2.
	c, m, body = d.do("GET", "/v1/sys/internal/ui/mounts/secret/db/password", nil)
	if md, _ := m["data"].(map[string]any); c != 200 || md["type"] != "kv" || md["path"] != "secret/" || md["options"].(map[string]any)["version"] != "2" {
		t.Fatalf("mounts: %d %s", c, body)
	}
	if c, _, _ := d.do("GET", "/v1/sys/internal/ui/mounts/nope/x", nil); c != 404 {
		t.Fatalf("an unknown mount: %d", c)
	}
	// A value that is not UTF-8 is given in base64 only.
	c, m, body = d.do("GET", "/vaults/ops/secrets/tls/key", nil)
	if _, has := m["value"]; c != http.StatusOK || has || m["value_base64"] != "/wBiaW5hcnk=" {
		t.Fatalf("binary: %d %s", c, body)
	}
	for path, want := range map[string]int{
		"/vaults/" + id + "/secrets/api/token": http.StatusOK,
		"/v1/" + id + "/data/db/password":      http.StatusOK,
		"/secrets/no/such":                     http.StatusNotFound,
		"/secrets/Bad Name":                    http.StatusNotFound,
		"/vaults/nope/secrets/api/token":       http.StatusNotFound,
		"/v1/secret/metadata/api/token":        http.StatusNotFound,
	} {
		if c, _, body := d.do("GET", path, nil); c != want {
			t.Errorf("%s: %d, want %d: %s", path, c, want, body)
		}
	}
	c, _, body = d.do("GET", "/status", nil)
	if c != http.StatusOK || !strings.Contains(body, `"secrets":["api/token","db/password","tls/key"]`) || strings.Contains(body, "hunter2") {
		t.Fatalf("status: %d %s", c, body)
	}
	// One home, one command: the daemon holds the home.
	h.want(h.run("alice", "", "get", "db/password"), exitUsage, "another bsecret command is using the home")

	// A new version is served once the next walk reads it.
	h.put("db/password", "hunter3")
	d.until("the new version", func() bool { _, m, _ := d.do("GET", "/secrets/db/password", nil); return m["value"] == "hunter3" })

	// A removal: the vault is behind and every value exposed, which the
	// default policy refuses with the standing and no value.
	if err := h.borg.Remove(h.group, h.keys["bob"]); err != nil {
		t.Fatal(err)
	}
	if c, _, _ := d.do("POST", "/refresh", nil); c != http.StatusAccepted && c != http.StatusTooManyRequests {
		t.Fatalf("refresh: %d", c)
	}
	d.until("the removal", func() bool { c, _, _ := d.do("GET", "/secrets/db/password", nil); return c == http.StatusConflict })
	c, m, body = d.do("GET", "/secrets/db/password", nil)
	if _, has := m["value"]; has || !strings.Contains(body, "exposed") || !strings.Contains(body, "unsettled") || standingOfBody(t, m)["vault"] != "behind" {
		t.Fatalf("refused: %d %s", c, body)
	}
	if c, m, _ := d.do("GET", "/v1/secret/data/db/password", nil); c != http.StatusConflict || m["errors"] == nil {
		t.Fatalf("KV refused: %d %v", c, m)
	}
	_, _, metrics := d.do("GET", "/metrics", nil)
	for _, want := range []string{`bsecret_serve_secrets{vault="` + id + `"} 3`, `bsecret_serve_secrets_exposed{vault="` + id + `"} 3`,
		`bsecret_serve_vault_settled{vault="` + id + `"} 0`, `bsecret_serve_refused_total{condition="exposed"}`, `result="ok"`, `route="secret",code="409"`} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics lack %q:\n%s", want, metrics)
		}
	}
	if r := d.stop(); r.code != exitOK || strings.Contains(r.stderr, "hunter") {
		t.Fatalf("serve exit %d:\n%s", r.code, r.stderr)
	}

	// -once, with nothing refused, reads every value and exits 0; with the
	// default policy a behind vault is incomplete.
	r := h.must("alice", "serve", "-once", "-refuse", "none")
	if !strings.Contains(r.stdout, `"vault": "behind"`) || strings.Contains(r.stdout, "hunter") {
		t.Fatalf("serve -once:\n%s", r.stdout)
	}
	h.want(h.run("alice", "", "serve", "-once"), exitIncomplete, "refused under -refuse")
	// The rotation settles the vault and the values are served again.
	h.must("org", "rotate", "-same-all")
	d = h.serve("alice", "")
	d.until("the settled vault", func() bool { _, m, _ := d.do("GET", "/secrets/api/token", nil); return m["value"] == "tok-1" })
	// The removed member reads nothing keyed after the rotation: each
	// secret is named unread, and nothing is served.
	b := h.serve("bob", "")
	b.until("bob's refusal", func() bool {
		c, m, _ := b.do("GET", "/secrets/api/token", nil)
		return c == http.StatusServiceUnavailable && strings.Contains(m["error"].(string), "undecryptable")
	})
	if _, _, body := b.do("GET", "/status", nil); !strings.Contains(body, "undecryptable") || strings.Contains(body, "tok-1") {
		t.Fatalf("bob's status: %s", body)
	}
}

func TestServeRefusesWhatItCannotServe(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.vault()
	h.want(h.run("alice", "", "serve", "-listen", "0.0.0.0:0"), exitUsage, "is not a loopback address")
	h.want(h.run("alice", "", "serve", "-refuse", "exposed,sometimes"), exitUsage, "-refuse")
	h.want(h.run("alice", "", "serve", "-interval", "10ms"), exitUsage, "at least 1s")
	h.want(h.run("alice", "", "serve", "-token-file", h.file("short", "abc")), exitUsage, "at least 16")
	h.want(h.run("nobody", "", "serve", "-once"), exitUsage, "no home")
	// A vault with no secret is read whole.
	if r := h.must("alice", "serve", "-once"); !strings.Contains(r.stdout, `"ok": true`) {
		t.Fatalf("an empty vault:\n%s", r.stdout)
	}
}

package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/lightwebinc/bcommon/termsafe"

	"github.com/lightwebinc/bsecret/internal/secrec"
	"github.com/lightwebinc/bsecret/internal/state"
	"github.com/lightwebinc/bsecret/internal/vread"
)

const serveHelp = `usage: bsecret serve [-listen ADDR] [-interval DUR] [-refuse LIST] [-token-file FILE] [-vault V]... [-once]

A reader that stays running (docs/usage.md, "Serving"). It holds this home
for its whole life, walks each vault's chain on an interval, reads every
secret in the vault's set with the checks 'get' makes, in the signed
order, and serves the values it verified over HTTP on the loopback
address by default:

  GET /secrets/<name>                  the first vault's secret, as JSON
  GET /vaults/<vault>/secrets/<name>   a vault's secret, as JSON
  GET /v1/<mount>/data/<name>          the same, shaped like Vault's KV
                                       version 2; the mount is "secret" for
                                       the first vault, or a vault's
                                       identifier or display name
  GET /status                          each vault's standing and the names
                                       read, no value
  GET /healthz                         200 while every vault's last walk
                                       succeeded within three intervals
  GET /metrics                         Prometheus text
  POST /refresh                        walk now (at most once in 5 seconds)

A value's JSON carries its standing: the vault settled, behind or in
debt; the version anchored or not; exposed or current; whether the token
read is known to be the vault's latest. -refuse names what is not served
(answered 409, with the standing and no value): exposed, unsettled (behind
or in debt), stale (nothing says the token read is the latest, or the last
walk failed), unanchored, incomplete (a host disagreed, refused or could
not be asked). The default, exposed,unsettled,stale, is what 'get -strict'
refuses; none serves every value it verified.

A vault that is ahead of its group, broken, terminated or rolled back is
never served. Values live in this process's memory and nowhere else; none
is ever logged. With -token-file every request but /healthz must carry the
file's token, as 'Authorization: Bearer <token>' or 'X-Vault-Token'; a
listen address that is not loopback needs one.

-once walks once, prints the status JSON to standard output and exits: 0
when every secret was read and served under the policy, 3 otherwise.`

// The conditions -refuse names.
const (
	refuseExposed    = "exposed"
	refuseUnsettled  = "unsettled"
	refuseStale      = "stale"
	refuseUnanchored = "unanchored"
	refuseIncomplete = "incomplete"
)

var refuseConditions = []string{refuseExposed, refuseUnsettled, refuseStale, refuseUnanchored, refuseIncomplete}

// serveDefaultRefuse is what get -strict refuses.
const serveDefaultRefuse = "exposed,unsettled,stale"

// serveReady, when a test sets it, is told the address serve listens on.
var serveReady func(home, addr string)

// refreshEvery is the least time between two walks a POST /refresh asks for.
const refreshEvery = 5 * time.Second

// standing is a value's standing as served.
type standing struct {
	// Vault is settled, behind, in-debt or behind-in-debt.
	Vault      string `json:"vault"`
	Settled    bool   `json:"settled"`
	Epoch      uint64 `json:"epoch"`
	GroupEpoch uint64 `json:"group_epoch"`
	Stale      uint64 `json:"stale"`
	Seq        uint64 `json:"seq"`
	// Latest is set when a spend source says the token read is the
	// vault's latest, and the group's latest token is the group's.
	Latest     bool `json:"latest"`
	Anchored   bool `json:"anchored"`
	Exposed    bool `json:"exposed"`
	Current    bool `json:"current"`
	Incomplete bool `json:"incomplete"`
}

// servedValue is one verified value.
type servedValue struct {
	Name     string   `json:"name"`
	Vault    string   `json:"vault_id"`
	Version  uint64   `json:"version"`
	Epoch    uint64   `json:"secret_epoch"`
	Label    string   `json:"label"`
	Type     string   `json:"type,omitempty"`
	NotAfter string   `json:"not_after,omitempty"`
	Standing standing `json:"standing"`
	ReadAt   string   `json:"read_at"`
	// Refused names the -refuse conditions this value meets: it is
	// answered 409 without its value.
	Refused []string `json:"refused,omitempty"`
	value   []byte
	created time.Time
}

// vaultSnap is what the last walk of one vault established.
type vaultSnap struct {
	ID   string `json:"vault_id"`
	Name string `json:"name"`
	// OK is set when the last walk established the vault and read every
	// secret of its set.
	OK       bool     `json:"ok"`
	Usable   bool     `json:"usable"`
	Problem  string   `json:"problem,omitempty"`
	Standing standing `json:"standing"`
	Secrets  []string `json:"secrets"`
	// Unread are the set's secrets the walk could not read, by identifier,
	// with the reason.
	Unread   map[string]string `json:"unread,omitempty"`
	WalkedAt string            `json:"walked_at,omitempty"`
	// LastOK is when a walk last established the vault.
	LastOK string `json:"last_ok,omitempty"`
	values map[string]*servedValue
	lastOK time.Time
	// refused is set when the walk failed on a refusal.
	refused bool
}

// serveVault is one vault served.
type serveVault struct {
	t     *target
	mount []string
}

// server is the daemon's state.
type server struct {
	g *global
	// st is the home's state, whose lock the daemon holds for its life.
	st       *state.State
	vaults   []*serveVault
	refuse   map[string]bool
	interval time.Duration
	token    []byte

	mu    sync.RWMutex
	snaps map[string]*vaultSnap

	metricsMu sync.Mutex
	walks     map[[2]string]uint64
	requests  map[[2]string]uint64
	refusals  map[string]uint64
	walkSecs  map[string]float64

	kick     chan struct{}
	lastKick time.Time
}

func parseRefuse(s string) (map[string]bool, error) {
	out := map[string]bool{}
	if s == "none" {
		return out, nil
	}
	for _, c := range strings.Split(s, ",") {
		c = strings.TrimSpace(c)
		ok := false
		for _, k := range refuseConditions {
			ok = ok || c == k
		}
		if !ok {
			return nil, usage("-refuse %q: a comma list of %s, or none", termsafe.Abbrev(c), strings.Join(refuseConditions, ", "))
		}
		out[c] = true
	}
	return out, nil
}

// isLoopback reports whether a listen address binds only a loopback
// interface.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func cmdServe(ctx context.Context, g *global, args []string) error {
	fs := g.flagSet("serve", serveHelp)
	listen := fs.String("listen", "127.0.0.1:8250", "host:port to serve on")
	interval := fs.Duration("interval", time.Minute, "how often each vault's chain is walked")
	refuseList := fs.String("refuse", serveDefaultRefuse, "what is not served: "+strings.Join(refuseConditions, ",")+", or none")
	tokenFile := fs.String("token-file", "", "a file holding the token every request must carry")
	once := fs.Bool("once", false, "walk once, print the status and exit")
	var vaults listFlag
	fs.Var(&vaults, "vault", "a vault to serve, by identifier or display name; repeat for more (default: the configured vault)")
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return usage("serve takes no arguments")
	}
	if *interval < time.Second {
		return usage("-interval is at least 1s")
	}
	refuse, err := parseRefuse(*refuseList)
	if err != nil {
		return err
	}
	s := &server{g: g, refuse: refuse, interval: *interval, snaps: map[string]*vaultSnap{},
		walks: map[[2]string]uint64{}, requests: map[[2]string]uint64{}, refusals: map[string]uint64{}, walkSecs: map[string]float64{},
		kick: make(chan struct{}, 1)}
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile) //nolint:gosec // the operator's own path
		if err != nil {
			return usage("-token-file: %v", err)
		}
		if s.token = []byte(strings.TrimSpace(string(b))); len(s.token) < 16 {
			return usage("-token-file holds %d bytes of token; at least 16", len(s.token))
		}
	}
	if !*once && s.token == nil && !isLoopback(*listen) {
		return usage("-listen %s is not a loopback address: give a -token-file, so that only who holds the token reads", *listen)
	}
	h, err := g.readerHome()
	if err != nil {
		return err
	}
	if h == nil {
		return usage("serve reads as this home's identity: there is no home at %s (bsecret init)", g.cfg.Home)
	}
	defer h.close()
	s.st = h.st
	if len(vaults) == 0 {
		vaults = listFlag{g.cfg.Vault}
	}
	seen := map[string]bool{}
	for i, want := range vaults {
		g.cfg.Vault = want
		t, err := g.readTarget(ctx, true)
		if err != nil {
			return err
		}
		if seen[t.vaultHex()] {
			return usage("vault %s is named twice", t.vaultHex())
		}
		seen[t.vaultHex()] = true
		sv := &serveVault{t: t, mount: []string{t.vaultHex()}}
		if i == 0 {
			sv.mount = append(sv.mount, "secret")
		}
		s.vaults = append(s.vaults, sv)
	}
	if *once {
		s.walk(ctx)
		_ = h.st.Save()
		st := s.status()
		b, _ := json.MarshalIndent(st, "", "  ")
		fmt.Fprintln(g.stdout, string(b))
		for _, v := range st {
			if !v.OK || !v.Usable {
				return incomplete("a vault was not read whole: %s", v.ID)
			}
			for _, sv := range v.values {
				if len(sv.Refused) > 0 {
					return incomplete("%s of vault %s is refused under -refuse (%s)", sv.Name, v.ID, strings.Join(sv.Refused, ","))
				}
			}
		}
		return nil
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return usage("-listen %s: %v", *listen, err)
	}
	srv := &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
	g.say("serve   listening on %s: %d vault(s), walked every %s, refusing %s", ln.Addr(), len(s.vaults), s.interval, strings.Join(sortedKeys(refuse), ",")+map[bool]string{true: "nothing", false: ""}[len(refuse) == 0])
	if serveReady != nil {
		serveReady(g.cfg.Home, ln.Addr().String())
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	walkDone := make(chan struct{})
	go func() {
		defer close(walkDone)
		tick := time.NewTicker(s.interval)
		defer tick.Stop()
		for {
			s.walk(ctx)
			if err := h.st.Save(); err != nil {
				g.say("serve   the home's state could not be saved: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			case <-s.kick:
			}
		}
	}()
	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	<-walkDone
	g.say("serve   stopped")
	return nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func standingOf(o *opened, fresh bool) standing {
	s := standing{Settled: o.stand.Settled(), Epoch: o.stand.Epoch, GroupEpoch: o.stand.Group, Stale: o.stand.Stale,
		Seq: o.chain.Head().Seq(), Latest: fresh, Incomplete: o.problem != nil}
	switch {
	case o.stand.Behind && o.stand.Stale > 0:
		s.Vault = "behind-in-debt"
	case o.stand.Behind:
		s.Vault = "behind"
	case o.stand.Stale > 0:
		s.Vault = "in-debt"
	default:
		s.Vault = "settled"
	}
	return s
}

// walk establishes every vault served and reads every secret of its set.
func (s *server) walk(ctx context.Context) {
	for _, v := range s.vaults {
		if ctx.Err() != nil {
			return
		}
		t0 := time.Now()
		snap, result := s.walkVault(ctx, v)
		s.metricsMu.Lock()
		s.walks[[2]string{v.t.vaultHex(), result}]++
		s.walkSecs[v.t.vaultHex()] = time.Since(t0).Seconds()
		s.metricsMu.Unlock()
		s.mu.Lock()
		if prev := s.snaps[snap.ID]; prev != nil && result == "failed" {
			snap.lastOK, snap.LastOK = prev.lastOK, prev.LastOK
			// A walk that could not establish the vault, and found nothing
			// that refuses it, leaves what the last walk verified: every
			// value is then not known to be current (stale), and what was
			// left open is said (incomplete). A refusal leaves nothing.
			if !snap.refused && prev.Usable {
				snap.Name, snap.Usable, snap.Standing, snap.Secrets, snap.Unread = prev.Name, true, prev.Standing, prev.Secrets, prev.Unread
				snap.Standing.Latest, snap.Standing.Incomplete = false, true
				for n, pv := range prev.values {
					sv := *pv
					sv.Standing.Latest, sv.Standing.Current, sv.Standing.Incomplete = false, false, true
					sv.Refused = s.refusedFor(sv.Standing)
					snap.values[n] = &sv
				}
			}
		}
		s.snaps[snap.ID] = snap
		s.mu.Unlock()
	}
}

func (s *server) walkVault(ctx context.Context, v *serveVault) (*vaultSnap, string) {
	g, t := s.g, v.t
	now := time.Now().UTC()
	snap := &vaultSnap{ID: t.vaultHex(), values: map[string]*servedValue{}, WalkedAt: now.Format(time.RFC3339)}
	// A walk that fails on a refusal (a check that named a culprit: a
	// rollback, a vault ahead, broken or terminated) keeps nothing it read
	// before.
	fail := func(err error) (*vaultSnap, string) {
		var ee *exitError
		var f *vread.Failure
		snap.refused = errors.As(err, &f) || (errors.As(err, &ee) && ee.code == exitRefused)
		snap.Problem = firstLine(err.Error())
		g.say("serve   vault %s: %s", vread.Short(snap.ID), snap.Problem)
		return snap, "failed"
	}
	o, err := g.open(ctx, t, s.st)
	if err != nil {
		return fail(err)
	}
	head := o.chain.Head().Token.Vault
	snap.Name = head.Name
	if o.stand.Ahead {
		return fail(refused("vault %s is %s: nothing is taken from it", vread.Short(snap.ID), o.stand))
	}
	if b := o.chain.Broken(); b != "" {
		return fail(refused("vault %s is broken from seq %d on (%s): nothing is taken from it", vread.Short(snap.ID), o.chain.Usable(), b))
	}
	keys, _, err := g.keysFor(o)
	if err != nil {
		return fail(err)
	}
	_, fresh, err := g.freshness(ctx, o)
	if err != nil {
		var ee *exitError
		if errors.As(err, &ee) && ee.code == exitRefused {
			// Terminated: nothing new is taken from it.
			return fail(err)
		}
		o.leave(err)
		fresh = false
	}
	snap.Usable, snap.lastOK, snap.LastOK = true, now, now.Format(time.RFC3339)
	for _, cur := range o.chain.Set() {
		idHex := hex.EncodeToString(cur.ID[:])
		rd, _, err := g.readOne(ctx, o, keys, cur.ID, "id:"+idHex, 0)
		if err != nil {
			if snap.Unread == nil {
				snap.Unread = map[string]string{}
			}
			snap.Unread[idHex] = firstLine(err.Error())
			continue
		}
		rec := rd.Car.Carrier.Secret
		sv := &servedValue{Name: rd.Payload.Name, Vault: snap.ID, Version: rec.Version, Epoch: rec.Epoch, Label: rec.Label,
			Type: rd.Payload.Type, ReadAt: snap.WalkedAt, value: rd.Payload.Value, created: now}
		if rd.Payload.NotAfter != 0 {
			sv.NotAfter = time.Unix(int64(rd.Payload.NotAfter), 0).UTC().Format(time.RFC3339) //nolint:gosec // bounded by the record
		}
		sv.Standing = standingOf(o, fresh)
		sv.Standing.Anchored, sv.Standing.Exposed = rd.Anchored, rd.Exposed
		sv.Standing.Current = fresh && !rd.Exposed
		snap.values[sv.Name] = sv
	}
	snap.Standing = standingOf(o, fresh)
	for n, sv := range snap.values {
		sv.Standing.Incomplete = o.problem != nil
		sv.Refused = s.refusedFor(sv.Standing)
		snap.Secrets = append(snap.Secrets, n)
	}
	sort.Strings(snap.Secrets)
	snap.OK = len(snap.Unread) == 0
	result := "ok"
	if o.problem != nil || !snap.OK {
		result = "incomplete"
		if o.problem != nil {
			snap.Problem = firstLine(o.problem.Error())
		}
	}
	return snap, result
}

// refusedFor names the -refuse conditions a standing meets.
func (s *server) refusedFor(st standing) []string {
	var out []string
	add := func(c string, met bool) {
		if met && s.refuse[c] {
			out = append(out, c)
		}
	}
	add(refuseExposed, st.Exposed)
	add(refuseUnsettled, !st.Settled)
	add(refuseStale, !st.Latest)
	add(refuseUnanchored, !st.Anchored)
	add(refuseIncomplete, st.Incomplete)
	return out
}

// status is every vault's last walk.
func (s *server) status() []*vaultSnap {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*vaultSnap
	for _, v := range s.vaults {
		if snap := s.snaps[v.t.vaultHex()]; snap != nil {
			out = append(out, snap)
		} else {
			out = append(out, &vaultSnap{ID: v.t.vaultHex(), Problem: "not walked yet"})
		}
	}
	return out
}

// find is the snapshot of the vault a mount or vault path segment names.
func (s *server) find(name string) *vaultSnap {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var byName []*vaultSnap
	for _, v := range s.vaults {
		snap := s.snaps[v.t.vaultHex()]
		for _, m := range v.mount {
			if m == name {
				if snap == nil {
					return &vaultSnap{ID: v.t.vaultHex(), Problem: "not walked yet"}
				}
				return snap
			}
		}
		if snap != nil && snap.Name == name {
			byName = append(byName, snap)
		}
	}
	if len(byName) == 1 {
		return byName[0]
	}
	return nil
}

func (s *server) authorized(r *http.Request) bool {
	if s.token == nil {
		return true
	}
	got := r.Header.Get("X-Vault-Token")
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		got = strings.TrimPrefix(a, "Bearer ")
	}
	return subtle.ConstantTimeCompare([]byte(got), s.token) == 1
}

func (s *server) count(route string, code int) {
	s.metricsMu.Lock()
	s.requests[[2]string{route, fmt.Sprint(code)}]++
	s.metricsMu.Unlock()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ServeHTTP routes a request.
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	route, code := "other", http.StatusNotFound
	defer func() { s.count(route, code) }()
	if path == "/healthz" {
		route = "healthz"
		code = s.health(w)
		return
	}
	if !s.authorized(r) {
		code = http.StatusUnauthorized
		writeJSON(w, code, map[string]any{"error": "a token is required", "errors": []string{"permission denied"}})
		return
	}
	switch {
	case path == "/status" && r.Method == http.MethodGet:
		route, code = "status", http.StatusOK
		writeJSON(w, code, s.status())
	case path == "/metrics" && r.Method == http.MethodGet:
		route, code = "metrics", http.StatusOK
		s.metrics(w)
	case path == "/refresh" && r.Method == http.MethodPost:
		route, code = "refresh", http.StatusAccepted
		s.metricsMu.Lock()
		if time.Since(s.lastKick) < refreshEvery {
			code = http.StatusTooManyRequests
		} else {
			s.lastKick = time.Now()
			select {
			case s.kick <- struct{}{}:
			default:
			}
		}
		s.metricsMu.Unlock()
		writeJSON(w, code, map[string]any{"refresh": code == http.StatusAccepted})
	case r.Method != http.MethodGet:
		code = http.StatusMethodNotAllowed
		writeJSON(w, code, map[string]any{"error": "only GET is served", "errors": []string{"unsupported operation"}})
	case strings.HasPrefix(path, "/secrets/"):
		route = "secret"
		code = s.secret(w, s.first(), strings.TrimPrefix(path, "/secrets/"), false)
	case strings.HasPrefix(path, "/vaults/"):
		route = "secret"
		rest := strings.TrimPrefix(path, "/vaults/")
		vault, name, ok := strings.Cut(rest, "/secrets/")
		if !ok {
			code = http.StatusNotFound
			writeJSON(w, code, map[string]any{"error": "no such route"})
			return
		}
		code = s.secret(w, s.find(vault), name, false)
	case strings.HasPrefix(path, "/v1/"):
		route = "kv"
		mount, name, ok := strings.Cut(strings.TrimPrefix(path, "/v1/"), "/data/")
		if !ok {
			code = http.StatusNotFound
			writeJSON(w, code, map[string]any{"errors": []string{"no handler for route: only <mount>/data/<name> is served"}})
			return
		}
		code = s.secret(w, s.find(mount), name, true)
	default:
		writeJSON(w, code, map[string]any{"error": "no such route"})
	}
}

func (s *server) first() *vaultSnap { return s.find("secret") }

// health is 200 while every vault's last walk established it within three
// intervals.
func (s *server) health(w http.ResponseWriter) int {
	code := http.StatusOK
	var why []string
	for _, v := range s.status() {
		switch {
		case !v.Usable:
			why = append(why, v.ID+": "+v.Problem)
		case time.Since(v.lastOK) > 3*s.interval:
			why = append(why, v.ID+": not walked since "+v.LastOK)
		default:
			continue
		}
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{"ok": code == http.StatusOK, "problems": why})
	return code
}

// secret answers one value: JSON, or the KV version 2 shape.
func (s *server) secret(w http.ResponseWriter, snap *vaultSnap, name string, kv bool) int {
	fail := func(code int, msg string, extra map[string]any) int {
		body := map[string]any{"error": msg}
		if kv {
			body = map[string]any{"errors": []string{msg}}
		}
		for k, v := range extra {
			body[k] = v
		}
		writeJSON(w, code, body)
		return code
	}
	if snap == nil {
		return fail(http.StatusNotFound, "no vault served by that name", nil)
	}
	if secrec.CheckSecretName(name) != nil {
		return fail(http.StatusNotFound, "not a secret name", nil)
	}
	if !snap.Usable {
		return fail(http.StatusServiceUnavailable, "the vault is not served: "+snap.Problem, nil)
	}
	sv := snap.values[name]
	if sv == nil {
		id, _ := secrec.SecretID(mustHex32(snap.ID), name)
		if why, ok := snap.Unread[hex.EncodeToString(id[:])]; ok {
			return fail(http.StatusServiceUnavailable, "the secret could not be read: "+why, nil)
		}
		return fail(http.StatusNotFound, "the vault's set holds no secret by that name", nil)
	}
	if len(sv.Refused) > 0 {
		s.metricsMu.Lock()
		for _, c := range sv.Refused {
			s.refusals[c]++
		}
		s.metricsMu.Unlock()
		return fail(http.StatusConflict, "not served under the policy: "+strings.Join(sv.Refused, ", "), map[string]any{"standing": sv.Standing, "refused": sv.Refused})
	}
	data := map[string]any{"value_base64": base64.StdEncoding.EncodeToString(sv.value)}
	if utf8.Valid(sv.value) {
		data["value"] = string(sv.value)
	}
	if !kv {
		out := map[string]any{}
		b, _ := json.Marshal(sv)
		_ = json.Unmarshal(b, &out)
		for k, v := range data {
			out[k] = v
		}
		writeJSON(w, http.StatusOK, out)
		return http.StatusOK
	}
	st := sv.Standing
	custom := map[string]string{
		"vault_id": sv.Vault, "label": sv.Label, "secret_epoch": fmt.Sprint(sv.Epoch), "vault_standing": st.Vault,
		"anchored": fmt.Sprint(st.Anchored), "exposed": fmt.Sprint(st.Exposed), "current": fmt.Sprint(st.Current),
		"latest": fmt.Sprint(st.Latest), "seq": fmt.Sprint(st.Seq), "read_at": sv.ReadAt,
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"request_id": "", "lease_id": "", "renewable": false, "lease_duration": 0, "wrap_info": nil, "warnings": nil, "auth": nil,
		"data": map[string]any{
			"data": data,
			"metadata": map[string]any{"created_time": sv.created.Format(time.RFC3339Nano), "custom_metadata": custom,
				"deletion_time": "", "destroyed": false, "version": sv.Version},
		},
	})
	return http.StatusOK
}

func mustHex32(s string) [32]byte {
	v, _ := vread.Hex32(s)
	return v
}

// metrics writes the daemon's metrics as Prometheus text.
func (s *server) metrics(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	var b strings.Builder
	line := func(name, labels string, v any) {
		if labels != "" {
			labels = "{" + labels + "}"
		}
		fmt.Fprintf(&b, "%s%s %v\n", name, labels, v)
	}
	help := func(name, typ, text string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, text, name, typ)
	}
	bool01 := func(v bool) int {
		if v {
			return 1
		}
		return 0
	}
	snaps := s.status()
	help("bsecret_serve_vault_usable", "gauge", "1 while the last walk established the vault")
	for _, v := range snaps {
		line("bsecret_serve_vault_usable", `vault="`+v.ID+`"`, bool01(v.Usable))
	}
	help("bsecret_serve_vault_settled", "gauge", "1 while the vault is settled: its epoch is the group's latest and nothing is stale")
	for _, v := range snaps {
		line("bsecret_serve_vault_settled", `vault="`+v.ID+`"`, bool01(v.Usable && v.Standing.Settled))
	}
	help("bsecret_serve_vault_latest", "gauge", "1 while a spend source says the token read is the vault's latest")
	for _, v := range snaps {
		line("bsecret_serve_vault_latest", `vault="`+v.ID+`"`, bool01(v.Usable && v.Standing.Latest))
	}
	help("bsecret_serve_vault_seq", "gauge", "the seq of the vault's token read")
	for _, v := range snaps {
		line("bsecret_serve_vault_seq", `vault="`+v.ID+`"`, v.Standing.Seq)
	}
	help("bsecret_serve_secrets", "gauge", "secrets read and verified by the last walk")
	for _, v := range snaps {
		line("bsecret_serve_secrets", `vault="`+v.ID+`"`, len(v.values))
	}
	help("bsecret_serve_secrets_unread", "gauge", "secrets of the set the last walk could not read")
	for _, v := range snaps {
		line("bsecret_serve_secrets_unread", `vault="`+v.ID+`"`, len(v.Unread))
	}
	help("bsecret_serve_secrets_exposed", "gauge", "secrets keyed under an epoch before the group's latest")
	for _, v := range snaps {
		n := 0
		for _, sv := range v.values {
			n += bool01(sv.Standing.Exposed)
		}
		line("bsecret_serve_secrets_exposed", `vault="`+v.ID+`"`, n)
	}
	help("bsecret_serve_last_walk_ok_timestamp_seconds", "gauge", "when a walk last established the vault")
	for _, v := range snaps {
		if !v.lastOK.IsZero() {
			line("bsecret_serve_last_walk_ok_timestamp_seconds", `vault="`+v.ID+`"`, v.lastOK.Unix())
		}
	}
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	help("bsecret_serve_walk_seconds", "gauge", "how long the last walk of the vault took")
	for _, k := range sortedMapKeys(s.walkSecs) {
		line("bsecret_serve_walk_seconds", `vault="`+k+`"`, s.walkSecs[k])
	}
	help("bsecret_serve_walks_total", "counter", "walks by result: ok, incomplete, failed")
	for _, k := range sortedPairs(s.walks) {
		line("bsecret_serve_walks_total", `vault="`+k[0]+`",result="`+k[1]+`"`, s.walks[k])
	}
	help("bsecret_serve_requests_total", "counter", "requests by route and status code")
	for _, k := range sortedPairs(s.requests) {
		line("bsecret_serve_requests_total", `route="`+k[0]+`",code="`+k[1]+`"`, s.requests[k])
	}
	help("bsecret_serve_refused_total", "counter", "values not served under the policy, by condition")
	for _, c := range refuseConditions {
		line("bsecret_serve_refused_total", `condition="`+c+`"`, s.refusals[c])
	}
	_, _ = w.Write([]byte(b.String()))
}

func sortedMapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedPairs(m map[[2]string]uint64) [][2]string {
	out := make([][2]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][1] < out[j][1]
	})
	return out
}

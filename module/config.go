// Package module is the bsecret overlay module in Go: `tm_bsecret_<crypt>`
// for each configured crypt and `ls_bsecret` for all of them, written to
// bcommon's engine-neutral contract (github.com/lightwebinc/bcommon/module)
// so that any Go overlay host that carries the adapter mounts it. It is the
// twin of the TypeScript module under host/src (frozen), built from the Go
// core: the admission rules are secrec.Admit, the index rules secrec's
// folds, listings and rows, and the questions secrec's classes.
//
// Configuration is the TypeScript module's, read from the environment when
// the host calls the factory (docs/host.md): BSECRET_CRYPTS,
// BSECRET_STATE_DIR, BSECRET_HEADERS_URL, BSECRET_RETENTION_DAYS,
// BSECRET_UNHELD_HOURS, BSECRET_MAX_BEEF, BSECRET_MAX_SWEEP_INPUTS,
// BSECRET_SPEND_TABLE, BSECRET_LISTEN, BSECRET_PRICES, BSECRET_PAYEE_KEY,
// BSECRET_SESSIONS, BSECRET_SESSION_TTL, the handshake and response
// budgets, BSECRET_PRIVATE, BSECRET_HALL_URL, BSECRET_MEMBER_TTL,
// BSECRET_ARCADE_URL, BSECRET_ASSET_URL and the BSECRET_ACCEPT_* rule, and
// one of its own, BSECRET_JOURNAL_SYNC_MS (the rows journal's group commit
// window). Every mistake is an error, and the host refuses to start.
package module

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/lightwebinc/bcommon/guard"
	"github.com/lightwebinc/bcommon/termsroute"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// The floors an operator cannot go under (docs/spec.md sections 11.1 and
// 11.3).
const (
	FloorDays        = 31
	FloorUnheldHours = 24
	MinSpendTable    = 65536
	DefaultMemberTTL = 60
	MinMemberTTL     = 1
)

// The rows journal's group commit window (BSECRET_JOURNAL_SYNC_MS): lines
// are written at once and fsynced together this often, off the lookup
// service's lock; 0 fsyncs each line before the admission goes on. The
// default and the bound are a timed write-ahead log's usual ones.
const (
	DefaultJournalSyncMs = 100
	MaxJournalSyncMs     = 60_000
)

// Config is the module's configuration.
type Config struct {
	Crypts         []string
	StateDir       string
	HeadersURL     string
	RetentionDays  int
	UnheldHours    int
	MaxBEEF        int
	MaxSweepInputs int
	SpendTable     int
	// JournalSync is the rows journal's group commit window; 0 syncs every
	// line.
	JournalSync time.Duration
	// Listen is the terms route's host:port; empty for none.
	Listen   string
	Prices   map[string]uint64
	PayeeKey *ec.PrivateKey
	Sessions termsroute.SessionBound
	Budget   termsroute.BudgetConfig
	Response termsroute.ResponseBudgetConfig
	Accept   termsroute.AcceptConfig
	// Private are the private crypts and the organizations each is served
	// to; HallURLs the borg hosts asked who is a member; MemberTTL how long
	// an answer is kept.
	Private   map[string]map[string]bool
	HallURLs  []string
	MemberTTL time.Duration
}

// Classes are the lookup classes as the route prices them.
var Classes = func() []termsroute.PricedClass {
	out := make([]termsroute.PricedClass, len(secrec.Classes))
	for i, c := range secrec.Classes {
		out[i] = termsroute.PricedClass{Name: c.Name, Free: c.Free}
	}
	return out
}()

// ParseCrypts parses BSECRET_CRYPTS: crypt identifiers, once each.
func ParseCrypts(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("BSECRET_CRYPTS is required: name each crypt this host carries")
	}
	var out []string
	for _, e := range strings.Split(raw, ",") {
		c := strings.TrimSpace(e)
		if secrec.CheckCrypt(c) != nil {
			return nil, fmt.Errorf("BSECRET_CRYPTS: %q is not a crypt identifier <name>_<suffix>", c)
		}
		for _, x := range out {
			if x == c {
				return nil, fmt.Errorf("BSECRET_CRYPTS names %s twice", c)
			}
		}
		out = append(out, c)
	}
	return out, nil
}

var digits = regexp.MustCompile(`^[0-9]+$`)
var rateRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

func integer(name, raw string, def, min int) (int, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if !digits.MatchString(v) || err != nil || n > termsroute.MaxSafe || int(n) < min {
		return 0, fmt.Errorf("%s: %q is not an integer of at least %d", name, raw, min)
	}
	return int(n), nil
}

// rate is a positive rate, decimals allowed, at most 1e6.
func rate(name, raw string, def float64) (float64, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if !rateRE.MatchString(v) || err != nil || !(f > 0) || f > 1e6 {
		return 0, fmt.Errorf("%s: %q is not a positive number of at most 1000000", name, raw)
	}
	return f, nil
}

func isNativeSource(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

var keyRE = regexp.MustCompile(`^[0-9a-f]{66}$`)

func keyHex(s string) bool {
	if !keyRE.MatchString(s) {
		return false
	}
	b, _ := hex.DecodeString(s)
	if _, err := guard.ParsePubKey(b); err != nil {
		return false
	}
	return !secrec.IsAnyone(b)
}

// ParsePrivate parses BSECRET_PRIVATE: <crypt>=<org>[,<org>...] entries
// separated by ;, each crypt one this host carries, each organization an
// identity key.
func ParsePrivate(raw string, carried []string) (map[string]map[string]bool, error) {
	out := map[string]map[string]bool{}
	if strings.TrimSpace(raw) == "" {
		return out, nil
	}
	for _, entry := range strings.Split(raw, ";") {
		if strings.TrimSpace(entry) == "" {
			continue
		}
		at := strings.IndexByte(entry, '=')
		c := entry
		rest := ""
		if at >= 0 {
			c, rest = entry[:at], entry[at+1:]
		}
		c = strings.TrimSpace(c)
		if secrec.CheckCrypt(c) != nil {
			return nil, fmt.Errorf("BSECRET_PRIVATE: %q is not a crypt identifier <name>_<suffix>", c)
		}
		found := false
		for _, x := range carried {
			found = found || x == c
		}
		if !found {
			return nil, fmt.Errorf("BSECRET_PRIVATE names %s, which BSECRET_CRYPTS does not carry", c)
		}
		if _, dup := out[c]; dup {
			return nil, fmt.Errorf("BSECRET_PRIVATE names %s twice", c)
		}
		orgs := map[string]bool{}
		for _, o := range strings.Split(rest, ",") {
			k := strings.TrimSpace(o)
			if !keyHex(k) {
				return nil, fmt.Errorf("BSECRET_PRIVATE: %s: %q is not an identity key, 66 lowercase hex digits", c, k)
			}
			orgs[k] = true
		}
		out[c] = orgs
	}
	return out, nil
}

// ParseHallURLs parses BSECRET_HALL_URL: a comma list of http or https
// base URLs.
func ParseHallURLs(raw string) ([]string, error) {
	var out []string
	for _, u := range strings.Split(raw, ",") {
		s := strings.TrimRight(strings.TrimSpace(u), "/")
		if s == "" {
			continue
		}
		p, err := url.Parse(s)
		if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" || p.RawQuery != "" || p.Fragment != "" {
			return nil, fmt.Errorf("BSECRET_HALL_URL: %q is not an http or https base URL", s)
		}
		out = append(out, s)
	}
	return out, nil
}

// ParseConfig reads the whole configuration through getenv.
func ParseConfig(getenv func(string) string) (*Config, error) {
	crypts, err := ParseCrypts(getenv("BSECRET_CRYPTS"))
	if err != nil {
		return nil, err
	}
	c := &Config{Crypts: crypts, StateDir: getenv("BSECRET_STATE_DIR")}
	if c.StateDir == "" || !filepath.IsAbs(c.StateDir) {
		return nil, errors.New("BSECRET_STATE_DIR is required: an absolute directory kept for the host's life, where the outpoint rows live")
	}
	own := strings.TrimSpace(getenv("BSECRET_HEADERS_URL"))
	host := strings.TrimSpace(getenv("OVERLAY_CHAIN_TRACKER_URL"))
	switch {
	case own != "":
		if !isNativeSource(own) {
			return nil, fmt.Errorf("BSECRET_HEADERS_URL: %q is not an http or https URL", own)
		}
		c.HeadersURL = own
	case host != "" && isNativeSource(host):
		c.HeadersURL = host
	default:
		return nil, errors.New("BSECRET_HEADERS_URL is required: a native header source (/v1/root/<height>, /v1/tip) that token and sweep proofs are checked against; OVERLAY_CHAIN_TRACKER_URL is not one")
	}
	ints := []struct {
		dst      *int
		name     string
		def, min int
	}{
		{&c.RetentionDays, "BSECRET_RETENTION_DAYS", FloorDays, FloorDays},
		{&c.UnheldHours, "BSECRET_UNHELD_HOURS", FloorUnheldHours, FloorUnheldHours},
		{&c.MaxBEEF, "BSECRET_MAX_BEEF", secrec.DefaultMaxBEEF, secrec.DefaultMaxBEEF},
		{&c.MaxSweepInputs, "BSECRET_MAX_SWEEP_INPUTS", secrec.DefaultMaxSweepInputs, secrec.DefaultMaxSweepInputs},
		{&c.SpendTable, "BSECRET_SPEND_TABLE", MinSpendTable, MinSpendTable},
	}
	for _, x := range ints {
		if *x.dst, err = integer(x.name, getenv(x.name), x.def, x.min); err != nil {
			return nil, err
		}
	}
	syncMs, err := integer("BSECRET_JOURNAL_SYNC_MS", getenv("BSECRET_JOURNAL_SYNC_MS"), DefaultJournalSyncMs, 0)
	if err != nil {
		return nil, err
	}
	if syncMs > MaxJournalSyncMs {
		return nil, fmt.Errorf("BSECRET_JOURNAL_SYNC_MS: %d is over %d", syncMs, MaxJournalSyncMs)
	}
	c.JournalSync = time.Duration(syncMs) * time.Millisecond
	if c.Prices, err = termsroute.ParsePrices(getenv("BSECRET_PRICES"), Classes, "BSECRET_PRICES"); err != nil {
		return nil, err
	}
	maxSessions, err := integer("BSECRET_SESSIONS", getenv("BSECRET_SESSIONS"), termsroute.DefaultMaxSessions, 1)
	if err != nil {
		return nil, err
	}
	ttl, err := integer("BSECRET_SESSION_TTL", getenv("BSECRET_SESSION_TTL"), termsroute.DefaultSessionTTL, 1)
	if err != nil {
		return nil, err
	}
	c.Sessions = termsroute.SessionBound{Max: maxSessions, TTL: time.Duration(ttl) * time.Second}
	c.Budget = termsroute.DefaultBudget
	if c.Budget.PerSec, err = rate("BSECRET_HANDSHAKES_PER_SEC", getenv("BSECRET_HANDSHAKES_PER_SEC"), termsroute.DefaultBudget.PerSec); err != nil {
		return nil, err
	}
	if c.Budget.Burst, err = integer("BSECRET_HANDSHAKE_BURST", getenv("BSECRET_HANDSHAKE_BURST"), termsroute.DefaultBudget.Burst, 1); err != nil {
		return nil, err
	}
	if c.Budget.PerAddressPerSec, err = rate("BSECRET_HANDSHAKES_PER_ADDR_PER_SEC", getenv("BSECRET_HANDSHAKES_PER_ADDR_PER_SEC"), termsroute.DefaultBudget.PerAddressPerSec); err != nil {
		return nil, err
	}
	if c.Budget.AddressBurst, err = integer("BSECRET_HANDSHAKE_ADDR_BURST", getenv("BSECRET_HANDSHAKE_ADDR_BURST"), termsroute.DefaultBudget.AddressBurst, 1); err != nil {
		return nil, err
	}
	c.Response = termsroute.DefaultResponseBudget
	if c.Response.PerSec, err = rate("BSECRET_RESPONSES_PER_SEC", getenv("BSECRET_RESPONSES_PER_SEC"), termsroute.DefaultResponseBudget.PerSec); err != nil {
		return nil, err
	}
	if c.Response.Burst, err = integer("BSECRET_RESPONSE_BURST", getenv("BSECRET_RESPONSE_BURST"), termsroute.DefaultResponseBudget.Burst, 1); err != nil {
		return nil, err
	}
	if c.Accept, err = termsroute.ParseAcceptConfig("BSECRET", getenv); err != nil {
		return nil, err
	}
	if listen := strings.TrimSpace(getenv("BSECRET_LISTEN")); listen != "" {
		h, p, err := net.SplitHostPort(listen)
		port, perr := strconv.Atoi(p)
		if err != nil || h == "" || perr != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("BSECRET_LISTEN: %q is not host:port", listen)
		}
		c.Listen = listen
	}
	if k := strings.TrimSpace(getenv("BSECRET_PAYEE_KEY")); k != "" {
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(k) {
			return nil, errors.New("BSECRET_PAYEE_KEY is not 64 lowercase hex characters")
		}
		b, _ := hex.DecodeString(k)
		c.PayeeKey, _ = ec.PrivateKeyFromBytes(b)
		if c.PayeeKey == nil {
			return nil, errors.New("BSECRET_PAYEE_KEY is not a private key")
		}
	}
	if c.Private, err = ParsePrivate(getenv("BSECRET_PRIVATE"), crypts); err != nil {
		return nil, err
	}
	if c.HallURLs, err = ParseHallURLs(getenv("BSECRET_HALL_URL")); err != nil {
		return nil, err
	}
	ttlS, err := integer("BSECRET_MEMBER_TTL", getenv("BSECRET_MEMBER_TTL"), DefaultMemberTTL, MinMemberTTL)
	if err != nil {
		return nil, err
	}
	c.MemberTTL = time.Duration(ttlS) * time.Second
	if len(c.Private) > 0 {
		if c.Listen == "" || c.PayeeKey == nil {
			return nil, errors.New("BSECRET_PRIVATE makes crypts private: BSECRET_LISTEN (the terms route, where they are asked) and BSECRET_PAYEE_KEY (the route's BRC-104 identity) are required")
		}
		if len(c.HallURLs) == 0 {
			return nil, errors.New("BSECRET_PRIVATE serves the members of the named organizations' groups: BSECRET_HALL_URL names the borg hosts asked who they are")
		}
	}
	charged := false
	for _, p := range c.Prices {
		charged = charged || p > 0
	}
	if charged && (c.Listen == "" || c.PayeeKey == nil) {
		return nil, errors.New("BSECRET_PRICES prices a class: BSECRET_LISTEN and BSECRET_PAYEE_KEY are required")
	}
	if len(c.Prices) > 0 && c.Listen == "" {
		return nil, errors.New("BSECRET_PRICES needs BSECRET_LISTEN, where the terms document is served")
	}
	return c, nil
}

// CheckNoSync refuses a host configured to synchronise a tm_bsecret_ topic
// with a peer (OVERLAY_SYNC_PEERS, topic=url,...;topic=...): such a
// synchronisation carries only unspent outputs, so it never carries a
// chain's spent tokens, and it drops what a topic manager refuses without
// retrying it. A crypt is joined by replay (spec section 11.6).
func CheckNoSync(raw string) error {
	for _, entry := range strings.Split(raw, ";") {
		t := strings.TrimSpace(strings.SplitN(entry, "=", 2)[0])
		if strings.HasPrefix(t, secrec.TopicPrefix) {
			return fmt.Errorf("OVERLAY_SYNC_PEERS names %s: a tm_bsecret_ topic is never synchronised as unspent outputs; a host joins a crypt by replay", t)
		}
	}
	return nil
}

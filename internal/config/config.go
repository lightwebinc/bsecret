// Package config resolves the bsecret command's settings: flags, then
// BSECRET_* in the environment, then the config file, then the built-in
// default.
//
// The deployment addresses have no default: the overlay hosts of the crypt
// and of the hall, the facade, the header source, the settlement leg, the
// node, where large ciphertexts are kept, and the host a priced question
// goes to. A default there would quietly send an organisation's records, or
// a member's questions, to somebody else's server, so a command that needs
// one and finds none is a usage error.
package config

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lightwebinc/borg/borgrec"

	"github.com/lightwebinc/bsecret/internal/limits"
	"github.com/lightwebinc/bsecret/internal/secrec"
)

// Config is the resolved settings.
type Config struct {
	// ArcadeKey is the bearer token for an arcade installation in Settle.
	ArcadeKey string
	// Asset is the node's asset API base URL: proofs, the chain tip, raw
	// transactions and the node's view of which outputs are spent.
	Asset string
	// ChainTreeCount is how many outputs a new chain tree has.
	ChainTreeCount int
	// Content is where a ciphertext too large to be carried is kept: a
	// directory (a writer stores into it, a reader reads from it) or an
	// http(s) base URL a reader fetches <base>/<hash> from, comma
	// separated when there are several. A file there is named by the
	// lowercase hex of its SHA-256.
	Content []string
	// Crypt is the crypt identifier <name>_<suffix> a command uses when it
	// names none.
	Crypt string
	// Delay is the propagation delay: how long after a mined object's block
	// is in the publisher's headers it is published (spec section 8.3).
	Delay time.Duration
	// Facade is the overlay host a publisher submits to in mode plane.
	Facade string
	// Freshness bounds how old a writer's evidence that the vault's and the
	// group's latest tokens are unspent may be when it publishes a version
	// (spec section 7.1). Every transition retakes the evidence as it is
	// built, whatever this says.
	Freshness time.Duration
	// Hall is the borg hall a new vault's group lives in.
	Hall string
	// HallHosts are the overlay hosts asked about the group's hall; unset,
	// Hosts are asked.
	HallHosts []string
	// HeaderURL is the header source every proof is checked against: a
	// bridge's /v1 base URL, woc:main, woc:test or chaintracks:URL. No
	// default, ever.
	HeaderURL string
	// Home is the identity's directory: key, coin pool and state.
	Home string
	// Hosts are the overlay hosts of the crypt a reader asks. In mode
	// unicast they are every host a publisher submits to; in mode plane
	// mined objects also go to each of them directly.
	Hosts []string
	// MaxFetch is the most ciphertext a reader fetches by hash, in bytes.
	MaxFetch int
	// Mode is how a publisher's objects reach the hosts: "plane" or
	// "unicast".
	Mode string
	// Network is "main", "test" or "regtest".
	Network string
	// ObjectBound is the largest object the plane takes, in bytes.
	ObjectBound int
	// Org is the owner a reader's command reads when it names none: the
	// organisation's identity key, 66 lowercase hex digits.
	Org string
	// Originator is the BRC-100 originator presented to the wallet.
	Originator string
	// PaidHost is the base URL of ls_bsecret on the host a priced question
	// is asked of: the host's terms route (spec section 10.3).
	PaidHost string
	// Quorum is, in mode unicast, how many of Hosts must take a carrier for
	// it to count as published: "all", "majority", "one" or a number.
	// Tokens and sweeps always need every host.
	Quorum string
	// RPC is the node's JSON-RPC URL; RPCUser and RPCPass its basic auth.
	RPC     string
	RPCPass string
	RPCUser string
	// Settle is the settlement leg mined transactions go to: tcp:<host:port>,
	// rpc:<url> or arcade:<url>.
	Settle string
	// Timeout bounds each request to a host, node or header source.
	Timeout time.Duration
	// TreeCount is how many outputs a new secret funding tree has.
	TreeCount int
	// Vault is the vault a command uses when it names none: its
	// identifier, 64 lowercase hex digits, or its display name.
	Vault string
}

// The modes and the named quorums.
const (
	ModePlane      = "plane"
	ModeUnicast    = "unicast"
	QuorumAll      = "all"
	QuorumMajority = "majority"
	QuorumOne      = "one"
)

// Need is how many of n hosts the quorum q requires. A number above n is an
// error: a quorum no host set can meet would refuse every publish.
func Need(q string, n int) (int, error) {
	if n < 1 {
		return 0, errors.New("no hosts")
	}
	switch q {
	case QuorumAll, "":
		return n, nil
	case QuorumMajority:
		return n/2 + 1, nil
	case QuorumOne:
		return 1, nil
	}
	k, err := strconv.Atoi(q)
	if err != nil || k < 1 {
		return 0, fmt.Errorf("quorum %q is not all, majority, one or a positive number", q)
	}
	if k > n {
		return 0, fmt.Errorf("quorum %d is more than the %d configured host(s)", k, n)
	}
	return k, nil
}

// DefaultHome is ~/.bsecret, or .bsecret when there is no home directory.
func DefaultHome() string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".bsecret")
	}
	return ".bsecret"
}

// Defaults are the built-in values for the keys that have one.
func Defaults() Config {
	return Config{
		ChainTreeCount: limits.DefaultChainTreeCount,
		Delay:          limits.DefaultDelay,
		Freshness:      limits.DefaultFreshness,
		Home:           DefaultHome(),
		MaxFetch:       limits.DefaultMaxFetch,
		Mode:           ModePlane,
		Network:        "main",
		ObjectBound:    limits.DefaultObjectBound,
		Originator:     "bsecret",
		Quorum:         QuorumAll,
		RPCPass:        "bitcoin",
		RPCUser:        "bitcoin",
		Timeout:        limits.DefaultTimeout,
		TreeCount:      limits.DefaultTreeCount,
	}
}

// Keys is the file grammar's key list, in lexicographic order. A key not in
// it is an error: a misspelt key that was silently ignored would leave a
// setting at its default with no sign that the file was ever read.
var Keys = []string{"arcade_key", "asset", "chain_tree_count", "content", "crypt", "delay", "facade", "freshness", "hall",
	"hall_hosts", "header_url", "home", "hosts", "max_fetch", "mode", "network", "object_bound", "org", "originator",
	"paid_host", "quorum", "rpc", "rpc_pass", "rpc_user", "settle", "timeout", "tree_count", "vault"}

// ErrUnknownKey reports a key the grammar does not define.
var ErrUnknownKey = errors.New("config: unknown key")

// Path is the config file location: the -config flag, else
// $BSECRET_HOME/config, else $XDG_CONFIG_HOME/bsecret/config, else
// ~/.bsecret/config.
func Path(flagPath string, getenv func(string) string) string {
	if flagPath != "" {
		return flagPath
	}
	if h := getenv("BSECRET_HOME"); h != "" {
		return filepath.Join(h, "config")
	}
	if x := getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "bsecret", "config")
	}
	return filepath.Join(DefaultHome(), "config")
}

// Parse reads the key = value grammar: one setting per line, '#' comments,
// blank lines ignored, a key at most once.
func Parse(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			return nil, fmt.Errorf("config line %d: not key = value", line)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !known(k) {
			return nil, fmt.Errorf("%w: line %d: %q", ErrUnknownKey, line, k)
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("config line %d: %q set twice", line, k)
		}
		out[k] = v
	}
	return out, sc.Err()
}

func known(k string) bool {
	for _, x := range Keys {
		if x == k {
			return true
		}
	}
	return false
}

// Load resolves the file (a missing one is fine) and the environment over
// the defaults. Flags are applied by the caller afterwards with Apply.
func Load(path string, getenv func(string) string) (Config, error) {
	c := Defaults()
	vals := map[string]string{}
	if f, err := os.Open(path); err == nil { //nolint:gosec // the operator's own path
		defer f.Close()
		vals, err = Parse(f)
		if err != nil {
			return c, fmt.Errorf("%s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return c, err
	}
	for _, k := range Keys {
		if v := getenv("BSECRET_" + strings.ToUpper(k)); v != "" {
			vals[k] = v
		}
	}
	return c.Apply(vals)
}

// IsKeyHex reports whether s is an identity key that may own a vault or be
// a member: 66 lowercase hex digits whose bytes meet the key rule.
func IsKeyHex(s string) bool {
	if len(s) != 66 || strings.ToLower(s) != s {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && secrec.CheckIdentity(b) == nil
}

// IsHex32 reports whether s is 64 lowercase hex digits: a vault or secret
// identifier, or a txid.
func IsHex32(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func positiveInt(k, v string, lo, hi int, why string) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("config: %s %q is not a number from %d to %d: %s (docs/limits.md)", k, v, lo, hi, why)
	}
	return n, nil
}

func list(v string) []string {
	var out []string
	for _, h := range strings.Split(v, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// Apply sets the given keys the same way for a file, the environment or
// flags, so all three parse alike.
func (c Config) Apply(vals map[string]string) (Config, error) {
	for _, k := range Keys {
		v, ok := vals[k]
		if !ok {
			continue
		}
		var err error
		switch k {
		case "arcade_key":
			c.ArcadeKey = v
		case "asset":
			c.Asset = v
		case "chain_tree_count":
			c.ChainTreeCount, err = positiveInt(k, v, 1, limits.MaxChainTreeCount, "a vault's first token carries its chain tree whole")
		case "content":
			c.Content = list(v)
		case "crypt":
			if v != "" && secrec.CheckCrypt(v) != nil {
				return c, fmt.Errorf("config: crypt %q is not a crypt identifier <name>_<suffix> (bsecret crypt new prints one)", v)
			}
			c.Crypt = v
		case "delay":
			d, perr := time.ParseDuration(v)
			if perr != nil || d < 0 || d > limits.MaxDelay {
				return c, fmt.Errorf("config: delay %q is not a duration from 0s to %s (docs/limits.md)", v, limits.MaxDelay)
			}
			c.Delay = d
		case "facade":
			c.Facade = v
		case "freshness":
			d, perr := time.ParseDuration(v)
			if perr != nil || d <= 0 || d > limits.MaxFreshness {
				return c, fmt.Errorf("config: freshness %q is not a duration above 0s and at most %s (spec section 7.1)", v, limits.MaxFreshness)
			}
			c.Freshness = d
		case "hall":
			if v != "" && borgrec.CheckHall(v) != nil {
				return c, fmt.Errorf("config: hall %q is not a hall identifier <name>_<suffix> (borg hall new prints one)", v)
			}
			c.Hall = v
		case "hall_hosts":
			c.HallHosts = list(v)
			if len(c.HallHosts) > limits.MaxHosts {
				return c, fmt.Errorf("config: hall_hosts names %d hosts, over the limit of %d (docs/limits.md)", len(c.HallHosts), limits.MaxHosts)
			}
		case "header_url":
			c.HeaderURL = v
		case "home":
			c.Home = v
		case "hosts":
			c.Hosts = list(v)
			if len(c.Hosts) > limits.MaxHosts {
				return c, fmt.Errorf("config: hosts names %d hosts, over the limit of %d: a reader asks every host, and a unicast publisher uploads every object to each (docs/limits.md)", len(c.Hosts), limits.MaxHosts)
			}
		case "max_fetch":
			c.MaxFetch, err = positiveInt(k, v, 1, limits.MaxFetch, "the record bound on a ciphertext")
		case "mode":
			if v != ModePlane && v != ModeUnicast {
				return c, fmt.Errorf("config: mode must be plane or unicast, got %q", v)
			}
			c.Mode = v
		case "network":
			if v != "main" && v != "test" && v != "regtest" {
				return c, fmt.Errorf("config: network must be main, test or regtest, got %q", v)
			}
			c.Network = v
		case "object_bound":
			c.ObjectBound, err = positiveInt(k, v, 1, limits.MaxObjectBound, "no plane admits a larger object (BRC-149)")
		case "org":
			if v != "" && !IsKeyHex(v) {
				return c, fmt.Errorf("config: org %q is not an identity key (66 lowercase hex digits)", v)
			}
			c.Org = v
		case "originator":
			c.Originator = v
		case "paid_host":
			c.PaidHost = v
		case "quorum":
			if _, qerr := Need(v, 1<<30); qerr != nil {
				return c, fmt.Errorf("config: %w", qerr)
			}
			c.Quorum = v
		case "rpc":
			c.RPC = v
		case "rpc_pass":
			c.RPCPass = v
		case "rpc_user":
			c.RPCUser = v
		case "settle":
			c.Settle = v
		case "timeout":
			d, perr := time.ParseDuration(v)
			if perr != nil || d <= 0 {
				return c, fmt.Errorf("config: timeout %q is not a positive duration", v)
			}
			if d < limits.MinTimeout || d > limits.MaxTimeout {
				return c, fmt.Errorf("config: timeout %s is outside the limits of %s to %s (docs/limits.md)", d, limits.MinTimeout, limits.MaxTimeout)
			}
			c.Timeout = d
		case "tree_count":
			c.TreeCount, err = positiveInt(k, v, 1, limits.MaxTreeCount, "every carrier's BEEF carries its whole funding tree")
		case "vault":
			c.Vault = v
		}
		if err != nil {
			return c, err
		}
	}
	for k := range vals {
		if !known(k) {
			return c, fmt.Errorf("%w: %q", ErrUnknownKey, k)
		}
	}
	return c, nil
}

// GroupHosts are the hosts asked about the group's hall.
func (c Config) GroupHosts() []string {
	if len(c.HallHosts) > 0 {
		return c.HallHosts
	}
	return c.Hosts
}

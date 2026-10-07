package config

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const orgKey = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"

func TestFileEnvironmentAndFlagsLayer(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config")
	file := "# a reader\nfacade = http://192.0.2.10:8080\nhosts = http://192.0.2.10:8080, http://192.0.2.11:8080\nnetwork = test\ntimeout = 5s\ncrypt = example_abcdefghij\ncontent = /srv/content, https://content.example.com\n"
	if err := os.WriteFile(p, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"BSECRET_NETWORK": "regtest", "BSECRET_OBJECT_BOUND": "2048", "BSECRET_ORG": orgKey, "BSECRET_DELAY": "5s",
		"BSECRET_HALL_HOSTS": "http://192.0.2.20:8080", "BSECRET_HALL": "example_klmnopqrst"}
	c, err := Load(p, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if c.Facade != "http://192.0.2.10:8080" || len(c.Hosts) != 2 || c.Hosts[1] != "http://192.0.2.11:8080" ||
		c.Network != "regtest" || c.Timeout != 5*time.Second || c.ObjectBound != 2048 || c.Originator != "bsecret" ||
		c.Crypt != "example_abcdefghij" || c.Org != orgKey || c.TreeCount != 32 || c.ChainTreeCount != 8 ||
		c.Delay != 5*time.Second || c.Freshness != time.Minute || len(c.Content) != 2 || c.MaxFetch != 16<<20 ||
		c.Hall != "example_klmnopqrst" || len(c.GroupHosts()) != 1 || c.Mode != ModePlane || c.Quorum != QuorumAll {
		t.Fatalf("%+v", c)
	}
	c, err = c.Apply(map[string]string{"network": "main", "hall_hosts": ""})
	if err != nil || c.Network != "main" || len(c.GroupHosts()) != 2 {
		t.Fatalf("flag over environment, and the hall's hosts default to the crypt's: %v %+v", err, c)
	}
	if _, err := Load(filepath.Join(dir, "absent"), func(string) string { return "" }); err != nil {
		t.Fatalf("a missing file is not an error: %v", err)
	}
}

func TestTheGrammarRefuses(t *testing.T) {
	for _, bad := range []string{"facde = x\n", "no equals\n", "facade = a\nfacade = b\n"} {
		if _, err := Parse(strings.NewReader(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	if _, err := Parse(strings.NewReader("facde = x\n")); !errors.Is(err, ErrUnknownKey) {
		t.Error("an unknown key is not ErrUnknownKey")
	}
	for k, v := range map[string]string{"network": "mainnet", "timeout": "-1s", "object_bound": "0", "crypt": "example", "hall": "example",
		"tree_count": "1001", "chain_tree_count": "33", "freshness": "601s", "delay": "11m", "max_fetch": "134217729", "mode": "multicast",
		"org": strings.ToUpper(orgKey), "quorum": "none", "hosts": strings.Repeat("http://h,", 17), "timeout ": "1s"} {
		if _, err := Defaults().Apply(map[string]string{k: v}); err == nil {
			t.Errorf("%s = %s applied", k, v)
		}
	}
	if !slices.IsSorted(Keys) {
		t.Error("Keys is not in lexicographic order")
	}
}

func TestNoDeploymentAddressHasADefault(t *testing.T) {
	c := Defaults()
	if c.Facade != "" || c.Hosts != nil || c.HallHosts != nil || c.HeaderURL != "" || c.Asset != "" || c.RPC != "" || c.Settle != "" ||
		c.PaidHost != "" || c.Content != nil || c.Crypt != "" || c.Org != "" || c.Vault != "" || c.Hall != "" {
		t.Fatalf("a deployment address has a default: %+v", c)
	}
}

func TestNeed(t *testing.T) {
	for _, c := range []struct {
		q    string
		n    int
		want int
	}{{"all", 3, 3}, {"", 3, 3}, {"majority", 3, 2}, {"majority", 4, 3}, {"one", 3, 1}, {"2", 3, 2}} {
		if got, err := Need(c.q, c.n); err != nil || got != c.want {
			t.Errorf("Need(%q, %d) = %d, %v", c.q, c.n, got, err)
		}
	}
	for _, q := range []string{"4", "0", "-1", "most"} {
		if _, err := Need(q, 3); err == nil {
			t.Errorf("Need(%q, 3) passed", q)
		}
	}
	if _, err := Need("all", 0); err == nil {
		t.Error("a quorum of no hosts passed")
	}
}

func TestPathAndKeys(t *testing.T) {
	env := map[string]string{"BSECRET_HOME": "/h", "XDG_CONFIG_HOME": "/x"}
	if p := Path("/f", func(k string) string { return env[k] }); p != "/f" {
		t.Error(p)
	}
	if p := Path("", func(k string) string { return env[k] }); p != "/h/config" {
		t.Error(p)
	}
	delete(env, "BSECRET_HOME")
	if p := Path("", func(k string) string { return env[k] }); p != "/x/bsecret/config" {
		t.Error(p)
	}
	if !IsKeyHex(orgKey) || IsKeyHex(orgKey[:64]) || IsKeyHex(strings.ToUpper(orgKey)) || IsKeyHex("02"+strings.Repeat("ff", 32)) {
		t.Error("IsKeyHex")
	}
	if !IsHex32(strings.Repeat("ab", 32)) || IsHex32(strings.Repeat("AB", 32)) || IsHex32("ab") {
		t.Error("IsHex32")
	}
}

// On main and test a home needs no node: the chain view, the header
// source and the settlement leg have defaults. regtest has none.
func TestResolveTheNoNodeDefaults(t *testing.T) {
	for _, n := range []string{"main", "test"} {
		c, err := Defaults().Apply(map[string]string{"network": n})
		if err == nil {
			c, err = c.Resolve()
		}
		if err != nil || c.Chain != "woc:"+n || c.HeaderURL != "woc:"+n || c.Settle != "arcade:"+n || c.CheckNetwork() != nil {
			t.Fatalf("%s: %v %+v", n, err, c)
		}
	}
	c, err := Defaults().Apply(map[string]string{"network": "regtest"})
	if c, err = c.Resolve(); err != nil || c.Chain != "" || c.HeaderURL != "" || c.Settle != "" {
		t.Fatalf("regtest: %v %+v", err, c)
	}
	// The older key asset is the chain view asset:<URL>.
	c, _ = Defaults().Apply(map[string]string{"asset": "http://192.0.2.1:8090"})
	if c, err = c.Resolve(); err != nil || c.Chain != "asset:http://192.0.2.1:8090" || c.AssetURL() != "http://192.0.2.1:8090" {
		t.Fatalf("asset: %v %+v", err, c)
	}
	c, _ = Defaults().Apply(map[string]string{"asset": "http://192.0.2.1:8090", "chain": "woc:main"})
	if _, err := c.Resolve(); err == nil {
		t.Fatal("asset and chain both set resolved")
	}
	c, _ = Defaults().Apply(map[string]string{"chain": "woc:test,spend=asset:http://192.0.2.1:8090"})
	if c.AssetURL() != "http://192.0.2.1:8090" {
		t.Fatal(c.AssetURL())
	}
	for _, bad := range []map[string]string{{"network": "main", "chain": "woc:test"}, {"network": "test", "settle": "arcade:main"}} {
		c, _ := Defaults().Apply(bad)
		if c, _ = c.Resolve(); c.CheckNetwork() == nil {
			t.Errorf("%v passed", bad)
		}
	}
}

func TestFeeKeys(t *testing.T) {
	c, err := Defaults().Apply(map[string]string{"fee_rate": "50/1000", "fee_floor": "1", "fee_dust": "1", "fee_max_rate": "1/1",
		"fee_max_tx": "100000", "fee_min_rate": "1/1000", "fee_source": "arc", "fee_policy_urls": "https://a.example, https://b.example"})
	if err != nil {
		t.Fatal(err)
	}
	f := c.Fee
	if f.Rate.Sats != 50 || f.Rate.Bytes != 1000 || *f.Floor != 1 || *f.Dust != 1 || f.MaxRate.Sats != 1 || f.MaxTx != 100000 ||
		f.MinRate.Bytes != 1000 || f.Source != "arc" || len(f.PolicyURLs) != 2 {
		t.Fatalf("%+v", f)
	}
	for k, v := range map[string]string{"fee_rate": "0/1000", "fee_floor": "-1", "fee_source": "live", "fee_max_rate": "x", "fund_unmined": "maybe", "woc_rate": "0"} {
		if _, err := Defaults().Apply(map[string]string{k: v}); err == nil {
			t.Errorf("%s = %s applied", k, v)
		}
	}
}

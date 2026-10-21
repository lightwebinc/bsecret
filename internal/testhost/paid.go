package testhost

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/lightwebinc/bcommon/devkit/paidhost"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// Paid is a stand-in for a host's terms route (docs/spec.md section 10.3):
// devkit's paidhost answering from a Host.
type Paid = paidhost.Paid

// Payment is one accepted payment, in the host ledger's shape.
type Payment = paidhost.Payment

// NewPaid is a terms route for host, paid to payee: ls_bsecret's classes,
// its questions parsed by secrec and answered by the host.
func NewPaid(host *Host, payee *ec.PrivateKey, prices map[string]uint64) *Paid {
	classes := make([]string, len(secrec.Classes))
	for i, c := range secrec.Classes {
		classes[i] = c.Name
	}
	return paidhost.New(paidhost.Service{Name: secrec.LookupService, Classes: classes, Headers: host.chain,
		Ask: func(raw json.RawMessage) (string, func() (any, error), error) {
			qq, err := secrec.ParseQuery(raw)
			if err != nil {
				return "", nil, err
			}
			return qq.Class.Name, func() (any, error) { return host.Answer(qq) }, nil
		}}, payee, prices)
}

// Private is a stand-in for a host whose crypts are private (docs/spec.md
// section 10.4): its /lookup and /.well-known/auth are a terms route that
// answers ls_bsecret over BRC-104, about a private crypt only to the askers
// Allowed names, and every other path is the host's own, whose /lookup
// refuses every question about a private crypt.
type Private struct {
	mu   sync.Mutex
	who  string
	host *Host
	paid *Paid
	// Allowed says whether a private crypt is served to an identity key.
	Allowed func(crypt, identity string) bool
}

// NewPrivate makes crypt private on host, behind a route whose BRC-104
// identity is key.
func NewPrivate(host *Host, key *ec.PrivateKey, crypt string, allowed func(crypt, identity string) bool) *Private {
	host.mu.Lock()
	if host.Private == nil {
		host.Private = map[string]bool{}
	}
	host.Private[crypt] = true
	host.mu.Unlock()
	p := &Private{host: host, Allowed: allowed}
	classes := make([]string, len(secrec.Classes))
	for i, c := range secrec.Classes {
		classes[i] = c.Name
	}
	p.paid = paidhost.New(paidhost.Service{Name: secrec.LookupService, Classes: classes, Headers: host.chain,
		Ask: func(raw json.RawMessage) (string, func() (any, error), error) {
			qq, err := secrec.ParseQuery(raw)
			if err != nil {
				return "", nil, err
			}
			c := qq.Members["crypt"]
			switch {
			case !host.isPrivate(c):
			case p.who == "":
				return "", nil, fmt.Errorf("ls_bsecret: ask over BRC-104: crypt %s is private on this host", c)
			case !p.Allowed(c, p.who):
				return "", nil, fmt.Errorf("ls_bsecret: not served to this key: crypt %s is private on this host", c)
			}
			return qq.Class.Name, func() (any, error) { return host.Answer(qq) }, nil
		}}, key, nil)
	return p
}

// ServeHTTP routes the route's paths to the route, the rest to the host.
func (p *Private) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/lookup" && r.URL.Path != "/.well-known/auth" {
		p.host.ServeHTTP(w, r)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// The route verifies a request under the identity key it names before
	// it asks anything of Ask.
	p.who = r.Header.Get("x-bsv-auth-identity-key")
	p.paid.ServeHTTP(w, r)
	p.who = ""
}

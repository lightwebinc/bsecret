package module

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	bmodule "github.com/lightwebinc/bcommon/module"
	"github.com/lightwebinc/bcommon/termsroute"
)

// Private crypts (docs/host.md): a crypt this host serves only to the
// organizations BSECRET_PRIVATE names for it and to the members of their
// groups, every class through the terms route over BRC-104. The host's own
// /lookup refuses every question about such a crypt, and so does the route
// for an asker it cannot place. Who is a member is borg's: the hosts of the
// halls the organization's vaults in the crypt name (BSECRET_HALL_URL) are
// asked borg's member-of class for the asker. An answer is kept for
// BSECRET_MEMBER_TTL; a host that does not answer refuses the asker until
// one does. The asker is the identity key the route verified the request
// under, carried in ctx (termsroute.Caller).
const (
	// MaxMembers is the most askers whose membership is kept at once.
	MaxMembers = 10000
	// HallTimeout is how long a hall host is given to answer.
	HallTimeout = 5 * time.Second
	// MaxHallAnswer is the most bytes of a hall host's answer read.
	MaxHallAnswer = 16 << 20
)

// PrivateResults are the results the gate counts in bsecret_private_total.
var PrivateResults = []string{"served", "unauthenticated", "refused", "unknown"}

type known struct {
	crypts  map[string]bool
	unknown map[string]bool
	at      time.Time
}

// MembersOptions build Members.
type MembersOptions struct {
	// Crypts are the private crypts and the organizations each is served to.
	Crypts map[string]map[string]bool
	// HallURLs are borg hosts, asked member-of.
	HallURLs []string
	// Halls are the halls an organization's vaults in a crypt name, from
	// the index.
	Halls func(crypt, org string) []string
	Host  bmodule.Host
	TTL   time.Duration
	// Client asks the hall hosts; http.DefaultClient with HallTimeout when nil.
	Client *http.Client
	Now    func() time.Time
}

// Members is who a private crypt is served to.
type Members struct {
	o      MembersOptions
	mu     sync.Mutex
	known  map[string]*known
	order  []string
	client *http.Client
	now    func() time.Time
}

// NewMembers makes the gate.
func NewMembers(o MembersOptions) *Members {
	if o.TTL <= 0 {
		o.TTL = DefaultMemberTTL * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: HallTimeout}
	}
	m := &Members{o: o, known: map[string]*known{}, client: o.Client, now: o.Now}
	for _, r := range PrivateResults {
		o.Host.Metrics().Preset("bsecret_private_total", map[string]string{"result": r})
	}
	return m
}

// Size is how many askers are known.
func (m *Members) Size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.known)
}

// Any is whether the host has any private crypt.
func (m *Members) Any() bool { return len(m.o.Crypts) > 0 }

// IsPrivate is whether crypt is private.
func (m *Members) IsPrivate(crypt string) bool { _, ok := m.o.Crypts[crypt]; return ok }

// Prime settles which private crypts identity is served, unless what is
// known of it is younger than the TTL.
func (m *Members) Prime(ctx context.Context, identity string) {
	if !m.Any() || !keyHex(identity) {
		return
	}
	m.mu.Lock()
	if k := m.known[identity]; k != nil && m.now().Sub(k.at) < m.o.TTL {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()
	crypts := map[string]bool{}
	unknown := map[string]bool{}
	for c, orgs := range m.o.Crypts {
		if orgs[identity] {
			crypts[c] = true
			continue
		}
		failed := false
	search:
		for org := range orgs {
			for _, hall := range m.o.Halls(c, org) {
				for _, url := range m.o.HallURLs {
					r := m.memberOf(ctx, url, hall, org, identity)
					if r == 1 {
						crypts[c] = true
						failed = false
						break search
					}
					if r < 0 {
						failed = true
					}
				}
			}
		}
		if failed && !crypts[c] {
			unknown[c] = true
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.known[identity]; ok {
		delete(m.known, identity)
		for i, id := range m.order {
			if id == identity {
				m.order = append(m.order[:i], m.order[i+1:]...)
				break
			}
		}
	}
	for len(m.order) >= MaxMembers {
		delete(m.known, m.order[0])
		m.order = m.order[1:]
	}
	at := m.now()
	if len(unknown) > 0 {
		at = time.Time{}
	}
	m.known[identity] = &known{crypts: crypts, unknown: unknown, at: at}
	m.order = append(m.order, identity)
}

// memberOf is whether a hall host says identity is a member of a group of
// org: 1 yes, 0 no, -1 when it could not say.
func (m *Members) memberOf(ctx context.Context, url, hall, org, identity string) int {
	body, _ := json.Marshal(map[string]any{"service": "ls_borg", "query": map[string]string{"hall": hall, "org": org, "memberOf": identity}})
	ctx, cancel := context.WithTimeout(ctx, HallTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/lookup", bytes.NewReader(body))
	if err != nil {
		return -1
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := m.client.Do(req)
	if err != nil {
		m.o.Host.Log("bsecret private crypt: a hall host could not be asked", map[string]any{"url": url, "err": err.Error()})
		return -1
	}
	defer res.Body.Close()
	text, err := io.ReadAll(io.LimitReader(res.Body, MaxHallAnswer+1))
	if err != nil || res.StatusCode != http.StatusOK || len(text) > MaxHallAnswer {
		return -1
	}
	var a struct {
		Type    string            `json:"type"`
		Outputs []json.RawMessage `json:"outputs"`
	}
	if err := json.Unmarshal(text, &a); err != nil || a.Type != "output-list" || a.Outputs == nil {
		return -1
	}
	if len(a.Outputs) > 0 {
		return 1
	}
	return 0
}

// Check refuses a question about a private crypt from anyone it is not
// served to: by the host's own /lookup (no asker), and by the route for an
// asker that is neither one of the crypt's organizations nor a member of
// their groups. An asker the route verified is primed first.
func (m *Members) Check(ctx context.Context, crypt string) error {
	if _, private := m.o.Crypts[crypt]; !private {
		return nil
	}
	count := func(result string) {
		m.o.Host.Metrics().Inc("bsecret_private_total", map[string]string{"result": result}, 1)
	}
	identity, ok := termsroute.Caller(ctx)
	if !ok {
		count("unauthenticated")
		return fmt.Errorf("ls_bsecret: ask over BRC-104: crypt %s is private on this host; its terms route's /lookup answers the crypt's organizations and the members of their groups", crypt)
	}
	m.Prime(ctx, identity)
	m.mu.Lock()
	k := m.known[identity]
	m.mu.Unlock()
	switch {
	case k != nil && k.crypts[crypt]:
		count("served")
		return nil
	case k != nil && k.unknown[crypt]:
		count("unknown")
		return fmt.Errorf("ls_bsecret: membership unknown: crypt %s is private on this host, and no hall host could say whether this key is a member; ask again later", crypt)
	}
	count("refused")
	return fmt.Errorf("ls_bsecret: not served to this key: crypt %s is private on this host", crypt)
}

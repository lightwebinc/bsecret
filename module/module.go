package module

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"

	"github.com/lightwebinc/bcommon/bwallet"
	"github.com/lightwebinc/bcommon/headers"
	bmodule "github.com/lightwebinc/bcommon/module"
	"github.com/lightwebinc/bcommon/termsroute"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// Name is the module's name, as a host's module list names it.
const Name = "bsecret"

// PruneEvery is how often retention runs; TickEvery how often the
// background tick runs (the payment watch; retention every PruneEvery).
const (
	PruneEvery = time.Hour
	TickEvery  = 30 * time.Second
)

// Build is the version the host logs; a binary sets it.
var Build = "unversioned"

// Mounted is the module for one configuration: the contract's Module, the
// lookup service, and what Start runs.
type Mounted struct {
	Module bmodule.Module
	LS     *Service
	// Members is who the private crypts are served to, when there are any.
	Members *Members
	// Front is the terms route, when configured.
	Front  *Front
	config *Config
	host   bmodule.Host
	ledger *termsroute.Ledger
}

// Front is the terms route and where it listens.
type Front struct {
	*termsroute.Front
	Addr string
}

// Mount builds the module for c. overlayTopics is OVERLAY_TOPICS, when
// known; journal replaces the state directory's, hdrs the configured
// header source and now the host's clock, for tests.
func Mount(host bmodule.Host, c *Config, overlayTopics []string, journal Journal, hdrs chaintracker.ChainTracker, now func() time.Time) (*Mounted, error) {
	names := map[string]bool{}
	for _, crypt := range c.Crypts {
		names[secrec.Topic(crypt)] = true
	}
	for _, t := range overlayTopics {
		if strings.HasPrefix(t, secrec.TopicPrefix) && !names[t] {
			return nil, fmt.Errorf("OVERLAY_TOPICS names %s but BSECRET_CRYPTS does not configure it; it would be admitted by the default manager", t)
		}
	}
	m := host.Metrics()
	for _, kind := range AdmitKinds {
		m.Preset("bsecret_admitted_total", map[string]string{"kind": kind})
		m.Preset("bsecret_admitted_repeats_total", map[string]string{"kind": kind})
	}
	for _, reason := range Reasons {
		m.Preset("bsecret_refused_total", map[string]string{"reason": reason})
	}
	for _, status := range TokenStatuses {
		m.Preset("bsecret_token_status_total", map[string]string{"status": status})
	}
	for _, why := range []string{"evidence", "retention", "table"} {
		m.Preset("bsecret_dropped_total", map[string]string{"why": why})
	}
	m.Preset("bsecret_retractions_total", nil)
	m.Preset("bsecret_equivocations_total", nil)
	priced := map[string]bool{}
	for name, p := range c.Prices {
		if p > 0 {
			priced[name] = true
		}
	}
	if hdrs == nil {
		hdrs = headers.New(c.HeadersURL)
	}
	if now == nil {
		now = time.Now
	}
	if journal == nil {
		fj, err := NewFileJournal(c.StateDir)
		if err != nil {
			return nil, err
		}
		journal = fj
	}
	var members *Members
	ls, err := NewService(Options{Crypts: c.Crypts, Host: host, Journal: journal, Priced: priced, RetentionDays: c.RetentionDays, UnheldHours: c.UnheldHours,
		SpendTable: c.SpendTable, Headers: hdrs, Now: now, Access: func(ctx context.Context, crypt string) error {
			if members == nil {
				return nil
			}
			return members.Check(ctx, crypt)
		}})
	if err != nil {
		return nil, err
	}
	if len(c.Private) > 0 {
		members = NewMembers(MembersOptions{Crypts: c.Private, HallURLs: c.HallURLs, Halls: ls.HallsOf, Host: host, TTL: c.MemberTTL, Now: now})
		m.Gauge("bsecret_private_crypts", func() float64 { return float64(len(c.Private)) })
		m.Gauge("bsecret_private_members_known", func() float64 { return float64(members.Size()) })
	}
	m.Gauge("bsecret_crypts", func() float64 { return float64(len(c.Crypts)) })
	m.Gauge("bsecret_vaults", func() float64 { return float64(ls.Counts().Vaults) })
	m.Gauge("bsecret_tokens", func() float64 { return float64(ls.Counts().Tokens) })
	m.Gauge("bsecret_tokens_pending", func() float64 { return float64(ls.Counts().PendingTokens) })
	m.Gauge("bsecret_carriers", func() float64 { return float64(ls.Counts().Carriers) })
	m.Gauge("bsecret_sweeps", func() float64 { return float64(ls.Counts().Sweeps) })
	m.Gauge("bsecret_outpoint_rows", func() float64 { return float64(ls.Counts().Rows) })
	m.Gauge("bsecret_spend_table", func() float64 { return float64(ls.Counts().Table) })
	topics := map[string]bmodule.TopicManager{}
	for _, crypt := range c.Crypts {
		tm, err := NewTopicManager(secrec.Topic(crypt), host, hdrs, c.MaxBEEF, c.MaxSweepInputs)
		if err != nil {
			return nil, err
		}
		topics[secrec.Topic(crypt)] = tm
	}
	out := &Mounted{Module: bmodule.Module{Topics: topics, Lookups: map[string]bmodule.LookupService{secrec.LookupService: ls}}, LS: ls, Members: members, config: c, host: host}
	if c.Listen != "" {
		var receiver termsroute.Receiver
		var gate *termsroute.Gate
		if len(priced) > 0 {
			ledger, err := termsroute.OpenLedger(c.StateDir, termsroute.LayoutSpread, now)
			if err != nil {
				return nil, err
			}
			out.ledger = ledger
			receiver = ledger
			gate = termsroute.GateFor("bsecret", host, hdrs, c.Accept, c.StateDir)
		}
		f, err := termsroute.New(termsroute.Options{App: "bsecret", Service: secrec.LookupService, Classes: Classes, PaymentProtocol: bwallet.PaymentProtocol,
			LS: RouteAnswerer{LS: ls}, Host: host, Prices: c.Prices, Payee: c.PayeeKey, Receiver: receiver, Headers: hdrs, Gate: gate,
			Sessions: c.Sessions, Budget: c.Budget, Responses: c.Response, Now: now})
		if err != nil {
			return nil, err
		}
		if out.ledger != nil {
			f.RestoreFast(out.ledger.Fast)
		}
		out.Front = &Front{Front: f, Addr: c.Listen}
	}
	terms, sessions, handshakes, responses, payments := "none", "none", "none", "none", "none"
	if c.Listen != "" {
		terms = c.Listen
		sessions = fmt.Sprintf("%d, idle %ds", c.Sessions.Max, int(c.Sessions.TTL/time.Second))
		handshakes = fmt.Sprintf("%g/s burst %d, per address %g/s burst %d", c.Budget.PerSec, c.Budget.Burst, c.Budget.PerAddressPerSec, c.Budget.AddressBurst)
		responses = fmt.Sprintf("%g/s burst %d a session", c.Response.PerSec, c.Response.Burst)
	}
	if out.Front != nil && out.Front.Gate != nil {
		if out.Front.Gate.Networked() {
			payments = fmt.Sprintf("fast to %d sat, payer %d, total %d", c.Accept.Policy.ThresholdSats, c.Accept.Policy.PayerLimit, c.Accept.Policy.TotalLimit)
		} else {
			payments = "held until mined (no arcade or asset URL)"
		}
	}
	pricedNames := make([]string, 0, len(priced))
	for n := range priced {
		pricedNames = append(pricedNames, n)
	}
	privateNames := make([]string, 0, len(c.Private))
	for n := range c.Private {
		privateNames = append(privateNames, n)
	}
	topicNames := make([]string, 0, len(topics))
	for t := range topics {
		topicNames = append(topicNames, t)
	}
	host.Log("bsecret module mounted", map[string]any{"topics": strings.Join(sortedStrings(topicNames), ","), "lookup": secrec.LookupService, "headers": c.HeadersURL,
		"terms": terms, "priced": orNone(sortedStrings(pricedNames)), "sessions": sessions, "handshakes": handshakes, "responses": responses,
		"private": orNone(sortedStrings(privateNames)), "payments": payments, "build": Build})
	return out, nil
}

func orNone(a []string) string {
	if len(a) == 0 {
		return "none"
	}
	return strings.Join(a, ",")
}

// Start serves the terms route (when configured) until ctx ends, and runs
// the background tick: the payment watch every TickEvery and retention
// every PruneEvery once the index is restored. It returns when ctx ends.
func (m *Mounted) Start(ctx context.Context) error {
	go func() {
		pruned := time.Now()
		t := time.NewTicker(TickEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			if m.Front != nil {
				m.Front.Tick(ctx)
			}
			if !m.LS.Restored() || time.Since(pruned) < PruneEvery {
				continue
			}
			pruned = time.Now()
			m.LS.Prune(ctx)
		}
	}()
	if m.Front == nil {
		<-ctx.Done()
		return nil
	}
	return m.Front.Front.Listen(ctx, m.Front.Addr)
}

// New is the factory a host calls: the configuration from getenv, checked
// against OVERLAY_TOPICS and OVERLAY_SYNC_PEERS.
func New(host bmodule.Host, getenv func(string) string) (*Mounted, error) {
	if getenv == nil {
		return nil, errors.New("bsecret: no environment")
	}
	var topics []string
	for _, t := range strings.Split(getenv("OVERLAY_TOPICS"), ",") {
		if t = strings.TrimSpace(t); t != "" {
			topics = append(topics, t)
		}
	}
	if err := CheckNoSync(getenv("OVERLAY_SYNC_PEERS")); err != nil {
		return nil, err
	}
	c, err := ParseConfig(getenv)
	if err != nil {
		return nil, err
	}
	return Mount(host, c, topics, nil, nil, nil)
}

func sortedStrings(a []string) []string {
	out := append([]string(nil), a...)
	sort.Strings(out)
	return out
}

package limits

import (
	"fmt"
	"time"
)

// The policy limits of docs/limits.md, as the bsecret command applies them.
// None is a wire format or a signed bound (docs/frozen.md): the record
// bounds every reader accepts are secrec's, and these are what a client
// chooses to send and to ask, so a later version may change any of them
// without a new record version. A cap refuses the setting before anything
// is sent, with a message naming the setting and the limit; a warning is
// printed and the command goes on.

// The plane's packets: an object larger than one is carried as fragments
// of FragmentPayload bytes (the IPv6 minimum MTU of 1280 less the IPv6, UDP
// and object fragment headers).
const (
	FragmentPayload = 1128
	// OpenObjectBound is BRC-149's bound on an object submitted on the open
	// path; MaxObjectBound the authenticated path's. No plane admits more.
	OpenObjectBound = 1 << 20
	MaxObjectBound  = 8 << 20
	// DefaultObjectBound is the object bound assumed when none is set.
	DefaultObjectBound = OpenObjectBound
)

// Funding trees.
const (
	DefaultTreeCount   = 32
	MaxTreeCount       = 1000
	PlaneTreeCountWarn = 100
	// DefaultChainTreeCount and MaxChainTreeCount size a chain tree: a
	// vault's first token carries its chain tree whole.
	DefaultChainTreeCount = 8
	MaxChainTreeCount     = 32
	// DefaultTreeSats is each funding output's value. A carrier carries its
	// funding output's whole value and is never mined, and a first token
	// spends one chain-tree output, so one satoshi is enough.
	DefaultTreeSats = 1
	// DefaultAhead is how few outputs a secret tree has left when the next
	// is minted ahead.
	DefaultAhead = 4
)

// Secrets and transitions.
const (
	// SecretsWarn is the vault size above which a put is warned about: a
	// removal from the group then takes more than 4 blocks to settle.
	SecretsWarn = 256
	// PlaneChangesWarn is the most changes one token makes on the plane
	// before a warning, except while the vault is in debt.
	PlaneChangesWarn = 16
	// InlineValueWarn is the value size above which a put on the plane is
	// warned about: the carrier then passes 7 packets.
	InlineValueWarn = 4096
	// DefaultSegment is the plaintext bytes of one segment: an inline
	// secret is one segment.
	DefaultSegment = 16384
	// PadBlock is the multiple an encoded payload is padded to.
	PadBlock = 256
	// DefaultMaxFetch is the most ciphertext a reader fetches by hash;
	// MaxFetch the record bound.
	DefaultMaxFetch = 16 << 20
	MaxFetch        = 1 << 27
)

// Publication and freshness.
const (
	// DefaultDelay is the propagation delay after a mined object's block
	// is in the publisher's headers, before it is published; MaxDelay its
	// cap.
	DefaultDelay = 60 * time.Second
	MaxDelay     = 10 * time.Minute
	// DefaultFreshness and MaxFreshness bound how old a writer's or a
	// reader's evidence that a token is the latest may be (spec section
	// 7.1).
	DefaultFreshness = 60 * time.Second
	MaxFreshness     = 600 * time.Second
)

// Hosts, quorum and requests.
const (
	MaxHosts         = 16
	UnicastHostsWarn = 5
	MinTimeout       = time.Second
	MaxTimeout       = 5 * time.Minute
	DefaultTimeout   = 15 * time.Second
)

// Retries are the waits between the tries of a submission: four tries,
// then the host is reported missed and the object stays persisted.
var Retries = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}

// PlaneWait are the waits between a publisher's lookups for a carrier it
// submitted to the plane, at each host it names, before it offers the
// carrier to that host directly: the plane delivers in well under a second.
var PlaneWait = []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second}

// Reading.
const (
	// TokenPage and CarrierPage are the most outputs one answer page holds
	// (the spec's): tokens, and secret carriers.
	TokenPage   = 64
	CarrierPage = 16
	// MaxPages is the most pages one question reads per host.
	MaxPages = 256
	// MaxVaults is the most vaults of one owner a client lists per host.
	MaxVaults = 4096
	// DefaultMaxPrice is the most a priced question is paid without
	// -max-sats.
	DefaultMaxPrice = 1000
	// RunVersions is the most unlisted versions above a listed one a
	// reader of an interval vault follows: a run is asked for version by
	// version, and what a host or an owner claims above it is never
	// walked to.
	RunVersions = 64
	// MaxAnswer is the most bytes a reader takes for one lookup answer: a
	// full page of the largest objects the plane carries fits several
	// times over.
	MaxAnswer = 16 << 20
	// DefaultBudget is the most a command that asks several priced
	// questions pays in all without -budget.
	DefaultBudget = 16 * DefaultMaxPrice
	// MaxBEEF is the most a reader takes for one answered object.
	MaxBEEF = 1 << 20
	// MaxUnminedPayments is how many of a payer's own payments may be
	// unmined at once with the next spending the change of the last: each
	// adds its transaction to the next payment's BEEF.
	MaxUnminedPayments = 16
)

// Settling.
const (
	DefaultSettleInFlight = 16
	MaxSettleInFlight     = 64
)

// Publisher is a publisher's settings, as the checks see them.
type Publisher struct {
	Plane          bool
	Hosts          int
	Need           int
	TreeCount      int
	ChainTreeCount int
	ObjectBound    int
}

func over(what string, v, limit any, why string) error {
	return fmt.Errorf("%s %v is over the limit of %v: %s (docs/limits.md)", what, v, limit, why)
}

// Check applies the caps, returning the first broken as an error, and the
// recommendations, returning each passed as a warning.
func (p Publisher) Check() (warnings []string, err error) {
	switch {
	case p.TreeCount < 1:
		return nil, fmt.Errorf("tree_count %d is under the limit of 1: a funding tree has at least one output (docs/limits.md)", p.TreeCount)
	case p.TreeCount > MaxTreeCount:
		return nil, over("tree_count", p.TreeCount, MaxTreeCount, "every carrier's BEEF carries its whole funding tree")
	case p.ChainTreeCount < 1:
		return nil, fmt.Errorf("chain_tree_count %d is under the limit of 1 (docs/limits.md)", p.ChainTreeCount)
	case p.ChainTreeCount > MaxChainTreeCount:
		return nil, over("chain_tree_count", p.ChainTreeCount, MaxChainTreeCount, "a vault's first token carries its chain tree whole")
	case p.ObjectBound > MaxObjectBound:
		return nil, over("object_bound", p.ObjectBound, MaxObjectBound, "no plane admits a larger object (BRC-149)")
	case p.Hosts > MaxHosts:
		return nil, over("hosts", p.Hosts, MaxHosts, "a unicast publisher uploads every object to each host, and a reader asks each")
	}
	if p.Plane {
		if p.TreeCount > PlaneTreeCountWarn {
			warnings = append(warnings, fmt.Sprintf("tree_count %d on the plane adds about %d bytes of funding tree to every carrier; %d is the default (docs/limits.md)", p.TreeCount, p.TreeCount*49, DefaultTreeCount))
		}
	} else {
		if p.Hosts > UnicastHostsWarn {
			warnings = append(warnings, fmt.Sprintf("%d hosts in mode unicast: every object is uploaded %d times; beyond %d hosts the plane is what removes that cost (docs/limits.md)", p.Hosts, p.Hosts, UnicastHostsWarn))
		}
		if p.Need > 0 && p.Need < p.Hosts/2+1 {
			warnings = append(warnings, fmt.Sprintf("a quorum of %d of %d hosts is below a majority: a carrier counts as published while most hosts lack it; tokens and sweeps always need every host (docs/limits.md)", p.Need, p.Hosts))
		}
	}
	return warnings, nil
}

// Package state is an identity's durable record in its home: the funding
// trees its carriers and vaults spend, the vaults it owns (each vault's
// chain of mined tokens and every version it published), the objects
// persisted before they are published, the sweeps it built, every content
// key commitment it ever published or listed, and, for a reader, the latest
// token of each vault it has verified.
//
// It is written before anything leaves the machine. A carrier is persisted
// with the funding output it spends marked used and its commitment
// recorded, and a transition with the record it signs, before either is
// sent, so a run that stops part way sends the same bytes again and never
// makes a second carrier on one funding output. The file is written
// atomically (a temporary file, fsync, rename, fsync of the directory) at
// mode 0600, and the home is locked while a command writes.
//
// The file holds no key: a content key is sampled, wrapped and forgotten,
// and an epoch key is opened from the group's wraps each time it is
// needed. The identity key the wallet keeps in the same directory opens
// every version this identity wrote through its self wrap, so the home is
// kept at mode 0700 and backed up as a secret.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/lightwebinc/bcommon/bwallet"
	"github.com/lightwebinc/bcommon/funding"
)

// Version is the state file's format version.
const Version = 1

// File is the state file's name in the home.
const File = "state.json"

// The kinds of object a home publishes.
const (
	KindSecret = "secret"
	KindToken  = "vault-token"
	KindSweep  = "sweep"
)

// The kinds of funding tree, each under its own key and basket (spec
// section 12.4).
const (
	TreeSecret = "secret"
	TreeChain  = "chain"
)

// TreeKinds are the tree kinds in a fixed order.
var TreeKinds = []string{TreeSecret, TreeChain}

// State is one identity's state.
type State struct {
	Version int `json:"version"`
	// Identity is the identity key, compressed hex.
	Identity string `json:"identity"`
	// Crypts are the crypts this home created (crypt new).
	Crypts []string `json:"crypts,omitempty"`

	// Trees are the funding trees by kind.
	Trees map[string]*TreeSet `json:"trees,omitempty"`

	// Vaults are the vaults this identity owns.
	Vaults []Vault `json:"vaults,omitempty"`

	// Outbox holds every object persisted and not yet confirmed published,
	// oldest first. A command that finds one publishes the same bytes
	// before it builds anything new.
	Outbox []Pending `json:"outbox,omitempty"`
	// Sweeps are the sweeps this home built.
	Sweeps []Sweep `json:"sweeps,omitempty"`

	// Commitments are every content key commitment this home published or
	// listed, in any vault (hash byte order, hex). A version whose
	// commitment is here is never published (spec section 6.2).
	Commitments []string `json:"commitments,omitempty"`

	// Seen is the latest token of each vault this identity verified as a
	// reader: a host that answers an older one is answering an old state.
	Seen []Seen `json:"seen,omitempty"`

	// Payments are the payments this identity made for priced questions
	// that have not mined yet, each as the BEEF the host was handed: the
	// next payment may spend the change of one, and then carries it.
	Payments []Payment `json:"payments,omitempty"`

	// Settled are the txids of payments to this identity as a host's payee
	// that payee settle internalized; Unsettleable those the network
	// refused for good.
	Settled      []string       `json:"settled,omitempty"`
	Unsettleable []Unsettleable `json:"unsettleable,omitempty"`

	path string
}

// TreeSet is one kind's funding trees: the one carriers spend now, every
// tree minted, and the trees minted ahead and never adopted when a run
// ended (on the chain, in no other list, kept so a sweep finds them).
type TreeSet struct {
	Tree  *funding.Tree  `json:"tree,omitempty"`
	Trees []funding.Tree `json:"trees,omitempty"`
	Ahead []funding.Tree `json:"ahead,omitempty"`
}

// Set is the tree set of kind, made when absent.
func (s *State) Set(kind string) *TreeSet {
	if s.Trees == nil {
		s.Trees = map[string]*TreeSet{}
	}
	ts := s.Trees[kind]
	if ts == nil {
		ts = &TreeSet{}
		s.Trees[kind] = ts
	}
	return ts
}

// TreeOf finds a funding tree of any kind the home recorded, and its kind.
func (s *State) TreeOf(txid string) (*funding.Tree, string, bool) {
	for _, kind := range TreeKinds {
		ts := s.Trees[kind]
		if ts == nil {
			continue
		}
		if ts.Tree != nil && ts.Tree.Txid == txid {
			return ts.Tree, kind, true
		}
		for i := range ts.Trees {
			if ts.Trees[i].Txid == txid {
				return &ts.Trees[i], kind, true
			}
		}
		for i := range ts.Ahead {
			if ts.Ahead[i].Txid == txid {
				return &ts.Ahead[i], kind, true
			}
		}
	}
	return nil, "", false
}

// Vault is one vault this identity owns.
type Vault struct {
	// ID is the vault identifier, 64 lowercase hex digits.
	ID    string `json:"id"`
	Crypt string `json:"crypt"`
	Name  string `json:"name"`
	// Hall and Group name the borg group whose epochs key the vault.
	Hall   string   `json:"hall"`
	Group  string   `json:"group"`
	Anchor uint64   `json:"anchor"`
	Labels []string `json:"labels"`
	// Tokens are its chain, mined, in seq order.
	Tokens []Token `json:"tokens,omitempty"`
	// Pending is a transition built and persisted, not yet known mined.
	Pending *Transition `json:"pending,omitempty"`
	// Versions are every version of every secret this home published in
	// the vault, oldest first.
	Versions []SecretVersion `json:"versions,omitempty"`
}

// Token is one mined vault token.
type Token struct {
	Seq    uint64 `json:"seq"`
	Txid   string `json:"txid"`
	RawHex string `json:"rawHex"`
	// BumpHex is its proof and Height its block's height.
	BumpHex string `json:"bumpHex"`
	Height  uint32 `json:"height"`
	// Record is the token's vault record, hex; Vout its token output.
	Record string `json:"record"`
	Vout   uint32 `json:"vout"`
	// Parent is the transaction its predecessor input spends: the token at
	// seq - 1, or at seq 0 the chain tree.
	Parent string `json:"parent"`
	// Published is set once every host named took it.
	Published bool `json:"published,omitempty"`
}

// SecretVersion is one version of one secret, as its owner keeps it.
type SecretVersion struct {
	// Name is the secret's name; ID its identifier, hex.
	Name    string `json:"name"`
	ID      string `json:"id"`
	Version uint64 `json:"version"`
	// ContentID and Commitment are the version's, hash byte order, hex.
	ContentID  string `json:"contentId"`
	Commitment string `json:"commitment"`
	Epoch      uint64 `json:"epoch"`
	Label      string `json:"label"`
	// Txid is the carrier's txid, display order.
	Txid string `json:"txid"`
	// Tree and Vout are the secret-tree output the carrier spends: a sweep
	// of it retracts the version.
	Tree string `json:"tree"`
	Vout uint32 `json:"vout"`
	// Raw is the carrier's transaction, hex: its one output holds the
	// record, with the ciphertext when it is carried. Emptied once the
	// version is swept. The funding tree it spends is kept with the trees,
	// and the BEEF it is published in stays in the outbox only until every
	// host named took it.
	Raw string `json:"raw,omitempty"`
	// Hash is the ciphertext's SHA-256, hex; Stored is set when the
	// ciphertext is not carried and was written to the content directory.
	Hash   string `json:"hash"`
	Stored bool   `json:"stored,omitempty"`
	// Listed is set once a mined token of the vault lists the version, with
	// that token's seq.
	Listed bool   `json:"listed,omitempty"`
	Seq    uint64 `json:"seq,omitempty"`
	// Ended is set once a later token replaced or retired the version.
	Ended bool `json:"ended,omitempty"`
	// Swept is the sweep that spent its funding output.
	Swept string `json:"swept,omitempty"`
	// Created is the record's claim; RotateEvery and NotAfter the
	// payload's, kept so that what is due is computed without a read.
	Created     uint64 `json:"created"`
	RotateEvery uint64 `json:"rotateEvery,omitempty"`
	NotAfter    uint64 `json:"notAfter,omitempty"`
}

// Transition is a vault token built and persisted before it is sent.
type Transition struct {
	// Vault is the vault's identifier.
	Vault string `json:"vault"`
	Seq   uint64 `json:"seq"`
	Txid  string `json:"txid"`
	// RawHex is the signed transaction, Record its vault record.
	RawHex string `json:"rawHex"`
	Record string `json:"record"`
	Vout   uint32 `json:"vout"`
	// Parent is the transaction its predecessor input spends, and
	// ParentVout the output.
	Parent     string `json:"parent"`
	ParentVout uint32 `json:"parentVout"`
	// Fee is the pool coin that pays its fee, as the pool held it.
	Fee *bwallet.Output `json:"fee,omitempty"`
	// Submitted is set once the settlement leg took it.
	Submitted bool `json:"submitted,omitempty"`
	// What describes it in notes.
	What string `json:"what,omitempty"`
}

// Pending is one object persisted before it is published.
type Pending struct {
	Kind  string `json:"kind"`
	Crypt string `json:"crypt"`
	Txid  string `json:"txid"`
	// Beef is the object's BEEF, hex.
	Beef string `json:"beef"`
	// The lookup that confirms a host holds it, when the host's answer to
	// the submission admitted nothing: for a secret the owner, vault,
	// secret and version (version class); for a token the owner, vault and
	// seq (vault-seq class); for a sweep one outpoint it spends.
	Org      string `json:"org,omitempty"`
	Vault    string `json:"vault,omitempty"`
	Seq      uint64 `json:"seq,omitempty"`
	Secret   string `json:"secret,omitempty"`
	Version  uint64 `json:"version,omitempty"`
	Outpoint string `json:"outpoint,omitempty"`
	// NotBefore is the Unix time before which it is not published: a mined
	// object waits for the propagation delay (spec section 8.3).
	NotBefore int64 `json:"notBefore,omitempty"`
}

// Mined reports whether a pending object is a mined one, which every host
// named must take.
func (p Pending) Mined() bool { return p.Kind == KindToken || p.Kind == KindSweep }

// Sweep is one mined transaction spending funding-tree outputs: output 0 a
// funding-shaped tombstone, so a host admits it, and every carrier that
// spent one of Vouts retracted once it mines.
type Sweep struct {
	Tree  string   `json:"tree"`
	Vouts []uint32 `json:"vouts"`
	Crypt string   `json:"crypt"`
	Txid  string   `json:"txid"`
	// RawHex is the signed sweep; BumpHex and Height are set once it mined.
	RawHex    string `json:"rawHex"`
	BumpHex   string `json:"bumpHex,omitempty"`
	Height    uint32 `json:"height,omitempty"`
	Submitted bool   `json:"submitted,omitempty"`
	// Done is set once it is mined and handed to the outbox.
	Done bool `json:"done,omitempty"`
	// Fee is the pool coin that pays its fee, as the pool held it.
	Fee *bwallet.Output `json:"fee,omitempty"`
	// Failed is why the network refused it, once it did.
	Failed string `json:"failed,omitempty"`
}

// Seen is the latest token of one vault this identity verified.
type Seen struct {
	Crypt string `json:"crypt"`
	Org   string `json:"org"`
	Vault string `json:"vault"`
	Seq   uint64 `json:"seq"`
	Txid  string `json:"txid"`
}

// Payment is a payment this identity made that has not mined yet.
type Payment struct {
	Txid string `json:"txid"`
	// Beef is the payment as Atomic BEEF, hex, with its ancestry back to
	// each proof.
	Beef string `json:"beef"`
}

// PaymentOf finds an unmined payment of this identity's.
func (s *State) PaymentOf(txid string) *Payment {
	for i := range s.Payments {
		if s.Payments[i].Txid == txid {
			return &s.Payments[i]
		}
	}
	return nil
}

// KeepPayments drops every payment whose txid is not in waiting: it mined,
// and its change needs no ancestry any more. It reports whether any went.
func (s *State) KeepPayments(waiting []string) bool {
	n := len(s.Payments)
	s.Payments = slices.DeleteFunc(s.Payments, func(p Payment) bool { return !slices.Contains(waiting, p.Txid) })
	return len(s.Payments) != n
}

// Unsettleable is a payment the network refused, and why.
type Unsettleable struct {
	Txid string `json:"txid"`
	Why  string `json:"why"`
}

// IsUnsettleable reports whether txid is a payment recorded as refused.
func (s *State) IsUnsettleable(txid string) bool {
	return slices.ContainsFunc(s.Unsettleable, func(u Unsettleable) bool { return u.Txid == txid })
}

// Load reads the home's state, or a new one for identity when the home has
// none yet.
func Load(home, identity string) (*State, error) {
	p := filepath.Join(home, File)
	raw, err := os.ReadFile(p) //nolint:gosec // the home's own file
	if errors.Is(err, os.ErrNotExist) {
		return &State{Version: Version, Identity: identity, path: p}, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("state %s: %w", p, err)
	}
	if s.Version != Version {
		return nil, fmt.Errorf("state %s: version %d, this bsecret reads %d", p, s.Version, Version)
	}
	if identity != "" && s.Identity != identity {
		return nil, fmt.Errorf("state %s: belongs to identity %s, not this home's %s", p, s.Identity, identity)
	}
	s.path = p
	return &s, nil
}

// Save writes the state atomically at mode 0600.
func (s *State) Save() error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return WriteAtomic(s.path, append(raw, '\n'), 0o600)
}

// AddCrypt records a crypt this home created, once.
func (s *State) AddCrypt(crypt string) {
	if !slices.Contains(s.Crypts, crypt) {
		s.Crypts = append(s.Crypts, crypt)
	}
}

// Done removes a published object from the outbox.
func (s *State) Done(txid string) {
	s.Outbox = slices.DeleteFunc(s.Outbox, func(p Pending) bool { return p.Txid == txid })
}

// Queued reports whether txid is in the outbox.
func (s *State) Queued(txid string) bool {
	return slices.ContainsFunc(s.Outbox, func(p Pending) bool { return p.Txid == txid })
}

// InFlight is the sweep built and not yet finished, if there is one.
func (s *State) InFlight() *Sweep {
	for i := range s.Sweeps {
		if !s.Sweeps[i].Done && s.Sweeps[i].Failed == "" {
			return &s.Sweeps[i]
		}
	}
	return nil
}

// VaultByID finds one of the home's vaults by identifier.
func (s *State) VaultByID(id string) *Vault {
	for i := range s.Vaults {
		if s.Vaults[i].ID == id {
			return &s.Vaults[i]
		}
	}
	return nil
}

// Committed reports whether a commitment (hash byte order, hex) was
// published or listed by this home before.
func (s *State) Committed(c string) bool { return slices.Contains(s.Commitments, c) }

// Commit records a commitment, once.
func (s *State) Commit(c string) {
	if !s.Committed(c) {
		s.Commitments = append(s.Commitments, c)
	}
}

// Latest is the chain's last token, or nil.
func Latest(ts []Token) *Token {
	if len(ts) == 0 {
		return nil
	}
	return &ts[len(ts)-1]
}

// VersionOf finds a version of a secret (by identifier, hex) the home
// published: the one with the given content id when cid is not empty, else
// the highest listed and not ended.
func (v *Vault) VersionOf(id, cid string) *SecretVersion {
	var best *SecretVersion
	for i := range v.Versions {
		x := &v.Versions[i]
		if x.ID != id {
			continue
		}
		if cid != "" {
			if x.ContentID == cid {
				return x
			}
			continue
		}
		if x.Listed && !x.Ended && (best == nil || x.Version > best.Version) {
			best = x
		}
	}
	return best
}

// ByTxid finds a version by its carrier's txid.
func (v *Vault) ByTxid(txid string) *SecretVersion {
	for i := range v.Versions {
		if v.Versions[i].Txid == txid {
			return &v.Versions[i]
		}
	}
	return nil
}

// SeenOf is the latest token of a vault this identity verified, or nil.
func (s *State) SeenOf(crypt, org, vault string) *Seen {
	for i := range s.Seen {
		x := &s.Seen[i]
		if x.Crypt == crypt && x.Org == org && x.Vault == vault {
			return x
		}
	}
	return nil
}

// See records a verified latest token, never moving a vault backwards.
func (s *State) See(v Seen) {
	if old := s.SeenOf(v.Crypt, v.Org, v.Vault); old != nil {
		if v.Seq >= old.Seq {
			*old = v
		}
		return
	}
	s.Seen = append(s.Seen, v)
}

// Forget drops what was seen of a vault: the token remembered is no longer
// mined, so a reorganisation displaced it (spec section 14).
func (s *State) Forget(crypt, org, vault string) {
	s.Seen = slices.DeleteFunc(s.Seen, func(x Seen) bool { return x.Crypt == crypt && x.Org == org && x.Vault == vault })
}

// WriteAtomic writes data to path through a temporary file in the same
// directory, synced and renamed, then syncs the directory, so a crash
// leaves either the old file or the new one.
func WriteAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(f.Name())
		}
	}()
	if err = f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir) //nolint:gosec // the home's own directory
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// ErrLocked is a lock another process holds.
var ErrLocked = errors.New("state: locked by another bsecret process")

// Lock takes an exclusive lock on path (created at 0600), without waiting.
// The lock is the kernel's and ends with the process, so a crash never
// leaves it held. Release it with the returned function.
func Lock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // the home's own file
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // a file descriptor
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s", ErrLocked, path)
		}
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:gosec // a file descriptor
		f.Close()
	}, nil
}

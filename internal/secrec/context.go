package secrec

import (
	"fmt"

	"github.com/lightwebinc/bcommon/cbor"
	"github.com/lightwebinc/bcommon/commit"
)

// MaxPathSteps bounds an inclusion path: a set of at most MaxSecrets secrets
// has a path of at most 12 steps.
const MaxPathSteps = 32

// MaxContext bounds an encoded inclusion context.
const MaxContext = 2048

// InclusionContext is the BRC-24 context a secret answer carries (docs/spec.md
// section 10.2): the vault token whose set was used, by its seq and its
// txid (hash byte order; two tokens can share a seq after a reorganisation),
// the secret's leaf index and the set's size, and the RFC 6962 inclusion
// path.
type InclusionContext struct {
	Seq   uint64
	Token [32]byte
	Index uint64
	Size  uint64
	Path  commit.Path
}

// Encode writes the context as canonical CBOR [seq, token, index, size,
// path], each step [bytes(32), bool], the bool true when the sibling is on
// the left.
func (c *InclusionContext) Encode() ([]byte, error) {
	if len(c.Path) > MaxPathSteps || c.Size == 0 || c.Size > MaxSecrets || c.Index >= c.Size {
		return nil, ErrRange
	}
	steps := make([]cbor.Value, len(c.Path))
	for i, st := range c.Path {
		steps[i] = []cbor.Value{append([]byte(nil), st.Hash[:]...), st.Left}
	}
	return cbor.Encode([]cbor.Value{c.Seq, append([]byte(nil), c.Token[:]...), c.Index, c.Size, steps})
}

// DecodeContext parses a context, bounding it first.
func DecodeContext(b []byte) (*InclusionContext, error) {
	if len(b) > MaxContext {
		return nil, ErrTooLarge
	}
	v, err := cbor.DecodeValue(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCBOR, err)
	}
	a, ok := v.([]cbor.Value)
	if !ok || len(a) != 5 {
		return nil, ErrType
	}
	c := &InclusionContext{}
	var ok1, ok2, ok3 bool
	c.Seq, ok1 = a[0].(uint64)
	tok, okT := a[1].([]byte)
	c.Index, ok2 = a[2].(uint64)
	c.Size, ok3 = a[3].(uint64)
	steps, ok4 := a[4].([]cbor.Value)
	if !ok1 || !ok2 || !ok3 || !ok4 || !okT || len(tok) != 32 {
		return nil, ErrType
	}
	copy(c.Token[:], tok)
	if c.Seq > MaxSafe {
		return nil, ErrRange
	}
	if c.Size == 0 || c.Size > MaxSecrets || c.Index >= c.Size || len(steps) > MaxPathSteps {
		return nil, ErrRange
	}
	for _, s := range steps {
		p, ok := s.([]cbor.Value)
		if !ok || len(p) != 2 {
			return nil, ErrType
		}
		h, ok := p[0].([]byte)
		left, ok2 := p[1].(bool)
		if !ok || !ok2 || len(h) != 32 {
			return nil, ErrType
		}
		var st commit.Step
		copy(st.Hash[:], h)
		st.Left = left
		c.Path = append(c.Path, st)
	}
	return c, nil
}

// ProveSecret builds the context for the secret id within the current set
// of the token at seq whose txid is token.
func ProveSecret(seq uint64, token [32]byte, set []Current, id [32]byte) (*InclusionContext, error) {
	leaves := setLeaves(set)
	sorted := sortSet(set)
	for i, c := range sorted {
		if c.ID == id {
			p, err := commit.Prove(leaves, i)
			if err != nil {
				return nil, err
			}
			return &InclusionContext{Seq: seq, Token: token, Index: uint64(i), Size: uint64(len(sorted)), Path: p}, nil
		}
	}
	return nil, fmt.Errorf("%w: not in the set", ErrRange)
}

// VerifySecret checks a context against the root of the vault token at its
// seq: the path takes the leaf of (id, version, content id) to the root. The
// leaf and node prefixes of RFC 6962 keep a path from passing a subtree off
// as a leaf, so membership needs no more; index and size are hints.
func (c *InclusionContext) VerifySecret(id [32]byte, version uint64, contentID, root [32]byte) bool {
	return commit.Verify(Leaf(id, version, contentID), c.Path, root)
}

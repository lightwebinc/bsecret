// The record helpers below are shared in shape with every application on
// the same library (docs/spec.md section 16.1).

package secrec

import (
	"bytes"
	"fmt"
	"unicode/utf8"

	"github.com/lightwebinc/bcommon/cbor"
)

// fields is a decoded record: its known integer keys and the unknown ones
// above the last defined key, which are preserved.
type fields struct {
	known map[uint64]cbor.Value
	extra cbor.Map
}

// decodeRecord is refusal steps 1 to 5: the bound, one canonical CBOR item
// that is a map, at most MaxKeys entries, integer keys, and the magic.
func decodeRecord(b []byte, max int, last uint64, magic []byte) (*fields, error) {
	if len(b) > max {
		return nil, ErrTooLarge
	}
	v, err := cbor.DecodeValue(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCBOR, err)
	}
	m, ok := v.(cbor.Map)
	if !ok {
		return nil, ErrCBOR
	}
	if len(m) > MaxKeys {
		return nil, fmt.Errorf("%w: more than %d keys", ErrTooLarge, MaxKeys)
	}
	f := &fields{known: make(map[uint64]cbor.Value, len(m))}
	for _, p := range m {
		k, ok := p.Key.(uint64)
		if !ok {
			return nil, ErrKeyType
		}
		if k > last {
			f.extra = append(f.extra, p)
			continue
		}
		f.known[k] = p.Val
	}
	if b, ok := f.known[0].([]byte); !ok || !bytes.Equal(b, magic) {
		return nil, ErrMagic
	}
	return f, nil
}

// checkExtra holds preserved keys to the rule that they sit above the known
// keys, so re-encoding cannot shadow a known field, and bounds the total.
func checkExtra(extra cbor.Map, last uint64, defined int) error {
	for _, p := range extra {
		k, ok := p.Key.(uint64)
		if !ok || k <= last {
			return ErrKeyType
		}
	}
	if len(extra)+defined > MaxKeys {
		return fmt.Errorf("%w: more than %d keys", ErrTooLarge, MaxKeys)
	}
	return nil
}

// encodeRecord writes known fields then the preserved extras, canonically,
// and holds the result to max.
func encodeRecord(m cbor.Map, extra cbor.Map, max int) ([]byte, error) {
	m = append(m, extra...)
	out, err := cbor.Encode(m)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCBOR, err)
	}
	if len(out) > max {
		return nil, ErrTooLarge
	}
	return out, nil
}

func (f *fields) need(k uint64) (cbor.Value, error) {
	v, ok := f.known[k]
	if !ok {
		return nil, fmt.Errorf("%w: key %d", ErrMissing, k)
	}
	return v, nil
}

func (f *fields) bytesN(k uint64, n int) ([]byte, error) {
	v, err := f.need(k)
	if err != nil {
		return nil, err
	}
	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: key %d", ErrType, k)
	}
	if n >= 0 && len(b) != n {
		return nil, fmt.Errorf("%w: key %d", ErrRange, k)
	}
	return b, nil
}

func (f *fields) text(k uint64) (string, error) {
	v, err := f.need(k)
	if err != nil {
		return "", err
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w: key %d", ErrType, k)
	}
	return s, nil
}

func (f *fields) uint(k uint64, lo, hi uint64) (uint64, error) {
	v, err := f.need(k)
	if err != nil {
		return 0, err
	}
	n, ok := v.(uint64)
	if !ok {
		return 0, fmt.Errorf("%w: key %d", ErrType, k)
	}
	if n < lo || n > hi {
		return 0, fmt.Errorf("%w: key %d", ErrRange, k)
	}
	return n, nil
}

func (f *fields) boolean(k uint64) (bool, error) {
	v, err := f.need(k)
	if err != nil {
		return false, err
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%w: key %d", ErrType, k)
	}
	return b, nil
}

// array returns key k as an array whose length is bounded before anything is
// allocated for its elements.
func (f *fields) array(k uint64, max int) ([]cbor.Value, error) {
	v, err := f.need(k)
	if err != nil {
		return nil, err
	}
	a, ok := v.([]cbor.Value)
	if !ok {
		return nil, fmt.Errorf("%w: key %d", ErrType, k)
	}
	if len(a) > max {
		return nil, fmt.Errorf("%w: key %d", ErrList, k)
	}
	return a, nil
}

func inRange(n, lo, hi uint64, what string) error {
	if n < lo || n > hi {
		return fmt.Errorf("%w: %s", ErrRange, what)
	}
	return nil
}

// checkName is the display-name rule: 1 to MaxName bytes of UTF-8 text.
// Rendering filters it; the record only bounds it.
func checkName(s string) error {
	if len(s) < 1 || len(s) > MaxName || !utf8.ValidString(s) {
		return ErrName
	}
	return nil
}

// sortedDistinct32 holds a list of 32-byte values to strictly ascending
// byte order, so one set has one encoding.
func sortedDistinct32(a [][32]byte) error {
	for i := 1; i < len(a); i++ {
		if bytes.Compare(a[i-1][:], a[i][:]) >= 0 {
			return ErrList
		}
	}
	return nil
}

// list32 decodes key k as an array of at most max 32-byte strings in
// strictly ascending order.
func (f *fields) list32(k uint64, max int) ([][32]byte, error) {
	a, err := f.array(k, max)
	if err != nil {
		return nil, err
	}
	out := make([][32]byte, len(a))
	for i, e := range a {
		b, ok := e.([]byte)
		if !ok || len(b) != 32 {
			return nil, fmt.Errorf("%w: key %d", ErrList, k)
		}
		copy(out[i][:], b)
	}
	if err := sortedDistinct32(out); err != nil {
		return nil, fmt.Errorf("%w: key %d", err, k)
	}
	return out, nil
}

func values32(a [][32]byte) []cbor.Value {
	out := make([]cbor.Value, len(a))
	for i := range a {
		out[i] = append([]byte(nil), a[i][:]...)
	}
	return out
}

func zero32(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

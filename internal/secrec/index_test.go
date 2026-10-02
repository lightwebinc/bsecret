package secrec

import (
	"errors"
	"fmt"
	"testing"
)

func c32(b byte) [32]byte { return [32]byte{b} }

// The tooling refuses a commitment it published or listed before
// (docs/spec.md section 6.2).
func TestCommitmentsRefuseReuse(t *testing.T) {
	c := NewCommitments()
	if c.Seen(c32(1)) {
		t.Fatal("an empty record has seen something")
	}
	if err := c.Use(c32(1)); err != nil {
		t.Fatal(err)
	}
	if err := c.Use(c32(2)); err != nil {
		t.Fatal(err)
	}
	err := c.Use(c32(1))
	if !errors.Is(err, ErrReuse) || Reason(err) != "commitment-reuse" {
		t.Fatalf("a commitment used twice: %v", err)
	}
	if !c.Seen(c32(1)) || !c.Seen(c32(2)) || c.Seen(c32(3)) {
		t.Error("Seen disagrees with Use")
	}
}

// A row's winner is a running minimum, whatever was dropped and in whatever
// order the carriers arrived.
func TestOutpointRow(t *testing.T) {
	r := &OutpointRow{}
	if got := r.Status(c32(5)); got != StatusSuperseded {
		t.Errorf("an empty row: %q", got)
	}
	r.Add(c32(5))
	if r.Winner != c32(5) || r.Status(c32(5)) != "" {
		t.Fatalf("one carrier: %+v", r)
	}
	r.Add(c32(9))
	if r.Winner != c32(5) || r.Status(c32(9)) != StatusSuperseded || len(r.Others) != 1 {
		t.Fatalf("a higher commitment: %+v", r)
	}
	// The winner is dropped: every carrier on the outpoint is superseded,
	// the winner included, and a higher one never takes its place.
	r.Dropped = true
	if r.Status(c32(5)) != StatusSuperseded || r.Status(c32(9)) != StatusSuperseded {
		t.Errorf("a dropped winner: %q %q", r.Status(c32(5)), r.Status(c32(9)))
	}
	r.Add(c32(7))
	if r.Winner != c32(5) || !r.Dropped {
		t.Errorf("a higher commitment after the drop: %+v", r)
	}
	// A lower commitment that arrives after the drop is the running
	// minimum, and is superseded with every other: the outpoint answers
	// nothing again at this host.
	r.Add(c32(3))
	if r.Winner != c32(3) || !r.Dropped || r.Status(c32(3)) != StatusSuperseded || r.Others[0] != c32(5) {
		t.Errorf("a lower commitment after the drop: %+v", r)
	}
	r.Swept = true
	if r.Status(c32(3)) != StatusRetracted {
		t.Errorf("a swept row: %q", r.Status(c32(3)))
	}
	// The bound: the lowest MaxOthers of the rest are kept, the others
	// counted, in any order of arrival.
	a, b := &OutpointRow{}, &OutpointRow{}
	for i := 0; i < 20; i++ {
		a.Add(c32(byte(i + 1)))
		b.Add(c32(byte(20 - i)))
	}
	if fmt.Sprint(a) != fmt.Sprint(b) || a.More != 20-1-MaxOthers || len(a.Others) != MaxOthers || a.Winner != c32(1) || a.Others[MaxOthers-1] != c32(byte(MaxOthers+1)) {
		t.Errorf("bounded rows differ or are wrong:\n%+v\n%+v", a, b)
	}
}

func TestListingsWithNoToken(t *testing.T) {
	l := NewListings()
	if got := l.Status(&Secret{Label: "internal"}); got != StatusUnlisted {
		t.Errorf("a record of a vault with no token held: %q", got)
	}
	if got := CarrierStatus(&OutpointRow{}, c32(1), l, &Secret{}); got != StatusSuperseded {
		t.Errorf("a carrier with no row: %q", got)
	}
}

func TestTransactionReasons(t *testing.T) {
	for err, want := range map[error]string{
		ErrShape: "shape", ErrBEEF: "beef", ErrMineable: "mineable", ErrUnlock: "unlock", ErrLock: "lock",
		ErrFieldSig: "signature", ErrFunding: "funding", ErrUnmined: "unmined", ErrTokenInput: "token-input",
		ErrVaultID: "vault-id", ErrNotBsecret: "not-bsecret", ErrHostConfig: "other",
		fmt.Errorf("%w: detail", ErrTokenInput): "token-input",
	} {
		if got := Reason(err); got != want {
			t.Errorf("%v: %q, want %q", err, got, want)
		}
	}
	for k, want := range map[TxKind]string{TxSecret: "secret", TxVaultToken: "vault-token", TxSweep: "sweep", 0: "none"} {
		if k.String() != want {
			t.Errorf("kind %d: %q", k, k.String())
		}
	}
}

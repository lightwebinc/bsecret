package secrec

import (
	"fmt"

	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/lightwebinc/bcommon/chaintoken"
)

// DefaultMaxBEEF is the BEEF bound Admit applies when a host names none: the
// floor docs/spec.md section 11.1 sets for a host's own bound.
const DefaultMaxBEEF = chaintoken.DefaultMaxBEEF

// DefaultMaxSweepInputs is the sweep input bound Admit applies when a host
// names none: the floor docs/spec.md section 11.1 sets.
const DefaultMaxSweepInputs = 1024

// TokenBEEF assembles the BEEF a vault token is admitted in (docs/spec.md
// sections 11.1 and 11.6): a BEEF V1 of exactly the parent then the token,
// each with its own minimal path, or one merged path when both are in one
// block (bcommon chaintoken.TokenBEEF). A replayer builds it from the token
// as a host stores it and its parent: the token before it, or at seq 0 the
// chain tree.
func TokenBEEF(token, parent *transaction.Transaction) ([]byte, error) {
	return chaintoken.TokenBEEF(token, parent)
}

// StoredToken reads a vault token as a host stores it: the token's
// transaction alone, with its proof (docs/spec.md section 11.4). It returns
// the transaction and the token output's record, decoded, without the
// parent. An index and a reader read a stored token this way and never
// admit it again.
func StoredToken(b []byte) (*transaction.Transaction, *VaultToken, error) {
	tx, err := chaintoken.Stored(b, DefaultMaxBEEF)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrBEEF, err)
	}
	t, err := ReadToken(tx)
	return tx, t, err
}

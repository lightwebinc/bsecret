package engine

import (
	"context"
	"fmt"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/transaction"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// Minimal is mp cut to the proof of txid alone (secrec.MinimalPath).
func Minimal(mp *transaction.MerklePath, txid *chainhash.Hash) (*transaction.MerklePath, error) {
	return secrec.MinimalPath(mp, txid)
}

// current gives tx a proof that verifies against the publisher's own
// headers. The proof a home keeps is the one the node gave when the
// transaction mined; after a reorganization it may name a block that is no
// longer in the best chain, although the same transaction was mined again
// elsewhere (docs/spec.md section 11.5). A kept proof that no longer
// verifies is replaced by the transaction's current proof from the node,
// once that one verifies; it reports whether the proof changed. A header
// source that fails is an error, never a verdict.
func (e *Engine) current(ctx context.Context, tx *transaction.Transaction) (bool, error) {
	id := tx.TxID()
	if tx.MerklePath != nil {
		ok, err := tx.MerklePath.Verify(ctx, id, e.Legs.Headers)
		if err != nil {
			return false, fmt.Errorf("checking the proof of %s against the header source: %w", Short(id.String()), err)
		}
		if ok {
			return false, nil
		}
	}
	mp, _, err := e.Legs.Chain.Proof(ctx, id.String())
	if err != nil {
		return false, fmt.Errorf("the kept proof of %s does not verify against the header source, and the node gave no current one: %w", Short(id.String()), err)
	}
	if ok, err := mp.Verify(ctx, id, e.Legs.Headers); err != nil || !ok {
		return false, fmt.Errorf("neither the kept proof of %s nor the node's current one verifies against the header source", Short(id.String()))
	}
	tx.MerklePath = mp
	return true, nil
}

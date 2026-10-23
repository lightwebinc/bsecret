package module

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/chaintracker"

	bmodule "github.com/lightwebinc/bcommon/module"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// Reasons are every label a host counts a refused submission by: the
// record rules of spec section 3.1, the transition rules of section 4.2 and
// the transaction rules of section 11.1.
var Reasons = []string{
	"too-large", "cbor", "key-type", "magic", "missing", "type", "range", "identity", "crypt", "hall", "name", "label", "list", "entry",
	"chain", "count", "debt", "content", "transition", "epoch", "shape", "beef", "mineable", "unlock", "lock", "signature", "funding",
	"unmined", "token-input", "vault-id", "not-bsecret",
}

// AdmitKinds are what an admitted transaction was.
var AdmitKinds = []string{"secret", "vault-token", "sweep"}

// RecentAdmissions is how many admitted txids a manager remembers to count
// each once.
const RecentAdmissions = 4096

// Refused is raised for every refusal. The engine counts it as a failed
// topic for this submission and stores nothing.
type Refused struct {
	Reason string
	Detail string
}

func (r *Refused) Error() string { return "bsecret: refused, " + r.Reason + ": " + r.Detail }

// ErrNoSubmission is a host that hands the manager a parsed BEEF without
// the submission's bytes (bcommon module.WithSubmission): the manager
// decides on the wire form, which a parsed and merged BEEF no longer shows.
var ErrNoSubmission = errors.New("bsecret: the host did not hand the manager the submission's bytes (bcommon module.WithSubmission)")

// TopicManager is tm_bsecret_<crypt>: the topic manager of one crypt
// (spec section 11.1). The rules are secrec.Admit's; this is the engine
// seam: it runs them on the submission and turns the verdict into
// admittance instructions. Every refusal is raised, so the engine records
// nothing and marks nothing spent: a refused transaction offered again is
// decided again. No rule reads another topic, another record or anything
// this topic holds.
type TopicManager struct {
	Topic string
	Crypt string
	host  bmodule.Host
	h     secrec.Host

	mu     sync.Mutex
	recent map[string]bool
	order  []string
}

var _ bmodule.TopicManager = (*TopicManager)(nil)

// NewTopicManager makes the manager of one topic. The floors are held
// where an operator sets the bounds (ParseConfig); a test may name smaller
// ones.
func NewTopicManager(topic string, host bmodule.Host, headers chaintracker.ChainTracker, maxBEEF, maxSweepInputs int) (*TopicManager, error) {
	if !strings.HasPrefix(topic, secrec.TopicPrefix) {
		return nil, fmt.Errorf("bsecret: %s is not a tm_bsecret_ topic", topic)
	}
	crypt := topic[len(secrec.TopicPrefix):]
	if err := secrec.CheckCrypt(crypt); err != nil {
		return nil, err
	}
	if maxBEEF < 1 || maxSweepInputs < 1 {
		return nil, fmt.Errorf("bsecret: a BEEF bound of %d and a sweep input bound of %d", maxBEEF, maxSweepInputs)
	}
	return &TopicManager{Topic: topic, Crypt: crypt, host: host, h: secrec.Host{Crypt: crypt, Headers: headers, MaxBEEF: maxBEEF, MaxSweepInputs: maxSweepInputs}, recent: map[string]bool{}}, nil
}

// Admit applies the rules to the submission's bytes with the held inputs,
// as the TypeScript manager's identifyAdmissibleOutputs does.
func (t *TopicManager) Admit(ctx context.Context, raw []byte, held []int) (overlay.AdmittanceInstructions, error) {
	a, err := secrec.Admit(ctx, raw, held, t.h)
	if err != nil {
		reason := secrec.Reason(err)
		if reason == "" {
			return overlay.AdmittanceInstructions{}, err
		}
		t.host.Metrics().Inc("bsecret_refused_total", map[string]string{"reason": reason}, 1)
		detail := strings.TrimPrefix(err.Error(), "secrec: ")
		t.host.Log("tm_bsecret refused", map[string]any{"topic": t.Topic, "reason": reason, "detail": detail})
		return overlay.AdmittanceInstructions{}, &Refused{Reason: reason, Detail: detail}
	}
	txid := chainhash.Hash(a.Txid)
	t.count(a.Kind.String(), txid.String())
	ai := overlay.AdmittanceInstructions{OutputsToAdmit: make([]uint32, 0, len(a.Outputs)), CoinsToRetain: make([]uint32, 0, len(a.Retain))}
	for _, o := range a.Outputs {
		ai.OutputsToAdmit = append(ai.OutputsToAdmit, uint32(o)) //nolint:gosec // bounded by the transaction's outputs
	}
	for _, r := range a.Retain {
		ai.CoinsToRetain = append(ai.CoinsToRetain, uint32(r)) //nolint:gosec // bounded by the transaction's inputs
	}
	return ai, nil
}

// IdentifyAdmissibleOutputs implements bcommon's module.TopicManager over
// the submission's bytes in ctx.
func (t *TopicManager) IdentifyAdmissibleOutputs(ctx context.Context, _ *transaction.Beef, _ *chainhash.Hash, previousCoins []uint32) (overlay.AdmittanceInstructions, error) {
	raw, ok := bmodule.Submission(ctx)
	if !ok {
		return overlay.AdmittanceInstructions{}, ErrNoSubmission
	}
	held := make([]int, 0, len(previousCoins))
	for _, c := range previousCoins {
		held = append(held, int(c))
	}
	return t.Admit(ctx, raw, held)
}

// count counts an admission once per transaction. The engine shows a
// manager a txid it already applied only when two submissions of it race
// past its duplicate check, so bsecret_admitted_total counts distinct
// transactions and bsecret_admitted_repeats_total the rest.
func (t *TopicManager) count(kind, txid string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.recent[txid] {
		t.host.Metrics().Inc("bsecret_admitted_repeats_total", map[string]string{"kind": kind}, 1)
		return
	}
	t.recent[txid] = true
	t.order = append(t.order, txid)
	if len(t.order) > RecentAdmissions {
		delete(t.recent, t.order[0])
		t.order = t.order[1:]
	}
	t.host.Metrics().Inc("bsecret_admitted_total", map[string]string{"kind": kind}, 1)
}

// GetDocumentation implements module.TopicManager.
func (t *TopicManager) GetDocumentation() string {
	return strings.Join([]string{
		"# " + t.Topic,
		"",
		"The bsecret crypt " + t.Crypt + ": secret carriers, each spending one output of its",
		"owner's mined funding tree; vault tokens, each mined and published with its",
		"parent; and the tombstones of mined sweeps (spec section 11.1). Each is admitted",
		"on its own bytes and the host's headers; no other record and nothing the topic",
		"holds is read. Every refusal is raised, so nothing refused is recorded.",
	}, "\n")
}

// GetMetaData implements module.TopicManager.
func (t *TopicManager) GetMetaData() *overlay.MetaData {
	return &overlay.MetaData{Name: t.Topic, Description: "Admits the bsecret crypt " + t.Crypt + "."}
}

func hexOf(b [32]byte) string { return hex.EncodeToString(b[:]) }

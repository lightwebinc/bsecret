package testhost

import (
	"encoding/json"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

	"github.com/lightwebinc/bcommon/devkit/paidhost"

	"github.com/lightwebinc/bsecret/internal/secrec"
)

// Paid is a stand-in for a host's terms route (docs/spec.md section 10.3):
// devkit's paidhost answering from a Host.
type Paid = paidhost.Paid

// Payment is one accepted payment, in the host ledger's shape.
type Payment = paidhost.Payment

// NewPaid is a terms route for host, paid to payee: ls_bsecret's classes,
// its questions parsed by secrec and answered by the host.
func NewPaid(host *Host, payee *ec.PrivateKey, prices map[string]uint64) *Paid {
	classes := make([]string, len(secrec.Classes))
	for i, c := range secrec.Classes {
		classes[i] = c.Name
	}
	return paidhost.New(paidhost.Service{Name: secrec.LookupService, Classes: classes, Headers: host.chain,
		Ask: func(raw json.RawMessage) (string, func() (any, error), error) {
			qq, err := secrec.ParseQuery(raw)
			if err != nil {
				return "", nil, err
			}
			return qq.Class.Name, func() (any, error) { return host.Answer(qq) }, nil
		}}, payee, prices)
}

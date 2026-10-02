package main

import (
	"github.com/lightwebinc/borg/reader"

	"github.com/lightwebinc/bsecret/internal/state"
)

// groupFloor is the home's record of the latest token of each group's
// chain it verified, as the Floor of borg's reader (spec section 14, no
// going back): hosts of the hall that answer a group only below what this
// home verified are refused, not believed. Without it a host set that
// withholds the group token that removed a member answers a group in
// which that member still is one, every token of which verifies, and the
// vault looks settled under an epoch that has ended. What a read raises is
// saved with the home.
type groupFloor struct{ st *state.State }

func (f groupFloor) Seen(hall, org, chain string) (uint64, string, bool) {
	if s := f.st.SeenGroupOf(hall, org, chain); s != nil {
		return s.Seq, s.Txid, true
	}
	return 0, "", false
}

func (f groupFloor) See(hall, org, chain string, seq uint64, txid string) {
	f.st.SeeGroup(state.SeenGroup{Hall: hall, Org: org, Chain: chain, Seq: seq, Txid: txid})
}

// Forget drops the floor of one chain: the token remembered is no longer
// mined (vread.ReadGroup asks the node first).
func (f groupFloor) Forget(hall, org, chain string) { f.st.ForgetGroup(hall, org, chain) }

// hold gives the group reader this home's floor. st is the home's state:
// under the home's lock what is verified is saved; a state read without
// the lock still refuses an older answer.
func hold(rd *reader.Client, st *state.State) {
	if rd != nil && st != nil {
		rd.Floor = groupFloor{st}
	}
}

//go:build phase5release

// TEMPORARY — issue #23 Definition-of-Done item 11.
//
// This file exists only long enough to prove, on real hosted CI, that a
// failing security contract propagates through pr-gate.yml's
// `go test -tags phase5release ./internal/securitytest -count=1` step into a
// red `Required PR gate` check — i.e. that the security step is genuinely
// gating and not advisory. It is removed by a normal revert commit in the
// same pull request, before that PR is certified.
//
// The `phase5release` build tag is deliberate: it keeps this out of
// `go test -race ./...` (the gate's earlier step) so the resulting failure
// isolates the security step's own wiring. An untagged failure would prove
// only what an earlier accidental red run already proved.
package securitytest

import "testing"

func TestPRGateDeliberateFailureProof(t *testing.T) {
	t.Fatal("deliberate issue #23 gate proof — if you are reading this in a real run, the revert commit was lost")
}

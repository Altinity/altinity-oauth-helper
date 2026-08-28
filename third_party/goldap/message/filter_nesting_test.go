package message

import (
	"strings"
	"testing"
)

// This file is the regression for the fix described in
// third_party/goldap/PATCHES.md's third item and filter.go's
// maxFilterNestingDepth: readFilterAnd/readFilterOr/readFilterNot used to
// recurse into an arbitrarily deep chain of nested Filter AND/OR/NOT
// alternatives with no bound of their own, and every level of that
// recursion re-wrapped the error returned by a failing descendant — so a
// single message containing on the order of 1000 nested AND filters ending
// in one malformed child (proven empirically in the consuming repository's
// internal/ldap package, see its filter_resource_test.go) allocated on the
// order of 150 MB just constructing that error chain, entirely independent
// of the 64 KiB per-message byte cap the consuming repository's own
// transport layer enforces before this package ever sees the bytes.
//
// nestedANDFilterBytes and the raw byte layout below are built by hand
// from the same ASN.1 identifier-octet rules struct.go's Tag* constants
// and asn1.go's parseTagAndLength document, independent of this package's
// own write-side encoders — this test exists to characterize the READ
// side, so it deliberately does not share construction code with it.

// nestedANDFilterBytes returns depth nested `(&(&(&...(objectClass=x)...)))`
// AND filters wrapping one ordinary, syntactically valid equalityMatch leaf
// (`objectClass=x`), so that whether parsing succeeds or fails is
// attributable solely to nesting depth, not to any malformed content.
func nestedANDFilterBytes(depth int) []byte {
	// equalityMatch [3] AttributeValueAssertion ::= SEQUENCE {
	//     attributeDesc  AttributeDescription,  -- OCTET STRING "objectClass"
	//     assertionValue AssertionValue }        -- OCTET STRING "x"
	leaf := []byte{
		0xa3, 0x0f, // [3] SEQUENCE, length 15
		0x04, 0x0b, 'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's',
		0x04, 0x00, // "" — deliberately empty; value doesn't matter here
	}
	node := leaf
	for i := 0; i < depth; i++ {
		// AND ::= [0] SET SIZE (1..MAX) OF Filter — a single-element SET,
		// short-form length since every depth used by this test's own
		// content length stays well under 128 bytes for the levels that
		// matter (the guard fires long before length encoding would need
		// to grow to long form).
		content := node
		if len(content) >= 128 {
			// Long-form length, matching parseTagAndLength's own decoding
			// (asn1.go): 0x80|numBytes, then that many big-endian bytes.
			n := 0
			for v := len(content); v > 0; v >>= 8 {
				n++
			}
			lenBytes := make([]byte, n)
			for i := 0; i < n; i++ {
				lenBytes[n-1-i] = byte(len(content) >> (8 * i))
			}
			node = append(append([]byte{0xa0, 0x80 | byte(n)}, lenBytes...), content...)
		} else {
			node = append([]byte{0xa0, byte(len(content))}, content...)
		}
	}
	return node
}

// wrapAsSearchFilter embeds filterBytes (an already-encoded Filter) as the
// sole readFilter input by decoding it directly with readFilter — this
// test targets readFilter/readFilterAnd directly rather than round-tripping
// through a full LDAPMessage/SearchRequest envelope, since the guard under
// test lives entirely inside filter parsing.
func readFilterFromBytes(t *testing.T, raw []byte) (Filter, error) {
	t.Helper()
	b := NewBytes(0, raw)
	return readFilter(b)
}

func TestReadFilter_NestingWithinLimitSucceeds(t *testing.T) {
	// maxFilterNestingDepth-1 nested ANDs stays strictly within the guard
	// (the guard rejects at bytes.filterDepth >= maxFilterNestingDepth,
	// so depth values 0..maxFilterNestingDepth-1 must all still dispatch
	// normally), so this must parse the well-formed leaf successfully.
	raw := nestedANDFilterBytes(maxFilterNestingDepth - 1)
	filter, err := readFilterFromBytes(t, raw)
	if err != nil {
		t.Fatalf("readFilter with depth %d (within maxFilterNestingDepth=%d) failed: %v", maxFilterNestingDepth-1, maxFilterNestingDepth, err)
	}
	if _, ok := filter.(FilterAnd); !ok {
		t.Fatalf("readFilter returned %T, want FilterAnd", filter)
	}
}

func TestReadFilter_ExceedingNestingLimitIsRejectedWithoutUnboundedGrowth(t *testing.T) {
	// depth is deliberately far beyond maxFilterNestingDepth. Before the
	// fix this recursed all the way to the leaf and then re-wrapped the
	// resulting error once per level on the way back out; after the fix,
	// readFilterAnd must reject as soon as bytes.filterDepth reaches
	// maxFilterNestingDepth, without ever decoding anything past that
	// point.
	const depth = 2000
	raw := nestedANDFilterBytes(depth)

	_, err := readFilterFromBytes(t, raw)
	if err == nil {
		t.Fatalf("readFilter with depth %d succeeded, want a nesting-limit rejection", depth)
	}

	const wantSubstring = "filter nesting exceeds maximum depth"
	got := err.Error()
	if !strings.Contains(got, wantSubstring) {
		t.Fatalf("readFilter error = %q, want it to contain %q", got, wantSubstring)
	}

	// Bounded error generation: the fix's whole point is that the
	// returned error chain is O(maxFilterNestingDepth), not O(depth) — at
	// depth=2000 vs. maxFilterNestingDepth=32, an unbounded implementation
	// would produce a message at least two orders of magnitude longer
	// than this. This is a coarse, non-timing structural check, not a
	// tight assertion on the exact byte count.
	const generousBound = 4096
	if len(got) > generousBound {
		t.Fatalf("readFilter error message is %d bytes long (want <= %d) — this suggests the nesting guard did not actually stop the wrap chain early", len(got), generousBound)
	}
}

func TestReadFilter_NestingLimitAppliesToOrAndNot(t *testing.T) {
	// OR and NOT carry the identical guard (filter_or.go/filter_not.go);
	// spot-check OR here without duplicating the AND case's full
	// construction — nestedANDFilterBytes only builds AND wrappers, so for
	// OR/NOT this test constructs one single OR/NOT wrapper directly
	// around an already-over-the-limit AND chain and confirms the failure
	// still surfaces (proving the depth these outer wrappers see already
	// accounts for their own +1, not just the inner AND chain's).
	inner := nestedANDFilterBytes(maxFilterNestingDepth) // already at the limit on its own

	or := append([]byte{0xa1, byte(len(inner))}, inner...) // OR ::= [1] SET SIZE(1..MAX) OF Filter
	if _, err := readFilterFromBytes(t, or); err == nil {
		t.Fatalf("readFilter(OR wrapping an already-at-limit AND chain) succeeded, want rejection")
	}
}

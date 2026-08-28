package ldap

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"testing"
	"time"

	ldapserver "github.com/vjeantet/ldapserver"
)

// This file covers plan-19p5 §6/§12/§25's remaining "deep malformed
// filter"/"wide malformed filter" resource gap: does a single, well-under-
// the-64-KiB-cap raw Search request whose filter is either very deeply
// nested (many AND wrappers) or very wide (many AND/OR siblings), ending in
// one syntactically invalid child, make the production decode path
// (third_party/goldap/message's readFilter/readFilterAnd/readFilterOr,
// reached from third_party/ldapserver's per-connection read loop before any
// routing) consume pathological time or memory.
//
// The filter bytes here are built by hand, byte-for-byte, from RFC 4511's
// ASN.1 grammar (see berTLV/berInt and the comments beside each field
// below) rather than by driving any goldap/ber library encoder — this test
// exists to characterize the READ side of that dependency, so its INPUT
// construction deliberately shares no code with it.
//
// Because a genuine defect here could make a single message hang or
// allocate without bound, this file drives every measured attempt in a
// re-exec'd subprocess (the same pattern the Go standard library uses for
// os/exec's own tests): TestFilterResourceHelperProcess is a no-op under a
// normal `go test` invocation and only does real work when re-invoked with
// filterResourceHelperEnv=1, which only the staged runner below does. The
// PARENT enforces a hard wall-clock timeout on that subprocess via
// context cancellation (which SIGKILLs it), so a pathological stage is
// observed as "timed out" rather than hanging this test, or the whole `go
// test` run, forever. Escalation only proceeds to a larger stage once the
// previous one is measured to stay within the generous bounds below.

// ---- helper-process plumbing ----------------------------------------------

const (
	filterResourceHelperEnv = "ALTINITY_LDAP_FILTER_RESOURCE_HELPER"
	filterResourceShapeEnv  = "ALTINITY_LDAP_FILTER_RESOURCE_SHAPE"
	filterResourceSizeEnv   = "ALTINITY_LDAP_FILTER_RESOURCE_SIZE"
)

// filterResourceResultRe matches the one stdout line
// TestFilterResourceHelperProcess prints on success, carrying every
// measurement the parent needs. It never leaks the raw filter/DN bytes.
var filterResourceResultRe = regexp.MustCompile(`FILTER_RESOURCE_RESULT elapsed_ms=(\d+) heap_alloc_delta=(\d+) post_check=(\S+)`)

// filterResourceStageTimeout is the PARENT-enforced hard wall-clock bound
// per stage. It is the actual backstop against a genuinely pathological
// (e.g. exponential or hung) parse: exceeding it kills the subprocess
// rather than waiting on it, so a real defect shows up as a bounded
// "timeout" measurement instead of blocking the test run.
const filterResourceStageTimeout = 12 * time.Second

// filterResourceElapsedBudget and filterResourceHeapBudget are deliberately
// generous bounds a stage's *measured* result (not the hard kill above)
// must stay under to be judged "bounded" and allow escalation to the next,
// larger stage. Ordinary linear-time/allocation parsing of even the
// largest stage below finishes in low single-digit milliseconds and
// allocates a small multiple of the ~64 KiB message itself; these budgets
// leave enormous headroom for a loaded CI box without being tight timing
// assertions.
const (
	filterResourceElapsedBudget = 5 * time.Second
	filterResourceHeapBudget    = 64 << 20 // 64 MiB
)

// runFilterResourceHelperProcess re-execs this same test binary
// (os.Args[0], exactly as it was invoked to run this very test — the
// standard Go helper-process pattern), selecting only
// TestFilterResourceHelperProcess via -test.run and passing shape/size
// through dedicated environment variables (there is nothing confidential
// about either, but this keeps them off any process-listing argv anyway).
// hardTimeout is enforced here, by the parent, via context cancellation;
// os/exec kills the child process when the context is done.
func runFilterResourceHelperProcess(t *testing.T, shape string, size int, hardTimeout time.Duration) (elapsed time.Duration, heapDelta uint64, postCheck string, timedOut bool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), hardTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFilterResourceHelperProcess$", "-test.v=true")
	cmd.Env = append(os.Environ(),
		filterResourceHelperEnv+"=1",
		filterResourceShapeEnv+"="+shape,
		filterResourceSizeEnv+"="+strconv.Itoa(size),
	)
	out, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		t.Logf("stage shape=%s size=%d: hard parent timeout after %v (subprocess killed); output so far:\n%s", shape, size, hardTimeout, out)
		return 0, 0, "timeout", true
	}
	if err != nil {
		t.Fatalf("stage shape=%s size=%d: helper process failed: %v\noutput:\n%s", shape, size, err, out)
	}

	m := filterResourceResultRe.FindSubmatch(out)
	if m == nil {
		t.Fatalf("stage shape=%s size=%d: helper process produced no parseable result line; output:\n%s", shape, size, out)
	}
	elapsedMs, convErr := strconv.ParseInt(string(m[1]), 10, 64)
	if convErr != nil {
		t.Fatalf("stage shape=%s size=%d: bad elapsed_ms in result line: %v", shape, size, convErr)
	}
	heapDelta, convErr = strconv.ParseUint(string(m[2]), 10, 64)
	if convErr != nil {
		t.Fatalf("stage shape=%s size=%d: bad heap_alloc_delta in result line: %v", shape, size, convErr)
	}
	postCheck = string(m[3])
	return time.Duration(elapsedMs) * time.Millisecond, heapDelta, postCheck, false
}

// testFilterResourceStaged drives sizes for shape in increasing order,
// stopping escalation at the first stage that is not measured bounded
// (timeout, a failed post-malformed liveness check, or exceeding the
// generous elapsed/heap budgets) and failing the test for that stage —
// per this sub-task's decision rule, that is evidence of a real resource
// defect worth reporting/patching, not something to loosen the budget for.
func testFilterResourceStaged(t *testing.T, shape string, sizes []int) {
	t.Helper()

	for _, size := range sizes {
		elapsed, heapDelta, postCheck, timedOut := runFilterResourceHelperProcess(t, shape, size, filterResourceStageTimeout)

		display := postCheck
		if timedOut {
			display = "timeout"
		}
		bounded := !timedOut && postCheck == "ok" && elapsed <= filterResourceElapsedBudget && heapDelta <= filterResourceHeapBudget

		t.Logf("stage shape=%-8s size=%-6d elapsed_ms=%-6d heap_alloc_delta=%-10d post_check=%-6s bounded=%v",
			shape, size, elapsed.Milliseconds(), heapDelta, display, bounded)

		if !bounded {
			t.Errorf("stage shape=%s size=%d exceeded the bounded budget (elapsed=%v, budget=%v; heap_delta=%d, budget=%d; post_check=%s, timed_out=%v) — stopping escalation here",
				shape, size, elapsed, filterResourceElapsedBudget, heapDelta, filterResourceHeapBudget, display, timedOut)
			return
		}
	}
}

// ---- raw BER construction (independent of the code under test) -----------

// berTLV manually BER-encodes one tag-length-value using the same
// identifier-octet/length-octet layout RFC 4511/X.690 (and, transitively,
// third_party/goldap/message/asn1.go's parseTagAndLength) define: an
// already-computed single identifier byte (low-tag-form only — every tag
// number this file uses is under 31), then a minimal-length-form length,
// then the raw value bytes.
func berTLV(identifier byte, value []byte) []byte {
	length := len(value)
	var lengthBytes []byte
	if length < 128 {
		lengthBytes = []byte{byte(length)}
	} else {
		n := 0
		for v := length; v > 0; v >>= 8 {
			n++
		}
		lengthBytes = make([]byte, 1+n)
		lengthBytes[0] = 0x80 | byte(n)
		for i := 0; i < n; i++ {
			lengthBytes[1+n-1-i] = byte(length >> (8 * i))
		}
	}
	out := make([]byte, 0, 1+len(lengthBytes)+length)
	out = append(out, identifier)
	out = append(out, lengthBytes...)
	out = append(out, value...)
	return out
}

// berInt encodes one of this file's small (0..3) non-negative integer
// fields (scope, derefAliases, sizeLimit, timeLimit), which always fit in a
// single content byte.
func berInt(identifier byte, v int) []byte {
	return berTLV(identifier, []byte{byte(v)})
}

// Identifier octets used below, computed by hand from X.690's identifier
// octet layout (class in bits 8-7, constructed bit 6, tag number in bits
// 5-1 for low-tag-form) and cross-checked against
// third_party/goldap/message/asn1.go's parseTagAndLength and struct.go's
// Tag* constants:
const (
	berMessageID        = 0x02 // UNIVERSAL, primitive, INTEGER (tag 2)
	berSearchRequestOp  = 0x63 // APPLICATION, constructed, tag 3 (SearchRequest)
	berBaseObject       = 0x04 // UNIVERSAL, primitive, OCTET STRING (tag 4)
	berEnumerated       = 0x0a // UNIVERSAL, primitive, ENUMERATED (tag 10) — scope/derefAliases
	berInteger          = 0x02 // UNIVERSAL, primitive, INTEGER (tag 2) — sizeLimit/timeLimit
	berBoolean          = 0x01 // UNIVERSAL, primitive, BOOLEAN (tag 1) — typesOnly
	berSequence         = 0x30 // UNIVERSAL, constructed, SEQUENCE (tag 16) — attributes/envelope
	berFilterAnd        = 0xa0 // CONTEXT, constructed, tag 0  (TagFilterAnd)
	berFilterOr         = 0xa1 // CONTEXT, constructed, tag 1  (TagFilterOr)
	berFilterPresent    = 0x87 // CONTEXT, primitive,   tag 7  (TagFilterPresent)
	berFilterInvalidTag = 0x8f // CONTEXT, primitive,   tag 15 (unassigned by RFC 4511's Filter CHOICE)
)

// malformedFilterLeaf is the fixed, minimal (2-byte) malformed filter node
// every stage below terminates on: a syntactically well-formed BER
// tag/length pair whose CONTEXT-SPECIFIC tag (15) is not one of the nine
// RFC 4511 Filter CHOICE alternatives, so third_party/goldap/message's
// readFilter unconditionally rejects it in its `default:` branch — the
// cheapest possible parse failure, deliberately not itself a source of
// extra recursion or allocation, so every stage's measurement is
// attributable to the surrounding deep/wide structure, not to this leaf.
func malformedFilterLeaf() []byte {
	return berTLV(berFilterInvalidTag, nil)
}

// validFilterPresentLeaf is a syntactically and semantically ordinary
// `(cn=*)` present filter, used as the non-malformed siblings a wide
// filter carries ahead of its one malformed trailing child.
func validFilterPresentLeaf() []byte {
	return berTLV(berFilterPresent, []byte("cn"))
}

// deepMalformedANDFilter wraps malformedFilterLeaf in depth nested AND
// filters — "deeply nested AND filters ending in a malformed child" per
// this sub-task's description.
func deepMalformedANDFilter(depth int) []byte {
	node := malformedFilterLeaf()
	for i := 0; i < depth; i++ {
		node = berTLV(berFilterAnd, node)
	}
	return node
}

// wideMalformedFilter builds one AND/OR filter (andOr selects which) with
// exactly width children: width-1 valid present-filter siblings followed
// by exactly one malformedFilterLeaf — "very wide AND/OR filters ending in
// a malformed child" per this sub-task's description. width must be >= 1.
func wideMalformedFilter(andOr byte, width int) []byte {
	valid := validFilterPresentLeaf()
	var content []byte
	for i := 0; i < width-1; i++ {
		content = append(content, valid...)
	}
	content = append(content, malformedFilterLeaf()...)
	return berTLV(andOr, content)
}

// buildMalformedFilterSearchEnvelope hand-assembles one complete raw
// LDAPMessage carrying a SearchRequest whose filter is filterBytes (already
// a complete, correctly tagged Filter encoding — deep or wide, from above),
// mirroring third_party/goldap/message/search_request.go's documented
// ASN.1 grammar field-for-field. scope is fixed at wholeSubtree(2) and
// derefAliases at neverDerefAliases(0) — matching every other real
// SearchRequest this package's tests send — sizeLimit/timeLimit at 0
// (unlimited/no deadline), and typesOnly at false, since none of those are
// what this file is probing.
func buildMalformedFilterSearchEnvelope(messageID int, baseDN string, filterBytes []byte) []byte {
	var searchReqBody []byte
	searchReqBody = append(searchReqBody, berTLV(berBaseObject, []byte(baseDN))...)
	searchReqBody = append(searchReqBody, berInt(berEnumerated, 2)...) // scope=wholeSubtree
	searchReqBody = append(searchReqBody, berInt(berEnumerated, 0)...) // derefAliases=never
	searchReqBody = append(searchReqBody, berInt(berInteger, 0)...)    // sizeLimit=0
	searchReqBody = append(searchReqBody, berInt(berInteger, 0)...)    // timeLimit=0
	searchReqBody = append(searchReqBody, berTLV(berBoolean, []byte{0x00})...)
	searchReqBody = append(searchReqBody, filterBytes...)
	searchReqBody = append(searchReqBody, berTLV(berSequence, nil)...) // attributes: empty

	searchReq := berTLV(berSearchRequestOp, searchReqBody)

	var msgBody []byte
	msgBody = append(msgBody, berInt(berMessageID, messageID)...)
	msgBody = append(msgBody, searchReq...)

	return berTLV(berSequence, msgBody)
}

// ---- the helper process itself --------------------------------------------

// TestFilterResourceHelperProcess is a no-op under any normal `go test`
// invocation (including this package's own full suite and the
// TestFilterResource_* entry points below, which never set
// filterResourceHelperEnv themselves — only runFilterResourceHelperProcess's
// re-exec'd child does). It only performs real work when re-invoked by
// runFilterResourceHelperProcess above, selecting shape/size from the
// dedicated environment variables it set.
//
// One real production server is started; the shaped, malformed Search
// envelope is sent on a raw connection, with elapsed time and heap
// allocation delta measured across that write plus a same-connection
// follow-on Bind's response — bounding worst-case processing time for the
// malformed message itself, since a pathologically stuck decode would
// prevent that Bind's response from ever arriving too. A fresh
// Bind+Search on a brand-new connection to the same server then proves the
// server as a whole is still fully healthy. Exactly one result line is
// printed to stdout on success; the process exits non-zero (a normal `go
// test` failure) if any of those steps fails outright, which the parent
// surfaces as a hard failure rather than a soft "not bounded" measurement.
func TestFilterResourceHelperProcess(t *testing.T) {
	if os.Getenv(filterResourceHelperEnv) != "1" {
		t.Skip("helper process test; only runs when re-exec'd by TestFilterResource_* via runFilterResourceHelperProcess")
	}

	shape := os.Getenv(filterResourceShapeEnv)
	size, err := strconv.Atoi(os.Getenv(filterResourceSizeEnv))
	if err != nil {
		t.Fatalf("bad %s=%q: %v", filterResourceSizeEnv, os.Getenv(filterResourceSizeEnv), err)
	}

	var filterBytes []byte
	switch shape {
	case "deep-and":
		filterBytes = deepMalformedANDFilter(size)
	case "wide-and":
		filterBytes = wideMalformedFilter(berFilterAnd, size)
	case "wide-or":
		filterBytes = wideMalformedFilter(berFilterOr, size)
	default:
		t.Fatalf("unknown %s=%q", filterResourceShapeEnv, shape)
	}

	acct := account("alice", "https://idp.test/", "sub-alice", "jwt-alice", []string{"ch_a"})
	fv := newFakeVerifier(acct)
	addr, _, _ := startTestServer(t, fv, newFakeRoles(acct))
	appLog := swapAppLog(t)

	env := buildMalformedFilterSearchEnvelope(1, protoGroupBaseDN, filterBytes)
	if bodyLen := envelopeBodyLength(env); bodyLen >= 64<<10 {
		t.Fatalf("test fixture bug: shape=%s size=%d produced LDAPMessage body length %d, not under the 64 KiB cap — reduce size", shape, size, bodyLen)
	}

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()

	if _, err := raw.Write(env); err != nil {
		t.Fatalf("write malformed %s filter search (size=%d): %v", shape, size, err)
	}

	// The malformed filter fails LDAPMessage decode inside
	// third_party/ldapserver's per-connection read loop, which — per
	// client.go's `if err != nil { Logger.Printf(...); continue }` — logs
	// (discarded in production; captured to appLog here) and moves on to
	// the next request on this SAME connection without ever sending a
	// response for the malformed message itself. A subsequent valid Bind
	// on this same connection is therefore the direct way to observe how
	// long that decode-and-continue actually took.
	if _, err := raw.Write(rawSimpleBindMessage(2, protoBindDN("alice"), "jwt-alice")); err != nil {
		t.Fatalf("write follow-on bind: %v", err)
	}
	pkt := readRawEnvelope(t, raw, 30*time.Second) // generous; the PARENT's own hard process-level kill is the real backstop
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)

	postCheck := "ok"
	code, matchedDN, diagnostic := bindResponseFields(t, pkt, 2)
	if code != int64(ldapserver.LDAPResultSuccess) {
		postCheck = fmt.Sprintf("bindcode%d", code)
	}
	_ = matchedDN
	_ = diagnostic

	// Second half of "prove a fresh valid Bind/Search": a brand-new
	// connection to the very same server instance. requireFreshConnectionWorks
	// (hostile_dn_test.go) calls t.Fatalf on any failure, which — same as
	// every other Fatalf in this function — simply fails this helper
	// process outright (non-zero exit), surfaced by the parent as a hard
	// failure rather than a "not bounded" data point, which is the correct
	// severity for an actual broken Bind/Search rather than a merely slow
	// one.
	requireFreshConnectionWorks(t, addr)

	requireNoLeak(t, appLog, "jwt-alice", "HOSTILE-FILTER")

	fmt.Printf("FILTER_RESOURCE_RESULT elapsed_ms=%d heap_alloc_delta=%d post_check=%s\n",
		elapsed.Milliseconds(), after.TotalAlloc-before.TotalAlloc, postCheck)
}

// ---- staged entry points ---------------------------------------------------

// TestFilterResource_DeepMalformedFilterStaysBounded stages increasingly
// deep nested-AND malformed filters. The largest stage (12000) was checked
// (see buildMalformedFilterSearchEnvelope's self-check above, which fails
// loudly rather than silently testing something smaller) to still encode
// under the 64 KiB per-message cap.
func TestFilterResource_DeepMalformedFilterStaysBounded(t *testing.T) {
	testFilterResourceStaged(t, "deep-and", []int{10, 100, 1000, 4000, 8000, 12000})
}

// TestFilterResource_WideMalformedANDFilterStaysBounded stages increasingly
// wide single-level AND malformed filters.
func TestFilterResource_WideMalformedANDFilterStaysBounded(t *testing.T) {
	testFilterResourceStaged(t, "wide-and", []int{10, 100, 1000, 5000, 10000, 16000})
}

// TestFilterResource_WideMalformedORFilterStaysBounded stages increasingly
// wide single-level OR malformed filters — the sibling shape to the AND
// case above, per "wide AND/OR malformed filter" in this sub-task's
// description.
func TestFilterResource_WideMalformedORFilterStaysBounded(t *testing.T) {
	testFilterResourceStaged(t, "wide-or", []int{10, 100, 1000, 5000, 10000, 16000})
}

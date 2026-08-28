# Local fork of github.com/vjeantet/goldap

This is a vendored, patched copy of `github.com/vjeantet/goldap`'s `message`
package, pinned via a `replace` directive in the root `go.mod`. It exists
solely to carry three fixes the upstream project (last release
`v0.0.0-20260720153039-a51461838017`, as consumed by
`github.com/vjeantet/ldapserver`) does not have. `LICENSE` is the unmodified
upstream MIT license, preserved per its terms; only `message/asn1.go`,
`message/modify_dn_response.go`, `message/bytes.go`, `message/filter.go`,
`message/filter_and.go`, `message/filter_or.go`, and
`message/filter_not.go` differ from upstream, as follows.
`message/filter_nesting_test.go` is a wholly new file (fix 3's regression
test below) with no upstream counterpart at all, so it isn't a "differs
from upstream" entry — it's new.

## 1. BER INTEGER encoding was missing sign-disambiguation padding

`message/asn1.go`'s `sizeInt32`/`writeInt32` — the pair `bytes.go`'s
`WritePrimitiveSubBytes`/`SizePrimitiveSubBytes` use to encode an actual
ASN.1 INTEGER or ENUMERATED value (reached from `integer.go`'s
`INTEGER.write`, and so from every `MessageID`) — encoded any
two's-complement value using exactly as many bytes as it took to shift the
value down to zero, with no check on the high bit of the leading byte. For
any positive value `>= 128` (and, symmetrically, certain negative ranges),
that mis-encodes: e.g. `128` needs a leading `0x00` padding byte to stay
positive under BER/DER's two's-complement rule (correct encoding is
`02 02 00 80`), but the old algorithm emitted a bare `02 01 80`, which decodes
as `-128`.

`message.MessageID` is exactly this INTEGER type, and `go-ldap/v3` (the
client library this repo's own tests, and every real LDAP client, use)
increments a connection's message ID by 1 per request starting at 1 — so any
LDAP connection issuing 128 or more requests hits this every time, silently
desynchronizing request/response correlation from that point on.

The fix replaces `sizeInt32`/`writeInt32` with the standard minimal
two's-complement encoding (the same algorithm
`github.com/go-asn1-ber/asn1-ber`'s `int64Length`/`marshalInt64` use): grow
the byte count only while the remaining value doesn't fit in a signed byte
(`>127` or `<-128`), then emit that many bytes least-significant-first.
`sizeInt64`/`writeInt64` are deliberately left untouched: `writeTagAndLength`
also calls `writeInt64` directly, to encode a BER length octet run, which is
an unsigned magnitude with no sign to disambiguate — patching that pair the
same way would instead break every length >= 128. See `internal/ldap` in the
consuming repo for the regression test
(`TestAdversarial_MessageIDBoundaryPreservesResponseCorrelation`) that drives
a real connection's message ID across 127/128/129 and asserts every response
still correlates.

## 2. `ModifyDNResponse` had no way to set a result code

Every other `LDAPResult`-based response type in this package (`AddResponse`,
`ModifyResponse`, `DelResponse`, `CompareResponse`, ...) gets its own
`SetResultCode` method, defined by hand in that type's own file — but
`modify_dn_response.go` never got one, so no caller outside this package
could ever construct a non-default-result-code `ModifyDNResponse` (the
struct's `LDAPResult` fields are unexported). This blocked the consuming
repo's `internal/ldap` package from responding to an unhandled
`ModifyDNRequest` with a fail-closed `LDAPResultUnwillingToPerform`, the same
way it already does for Add/Modify/Delete/Compare — it had no way to build
the response value at all, so a `ModifyDNRequest` reaching the server's
catch-all got silently dropped instead of a real LDAP response.

The fix adds `func (m *ModifyDNResponse) SetResultCode(code int)`, matching
the existing pattern (compare `message/add_response.go`) exactly.

## 3. Unbounded Filter AND/OR/NOT nesting recursion allowed quadratic error-chain allocation

`readFilter` (`message/filter.go`) dispatches a `Filter` CHOICE's `and`/
`or`/`not` alternatives to `readFilterAnd`/`readFilterOr`/`readFilterNot`
(`message/filter_and.go`/`message/filter_or.go`/`message/filter_not.go`),
each of which recurses back into `readFilter` for its own child(ren) with
no depth bound of its own. That recursion is not itself the problem — Go
goroutine stacks grow automatically — but every one of those three
functions, `readComponents` (the callback each hands `ReadSubBytes`), and
`ReadSubBytes` (`message/bytes.go`) itself all re-wrap a failing
descendant's error on the way back out (`fmt.Sprintf("readFilterAnd:\n%s",
err.Error())` and siblings), and each such wrap allocates an entirely new
string containing the *previous* string's full content plus a small
prefix. For N levels of nesting ending in one malformed leaf, that is
O(N) wrap operations, each copying a string whose length is already O(N)
from the wraps below it — O(N²) total bytes copied, for a final message
whose own length is a comparatively small O(N).

This is concretely dangerous because N is bounded only by the *encoded
byte size* of the nesting, not by anything else: a single AND filter
adds as little as 2-4 bytes of BER tag+length overhead per level (see the
consuming repository's `internal/ldap/filter_resource_test.go`, which
builds exactly this shape), so on the order of 1000-16000 levels fit
comfortably inside `third_party/ldapserver`'s independent, unrelated 64
KiB per-message body cap. That sub-task's staged measurements (before
this fix) showed ~1000 levels of nesting already allocating on the order
of 150 MB decoding a single malformed Search filter — pure quadratic
error-string-construction cost, not the recursion depth itself.

The fix adds a small `filterDepth int` field to `Bytes`
(`message/bytes.go`), defaulting to zero for every ordinary `Bytes` value
(only filter-nesting code ever reads or advances it), and a
`maxFilterNestingDepth = 32` constant (`message/filter.go`).
`readFilterAnd`/`readFilterOr`/`readFilterNot` each check
`bytes.filterDepth >= maxFilterNestingDepth` *before* reading anything —
rejecting immediately with a short, fixed-shape error instead of
recursing or wrapping further — and otherwise propagate
`bytes.filterDepth + 1` into the sub-`Bytes` region they hand their own
`readComponents` callback. This bounds both the recursion depth and the
error-wrap chain length to O(32) regardless of how deep or wide the input
claims to be. 32 is deliberately generous: the one Search filter the
consuming repository's `internal/ldap` package ever authorizes
(`AuthorizeGroupMembershipFilter`'s `(&(objectClass=...)(member=...))`) is
exactly one AND with two non-recursive equality children — nesting depth
1.

See `message/filter_nesting_test.go` for the regression: nesting exactly
`maxFilterNestingDepth` levels deep still parses — the guard's check
(`bytes.filterDepth >= maxFilterNestingDepth`) runs BEFORE each level
recurses, so `maxFilterNestingDepth` nested wrappers only ever present it
with `filterDepth` values `0..maxFilterNestingDepth-1`, never
`maxFilterNestingDepth` itself; nesting one level past that
(`maxFilterNestingDepth+1`) is the shallowest depth actually rejected, and
far deeper nesting is rejected the same way, with a short, bounded error
rather than an unboundedly long one. Both boundary depths
(`maxFilterNestingDepth` succeeding, `maxFilterNestingDepth+1` failing) have
their own dedicated test, not just the far-beyond-the-limit case. See also
the consuming
repository's `internal/ldap/filter_resource_test.go` for the staged,
subprocess-isolated empirical measurement (deep AND: heap allocation delta
now grows roughly linearly with nesting depth instead of quadratically;
wide AND/OR — which never nests, so was never at risk — stayed linear
throughout and needed no fix) that drove this fix and proves it against
the real production decode path.

## Keeping this fork in sync

If the pinned `github.com/vjeantet/goldap`/`github.com/vjeantet/ldapserver`
versions in the root `go.mod` are ever bumped, re-diff this directory against
the new upstream `message` package and re-apply exactly these three changes
(or drop this fork entirely if upstream has fixed them by then).

# Local fork of github.com/vjeantet/goldap

This is a vendored, patched copy of `github.com/vjeantet/goldap`'s `message`
package, pinned via a `replace` directive in the root `go.mod`. It exists
solely to carry two fixes the upstream project (last release
`v0.0.0-20260720153039-a51461838017`, as consumed by
`github.com/vjeantet/ldapserver`) does not have. `LICENSE` is the unmodified
upstream MIT license, preserved per its terms; only `message/asn1.go` and
`message/modify_dn_response.go` differ from upstream, as follows.

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

## Keeping this fork in sync

If the pinned `github.com/vjeantet/goldap`/`github.com/vjeantet/ldapserver`
versions in the root `go.mod` are ever bumped, re-diff this directory against
the new upstream `message` package and re-apply exactly these two changes
(or drop this fork entirely if upstream has fixed them by then).

# Local fork of github.com/vjeantet/ldapserver

This is a vendored, patched copy of `github.com/vjeantet/ldapserver`'s root
package, pinned via a `replace` directive in the root `go.mod`. It exists
solely to carry two fixes the pinned version
(`v1.0.2-0.20260725103726-663e6b9910fb`) lacks. `LICENSE` is the unmodified
upstream MIT license, preserved per its terms; only `packet.go` differs from
upstream, as follows. Every other file (`cancel.go`, `client.go`,
`constants.go`, `logger.go`, `message.go`, `responsemessage.go`, `route.go`,
`server.go`, and the `*_test.go` files) is an unmodified copy of the pinned
version, kept here only so this fork builds and can be diffed/re-synced as
one complete package rather than a partial patch.

## An unauthenticated declared BER length allowed a ~2 GiB pre-auth allocation

`packet.go`'s `readTagAndLength` decodes the ASN.1 length octets of an
incoming LDAP message directly off the wire, before any Bind/auth ever runs
— `client.go`'s per-connection `serve()` loop calls this (via `ReadPacket` ->
`readMessagePacket` -> `readLdapMessageBytes`) as the very first thing it
does with a freshly accepted connection. The decoded length then flows
straight into `readBytes`' `make([]byte, length)`, unconditionally.

The existing overflow guard inside the long-form length loop
(`if ret.Length >= 1<<23 { ... "length too large" }`) only stops the
`ret.Length <<= 8; ret.Length |= int(b)` shift/OR from wrapping past Go's
`int` range — it does **not** bound the final decoded value to anything
memory-safe. The guard checks the *pre-shift* value each iteration, so a
4-byte long-form length (BER tag `0x84`) can carry the running value up to
just under `1<<23` after three bytes, then the guard passes and the fourth
byte's shift pushes it as high as `0x7fffffff` (~2 GiB) — perfectly legal by
the guard's own rule, since the check never re-fires after that final shift.

Concretely, a single unauthenticated 6-byte header —
`30 84 7f ff ff ff` (SEQUENCE, long-form length, 4 length bytes decoding to
`0x7fffffff`) — is enough to make the very next line,
`readBytes(br, &bytes, tagAndLength.Length)`, attempt
`make([]byte, 2147483647)` for that one connection, before any credential is
checked. Nothing bounds how many connections can do this concurrently.

The fix adds `maxMessageBodyLength` (1 MiB — see the comment at its
declaration in `packet.go` for why that's generous for this consumer's
Bind/Search-only traffic) and enforces it in `readTagAndLength`, after both
the short-form and long-form branches have produced a final `ret.Length`,
and unconditionally before returning — i.e. strictly before
`readLdapMessageBytes` ever passes that length to `readBytes`' allocation.
An over-limit declared length is rejected with a `StructuralError` the same
way the existing malformed-length cases already are, `ret.Length` is reset
to `0` on that path, and the connection is closed by `client.serve()`'s
existing `err != nil -> return` handling — the same fate as any other
malformed packet, just without ever attempting the advertised allocation
first.

See `internal/ldap/adversarial_test.go` in the consuming repo for the
regression test
(`TestAdversarial_OversizedDeclaredLengthRejectedWithoutBoundedAllocation`)
that drives this exact 6-byte header at the real production server over TCP
and asserts both that the connection is closed without a bounded-allocation
budget being exceeded (proving the fix, not just server survival) and that a
fresh connection still Binds/Searches correctly afterward.

## A single short `Read` silently truncated message bodies with no error

`packet.go`'s `readBytes` is the function every byte read off the wire goes
through — both the one-byte-at-a-time tag/length parsing in
`readTagAndLength` and the bulk body read `readLdapMessageBytes` issues once
the declared length is known. The pre-fix version did exactly one
`conn.Read(newbytes)` call and treated it as authoritative:

```go
func readBytes(conn *bufio.Reader, bytes *[]byte, length int) (b byte, err error) {
	newbytes := make([]byte, length)
	n, err := conn.Read(newbytes)
	if n != length {
		err = fmt.Errorf("%d bytes read instead of %d", n, length)
		return
	}
	...
}
```

That assumption is simply wrong: per Go's `io.Reader` contract, a single
`Read` call is explicitly allowed to return fewer bytes than requested even
with `err == nil` — this is not a hypothetical edge case, it is normal,
expected behavior whenever a TCP message body happens to arrive split across
more than one network segment (entirely plausible for, e.g., a longer
JWT-as-Bind-password). A correct reader must loop until it has everything it
asked for, EOF, or a real error; this one didn't.

It got worse one call site up. `readLdapMessageBytes` called this function
for the message body and discarded *both* of its return values:

```go
func readLdapMessageBytes(br *bufio.Reader) (ret *[]byte, err error) {
	var bytes []byte
	var tagAndLength ldap.TagAndLength
	tagAndLength, err = readTagAndLength(br, &bytes)
	if err != nil {
		return
	}
	readBytes(br, &bytes, tagAndLength.Length)   // return values ignored
	return &bytes, err
}
```

On a short body read, `readBytes` hit its `n != length` branch and returned
*before* appending anything to `*bytes` (the `append` only runs on the
exact-length success path) — so `bytes` stayed as just the tag+length
header, `readLdapMessageBytes`'s own `err` stayed `nil` (it was last set by
the already-successful `readTagAndLength` call), and the caller got back a
truncated, header-only byte slice with **no error signal at all**. BER
decoding that truncated slice downstream then either failed unpredictably
or, via the `recover()` in `messagePacket.readMessage()`, got silently
turned into a generic "invalid packet" error — either way, an ordinary,
non-malicious client whose message body happened not to arrive in a single
`Read` could have its connection fail for no legitimate protocol reason.

The fix has two parts, both in `packet.go`:

1. `readBytes` now uses `io.ReadFull(conn, newbytes)` instead of a single
   `conn.Read` call. `io.ReadFull` already implements exactly the
   read-until-full-or-error loop this needed, and returns a proper error
   (`io.ErrUnexpectedEOF` on a short read due to EOF, or the underlying
   error otherwise) that the existing `if err != nil { return }` control
   flow handles correctly with no further change.
2. `readLdapMessageBytes` now captures and returns `readBytes`' error
   (`_, err = readBytes(br, &bytes, tagAndLength.Length)`) instead of
   discarding it, so a short/failed body read makes the function return a
   non-nil `err` rather than a truncated slice with `err == nil`.

See `internal/ldap/adversarial_test.go` in the consuming repo for the
regression test
(`TestAdversarial_FragmentedMessageBodyStillProcessedCorrectly`) that
delivers one valid, complete LDAP message's bytes to the real production
server as several small, separately-timed writes (to encourage the server
side to observe them as separate `Read` calls) and asserts the message is
still processed correctly end to end.

## Keeping this fork in sync

If the pinned `github.com/vjeantet/ldapserver` version in the root `go.mod`
is ever bumped, re-diff this directory against the new upstream package and
re-apply both of the changes above (or drop this fork entirely if upstream
has fixed them by then).

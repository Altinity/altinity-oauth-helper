# Local fork of github.com/vjeantet/ldapserver

This is a vendored, patched copy of `github.com/vjeantet/ldapserver`'s root
package, pinned via a `replace` directive in the root `go.mod`. It exists
solely to carry five fixes the pinned version
(`v1.0.2-0.20260725103726-663e6b9910fb`) lacks. `LICENSE` is the unmodified
upstream MIT license, preserved per its terms; only `packet.go`, `client.go`,
and `server.go` differ from upstream, as follows. Every other file
(`cancel.go`, `constants.go`, `logger.go`, `message.go`,
`responsemessage.go`, `route.go`, and the `*_test.go` files) is an
unmodified copy of the pinned version, kept here only so this fork builds
and can be diffed/re-synced as one complete package rather than a partial
patch.

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

The fix adds `maxMessageBodyLength` (1 MiB when this fix was first introduced;
**64 KiB is the current value** — see "Aggregate pre-auth memory across
connections was unbounded" below for why it was later reduced, and the
comment at `maxMessageBodyLength`'s declaration in `packet.go` for the full,
up-to-date reasoning) and enforces it in `readTagAndLength`, after both
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

## A non-reading client could pin unbounded per-connection goroutines and hang graceful shutdown

`client.go`'s `serve()` spawned one `ProcessRequestMessage` goroutine per
inbound request with no cap (the "TODO: Use a implementation to limit
runnuning request by client" this file used to carry, literally
unimplemented), and its single per-client writer goroutine wrote each
response with no deadline at all (`WriteTimeout` was read once per
read-loop iteration, which only bounds the gap between finishing one read
and starting the next — not the actual, independent write path). A client
that kept sending valid requests while never reading its own responses
could therefore make the server spawn goroutines without limit, each one
eventually blocking forever trying to send its response on the unbuffered
`chanOut` channel once the single writer goroutine itself blocked on a
stalled `bw.Write`/`Flush` call to that same non-reading peer — pinning
memory, goroutines, and the connection's file descriptor indefinitely, with
no cap on how many connections could do this concurrently.

It got worse on the shutdown path specifically:
`Server.Stop()`'s `s.wg.Wait()` waits for every accepted client's
`close()` to return; `close()` itself waits (`c.wg.Wait()`) for every
still-running `ProcessRequestMessage` to finish, and separately, the
per-client shutdown-listener goroutine that `close()` also waits on
(`<-c.shutdownDone`) sends its own Notice-of-Disconnection through that
very same blocked `chanOut` channel before it can even set a read deadline
to unblock the read side. A single non-reading client — accidental or
malicious — could therefore hang graceful shutdown for the entire process
indefinitely, not just that one connection.

The fix has two parts, both in `client.go`:

1. `MaxInFlightRequestsPerClient` (20, exported so the consuming repo's
   regression tests can reference it directly rather than duplicating the
   literal) bounds how many
   `ProcessRequestMessage` executions one client connection may have
   concurrently live, enforced by `acquireRequestSlot`/
   `releaseRequestSlot` (a buffered-channel semaphore) around every
   dispatch site in `serve()`'s read loop, including the synchronous
   StartTLS path. `acquireRequestSlot` also selects on the server's
   shutdown signal (`srv.chDone`), so a client stuck waiting for a slot
   during a global shutdown returns rather than blocking it — the
   `c.closing` channel closed by this same client's own `close()` would be
   too late to help, since `close()` is itself waiting on this goroutine to
   return.
2. `writeMessage` now sets `WriteTimeout` as an actual deadline
   immediately before its `bw.Write`/`Flush` call — not once per
   read-loop iteration as before (that call is now removed entirely: it
   could otherwise keep re-arming, and therefore indefinitely postponing,
   the deadline governing an already-in-flight blocked write, purely
   because the client kept sending more requests on the read side) — and
   returns any error from that write. The per-client writer goroutine
   treats a returned error as fatal: it closes the raw connection and
   keeps draining (never writing again to) `chanOut` without blocking, so
   every handler goroutine already blocked sending a response — and any
   still to come, including the shutdown-listener's own
   Notice-of-Disconnection send — is promptly unblocked instead of left
   waiting forever. That is what bounds the graceful-shutdown hang above to
   `WriteTimeout`, not indefinitely.

Both mechanisms are needed together: the cap alone would still deadlock
forever once full, since nothing would ever free a slot without the
write-deadline fix unblocking the handlers holding them; the write-deadline
fix alone would still let goroutines accumulate without limit until the
first write happened to stall.

This directory is its own Go module (see `go.mod`) with no `replace` of its
own for `github.com/vjeantet/goldap` — it only resolves at all as part of
the consuming repo's root module build, via that repo's `go.mod` `replace`
directives for both `ldapserver` and `goldap`. It cannot be built or tested
standalone, and the root module's own `go test ./...` does not descend into
it either, since it is a separate module boundary — exactly why every
`*_test.go` file already in this directory is an unmodified, never-actually-
executed-by-anyone's-test-run copy of the pinned version (see the top of
this file). Regression tests for every fix here, including this one,
therefore live in the consuming repo's `internal/ldap/adversarial_test.go`,
which the root gate (`go build ./... && go vet ./... && go test ./...`)
does cover, and which resolves this package through the root module's
`replace` directives like any real consumer would:

- `TestAdversarial_StalledPartialBodyReadTimesOutWithoutBlockingShutdown`
  (also covers this file's `PATCHES.md` first item) proves
  `internal/ldap.New` wires a nonzero `ReadTimeout` into the production
  server and that a stalled partial-body connection is closed and does not
  block graceful shutdown.
- `TestAdversarial_BoundedInFlightGoroutinesPerClient` pipelines more Binds
  than `MaxInFlightRequestsPerClient` on one connection — all serialized
  behind `internal/ldap`'s own per-connection Bind/Search lock, which is
  exactly why this test counts live goroutines via `runtime.NumGoroutine()`
  rather than counting handler entries the way a test written directly
  against this package (with a custom, non-serializing route handler)
  could — and asserts the attributable goroutine count stays bounded near
  the cap rather than growing with the number of pipelined requests.
- `TestAdversarial_WriteDeadlineClosesStalledConnectionAndUnblocksGracefulShutdown`
  drives a real non-reading client over TCP (a shrunk receive buffer plus a
  volume of ordinary, fast-completing Binds whose responses are never read)
  and asserts both that the server actively closes the connection once
  `WriteTimeout` elapses and that `Server.Stop()` still completes promptly
  despite it — proving the shutdown-hang scenario above is fixed, not
  merely that the connection eventually errors out.

## Aggregate pre-auth memory across connections was unbounded

The first item above bounds how large a single connection's declared
message-body length may be (originally 1 MiB, now 64 KiB — see the updated
comment at `maxMessageBodyLength`'s declaration in `packet.go`), and the
third item's `ReadTimeout` bounds how long any one connection may hold that
buffer while stalled. Neither bounds how many connections can do this AT
ONCE: `server.go`'s `serve()` accept loop had no cap on concurrent accepted
connections at all, so an unauthenticated attacker opening many concurrent
sockets — each sending only the handful of bytes needed to declare a
maximal-length body, then nothing further — could still pin
`N * maxMessageBodyLength` bytes of live server memory for up to
`ReadTimeout`, with no ceiling on `N` other than available file descriptors.

The fix adds `Server.MaxConnections` (see its doc comment in `server.go`):
zero means unbounded, preserving prior behavior for any caller that never
sets it; a positive value makes `serve()`'s accept loop reject (close
immediately, before any per-connection buffer — bufio reader/writer, let
alone a `readMessagePacket` body allocation — is ever created for it) any
connection accepted once that many are already live, tracked by a
buffered-channel semaphore (`connSlots`) released when that connection's
`serve()` returns. `internal/ldap/server.go` in the consuming repo sets this
to 256, documented there alongside the updated 64 KiB body cap: together
they turn aggregate pre-auth memory into an explicit, justified arithmetic
bound (256 * 64 KiB = 16 MiB worst case) instead of an unbounded one.

See `internal/ldap/adversarial_test.go`'s
`TestAdversarial_ConcurrentMaxLengthStalledConnectionsAreBounded`, which
dials more at-cap-length stalled connections than `MaxConnections` against
the real production server (with `MaxConnections` overridden small for a
fast, deterministic test) and asserts both that connections within the cap
behave as the single-connection oversized-length test already proved and
that every connection beyond the cap is rejected immediately rather than
allowed to allocate its own body buffer.

## Abandon/Cancel could be starved behind saturated ordinary-work dispatch

The third item above (`MaxInFlightRequestsPerClient`) bounds how many
ordinary `ProcessRequestMessage` executions one client connection may have
concurrently live, enforced by gating every dispatch in `serve()`'s read
loop — including Abandon and a Cancel Extended request (RFC 3909, OID
`1.3.6.1.1.8`) — behind the same semaphore. That is exactly backwards for
those two operations: a client sends Abandon/Cancel precisely because it
wants to relieve a backed-up connection, so gating them behind the very
saturation they exist to relieve meant an already-decoded Abandon/Cancel
request could not run until an ordinary-work slot freed. The read loop
itself was also stuck blocked on that same semaphore while waiting to
dispatch that already-decoded Abandon/Cancel message, so it could not get
back to `ReadPacket` to notice a subsequent peer disconnect promptly either
— one root cause producing both symptoms.

The fix (`client.go`) adds `MaxInFlightControlOperationsPerClient`, a
second, independent, buffered-channel semaphore
(`controlInFlight`/`acquireControlSlot`/`releaseControlSlot`) that Abandon
and Cancel dispatch against instead of the ordinary-work one, via the new
`isControlOperation` check placed in `serve()`'s read loop immediately after
the existing Unbind short-circuit and before the ordinary-work
`acquireRequestSlot` call. This is deliberately a *separate, still-bounded*
capacity rather than an unconditional bypass: Abandon/Cancel always get to
run without queueing behind unrelated long-running application work, while
remaining bounded so a flood of distinct Abandon/Cancel messages cannot
itself become an unbounded-goroutine vector the way removing the cap
entirely would risk. Both operations are lightweight and bounded by
construction — a map lookup plus signaling an already-registered request's
`Done` channel (see `route.go`'s Abandon/Cancel handling and `cancel.go`'s
`handleCancel`) — never a call into arbitrary application handler code or a
slow external dependency, which is what makes a dedicated capacity safe
here in a way it would not be for ordinary Bind/Search dispatch.

See `internal/ldap/adversarial_test.go`'s
`TestAdversarial_AbandonRunsPromptlyDespiteSaturatedOrdinaryWork`,
`TestAdversarial_CancelRunsPromptlyDespiteSaturatedOrdinaryWork`, and
`TestAdversarial_ConnectionCloseDetectedPromptlyAfterControlOpDespiteSaturation`
— the last of which sends a Cancel while every ordinary-work slot is held
and then immediately closes the raw TCP connection, asserting the server
notices and cleans up promptly rather than only after a slot eventually
frees, proving the read-loop-stall half of this fix as well as the
dispatch-starvation half.

## Keeping this fork in sync

If the pinned `github.com/vjeantet/ldapserver` version in the root `go.mod`
is ever bumped, re-diff this directory against the new upstream package and
re-apply all five of the changes above (or drop this fork entirely if
upstream has fixed them by then).

package profile

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func testAuthState(t *testing.T) authState {
	t.Helper()
	bound, err := ParseDN("uid=alice,ou=users,dc=profile,dc=test")
	if err != nil {
		t.Fatalf("ParseDN: %v", err)
	}
	return authState{
		Username:  "alice",
		Issuer:    "https://idp.example.com/",
		Subject:   "subject-alice",
		BoundDN:   "uid=alice,ou=users,dc=profile,dc=test",
		boundDN:   bound,
		ExpiresAt: 1000,
		Roles:     []string{"clickhouse_reader", "clickhouse_writer"},
	}
}

// TestConnection_InitialStateUnauthenticated proves a freshly constructed
// connection starts UNAUTHENTICATED with a zero-value authState, per
// "Authentication state" in the plan.
func TestConnection_InitialStateUnauthenticated(t *testing.T) {
	var c connection
	if c.authenticated {
		t.Fatal("zero-value connection: authenticated = true, want false")
	}
	if !reflect.DeepEqual(c.auth, authState{}) {
		t.Fatalf("zero-value connection: auth = %+v, want zero value", c.auth)
	}
}

// TestConnection_ReplaceAuthStoresState proves replaceAuth stores the
// given state and marks the connection authenticated.
func TestConnection_ReplaceAuthStoresState(t *testing.T) {
	var c connection
	want := testAuthState(t)
	c.replaceAuth(want)

	if !c.authenticated {
		t.Fatal("after replaceAuth: authenticated = false, want true")
	}
	if c.auth.Username != want.Username || c.auth.Issuer != want.Issuer ||
		c.auth.Subject != want.Subject || c.auth.BoundDN != want.BoundDN ||
		c.auth.ExpiresAt != want.ExpiresAt {
		t.Fatalf("after replaceAuth: auth = %+v, want %+v", c.auth, want)
	}
	if !c.auth.boundDN.Equal(want.boundDN) {
		t.Fatalf("after replaceAuth: boundDN not preserved structurally")
	}
	if !reflect.DeepEqual(c.auth.Roles, want.Roles) {
		t.Fatalf("after replaceAuth: Roles = %v, want %v", c.auth.Roles, want.Roles)
	}
}

// TestConnection_ReplaceAuthStoresClonedRoles is the doneWhen check named
// by this sub-task: it must fail if cloneRoles is replaced by a direct
// slice assignment in replaceAuth. It mutates the original slice AFTER
// calling replaceAuth and asserts the connection's stored snapshot is
// unaffected — only true if replaceAuth copied the slice's backing array
// rather than aliasing it.
func TestConnection_ReplaceAuthStoresClonedRoles(t *testing.T) {
	original := []string{markerLegitimateRole, "clickhouse_writer"}

	var c connection
	c.replaceAuth(authState{Roles: original})

	// Mutate the caller's original slice after the store.
	original[0] = "MUTATED-AFTER-STORE"
	original[1] = "MUTATED-AFTER-STORE"

	if c.auth.Roles[0] == "MUTATED-AFTER-STORE" || c.auth.Roles[1] == "MUTATED-AFTER-STORE" {
		t.Fatalf("connection.auth.Roles observed a post-store mutation of the caller's slice: %v — replaceAuth must clone via cloneRoles, not alias the caller's backing array", c.auth.Roles)
	}
	if c.auth.Roles[0] != markerLegitimateRole {
		t.Fatalf("connection.auth.Roles[0] = %q, want %q", c.auth.Roles[0], markerLegitimateRole)
	}
}

// TestConnection_ReplaceAuthClonesEvenWithFakeResolver drives the same
// proof through fakeResolver's documented same-slice-every-call behavior,
// closer to how a real Bind handler would use it: Roles() returns the
// stored slice verbatim, replaceAuth clones it on the way in, and mutating
// the slice fakeResolver handed back afterward must not reach the
// connection's stored state.
func TestConnection_ReplaceAuthClonesEvenWithFakeResolver(t *testing.T) {
	resolver := newFakeResolver().withRoles("subject-alice", []string{markerLegitimateRole})

	claims := &newVerificationResult("alice", "https://idp.example.com/", "subject-alice", 0).Claims
	roles, err := resolver.Roles(claims)
	if err != nil {
		t.Fatalf("Roles: unexpected error: %v", err)
	}

	var c connection
	c.replaceAuth(authState{Subject: "subject-alice", Roles: roles})

	roles[0] = "MUTATED-AFTER-STORE"

	if c.auth.Roles[0] != markerLegitimateRole {
		t.Fatalf("connection.auth.Roles[0] = %q after resolver-slice mutation, want unaffected %q", c.auth.Roles[0], markerLegitimateRole)
	}
}

// TestConnection_ClearAuthResetsEverything proves clearAuth zeroes every
// field of authState, not merely flipping authenticated to false — a
// stale BoundDN/boundDN/Roles left behind after clear would let a
// still-in-scope reference to the old state leak into a later mistaken
// read.
func TestConnection_ClearAuthResetsEverything(t *testing.T) {
	var c connection
	c.replaceAuth(testAuthState(t))
	c.clearAuth()

	if c.authenticated {
		t.Fatal("after clearAuth: authenticated = true, want false")
	}
	if !reflect.DeepEqual(c.auth, authState{}) {
		t.Fatalf("after clearAuth: auth = %+v, want zero value", c.auth)
	}
}

// TestConnection_SecondReplaceAuthFullyReplacesNoMerge proves a second
// replaceAuth call installs its argument wholesale: fields the second
// authState leaves zero must end up zero on the connection, not
// inherited from the first Bind's state (plan: "Authentication state" ->
// "successful Bind(B) -> AUTHENTICATED(B)", never a merge of A and B).
func TestConnection_SecondReplaceAuthFullyReplacesNoMerge(t *testing.T) {
	var c connection
	c.replaceAuth(testAuthState(t)) // full state A

	partial := authState{
		Username: "bob", // only Username set; everything else left zero
	}
	c.replaceAuth(partial)

	if !c.authenticated {
		t.Fatal("after second replaceAuth: authenticated = false, want true")
	}
	if c.auth.Username != "bob" {
		t.Fatalf("auth.Username = %q, want %q", c.auth.Username, "bob")
	}
	if c.auth.Issuer != "" || c.auth.Subject != "" || c.auth.BoundDN != "" || c.auth.ExpiresAt != 0 {
		t.Fatalf("second replaceAuth did not fully replace state A: auth = %+v, want every unset field zero", c.auth)
	}
	if !c.auth.boundDN.Equal(DN{}) {
		t.Fatalf("second replaceAuth left a stale parsed boundDN from state A")
	}
	if c.auth.Roles != nil {
		t.Fatalf("auth.Roles = %v, want nil after replacing with a state carrying no roles", c.auth.Roles)
	}
}

// TestCloneRoles proves cloneRoles' documented contract directly: nil for
// empty/nil input, and a copy (not an alias) otherwise.
func TestCloneRoles(t *testing.T) {
	if got := cloneRoles(nil); got != nil {
		t.Fatalf("cloneRoles(nil) = %v, want nil", got)
	}
	if got := cloneRoles([]string{}); got != nil {
		t.Fatalf("cloneRoles([]string{}) = %v, want nil", got)
	}

	original := []string{"a", "b"}
	cloned := cloneRoles(original)
	if !reflect.DeepEqual(cloned, original) {
		t.Fatalf("cloneRoles(%v) = %v, want equal contents", original, cloned)
	}
	original[0] = "MUTATED"
	if cloned[0] == "MUTATED" {
		t.Fatal("cloneRoles returned an alias of its input, not a copy")
	}
}

// TestAuthState_FieldSetIsExactNoCredentialField is a mechanical guard
// against a password/JWT/frame-reference field silently being added to
// authState later: it enumerates the exact field set the plan specifies
// (Username, Issuer, Subject, BoundDN, boundDN, ExpiresAt, Roles) and fails
// if any field is added, removed, or renamed — including, specifically, any
// field whose name suggests a credential or raw frame.
func TestAuthState_FieldSetIsExactNoCredentialField(t *testing.T) {
	want := []string{"Username", "Issuer", "Subject", "BoundDN", "boundDN", "ExpiresAt", "Roles"}

	typ := reflect.TypeOf(authState{})
	if typ.NumField() != len(want) {
		names := make([]string, typ.NumField())
		for i := range names {
			names[i] = typ.Field(i).Name
		}
		t.Fatalf("authState has %d fields %v, want exactly %v", typ.NumField(), names, want)
	}
	for i, name := range want {
		if got := typ.Field(i).Name; got != name {
			t.Fatalf("authState field %d = %q, want %q (full expected set: %v)", i, got, name, want)
		}
	}
}

// TestConnection_FieldSetHasNoPasswordOrFrameField is the same mechanical
// guard applied to connection: no field name containing "password",
// "token", "jwt", "frame", or "body" (case-insensitively) may exist,
// matching the plan's "No password/frame reference field may exist on the
// struct."
func TestConnection_FieldSetHasNoPasswordOrFrameField(t *testing.T) {
	forbidden := []string{"password", "token", "jwt", "frame", "body", "credential"}
	typ := reflect.TypeOf(connection{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		lower := toLowerASCII(name)
		for _, bad := range forbidden {
			if containsASCII(lower, bad) {
				t.Fatalf("connection field %q looks like a retained credential/frame reference (matches %q) — the plan forbids this", name, bad)
			}
		}
	}
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func containsASCII(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestConnection_ClockFieldMatchesFakeClockShape proves fakeClock.Now
// (from fakes_test.go) assigns directly to connection.clock without an
// adapter, i.e. connection.clock really is func() time.Time (or an
// assignment-compatible shape), and that a stored connection can read a
// deterministic, advanceable time through it.
func TestConnection_ClockFieldMatchesFakeClockShape(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fc := newFakeClock(start)

	c := connection{clock: fc.Now}

	if got := c.clock(); !got.Equal(start) {
		t.Fatalf("c.clock() = %v, want %v", got, start)
	}
	fc.advance(30 * time.Second)
	if got := c.clock(); got.Equal(start) {
		t.Fatalf("c.clock() did not advance after fakeClock.advance")
	}
}

// TestConnection_ContextFieldHoldsGivenContext is a minimal smoke test that
// connection.ctx is a plain context.Context field usable the ordinary way.
func TestConnection_ContextFieldHoldsGivenContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := connection{ctx: ctx}
	if c.ctx != ctx {
		t.Fatal("connection.ctx does not hold the assigned context.Context")
	}
}

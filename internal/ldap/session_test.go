package ldap

import "testing"

func TestSession_InitiallyUnauthenticated(t *testing.T) {
	s := newSession()
	s.Lock()
	defer s.Unlock()

	if _, ok := s.snapshot(); ok {
		t.Fatalf("snapshot on a fresh session: ok = true, want false")
	}
}

func TestSession_ReplaceThenSnapshot(t *testing.T) {
	s := newSession()
	s.Lock()

	s.replace(authenticatedState{
		Username:  "alice",
		Issuer:    "https://idp.example/",
		Subject:   "sub-1",
		BoundDN:   "uid=alice,ou=users,dc=altinity,dc=internal",
		ExpiresAt: 1234,
		Roles:     []string{"ch_readonly", "ch_engineer"},
	})

	got, ok := s.snapshot()
	s.Unlock()

	if !ok {
		t.Fatalf("snapshot after replace: ok = false, want true")
	}
	if got.Username != "alice" || got.Issuer != "https://idp.example/" || got.Subject != "sub-1" ||
		got.BoundDN != "uid=alice,ou=users,dc=altinity,dc=internal" || got.ExpiresAt != 1234 {
		t.Fatalf("snapshot fields = %+v, want the replaced values", got)
	}
	if len(got.Roles) != 2 || got.Roles[0] != "ch_readonly" || got.Roles[1] != "ch_engineer" {
		t.Fatalf("snapshot Roles = %v, want [ch_readonly ch_engineer]", got.Roles)
	}
}

func TestSession_Clear(t *testing.T) {
	s := newSession()
	s.Lock()
	s.replace(authenticatedState{Username: "alice", Roles: []string{"ch_readonly"}})
	s.clear()
	_, ok := s.snapshot()
	s.Unlock()

	if ok {
		t.Fatalf("snapshot after clear: ok = true, want false")
	}
}

// TestSession_ReplaceDefensivelyCopiesRoles proves that mutating the caller's
// role slice after replace cannot retroactively change the stored session
// state — the plan's required defensive copy on the way in.
func TestSession_ReplaceDefensivelyCopiesRoles(t *testing.T) {
	s := newSession()
	roles := []string{"ch_readonly"}

	s.Lock()
	s.replace(authenticatedState{Username: "alice", Roles: roles})
	s.Unlock()

	roles[0] = "mutated" // alias mutation, after storing

	s.Lock()
	got, ok := s.snapshot()
	s.Unlock()

	if !ok {
		t.Fatalf("snapshot: ok = false, want true")
	}
	if got.Roles[0] != "ch_readonly" {
		t.Fatalf("stored role = %q after aliased mutation, want %q (replace must clone)", got.Roles[0], "ch_readonly")
	}
}

// TestSession_SnapshotDefensivelyCopiesRoles proves that mutating the slice
// returned by snapshot cannot reach or change the stored session state —
// the plan's required defensive copy on the way out.
func TestSession_SnapshotDefensivelyCopiesRoles(t *testing.T) {
	s := newSession()

	s.Lock()
	s.replace(authenticatedState{Username: "alice", Roles: []string{"ch_readonly"}})
	s.Unlock()

	s.Lock()
	first, ok := s.snapshot()
	s.Unlock()
	if !ok {
		t.Fatalf("first snapshot: ok = false, want true")
	}

	first.Roles[0] = "mutated" // alias mutation of the returned copy

	s.Lock()
	second, ok := s.snapshot()
	s.Unlock()
	if !ok {
		t.Fatalf("second snapshot: ok = false, want true")
	}
	if second.Roles[0] != "ch_readonly" {
		t.Fatalf("stored role = %q after mutating a prior snapshot, want %q (snapshot must clone)", second.Roles[0], "ch_readonly")
	}
}

func TestSession_ReplaceReplacesCompletely(t *testing.T) {
	s := newSession()

	s.Lock()
	s.replace(authenticatedState{Username: "alice", BoundDN: "uid=alice,ou=users,dc=altinity,dc=internal", Roles: []string{"ch_readonly"}})
	s.Unlock()

	// A failed re-Bind must clear before leaving state unauthenticated,
	// and a successful re-Bind must fully replace rather than merge.
	s.Lock()
	s.clear() // required first mutation of every Bind attempt
	s.replace(authenticatedState{Username: "bob", BoundDN: "uid=bob,ou=users,dc=altinity,dc=internal", Roles: []string{"ch_engineer"}})
	got, ok := s.snapshot()
	s.Unlock()

	if !ok {
		t.Fatalf("snapshot after re-Bind: ok = false, want true")
	}
	if got.Username != "bob" || got.BoundDN != "uid=bob,ou=users,dc=altinity,dc=internal" {
		t.Fatalf("snapshot after re-Bind = %+v, want bob's fresh state (no trace of alice)", got)
	}
	if len(got.Roles) != 1 || got.Roles[0] != "ch_engineer" {
		t.Fatalf("snapshot Roles after re-Bind = %v, want [ch_engineer] only", got.Roles)
	}
}

func TestSession_ClearAfterFailedRebindLeavesUnauthenticated(t *testing.T) {
	s := newSession()

	s.Lock()
	s.replace(authenticatedState{Username: "alice", Roles: []string{"ch_readonly"}})
	s.Unlock()

	// Simulate a Bind attempt that clears first (required ordering) and
	// then fails before any replace call.
	s.Lock()
	s.clear()
	_, ok := s.snapshot()
	s.Unlock()

	if ok {
		t.Fatalf("snapshot after clear-then-failed-Bind: ok = true, want false (stale prior authentication must not survive)")
	}
}

func TestCloneRoles_NilAndEmpty(t *testing.T) {
	if got := cloneRoles(nil); got != nil {
		t.Fatalf("cloneRoles(nil) = %v, want nil", got)
	}
	if got := cloneRoles([]string{}); got != nil {
		t.Fatalf("cloneRoles(empty) = %v, want nil", got)
	}
}

func TestCloneRoles_Independence(t *testing.T) {
	src := []string{"a", "b"}
	cloned := cloneRoles(src)
	cloned[0] = "z"
	if src[0] != "a" {
		t.Fatalf("mutating clone changed source: src[0] = %q, want %q", src[0], "a")
	}
}

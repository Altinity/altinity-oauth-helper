package ldap

import (
	"time"

	"github.com/rs/zerolog/log"

	message "github.com/vjeantet/goldap/message"
	ldapserver "github.com/vjeantet/ldapserver"
)

// searchNotAuthorizedDiagnostic is the one fixed diagnostic text every
// Search this connection is not authorized to see converges on — an
// unauthenticated connection, a wrong base/scope/filter shape, and a
// member DN naming a different principal are all, deliberately,
// indistinguishable to the client. See "Restricted Search authorization" in
// the phase-2 plan.
const searchNotAuthorizedDiagnostic = "insufficient access"

// handleSearch is the restricted-Search route handler shared by every
// Search on this connection. It never calls verifier.Verify or
// roles.Roles, never retrieves or reinterprets the JWT/claims, and never
// recomputes roles: it answers solely from the role snapshot the most
// recent successful Bind on this same connection stored. See "Role
// snapshot semantics" and "Restricted Search authorization" in the plan.
//
// It also enforces the client-declared sizeLimit/timeLimit request fields
// (see "Search sizeLimit"/"Search timeLimit" in the phase-5 plan):
//
//   - sizeLimit: 0 means unlimited; a positive N caps the number of
//     rendered entries at N — the count of entries NewGroupEntry actually
//     rendered, not the raw length of the role snapshot, since a role can
//     be defensively skipped. Exactly N valid entries is success; N+1 or
//     more emits exactly N entries then SearchResultDone(sizeLimitExceeded).
//   - timeLimit: 0 means no client-requested deadline; a positive value is
//     a wall-clock deadline in seconds, measured from before this handler
//     ever waits on the per-connection operation lock. It is checked again
//     immediately after acquiring the authenticated session snapshot,
//     before and after every entry write, and once more before the final
//     result is decided, so an expiry discovered at any of those points
//     ends the Search with SearchResultDone(timeLimitExceeded).
//
// When both limits are simultaneously active, whichever terminating
// condition this handler observes first wins; the two are never both
// reported for the same Search.
func (h *connectionHandler) handleSearch(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	// start anchors timeLimit's wall-clock deadline. It is deliberately
	// recorded before this handler ever waits on the per-connection
	// operation lock, per the plan's timeLimit semantics — a Search that
	// queues behind a slow Bind/Search on the same connection must have
	// that queuing time count against its own declared deadline.
	start := time.Now()

	requestCtx, cancel := requestContext(h.rootCtx, m)
	defer cancel()

	req := m.GetSearchRequest()
	sizeLimit := int(req.SizeLimit())
	timeLimit := int(req.TimeLimit())
	typesOnly := bool(req.TypesOnly())

	var deadline time.Time
	if timeLimit > 0 {
		deadline = start.Add(time.Duration(timeLimit) * time.Second)
	}
	expired := func() bool {
		return !deadline.IsZero() && time.Now().After(deadline)
	}

	h.session.Lock()
	defer h.session.Unlock()

	if requestCtx.Err() != nil {
		return
	}

	state, ok := h.session.snapshot()
	if !ok {
		h.failSearch(w, "unauthenticated")
		return
	}

	// First timeLimit check point: immediately after acquiring the
	// authenticated session snapshot.
	if expired() {
		h.finishSearch(w, ldapserver.LDAPResultTimeLimitExceeded, state.Username, sizeLimit, timeLimit, typesOnly, 0)
		return
	}

	if !h.groupBase.Equal(string(req.BaseObject())) {
		h.failSearch(w, "wrong base")
		return
	}
	if int(req.Scope()) != ldapserver.SearchRequestWholeSubtree {
		h.failSearch(w, "wrong scope")
		return
	}
	if !AuthorizeGroupMembershipFilter(req.Filter(), state.BoundDN) {
		h.failSearch(w, "unauthorized filter shape")
		return
	}

	if len(state.Roles) == 0 {
		h.finishSearch(w, ldapserver.LDAPResultSuccess, state.Username, sizeLimit, timeLimit, typesOnly, 0)
		return
	}

	requested := attributeSelectionStrings(req.Attributes())

	emitted := 0
	resultCode := ldapserver.LDAPResultSuccess

emitLoop:
	for _, role := range state.Roles {
		// timeLimit check point: before considering the next entry.
		if expired() {
			resultCode = ldapserver.LDAPResultTimeLimitExceeded
			break emitLoop
		}

		entry, err := NewGroupEntry(h.groupBase, h.roleCNPrefix, role, state.BoundDN)
		if err != nil {
			// A stored role can only be empty if the role pipeline (which
			// already rejects empty mapped roles upstream) returned one
			// anyway; skip defensively rather than emit a malformed entry.
			// sizeLimit counts only entries actually rendered, so a skipped
			// role never consumes budget it was never granted.
			continue
		}

		if sizeLimit > 0 && emitted >= sizeLimit {
			resultCode = ldapserver.LDAPResultSizeLimitExceeded
			break emitLoop
		}

		w.Write(entry.Render(requested, typesOnly))
		emitted++

		// timeLimit check point: immediately after writing an entry.
		if expired() {
			resultCode = ldapserver.LDAPResultTimeLimitExceeded
			break emitLoop
		}
	}

	// Final timeLimit check point: a Search that reached the end of its
	// role snapshot without tripping sizeLimit still must not report
	// success if the deadline has since passed. This never overrides a
	// sizeLimit result already decided above — whichever terminating
	// condition this handler observed first is the one reported.
	if resultCode == ldapserver.LDAPResultSuccess && expired() {
		resultCode = ldapserver.LDAPResultTimeLimitExceeded
	}

	h.finishSearch(w, resultCode, state.Username, sizeLimit, timeLimit, typesOnly, emitted)
}

// finishSearch writes the final SearchResultDone response for a Search that
// passed authorization (unlimited success, zero roles, sizeLimit
// exhaustion, or timeLimit expiry), and logs only safe numeric/bool
// telemetry describing the outcome — size_limit, time_limit, types_only,
// the emitted entry count, and the final LDAP result code. It never logs
// the filter, the bound/member DN, controls, the raw request, or any role
// value; see "Safe Search telemetry" in the phase-5 plan.
func (h *connectionHandler) finishSearch(w ldapserver.ResponseWriter, resultCode int, username string, sizeLimit, timeLimit int, typesOnly bool, entries int) {
	msg := "ldap search succeeded"
	switch {
	case resultCode == ldapserver.LDAPResultSizeLimitExceeded:
		msg = "ldap search size limit exceeded"
	case resultCode == ldapserver.LDAPResultTimeLimitExceeded:
		msg = "ldap search time limit exceeded"
	case entries == 0:
		msg = "ldap search succeeded (zero roles)"
	}

	log.Info().
		Str("op", "search").
		Bool("success", resultCode == ldapserver.LDAPResultSuccess).
		Int("result", resultCode).
		Str("username", username).
		Int("size_limit", sizeLimit).
		Int("time_limit", timeLimit).
		Bool("types_only", typesOnly).
		Int("entries", entries).
		Msg(msg)

	w.Write(ldapserver.NewSearchResultDoneResponse(resultCode))
}

// failSearch writes the one fixed non-success SearchResultDone (zero
// entries) every unauthorized Search converges on, and logs only a short
// internal, non-disclosing classification.
func (h *connectionHandler) failSearch(w ldapserver.ResponseWriter, reason string) {
	res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultInsufficientAccessRights)
	res.SetDiagnosticMessage(searchNotAuthorizedDiagnostic)

	log.Info().
		Str("op", "search").
		Bool("success", false).
		Int("result", ldapserver.LDAPResultInsufficientAccessRights).
		Str("reason", reason).
		Msg("ldap search rejected")

	w.Write(res)
}

// attributeSelectionStrings converts a decoded AttributeSelection (a slice
// of the dependency's LDAPString type) into plain strings for GroupEntry's
// attribute-projection helper, without altering the underlying bytes.
func attributeSelectionStrings(sel message.AttributeSelection) []string {
	if len(sel) == 0 {
		return nil
	}
	out := make([]string, len(sel))
	for i, a := range sel {
		out[i] = string(a)
	}
	return out
}

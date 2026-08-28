package ldap

import (
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
func (h *connectionHandler) handleSearch(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	requestCtx, cancel := requestContext(h.rootCtx, m)
	defer cancel()

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

	req := m.GetSearchRequest()

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
		log.Info().
			Str("op", "search").
			Bool("success", true).
			Int("result", ldapserver.LDAPResultSuccess).
			Str("username", state.Username).
			Int("entries", 0).
			Msg("ldap search succeeded (zero roles)")
		w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))
		return
	}

	requested := attributeSelectionStrings(req.Attributes())
	typesOnly := bool(req.TypesOnly())

	for _, role := range state.Roles {
		entry, err := NewGroupEntry(h.groupBase, h.roleCNPrefix, role, state.BoundDN)
		if err != nil {
			// A stored role can only be empty if the role pipeline (which
			// already rejects empty mapped roles upstream) returned one
			// anyway; skip defensively rather than emit a malformed entry.
			continue
		}
		w.Write(entry.Render(requested, typesOnly))
	}

	log.Info().
		Str("op", "search").
		Bool("success", true).
		Int("result", ldapserver.LDAPResultSuccess).
		Str("username", state.Username).
		Int("entries", len(state.Roles)).
		Msg("ldap search succeeded")

	w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))
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

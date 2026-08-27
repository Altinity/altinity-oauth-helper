package ldap

import (
	"github.com/rs/zerolog/log"

	message "github.com/vjeantet/goldap/message"
	ldapserver "github.com/vjeantet/ldapserver"
)

// unsupportedOperationDiagnostic is the fixed diagnostic every fail-closed
// unsupported operation returns. These operations carry no credential
// material and no authorization decision, so — unlike Bind/Search failures
// — there is no non-disclosure requirement driving this; it is fixed simply
// because there is nothing operation-specific and safe to say.
const unsupportedOperationDiagnostic = "operation not supported"

// logUnsupported records a fail-closed unsupported-operation response.
// Every field here is a fixed literal or a protocol constant — never
// attacker-controlled request content — so this is safe to log
// unconditionally per the plan's allowed-fields list.
func logUnsupported(op string, resultCode int) {
	log.Info().
		Str("op", op).
		Bool("success", false).
		Int("result", resultCode).
		Msg("ldap operation rejected: unsupported")
}

// handleAdd, handleModify, handleDelete and handleCompare implement the
// plan's "Unsupported LDAP operations" fail-closed table: every one of
// these request types unconditionally fails with LDAPResultUnwillingToPerform,
// via the typed response its own operation expects, and none of them read
// or mutate session state. Directory mutation and directory disclosure via
// Compare are both out of scope for this helper's MVP; see the plan's
// "Delivery boundary" section.
// Add/Modify/Delete/Compare response types (message.AddResponse etc.) are
// each defined as `type X LDAPResult` rather than embedding it, so — unlike
// BindResponse/ExtendedResponse/SearchResultDone — they expose only
// SetResultCode, not SetDiagnosticMessage; NewXResponse already sets the
// result code, so there is nothing further to set here.
func (h *connectionHandler) handleAdd(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	res := ldapserver.NewAddResponse(ldapserver.LDAPResultUnwillingToPerform)
	logUnsupported("add", ldapserver.LDAPResultUnwillingToPerform)
	w.Write(res)
}

func (h *connectionHandler) handleModify(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	res := ldapserver.NewModifyResponse(ldapserver.LDAPResultUnwillingToPerform)
	logUnsupported("modify", ldapserver.LDAPResultUnwillingToPerform)
	w.Write(res)
}

func (h *connectionHandler) handleDelete(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	res := ldapserver.NewDeleteResponse(ldapserver.LDAPResultUnwillingToPerform)
	logUnsupported("delete", ldapserver.LDAPResultUnwillingToPerform)
	w.Write(res)
}

func (h *connectionHandler) handleCompare(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	res := ldapserver.NewCompareResponse(ldapserver.LDAPResultUnwillingToPerform)
	logUnsupported("compare", ldapserver.LDAPResultUnwillingToPerform)
	w.Write(res)
}

// handleNotFound is registered as this connection's RouteMux NotFound
// handler (see server.go's GetHandler for why: the dependency's route
// matcher makes an unqualified .Extended(...) registration unreachable, so
// routing every Extended request through NotFound is what makes this a true
// catch-all for StartTLS, password modification, WhoAmI and any other
// Extended OID). It also fail-closes ModifyDNRequest: the dependency's
// RouteMux exposes no ModifyDN route method at all (route.go defines routes
// only for Bind/Search/Add/Modify/Delete/Compare/Extended/Abandon/Cancel),
// so every ModifyDNRequest falls through the same NotFound path regardless
// of whether it's ever registered — this handler is the only place that can
// ever see one.
//
// NotFound is also, as a dependency quirk, reached once more for an
// AbandonRequest the dependency's own built-in fallback has already
// signaled (see route.go's ServeLDAP): that case intentionally gets no
// response here, because Abandon has no response in the LDAP protocol and
// the cancellation signal has already been delivered by the time this
// runs — see cancel.go/message.go's Message.Done and client.go's close().
// Neither switch case below matches AbandonRequest, so it falls through to
// the same no-op silently, preserving that behavior.
//
// A second, related carve-out: the RFC 3909 Cancel Extended operation (OID
// 1.3.6.1.1.8) never reaches this handler at all. The dependency's own
// RouteMux.ServeLDAP (route.go) intercepts a Cancel request itself, before
// falling through to NotFound, and serves it entirely via its own built-in
// handleCancel (cancel.go) — so Cancel gets none of this package's
// fail-closed LDAPResultUnwillingToPerform handling, unlike every other
// Extended OID. This is intentionally accepted rather than worked around:
// handleCancel only ever looks up and abandons a message already on the
// SAME connection's own client.requestList (no cross-connection state
// access), and explicitly refuses to touch a Bind or Abandon target
// (returns LDAPResultCannotCancel) — so it cannot affect any state this
// package owns, authenticate as anyone, or disclose anything. See
// TestAdversarial_CancelExtendedOperationCannotAffectBindOrLeak
// (adversarial_test.go) for the proof against the real server, exercised
// over the wire rather than only inferred from reading cancel.go.
func (h *connectionHandler) handleNotFound(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	switch m.ProtocolOp().(type) {
	case message.ExtendedRequest:
		res := ldapserver.NewExtendedResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(unsupportedOperationDiagnostic)
		logUnsupported("extended", ldapserver.LDAPResultUnwillingToPerform)
		w.Write(res)
	case message.ModifyDNRequest:
		// message.ModifyDNResponse is `type ModifyDNResponse LDAPResult`,
		// like AddResponse/ModifyResponse/DelResponse/CompareResponse — it
		// exposes only SetResultCode (see third_party/goldap/PATCHES.md item
		// 2, which is what makes this call possible at all), not
		// SetDiagnosticMessage, matching the same fixed-diagnostic-free
		// shape as handleAdd/handleModify/handleDelete/handleCompare below.
		res := message.ModifyDNResponse{}
		res.SetResultCode(ldapserver.LDAPResultUnwillingToPerform)
		logUnsupported("modifyDN", ldapserver.LDAPResultUnwillingToPerform)
		w.Write(res)
	}
}

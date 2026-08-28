package ldap

import (
	"github.com/rs/zerolog/log"

	message "github.com/vjeantet/goldap/message"
	ldapserver "github.com/vjeantet/ldapserver"
)

// criticalControlDiagnostic is the one fixed diagnostic text every
// critical-control rejection returns, on the response types that support a
// diagnostic message at all (see the per-response-type comment in
// unsupported.go: Add/Modify/Delete/Compare/ModifyDN responses expose only
// SetResultCode). It is intentionally generic: an attacker-controlled
// control OID or value must never appear in a client-visible diagnostic or
// in a log line (see hasCriticalControl/logCriticalControlRejected below).
const criticalControlDiagnostic = "critical control unavailable"

// hasCriticalControl reports whether m carries at least one LDAP control
// with criticality=true. It never inspects or returns the control's OID or
// value — only the boolean criticality flag — per the plan's "never include
// attacker-controlled OID/value content in logs or diagnostics" requirement.
//
// message.LDAPMessage.Controls() (embedded in *ldapserver.Message) returns
// nil when the wire message carried no [0] Controls element at all — see
// third_party/goldap/message/message.go's readComponents, which only ever
// assigns m.controls when that optional tag was actually present.
func hasCriticalControl(m *ldapserver.Message) bool {
	controls := m.Controls()
	if controls == nil {
		return false
	}
	for _, c := range *controls {
		if bool(c.Criticality()) {
			return true
		}
	}
	return false
}

// logCriticalControlRejected records a fail-closed critical-control
// rejection. op and resultCode are always fixed literals/protocol constants
// from the switch below — never attacker-controlled request content — so
// this is safe to log unconditionally, matching unsupported.go's
// logUnsupported.
func logCriticalControlRejected(op string) {
	log.Info().
		Str("op", op).
		Bool("success", false).
		Int("result", ldapserver.LDAPResultUnavailableCriticalExtension).
		Msg("ldap operation rejected: unsupported critical control")
}

// criticalControlGuard implements ldapserver.Handler and wraps the existing
// per-connection RouteMux (next), per "Production file boundary" in the
// phase-5 plan:
//
//	connectionHandler
//	    -> criticalControlGuard
//	        -> existing RouteMux
//
// server.go's GetHandler constructs and returns this in place of the bare
// RouteMux it used to return directly, so this guard's ServeLDAP runs for
// every request on the connection BEFORE RouteMux ever sees it — including
// Abandon and the Cancel Extended operation, which RouteMux would otherwise
// dispatch to its own built-in fallback (see third_party/ldapserver/
// route.go's ServeLDAP, lines ~161-171) before this package's NotFound
// handler ever runs. Intercepting here, outside RouteMux entirely, is what
// lets a critical Abandon/Cancel be rejected without ever abandoning or
// cancelling its target.
//
// RFC 4511 §4.1.11 requires an unsupported critical control to prevent the
// requested operation from being performed at all, while an unsupported
// control with criticality omitted or explicitly false must be ignored. The
// server implements no controls of its own, so the only two the guard can
// ever face here are: no controls at all, or one or more controls it does
// not implement. This guard's job is deciding delegate-vs-reject on that
// single distinction (any control with criticality=true present at all —
// see hasCriticalControl above); it never inspects a control's OID or value
// (there being nothing this server implements to distinguish them by), and
// it never mutates session state except for the one explicit clear the
// critical-Bind case below performs.
type criticalControlGuard struct {
	// session is the same per-connection session connectionHandler owns and
	// passes to its own Bind/Search handlers. The guard needs it for
	// exactly one purpose: a critical Bind must still clear any previously
	// authenticated state before responding, so a critical re-Bind cannot
	// leave a stale principal's session reachable by a later Search on the
	// same connection (see the "Critical Bind lifecycle" plan section and
	// TestControls_SuccessfulBindThenCriticalReBindLeavesSearchUnauthenticated).
	session *session
	// next is the existing per-connection RouteMux, unchanged. Every
	// request this guard delegates (no controls, or only non-critical
	// ones) reaches it exactly as before this guard existed.
	next ldapserver.Handler
}

// ServeLDAP implements ldapserver.Handler.
func (g *criticalControlGuard) ServeLDAP(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	if !hasCriticalControl(m) {
		// No controls, or only unknown controls with criticality omitted
		// or explicitly false: this server has nothing to enforce, so the
		// request proceeds exactly as it did before this guard existed.
		g.next.ServeLDAP(w, m)
		return
	}

	switch m.ProtocolOp().(type) {
	case message.BindRequest:
		// "Critical Bind lifecycle": a critical Bind remains a
		// reauthentication attempt. Lock, clear, unlock — in that order,
		// before any response — then respond 12 without ever calling the
		// verifier or role resolver. Never both lock this and touch
		// verifier/roles: doing so would make a critical Bind able to leak
		// timing or side effects from real credential verification.
		g.session.Lock()
		g.session.clear()
		g.session.Unlock()

		res := ldapserver.NewBindResponse(ldapserver.LDAPResultUnavailableCriticalExtension)
		res.SetDiagnosticMessage(criticalControlDiagnostic)
		logCriticalControlRejected("bind")
		w.Write(res)

	case message.SearchRequest:
		// A critical Search must NOT clear a valid session — unlike a
		// critical Bind, it is not a reauthentication attempt, and the
		// connection's already-authenticated state (if any) must survive
		// it untouched for a later ordinary Search to observe.
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnavailableCriticalExtension)
		res.SetDiagnosticMessage(criticalControlDiagnostic)
		logCriticalControlRejected("search")
		w.Write(res)

	case message.AddRequest:
		res := ldapserver.NewAddResponse(ldapserver.LDAPResultUnavailableCriticalExtension)
		logCriticalControlRejected("add")
		w.Write(res)

	case message.ModifyRequest:
		res := ldapserver.NewModifyResponse(ldapserver.LDAPResultUnavailableCriticalExtension)
		logCriticalControlRejected("modify")
		w.Write(res)

	case message.DelRequest:
		res := ldapserver.NewDeleteResponse(ldapserver.LDAPResultUnavailableCriticalExtension)
		logCriticalControlRejected("delete")
		w.Write(res)

	case message.CompareRequest:
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultUnavailableCriticalExtension)
		logCriticalControlRejected("compare")
		w.Write(res)

	case message.ModifyDNRequest:
		// message.ModifyDNResponse is `type ModifyDNResponse LDAPResult`
		// (see unsupported.go's handleNotFound and
		// third_party/goldap/PATCHES.md item 2): it exposes only
		// SetResultCode, not SetDiagnosticMessage.
		res := message.ModifyDNResponse{}
		res.SetResultCode(ldapserver.LDAPResultUnavailableCriticalExtension)
		logCriticalControlRejected("modifyDN")
		w.Write(res)

	case message.ExtendedRequest:
		// This covers both the RFC 3909 Cancel Extended operation (OID
		// 1.3.6.1.1.8) and every other Extended request alike: both
		// converge on the same typed ExtendedResponse(12), and — because
		// this guard runs before RouteMux ever sees the request — a
		// critical Cancel never reaches RouteMux's own built-in Cancel
		// dispatch (third_party/ldapserver/route.go), so its target is
		// never actually cancelled.
		res := ldapserver.NewExtendedResponse(ldapserver.LDAPResultUnavailableCriticalExtension)
		res.SetDiagnosticMessage(criticalControlDiagnostic)
		logCriticalControlRejected("extended")
		w.Write(res)

	case message.AbandonRequest:
		// Abandon has no response in the LDAP protocol. Intercepting it
		// here, before RouteMux's own built-in Abandon fallback
		// (route.go), means the target request is never actually
		// abandoned — the guard simply drops the request after logging.
		logCriticalControlRejected("abandon")

	default:
		// No other request type reaches a connection's Handler: Unbind is
		// handled by client.go before any handler ever runs (see
		// server.go's GetHandler doc), and every remaining ProtocolOp
		// variant is a response type this server never receives from a
		// client. Delegating here is a defensive fallback only, never
		// expected to execute in practice.
		g.next.ServeLDAP(w, m)
	}
}

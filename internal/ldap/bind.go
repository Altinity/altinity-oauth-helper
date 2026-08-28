package ldap

import (
	"github.com/rs/zerolog/log"

	ldapserver "github.com/vjeantet/ldapserver"
)

// invalidCredentialsDiagnostic is the one fixed diagnostic text every
// simple-Bind authentication/role failure returns, regardless of cause. See
// "Bind failure non-disclosure" in the phase-2 plan: malformed/unexpected
// Bind DN, missing password, malformed token, signature failure, JWKS
// validation failure, issuer/audience mismatch, expiry failure, username
// mismatch, email/domain policy failure, denied username, malformed
// configured groups claim and role-pipeline error must all be
// indistinguishable to the client.
const invalidCredentialsDiagnostic = "invalid credentials"

// handleBind is the simple-Bind route handler shared by every Bind attempt
// on this connection, whatever its authentication choice. It implements
// the "Bind authentication state machine" and "Per-connection operation
// ordering" sections of the phase-2 plan.
func (h *connectionHandler) handleBind(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	requestCtx, cancel := requestContext(h.rootCtx, m)
	defer cancel()

	h.session.Lock()
	defer h.session.Unlock()

	// clear() is required to be the first state mutation of every Bind
	// attempt, before any validation or verification runs, so that a
	// concurrent Search which obtains the lock after this Bind began can
	// never observe the previous principal's state (see the plan's
	// "Required re-Bind transition" diagram).
	h.session.clear()

	if requestCtx.Err() != nil {
		// The request was abandoned or the process/connection is
		// shutting down before we did anything credential-bearing. State
		// is already cleared; there is nothing safe or useful to respond
		// with, so stop here.
		return
	}

	req := m.GetBindRequest()

	if req.AuthenticationChoice() != "simple" {
		// SASL/unsupported choice: state stays cleared (already done
		// above), and this converges on a distinct, typed protocol
		// response — never the generic invalidCredentials boundary, which
		// is reserved for simple-Bind authentication/role failures.
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultAuthMethodNotSupported)
		res.SetDiagnosticMessage("only simple authentication is supported")
		log.Info().Str("op", "bind").Bool("success", false).Int("result", ldapserver.LDAPResultAuthMethodNotSupported).Msg("ldap bind rejected: unsupported authentication choice")
		w.Write(res)
		return
	}

	bindDN := string(req.Name())
	password := string(req.AuthenticationSimple())

	if bindDN == "" || password == "" {
		h.failBind(w, "empty bind DN or password")
		return
	}

	username, err := h.userBase.ExtractUsername(bindDN)
	if err != nil {
		// bindDN is attacker-controlled and still unauthenticated: never
		// log it, even redacted — the plan's "Safe Bind-DN parsing"
		// section says to prefer not logging it at all.
		h.failBind(w, "bind DN rejected")
		return
	}

	// verifier.Verify is called exactly once per Bind attempt. Its error
	// already covers every cryptographic/identity-policy failure reason
	// (signature, issuer, audience, expiry, username-claim mismatch, email
	// policy, denied username, transient JWKS failure, ...); none of that
	// detail crosses the boundary below.
	result, err := h.verifier.Verify(requestCtx, username, password)
	if err != nil {
		h.failBind(w, "verification failed")
		return
	}

	// roles.Roles is called exactly once per successful verification, and
	// only once: Search later reads only the snapshot this call produces,
	// it never calls Roles (or Verify) itself. A malformed configured
	// groups claim or any other role-pipeline error is, by design,
	// exactly as client-visible as any other Bind failure.
	mappedRoles, err := h.roles.Roles(&result.Claims)
	if err != nil {
		h.failBind(w, "role derivation failed")
		return
	}

	issuer, subject, _ := result.Principal.StableSubject()
	h.session.replace(authenticatedState{
		Username:  result.Principal.Username,
		Issuer:    issuer,
		Subject:   subject,
		BoundDN:   bindDN,
		ExpiresAt: result.Claims.ExpiresAt,
		Roles:     mappedRoles,
	})

	log.Info().
		Str("op", "bind").
		Bool("success", true).
		Int("result", ldapserver.LDAPResultSuccess).
		Str("username", result.Principal.Username).
		Str("correlation_id", correlationID(issuer, subject)).
		Int("roles", len(mappedRoles)).
		Msg("ldap bind succeeded")

	w.Write(ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess))
}

// failBind writes the one fixed invalidCredentials response (code 49,
// empty matched DN, the fixed diagnostic) and logs only generic,
// non-disclosing information: the reason string here is a short internal
// classification for our own logs, never sent to the client and never
// derived from attacker-controlled input (it is always one of a small set
// of fixed literals passed by handleBind above).
func (h *connectionHandler) failBind(w ldapserver.ResponseWriter, reason string) {
	res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
	res.SeMatchedDN("")
	res.SetDiagnosticMessage(invalidCredentialsDiagnostic)

	log.Info().
		Str("op", "bind").
		Bool("success", false).
		Int("result", ldapserver.LDAPResultInvalidCredentials).
		Str("reason", reason).
		Msg("ldap bind failed")

	w.Write(res)
}

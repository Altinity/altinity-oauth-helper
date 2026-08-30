package profile

import (
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// This file implements the plan's "Bind" section: the BindRequest
// decoder, the fixed state/result policy, the LDAPv3-only version
// narrowing, Amendment 2's [3]->7 / any-other-tag->close authentication
// narrowing, and the successful-Bind flow. It is this package's one,
// exclusive call site for both Verifier.Verify and RoleResolver.Roles —
// Search never authenticates or re-verifies.
//
// # Recognized wire shape
//
//	BindRequest [APPLICATION 0] {
//	    version        INTEGER,
//	    name           OCTET STRING,
//	    authentication [0] OCTET STRING     -- simple, recognized
//	                   [3] SaslCredentials  -- sasl, recognized as unsupported
//	}
//
// Amendment 2: legacy's vendored goldap decoder only ever recognizes
// context tags [0] and [3] for AuthenticationChoice and turns any other
// tag into a decode error that closes the connection — so result 7 is
// reachable only for [3], and every other tag (or any other ASN.1
// malformation anywhere in this shape) is "not a recognizable Bind":
// handleBind returns errMalformed and the caller (server.go) closes the
// connection without writing a response or touching authentication
// state.

// authChoiceSimple/authChoiceSASL are the only two authentication CHOICE
// tags this profile recognizes (RFC 4511 §4.2's AuthenticationChoice):
// context [0] primitive (an OCTET STRING password) and context [3]
// constructed (SaslCredentials, whose content this package never
// decodes — every SASL mechanism collapses to the same fixed
// authMethodNotSupported outcome, with no general SASL implementation).
var (
	authChoiceSimple = asn1.Tag(0).ContextSpecific()
	authChoiceSASL   = asn1.Tag(3).ContextSpecific().Constructed()
)

// handleBind decodes and processes one BindRequest. op is the
// already-tag/length-stripped protocolOp content (an Envelope's Content
// field when ProtocolOp == tagBindRequest); hasCritical reports whether
// the enclosing LDAPMessage carried a critical Controls element
// (frame.go's scanControls). A returned non-nil error means "close the
// connection without writing a response"; the caller must not attempt to
// write anything of its own in that case.
func (c *connection) handleBind(msgID int32, op cryptobyte.String, hasCritical bool) error {
	if hasCritical {
		// Critical-control rejection never even looks at op: the state
		// transition is UNAUTHENTICATED (prior state cleared), the
		// connection stays open, and no Bind semantics are evaluated.
		c.clearAuth()
		logCriticalControlRejected(opBind)
		return c.writeBindResponse(msgID, resultUnavailableCriticalExtension, diagCriticalControl)
	}

	var versionContent cryptobyte.String
	if !op.ReadASN1(&versionContent, asn1.INTEGER) {
		return errMalformed
	}
	version, err := minimalPositiveInt32(versionContent)
	if err != nil {
		return errMalformed
	}

	var nameBytes []byte
	if !op.ReadASN1Bytes(&nameBytes, asn1.OCTET_STRING) {
		return errMalformed
	}

	var authContent cryptobyte.String
	var authTag asn1.Tag
	if !op.ReadAnyASN1(&authContent, &authTag) {
		return errMalformed
	}

	if !op.Empty() {
		// Trailing bytes after the authentication CHOICE: not a
		// recognizable Bind, whatever the CHOICE tag itself was.
		return errMalformed
	}

	switch authTag {
	case authChoiceSASL:
		// Amendment 2's parity case: legacy reaches result 7 only for
		// [3]. No credential/mechanism content is ever inspected.
		c.clearAuth()
		logBindUnsupportedAuthChoice()
		return c.writeBindResponse(msgID, resultAuthMethodNotSupported, diagSimpleOnly)
	case authChoiceSimple:
		// Recognized; semantic validation continues below.
	default:
		// Amendment 2: every tag beyond [0]/[3] is not recognizable —
		// legacy's vendored decoder itself turns it into a decode
		// error that closes the connection, so this profile does the
		// same rather than inventing a result for a choice legacy
		// never actually reaches.
		return errMalformed
	}

	bindDN := string(nameBytes)
	password := string(authContent)

	// Every recognizable Bind clears prior authentication BEFORE any
	// semantic validation runs — including the version check just
	// below — so a rejected re-Bind can never leave the previous
	// principal's state in place (see session.go's authentication-state
	// diagram: version!=3/empty-credential/malformed-DN/verifier/
	// role-resolver failure all transition to UNAUTHENTICATED).
	c.clearAuth()

	if version != 3 {
		logBindUnsupportedProtocolVersion()
		return c.writeBindResponse(msgID, resultProtocolError, diagLDAPv3Required)
	}

	if bindDN == "" || password == "" {
		logBindFailed(reasonEmptyBindDNOrPassword)
		return c.writeBindResponse(msgID, resultInvalidCredentials, diagInvalidCredentials)
	}

	username, err := ParseBindDN(bindDN, c.cfg.userBase, c.cfg.rdnAttribute)
	if err != nil {
		// bindDN is attacker-controlled and still unauthenticated:
		// never logged, even redacted.
		logBindFailed(reasonBindDNRejected)
		return c.writeBindResponse(msgID, resultInvalidCredentials, diagInvalidCredentials)
	}

	// The one call site for Verifier.Verify in this package (mechanically
	// enforced elsewhere by an AST-based architecture contract): its
	// error already covers every cryptographic/identity-policy failure
	// reason, none of which crosses the invalidCredentials boundary
	// below.
	result, err := c.verifier.Verify(c.ctx, username, password)
	if err != nil {
		logBindFailed(reasonVerificationFailed)
		return c.writeBindResponse(msgID, resultInvalidCredentials, diagInvalidCredentials)
	}

	// The one call site for RoleResolver.Roles in this package, reached
	// only after a successful Verify. Search later reads only the
	// snapshot this call produces; it never calls Roles (or Verify)
	// itself.
	mappedRoles, err := c.roles.Roles(&result.Claims)
	if err != nil {
		logBindFailed(reasonRoleDerivationFailed)
		return c.writeBindResponse(msgID, resultInvalidCredentials, diagInvalidCredentials)
	}

	// bindDN already parsed successfully once, inside ParseBindDN above;
	// re-parsing it here for its structural form cannot fail in
	// practice, but a failure is still treated as the one fixed Bind
	// failure outcome rather than trusted blindly.
	boundDN, err := ParseDN(bindDN)
	if err != nil {
		logBindFailed(reasonBindDNRejected)
		return c.writeBindResponse(msgID, resultInvalidCredentials, diagInvalidCredentials)
	}

	issuer, subject, _ := result.Principal.StableSubject()
	c.replaceAuth(authState{
		Username:  result.Principal.Username,
		Issuer:    issuer,
		Subject:   subject,
		BoundDN:   bindDN,
		boundDN:   boundDN,
		ExpiresAt: result.Claims.ExpiresAt,
		Roles:     mappedRoles,
	})

	logBindSucceeded(result.Principal.Username, issuer, subject, len(mappedRoles))
	return c.writeBindResponse(msgID, resultSuccess, diagEmpty)
}

// writeBindResponse encodes one BindResponse and writes it, setting the
// connection's write deadline immediately before writing ("Response
// writes set WriteDeadline(now+writeTimeout) immediately before
// writing").
func (c *connection) writeBindResponse(msgID int32, result int32, d diagnostic) error {
	resp, err := encodeBindResponse(msgID, int(result), d)
	if err != nil {
		return err
	}
	if err := c.nc.SetWriteDeadline(c.clock().Add(c.writeTimeout)); err != nil {
		return err
	}
	_, err = c.nc.Write(resp)
	return err
}

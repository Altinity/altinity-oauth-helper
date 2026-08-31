package profile

// This file owns every production log line this package emits: the
// correlation_id derivation, the closed reason/op vocabularies, and the
// unexported helpers that are the only functions allowed to call
// zerolog.Info. No helper accepts a DN, password, JWT, claims, or error
// value — only verified identity metadata and fixed constants ever reach
// a log line. See "Exact logging contract" in the phase-2 plan.

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/rs/zerolog/log"
)

// correlationID is a byte-identical reimplementation — never an import,
// per "Correlation ID ownership" — of
// internal/ldap/server.go:326-329's algorithm: sha256(issuer + "\x00" +
// subject), first 8 bytes, lowercase hex. Changing the separator,
// truncation, or encoding changes every caller's output.
func correlationID(issuer, subject string) string {
	sum := sha256.Sum256([]byte(issuer + "\x00" + subject))
	return hex.EncodeToString(sum[:8])
}

// reason is the closed, fixed-cardinality vocabulary of internal,
// non-disclosing classification strings logged alongside a Bind failure or
// Search rejection (Amendment 3); no function accepts a reason as a
// string/error/other dynamic value, only these constants, and text() is
// the one place their literal spelling lives. The first eight are
// preserved byte-identically from the legacy package
// (internal/ldap/bind.go:78,86,103,113, search.go:79,91,95,99) for the
// shared compat test; the remaining four are new profile-only classes —
// the fixed Search profile narrows deref/typesOnly/attribute-selection to
// one accepted value each, and a member DN that parses but names a
// different principal is now distinct from a malformed filter shape.
type reason uint8

const (
	reasonEmptyBindDNOrPassword reason = iota
	reasonBindDNRejected
	reasonVerificationFailed
	reasonRoleDerivationFailed
	reasonUnauthenticated
	reasonWrongBase
	reasonWrongScope
	reasonUnauthorizedFilterShape
	reasonDerefAliasesOutOfProfile
	reasonTypesOnlyOutOfProfile
	reasonAttributeSelectionOutOfProfile
	reasonMemberDNMismatch
)

// text returns reason's one fixed literal.
func (r reason) text() string {
	switch r {
	case reasonEmptyBindDNOrPassword:
		return "empty bind DN or password"
	case reasonBindDNRejected:
		return "bind DN rejected"
	case reasonVerificationFailed:
		return "verification failed"
	case reasonRoleDerivationFailed:
		return "role derivation failed"
	case reasonUnauthenticated:
		return "unauthenticated"
	case reasonWrongBase:
		return "wrong base"
	case reasonWrongScope:
		return "wrong scope"
	case reasonUnauthorizedFilterShape:
		return "unauthorized filter shape"
	case reasonDerefAliasesOutOfProfile:
		return "derefAliases out of profile"
	case reasonTypesOnlyOutOfProfile:
		return "typesOnly out of profile"
	case reasonAttributeSelectionOutOfProfile:
		return "attribute selection out of profile"
	case reasonMemberDNMismatch:
		return "member DN mismatch"
	default:
		return "unknown"
	}
}

// op is the closed set of fixed operation-name literals logged in this
// package's "op" field — never a request-derived or otherwise dynamic
// string.
type op string

const (
	opBind     op = "bind"
	opSearch   op = "search"
	opAbandon  op = "abandon"
	opUnbind   op = "unbind"
	opAdd      op = "add"
	opModify   op = "modify"
	opDelete   op = "delete"
	opCompare  op = "compare"
	opModifyDN op = "modifydn"
	opExtended op = "extended"
)

// logBindSucceeded records a successful simple Bind; issuer/subject are
// never logged raw, only correlationID's hash of them.
func logBindSucceeded(username, issuer, subject string, roleCount int) {
	log.Info().Str("op", string(opBind)).Bool("success", true).Int("result", int(resultSuccess)).
		Str("username", username).Str("correlation_id", correlationID(issuer, subject)).
		Int("roles", roleCount).Msg("ldap bind succeeded")
}

// logBindFailed records a failed simple Bind (the one fixed
// invalidCredentials response); r is always a reason constant.
func logBindFailed(r reason) {
	log.Info().Str("op", string(opBind)).Bool("success", false).Int("result", int(resultInvalidCredentials)).
		Str("reason", r.text()).Msg("ldap bind failed")
}

// logBindUnsupportedAuthChoice: Bind rejected for a non-simple
// authentication choice (Amendment 2: reachable only for SASL [3]).
func logBindUnsupportedAuthChoice() {
	log.Info().Str("op", string(opBind)).Bool("success", false).Int("result", int(resultAuthMethodNotSupported)).
		Msg("ldap bind rejected: unsupported authentication choice")
}

// logBindUnsupportedProtocolVersion: Bind rejected for a version other than 3.
func logBindUnsupportedProtocolVersion() {
	log.Info().Str("op", string(opBind)).Bool("success", false).Int("result", int(resultProtocolError)).
		Msg("ldap bind rejected: unsupported protocol version")
}

// logSearchTerminal records a Search that passed authorization: unlimited
// success, zero roles, sizeLimit/timeLimit exhaustion, or the response-PDU
// administrative limit (result 11). Exactly one of the five fixed messages
// is chosen from resultCode/entries alone, matching legacy finishSearch's
// dispatch plus the new administrative-limit case.
func logSearchTerminal(username string, sizeLimit, timeLimit int, typesOnly bool, entries int, resultCode int32) {
	msg := "ldap search succeeded"
	switch {
	case resultCode == resultSizeLimitExceeded:
		msg = "ldap search size limit exceeded"
	case resultCode == resultTimeLimitExceeded:
		msg = "ldap search time limit exceeded"
	case resultCode == resultAdminLimitExceeded:
		msg = "ldap search administrative limit exceeded"
	case entries == 0:
		msg = "ldap search succeeded (zero roles)"
	}

	log.Info().Str("op", string(opSearch)).Bool("success", resultCode == resultSuccess).
		Int("result", int(resultCode)).Str("username", username).Int("size_limit", sizeLimit).
		Int("time_limit", timeLimit).Bool("types_only", typesOnly).Int("entries", entries).Msg(msg)
}

// logSearchRejected: Search failed authorization before any entry was
// considered; r is always a reason constant.
func logSearchRejected(r reason) {
	log.Info().Str("op", string(opSearch)).Bool("success", false).
		Int("result", int(resultInsufficientAccessRights)).Str("reason", r.text()).Msg("ldap search rejected")
}

// logOperationUnsupported: fail-closed unsupported-operation response
// (Add/Modify/Delete/Compare/ModifyDN/Extended); o is always an op constant.
func logOperationUnsupported(o op) {
	log.Info().Str("op", string(o)).Bool("success", false).Int("result", int(resultUnwillingToPerform)).
		Msg("ldap operation rejected: unsupported")
}

// logCriticalControlRejected: fail-closed critical-control rejection,
// including Abandon (no response of its own, but still logged); o is
// always an op constant.
func logCriticalControlRejected(o op) {
	log.Info().Str("op", string(o)).Bool("success", false).
		Int("result", int(resultUnavailableCriticalExtension)).
		Msg("ldap operation rejected: unsupported critical control")
}

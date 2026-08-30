package profile

import (
	"errors"
	"math"
	"time"

	"golang.org/x/crypto/cryptobyte/asn1"
)

// This file collects the fixed, shared wire constants and the one small
// decode helper (minimalPositiveInt32) every other file in this package
// builds on: LDAP application tags, the one context tag frame.go needs for
// Controls, the plan's result codes, and the two resource-shape constants
// (body cap, socket deadline). Bind/Search-specific context tags
// (AuthenticationChoice, Filter operators, scope, derefAliases, ...)
// belong to their own decoders (bind.go, search.go), not here.

// LDAP application tags (RFC 4511 §4.2 protocolOp CHOICE): class
// APPLICATION (0x40) plus, for constructed shapes, the constructed bit
// (0x20), plus the low-tag-number tag itself. Unbind/Delete carry no
// content and so are primitive; every other shape here is constructed.
const (
	tagBindRequest       = asn1.Tag(0x60) // [APPLICATION  0] constructed — BindRequest
	tagBindResponse      = asn1.Tag(0x61) // [APPLICATION  1] constructed — BindResponse
	tagUnbindRequest     = asn1.Tag(0x42) // [APPLICATION  2] primitive   — UnbindRequest
	tagSearchRequest     = asn1.Tag(0x63) // [APPLICATION  3] constructed — SearchRequest
	tagSearchResultEntry = asn1.Tag(0x64) // [APPLICATION  4] constructed — SearchResultEntry
	tagSearchResultDone  = asn1.Tag(0x65) // [APPLICATION  5] constructed — SearchResultDone
	tagModifyRequest     = asn1.Tag(0x66) // [APPLICATION  6] constructed — ModifyRequest
	tagModifyResponse    = asn1.Tag(0x67) // [APPLICATION  7] constructed — ModifyResponse
	tagAddRequest        = asn1.Tag(0x68) // [APPLICATION  8] constructed — AddRequest
	tagAddResponse       = asn1.Tag(0x69) // [APPLICATION  9] constructed — AddResponse
	tagDelRequest        = asn1.Tag(0x4a) // [APPLICATION 10] primitive   — DelRequest
	tagDelResponse       = asn1.Tag(0x6b) // [APPLICATION 11] constructed — DelResponse
	tagModifyDNRequest   = asn1.Tag(0x6c) // [APPLICATION 12] constructed — ModifyDNRequest
	tagModifyDNResponse  = asn1.Tag(0x6d) // [APPLICATION 13] constructed — ModifyDNResponse
	tagCompareRequest    = asn1.Tag(0x6e) // [APPLICATION 14] constructed — CompareRequest
	tagCompareResponse   = asn1.Tag(0x6f) // [APPLICATION 15] constructed — CompareResponse
	tagAbandonRequest    = asn1.Tag(0x50) // [APPLICATION 16] primitive   — AbandonRequest
	tagExtendedRequest   = asn1.Tag(0x77) // [APPLICATION 23] constructed — ExtendedRequest
	tagExtendedResponse  = asn1.Tag(0x78) // [APPLICATION 24] constructed — ExtendedResponse
)

// tagControls is the LDAPMessage envelope's optional
// "controls [0] Controls" element: context-specific, constructed, tag
// number 0 (RFC 4511 §4.1.1) — the only context tag this package's
// framing layer needs.
var tagControls = asn1.Tag(0).ContextSpecific().Constructed() // 0xa0

// Result codes (RFC 4511 §4.1.9): exactly the ten values the plan's
// dispatch/authorization tables use, not a general enumeration.
const (
	resultSuccess                      int32 = 0
	resultProtocolError                int32 = 2
	resultTimeLimitExceeded            int32 = 3
	resultSizeLimitExceeded            int32 = 4
	resultAuthMethodNotSupported       int32 = 7
	resultAdminLimitExceeded           int32 = 11
	resultUnavailableCriticalExtension int32 = 12
	resultInvalidCredentials           int32 = 49
	resultInsufficientAccessRights     int32 = 50
	resultUnwillingToPerform           int32 = 53
)

// maxBodyBytes is the maximum accepted LDAPMessage body length: exactly
// 65536 bytes are accepted, 65537 rejected, checked before any allocation
// sized to the declared length ("Framing before allocation").
const maxBodyBytes = 65536

// defaultDeadline is the read/write socket deadline applied to every
// admitted connection.
const defaultDeadline = 30 * time.Second

// errMalformed is the sentinel every structural decode failure in this
// package returns — bad framing, a malformed envelope, or malformed
// Controls. The connection loop (server.go) treats it as "close without
// resynchronizing the stream". It carries no per-call detail because the
// byte content that produced it must never reach a log line or error
// string (internal/securitytest's redaction inventory) — a fixed sentinel
// makes that mechanical.
var errMalformed = errors.New("ldap/profile: malformed message")

// minimalPositiveInt32 validates content as the minimal two's-complement
// DER encoding (no non-minimal leading 0x00/0xff padding octet) of an
// INTEGER whose value lies in 1..math.MaxInt32, and returns that value.
// Shared by the LDAPMessage envelope's MessageID (frame.go) and, later,
// the AbandonRequest [APPLICATION 16] IMPLICIT target integer
// (coordinator amendment 6) — Abandon's target is wire-identical to a
// MessageID, just read out from under an application tag instead of the
// universal INTEGER tag, so both reuse this one rule.
func minimalPositiveInt32(content []byte) (int32, error) {
	if len(content) == 0 {
		return 0, errMalformed
	}

	if len(content) > 1 {
		// A leading 0x00 is legal only to disambiguate a following byte
		// whose own high bit is set (the value would otherwise read as
		// negative); a leading 0xff only to disambiguate a following
		// high bit that's clear. Either leading octet paired with a
		// following byte sharing its own high-bit state means the
		// encoding used one octet more than the minimal DER form
		// requires.
		if content[0] == 0x00 || content[0] == 0xff {
			if content[0]&0x80 == content[1]&0x80 {
				return 0, errMalformed
			}
		}
	}

	if content[0]&0x80 != 0 {
		// Negative: outside the 1..MaxInt32 range this validator accepts.
		return 0, errMalformed
	}

	if len(content) > 5 {
		// No positive value representable in <=5 octets can be
		// <=MaxInt32 once the non-minimal-padding check above has
		// already passed, so this is well outside range regardless of
		// its actual digits; bail before the decode loop below.
		return 0, errMalformed
	}

	var v int64
	for _, b := range content {
		v = v<<8 | int64(b)
	}
	if v <= 0 || v > math.MaxInt32 {
		return 0, errMalformed
	}
	return int32(v), nil
}

package profile

// This file implements the plan's "Search request profile", "Search
// authorization/result table", "Fixed filter decoder", "{bind_dn} filter
// pipeline", "Search execution and deadlines", and "Response memory bound"
// sections, plus Amendment 2's ENUMERATED range rule: an out-of-range
// scope/derefAliases value is malformed (close), while an in-range value
// outside this profile's one accepted choice is an authorization
// rejection (result 50). Search never invokes Verifier.Verify or
// RoleResolver.Roles — it reads only the Bind-time role snapshot
// (c.auth.Roles).
//
// # Recognized wire shape
//
//	SearchRequest [APPLICATION 3] {
//	    baseObject   OCTET STRING,
//	    scope        ENUMERATED (0..2),
//	    derefAliases ENUMERATED (0..3),
//	    sizeLimit    INTEGER (0..maxInt32),
//	    timeLimit    INTEGER (0..maxInt32),
//	    typesOnly    BOOLEAN,
//	    filter       Filter,                     -- CHOICE, decoded opaquely
//	    attributes   SEQUENCE OF OCTET STRING
//	}
//
// Only the exact shape documented in docs/clickhouse-ldap-wire-profile.md
// is authorized: subtree scope, never-deref-aliases, no typesOnly, one
// "cn" attribute, and the fixed groupOfNames/member membership filter.
// Every other value in that shape's legal ASN.1 range (not every possible
// byte sequence — those are malformed) is a deliberate Phase 3-visible
// narrowing to result 50, never a silent pass-through.

import (
	"errors"
	"net"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// Fixed profile values every Search must match exactly, and the
// ENUMERATED types' own legal-value ranges (Amendment 2): a scope/deref
// value outside these ranges is not a recognized ENUMERATED value for
// this wire type at all, and is treated as malformed rather than merely
// out of profile.
const (
	scopeWholeSubtree = 2
	maxScopeValue     = 2
	derefNever        = 0
	maxDerefValue     = 3
)

// filterTagAnd/filterTagEquality are the two Filter CHOICE (RFC 4511
// §4.5.1) tags this profile's fixed membership filter ever recognizes:
// context [0] constructed (SET OF Filter, the "and" choice) and context
// [3] constructed (AttributeValueAssertion, "equalityMatch"). Every other
// Filter CHOICE tag — or/not/substrings/present/greaterOrEqual/
// lessOrEqual/approxMatch/extensibleMatch, or a nested "and" — is
// rejected by decodeMembershipFilter below as an unauthorized filter
// shape; no other tag is specially recognized here.
var (
	filterTagAnd      = asn1.Tag(0).ContextSpecific().Constructed()
	filterTagEquality = asn1.Tag(3).ContextSpecific().Constructed()
)

// membershipObjectClassValue is the one byte-exact objectClass value the
// fixed membership filter's objectClass predicate must carry — compared
// byte-for-byte, never case-insensitively (only the attribute
// description is case-insensitive; see "Case rules" in the plan).
const membershipObjectClassValue = "groupOfNames"

// filterOutcome is decodeMembershipFilter's closed result: whether the
// filter is exactly the fixed two-predicate membership shape, has some
// other shape problem (wrong Filter CHOICE, wrong predicate count,
// duplicate/missing predicate, wrong description, wrong objectClass
// value), or has the right shape but a member assertion that does not
// name the current connection's authenticated principal.
type filterOutcome uint8

const (
	filterOK filterOutcome = iota
	filterShapeInvalid
	filterMemberMismatch
)

// handleSearch decodes and processes one SearchRequest. op is the
// already-tag/length-stripped protocolOp content; hasCritical reports
// whether the enclosing LDAPMessage carried a critical Controls element.
// A returned non-nil error means "close the connection without writing a
// response"; every other outcome writes exactly one SearchResultDone (and
// zero or more SearchResultEntry PDUs before it) and returns nil, or
// returns whatever error a failed write produced (the caller then
// closes).
func (c *connection) handleSearch(msgID int32, op cryptobyte.String, hasCritical bool) error {
	// searchStart anchors timeLimit's deadline: recorded before any
	// SearchRequest field is decoded, per "searchStart" in the plan.
	searchStart := c.clock()

	if hasCritical {
		// Critical-control rejection never decodes op at all: prior
		// auth state is preserved (unlike Bind's clear-on-critical),
		// and no Search semantics are evaluated.
		logCriticalControlRejected(opSearch)
		return c.writeSearchResultDone(msgID, resultUnavailableCriticalExtension, diagCriticalControl)
	}

	var baseBytes []byte
	if !op.ReadASN1Bytes(&baseBytes, asn1.OCTET_STRING) {
		return errMalformed
	}

	var scopeVal int
	if !op.ReadASN1Enum(&scopeVal) {
		return errMalformed
	}
	if scopeVal < 0 || scopeVal > maxScopeValue {
		// Amendment 2: outside the ENUMERATED type's own legal value
		// range — not a recognizable scope value at all.
		return errMalformed
	}

	var derefVal int
	if !op.ReadASN1Enum(&derefVal) {
		return errMalformed
	}
	if derefVal < 0 || derefVal > maxDerefValue {
		return errMalformed
	}

	var sizeLimit int32
	if !op.ReadASN1Integer(&sizeLimit) {
		return errMalformed
	}
	if sizeLimit < 0 {
		return errMalformed
	}

	var timeLimit int32
	if !op.ReadASN1Integer(&timeLimit) {
		return errMalformed
	}
	if timeLimit < 0 {
		return errMalformed
	}

	var typesOnly bool
	if !op.ReadASN1Boolean(&typesOnly) {
		return errMalformed
	}

	var filterTag asn1.Tag
	var filterContent cryptobyte.String
	if !op.ReadAnyASN1(&filterContent, &filterTag) {
		return errMalformed
	}

	var attrsSeq cryptobyte.String
	if !op.ReadASN1(&attrsSeq, asn1.SEQUENCE) {
		return errMalformed
	}
	// Streamed, not materialized: only the count (capped at 2 — "more
	// than one" needs no exact tally) and the first entry's bytes are
	// ever retained. A second well-formed attribute already settles the
	// exactly-one-cn authorization outcome below, so decoding stops
	// there rather than walking every remaining attacker-controlled
	// entry — a near-cap 64 KiB request otherwise builds tens of
	// thousands of single-byte string headers before authentication or
	// the exactly-one-cn rule ever runs (issue #33 §2.1's "avoid
	// proportional duplicate copies of attacker-controlled message
	// bodies").
	var attrCount int
	var firstAttribute string
	for attrCount < 2 && !attrsSeq.Empty() {
		var a []byte
		if !attrsSeq.ReadASN1Bytes(&a, asn1.OCTET_STRING) {
			return errMalformed
		}
		attrCount++
		if attrCount == 1 {
			firstAttribute = string(a)
		}
	}

	if !op.Empty() {
		// Trailing bytes after attributes: not a recognizable
		// SearchRequest.
		return errMalformed
	}

	// --- Authorization, in the plan's exact table order --------------

	if !c.authenticated {
		logSearchRejected(reasonUnauthenticated)
		return c.writeSearchResultDone(msgID, resultInsufficientAccessRights, diagInsufficientAccess)
	}

	base, err := ParseDN(string(baseBytes))
	if err != nil || !base.Equal(c.cfg.groupBase) {
		logSearchRejected(reasonWrongBase)
		return c.writeSearchResultDone(msgID, resultInsufficientAccessRights, diagInsufficientAccess)
	}

	if scopeVal != scopeWholeSubtree {
		logSearchRejected(reasonWrongScope)
		return c.writeSearchResultDone(msgID, resultInsufficientAccessRights, diagInsufficientAccess)
	}

	if derefVal != derefNever {
		logSearchRejected(reasonDerefAliasesOutOfProfile)
		return c.writeSearchResultDone(msgID, resultInsufficientAccessRights, diagInsufficientAccess)
	}

	if typesOnly {
		logSearchRejected(reasonTypesOnlyOutOfProfile)
		return c.writeSearchResultDone(msgID, resultInsufficientAccessRights, diagInsufficientAccess)
	}

	if attrCount != 1 || !asciiEqualFold(firstAttribute, cnAttributeType) {
		// Covers empty selection, "*", sole "1.1", multiple
		// attributes, and any single attribute other than "cn" —
		// every out-of-profile shape lands on this one reason.
		logSearchRejected(reasonAttributeSelectionOutOfProfile)
		return c.writeSearchResultDone(msgID, resultInsufficientAccessRights, diagInsufficientAccess)
	}

	switch decodeMembershipFilter(filterTag, filterContent, c.auth.boundDN) {
	case filterShapeInvalid:
		logSearchRejected(reasonUnauthorizedFilterShape)
		return c.writeSearchResultDone(msgID, resultInsufficientAccessRights, diagInsufficientAccess)
	case filterMemberMismatch:
		logSearchRejected(reasonMemberDNMismatch)
		return c.writeSearchResultDone(msgID, resultInsufficientAccessRights, diagInsufficientAccess)
	}

	return c.executeSearch(msgID, searchStart, sizeLimit, timeLimit)
}

// decodeEquality decodes one Filter CHOICE child as an equalityMatch
// AttributeValueAssertion (attributeDesc OCTET STRING, assertionValue
// OCTET STRING, nothing else) if tag is the equalityMatch CHOICE tag.
// This is the base case of the filter decoder's nonrecursive two-child
// walk: it never reads another Filter CHOICE, only the two fixed OCTET
// STRING fields RFC 4511's AttributeValueAssertion defines.
func decodeEquality(tag asn1.Tag, content cryptobyte.String) (desc string, value []byte, ok bool) {
	if tag != filterTagEquality {
		return "", nil, false
	}
	var descBytes []byte
	if !content.ReadASN1Bytes(&descBytes, asn1.OCTET_STRING) {
		return "", nil, false
	}
	var valueBytes []byte
	if !content.ReadASN1Bytes(&valueBytes, asn1.OCTET_STRING) {
		return "", nil, false
	}
	if !content.Empty() {
		return "", nil, false
	}
	return string(descBytes), valueBytes, true
}

// decodeMembershipFilter decodes exactly the fixed two-predicate filter
// AND(equalityMatch(objectClass, groupOfNames), equalityMatch(member,
// <current BoundDN>)) in either child order. Deliberately nonrecursive —
// exactly two decodeEquality calls, no general filter AST/evaluator, no
// recursion into another AND/OR/NOT: filterTag must be the "and" CHOICE,
// its two children (no third) must each be equalityMatch, and
// decodeEquality itself never reads another Filter CHOICE. Any OR, NOT,
// substrings, present, greaterOrEqual, lessOrEqual, approxMatch,
// extensibleMatch, nested AND, duplicate/missing/third predicate, wrong
// description, or wrong objectClass value is filterShapeInvalid. A member
// assertion that fails to parse, or parses but is not structurally equal
// (DN.Equal) to boundDN, is filterMemberMismatch — a distinct,
// profile-only reason from a wrong filter shape.
func decodeMembershipFilter(filterTag asn1.Tag, filterContent cryptobyte.String, boundDN DN) filterOutcome {
	if filterTag != filterTagAnd {
		return filterShapeInvalid
	}

	var child1Content, child2Content cryptobyte.String
	var child1Tag, child2Tag asn1.Tag
	if !filterContent.ReadAnyASN1(&child1Content, &child1Tag) {
		return filterShapeInvalid
	}
	if !filterContent.ReadAnyASN1(&child2Content, &child2Tag) {
		return filterShapeInvalid
	}
	if !filterContent.Empty() {
		// A third (or later) predicate is present.
		return filterShapeInvalid
	}

	desc1, val1, ok1 := decodeEquality(child1Tag, child1Content)
	desc2, val2, ok2 := decodeEquality(child2Tag, child2Content)
	if !ok1 || !ok2 {
		return filterShapeInvalid
	}

	isObjClass1, isMember1 := asciiEqualFold(desc1, "objectClass"), asciiEqualFold(desc1, "member")
	isObjClass2, isMember2 := asciiEqualFold(desc2, "objectClass"), asciiEqualFold(desc2, "member")

	var objectClassVal, memberVal []byte
	switch {
	case isObjClass1 && isMember2 && !isObjClass2 && !isMember1:
		objectClassVal, memberVal = val1, val2
	case isObjClass2 && isMember1 && !isObjClass1 && !isMember2:
		objectClassVal, memberVal = val2, val1
	default:
		// Duplicate objectClass/member, a missing predicate, or a
		// description matching neither expected attribute.
		return filterShapeInvalid
	}

	if string(objectClassVal) != membershipObjectClassValue {
		return filterShapeInvalid
	}

	memberDN, err := ParseDN(string(memberVal))
	if err != nil || !memberDN.Equal(boundDN) {
		return filterMemberMismatch
	}

	return filterOK
}

// executeSearch runs the authorized Search's entry loop and writes the
// terminal SearchResultDone. It reads only c.auth.Roles (the Bind-time
// snapshot) — never Verifier.Verify or RoleResolver.Roles, and never
// re-evaluates c.auth.ExpiresAt.
func (c *connection) executeSearch(msgID int32, searchStart time.Time, sizeLimit, timeLimit int32) error {
	username := c.auth.Username
	roles := c.auth.Roles

	var searchDeadline time.Time
	if timeLimit > 0 {
		searchDeadline = searchStart.Add(time.Duration(timeLimit) * time.Second)
	}
	expired := func() bool {
		return !searchDeadline.IsZero() && !c.clock().Before(searchDeadline)
	}

	emitted := 0
	resultCode := int32(resultSuccess)

emitLoop:
	for _, role := range roles {
		// timeLimit check point: before considering the next entry,
		// unconditionally — matching legacy (internal/ldap/search.go),
		// including on an iteration that will itself be skipped below.
		// Checking sizeLimit first would let an empty-role skip or a
		// RenderGroupDN failure silently step past an already-expired
		// deadline, reporting sizeLimitExceeded (4) where legacy
		// reports timeLimitExceeded (3) for the identical input.
		if expired() {
			resultCode = resultTimeLimitExceeded
			break emitLoop
		}

		if role == "" {
			// Empty roles are skipped entirely: not an eligible
			// entry, so they consume no sizeLimit budget and are
			// never subject to the per-entry checks below.
			continue
		}

		objectName, ok := RenderGroupDN(c.cfg.groupBaseText, c.cfg.rolePrefix, role)
		if !ok {
			// Unreachable given the role=="" filter above; kept as
			// the same defensive skip RenderGroupDN's own contract
			// documents, matching current production's behavior for
			// a role that cannot be safely rendered.
			continue
		}

		if sizeLimit > 0 && emitted >= int(sizeLimit) {
			// This is the (N+1)th eligible entry: emit exactly N,
			// then report sizeLimitExceeded, without attempting
			// this entry's preflight/write steps.
			resultCode = resultSizeLimitExceeded
			break emitLoop
		}

		cnValue := c.cfg.rolePrefix + role

		if _, fits := entryPDUSize(objectName, cnValue); !fits {
			logSearchTerminal(username, int(sizeLimit), int(timeLimit), false, emitted, resultAdminLimitExceeded)
			return c.writeSearchResultDone(msgID, resultAdminLimitExceeded, diagEmpty)
		}

		entryBytes, err := encodeSearchResultEntry(msgID, objectName, cnValue)
		if err != nil {
			// entryPDUSize already guaranteed this fits; a failure
			// here is an encoder defect, not a client-facing
			// outcome, so it closes rather than silently dropping
			// or double-responding.
			return err
		}

		deadline := c.clock().Add(c.writeTimeout)
		searchDeadlineBinding := false
		if !searchDeadline.IsZero() && searchDeadline.Before(deadline) {
			deadline = searchDeadline
			searchDeadlineBinding = true
		}
		if err := c.nc.SetWriteDeadline(deadline); err != nil {
			return err
		}

		n, werr := c.nc.Write(entryBytes)
		if werr != nil {
			if searchDeadlineBinding && n == 0 && isTimeoutErr(werr) {
				// The entry write itself reached its Search
				// deadline (the operative, binding one — see
				// searchDeadlineBinding above) with zero bytes
				// on the wire: no partial PDU exists, so report
				// timeLimitExceeded under a fresh ordinary
				// deadline rather than closing. A zero-byte
				// timeout under the ordinary write deadline
				// (searchDeadlineBinding false — either
				// timeLimit==0 or the ordinary deadline was
				// earlier) is a plain transport write stall,
				// not a time-limit event, and falls through to
				// the close below.
				logSearchTerminal(username, int(sizeLimit), int(timeLimit), false, emitted, resultTimeLimitExceeded)
				return c.writeSearchResultDone(msgID, resultTimeLimitExceeded, diagEmpty)
			}
			// Any bytes already written, any other transport
			// error, or a zero-byte timeout under the ordinary
			// (non-Search) write deadline: never append a further
			// PDU after a partial one, and never misreport a
			// plain write stall as a time-limit event — the
			// caller (server.go) closes on any non-nil error from
			// this function.
			return werr
		}

		emitted++
	}

	if resultCode == resultSuccess && expired() {
		// The role snapshot was exhausted without tripping sizeLimit,
		// but the Search deadline has since passed.
		resultCode = resultTimeLimitExceeded
	}

	logSearchTerminal(username, int(sizeLimit), int(timeLimit), false, emitted, resultCode)
	return c.writeSearchResultDone(msgID, resultCode, diagEmpty)
}

// isTimeoutErr reports whether err is a net.Error with Timeout() true —
// the shape SetWriteDeadline-triggered write failures take.
func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// writeSearchResultDone encodes one SearchResultDone and writes it,
// setting the connection's write deadline to now+writeTimeout immediately
// before writing — every terminal SearchResultDone uses this same fresh
// ordinary deadline, never an already-expired Search deadline, per
// "Terminal SearchResultDone" in the plan.
func (c *connection) writeSearchResultDone(msgID int32, result int32, d diagnostic) error {
	resp, err := encodeSearchResultDone(msgID, int(result), d)
	if err != nil {
		return err
	}
	if err := c.nc.SetWriteDeadline(c.clock().Add(c.writeTimeout)); err != nil {
		return err
	}
	_, err = c.nc.Write(resp)
	return err
}

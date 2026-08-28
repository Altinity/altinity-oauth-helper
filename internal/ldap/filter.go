package ldap

import (
	"strings"

	ldapdn "github.com/go-ldap/ldap/v3"
	message "github.com/vjeantet/goldap/message"
)

// groupObjectClassValue is the fixed, safely-compared objectClass value of
// every synthetic group entry this helper exposes.
const groupObjectClassValue = "groupOfNames"

// AuthorizeGroupMembershipFilter inspects the already-decoded goldap filter
// AST and reports whether it is exactly the one documented ClickHouse
// membership query this helper answers: an AND of exactly two equality
// predicates, in either order —
//
//	objectClass = groupOfNames
//	member      = <boundDN>
//
// where <boundDN> parses to a DN structurally equal to the current
// connection's authenticated bound DN (boundDN). This is the sole
// authorization primitive for Search: it inspects filter structure, never
// filter text, and treats every unrecognized node — OR, NOT, substring,
// present, greater/less-or-equal, approximate, extensible, a missing,
// duplicate, or additional predicate, a wrong objectClass value, a
// malformed member DN, or a member DN naming a different principal — as
// unauthorized. It never constructs a filter from attacker-controlled
// values to decide authorization.
func AuthorizeGroupMembershipFilter(f message.Filter, boundDN string) bool {
	and, ok := f.(message.FilterAnd)
	if !ok {
		return false
	}

	expectedMember, err := ldapdn.ParseDN(boundDN)
	if err != nil {
		return false
	}

	var sawObjectClass, sawMember bool
	for _, child := range and {
		eq, ok := child.(message.FilterEqualityMatch)
		if !ok {
			return false
		}

		attr := string(eq.AttributeDesc())
		val := string(eq.AssertionValue())

		switch {
		case strings.EqualFold(attr, "objectClass"):
			if sawObjectClass {
				return false // duplicate predicate
			}
			if val != groupObjectClassValue {
				return false // wrong objectClass
			}
			sawObjectClass = true

		case strings.EqualFold(attr, "member"):
			if sawMember {
				return false // duplicate predicate
			}
			memberDN, err := ldapdn.ParseDN(val)
			if err != nil {
				return false // malformed member DN
			}
			if !memberDN.Equal(expectedMember) {
				return false // member DN names a different principal
			}
			sawMember = true

		default:
			return false // additional/unrecognized predicate
		}
	}

	// Both predicates are required; a single-predicate AND (missing the
	// other) falls through here with one flag still false.
	return sawObjectClass && sawMember
}

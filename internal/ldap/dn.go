package ldap

import (
	"errors"
	"fmt"
	"strings"

	ldapdn "github.com/go-ldap/ldap/v3"
)

// UserBaseDN is the once-parsed, immutable configured LDAP user base DN
// (ldap.user_base_dn) together with the RDN attribute type that must lead
// every valid Bind DN under it (ldap.user_rdn_attribute). See "Safe Bind-DN
// parsing" in the phase-2 plan: the base is parsed exactly once, at
// construction time, and every Bind DN afterward is validated structurally
// against this immutable parsed form — never via strings.Split or suffix
// stripping.
type UserBaseDN struct {
	dn           *ldapdn.DN
	rdnAttribute string
}

// NewUserBaseDN parses raw via RFC 4514 ParseDN once and fails on an invalid
// configured base DN or empty rdnAttribute, so construction-time validation
// (not a later Bind) is where a broken configuration is caught.
func NewUserBaseDN(raw, rdnAttribute string) (*UserBaseDN, error) {
	if strings.TrimSpace(rdnAttribute) == "" {
		return nil, errors.New("ldap: user_rdn_attribute must not be empty")
	}
	dn, err := ldapdn.ParseDN(raw)
	if err != nil {
		return nil, fmt.Errorf("ldap: invalid user base DN %q: %w", raw, err)
	}
	return &UserBaseDN{dn: dn, rdnAttribute: rdnAttribute}, nil
}

// ExtractUsername structurally validates a presented Bind DN against the
// configured user base and returns the parser-decoded username carried by
// its leading RDN.
//
// A valid Bind DN must:
//   - parse as a well-formed RFC 4514 DN;
//   - have exactly one RDN more than the configured user base;
//   - carry exactly one attribute on that leading RDN (a multivalued
//     leading RDN is rejected);
//   - have that attribute's type match the configured user_rdn_attribute
//     (case-insensitively, as LDAP attribute types are);
//   - have every remaining RDN structurally equal (position for position)
//     to the configured user base;
//   - decode to a non-empty username value.
//
// The returned username is the parser-decoded value (escapes already
// resolved), never a raw substring of bindDN.
func (b *UserBaseDN) ExtractUsername(bindDN string) (string, error) {
	parsed, err := ldapdn.ParseDN(bindDN)
	if err != nil {
		return "", fmt.Errorf("ldap: malformed bind DN: %w", err)
	}

	if len(parsed.RDNs) != len(b.dn.RDNs)+1 {
		return "", errors.New("ldap: bind DN is not exactly one RDN below the configured user base")
	}

	leading := parsed.RDNs[0]
	if len(leading.Attributes) != 1 {
		return "", errors.New("ldap: bind DN leading RDN must carry exactly one attribute")
	}

	attr := leading.Attributes[0]
	if !strings.EqualFold(attr.Type, b.rdnAttribute) {
		return "", fmt.Errorf("ldap: bind DN leading RDN attribute %q does not match configured user_rdn_attribute %q", attr.Type, b.rdnAttribute)
	}

	rest := &ldapdn.DN{RDNs: parsed.RDNs[1:]}
	if !rest.Equal(b.dn) {
		return "", errors.New("ldap: bind DN does not structurally match the configured user base")
	}

	username := attr.Value
	if username == "" {
		return "", errors.New("ldap: bind DN leading attribute value is empty")
	}
	return username, nil
}

// GroupBaseDN is the once-parsed, immutable configured LDAP group base DN
// (ldap.group_base_dn) that anchors both Search base authorization and
// synthetic group entry construction (see entry.go).
type GroupBaseDN struct {
	dn *ldapdn.DN
}

// NewGroupBaseDN parses raw via RFC 4514 ParseDN once and fails on an
// invalid configured group base DN.
func NewGroupBaseDN(raw string) (*GroupBaseDN, error) {
	dn, err := ldapdn.ParseDN(raw)
	if err != nil {
		return nil, fmt.Errorf("ldap: invalid group base DN %q: %w", raw, err)
	}
	return &GroupBaseDN{dn: dn}, nil
}

// Equal reports whether candidate parses to a DN structurally equal to the
// configured group base DN. A candidate that fails to parse is never equal.
func (g *GroupBaseDN) Equal(candidate string) bool {
	parsed, err := ldapdn.ParseDN(candidate)
	if err != nil {
		return false
	}
	return parsed.Equal(g.dn)
}

// DN returns the parsed, immutable group base DN for constructing synthetic
// group entries. Callers must not mutate the returned value or its RDNs.
func (g *GroupBaseDN) DN() *ldapdn.DN {
	return g.dn
}

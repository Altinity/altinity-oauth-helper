package ldap

import (
	"errors"
	"strings"

	ldapdn "github.com/go-ldap/ldap/v3"
	message "github.com/vjeantet/goldap/message"
	ldapserver "github.com/vjeantet/ldapserver"
)

// GroupEntry is the fixed, safely-rendered synthetic groupOfNames
// representation of one mapped ClickHouse role, scoped to a single
// connection's authenticated bound DN. See "Synthetic LDAP group entry" in
// the phase-2 plan.
type GroupEntry struct {
	// DN is the group entry's own distinguished name: cn=<CN> combined
	// with the configured group base, rendered through go-ldap's RFC 4514
	// escaping rules.
	DN string
	// CN is role_cn_prefix + the mapped role name (transport
	// representation only; this helper never queries ClickHouse and never
	// determines whether the local role actually exists there).
	CN string
	// Member is the exact successful bound DN of the connection the Search
	// arrived on.
	Member string
}

// groupAttribute is one logical attribute of a GroupEntry, prior to
// projection and rendering.
type groupAttribute struct {
	name   string
	values []string
}

// NewGroupEntry builds the synthetic group entry for role, transport
// prefixed with cnPrefix, anchored under the already-parsed groupBase, with
// memberDN as the entry's sole member value. The DN is constructed
// structurally — a leading cn RDN built with go-ldap's DN types, combined
// with the parsed group base and rendered through its escaping rules —
// never by concatenating an unescaped role into a DN string.
func NewGroupEntry(groupBase *GroupBaseDN, cnPrefix, role, memberDN string) (GroupEntry, error) {
	if groupBase == nil {
		return GroupEntry{}, errors.New("ldap: group base DN is nil")
	}
	if role == "" {
		return GroupEntry{}, errors.New("ldap: role must not be empty")
	}

	cnValue := cnPrefix + role

	cnRDN := &ldapdn.RelativeDN{
		Attributes: []*ldapdn.AttributeTypeAndValue{
			{Type: "cn", Value: cnValue},
		},
	}

	base := groupBase.DN()
	rdns := make([]*ldapdn.RelativeDN, 0, len(base.RDNs)+1)
	rdns = append(rdns, cnRDN)
	rdns = append(rdns, base.RDNs...)
	dn := &ldapdn.DN{RDNs: rdns}

	return GroupEntry{
		DN:     dn.String(),
		CN:     cnValue,
		Member: memberDN,
	}, nil
}

// fixedAttributes returns this entry's complete logical attribute set:
// objectClass, cn and member, and nothing else.
func (g GroupEntry) fixedAttributes() []groupAttribute {
	return []groupAttribute{
		{name: "objectClass", values: []string{groupObjectClassValue}},
		{name: "cn", values: []string{g.CN}},
		{name: "member", values: []string{g.Member}},
	}
}

// projectedAttributes applies the standard LDAP Search attribute-selection
// semantics to the fixed attribute set:
//   - an empty selection or "*" returns every fixed attribute;
//   - "1.1" returns no attributes at all;
//   - any other explicit selection returns only the fixed attributes whose
//     name matches (case-insensitively) a requested name — an unknown
//     requested name matches nothing and so exposes no new information.
//
// Search authorization is independent of this projection: it runs after
// AuthorizeGroupMembershipFilter has already decided the request may see
// this entry at all.
func (g GroupEntry) projectedAttributes(requested []string) []groupAttribute {
	fixed := g.fixedAttributes()

	if len(requested) == 0 {
		return fixed
	}

	for _, r := range requested {
		if r == "1.1" {
			return nil
		}
	}

	for _, r := range requested {
		if r == "*" {
			return fixed
		}
	}

	projected := make([]groupAttribute, 0, len(fixed))
	for _, f := range fixed {
		for _, r := range requested {
			if strings.EqualFold(f.name, r) {
				projected = append(projected, f)
				break
			}
		}
	}
	return projected
}

// Render projects this entry onto requested (the Search's requested
// attribute list, e.g. from message.SearchRequest.Attributes()) and builds
// the production ldapserver search-result entry for it. When typesOnly is
// true, attribute names are present but carry no values, matching
// SearchRequest.TypesOnly() semantics.
func (g GroupEntry) Render(requested []string, typesOnly bool) message.SearchResultEntry {
	entry := ldapserver.NewSearchResultEntry(g.DN)

	for _, attr := range g.projectedAttributes(requested) {
		name := message.AttributeDescription(attr.name)
		if typesOnly {
			entry.AddAttribute(name)
			continue
		}
		values := make([]message.AttributeValue, len(attr.values))
		for i, v := range attr.values {
			values[i] = message.AttributeValue(v)
		}
		entry.AddAttribute(name, values...)
	}

	return entry
}

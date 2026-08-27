package ldap

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldapclient "github.com/go-ldap/ldap/v3"
	message "github.com/vjeantet/goldap/message"
)

// decodeFilter compiles filterStr with the real go-ldap filter grammar,
// embeds the resulting packet as the filter of a minimal but wire-accurate
// SearchRequest wrapped in an LDAPMessage envelope, and decodes that
// envelope with the production goldap message package — the same decode
// path the real TCP server exercises. This produces a genuine decoded
// message.Filter AST for AuthorizeGroupMembershipFilter to inspect, without
// depending on any unexported construction path (goldap's own filter/AVA
// types cannot be built with a struct literal from outside its package).
func decodeFilter(t *testing.T, filterStr string) message.Filter {
	t.Helper()

	filterPacket, err := goldapclient.CompileFilter(filterStr)
	if err != nil {
		t.Fatalf("CompileFilter(%q): %v", filterStr, err)
	}

	searchReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "SearchRequest")
	searchReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "baseObject"))
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, "scope"))
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "derefAliases"))
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "sizeLimit"))
	searchReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "timeLimit"))
	searchReq.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "typesOnly"))
	searchReq.AppendChild(filterPacket)
	searchReq.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes"))

	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "messageID"))
	envelope.AppendChild(searchReq)

	decoded, err := message.ReadLDAPMessage(message.NewBytes(0, envelope.Bytes()))
	if err != nil {
		t.Fatalf("ReadLDAPMessage: %v", err)
	}

	sr, ok := decoded.ProtocolOp().(message.SearchRequest)
	if !ok {
		t.Fatalf("decoded protocolOp is %T, want message.SearchRequest", decoded.ProtocolOp())
	}
	return sr.Filter()
}

const (
	testUserBase  = "ou=users,dc=altinity,dc=internal"
	testAliceDN   = "uid=alice," + testUserBase
	testBobDN     = "uid=bob," + testUserBase
	acceptFilterA = "(&(objectClass=groupOfNames)(member=" + testAliceDN + "))"
	acceptFilterB = "(&(member=" + testAliceDN + ")(objectClass=groupOfNames))"
)

func TestAuthorizeGroupMembershipFilter_Accepts(t *testing.T) {
	cases := map[string]string{
		"AND order objectClass,member": acceptFilterA,
		"AND order member,objectClass": acceptFilterB,
	}
	for name, filterStr := range cases {
		t.Run(name, func(t *testing.T) {
			f := decodeFilter(t, filterStr)
			if !AuthorizeGroupMembershipFilter(f, testAliceDN) {
				t.Fatalf("AuthorizeGroupMembershipFilter(%q) = false, want true", filterStr)
			}
		})
	}
}

func TestAuthorizeGroupMembershipFilter_Rejects(t *testing.T) {
	cases := map[string]string{
		"OR": "(|(objectClass=groupOfNames)(member=" + testAliceDN + "))",
		"NOT": "(!(objectClass=groupOfNames))",
		"substring on member": "(&(objectClass=groupOfNames)(member=" + "uid=al*" + "))",
		"present instead of equality": "(&(objectClass=groupOfNames)(member=*))",
		"extra child": "(&(objectClass=groupOfNames)(member=" + testAliceDN + ")(cn=extra))",
		"duplicate objectClass, missing member": "(&(objectClass=groupOfNames)(objectClass=groupOfNames))",
		"wrong objectClass": "(&(objectClass=person)(member=" + testAliceDN + "))",
		"malformed member DN": "(&(objectClass=groupOfNames)(member=not-a-dn-no-equals-sign))",
		"member DN for another user": "(&(objectClass=groupOfNames)(member=" + testBobDN + "))",
		"bare equality, not AND": "(objectClass=groupOfNames)",
		"missing member predicate": "(&(objectClass=groupOfNames))",
	}
	for name, filterStr := range cases {
		t.Run(name, func(t *testing.T) {
			f := decodeFilter(t, filterStr)
			if AuthorizeGroupMembershipFilter(f, testAliceDN) {
				t.Fatalf("AuthorizeGroupMembershipFilter(%q) = true, want false", filterStr)
			}
		})
	}
}

func TestAuthorizeGroupMembershipFilter_UnparsableBoundDN(t *testing.T) {
	f := decodeFilter(t, acceptFilterA)
	if AuthorizeGroupMembershipFilter(f, "") {
		t.Fatalf("AuthorizeGroupMembershipFilter with empty boundDN = true, want false")
	}
}

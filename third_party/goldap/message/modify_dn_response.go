package message

import "fmt"

// SetResultCode is patched from upstream goldap: see ../PATCHES.md item 2.
// Every sibling LDAPResult-based response type (AddResponse, ModifyResponse,
// DelResponse, CompareResponse, ...) gets its own SetResultCode defined by
// hand in that type's own file; ModifyDNResponse never got one upstream, so
// no caller outside this package could construct a non-default-result-code
// ModifyDNResponse at all (LDAPResult's fields are unexported). Matches
// AddResponse's SetResultCode in add_response.go exactly.
func (m *ModifyDNResponse) SetResultCode(code int) {
	m.resultCode = ENUMERATED(code)
}

//
//        ModifyDNResponse ::= [APPLICATION 13] LDAPResult
func readModifyDNResponse(bytes *Bytes) (ret ModifyDNResponse, err error) {
	var res LDAPResult
	res, err = readTaggedLDAPResult(bytes, classApplication, TagModifyDNResponse)
	if err != nil {
		err = LdapError{fmt.Sprintf("readModifyDNResponse:\n%s", err.Error())}
		return
	}
	ret = ModifyDNResponse(res)
	return
}

//
//        ModifyDNResponse ::= [APPLICATION 13] LDAPResult
func (m ModifyDNResponse) write(bytes *Bytes) int {
	return LDAPResult(m).writeTagged(bytes, classApplication, TagModifyDNResponse)
}

//
//        ModifyDNResponse ::= [APPLICATION 13] LDAPResult
func (m ModifyDNResponse) size() int {
	return LDAPResult(m).sizeTagged(TagModifyDNResponse)
}

package main

// Small hand-rolled BER encoders used only by this package's own tests to
// build synthetic LDAPMessage bytes (BindResponse, SearchRequest,
// AbandonRequest, UnbindRequest) that readLDAPMessage/the recorder can be
// exercised against, without depending on a real LDAP client/library. Real
// Bind requests in tests instead go through
// internal/wirefixture.BuildConstructedSimpleBind, since that is the one
// production (well, tooling-production) encoder this sub-task must not
// duplicate for that specific PDU shape.

func tlvBytes(tag byte, content []byte) []byte {
	out := append([]byte{tag}, lengthBytes(len(content))...)
	return append(out, content...)
}

func lengthBytes(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var be []byte
	for v := n; v > 0; v >>= 8 {
		be = append([]byte{byte(v)}, be...)
	}
	return append([]byte{0x80 | byte(len(be))}, be...)
}

func minimalIntBytes(n int) []byte {
	if n == 0 {
		return []byte{0x00}
	}
	var be []byte
	v := n
	for v > 0 {
		be = append([]byte{byte(v & 0xff)}, be...)
		v >>= 8
	}
	if be[0]&0x80 != 0 {
		be = append([]byte{0x00}, be...)
	}
	return be
}

func buildLDAPMessage(messageID int, opTag byte, opContent []byte) []byte {
	msgIDTLV := tlvBytes(0x02, minimalIntBytes(messageID))
	opTLV := tlvBytes(opTag, opContent)
	content := append(append([]byte{}, msgIDTLV...), opTLV...)
	return tlvBytes(0x30, content)
}

// buildBindRequest is a local, test-only Bind encoder distinct from
// internal/wirefixture.BuildConstructedSimpleBind: it exists so tests can
// embed an arbitrary marker/credential string into the password field,
// which the fixed constructed-generator deliberately does not allow.
func buildBindRequest(messageID int, dn, password string) []byte {
	version := tlvBytes(0x02, minimalIntBytes(3))
	name := tlvBytes(0x04, []byte(dn))
	auth := tlvBytes(0x80, []byte(password))
	content := append(append(append([]byte{}, version...), name...), auth...)
	return buildLDAPMessage(messageID, 0x60, content)
}

func buildBindResponse(messageID int) []byte {
	resultCode := tlvBytes(0x0a, []byte{0x00}) // ENUMERATED success(0)
	matchedDN := tlvBytes(0x04, nil)
	diagMsg := tlvBytes(0x04, nil)
	content := append(append(append([]byte{}, resultCode...), matchedDN...), diagMsg...)
	return buildLDAPMessage(messageID, 0x61, content)
}

// buildSearchRequest emits a syntactically bounded but semantically opaque
// SearchRequest content — recorder scope never parses inside it (plan §22).
func buildSearchRequest(messageID int) []byte {
	return buildLDAPMessage(messageID, 0x63, []byte{0x01, 0x02, 0x03})
}

func buildAbandonRequest(messageID, target int) []byte {
	return buildLDAPMessage(messageID, 0x50, minimalIntBytes(target))
}

func buildUnbindRequest(messageID int) []byte {
	return buildLDAPMessage(messageID, 0x42, nil)
}

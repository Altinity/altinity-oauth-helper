package main

// This file implements a small, fixed-profile LDAPv3 client over net.Conn:
// exactly the two operations this probe issues (a simple Bind, then a
// repeated fixed membership Search on that same connection) and nothing
// else. It is written from scratch and is independent of both
// github.com/go-ldap/ldap/v3 (removed from this binary entirely, per issue
// #33 phase 4) and this repository's own production
// internal/ldap/profile decoder: the probe must observe the wire exactly
// as any external client would, never by calling into the server's own
// implementation. Wire encoding and decoding use
// golang.org/x/crypto/cryptobyte/cryptobyte's asn1 helpers only.
//
// # Recognized wire shapes (client side)
//
// Sent:
//
//	BindRequest  [APPLICATION 0] { version INTEGER, name OCTET STRING,
//	                                authentication [0] OCTET STRING }
//	SearchRequest [APPLICATION 3] { baseObject OCTET STRING,
//	                                 scope ENUMERATED(2, wholeSubtree),
//	                                 derefAliases ENUMERATED(0, never),
//	                                 sizeLimit INTEGER(0), timeLimit INTEGER(0),
//	                                 typesOnly BOOLEAN(false),
//	                                 filter Filter, attributes SEQUENCE OF OCTET STRING }
//
// where the fixed filter is exactly
// AND(objectClass=groupOfNames, member=<bind DN>) and the fixed
// attribute list is exactly {"cn"}.
//
// Received and decoded, bounded to maxResponseBodyBytes per LDAPMessage
// before any allocation sized by a declared length:
//
//	BindResponse       [APPLICATION 1] { resultCode ENUMERATED, ... }
//	SearchResultEntry  [APPLICATION 4] { objectName OCTET STRING,
//	                                      attributes SEQUENCE OF
//	                                        SEQUENCE { type OCTET STRING,
//	                                                   vals SET OF OCTET STRING } }
//	SearchResultDone   [APPLICATION 5] { resultCode ENUMERATED, ... }
//
// Only the resultCode field of a result PDU and the "cn"-typed attribute
// values of a SearchResultEntry are ever extracted; matchedDN,
// diagnosticMessage, and any other attribute are read past but never
// retained, logged, or returned — preserving this binary's "no raw
// credential- or library-error-bearing text on stdout" contract, since a
// server's diagnosticMessage is not documented as credential-free.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// LDAP application tags this client sends or recognizes on receipt (RFC
// 4511 §4.2's protocolOp CHOICE): class APPLICATION (0x40) plus the
// constructed bit (0x20) plus the low-tag-number tag itself.
const (
	tagBindRequest       = asn1.Tag(0x60) // [APPLICATION 0] constructed
	tagBindResponse      = asn1.Tag(0x61) // [APPLICATION 1] constructed
	tagSearchRequest     = asn1.Tag(0x63) // [APPLICATION 3] constructed
	tagSearchResultEntry = asn1.Tag(0x64) // [APPLICATION 4] constructed
	tagSearchResultDone  = asn1.Tag(0x65) // [APPLICATION 5] constructed
)

// authChoiceSimple is AuthenticationChoice's "simple" arm (RFC 4511
// §4.2): context-specific, primitive, tag 0 — a bare OCTET STRING
// password.
var authChoiceSimple = asn1.Tag(0).ContextSpecific()

// filterTagAnd/filterTagEquality are the two Filter CHOICE (RFC 4511
// §4.5.1) tags this client's one fixed membership filter ever uses:
// context [0] constructed (the "and" choice) and context [3] constructed
// (AttributeValueAssertion, "equalityMatch").
var (
	filterTagAnd      = asn1.Tag(0).ContextSpecific().Constructed()
	filterTagEquality = asn1.Tag(3).ContextSpecific().Constructed()
)

// tagControls is the LDAPMessage envelope's optional trailing
// "controls [0] Controls" element (RFC 4511 §4.1.1). This client never
// sends one; it is tolerated (structurally skipped, never interpreted) on
// receipt only so a server that echoes controls back does not make an
// otherwise-well-formed response look malformed.
var tagControls = asn1.Tag(0).ContextSpecific().Constructed()

// Fixed profile values (RFC 4511 §4.5.1): subtree scope, never-deref
// aliases — the only Search shape this probe ever issues.
const (
	scopeWholeSubtree   = 2
	derefNeverAliases   = 0
	ldapVersion3        = 3
	membershipObjClass  = "groupOfNames"
	membershipAttrCN    = "cn"
)

// Result codes (RFC 4511 §4.1.9) this client distinguishes.
const (
	ldapResultSuccess            = 0
	ldapResultInvalidCredentials = 49
)

// maxResponseBodyBytes bounds a single LDAPMessage's declared body length
// this client will ever allocate for — generous for cn-only Search
// entries under this profile's fixed shape, but never unbounded. Checked
// before any allocation sized by the declared length, mirroring this
// repository's "framing before allocation" convention.
const maxResponseBodyBytes = 1 << 20 // 1 MiB

// errMalformedResponse is returned for any structurally invalid
// LDAPMessage this client reads: bad framing, a malformed envelope, or a
// response shape this client does not recognize. It carries no per-call
// detail so a decode failure can never leak wire bytes into a printed
// marker.
var errMalformedResponse = errors.New("session-probe: malformed LDAP response")

// errUnexpectedResponse is returned when a structurally well-formed
// LDAPMessage arrives with the wrong messageID or an operation tag this
// client did not ask for at this point in the exchange (e.g. a
// SearchResultEntry received in reply to a Bind).
var errUnexpectedResponse = errors.New("session-probe: unexpected LDAP response")

// ldapResultError reports a non-success resultCode from a BindResponse or
// SearchResultDone. It deliberately carries only the numeric code, never
// the server's matchedDN/diagnosticMessage text — those are not
// documented as credential-free, so classifyError (main.go) maps this
// down to one of a small closed set of safe classes and the raw code
// never reaches stdout.
type ldapResultError struct {
	code int
}

func (e *ldapResultError) Error() string {
	return fmt.Sprintf("session-probe: ldap result code %d", e.code)
}

// escapeDN escapes a DN attribute value per RFC 4514: a leading space or
// '#', a trailing space, the characters `"+,;<>\`, and NUL are escaped so
// the returned value can be safely concatenated into a DN string
// (`rdnAttr=<value>,<baseDN>`).
func escapeDN(v string) string {
	if v == "" {
		return ""
	}
	var b strings.Builder
	runes := []rune(v)
	for i, r := range runes {
		switch {
		case (i == 0 || i == len(runes)-1) && r == ' ':
			b.WriteByte('\\')
			b.WriteRune(r)
		case i == 0 && r == '#':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '"', r == '+', r == ',', r == ';', r == '<', r == '>', r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\x00':
			b.WriteString(`\00`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// probeConn is one persistent LDAP connection: a raw net.Conn plus the
// monotonically increasing messageID counter every request on it
// consumes. It is never re-dialed by any method on it — reconnection, if
// it ever happens, is the caller's (run's) explicit decision, and this
// binary's run loop never makes that decision (see the package doc
// comment's "Wire behavior" section).
type probeConn struct {
	conn   net.Conn
	nextID int32
}

// dialProbe opens exactly one TCP connection to addr.
func dialProbe(addr string, timeout time.Duration) (*probeConn, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	return &probeConn{conn: conn, nextID: 1}, nil
}

func (c *probeConn) Close() error { return c.conn.Close() }

func (c *probeConn) nextMessageID() int32 {
	id := c.nextID
	c.nextID++
	return id
}

func (c *probeConn) writeMessage(msg []byte, timeout time.Duration) error {
	if timeout > 0 {
		if err := c.conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
	}
	_, err := c.conn.Write(msg)
	return err
}

// respEnvelope is one decoded LDAPMessage response: its messageID, the
// application tag of its protocolOp, and that protocolOp's still-encoded
// content (further decoded by decodeResultCode/decodeEntryCNs depending
// on tag).
type respEnvelope struct {
	messageID int32
	tag       asn1.Tag
	content   cryptobyte.String
}

// readFrame reads exactly one bounded LDAPMessage off r and returns the
// outer SEQUENCE's raw content bytes, never allocating a buffer sized by
// an unchecked declared length: any declared length above
// maxResponseBodyBytes is rejected before the body is read.
func readFrame(r io.Reader) ([]byte, error) {
	var tagByte [1]byte
	if _, err := io.ReadFull(r, tagByte[:]); err != nil {
		return nil, err
	}
	if tagByte[0] != 0x30 { // universal constructed SEQUENCE
		return nil, errMalformedResponse
	}

	var firstLen [1]byte
	if _, err := io.ReadFull(r, firstLen[:]); err != nil {
		return nil, err
	}

	var length int
	if firstLen[0]&0x80 == 0 {
		length = int(firstLen[0])
	} else {
		n := int(firstLen[0] &^ 0x80)
		if n == 0 || n > 4 {
			// Indefinite form, or a long-form length wider than this
			// client will ever accept as a legitimate declared length
			// (four octets already exceeds maxResponseBodyBytes).
			return nil, errMalformedResponse
		}
		lenOctets := make([]byte, n)
		if _, err := io.ReadFull(r, lenOctets); err != nil {
			return nil, err
		}
		var v uint64
		for _, b := range lenOctets {
			v = v<<8 | uint64(b)
		}
		if v > maxResponseBodyBytes {
			return nil, errMalformedResponse
		}
		length = int(v)
	}
	if length > maxResponseBodyBytes {
		return nil, errMalformedResponse
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// decodeEnvelope decodes body (readFrame's return) as one LDAPMessage:
// messageID, exactly one protocolOp, an optional trailing Controls
// element (structurally skipped, never interpreted), and no trailing
// bytes after that. Any structural failure returns errMalformedResponse.
func decodeEnvelope(body []byte) (respEnvelope, error) {
	s := cryptobyte.String(body)

	var msgID int32
	if !s.ReadASN1Integer(&msgID) {
		return respEnvelope{}, errMalformedResponse
	}

	var opContent cryptobyte.String
	var opTag asn1.Tag
	if !s.ReadAnyASN1(&opContent, &opTag) {
		return respEnvelope{}, errMalformedResponse
	}

	var controlsPresent bool
	var controls cryptobyte.String
	if !s.ReadOptionalASN1(&controls, &controlsPresent, tagControls) {
		return respEnvelope{}, errMalformedResponse
	}

	if !s.Empty() {
		return respEnvelope{}, errMalformedResponse
	}

	return respEnvelope{messageID: msgID, tag: opTag, content: opContent}, nil
}

func (c *probeConn) readEnvelope(timeout time.Duration) (respEnvelope, error) {
	if timeout > 0 {
		if err := c.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return respEnvelope{}, err
		}
	}
	body, err := readFrame(c.conn)
	if err != nil {
		return respEnvelope{}, err
	}
	return decodeEnvelope(body)
}

// decodeResultCode reads only the leading resultCode ENUMERATED off an
// LDAPResult-shaped content (BindResponse or SearchResultDone);
// matchedDN/diagnosticMessage/referral, if present, are left undecoded
// and never retained.
func decodeResultCode(content cryptobyte.String) (int, error) {
	var code int
	if !content.ReadASN1Enum(&code) {
		return 0, errMalformedResponse
	}
	return code, nil
}

// decodeEntryCNs decodes a SearchResultEntry's content and returns every
// value of every attribute whose type equals "cn" (case-insensitively,
// per LDAP attribute-description matching rules). objectName itself is
// read past structurally but never returned.
func decodeEntryCNs(content cryptobyte.String) ([]string, error) {
	var objectName []byte
	if !content.ReadASN1Bytes(&objectName, asn1.OCTET_STRING) {
		return nil, errMalformedResponse
	}

	var attrs cryptobyte.String
	if !content.ReadASN1(&attrs, asn1.SEQUENCE) {
		return nil, errMalformedResponse
	}

	var cns []string
	for !attrs.Empty() {
		var attr cryptobyte.String
		if !attrs.ReadASN1(&attr, asn1.SEQUENCE) {
			return nil, errMalformedResponse
		}

		var attrType []byte
		if !attr.ReadASN1Bytes(&attrType, asn1.OCTET_STRING) {
			return nil, errMalformedResponse
		}

		var vals cryptobyte.String
		if !attr.ReadASN1(&vals, asn1.SET) {
			return nil, errMalformedResponse
		}

		isCN := strings.EqualFold(string(attrType), membershipAttrCN)
		for !vals.Empty() {
			var val []byte
			if !vals.ReadASN1Bytes(&val, asn1.OCTET_STRING) {
				return nil, errMalformedResponse
			}
			if isCN {
				cns = append(cns, string(val))
			}
		}
	}
	return cns, nil
}

// encodeMessage wraps build's content in one outer LDAPMessage SEQUENCE.
func encodeMessage(build cryptobyte.BuilderContinuation) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, build)
	return b.Bytes()
}

// buildBindRequest encodes a full simple-Bind LDAPMessage.
func buildBindRequest(msgID int32, bindDN, password string) ([]byte, error) {
	return encodeMessage(func(b *cryptobyte.Builder) {
		b.AddASN1Int64(int64(msgID))
		b.AddASN1(tagBindRequest, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(ldapVersion3)
			b.AddASN1OctetString([]byte(bindDN))
			b.AddASN1(authChoiceSimple, func(b *cryptobyte.Builder) {
				b.AddBytes([]byte(password))
			})
		})
	})
}

// buildSearchRequest encodes a full LDAPMessage for the one fixed Search
// shape this probe issues: subtree scope, never-deref-aliases, unbounded
// size/time limits, typesOnly=false, the fixed
// AND(objectClass=groupOfNames, member=<bindDN>) filter, and the single
// "cn" requested attribute.
func buildSearchRequest(msgID int32, groupBaseDN, bindDN string) ([]byte, error) {
	return encodeMessage(func(b *cryptobyte.Builder) {
		b.AddASN1Int64(int64(msgID))
		b.AddASN1(tagSearchRequest, func(b *cryptobyte.Builder) {
			b.AddASN1OctetString([]byte(groupBaseDN))
			b.AddASN1Enum(scopeWholeSubtree)
			b.AddASN1Enum(derefNeverAliases)
			b.AddASN1Int64(0) // sizeLimit: unbounded — the probe just counts what it gets back
			b.AddASN1Int64(0) // timeLimit: unbounded — the connection deadline already bounds the round trip
			b.AddASN1Boolean(false)
			b.AddASN1(filterTagAnd, func(b *cryptobyte.Builder) {
				b.AddASN1(filterTagEquality, func(b *cryptobyte.Builder) {
					b.AddASN1OctetString([]byte("objectClass"))
					b.AddASN1OctetString([]byte(membershipObjClass))
				})
				b.AddASN1(filterTagEquality, func(b *cryptobyte.Builder) {
					b.AddASN1OctetString([]byte("member"))
					b.AddASN1OctetString([]byte(bindDN))
				})
			})
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1OctetString([]byte(membershipAttrCN))
			})
		})
	})
}

// simpleBind performs one simple Bind on c and returns nil only on a
// success (resultCode 0) BindResponse addressed to the request's own
// messageID.
func (c *probeConn) simpleBind(bindDN, password string, timeout time.Duration) error {
	id := c.nextMessageID()
	req, err := buildBindRequest(id, bindDN, password)
	if err != nil {
		return err
	}
	if err := c.writeMessage(req, timeout); err != nil {
		return err
	}

	env, err := c.readEnvelope(timeout)
	if err != nil {
		return err
	}
	if env.messageID != id || env.tag != tagBindResponse {
		return errUnexpectedResponse
	}

	code, err := decodeResultCode(env.content)
	if err != nil {
		return err
	}
	if code != ldapResultSuccess {
		return &ldapResultError{code: code}
	}
	return nil
}

// searchMembership performs one fixed membership Search on c and returns
// every "cn" value collected across every SearchResultEntry received
// before a SearchResultDone, both addressed to the request's own
// messageID. A non-success SearchResultDone resultCode is returned as
// *ldapResultError; any other unexpected shape returns
// errUnexpectedResponse.
func (c *probeConn) searchMembership(groupBaseDN, bindDN string, timeout time.Duration) ([]string, error) {
	id := c.nextMessageID()
	req, err := buildSearchRequest(id, groupBaseDN, bindDN)
	if err != nil {
		return nil, err
	}
	if err := c.writeMessage(req, timeout); err != nil {
		return nil, err
	}

	var cns []string
	for {
		env, err := c.readEnvelope(timeout)
		if err != nil {
			return nil, err
		}
		if env.messageID != id {
			return nil, errUnexpectedResponse
		}

		switch env.tag {
		case tagSearchResultEntry:
			entryCNs, err := decodeEntryCNs(env.content)
			if err != nil {
				return nil, err
			}
			cns = append(cns, entryCNs...)
		case tagSearchResultDone:
			code, err := decodeResultCode(env.content)
			if err != nil {
				return nil, err
			}
			if code != ldapResultSuccess {
				return nil, &ldapResultError{code: code}
			}
			return cns, nil
		default:
			return nil, errUnexpectedResponse
		}
	}
}

// classifyError maps a client error into one of a small closed set of
// safe classes. It deliberately never returns underlying error text: a
// server's diagnosticMessage is not documented as credential-free, so it
// is discarded by decodeResultCode long before it could reach here, and
// this function itself only ever inspects error *types*.
func classifyError(err error) string {
	var resErr *ldapResultError
	if errors.As(err, &resErr) {
		if resErr.code == ldapResultInvalidCredentials {
			return "invalid-credentials"
		}
		return "ldap-result-error"
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return "timeout"
		}
		return "network-error"
	}

	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "connection-closed"
	}

	return "unknown-error"
}

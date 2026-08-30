package profile

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// This file implements ONE iterative (non-recursive) parser for the
// restricted RFC 4514 subset the ClickHouse compatibility profile accepts,
// used uniformly for configured bases (UserBaseDN/GroupBaseDN), Bind DNs,
// Search bases, and the fixed membership filter's member assertion — see
// "Restricted DN grammar" in the Phase 2 plan. ParseDN is the sole parse
// entry point; every other helper here builds on it.
//
// Accepted: comma-separated RDNs, one attribute per RDN; descriptors
// matching [A-Za-z][A-Za-z0-9-]*, compared case-insensitively; the first
// unescaped '=' as the type/value separator; backslash escapes for space,
// '"', '#', '+', ',', ';', '<', '=', '>', '\\', plus '\XX' exactly-two-hex-
// digit byte escapes whose decoded bytes may combine with adjacent raw or
// escaped bytes into a multi-byte UTF-8 sequence; unescaped ASCII spaces
// immediately around a type/value boundary are insignificant and stripped,
// while an escaped leading/trailing space ('\ ' or '\20') stays
// significant. Decoded values are byte-exact and, after decoding, rejected
// if they contain a NUL byte or are not valid UTF-8.
//
// Rejected — deliberate Phase 3-visible narrowings versus current
// production's github.com/go-ldap/ldap/v3-based parsing: multi-valued RDNs
// via an unescaped '+'; ';' as an RDN separator; '#' introducing a
// BER-hexstring value; dotted-decimal/OID attribute types and escaped
// attribute-type names (both rejected implicitly — a leading digit, an
// embedded '.', or a leading '\\' never matches the descriptor grammar);
// and any RFC 4514 equivalence beyond case-insensitive types and
// byte-exact values. Phase 3 must explicitly accept these narrowings
// (the plan's "Deliberate DN narrowing" handoff list) before Phase 4.

// DN is a parsed, immutable value produced by ParseDN under this package's
// restricted grammar. Its zero value is the empty DN (no RDNs).
type DN struct {
	rdns []attributeTypeAndValue
}

// attributeTypeAndValue is one parsed RDN: exactly one attribute type and
// its byte-exact decoded value. The profile grammar never admits a
// multi-valued RDN, so one attributeTypeAndValue is one complete RDN.
type attributeTypeAndValue struct {
	attrType string
	value    string
}

// RDNCount reports the number of RDNs in d, so a caller (e.g. ParseBindDN)
// can check an "exactly N RDNs above a configured base" shape without
// reaching into unexported fields.
func (d DN) RDNCount() int {
	return len(d.rdns)
}

// Equal reports whether d and other are structurally equal: the same
// number of RDNs, each attribute type equal case-insensitively and each
// decoded value equal byte-for-byte, in order. Equal never compares
// rendered text and never performs a suffix/substring check — see
// ParseBindDN's doc comment for why that distinction is a security
// property, not a style preference.
func (d DN) Equal(other DN) bool {
	if len(d.rdns) != len(other.rdns) {
		return false
	}
	for i := range d.rdns {
		if !strings.EqualFold(d.rdns[i].attrType, other.rdns[i].attrType) {
			return false
		}
		if d.rdns[i].value != other.rdns[i].value {
			return false
		}
	}
	return true
}

// String renders d back into this grammar's textual form, using
// EscapeDNValue on every decoded value. It exists primarily so tests (and
// fuzzing) can round-trip parse -> String -> parse and assert structural
// equality; it is not used to derive authorization decisions anywhere in
// this package (see Equal's doc comment).
func (d DN) String() string {
	if len(d.rdns) == 0 {
		return ""
	}
	parts := make([]string, len(d.rdns))
	for i, r := range d.rdns {
		parts[i] = r.attrType + "=" + EscapeDNValue(r.value)
	}
	return strings.Join(parts, ",")
}

// ValidAttributeDescriptor reports whether s matches this grammar's
// attribute-type descriptor rule, [A-Za-z][A-Za-z0-9-]*. Exported so config
// validation (UserRDNAttribute) reuses this exact rule instead of
// maintaining a second copy of it.
func ValidAttributeDescriptor(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDescriptorChar(s[i], i == 0) {
			return false
		}
	}
	return true
}

func isDescriptorChar(c byte, first bool) bool {
	if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
		return true
	}
	if first {
		return false
	}
	return (c >= '0' && c <= '9') || c == '-'
}

// isSpecialEscapeChar reports whether a two-byte '\'+c escape represents c
// literally. None of these are hex digits, so '\' followed by one of them
// is never ambiguous with a '\XX' hex-byte escape.
func isSpecialEscapeChar(c byte) bool {
	switch c {
	case ' ', '"', '#', '+', ',', ';', '<', '=', '>', '\\':
		return true
	}
	return false
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// hexDigitValue converts one already-validated (isHexDigit) hex digit byte
// to its 0-15 value.
func hexDigitValue(c byte) byte {
	if c >= '0' && c <= '9' {
		return c - '0'
	}
	if c >= 'a' && c <= 'f' {
		return c - 'a' + 10
	}
	return c - 'A' + 10 // 'A'-'F'
}

// ParseDN parses raw against the restricted grammar documented at the top
// of this file. It is the sole parser this package uses for configured
// bases, Bind DNs, Search bases, and member assertions — every one of
// those goes through this exact function, never a bespoke variant.
func ParseDN(raw string) (DN, error) {
	b := []byte(raw)
	i := 0
	var rdns []attributeTypeAndValue

	if len(b) == 0 {
		return DN{}, nil
	}

	for {
		// Insignificant unescaped spaces before the attribute-type
		// descriptor (after a comma, or at the start of the DN).
		i = skipSpaces(b, i)

		typeStart := i
		for i < len(b) && isDescriptorChar(b[i], i == typeStart) {
			i++
		}
		if i == typeStart {
			return DN{}, fmt.Errorf("profile: dn: expected attribute-type descriptor at byte %d", typeStart)
		}
		attrType := string(b[typeStart:i])

		// Insignificant unescaped spaces between the descriptor and '='.
		i = skipSpaces(b, i)
		if i >= len(b) || b[i] != '=' {
			return DN{}, fmt.Errorf("profile: dn: expected '=' after attribute type %q", attrType)
		}
		i++ // consume '='

		// Insignificant unescaped leading spaces in the value. An escaped
		// leading space ('\ ' or '\20') does not start with a literal
		// space byte, so this loop never consumes it.
		i = skipSpaces(b, i)

		if i < len(b) && b[i] == '#' {
			return DN{}, errors.New("profile: dn: '#' BER-hexstring values are not supported")
		}

		value, escaped, next, err := decodeValue(b, i)
		if err != nil {
			return DN{}, err
		}
		i = next

		value, escaped = trimTrailingUnescapedSpaces(value, escaped)

		if bytesContainNUL(value) {
			return DN{}, fmt.Errorf("profile: dn: value for attribute type %q decodes to a NUL byte", attrType)
		}
		if !utf8.Valid(value) {
			return DN{}, fmt.Errorf("profile: dn: value for attribute type %q does not decode to valid UTF-8", attrType)
		}

		rdns = append(rdns, attributeTypeAndValue{attrType: attrType, value: string(value)})

		if i >= len(b) {
			break
		}
		switch b[i] {
		case ',':
			i++
			continue
		case '+':
			return DN{}, errors.New("profile: dn: multi-valued RDNs (unescaped '+') are not supported")
		case ';':
			return DN{}, errors.New("profile: dn: ';' RDN separators are not supported")
		default:
			// Unreachable: decodeValue only ever stops on ',', '+', ';',
			// or end of input. Kept as an explicit failure, not a silent
			// fallthrough.
			return DN{}, fmt.Errorf("profile: dn: unexpected byte 0x%02x at byte %d", b[i], i)
		}
	}

	return DN{rdns: rdns}, nil
}

// skipSpaces advances past any run of literal (unescaped) ASCII space
// bytes starting at i. Because an escaped space is represented by a
// leading '\\' byte rather than a literal 0x20 byte, this can never
// consume part of an escape sequence.
func skipSpaces(b []byte, i int) int {
	for i < len(b) && b[i] == ' ' {
		i++
	}
	return i
}

// decodeValue decodes one RDN's value starting at i, stopping at the first
// unescaped ',', '+', ';', or end of input. escaped is a parallel flag per
// decoded byte, used only to tell a literal trailing space from a
// significant escaped one; next is the index of the terminating character
// (or len(b)).
func decodeValue(b []byte, i int) (value []byte, escaped []bool, next int, err error) {
	for i < len(b) {
		c := b[i]
		switch c {
		case ',', '+', ';':
			return value, escaped, i, nil
		case '\\':
			if i+1 >= len(b) {
				return nil, nil, 0, errors.New("profile: dn: trailing '\\' with no following escape")
			}
			nc := b[i+1]
			if isSpecialEscapeChar(nc) {
				value = append(value, nc)
				escaped = append(escaped, true)
				i += 2
				continue
			}
			if i+2 >= len(b) || !isHexDigit(b[i+1]) || !isHexDigit(b[i+2]) {
				return nil, nil, 0, fmt.Errorf("profile: dn: malformed '\\XX' escape at byte %d", i)
			}
			decoded := hexDigitValue(b[i+1])<<4 | hexDigitValue(b[i+2])
			value = append(value, decoded)
			escaped = append(escaped, true)
			i += 3
		default:
			value = append(value, c)
			escaped = append(escaped, false)
			i++
		}
	}
	return value, escaped, i, nil
}

// trimTrailingUnescapedSpaces removes trailing literal (unescaped) space
// bytes from value, stopping at the first byte (from the end) that is
// either not a space or was produced by an escape — an escaped trailing
// space stays significant.
func trimTrailingUnescapedSpaces(value []byte, escaped []bool) ([]byte, []bool) {
	end := len(value)
	for end > 0 && value[end-1] == ' ' && !escaped[end-1] {
		end--
	}
	return value[:end], escaped[:end]
}

func bytesContainNUL(value []byte) bool {
	for _, c := range value {
		if c == 0 {
			return true
		}
	}
	return false
}

// EscapeDNValue renders value as a safe RDN value under this grammar: a
// leading/trailing space and a leading '#' are backslash-escaped (mirroring
// the rules ParseDN enforces on the way in), every occurrence of '"', '+',
// ',', ';', '<', '=', '>', or '\\' is backslash-escaped, and any remaining
// ASCII control byte falls back to a '\XX' hex escape; ordinary printable
// ASCII and raw UTF-8 bytes pass through unescaped. Escaping value and
// re-parsing the result with ParseDN always decodes back to value
// unchanged.
func EscapeDNValue(value string) string {
	if value == "" {
		return ""
	}
	raw := []byte(value)
	last := len(raw) - 1
	out := make([]byte, 0, len(raw)+8)
	for i, c := range raw {
		switch {
		case c == ' ' && (i == 0 || i == last):
			out = append(out, '\\', ' ')
		case c == '#' && i == 0:
			out = append(out, '\\', '#')
		case c == '"', c == '+', c == ',', c == ';', c == '<', c == '=', c == '>', c == '\\':
			out = append(out, '\\', c)
		case c < 0x20 || c == 0x7f:
			out = append(out, '\\', hexDigitChar(c>>4), hexDigitChar(c&0x0f))
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

func hexDigitChar(v byte) byte {
	if v < 10 {
		return '0' + v
	}
	return 'a' + (v - 10)
}

// ParseBindDN validates candidate against the fixed Bind shape
// "<rdnAttribute>=<non-empty username>,<base>": precisely one leading RDN
// above base, that RDN's attribute type compared case-insensitively against
// rdnAttribute, and every remaining RDN structurally (DN.Equal) equal to
// base — never a rendered-text suffix/substring check, which a crafted
// candidate could satisfy while its actual RDN structure differs (see
// dn_test.go's suffix-only cases). On success it returns the leading RDN's
// decoded, non-empty username.
func ParseBindDN(candidate string, base DN, rdnAttribute string) (string, error) {
	parsed, err := ParseDN(candidate)
	if err != nil {
		return "", fmt.Errorf("profile: dn: malformed bind DN: %w", err)
	}

	if parsed.RDNCount() != base.RDNCount()+1 {
		return "", errors.New("profile: dn: bind DN is not exactly one RDN above the configured user base")
	}

	leading := parsed.rdns[0]
	if !strings.EqualFold(leading.attrType, rdnAttribute) {
		return "", fmt.Errorf("profile: dn: bind DN leading RDN attribute %q does not match configured user_rdn_attribute %q", leading.attrType, rdnAttribute)
	}
	if leading.value == "" {
		return "", errors.New("profile: dn: bind DN leading RDN value must not be empty")
	}

	rest := DN{rdns: parsed.rdns[1:]}
	if !rest.Equal(base) {
		return "", errors.New("profile: dn: bind DN does not structurally match the configured user base")
	}

	return leading.value, nil
}

// RenderGroupDN renders the synthetic group DN "cn=<escaped
// roleCNPrefix+role>,<groupBaseDN>" for one mapped role, using
// EscapeDNValue for safe rendering; groupBaseDN is used verbatim, never
// re-parsed/re-rendered. Matching current production's defensive behavior,
// an empty role is the caller's skip case, not a rendering failure:
// RenderGroupDN reports ("", false) for it instead of an error. The
// response-PDU size cap that can still reject an oversized rendered entry
// is enforced by the encoder, not here.
func RenderGroupDN(groupBaseDN, roleCNPrefix, role string) (string, bool) {
	if role == "" {
		return "", false
	}
	cn := roleCNPrefix + role
	return "cn=" + EscapeDNValue(cn) + "," + groupBaseDN, true
}

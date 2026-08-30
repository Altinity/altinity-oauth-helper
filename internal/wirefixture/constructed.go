package wirefixture

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ConstructedGeneratorVersion identifies the exact deterministic algorithm
// implemented by BuildConstructedSimpleBind, so committed constructed
// fixture metadata (Session.Mode / provenance) can be traced back to the
// generator that produced it, and the regenerate-and-compare contract
// (plan section 29) can detect a generator change.
const ConstructedGeneratorVersion = "wirefixture-constructed-v1"

// constructedBindDN and constructedBindPassword are the fixed, non-secret
// Bind DN and password literal used by BuildConstructedSimpleBind.
//
// The password is deliberately NOT JWT-shaped: it does not start with
// "eyJ" and does not contain three dot-separated base64url-like segments,
// so the repository-wide JWT-shape scanner (plan section 30.6) never
// flags committed constructed fixtures or this source file itself
// (coordinator amendment 5).
const (
	constructedBindDN       = "uid=wirefixture-boundary,ou=users,dc=altinity,dc=internal"
	constructedBindPassword = "wirefixture_constructed_boundary_not_a_token_000"
)

// BER tags used by BuildConstructedSimpleBind. Named individually (rather
// than computed) because this builder supports exactly one fixed message
// shape, not general BER/LDAP encoding.
const (
	tagSequence               byte = 0x30 // universal SEQUENCE, constructed — LDAPMessage
	tagInteger                byte = 0x02 // universal INTEGER, primitive — MessageID / version
	tagOctetString            byte = 0x04 // universal OCTET STRING, primitive — LDAPDN/LDAPString
	tagApplicationBindRequest byte = 0x60 // [APPLICATION 0], constructed — BindRequest
	tagContextSimpleAuth      byte = 0x80 // [0], primitive — AuthenticationChoice::simple
)

// BuildConstructedSimpleBind hand-encodes a minimal, deterministic BER
// LDAPMessage carrying a version-3 simple BindRequest with the given
// positive MessageID, a fixed non-secret Bind DN, and a fixed
// non-JWT-shaped password literal.
//
// It exists solely to produce reproducible MessageID-boundary evidence
// (plan section 29) — specifically the 127/128 positive-INTEGER boundary,
// where the DER-minimal encoding of 127 is a single content byte 0x7f,
// while 128 requires a leading zero content byte (0x00 0x80) to stay a
// positive INTEGER (a bare 0x80 would be a negative two's-complement
// INTEGER). It is not a general BER/LDAP encoder: it supports exactly the
// one message shape needed for that boundary, matching the recorder's own
// narrow scope (plan section 22).
//
// messageID must be positive. RFC 4511 permits MessageID 0, but every
// tracked libldap connection numbers its own first request 1 (see the
// package doc's wire-determinism basis), so 0 and negative values are
// rejected as out of the scope this builder exists for.
func BuildConstructedSimpleBind(messageID int) ([]byte, error) {
	if messageID <= 0 {
		return nil, fmt.Errorf("wirefixture: BuildConstructedSimpleBind: messageID must be positive, got %d", messageID)
	}

	messageIDTLV, err := encodeIntegerTLV(int64(messageID))
	if err != nil {
		return nil, fmt.Errorf("wirefixture: BuildConstructedSimpleBind: encode messageID: %w", err)
	}
	versionTLV, err := encodeIntegerTLV(3)
	if err != nil {
		return nil, fmt.Errorf("wirefixture: BuildConstructedSimpleBind: encode version: %w", err)
	}

	nameTLV := encodeTLV(tagOctetString, []byte(constructedBindDN))
	simpleTLV := encodeTLV(tagContextSimpleAuth, []byte(constructedBindPassword))

	bindRequestContent := concatBytes(versionTLV, nameTLV, simpleTLV)
	bindRequestTLV := encodeTLV(tagApplicationBindRequest, bindRequestContent)

	messageContent := concatBytes(messageIDTLV, bindRequestTLV)
	return encodeTLV(tagSequence, messageContent), nil
}

// encodeIntegerTLV encodes v as a full universal INTEGER TLV using the
// minimal positive DER content-byte form.
func encodeIntegerTLV(v int64) ([]byte, error) {
	content, err := minimalPositiveIntegerBytes(v)
	if err != nil {
		return nil, err
	}
	return encodeTLV(tagInteger, content), nil
}

// minimalPositiveIntegerBytes returns the minimal-length two's-complement
// content bytes for the non-negative value v, per DER: the shortest
// big-endian byte sequence such that the value is positive (a leading
// 0x00 byte is prepended only when the natural encoding's high bit is
// already set, to disambiguate it from a negative value).
//
// This builder only ever needs non-negative content (LDAP MessageID and
// Bind version 3 are both non-negative), so negative input is rejected
// rather than generally supported.
func minimalPositiveIntegerBytes(v int64) ([]byte, error) {
	if v < 0 {
		return nil, fmt.Errorf("wirefixture: negative INTEGER not supported by this builder, got %d", v)
	}
	if v == 0 {
		return []byte{0x00}, nil
	}
	var content []byte
	n := v
	for n > 0 {
		content = append([]byte{byte(n & 0xff)}, content...)
		n >>= 8
	}
	if content[0]&0x80 != 0 {
		content = append([]byte{0x00}, content...)
	}
	return content, nil
}

// encodeTLV encodes a single BER Tag-Length-Value with a definite-form
// length.
func encodeTLV(tag byte, content []byte) []byte {
	out := make([]byte, 0, 2+len(content))
	out = append(out, tag)
	out = append(out, encodeBERLength(len(content))...)
	out = append(out, content...)
	return out
}

// encodeBERLength encodes n as a BER definite-form length: short form for
// n < 128, long form otherwise.
func encodeBERLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var lb []byte
	m := n
	for m > 0 {
		lb = append([]byte{byte(m & 0xff)}, lb...)
		m >>= 8
	}
	return append([]byte{byte(0x80 | len(lb))}, lb...)
}

func concatBytes(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ConstructedMessageIDBoundaryMode names the Session.Mode recorded for the
// constructed MessageID-boundary fixture set (plan section 8.3's
// "construct-message-id-boundary" subcommand and section 25's
// constructed/message-id-boundary/ layout).
const ConstructedMessageIDBoundaryMode = "construct-message-id-boundary"

// BuildConstructedMessageIDBoundarySession builds the two boundary BER
// payloads (MessageID 127 and 128) via BuildConstructedSimpleBind, plus
// the stable Session metadata describing them, in the order committed at
// constructed/message-id-boundary/ (plan section 25):
// 001-bind-messageid-127.ber, 002-bind-messageid-128.ber.
//
// It does not touch disk. Callers — the wirecapture recorder's
// `construct-message-id-boundary` subcommand, and this package's own
// regenerate-and-compare tests — are responsible for writing the returned
// PDU bytes to those filenames and the Session through WriteSession.
//
// applicableLines records which tracked ClickHouse lines this constructed
// evidence is asserted to stand in for (see the package doc's
// wire-determinism basis); pass the current tracked-line set, e.g.
// []string{"24.8", "25.8"}.
func BuildConstructedMessageIDBoundarySession(applicableLines []string) (Session, [][]byte, error) {
	bind127, err := BuildConstructedSimpleBind(127)
	if err != nil {
		return Session{}, nil, fmt.Errorf("wirefixture: BuildConstructedMessageIDBoundarySession: %w", err)
	}
	bind128, err := BuildConstructedSimpleBind(128)
	if err != nil {
		return Session{}, nil, fmt.Errorf("wirefixture: BuildConstructedMessageIDBoundarySession: %w", err)
	}

	pdus := []PDU{
		{
			Sequence:          1,
			Filename:          "001-bind-messageid-127.ber",
			Direction:         DirectionClientToServer,
			Operation:         OperationBindRequest,
			MessageID:         127,
			SanitizedSHA256:   sha256Hex(bind127),
			RedactionStatus:   RedactionNotApplicableConstructed,
			ExpectedSemantics: "simple Bind, version 3, MessageID boundary 127 (single positive INTEGER content byte 0x7f)",
		},
		{
			Sequence:          2,
			Filename:          "002-bind-messageid-128.ber",
			Direction:         DirectionClientToServer,
			Operation:         OperationBindRequest,
			MessageID:         128,
			SanitizedSHA256:   sha256Hex(bind128),
			RedactionStatus:   RedactionNotApplicableConstructed,
			ExpectedSemantics: "simple Bind, version 3, MessageID boundary 128 (leading-zero positive INTEGER content 0x00 0x80)",
		},
	}

	session := Session{
		SchemaVersion:     SchemaVersion,
		Applicability:     append([]string(nil), applicableLines...),
		ProvenanceClass:   ProvenanceConstructed,
		Mode:              ConstructedMessageIDBoundaryMode,
		ConnectionCount:   0,
		PlaceholderLength: 0,
		PDUs:              pdus,
	}

	return session, [][]byte{bind127, bind128}, nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

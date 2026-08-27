package ldapserver

import (
	"bufio"
	"errors"
	"fmt"

	ldap "github.com/vjeantet/goldap/message"
)

type messagePacket struct {
	bytes []byte
}

// maxMessageBodyLength is a hard, unconditional upper bound on the BER body
// length one LDAP message may declare, enforced in readTagAndLength before
// readLdapMessageBytes ever calls readBytes with that length — i.e. before
// readBytes' make([]byte, length) allocates anything. This is a distinct
// property from the overflow guard a few lines below (`ret.Length >= 1<<23`
// inside the long-form loop): that guard only stops the int shift/OR from
// wrapping past Go's int range, so it still lets a 4-byte long-form length
// (tag 0x84) climb as high as 0x7fffffff (~2 GiB) through once the final
// byte is folded in — an unauthenticated, pre-Bind, single 6-byte header
// (0x30 0x84 0x7f 0xff 0xff 0xff) is enough to make client.ReadPacket's
// eventual readBytes call try to allocate that much, per connection, before
// any credential is ever checked. See PATCHES.md for the full writeup.
//
// 1 MiB is far larger than any legitimate message this repo's consumer
// (cmd/ch-oauth-ldap's simple Bind + restricted role-mapping Search) ever
// sends or receives: a Bind carries one DN and one JWT bearer password (at
// most a few KiB), and a Search request/response here is a handful of short
// attribute values — while still being nowhere near large enough for a
// concurrent-connection flood of rejected oversized headers to pressure
// process memory.
const maxMessageBodyLength = 1 << 20 // 1 MiB

func readMessagePacket(br *bufio.Reader) (*messagePacket, error) {
	var err error
	var bytes *[]byte
	bytes, err = readLdapMessageBytes(br)

	if err == nil {
		messagePacket := &messagePacket{bytes: *bytes}
		return messagePacket, err
	}
	return &messagePacket{}, err

}

func (msg *messagePacket) readMessage() (m ldap.LDAPMessage, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("invalid packet received hex=%x, %#v", msg.bytes, r)
		}
	}()

	return decodeMessage(msg.bytes)
}

func decodeMessage(bytes []byte) (ret ldap.LDAPMessage, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = errors.New(fmt.Sprintf("%s", e))
		}
	}()
	zero := 0
	ret, err = ldap.ReadLDAPMessage(ldap.NewBytes(zero, bytes))
	return
}

// BELLOW SHOULD BE IN ROOX PACKAGE

func readLdapMessageBytes(br *bufio.Reader) (ret *[]byte, err error) {
	var bytes []byte
	var tagAndLength ldap.TagAndLength
	tagAndLength, err = readTagAndLength(br, &bytes)
	if err != nil {
		return
	}
	readBytes(br, &bytes, tagAndLength.Length)
	return &bytes, err
}

// readTagAndLength parses an ASN.1 tag and length pair from a live connection
// into a byte slice. It returns the parsed data and the new offset. SET and
// SET OF (tag 17) are mapped to SEQUENCE and SEQUENCE OF (tag 16) since we
// don't distinguish between ordered and unordered objects in this code.
func readTagAndLength(conn *bufio.Reader, bytes *[]byte) (ret ldap.TagAndLength, err error) {
	// offset = initOffset
	//b := bytes[offset]
	//offset++
	var b byte
	b, err = readBytes(conn, bytes, 1)
	if err != nil {
		return
	}
	ret.Class = int(b >> 6)
	ret.IsCompound = b&0x20 == 0x20
	ret.Tag = int(b & 0x1f)

	//	// If the bottom five bits are set, then the tag number is actually base 128
	//	// encoded afterwards
	//	if ret.tag == 0x1f {
	//		ret.tag, err = parseBase128Int(conn, bytes)
	//		if err != nil {
	//			return
	//		}
	//	}
	// We are expecting the LDAP sequence tag 0x30 as first byte
	if b != 0x30 {
		err = fmt.Errorf("Expecting 0x30 as first byte, but got %#x instead", b)
		return
	}

	b, err = readBytes(conn, bytes, 1)
	if err != nil {
		return
	}
	if b&0x80 == 0 {
		// The length is encoded in the bottom 7 bits.
		ret.Length = int(b & 0x7f)
	} else {
		// Bottom 7 bits give the number of length bytes to follow.
		numBytes := int(b & 0x7f)
		if numBytes == 0 {
			err = ldap.SyntaxError{"indefinite length found (not DER)"}
			return
		}
		ret.Length = 0
		for i := 0; i < numBytes; i++ {

			b, err = readBytes(conn, bytes, 1)
			if err != nil {
				return
			}
			if ret.Length >= 1<<23 {
				// We can't shift ret.length up without
				// overflowing.
				err = ldap.StructuralError{"length too large"}
				return
			}
			ret.Length <<= 8
			ret.Length |= int(b)
			// Compat some lib which use go-ldap or someone else,
			// they encode int may have leading zeros when it's greater then 127
			// if ret.Length == 0 {
			// 	// DER requires that lengths be minimal.
			// 	err = ldap.StructuralError{"superfluous leading zeros in length"}
			// 	return
			// }
		}
	}

	// Enforce the hard cap on the fully-decoded length, regardless of
	// which branch (short-form or long-form) produced it, and before the
	// caller (readLdapMessageBytes) ever passes ret.Length to readBytes'
	// make([]byte, length). ret.Length is reset to 0 on this path so a
	// caller that ignores err can't accidentally read it as a valid
	// pre-cap length.
	if ret.Length > maxMessageBodyLength {
		ret.Length = 0
		err = ldap.StructuralError{"declared message length exceeds maximum allowed size"}
		return
	}

	return
}

// Read "length" bytes from the connection
// Append the read bytes to "bytes"
// Return the last read byte
func readBytes(conn *bufio.Reader, bytes *[]byte, length int) (b byte, err error) {
	newbytes := make([]byte, length)
	n, err := conn.Read(newbytes)
	if n != length {
		err = fmt.Errorf("%d bytes read instead of %d", n, length)
		return
	} else if err != nil {
		return
	}
	*bytes = append(*bytes, newbytes...)
	b = (*bytes)[len(*bytes)-1]
	return
}

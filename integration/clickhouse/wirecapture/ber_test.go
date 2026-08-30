package main

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/altinity/altinity-oauth-helper/internal/wirefixture"
)

func TestReadLDAPMessage_LabelsEachOperation(t *testing.T) {
	cases := []struct {
		name      string
		raw       []byte
		wantOp    string
		wantMsgID int
		abandon   int
		hasAband  bool
	}{
		{"search", buildSearchRequest(2), "search", 2, 0, false},
		{"unbind", buildUnbindRequest(4), "unbind", 4, 0, false},
		{"abandon", buildAbandonRequest(3, 2), "abandon", 3, 2, true},
		{"bind-response", buildBindResponse(1), "bind-response", 1, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := readLDAPMessage(bufio.NewReader(bytes.NewReader(tc.raw)))
			if err != nil {
				t.Fatalf("readLDAPMessage: %v", err)
			}
			if operationLabel(msg.opTag) != tc.wantOp {
				t.Fatalf("operation = %q, want %q", operationLabel(msg.opTag), tc.wantOp)
			}
			if msg.messageID != tc.wantMsgID {
				t.Fatalf("messageID = %d, want %d", msg.messageID, tc.wantMsgID)
			}
			if msg.hasAbandon != tc.hasAband {
				t.Fatalf("hasAbandon = %v, want %v", msg.hasAbandon, tc.hasAband)
			}
			if tc.hasAband && msg.abandonTarget != tc.abandon {
				t.Fatalf("abandonTarget = %d, want %d", msg.abandonTarget, tc.abandon)
			}
			if !bytes.Equal(msg.raw, tc.raw) {
				t.Fatalf("raw bytes not preserved exactly: got %x want %x", msg.raw, tc.raw)
			}
		})
	}
}

func TestReadLDAPMessage_Bind_UsesWirefixtureConstructedEncoding(t *testing.T) {
	raw, err := wirefixture.BuildConstructedSimpleBind(1)
	if err != nil {
		t.Fatalf("BuildConstructedSimpleBind: %v", err)
	}
	msg, err := readLDAPMessage(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("readLDAPMessage: %v", err)
	}
	if operationLabel(msg.opTag) != "bind" {
		t.Fatalf("operation = %q, want bind", operationLabel(msg.opTag))
	}
	if msg.messageID != 1 {
		t.Fatalf("messageID = %d, want 1", msg.messageID)
	}
}

func TestReadLDAPMessage_MessageIDBoundary127And128(t *testing.T) {
	for _, id := range []int{127, 128} {
		raw, err := wirefixture.BuildConstructedSimpleBind(id)
		if err != nil {
			t.Fatalf("BuildConstructedSimpleBind(%d): %v", id, err)
		}
		msg, err := readLDAPMessage(bufio.NewReader(bytes.NewReader(raw)))
		if err != nil {
			t.Fatalf("readLDAPMessage(%d): %v", id, err)
		}
		if msg.messageID != id {
			t.Fatalf("messageID = %d, want %d", msg.messageID, id)
		}
	}
}

func TestReadLDAPMessage_RejectsUnexpectedOuterTag(t *testing.T) {
	raw := []byte{0x31, 0x00} // SET, not SEQUENCE
	_, err := readLDAPMessage(bufio.NewReader(bytes.NewReader(raw)))
	if err == nil {
		t.Fatal("expected an error for a non-SEQUENCE outer tag")
	}
}

func TestReadLDAPMessage_RejectsIndefiniteLength(t *testing.T) {
	raw := []byte{0x30, 0x80} // SEQUENCE, indefinite length
	_, err := readLDAPMessage(bufio.NewReader(bytes.NewReader(raw)))
	if err == nil {
		t.Fatal("expected an error for indefinite-length framing")
	}
}

func TestReadLDAPMessage_RejectsTruncatedFrame(t *testing.T) {
	full := buildSearchRequest(2)
	truncated := full[:len(full)-2]
	_, err := readLDAPMessage(bufio.NewReader(bytes.NewReader(truncated)))
	if err == nil {
		t.Fatal("expected an error for a truncated frame")
	}
}

func TestReadLDAPMessage_RejectsOversizedLength(t *testing.T) {
	raw := []byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff} // claims a ~2GB body
	_, err := readLDAPMessage(bufio.NewReader(bytes.NewReader(raw)))
	if err == nil {
		t.Fatal("expected an error for a length exceeding maxPDUBytes")
	}
}

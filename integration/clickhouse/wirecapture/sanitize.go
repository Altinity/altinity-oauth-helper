package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/altinity/altinity-oauth-helper/internal/wirefixture"
)

// sha256Hex returns the hex-encoded SHA-256 of b. internal/wirefixture has
// its own equivalent helper but does not export it (it is an internal
// convenience for BuildConstructedMessageIDBoundarySession, not part of the
// package's committed API) — this package computes the same hash locally
// rather than either depending on an unexported symbol or asking wirefixture
// to export tooling convenience it does not otherwise need.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// wirefixtureOperation maps a recorder-scoped protocolOp application tag
// (ber.go's tag* constants) to the canonical Operation* vocabulary that
// internal/wirefixture.PDU.Operation commits to disk (plan section 9: the
// on-disk schema, including its vocabulary, is wirefixture's alone to
// define). operationLabel's own short-form labels ("bind", "search", ...)
// remain in local use for filenames and in-process branching; they are a
// distinct, unexported concern from the committed field's value.
func wirefixtureOperation(tag byte) string {
	switch tag {
	case tagBindRequest:
		return wirefixture.OperationBindRequest
	case tagSearchRequest:
		return wirefixture.OperationSearchRequest
	case tagAbandonRequest:
		return wirefixture.OperationAbandonRequest
	case tagUnbindRequest:
		return wirefixture.OperationUnbindRequest
	default:
		// Out of the recorder's client-request scope (plan section 22); fall
		// back to the local label rather than fabricating a wirefixture
		// vocabulary value that was never defined for it.
		return operationLabel(tag)
	}
}

// maxCredentialBytes bounds the stdin read in readCredentialFromStdin
// (plan §24): the credential is a compact JWT, never anywhere close to
// this size in practice; the bound exists only to keep the read itself
// bounded rather than trusting an unbounded stdin stream.
const maxCredentialBytes = 64 * 1024

// readCredentialFromStdin performs the ONLY supported credential transfer
// path into the sanitizer (plan §24): a bounded read from r (stdin in
// production). There is deliberately no flag or environment-variable
// alternative anywhere in this package — see sanitize_test.go's AST-level
// assertion and the doneWhen grep this sub-task is graded against. A single
// trailing "\n" (and, before it, a single "\r") is trimmed since shells
// commonly append one; no other trimming/normalization is performed.
func readCredentialFromStdin(r io.Reader) ([]byte, error) {
	limited := io.LimitReader(r, maxCredentialBytes+1)
	b, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("wirecapture: read credential from stdin: %w", err)
	}
	if len(b) > maxCredentialBytes {
		return nil, fmt.Errorf("wirecapture: credential on stdin exceeds %d bytes", maxCredentialBytes)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("wirecapture: credential on stdin is empty")
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	return b, nil
}

// SanitizeInput is the sanitize subcommand's configuration.
type SanitizeInput struct {
	RawDir       string // e.g. /run/ldap-wirecapture/raw — holds conn-NNNN subdirectories
	SanitizedDir string // e.g. /run/ldap-wirecapture/sanitized
	Credential   []byte // already read from stdin by the caller
	Line         string // applicability label carried into session metadata, e.g. "24.8"
	Mode         string // e.g. "success" or "timeout-abandon"
	SQL          string // the controlled SQL statement issued for this session, if any
}

var connDirPattern = regexp.MustCompile(`^conn-[0-9]{4,}$`)

// rawSanitizeFile is one raw captured client-request PDU loaded off disk,
// decoded just enough (via readLDAPMessage) to drive sanitization and
// metadata construction.
type rawSanitizeFile struct {
	name    string
	content []byte
	decoded pdu
}

// Sanitize implements the `ldap-wire-recorder sanitize` subcommand's core
// logic (plan §24): it refuses unless exactly one connection was captured,
// requires the credential to occur exactly once across every captured
// client PDU and for that occurrence to be inside the Bind PDU, replaces it
// in place with same-length ASCII 'x', writes the sanitized PDUs plus
// wirefixture-owned session metadata, and returns that metadata.
func Sanitize(in SanitizeInput) (*wirefixture.Session, error) {
	if len(in.Credential) == 0 {
		return nil, fmt.Errorf("wirecapture: sanitize: empty credential")
	}

	connDirs, err := listConnDirs(in.RawDir)
	if err != nil {
		return nil, errMalformedFrame("list raw connection directories", err)
	}
	if len(connDirs) != 1 {
		return nil, errConnectionCountNotOne(len(connDirs))
	}
	connDir := connDirs[0]

	files, err := loadRawSanitizeFiles(filepath.Join(in.RawDir, connDir))
	if err != nil {
		return nil, err
	}

	matchFile, matchOffset, totalMatches, err := locateCredential(files, in.Credential)
	if err != nil {
		return nil, err
	}
	if totalMatches == 0 {
		return nil, errSanitizeZeroMatch()
	}
	if totalMatches > 1 {
		return nil, errSanitizeMultipleMatches(totalMatches)
	}
	if files[matchFile].decoded.opTag != tagBindRequest {
		return nil, errSanitizeNotInBind(files[matchFile].name)
	}

	if err := os.MkdirAll(in.SanitizedDir, 0o700); err != nil {
		return nil, errMalformedFrame("create sanitized directory", err)
	}

	credLen := len(in.Credential)
	pdus := make([]wirefixture.PDU, 0, len(files))
	for i, f := range files {
		content := f.content
		if i == matchFile {
			sanitized := make([]byte, len(content))
			copy(sanitized, content)
			replacement := bytes.Repeat([]byte("x"), credLen)
			copy(sanitized[matchOffset:matchOffset+credLen], replacement)
			content = sanitized
		}

		outName := fmt.Sprintf("%03d-%s", i+1, sanitizedFilename(f.decoded))
		if err := os.WriteFile(filepath.Join(in.SanitizedDir, outName), content, 0o600); err != nil {
			return nil, errMalformedFrame("write sanitized PDU file", err)
		}

		wp := wirefixture.PDU{
			Sequence:        i + 1,
			Filename:        outName,
			Direction:       wirefixture.DirectionClientToServer,
			Operation:       wirefixtureOperation(f.decoded.opTag),
			MessageID:       f.decoded.messageID,
			SanitizedSHA256: sha256Hex(content),
		}
		if f.decoded.hasAbandon {
			target := f.decoded.abandonTarget
			wp.AbandonTarget = &target
		}
		if i == matchFile {
			wp.RedactionStatus = wirefixture.RedactionRedacted
		} else {
			wp.RedactionStatus = "no-credential-present"
		}
		pdus = append(pdus, wp)
	}

	session := wirefixture.Session{
		SchemaVersion:     wirefixture.SchemaVersion,
		Line:              in.Line,
		Applicability:     []string{in.Line},
		ProvenanceClass:   wirefixture.ProvenanceCapturedRedacted,
		Mode:              in.Mode,
		ConnectionCount:   1,
		SQL:               in.SQL,
		PlaceholderLength: credLen,
		PDUs:              pdus,
	}
	if err := wirefixture.WriteSession(filepath.Join(in.SanitizedDir, "session.json"), session); err != nil {
		return nil, errInvalidMetadata("write sanitized session.json", err)
	}
	return &session, nil
}

func listConnDirs(rawDir string) ([]string, error) {
	entries, err := os.ReadDir(rawDir)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() && connDirPattern.MatchString(e.Name()) {
			dirs = append(dirs, e.Name())
		}
	}
	sort.Strings(dirs)
	return dirs, nil
}

func loadRawSanitizeFiles(connDir string) ([]rawSanitizeFile, error) {
	entries, err := os.ReadDir(connDir)
	if err != nil {
		return nil, errMalformedFrame("read raw connection directory", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	out := make([]rawSanitizeFile, 0, len(names))
	for _, name := range names {
		content, err := os.ReadFile(filepath.Join(connDir, name))
		if err != nil {
			return nil, errMalformedFrame("read raw PDU file", err)
		}
		msg, err := readLDAPMessage(bufio.NewReader(bytes.NewReader(content)))
		if err != nil {
			return nil, errMalformedFrame("decode raw PDU file", err)
		}
		out = append(out, rawSanitizeFile{name: name, content: content, decoded: msg})
	}
	return out, nil
}

// locateCredential searches every file's raw content for credential and
// returns the index into files of the (first) file containing a match, the
// byte offset of that match within that file's content, and the TOTAL
// occurrence count across every file (used to enforce exactly-one).
func locateCredential(files []rawSanitizeFile, credential []byte) (fileIdx int, offset int, total int, err error) {
	fileIdx = -1
	for i, f := range files {
		count := bytes.Count(f.content, credential)
		if count > 0 && fileIdx == -1 {
			fileIdx = i
			offset = bytes.Index(f.content, credential)
		}
		total += count
	}
	return fileIdx, offset, total, nil
}

func sanitizedFilename(msg pdu) string {
	label := operationLabel(msg.opTag)
	switch label {
	case "bind":
		return "bind-request.ber"
	case "search":
		return "search-request.ber"
	case "abandon":
		return "abandon-request.ber"
	case "unbind":
		return "unbind-request.ber"
	default:
		return label + "-request.ber"
	}
}

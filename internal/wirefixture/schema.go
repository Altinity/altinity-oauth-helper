// Package wirefixture defines the single committed schema, strict codec,
// and stable-comparison projections for the ClickHouse/libldap wire
// evidence corpus under internal/ldap/testdata/clickhouse-wire, plus the
// deterministic constructed-fixture builder used for MessageID-boundary
// evidence (issue #33 phase 1, plan section 9).
//
// This package is the sole owner of the on-disk profile.json/session.json
// metadata format. Writers (the integration/clickhouse/wirecapture
// recorder) construct Profile/Session/PDU values and persist them only
// through WriteProfile/WriteSession; readers (the internal/ldap cryptobyte
// decision test and internal/securitytest's wire-profile contract) load
// them only through ReadProfile/ReadSession. No package outside
// wirefixture should declare its own copy of these types for on-disk
// serialization (plan section 9, "Mechanical enforcement").
//
// It is test/tooling support, not production code: nothing under
// cmd/ch-oauth-ldap imports it, and internal/securitytest's dependency
// contract (a separate sub-task) proves that mechanically.
//
// # Wire-determinism basis (coordinator amendment 5)
//
// Verify-mode byte-equality on captured/sanitized fixtures — and the
// exact MessageID values recorded in committed PDU metadata — rely on
// wire-determinism facts established from the tracked OpenLDAP source
// (contrib/openldap in the tracked ClickHouse revisions) and the
// synthetic IdP used to mint fixture tokens, not on anything this package
// enforces at runtime:
//
//   - Each captured session is exactly one client TCP connection (see
//     Session.ConnectionCount and the fixture-root/session rules
//     documented on ValidateFixtureRoot), and libldap's ldap_create
//     zero-initializes the per-handle ld_msgid counter, so MessageIDs are
//     deterministic and restart at 1 for every fresh connection:
//     Bind = 1, Search = 2, Abandon = 3 (timeout-abandon sessions only),
//     Unbind = 4.
//   - The Bind DN and Search filter are derived only from the fixed
//     synthetic-IdP subject used to mint the fixture token
//     (alice@example.com), so they do not vary between fresh captures of
//     the same tracked line.
//   - Session.PlaceholderLength stays constant across fresh captures only
//     because the synthetic IdP's /sign endpoint emits a fixed claim set
//     with fixed-digit iat/exp and no random jti. A verify run is
//     expected to check that a freshly minted token's byte length still
//     equals the committed PlaceholderLength before any BER comparison,
//     and to report a mismatch there as a credential-length mismatch, not
//     wire drift (plan section 28.1/41) — that check itself lives in the
//     wirecapture recorder, not in this package.
//   - The constructed fixtures built by BuildConstructedSimpleBind use a
//     fixed, non-JWT-shaped Bind DN and password literal precisely so the
//     repository-wide JWT-shape scanner (plan section 30.6: three
//     dot-separated base64url-like segments, first starting "eyJ") never
//     trips on committed constructed-fixture bytes.
//
// None of the above makes wall-clock timing deterministic:
// PDU.ObservedElapsedMS and any host/time/local-path provenance are
// diagnostic-only and are excluded by the Stable* projections in this
// file (plan section 28.2).
//
// # Error hygiene
//
// Every exported function in this package that returns an error reports
// only safe, structural information — a file path, a field/classification
// name, a count, a byte length — and never echoes raw JSON or BER content
// back into an error string or log line (plan section 36).
package wirefixture

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
)

// SchemaVersion is this package's on-disk schema version for both
// Profile and Session documents. Bump it, and teach ReadProfile/
// ReadSession callers about the change, whenever a field is added,
// renamed, or reinterpreted in a way that changes the committed JSON
// shape.
const SchemaVersion = 1

// Canonical committed source-blob keys for Profile.ClickHouseSourceBlobs
// (plan section 2.3 / section 26).
const (
	BlobKeyLDAPClientCPP             = "LDAPClient.cpp"
	BlobKeyLDAPClientH               = "LDAPClient.h"
	BlobKeyLDAPAccessStorageCPP      = "LDAPAccessStorage.cpp"
	BlobKeyExternalAuthenticatorsCPP = "ExternalAuthenticators.cpp"
)

// ProvenanceClass distinguishes a Session captured (then sanitized) from a
// real ClickHouse/libldap connection versus one hand-constructed by this
// package's builders (plan section 27).
type ProvenanceClass string

const (
	// ProvenanceCapturedRedacted marks a session captured from a real
	// ClickHouse/libldap connection with its credential bytes sanitized.
	ProvenanceCapturedRedacted ProvenanceClass = "captured-redacted"
	// ProvenanceConstructed marks a session hand-built by this package
	// (BuildConstructedSimpleBind and friends) rather than captured.
	ProvenanceConstructed ProvenanceClass = "constructed"
)

// Direction records which side of the LDAP connection originated a PDU.
// The phase-1 recorder scope (plan section 22) records only client
// request PDUs, so DirectionClientToServer is the only value used by
// fixtures committed in this phase; DirectionServerToClient is defined
// for schema completeness and later phases.
type Direction string

const (
	DirectionClientToServer Direction = "client-to-server"
	DirectionServerToClient Direction = "server-to-client"
)

// Redaction-status values for PDU.RedactionStatus.
const (
	// RedactionRedacted marks a captured PDU whose credential bytes were
	// replaced by the sanitizer (plan section 24).
	RedactionRedacted = "redacted"
	// RedactionNotApplicableConstructed marks a constructed PDU, which
	// never carried a real credential in the first place.
	RedactionNotApplicableConstructed = "not-applicable-constructed"
)

// Common PDU.Operation values.
const (
	OperationBindRequest    = "bindRequest"
	OperationSearchRequest  = "searchRequest"
	OperationAbandonRequest = "abandonRequest"
	OperationUnbindRequest  = "unbindRequest"
)

// Profile is the committed profile.json document for one tracked
// ClickHouse line: exact source/tool provenance, independent of any one
// captured session (plan section 26).
type Profile struct {
	SchemaVersion int `json:"schema_version"`

	// Line is the tracked line key, e.g. "24.8" (plan section 2.1).
	Line string `json:"line"`
	// TrackedImage is the exact image string from run-all-builds.sh's
	// BUILDS array for this line.
	TrackedImage string `json:"tracked_image"`

	ClickHouseRepository string `json:"clickhouse_repository"`
	ClickHouseTag        string `json:"clickhouse_tag"`
	ClickHouseCommit     string `json:"clickhouse_commit"`

	// ClickHouseSourceBlobs maps each required ClickHouse source file
	// (see the BlobKey* constants) to its full 40-hex git blob SHA at
	// ClickHouseCommit (plan section 2.3). Persist full SHAs, never
	// truncated prefixes.
	ClickHouseSourceBlobs map[string]string `json:"clickhouse_source_blobs"`

	OpenLDAPRepository string `json:"openldap_repository"`
	OpenLDAPPin        string `json:"openldap_pin"`
	OpenLDAPVersion    string `json:"openldap_version"`

	// CanonicalConfigPath is the repository-relative path to the
	// executable configuration authority (plan section 3.1), e.g.
	// "integration/clickhouse/clickhouse/common/config.d/ldap.xml".
	CanonicalConfigPath string `json:"canonical_config_path"`

	// ClickHouseConfigElementSHA256 is the hex SHA-256 of
	// strings.TrimSpace(<clickhouse>...</clickhouse>) extracted from the
	// file at CanonicalConfigPath (plan section 3.1), used for drift
	// hashing instead of hashing the whole file.
	ClickHouseConfigElementSHA256 string `json:"clickhouse_config_element_sha256"`

	// CaptureToolSchemaVersion is the schema version reported by the
	// wirecapture tool that produced this profile, independent of this
	// package's own SchemaVersion.
	CaptureToolSchemaVersion int `json:"capture_tool_schema_version"`

	// SessionPaths lists the stable, relative session directory names
	// committed for this line, e.g. []string{"success",
	// "timeout-abandon"}.
	SessionPaths []string `json:"session_paths"`
}

// PDU is one committed protocol data unit: metadata about a single
// sanitized .ber file plus, for constructed fixtures, the file's own
// generation record (plan section 27's per-PDU fields).
type PDU struct {
	// Sequence is this PDU's 1-based position within its session,
	// matching the numeric filename prefix.
	Sequence int `json:"sequence"`
	// Filename is the sanitized .ber file's name within the session
	// directory, e.g. "001-bind-request.ber".
	Filename string `json:"filename"`

	Direction Direction `json:"direction"`
	// Operation names the LDAP protocol operation, e.g. "bindRequest"
	// (see the Operation* constants for the currently used values).
	Operation string `json:"operation"`
	// MessageID is this PDU's LDAP MessageID.
	MessageID int `json:"message_id"`
	// AbandonTarget is the MessageID an abandonRequest PDU targets; nil
	// for every other operation.
	AbandonTarget *int `json:"abandon_target,omitempty"`

	// SanitizedSHA256 is the hex SHA-256 of the committed sanitized .ber
	// file's exact bytes.
	SanitizedSHA256 string `json:"sanitized_sha256"`
	// RedactionStatus records whether/why this PDU's credential bytes
	// were sanitized (see the Redaction* constants).
	RedactionStatus string `json:"redaction_status"`
	// ExpectedSemantics is a short human-readable statement of what this
	// PDU is expected to mean structurally, for Phase 2's bounded parser
	// to check against.
	ExpectedSemantics string `json:"expected_semantics"`

	// ObservedElapsedMS is diagnostic-only wall-clock timing observed
	// during the run that produced this PDU (e.g. time since the
	// preceding PDU). It is run-varying and explicitly excluded from
	// StablePDU / equality comparisons (plan section 28.2).
	ObservedElapsedMS *int64 `json:"observed_elapsed_ms,omitempty"`
}

// Session is the committed session.json document for one captured or
// constructed session: a fixed, ordered PDU sequence plus the stable
// metadata needed to reproduce and verify it (plan section 27).
type Session struct {
	SchemaVersion int `json:"schema_version"`

	// Line is the tracked line this session belongs to, e.g. "24.8", for
	// a captured session. It is empty for a constructed session, which
	// instead uses Applicability.
	Line string `json:"line,omitempty"`
	// Applicability lists the tracked line(s) this session's evidence is
	// asserted to apply to. For a captured session this is normally the
	// single-element slice matching Line; for a constructed session it
	// may list every tracked line the constructed evidence stands in
	// for.
	Applicability []string `json:"applicability"`

	ProvenanceClass ProvenanceClass `json:"provenance_class"`
	// Mode names the capture/construction mode, e.g. "success",
	// "timeout-abandon", or ConstructedMessageIDBoundaryMode.
	Mode string `json:"mode"`

	// ConnectionCount is the number of recorder-accepted client TCP
	// connections this session represents. A captured session must equal
	// exactly 1 (plan section 21); this package does not itself enforce
	// that invariant (the recorder does, before promotion), but callers
	// comparing sessions should treat any other value for a
	// captured-redacted session as invalid.
	ConnectionCount int `json:"connection_count"`

	// SQL is the exact controlled query issued during capture (plan
	// section 19), e.g. "SELECT currentUser()". Empty for a constructed
	// session.
	SQL string `json:"sql,omitempty"`
	// TokenClaimRecipe is a fixed, human-readable description of the
	// token claims used to mint the fixture credential (plan section
	// 19/26), e.g. the subject and group claims. Empty for a constructed
	// session, which never carries a real token.
	TokenClaimRecipe string `json:"token_claim_recipe,omitempty"`
	// PlaceholderLength is the exact byte length of the sanitizer's
	// repeated-'x' replacement for the credential, and therefore also
	// the exact byte length every freshly minted verify-mode token must
	// match before any BER comparison proceeds (plan section 24/28.1).
	// 0 for a constructed session.
	PlaceholderLength int `json:"placeholder_length"`

	// PDUs is the session's ordered PDU metadata, one entry per
	// committed .ber file.
	PDUs []PDU `json:"pdus"`
}

func encodeJSON(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// WriteProfile deterministically encodes p and writes it to path,
// overwriting any existing file. Two calls with an equal Profile value
// produce byte-identical output (encoding/json marshals map keys in
// sorted order and struct fields in declaration order).
func WriteProfile(path string, p Profile) error {
	data, err := encodeJSON(p)
	if err != nil {
		return fmt.Errorf("wirefixture: encode profile for %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("wirefixture: write profile %s: %w", path, err)
	}
	return nil
}

// WriteSession deterministically encodes s and writes it to path,
// overwriting any existing file.
func WriteSession(path string, s Session) error {
	data, err := encodeJSON(s)
	if err != nil {
		return fmt.Errorf("wirefixture: encode session for %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("wirefixture: write session %s: %w", path, err)
	}
	return nil
}

// ReadProfile strictly decodes the profile.json document at path,
// rejecting any field not present in Profile.
func ReadProfile(path string) (Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return Profile{}, fmt.Errorf("wirefixture: open profile %s: %w", path, err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()

	var p Profile
	if err := dec.Decode(&p); err != nil {
		return Profile{}, fmt.Errorf("wirefixture: decode profile %s: %w", path, err)
	}
	if dec.More() {
		return Profile{}, fmt.Errorf("wirefixture: profile %s: trailing content after JSON document", path)
	}
	return p, nil
}

// ReadSession strictly decodes the session.json document at path,
// rejecting any field not present in Session (and, transitively, PDU).
func ReadSession(path string) (Session, error) {
	f, err := os.Open(path)
	if err != nil {
		return Session{}, fmt.Errorf("wirefixture: open session %s: %w", path, err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()

	var s Session
	if err := dec.Decode(&s); err != nil {
		return Session{}, fmt.Errorf("wirefixture: decode session %s: %w", path, err)
	}
	if dec.More() {
		return Session{}, fmt.Errorf("wirefixture: session %s: trailing content after JSON document", path)
	}
	return s, nil
}

// StableProfileView is the subset of Profile compared for exact equality
// during verification (plan section 28.1). Profile carries no
// host/time-varying fields today, so StableProfile currently projects
// every field; the named type exists so a future host/time-varying field
// can be added to Profile without silently entering equality comparisons.
type StableProfileView struct {
	SchemaVersion                 int
	Line                          string
	TrackedImage                  string
	ClickHouseRepository          string
	ClickHouseTag                 string
	ClickHouseCommit              string
	ClickHouseSourceBlobs         map[string]string
	OpenLDAPRepository            string
	OpenLDAPPin                   string
	OpenLDAPVersion               string
	CanonicalConfigPath           string
	ClickHouseConfigElementSHA256 string
	CaptureToolSchemaVersion      int
	SessionPaths                  []string
}

// StableProfile projects p onto its stable-comparison view.
func StableProfile(p Profile) StableProfileView {
	blobs := make(map[string]string, len(p.ClickHouseSourceBlobs))
	for k, v := range p.ClickHouseSourceBlobs {
		blobs[k] = v
	}
	return StableProfileView{
		SchemaVersion:                 p.SchemaVersion,
		Line:                          p.Line,
		TrackedImage:                  p.TrackedImage,
		ClickHouseRepository:          p.ClickHouseRepository,
		ClickHouseTag:                 p.ClickHouseTag,
		ClickHouseCommit:              p.ClickHouseCommit,
		ClickHouseSourceBlobs:         blobs,
		OpenLDAPRepository:            p.OpenLDAPRepository,
		OpenLDAPPin:                   p.OpenLDAPPin,
		OpenLDAPVersion:               p.OpenLDAPVersion,
		CanonicalConfigPath:           p.CanonicalConfigPath,
		ClickHouseConfigElementSHA256: p.ClickHouseConfigElementSHA256,
		CaptureToolSchemaVersion:      p.CaptureToolSchemaVersion,
		SessionPaths:                  append([]string(nil), p.SessionPaths...),
	}
}

// StablePDUView is the subset of PDU compared for exact equality during
// verification; it excludes ObservedElapsedMS (plan section 28.2).
type StablePDUView struct {
	Sequence          int
	Filename          string
	Direction         Direction
	Operation         string
	MessageID         int
	AbandonTarget     *int
	SanitizedSHA256   string
	RedactionStatus   string
	ExpectedSemantics string
}

// StablePDU projects pdu onto its stable-comparison view, dropping
// ObservedElapsedMS.
func StablePDU(pdu PDU) StablePDUView {
	var target *int
	if pdu.AbandonTarget != nil {
		v := *pdu.AbandonTarget
		target = &v
	}
	return StablePDUView{
		Sequence:          pdu.Sequence,
		Filename:          pdu.Filename,
		Direction:         pdu.Direction,
		Operation:         pdu.Operation,
		MessageID:         pdu.MessageID,
		AbandonTarget:     target,
		SanitizedSHA256:   pdu.SanitizedSHA256,
		RedactionStatus:   pdu.RedactionStatus,
		ExpectedSemantics: pdu.ExpectedSemantics,
	}
}

// StableSessionView is the subset of Session (and its PDUs) compared for
// exact equality during verification; it excludes every PDU's
// ObservedElapsedMS and carries no wall-clock/host field of its own (plan
// section 28.1/28.2).
type StableSessionView struct {
	SchemaVersion     int
	Line              string
	Applicability     []string
	ProvenanceClass   ProvenanceClass
	Mode              string
	ConnectionCount   int
	SQL               string
	TokenClaimRecipe  string
	PlaceholderLength int
	PDUs              []StablePDUView
}

// StableSession projects s onto its stable-comparison view.
func StableSession(s Session) StableSessionView {
	pdus := make([]StablePDUView, 0, len(s.PDUs))
	for _, pdu := range s.PDUs {
		pdus = append(pdus, StablePDU(pdu))
	}
	return StableSessionView{
		SchemaVersion:     s.SchemaVersion,
		Line:              s.Line,
		Applicability:     append([]string(nil), s.Applicability...),
		ProvenanceClass:   s.ProvenanceClass,
		Mode:              s.Mode,
		ConnectionCount:   s.ConnectionCount,
		SQL:               s.SQL,
		TokenClaimRecipe:  s.TokenClaimRecipe,
		PlaceholderLength: s.PlaceholderLength,
		PDUs:              pdus,
	}
}

// lineDirPattern matches a tracked-line fixture directory name, e.g.
// "24.8" (plan section 25's fixture-root rule).
var lineDirPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)

// ConstructedDirName is the single permitted non-line directory name at
// the fixture root (plan section 25).
const ConstructedDirName = "constructed"

// ValidateFixtureRoot enumerates the immediate entries of a wirefixture
// corpus root directory (e.g.
// internal/ldap/testdata/clickhouse-wire) and enforces the fixture-root
// inventory rule from the phase-1 plan (section 25): every entry must be
// a directory, and must be either a tracked-line directory matching
// "^[0-9]+\.[0-9]+$" or exactly ConstructedDirName ("constructed"). Any
// other entry — a stray file, a misnamed directory, anything else — is a
// hard error rather than being silently skipped.
//
// It returns the sorted list of tracked-line directory names found.
func ValidateFixtureRoot(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("wirefixture: read fixture root %s: %w", root, err)
	}

	var lines []string
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() {
			return nil, fmt.Errorf("wirefixture: fixture root %s: unexpected non-directory entry %q", root, name)
		}
		switch {
		case name == ConstructedDirName:
			// the single permitted non-line directory
		case lineDirPattern.MatchString(name):
			lines = append(lines, name)
		default:
			return nil, fmt.Errorf(
				"wirefixture: fixture root %s: unexpected entry %q (want a tracked-line directory matching %s, or %q)",
				root, name, lineDirPattern.String(), ConstructedDirName,
			)
		}
	}
	sort.Strings(lines)
	return lines, nil
}

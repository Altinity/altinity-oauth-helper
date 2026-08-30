package main

import (
	"errors"
	"os"
	"reflect"
	"sort"

	"github.com/altinity/altinity-oauth-helper/internal/wirefixture"
)

// CaptureToolSchemaVersion is this tool's own schema version, reported in
// every profile.json's capture_tool_schema_version field (plan §26) — a
// deliberately separate number from internal/wirefixture.SchemaVersion
// (that one versions the committed document shape; this one versions the
// tool that produced it).
const CaptureToolSchemaVersion = 1

// ProfileInput configures profile.json writing, invoked as an optional
// part of the `sanitize` subcommand (plan §9/§26) rather than as its own
// sixth subcommand (plan §8.3 caps the tool at five). profile.json
// records exact per-line source/tool provenance, independent of any one
// captured session, so the SAME ProfileInput values are expected across
// every sanitize invocation for a given line's multiple sessions
// (success, timeout-abandon, ...) — see WriteProfileFromInput's
// idempotency behavior below.
type ProfileInput struct {
	// OutDir is the line directory profile.json is written into (e.g.
	// .../clickhouse-wire/24.8), NOT the per-session SanitizedDir.
	OutDir string

	Line                 string
	TrackedImage         string
	ClickHouseRepository string
	ClickHouseTag        string
	ClickHouseCommit     string

	BlobLDAPClientCPP             string
	BlobLDAPClientH               string
	BlobLDAPAccessStorageCPP      string
	BlobExternalAuthenticatorsCPP string

	OpenLDAPRepository string
	OpenLDAPPin        string
	OpenLDAPVersion    string

	// ConfigPath is the repository-relative canonical config path
	// recorded verbatim in Profile.CanonicalConfigPath — never used by
	// this tool to locate anything on disk (ConfigFile is, when set).
	ConfigPath string

	// Exactly one of ConfigFile/ConfigSHA256 must be set. ConfigFile
	// names a config file this tool reads and hashes in-container via
	// wirefixture.ClickHouseConfigElementSHA256; ConfigSHA256 supplies an
	// already-computed hex hash directly.
	ConfigFile   string
	ConfigSHA256 string

	// SessionPaths lists this line's session directory names (e.g.
	// "success", "timeout-abandon"); WriteProfileFromInput sorts them
	// deterministically before writing, so caller-supplied order never
	// matters and repeated invocations across a line's sessions agree.
	SessionPaths []string
}

// profileRequiredField pairs a ProfileInput value with the exact flag
// name errProfileFlagMissing reports for it (a fixed, safe literal — see
// redact.go's discipline: never a flag *value*, only its name).
type profileRequiredField struct {
	flag  string
	value string
}

func validateProfileInput(in ProfileInput) error {
	fields := []profileRequiredField{
		{"--profile-out", in.OutDir},
		{"--line", in.Line},
		{"--tracked-image", in.TrackedImage},
		{"--clickhouse-repository", in.ClickHouseRepository},
		{"--clickhouse-tag", in.ClickHouseTag},
		{"--clickhouse-commit", in.ClickHouseCommit},
		{"--blob-ldapclient-cpp", in.BlobLDAPClientCPP},
		{"--blob-ldapclient-h", in.BlobLDAPClientH},
		{"--blob-ldapaccessstorage-cpp", in.BlobLDAPAccessStorageCPP},
		{"--blob-externalauthenticators-cpp", in.BlobExternalAuthenticatorsCPP},
		{"--openldap-repository", in.OpenLDAPRepository},
		{"--openldap-pin", in.OpenLDAPPin},
		{"--openldap-version", in.OpenLDAPVersion},
		{"--config-path", in.ConfigPath},
	}
	for _, f := range fields {
		if f.value == "" {
			return errProfileFlagMissing(f.flag)
		}
	}
	if len(in.SessionPaths) == 0 {
		return errProfileFlagMissing("--session-paths")
	}
	switch {
	case in.ConfigFile == "" && in.ConfigSHA256 == "":
		return errProfileConfigHashSource("neither --config-file nor --config-sha256 was supplied")
	case in.ConfigFile != "" && in.ConfigSHA256 != "":
		return errProfileConfigHashSource("both --config-file and --config-sha256 were supplied")
	}
	return nil
}

// WriteProfileFromInput validates in, resolves the trimmed <clickhouse>
// element hash (from ConfigFile, computed in-container via
// wirefixture.ClickHouseConfigElementSHA256, or taken verbatim from
// ConfigSHA256), builds a wirefixture.Profile, and writes it via
// wirefixture.WriteProfile.
//
// profile.json is per-line evidence, but sanitize (and therefore this
// function) runs once per SESSION — so a second session of the same line
// calls this again with the same ProfileInput values. If a profile.json
// already exists at the target path, this requires the freshly built
// Profile value to equal (via reflect.DeepEqual) the one strictly decoded
// back from the existing file — which, since WriteProfile's encoding is a
// pure deterministic function of the Profile value (equal values always
// produce byte-identical output; see schema.go's WriteProfile doc
// comment), is exactly the "byte-identical re-encoding" requirement — and
// fails rather than silently overwriting committed provenance on any
// difference.
func WriteProfileFromInput(in ProfileInput) (*wirefixture.Profile, error) {
	if err := validateProfileInput(in); err != nil {
		return nil, err
	}

	hash := in.ConfigSHA256
	if in.ConfigFile != "" {
		data, err := os.ReadFile(in.ConfigFile)
		if err != nil {
			return nil, errInvalidMetadata("read config file for hashing", err)
		}
		h, err := wirefixture.ClickHouseConfigElementSHA256(data)
		if err != nil {
			return nil, errInvalidMetadata("compute clickhouse config element hash", err)
		}
		hash = h
	}

	sessionPaths := append([]string(nil), in.SessionPaths...)
	sort.Strings(sessionPaths)

	profile := wirefixture.Profile{
		SchemaVersion:        wirefixture.SchemaVersion,
		Line:                 in.Line,
		TrackedImage:         in.TrackedImage,
		ClickHouseRepository: in.ClickHouseRepository,
		ClickHouseTag:        in.ClickHouseTag,
		ClickHouseCommit:     in.ClickHouseCommit,
		ClickHouseSourceBlobs: map[string]string{
			wirefixture.BlobKeyLDAPClientCPP:             in.BlobLDAPClientCPP,
			wirefixture.BlobKeyLDAPClientH:               in.BlobLDAPClientH,
			wirefixture.BlobKeyLDAPAccessStorageCPP:      in.BlobLDAPAccessStorageCPP,
			wirefixture.BlobKeyExternalAuthenticatorsCPP: in.BlobExternalAuthenticatorsCPP,
		},
		OpenLDAPRepository:            in.OpenLDAPRepository,
		OpenLDAPPin:                   in.OpenLDAPPin,
		OpenLDAPVersion:               in.OpenLDAPVersion,
		CanonicalConfigPath:           in.ConfigPath,
		ClickHouseConfigElementSHA256: hash,
		CaptureToolSchemaVersion:      CaptureToolSchemaVersion,
		SessionPaths:                  sessionPaths,
	}

	if err := os.MkdirAll(in.OutDir, 0o700); err != nil {
		return nil, errInvalidMetadata("create profile output directory", err)
	}
	path := wirefixture.ProfilePath(in.OutDir)

	existing, err := wirefixture.ReadProfile(path)
	switch {
	case err == nil:
		if !reflect.DeepEqual(existing, profile) {
			return nil, errProfileDrift(in.Line)
		}
		return &profile, nil
	case errors.Is(err, os.ErrNotExist):
		// No committed profile.json yet for this line — proceed to write.
	default:
		return nil, errInvalidMetadata("read existing profile.json", err)
	}

	if err := wirefixture.WriteProfile(path, profile); err != nil {
		return nil, errInvalidMetadata("write profile.json", err)
	}
	return &profile, nil
}

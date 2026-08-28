package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/altinity/go-mcp-oauth-sdk/oauth"
)

// operatorGuideYAMLPath is the exact file docs/ch-oauth-ldap-operator-guide.md
// (plan-19p5.md §21.1/§21.3) copies its YAML fence from verbatim. Keeping the
// path as a named constant means every test below and the future docs
// contract test (§21.4) can point at the same file without repeating the
// literal path.
const operatorGuideYAMLPath = "testdata/operator-guide.yaml"

// validConfig returns a *Config that satisfies every validateConfig rule,
// so individual tests can copy it and break exactly one rule at a time.
func validConfig() *Config {
	cfg := defaultConfig()
	cfg.OAuth.ExpectedIssuer = "https://example.auth0.com/"
	cfg.OAuth.ExpectedAudiences = []string{"clickhouse", "mcp"}
	cfg.Roles.RolesFilter = "^ch_[A-Za-z0-9_]+$"
	cfg.LDAP = LDAPConfig{
		Listen:           ":389",
		UserBaseDN:       "ou=users,dc=altinity,dc=internal",
		GroupBaseDN:      "ou=groups,dc=altinity,dc=internal",
		UserRDNAttribute: "uid",
		RoleCNPrefix:     "clickhouse_",
	}
	return cfg
}

func TestLoadConfigDefaults(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	require.Equal(t, 60*time.Second, cfg.OAuth.VerifierLeeway)
	require.Equal(t, 5*time.Minute, cfg.OAuth.JWKSCacheLifetime)
	require.Equal(t, 30*time.Second, cfg.OAuth.TokenCacheLifetime)
	require.Equal(t, "lowercase_equal", cfg.Identity.UsernameMatch)
	require.True(t, cfg.Identity.RequireEmailVerified)
}

// --- oauth issuer/jwks_url either-or rule ---

func TestValidateConfigRejectsBothEmptyIssuerAndJWKSURL(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.OAuth.ExpectedIssuer = ""
	cfg.OAuth.JWKSURL = ""
	err := validateConfig(cfg)
	require.ErrorContains(t, err, "oauth: either issuer or jwks_url must be set")
}

func TestValidateConfigRejectsWhitespaceOnlyIssuerAndJWKSURL(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.OAuth.ExpectedIssuer = "   "
	cfg.OAuth.JWKSURL = "\t"
	err := validateConfig(cfg)
	require.ErrorContains(t, err, "oauth: either issuer or jwks_url must be set")
}

func TestValidateConfigAcceptsIssuerOnly(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.OAuth.ExpectedIssuer = "https://example.auth0.com/"
	cfg.OAuth.JWKSURL = ""
	require.NoError(t, validateConfig(cfg))
}

func TestValidateConfigAcceptsJWKSURLOnly(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.OAuth.ExpectedIssuer = ""
	cfg.OAuth.JWKSURL = "https://example.auth0.com/.well-known/jwks.json"
	require.NoError(t, validateConfig(cfg))
}

// --- verification.New-delegated checks ---

func TestValidateConfigRejectsEmptyAudiences(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.OAuth.ExpectedAudiences = nil
	err := validateConfig(cfg)
	require.ErrorContains(t, err, "audience")
}

func TestValidateConfigRejectsAudiencesWithOnlyEmptyEntries(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.OAuth.ExpectedAudiences = []string{"", "   "}
	err := validateConfig(cfg)
	require.ErrorContains(t, err, "audience")
}

func TestValidateConfigRejectsNegativeVerifierLeeway(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.OAuth.VerifierLeeway = -time.Second
	err := validateConfig(cfg)
	require.ErrorContains(t, err, "verifier_leeway")
}

func TestValidateConfigRejectsInvalidIdentityConfig(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.Identity.UsernameMatch = "not_a_real_match_mode"
	err := validateConfig(cfg)
	require.Error(t, err)
	require.ErrorContains(t, err, "match_mode")
}

// --- roles.New-delegated checks ---

func TestValidateConfigRejectsInvalidRolesFilter(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.Roles.RolesFilter = "[" // invalid regex
	err := validateConfig(cfg)
	require.ErrorContains(t, err, "roles_filter")
}

func TestValidateConfigRejectsInvalidRolesTransform(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.Roles.RolesTransform = "not a valid sed transform"
	err := validateConfig(cfg)
	require.ErrorContains(t, err, "roles_transform")
}

// --- LDAP base-DN parsing checks ---

func TestValidateConfigRejectsUnparseableUserBaseDN(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.LDAP.UserBaseDN = "not-a-dn"
	err := validateConfig(cfg)
	require.ErrorContains(t, err, "user_base_dn")
}

func TestValidateConfigRejectsUnparseableGroupBaseDN(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.LDAP.GroupBaseDN = "not-a-dn"
	err := validateConfig(cfg)
	require.ErrorContains(t, err, "group_base_dn")
}

// --- required LDAP scalar checks ---

func TestValidateConfigRejectsEmptyListen(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.LDAP.Listen = ""
	err := validateConfig(cfg)
	require.ErrorContains(t, err, "listen")
}

func TestValidateConfigRejectsEmptyUserBaseDN(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.LDAP.UserBaseDN = ""
	err := validateConfig(cfg)
	require.ErrorContains(t, err, "user_base_dn")
}

func TestValidateConfigRejectsEmptyGroupBaseDN(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.LDAP.GroupBaseDN = ""
	err := validateConfig(cfg)
	require.ErrorContains(t, err, "group_base_dn")
}

func TestValidateConfigRejectsEmptyUserRDNAttribute(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.LDAP.UserRDNAttribute = ""
	err := validateConfig(cfg)
	require.ErrorContains(t, err, "user_rdn_attribute")
}

func TestValidateConfigAcceptsFullyValidConfig(t *testing.T) {
	t.Parallel()
	require.NoError(t, validateConfig(validConfig()))
}

// --- exact conversion assertions ---

// TestToVerificationConfigExactMapping asserts every "Exact conversion"
// bullet from the phase-2 plan that targets verification.Config, field by
// field, plus the command-local negative-TTL default the plan requires
// (see defaultNegativeVerificationTTL).
func TestToVerificationConfigExactMapping(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.OAuth.ExpectedIssuer = "https://issuer.example/"
	cfg.OAuth.JWKSURL = "https://issuer.example/jwks.json"
	cfg.OAuth.ExpectedAudiences = []string{"clickhouse", "mcp"}
	cfg.OAuth.VerifierLeeway = 45 * time.Second
	cfg.OAuth.RequiredScopes = []string{"read", "write"}
	cfg.OAuth.JWKSCacheLifetime = 90 * time.Second
	cfg.OAuth.TokenCacheLifetime = 15 * time.Second
	cfg.OAuth.UsernameClaim = "email"
	cfg.Identity.UsernameMatch = "exact"
	cfg.Identity.RequireEmailVerified = false
	cfg.Identity.AllowedEmailDomains = []string{"example.com"}
	cfg.Identity.AllowedHostedDomains = []string{"example.com"}
	cfg.Identity.DeniedUsernames = []string{"default", "admin"}

	vc := cfg.toVerificationConfig()

	require.Equal(t, "https://issuer.example/", vc.ExpectedIssuer)
	require.Equal(t, "https://issuer.example/jwks.json", vc.JWKSURL)
	require.Equal(t, []string{"clickhouse", "mcp"}, vc.ExpectedAudiences)
	require.Equal(t, 45*time.Second, vc.VerifierLeeway)
	require.Equal(t, []string{"read", "write"}, vc.RequiredScopes)
	require.Equal(t, 90*time.Second, vc.JWKSCacheTTL)
	require.Equal(t, 15*time.Second, vc.PositiveTTL)
	// The core assertion the phase-2 plan calls out explicitly: the
	// generated NegativeTTL is exactly five minutes, always, regardless of
	// anything in YAML — there is no negative_ttl knob to set it from.
	require.Equal(t, 5*time.Minute, vc.NegativeTTL)
	require.Equal(t, defaultNegativeVerificationTTL, vc.NegativeTTL)

	require.Equal(t, "email", vc.Identity.UsernameClaim)
	require.Equal(t, "exact", vc.Identity.MatchMode)
	require.Equal(t, []string{"default", "admin"}, vc.Identity.DeniedUsernames)
	require.Equal(t, oauth.IdentityPolicy{
		RequireEmailVerified: false,
		AllowedEmailDomains:  []string{"example.com"},
		AllowedHostedDomains: []string{"example.com"},
	}, vc.Identity.ClaimPolicy)
}

// TestToVerificationConfigNegativeTTLIgnoresYAML proves there is no way for
// YAML content to change the negative TTL: even an empty/zero-value config
// still yields exactly five minutes, not the Go zero value that would
// otherwise disable reusable negative caching (see
// defaultNegativeVerificationTTL's doc comment).
func TestToVerificationConfigNegativeTTLIgnoresYAML(t *testing.T) {
	t.Parallel()
	cfg := &Config{}
	vc := cfg.toVerificationConfig()
	require.Equal(t, 5*time.Minute, vc.NegativeTTL)
	require.NotZero(t, vc.NegativeTTL)
}

// TestToRolesConfigExactMapping asserts the plan's oauth.groups_claim /
// roles_mapping / roles_filter / roles_transform -> roles.Config mapping.
func TestToRolesConfigExactMapping(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.OAuth.GroupsClaim = "roles"
	cfg.Roles.RolesMapping = map[string]string{
		"idp-readers":   "ch_readonly",
		"idp-engineers": "ch_engineer",
	}
	cfg.Roles.RolesFilter = "^ch_[A-Za-z0-9_]+$"
	cfg.Roles.RolesTransform = "s/^ch_//"

	rc := cfg.toRolesConfig()

	require.Equal(t, "roles", rc.GroupsClaim)
	require.Equal(t, map[string]string{
		"idp-readers":   "ch_readonly",
		"idp-engineers": "ch_engineer",
	}, rc.Mapping)
	require.Equal(t, "^ch_[A-Za-z0-9_]+$", rc.Filter)
	require.Equal(t, "s/^ch_//", rc.Transform)
}

// TestToLDAPConfigExactMapping asserts the plan's ldap.* -> internal/ldap.Config
// mapping.
func TestToLDAPConfigExactMapping(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.LDAP = LDAPConfig{
		Listen:           ":1389",
		UserBaseDN:       "ou=users,dc=altinity,dc=internal",
		GroupBaseDN:      "ou=groups,dc=altinity,dc=internal",
		UserRDNAttribute: "uid",
		RoleCNPrefix:     "clickhouse_",
	}

	lc := cfg.toLDAPConfig()

	require.Equal(t, ":1389", lc.Listen)
	require.Equal(t, "ou=users,dc=altinity,dc=internal", lc.UserBaseDN)
	require.Equal(t, "ou=groups,dc=altinity,dc=internal", lc.GroupBaseDN)
	require.Equal(t, "uid", lc.UserRDNAttribute)
	require.Equal(t, "clickhouse_", lc.RoleCNPrefix)
}

// TestLoadConfigParsesIssueVocabularyYAML loads the issue's exact example
// configuration (see "Configuration design" in the phase-2 plan) from a
// file and proves it activates and converts correctly end to end.
func TestLoadConfigParsesIssueVocabularyYAML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yamlContent := `
oauth:
  expected_issuer: https://example.auth0.com/
  jwks_url: ''
  expected_audiences:
    - clickhouse
    - mcp
  username_claim: email
  groups_claim: roles
  verifier_leeway: 60s
  required_scopes: []
  jwks_cache_lifetime: 1h
  token_cache_lifetime: 30s

identity:
  username_match: lowercase_equal
  require_email_verified: true
  allowed_email_domains: []
  allowed_hosted_domains: []
  denied_usernames:
    - default
    - admin

roles:
  roles_mapping:
    idp-readers: ch_readonly
    idp-engineers: ch_engineer
  roles_filter: '^ch_[A-Za-z0-9_]+$'
  roles_transform: ''

ldap:
  listen: ':389'
  user_base_dn: 'ou=users,dc=altinity,dc=internal'
  group_base_dn: 'ou=groups,dc=altinity,dc=internal'
  user_rdn_attribute: uid
  role_cn_prefix: 'clickhouse_'
`
	require.NoError(t, os.WriteFile(path, []byte(yamlContent), 0o600))

	cfg, err := LoadConfig(path)
	require.NoError(t, err)

	require.Equal(t, "https://example.auth0.com/", cfg.OAuth.ExpectedIssuer)
	require.Equal(t, []string{"clickhouse", "mcp"}, cfg.OAuth.ExpectedAudiences)
	require.Equal(t, "email", cfg.OAuth.UsernameClaim)
	require.Equal(t, "roles", cfg.OAuth.GroupsClaim)
	require.Equal(t, 60*time.Second, cfg.OAuth.VerifierLeeway)
	require.Equal(t, time.Hour, cfg.OAuth.JWKSCacheLifetime)
	require.Equal(t, 30*time.Second, cfg.OAuth.TokenCacheLifetime)

	require.Equal(t, "lowercase_equal", cfg.Identity.UsernameMatch)
	require.True(t, cfg.Identity.RequireEmailVerified)
	require.Equal(t, []string{"default", "admin"}, cfg.Identity.DeniedUsernames)

	require.Equal(t, map[string]string{
		"idp-readers":   "ch_readonly",
		"idp-engineers": "ch_engineer",
	}, cfg.Roles.RolesMapping)
	require.Equal(t, "^ch_[A-Za-z0-9_]+$", cfg.Roles.RolesFilter)

	require.Equal(t, ":389", cfg.LDAP.Listen)
	require.Equal(t, "ou=users,dc=altinity,dc=internal", cfg.LDAP.UserBaseDN)
	require.Equal(t, "ou=groups,dc=altinity,dc=internal", cfg.LDAP.GroupBaseDN)
	require.Equal(t, "uid", cfg.LDAP.UserRDNAttribute)
	require.Equal(t, "clickhouse_", cfg.LDAP.RoleCNPrefix)

	// This YAML has jwks_url empty but expected_issuer set: the either-or
	// rule must still accept it.
	require.NotEmpty(t, cfg.OAuth.ExpectedIssuer)
	require.Empty(t, cfg.OAuth.JWKSURL)

	vc := cfg.toVerificationConfig()
	require.Equal(t, 5*time.Minute, vc.NegativeTTL)
}

// --- operator-guide.yaml (plan-19p5.md §21.3/§21.4, A3) ---

// TestOperatorGuideYAML_LoadsThroughProductionLoadConfig loads
// testdata/operator-guide.yaml through the exact production LoadConfig entry
// point (config.go:101) and asserts every field the file sets, plus the
// derived verification/roles/ldap conversions. docs/ch-oauth-ldap-operator-
// guide.md's YAML fence (§21.3) is a verbatim copy of this file, so this test
// is the proof that the guide's example configuration actually
// parses/validates/converts under production code, not merely under eyeball
// review.
func TestOperatorGuideYAML_LoadsThroughProductionLoadConfig(t *testing.T) {
	t.Parallel()

	cfg, err := LoadConfig(operatorGuideYAMLPath)
	require.NoError(t, err)

	// oauth: expected_issuer + jwks_url both set, multiple
	// expected_audiences, username_claim, groups_claim, verifier/cache
	// settings.
	require.Equal(t, "https://tenant.example.auth0.com/", cfg.OAuth.ExpectedIssuer)
	require.Equal(t, "https://tenant.example.auth0.com/.well-known/jwks.json", cfg.OAuth.JWKSURL)
	require.Equal(t, []string{"clickhouse", "mcp"}, cfg.OAuth.ExpectedAudiences)
	require.Equal(t, "email", cfg.OAuth.UsernameClaim)
	require.Equal(t, "roles", cfg.OAuth.GroupsClaim)
	require.Equal(t, 60*time.Second, cfg.OAuth.VerifierLeeway)
	require.Empty(t, cfg.OAuth.RequiredScopes)
	require.Equal(t, 5*time.Minute, cfg.OAuth.JWKSCacheLifetime)
	require.Equal(t, 30*time.Second, cfg.OAuth.TokenCacheLifetime)

	// identity: username_match, require_email_verified,
	// allowed_email_domains, denied_usernames.
	require.Equal(t, "lowercase_equal", cfg.Identity.UsernameMatch)
	require.True(t, cfg.Identity.RequireEmailVerified)
	require.Equal(t, []string{"example.com"}, cfg.Identity.AllowedEmailDomains)
	require.Empty(t, cfg.Identity.AllowedHostedDomains)
	require.Equal(t, []string{"default", "admin"}, cfg.Identity.DeniedUsernames)

	// roles: roles_mapping, a restrictive roles_filter, a valid non-empty
	// roles_transform.
	require.Equal(t, map[string]string{
		"idp-readers":   "ch_readonly",
		"idp-engineers": "ch_engineer",
	}, cfg.Roles.RolesMapping)
	require.Equal(t, "^ch_[A-Za-z0-9_]+$", cfg.Roles.RolesFilter)
	require.Equal(t, "s/^ch_//", cfg.Roles.RolesTransform)

	// ldap: listen/user_base_dn/group_base_dn/user_rdn_attribute/role_cn_prefix.
	require.Equal(t, ":389", cfg.LDAP.Listen)
	require.Equal(t, "ou=users,dc=altinity,dc=internal", cfg.LDAP.UserBaseDN)
	require.Equal(t, "ou=groups,dc=altinity,dc=internal", cfg.LDAP.GroupBaseDN)
	require.Equal(t, "uid", cfg.LDAP.UserRDNAttribute)
	require.Equal(t, "clickhouse_", cfg.LDAP.RoleCNPrefix)

	// Conversions: LoadConfig's validateConfig already exercised real
	// verification.New/roles.New/ldap DN-parser construction (and returned
	// no error above), but assert the exact converted values too, so a
	// future accidental field-mapping regression in toVerificationConfig/
	// toRolesConfig/toLDAPConfig is caught by this same file rather than
	// only by the narrower field-by-field mapping tests above.
	vc := cfg.toVerificationConfig()
	require.Equal(t, "https://tenant.example.auth0.com/", vc.ExpectedIssuer)
	require.Equal(t, "https://tenant.example.auth0.com/.well-known/jwks.json", vc.JWKSURL)
	require.Equal(t, []string{"clickhouse", "mcp"}, vc.ExpectedAudiences)
	require.Equal(t, 60*time.Second, vc.VerifierLeeway)
	require.Equal(t, 5*time.Minute, vc.JWKSCacheTTL)
	require.Equal(t, 30*time.Second, vc.PositiveTTL)
	require.Equal(t, defaultNegativeVerificationTTL, vc.NegativeTTL)
	require.Equal(t, "email", vc.Identity.UsernameClaim)
	require.Equal(t, "lowercase_equal", vc.Identity.MatchMode)
	require.Equal(t, []string{"default", "admin"}, vc.Identity.DeniedUsernames)
	require.Equal(t, oauth.IdentityPolicy{
		RequireEmailVerified: true,
		AllowedEmailDomains:  []string{"example.com"},
		AllowedHostedDomains: []string{},
	}, vc.Identity.ClaimPolicy)

	rc := cfg.toRolesConfig()
	require.Equal(t, "roles", rc.GroupsClaim)
	require.Equal(t, "^ch_[A-Za-z0-9_]+$", rc.Filter)
	require.Equal(t, "s/^ch_//", rc.Transform)

	lc := cfg.toLDAPConfig()
	require.Equal(t, ":389", lc.Listen)
	require.Equal(t, "clickhouse_", lc.RoleCNPrefix)
}

// TestOperatorGuideYAML_StrictKnownFields is the test-only strictness A3
// requires: decode the exact same file with
// yaml.NewDecoder(...).KnownFields(true) directly against the production
// Config struct, and require no error. Production LoadConfig itself uses a
// lenient yaml.Unmarshal (config.go:102) and is deliberately not changed by
// this sub-task — this test adds strictness only as a documentation-
// provenance check on this one file, proving every key the guide's YAML
// fence uses is actually a real, spelled-correctly Config field rather than
// a silently-ignored typo. §21.4's docs contract test cites this test as the
// proof for every YAML fence copied from this file.
func TestOperatorGuideYAML_StrictKnownFields(t *testing.T) {
	t.Parallel()

	f, err := os.Open(operatorGuideYAMLPath)
	require.NoError(t, err)
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)

	var cfg Config
	require.NoError(t, dec.Decode(&cfg))

	// Sanity: KnownFields(true) alone would also pass on an empty file (no
	// keys to reject), so also confirm the strict decode actually populated
	// the struct — otherwise a truncated/renamed testdata file could pass
	// this test vacuously.
	require.Equal(t, "https://tenant.example.auth0.com/", cfg.OAuth.ExpectedIssuer)
	require.Equal(t, ":389", cfg.LDAP.Listen)

	t.Run("injected_unknown_key_fails_strict_decode_but_not_production_LoadConfig", func(t *testing.T) {
		t.Parallel()

		original, err := os.ReadFile(operatorGuideYAMLPath)
		require.NoError(t, err)

		// Inject a plausible-looking but nonexistent key inside the oauth
		// block, simulating an operator typo (e.g. "jwks_uri" instead of
		// "jwks_url") that a purely lenient decode would silently swallow.
		// Anchoring on "oauth:\n" (present exactly once, at file scope in
		// operator-guide.yaml) rather than prepending a second top-level
		// "oauth:" mapping avoids relying on YAML's unspecified duplicate-
		// key behavior.
		const anchor = "oauth:\n"
		originalStr := string(original)
		require.Contains(t, originalStr, anchor)
		mutated := []byte(strings.Replace(originalStr, anchor, anchor+"  unknown_typo_field: true\n", 1))

		dir := t.TempDir()
		path := filepath.Join(dir, "operator-guide-with-typo.yaml")
		require.NoError(t, os.WriteFile(path, mutated, 0o600))

		// Strict decode against the production Config struct must reject
		// the unknown key.
		mf, err := os.Open(path)
		require.NoError(t, err)
		defer mf.Close()
		strictDec := yaml.NewDecoder(mf)
		strictDec.KnownFields(true)
		var strictCfg Config
		strictErr := strictDec.Decode(&strictCfg)
		require.Error(t, strictErr)
		require.ErrorContains(t, strictErr, "unknown_typo_field")

		// Documented contrast: production LoadConfig (config.go:101-105)
		// uses a lenient yaml.Unmarshal and therefore does NOT fail on this
		// same mutated file — it silently ignores the unknown key. This
		// sub-task does not change config.go/main.go; this assertion exists
		// only to make that leniency an explicit, tested fact rather than
		// an implicit assumption.
		leniantCfg, err := LoadConfig(path)
		require.NoError(t, err, "production LoadConfig is documented-lenient and must not fail on an unknown key")
		require.Equal(t, "https://tenant.example.auth0.com/", leniantCfg.OAuth.ExpectedIssuer)
	})
}

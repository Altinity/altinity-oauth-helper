package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/altinity/go-mcp-oauth-sdk/oauth"

	"github.com/altinity/altinity-oauth-helper/internal/identity"
	"github.com/altinity/altinity-oauth-helper/internal/ldap"
	"github.com/altinity/altinity-oauth-helper/internal/roles"
	"github.com/altinity/altinity-oauth-helper/internal/verification"
)

// defaultNegativeVerificationTTL is the fixed negative-verification-cache
// TTL this command uses. The phase-2 public YAML contract deliberately does
// not expose a knob for it (see "Negative verification-cache TTL" in the
// phase-2 plan) — it is always this command-local constant, mirroring the
// concrete five-minute value the sibling ch-jwt-verify command already sets
// in its own defaultConfig. A zero value would effectively disable reusable
// negative caching (cache.get treats a zero TTL as already expired), so
// toVerificationConfig must always set this explicitly rather than leaving
// verification.Config.NegativeTTL at its Go zero value.
const defaultNegativeVerificationTTL = 5 * time.Minute

// Config is the YAML configuration consumed by the ch-oauth-ldap server.
// The four top-level blocks use the issue's exact external vocabulary (see
// "Configuration design" in the phase-2 plan) even though internally they
// convert into the already-existing verification.Config/identity.Config/
// roles.Config/internal_ldap.Config shapes ch-jwt-verify and phase-1
// already established.
type Config struct {
	OAuth    OAuthConfig    `yaml:"oauth"`
	Identity IdentityConfig `yaml:"identity"`
	Roles    RolesConfig    `yaml:"roles"`
	LDAP     LDAPConfig     `yaml:"ldap"`
}

// OAuthConfig mirrors the issue's `oauth:` block exactly. Unlike
// cmd/ch-jwt-verify's OAuthConfig, there is no legacy singular `audience`
// form and no `jwks_refresh_ahead` knob — phase 2 is a new binary with no
// backward-compatibility surface to preserve, and the plan explicitly says
// not to expose the existing no-op jwks_refresh_ahead in the new command.
type OAuthConfig struct {
	ExpectedIssuer     string        `yaml:"expected_issuer"`
	JWKSURL            string        `yaml:"jwks_url"`
	ExpectedAudiences  []string      `yaml:"expected_audiences"`
	UsernameClaim      string        `yaml:"username_claim"`
	GroupsClaim        string        `yaml:"groups_claim"`
	VerifierLeeway     time.Duration `yaml:"verifier_leeway"`
	RequiredScopes     []string      `yaml:"required_scopes"`
	JWKSCacheLifetime  time.Duration `yaml:"jwks_cache_lifetime"`
	TokenCacheLifetime time.Duration `yaml:"token_cache_lifetime"`
}

// IdentityConfig mirrors the issue's `identity:` block exactly, and converts
// into the same identity.Config / oauth.IdentityPolicy fields ch-jwt-verify
// already uses (see "Exact conversion" in the phase-2 plan).
type IdentityConfig struct {
	UsernameMatch        string   `yaml:"username_match"`
	RequireEmailVerified bool     `yaml:"require_email_verified"`
	AllowedEmailDomains  []string `yaml:"allowed_email_domains"`
	AllowedHostedDomains []string `yaml:"allowed_hosted_domains"`
	DeniedUsernames      []string `yaml:"denied_usernames"`
}

// RolesConfig mirrors the issue's `roles:` block exactly, and converts into
// roles.Config. oauth.groups_claim (which claim carries the source groups)
// lives under the `oauth:` block per the issue's vocabulary, not here.
type RolesConfig struct {
	RolesMapping   map[string]string `yaml:"roles_mapping"`
	RolesFilter    string            `yaml:"roles_filter"`
	RolesTransform string            `yaml:"roles_transform"`
}

// LDAPConfig mirrors the issue's `ldap:` block exactly, and converts into
// internal/ldap.Config.
type LDAPConfig struct {
	Listen           string `yaml:"listen"`
	UserBaseDN       string `yaml:"user_base_dn"`
	GroupBaseDN      string `yaml:"group_base_dn"`
	UserRDNAttribute string `yaml:"user_rdn_attribute"`
	RoleCNPrefix     string `yaml:"role_cn_prefix"`
}

// LoadConfig reads cfgPath as YAML layered over defaultConfig, then
// validates the result. Returns the parsed config plus any validation
// error; callers must not use a Config for which LoadConfig returned an
// error.
func LoadConfig(cfgPath string) (*Config, error) {
	cfg := defaultConfig()

	if cfgPath != "" {
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// defaultConfig sets values operators usually don't need to tune, mirroring
// the sibling ch-jwt-verify command's own defaults where the same concept
// exists.
func defaultConfig() *Config {
	return &Config{
		OAuth: OAuthConfig{
			VerifierLeeway:     60 * time.Second,
			JWKSCacheLifetime:  5 * time.Minute,
			TokenCacheLifetime: 30 * time.Second,
		},
		Identity: IdentityConfig{
			UsernameMatch:        "lowercase_equal",
			RequireEmailVerified: true,
		},
	}
}

// validateConfig rejects configuration before the caller ever listens (see
// "Fail config activation/startup" in the phase-2 plan). It combines
// command-level checks the shared packages deliberately don't own (the
// issuer/jwks_url either-or rule internal/verification.New does not
// enforce, and every ldap.* required-value check) with real construction
// calls into verification.New, roles.New and internal/ldap's DN parsers so
// an invalid identity config, an invalid roles_filter/roles_transform, or
// an unparseable configured base DN is caught here rather than surfacing
// only later during command composition.
func validateConfig(cfg *Config) error {
	if strings.TrimSpace(cfg.OAuth.ExpectedIssuer) == "" && strings.TrimSpace(cfg.OAuth.JWKSURL) == "" {
		return fmt.Errorf("oauth: either issuer or jwks_url must be set")
	}

	if strings.TrimSpace(cfg.LDAP.Listen) == "" {
		return fmt.Errorf("ldap: listen must be set")
	}
	if strings.TrimSpace(cfg.LDAP.UserBaseDN) == "" {
		return fmt.Errorf("ldap: user_base_dn must be set")
	}
	if strings.TrimSpace(cfg.LDAP.GroupBaseDN) == "" {
		return fmt.Errorf("ldap: group_base_dn must be set")
	}
	if strings.TrimSpace(cfg.LDAP.UserRDNAttribute) == "" {
		return fmt.Errorf("ldap: user_rdn_attribute must be set")
	}

	// Real construction, not a re-implementation of these packages'
	// validation rules: catches an empty/invalid expected_audiences list,
	// a negative verifier_leeway, and an invalid identity config (e.g. an
	// unknown username_match) exactly the way command composition later
	// would, but before any listener exists.
	if _, err := verification.New(cfg.toVerificationConfig()); err != nil {
		return err
	}

	// Catches an invalid roles_filter regex or malformed roles_transform
	// syntax the same way.
	if _, err := roles.New(cfg.toRolesConfig()); err != nil {
		return err
	}

	// Catches an unparseable configured user/group base DN the same way
	// internal/ldap.New itself would at command-composition time.
	if _, err := ldap.NewUserBaseDN(cfg.LDAP.UserBaseDN, cfg.LDAP.UserRDNAttribute); err != nil {
		return fmt.Errorf("ldap: invalid user_base_dn: %w", err)
	}
	if _, err := ldap.NewGroupBaseDN(cfg.LDAP.GroupBaseDN); err != nil {
		return fmt.Errorf("ldap: invalid group_base_dn: %w", err)
	}

	return nil
}

// toVerificationConfig builds the internal/verification.Config the shared
// verifier is constructed from. See "Exact conversion" in the phase-2 plan
// for the field-by-field mapping this implements.
func (cfg *Config) toVerificationConfig() verification.Config {
	return verification.Config{
		ExpectedIssuer:    cfg.OAuth.ExpectedIssuer,
		JWKSURL:           cfg.OAuth.JWKSURL,
		ExpectedAudiences: cfg.OAuth.ExpectedAudiences,
		VerifierLeeway:    cfg.OAuth.VerifierLeeway,
		RequiredScopes:    cfg.OAuth.RequiredScopes,
		JWKSCacheTTL:      cfg.OAuth.JWKSCacheLifetime,
		PositiveTTL:       cfg.OAuth.TokenCacheLifetime,
		// The public phase-2 YAML contract exposes no negative-cache knob;
		// this command always uses its own fixed default. See
		// defaultNegativeVerificationTTL's doc comment.
		NegativeTTL: defaultNegativeVerificationTTL,
		Identity: identity.Config{
			UsernameClaim:   cfg.OAuth.UsernameClaim,
			MatchMode:       cfg.Identity.UsernameMatch,
			DeniedUsernames: cfg.Identity.DeniedUsernames,
			ClaimPolicy: oauth.IdentityPolicy{
				RequireEmailVerified: cfg.Identity.RequireEmailVerified,
				AllowedEmailDomains:  cfg.Identity.AllowedEmailDomains,
				AllowedHostedDomains: cfg.Identity.AllowedHostedDomains,
			},
		},
	}
}

// toRolesConfig builds the internal/roles.Config the shared role pipeline
// is constructed from.
func (cfg *Config) toRolesConfig() roles.Config {
	return roles.Config{
		GroupsClaim: cfg.OAuth.GroupsClaim,
		Mapping:     cfg.Roles.RolesMapping,
		Filter:      cfg.Roles.RolesFilter,
		Transform:   cfg.Roles.RolesTransform,
	}
}

// toLDAPConfig builds the internal/ldap.Config the LDAP server is
// constructed from.
func (cfg *Config) toLDAPConfig() ldap.Config {
	return ldap.Config{
		Listen:           cfg.LDAP.Listen,
		UserBaseDN:       cfg.LDAP.UserBaseDN,
		GroupBaseDN:      cfg.LDAP.GroupBaseDN,
		UserRDNAttribute: cfg.LDAP.UserRDNAttribute,
		RoleCNPrefix:     cfg.LDAP.RoleCNPrefix,
	}
}

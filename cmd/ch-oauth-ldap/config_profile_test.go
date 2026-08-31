//go:build phase3profile

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// This file is config_legacy_test.go's phase3profile analog: assertions
// that either name internal/ldap/profile.Config directly or depend on the
// replacement backend's own validateLDAPBackendConfig error wrapping (see
// ldap_backend_phase3profile.go), plus the narrowing pairs proving the
// replacement's restricted DN/attribute grammar actually rejects forms the
// legacy backend accepts (config_legacy_test.go's "Accepts...Legacy..."
// tests are this file's other half of each pair).

// TestToProfileConfigExactMapping asserts the plan's ldap.* ->
// internal/ldap/profile.Config mapping. Unlike TestToLDAPConfigExactMapping
// (config_legacy_test.go), there is no Listen field to assert on: this
// package deliberately never maps cfg.LDAP.Listen into profile.Config (see
// internal/ldap/profile/doc.go and ldap_backend_phase3profile.go) —
// ldap.listen stays command-owned regardless of which backend is selected.
func TestToProfileConfigExactMapping(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.LDAP = LDAPConfig{
		Listen:           ":1389",
		UserBaseDN:       "ou=users,dc=altinity,dc=internal",
		GroupBaseDN:      "ou=groups,dc=altinity,dc=internal",
		UserRDNAttribute: "uid",
		RoleCNPrefix:     "clickhouse_",
	}

	pc := cfg.toProfileConfig()

	require.Equal(t, "ou=users,dc=altinity,dc=internal", pc.UserBaseDN)
	require.Equal(t, "ou=groups,dc=altinity,dc=internal", pc.GroupBaseDN)
	require.Equal(t, "uid", pc.UserRDNAttribute)
	require.Equal(t, "clickhouse_", pc.RoleCNPrefix)
}

// TestOperatorGuideYAML_LDAPBackendMapping is
// TestOperatorGuideYAML_LoadsThroughProductionLoadConfig's (config_test.go)
// phase3profile-backend addendum: it loads the same operator-guide.yaml
// through the exact production LoadConfig entry point and asserts the
// replacement toProfileConfig mapping. There is no Listen assertion here —
// profile.Config has no Listen field (see config_legacy_test.go's analog
// for the legacy side, which does assert Listen).
func TestOperatorGuideYAML_LDAPBackendMapping(t *testing.T) {
	t.Parallel()

	cfg, err := LoadConfig(operatorGuideYAMLPath)
	require.NoError(t, err)

	pc := cfg.toProfileConfig()
	require.Equal(t, "ou=users,dc=altinity,dc=internal", pc.UserBaseDN)
	require.Equal(t, "ou=groups,dc=altinity,dc=internal", pc.GroupBaseDN)
	require.Equal(t, "uid", pc.UserRDNAttribute)
	require.Equal(t, "clickhouse_", pc.RoleCNPrefix)
}

// TestValidateConfigRejectsUnparseableUserBaseDN pins the replacement
// backend's own validateLDAPBackendConfig wrapping around
// profile.ValidateConfig's fixed, non-credential sentinel error (see
// ldap_backend_phase3profile.go and internal/ldap/profile/config.go's
// errUserBaseDNInvalid) — note the exact wording differs from the legacy
// backend's ("user base DN" vs. "user_base_dn"), which is why this
// assertion cannot live in the shared, untagged config_test.go.
func TestValidateConfigRejectsUnparseableUserBaseDN(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.LDAP.UserBaseDN = "not-a-dn"
	err := validateConfig(cfg)
	require.ErrorContains(t, err, "user base DN")
}

// TestValidateConfigRejectsUnparseableGroupBaseDN is
// TestValidateConfigRejectsUnparseableUserBaseDN's group-base counterpart.
func TestValidateConfigRejectsUnparseableGroupBaseDN(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.LDAP.GroupBaseDN = "not-a-dn"
	err := validateConfig(cfg)
	require.ErrorContains(t, err, "group base DN")
}

// TestValidateConfigRejectsMultiValuedRDNGroupBase proves the command's own
// validateConfig, under -tags=phase3profile, actually enforces
// internal/ldap/profile's restricted DN grammar rather than merely calling
// into it vacuously: a base DN using an unescaped '+' (multi-valued RDN) —
// which config_legacy_test.go's
// TestValidateConfigAcceptsLegacyPermissiveMultiValuedRDNBase proves the
// legacy backend accepts — is rejected here (narrowing row 5, phase-3
// plan).
func TestValidateConfigRejectsMultiValuedRDNGroupBase(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.LDAP.GroupBaseDN = "ou=groups+ou=extra,dc=altinity,dc=internal"
	err := validateConfig(cfg)
	require.Error(t, err)
	require.ErrorContains(t, err, "group base DN")
}

// TestValidateConfigRejectsNonDescriptorUserRDNAttribute proves the
// command's own validateConfig, under -tags=phase3profile, enforces
// internal/ldap/profile's UserRDNAttribute descriptor-grammar check
// (ValidAttributeDescriptor: ^[A-Za-z][A-Za-z0-9-]*$) — a leading-digit
// value config_legacy_test.go's
// TestValidateConfigAcceptsLegacyPermissiveUserRDNAttribute proves the
// legacy backend accepts is rejected here (narrowing row 10, phase-3
// plan).
func TestValidateConfigRejectsNonDescriptorUserRDNAttribute(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.LDAP.UserRDNAttribute = "1uid"
	err := validateConfig(cfg)
	require.Error(t, err)
	require.ErrorContains(t, err, "attribute-type descriptor")
}

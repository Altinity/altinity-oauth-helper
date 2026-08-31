package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// This file holds assertions that name internal/ldap/profile.Config
// directly or depend on the LDAP backend's own validateLDAPBackendConfig
// error wrapping (see ldap_backend.go), plus the deliberate DN/attribute
// grammar narrowing rows the phase-3 plan accepted (values the legacy
// internal/ldap backend used to accept but the profile's restricted grammar
// rejects).

// TestToProfileConfigExactMapping asserts the plan's ldap.* ->
// internal/ldap/profile.Config mapping. There is no Listen field to assert
// on: this package deliberately never maps cfg.LDAP.Listen into
// profile.Config (see internal/ldap/profile/doc.go and ldap_backend.go) —
// ldap.listen stays command-owned.
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
// LDAP-backend addendum: it loads the same operator-guide.yaml through the
// exact production LoadConfig entry point and asserts the toProfileConfig
// mapping. There is no Listen assertion here — profile.Config has no Listen
// field.
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

// TestValidateConfigRejectsUnparseableUserBaseDN pins the LDAP backend's own
// validateLDAPBackendConfig wrapping around profile.ValidateConfig's fixed,
// non-credential sentinel error (see ldap_backend.go and
// internal/ldap/profile/config.go's errUserBaseDNInvalid).
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
// validateConfig actually enforces internal/ldap/profile's restricted DN
// grammar rather than merely calling into it vacuously: a base DN using an
// unescaped '+' (multi-valued RDN) — a value the deleted legacy internal/ldap
// backend used to accept — is rejected here (narrowing row 5, phase-3 plan).
func TestValidateConfigRejectsMultiValuedRDNGroupBase(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.LDAP.GroupBaseDN = "ou=groups+ou=extra,dc=altinity,dc=internal"
	err := validateConfig(cfg)
	require.Error(t, err)
	require.ErrorContains(t, err, "group base DN")
}

// TestValidateConfigRejectsNonDescriptorUserRDNAttribute proves the
// command's own validateConfig enforces internal/ldap/profile's
// UserRDNAttribute descriptor-grammar check (ValidAttributeDescriptor:
// ^[A-Za-z][A-Za-z0-9-]*$) — a leading-digit value the deleted legacy
// internal/ldap backend used to accept is rejected here (narrowing row 10,
// phase-3 plan).
func TestValidateConfigRejectsNonDescriptorUserRDNAttribute(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.LDAP.UserRDNAttribute = "1uid"
	err := validateConfig(cfg)
	require.Error(t, err)
	require.ErrorContains(t, err, "attribute-type descriptor")
}

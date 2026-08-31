//go:build !phase3profile

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// This file holds assertions that either name the legacy
// internal/ldap.Config type directly or depend on the legacy backend's
// exact validateLDAPBackendConfig error wrapping (see
// ldap_backend_legacy.go) — both of which stop being true the moment
// -tags=phase3profile selects the replacement backend instead. See
// config_phase3profile_test.go for this file's phase3profile analogs.

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

// TestValidateConfigRejectsUnparseableUserBaseDN pins the legacy backend's
// exact validateLDAPBackendConfig wrapping ("ldap: invalid user_base_dn:
// %w" — see ldap_backend_legacy.go), which the ordinary (untagged) build
// selects.
func TestValidateConfigRejectsUnparseableUserBaseDN(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.LDAP.UserBaseDN = "not-a-dn"
	err := validateConfig(cfg)
	require.ErrorContains(t, err, "user_base_dn")
}

// TestValidateConfigRejectsUnparseableGroupBaseDN is
// TestValidateConfigRejectsUnparseableUserBaseDN's group-base counterpart.
func TestValidateConfigRejectsUnparseableGroupBaseDN(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.LDAP.GroupBaseDN = "not-a-dn"
	err := validateConfig(cfg)
	require.ErrorContains(t, err, "group_base_dn")
}

// TestValidateConfigAcceptsLegacyPermissiveMultiValuedRDNBase proves the
// legacy backend's github.com/go-ldap/ldap/v3-based DN parsing accepts a
// base DN using an unescaped '+' (a multi-valued RDN) — the exact
// Phase-3-visible narrowing internal/ldap/profile's restricted grammar
// deliberately rejects (see internal/ldap/profile/dn.go's package doc
// comment, narrowing row 5 in the phase-3 plan). This is the legacy half of
// the "restricted group-base validation" pair; see
// TestValidateConfigRejectsMultiValuedRDNGroupBase in
// config_phase3profile_test.go for the phase3profile side proving the same
// value is rejected there.
func TestValidateConfigAcceptsLegacyPermissiveMultiValuedRDNBase(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.LDAP.GroupBaseDN = "ou=groups+ou=extra,dc=altinity,dc=internal"
	require.NoError(t, validateConfig(cfg))
}

// TestOperatorGuideYAML_LDAPBackendMapping is
// TestOperatorGuideYAML_LoadsThroughProductionLoadConfig's (config_test.go)
// legacy-backend addendum: it loads the same operator-guide.yaml through
// the exact production LoadConfig entry point and asserts the legacy
// toLDAPConfig mapping, including Listen (which has no profile.Config
// counterpart — see config_phase3profile_test.go's analog).
func TestOperatorGuideYAML_LDAPBackendMapping(t *testing.T) {
	t.Parallel()

	cfg, err := LoadConfig(operatorGuideYAMLPath)
	require.NoError(t, err)

	lc := cfg.toLDAPConfig()
	require.Equal(t, ":389", lc.Listen)
	require.Equal(t, "ou=users,dc=altinity,dc=internal", lc.UserBaseDN)
	require.Equal(t, "ou=groups,dc=altinity,dc=internal", lc.GroupBaseDN)
	require.Equal(t, "uid", lc.UserRDNAttribute)
	require.Equal(t, "clickhouse_", lc.RoleCNPrefix)
}

// TestValidateConfigAcceptsLegacyPermissiveUserRDNAttribute proves the
// legacy backend only requires UserRDNAttribute to be non-empty/non-
// whitespace — a leading-digit value the replacement profile's descriptor
// grammar rejects (ValidAttributeDescriptor, internal/ldap/profile/dn.go)
// is accepted here. See TestValidateConfigRejectsNonDescriptorUserRDNAttribute
// in config_phase3profile_test.go for the phase3profile side.
func TestValidateConfigAcceptsLegacyPermissiveUserRDNAttribute(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.LDAP.UserRDNAttribute = "1uid"
	require.NoError(t, validateConfig(cfg))
}

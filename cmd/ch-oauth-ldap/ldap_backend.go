//go:build phase3profile

// This file is the temporary issue #33 phase 3 replacement LDAP backend
// adapter, selected only when the command is built with -tags=phase3profile
// (see main.go's package doc comment). It is the only file in this command
// that imports internal/ldap/profile, and it owns the command LDAPConfig ->
// profile.Config mapping, profile.ValidateConfig, and profile.New. There is
// no fallback path to the legacy backend: a phase3profile build never
// touches internal/ldap.
//
// ldap.listen remains command-owned throughout Phase 3 — profile.Config
// deliberately has no Listen field (see internal/ldap/profile/doc.go), so
// this file does not map cfg.LDAP.Listen into it; main.go's net.Listen call
// is unaffected by which backend is selected.
//
// This is temporary Phase 3 certification scaffolding: Phase 4 deletes the
// phase3profile tag entirely and promotes this file's logic (minus the
// build constraint) to ordinary, permanent production code, at which point
// ldap_backend_legacy.go and internal/ldap's non-test implementation are
// deleted.
package main

import (
	"context"
	"fmt"

	"github.com/altinity/altinity-oauth-helper/internal/ldap/profile"
	"github.com/altinity/altinity-oauth-helper/internal/roles"
	"github.com/altinity/altinity-oauth-helper/internal/verification"
)

// toProfileConfig builds the internal/ldap/profile.Config the Phase 3
// replacement LDAP server is constructed from, mirroring
// ldap_backend_legacy.go's toLDAPConfig field-for-field (RoleCNPrefix
// included) except that Listen has no profile.Config counterpart to map
// into.
func (cfg *Config) toProfileConfig() profile.Config {
	return profile.Config{
		UserBaseDN:       cfg.LDAP.UserBaseDN,
		GroupBaseDN:      cfg.LDAP.GroupBaseDN,
		UserRDNAttribute: cfg.LDAP.UserRDNAttribute,
		RoleCNPrefix:     cfg.LDAP.RoleCNPrefix,
	}
}

// validateLDAPBackendConfig applies the Phase 3 replacement profile's own
// restricted-grammar startup validation (profile.ValidateConfig): real
// construction against the mapped profile.Config, so an unparseable
// configured base DN or a UserRDNAttribute that fails the profile's
// descriptor-grammar check (a deliberate Phase-3-visible narrowing versus
// the legacy backend — see internal/ldap/profile/config.go's
// errUserRDNAttributeInvalid) is caught here at command-composition time.
func validateLDAPBackendConfig(cfg *Config) error {
	if err := profile.ValidateConfig(cfg.toProfileConfig()); err != nil {
		return fmt.Errorf("ldap: %w", err)
	}
	return nil
}

// newLDAPServer constructs the Phase 3 replacement internal/ldap/profile.Server
// backend that a -tags=phase3profile build selects. rootCtx, v and r are
// threaded straight through to profile.New unchanged.
func newLDAPServer(rootCtx context.Context, cfg *Config, v *verification.Verifier, r *roles.Pipeline) (ldapServer, error) {
	return profile.New(rootCtx, cfg.toProfileConfig(), v, r)
}

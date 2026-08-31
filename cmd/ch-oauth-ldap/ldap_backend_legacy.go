//go:build !phase3profile

// This file is the ordinary (untagged) LDAP backend adapter for issue #33
// phase 3's temporary phase3profile build-tag seam (see main.go's package
// doc comment). It is the only file in this command that imports
// internal/ldap, and it owns every legacy-specific piece of command
// composition: the exact command LDAPConfig -> internal/ldap.Config
// conversion, the legacy DN-constructor startup validation, and legacy
// server construction. Nothing here changes production behavior — this is
// the pre-existing logic previously inlined in config.go/main.go, moved
// verbatim behind a name every ordinary build still resolves to, so the
// ordinary production closure stays byte-for-byte identical to what it was
// before this seam existed.
//
// Phase 4 deletes this file (and ldap_backend_phase3profile.go's tag)
// once the profile backend becomes the only, ordinary implementation.
package main

import (
	"context"
	"fmt"

	"github.com/altinity/altinity-oauth-helper/internal/ldap"
	"github.com/altinity/altinity-oauth-helper/internal/roles"
	"github.com/altinity/altinity-oauth-helper/internal/verification"
)

// validateLDAPBackendConfig applies the legacy internal/ldap package's
// startup DN validation: real construction calls into
// ldap.NewUserBaseDN/ldap.NewGroupBaseDN so an unparseable configured base
// DN is caught here rather than surfacing only later during command
// composition, exactly matching the pre-seam validateConfig behavior (error
// text included).
func validateLDAPBackendConfig(cfg *Config) error {
	if _, err := ldap.NewUserBaseDN(cfg.LDAP.UserBaseDN, cfg.LDAP.UserRDNAttribute); err != nil {
		return fmt.Errorf("ldap: invalid user_base_dn: %w", err)
	}
	if _, err := ldap.NewGroupBaseDN(cfg.LDAP.GroupBaseDN); err != nil {
		return fmt.Errorf("ldap: invalid group_base_dn: %w", err)
	}
	return nil
}

// toLDAPConfig builds the internal/ldap.Config the legacy LDAP server is
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

// newLDAPServer constructs the legacy internal/ldap.Server backend that
// every ordinary (untagged) build selects. rootCtx, v and r are threaded
// straight through to ldap.New unchanged.
func newLDAPServer(rootCtx context.Context, cfg *Config, v *verification.Verifier, r *roles.Pipeline) (ldapServer, error) {
	return ldap.New(rootCtx, cfg.toLDAPConfig(), v, r)
}

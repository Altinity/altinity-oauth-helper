// This file is the ordinary, permanent LDAP backend adapter for
// cmd/ch-oauth-ldap (issue #33 phase 4 production cutover): it is the only
// file in this command that imports internal/ldap/profile, and it owns the
// command LDAPConfig -> profile.Config mapping, profile.ValidateConfig,
// profile.New, and the minimal ldapServer composition interface run() (see
// main.go) depends on. There is exactly one production LDAP backend —
// internal/ldap/profile.Server — with no build tag, no runtime selector, and
// no fallback path: the legacy internal/ldap package and its command adapter
// were deleted in this same cutover.
//
// ldap.listen stays command-owned: profile.Config deliberately has no Listen
// field (see internal/ldap/profile/doc.go), so this file does not map
// cfg.LDAP.Listen into it; main.go's net.Listen call is unaffected by this
// package's LDAP backend.
package main

import (
	"context"
	"fmt"
	"net"

	"github.com/altinity/altinity-oauth-helper/internal/ldap/profile"
	"github.com/altinity/altinity-oauth-helper/internal/roles"
	"github.com/altinity/altinity-oauth-helper/internal/verification"
)

// ldapServer is the minimal backend surface run() depends on:
// internal/ldap/profile.Server implements it.
type ldapServer interface {
	Serve(net.Listener) error
	Stop()
}

// toProfileConfig builds the internal/ldap/profile.Config the LDAP server is
// constructed from, field-for-field, except that Listen has no
// profile.Config counterpart to map into (see this file's doc comment).
func (cfg *Config) toProfileConfig() profile.Config {
	return profile.Config{
		UserBaseDN:       cfg.LDAP.UserBaseDN,
		GroupBaseDN:      cfg.LDAP.GroupBaseDN,
		UserRDNAttribute: cfg.LDAP.UserRDNAttribute,
		RoleCNPrefix:     cfg.LDAP.RoleCNPrefix,
	}
}

// validateLDAPBackendConfig applies the profile's own restricted-grammar
// startup validation (profile.ValidateConfig): real construction against the
// mapped profile.Config, so an unparseable configured base DN or a
// UserRDNAttribute that fails the profile's descriptor-grammar check (see
// internal/ldap/profile/config.go's errUserRDNAttributeInvalid) is caught
// here at command-composition time.
func validateLDAPBackendConfig(cfg *Config) error {
	if err := profile.ValidateConfig(cfg.toProfileConfig()); err != nil {
		return fmt.Errorf("ldap: %w", err)
	}
	return nil
}

// newLDAPServer constructs the internal/ldap/profile.Server backend this
// command always selects. rootCtx, v and r are threaded straight through to
// profile.New unchanged.
func newLDAPServer(rootCtx context.Context, cfg *Config, v *verification.Verifier, r *roles.Pipeline) (ldapServer, error) {
	return profile.New(rootCtx, cfg.toProfileConfig(), v, r)
}

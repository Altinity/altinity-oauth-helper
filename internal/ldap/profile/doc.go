// Package profile is the Phase 2 first-party ClickHouse LDAP compatibility
// profile for issue #33 — a small, bounded compatibility implementation of
// the documented ClickHouse LDAP wire shape (see
// docs/clickhouse-ldap-wire-profile.md), not a general LDAP server. Its
// scope is fixed by ADR #32: LDAPv3 simple Bind, the one documented
// restricted Search shape, and nothing generic (no routing, no recursive
// filter evaluation, no request/Cancel/Abandon scheduling, no second
// general BER packet-tree library).
//
// # Phase 2 status
//
// Implementation and tests exist in this package, but as of Phase 2 it is
// production-inert:
//
//   - cmd/ch-oauth-ldap does not import it —
//     TestDependencyContract_ProfileImplementationIsNotProduction fails the
//     build if it ever appears in that command's dependency closure before
//     Phase 4;
//   - it carries no production ClickHouse traffic; the shipping server
//     remains internal/ldap's existing implementation, driven by
//     third_party/goldap and third_party/ldapserver;
//   - Config (introduced alongside the server implementation) deliberately
//     has no Listen field — this package never calls net.Listen itself, so
//     that omission is not a gap to fill later. The caller owns the address
//     and hands Server.Serve an already-listening net.Listener, exactly as
//     cmd/ch-oauth-ldap's ldap.listen already does for the current server.
//
// Phase 4 is the only phase authorized to import this package from
// cmd/ch-oauth-ldap, switch command config conversion to profile.Config,
// replace the old DN-constructor startup validation with
// profile.ValidateConfig, and delete internal/ldap's non-test
// implementation. No file in this package moves during that cutover; the
// package itself already sits at its permanent import path.
package profile

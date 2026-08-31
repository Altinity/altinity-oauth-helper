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
//     build if it ever appears in that command's ordinary (untagged)
//     dependency closure before Phase 4;
//   - it carries no production ClickHouse traffic; the shipping server
//     remains internal/ldap's existing implementation, driven by
//     third_party/goldap and third_party/ldapserver;
//   - Config (introduced alongside the server implementation) deliberately
//     has no Listen field — this package never calls net.Listen itself, so
//     that omission is not a gap to fill later. The caller owns the address
//     and hands Server.Serve an already-listening net.Listener, exactly as
//     cmd/ch-oauth-ldap's ldap.listen already does for the current server.
//
// # Phase 3 status — temporary tagged import, not yet production
//
// Issue #33 phase 3 adds a temporary, compile-time-only exception to the
// "cmd/ch-oauth-ldap does not import it" rule above: cmd/ch-oauth-ldap's
// ldap_backend_phase3profile.go (guarded by `//go:build phase3profile`)
// imports this package to map command config into profile.Config, call
// profile.ValidateConfig, and construct profile.New — but ONLY when the
// command is built with `-tags=phase3profile`, which no shipped production
// artifact does. The ordinary (untagged) build still compiles
// ldap_backend_legacy.go instead, importing internal/ldap exactly as
// before, so TestDependencyContract_ProfileImplementationIsNotProduction's
// untagged assertion above remains true and unweakened throughout Phase 3.
// The tagged import exists solely so the replacement's real command
// composition, lifecycle, and configuration mapping can be certified
// ahead of cutover (see docs/clickhouse-ldap-wire-profile.md's Phase 3
// evidence) — it is not a second production entrypoint, there is no
// runtime selector, and no file in this package moves for it.
//
// Phase 4 removes the phase3profile build tag entirely: it deletes
// ldap_backend_legacy.go, deletes internal/ldap's non-test implementation,
// and promotes ldap_backend_phase3profile.go's logic (minus the build
// constraint) to cmd/ch-oauth-ldap's only, ordinary LDAP backend adapter —
// at which point TestDependencyContract_ProfileImplementationIsNotProduction
// itself inverts (see that test's own Amendment 5 doc comment) rather than
// being deleted. No file in this package moves during that cutover either;
// the package itself already sits at its permanent import path.
package profile

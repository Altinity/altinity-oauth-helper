// Package profile is the first-party ClickHouse LDAP compatibility profile
// for issue #33 — a small, bounded compatibility implementation of the
// documented ClickHouse LDAP wire shape (see
// docs/clickhouse-ldap-wire-profile.md), not a general LDAP server. Its
// scope is fixed by ADR #32: LDAPv3 simple Bind, the one documented
// restricted Search shape, and nothing generic (no routing, no recursive
// filter evaluation, no request/Cancel/Abandon scheduling, no second
// general BER packet-tree library).
//
// # Production status
//
// Since issue #33 phase 4's cutover, this package is cmd/ch-oauth-ldap's
// only, ordinary LDAP backend: cmd/ch-oauth-ldap/ldap_backend.go imports it
// unconditionally (no build tag, no runtime selector) to map command config
// into profile.Config, call profile.ValidateConfig, and construct
// profile.New — the composition every build and every shipped production
// image uses. TestDependencyContract_ProfileIsProductionImplementation
// fails the build if this package is ever missing from that command's
// ordinary production dependency closure. There is no second, legacy LDAP
// implementation left in the repository for a runtime or build-time
// selector to choose between.
//
// Config (introduced alongside the server implementation) deliberately has
// no Listen field — this package never calls net.Listen itself, so that
// omission is not a gap to fill later. The caller owns the address and
// hands Server.Serve an already-listening net.Listener.
//
// # History
//
// This package shipped inert in Phase 2 (implemented and tested, but not
// yet linked into cmd/ch-oauth-ldap) and was certified ahead of cutover in
// Phase 3 through a temporary `phase3profile` Go build tag on a
// since-deleted command adapter file — see
// docs/clickhouse-ldap-wire-profile.md's frozen §11.5 Phase 3 evidence
// record for exactly what that tagged composition certified. Phase 4
// deleted that tag, deleted the legacy internal/ldap implementation it
// stood in for, and promoted this package's composition to
// cmd/ch-oauth-ldap's only backend, as described above. No file in this
// package moved for any of that; it has sat at this same import path since
// Phase 2.
package profile

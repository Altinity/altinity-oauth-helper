package profile

import (
	"context"
	"errors"
	"strings"

	"github.com/altinity/go-mcp-oauth-sdk/oauth"

	"github.com/altinity/altinity-oauth-helper/internal/verification"
)

// Config is the profile server's public configuration. It deliberately has
// no Listen field: this package never calls net.Listen itself (see doc.go
// "Phase 2 status") — the caller owns the address and hands Server.Serve an
// already-listening net.Listener, so a Listen field would be dead
// configuration until Phase 4 wires a real caller.
type Config struct {
	// UserBaseDN is the configured LDAP user base DN every valid Bind DN
	// must sit exactly one RDN above (see ParseBindDN).
	UserBaseDN string
	// GroupBaseDN is the base every synthetic role group DN is rendered
	// under (see RenderGroupDN). It is used verbatim in rendered output —
	// never re-escaped or re-parsed — so ValidateConfig only checks that it
	// parses under the restricted grammar, not any further shape.
	GroupBaseDN string
	// UserRDNAttribute is the attribute type that must lead every Bind DN's
	// leading RDN (e.g. "uid"). Its configured spelling is preserved for
	// display/config-echo purposes; every comparison against a request's
	// attribute type is case-insensitive (strings.EqualFold), matching LDAP
	// attribute-type equivalence.
	UserRDNAttribute string
	// RoleCNPrefix is prepended to every mapped role name when rendering a
	// synthetic group DN's "cn" value. It is a transport-formatting prefix,
	// not a security boundary: it gets no semantic validation beyond the
	// safe rendering RenderGroupDN already applies to its output, matching
	// current production's treatment of the same setting.
	RoleCNPrefix string
}

// Verifier validates a presented (username, password) pair, where password
// is the caller-supplied Basic/simple-Bind credential (in production, a
// JWT). It is the same shape *verification.Verifier already implements, so
// production wiring needs no adapter.
type Verifier interface {
	Verify(ctx context.Context, requestedUsername, password string) (*verification.Result, error)
}

// RoleResolver maps a verified token's claims to the caller's mapped
// ClickHouse roles. It is the same shape *roles.Pipeline already
// implements, so production wiring needs no adapter.
type RoleResolver interface {
	Roles(claims *oauth.Claims) ([]string, error)
}

// Sentinel construction-validation errors. Each is a fixed, non-credential
// string: none of them echo the invalid UserBaseDN/GroupBaseDN/
// UserRDNAttribute value, matching New's "fixed non-credential construction
// error" guard (see the Phase 2 plan's "New construction guards") — a
// malformed operator config is diagnosed by which field failed, never by
// printing the field's actual configured text back into a log or error.
var (
	errUserBaseDNInvalid  = errors.New("profile: config: user base DN is empty or does not parse under the restricted DN grammar")
	errGroupBaseDNInvalid = errors.New("profile: config: group base DN is empty or does not parse under the restricted DN grammar")
	// errUserRDNAttributeInvalid backs a Phase-3-visible narrowing (#10 in
	// the plan's handoff list, added by Amendment 1): current production
	// (internal/ldap/dn.go, cmd/ch-oauth-ldap/config.go) only rejects an
	// empty/whitespace user_rdn_attribute. This profile additionally
	// requires it to match the descriptor grammar ValidAttributeDescriptor
	// enforces on every parsed DN attribute type — Phase 3 must explicitly
	// accept this narrowing before Phase 4 cuts over.
	errUserRDNAttributeInvalid = errors.New("profile: config: user RDN attribute is empty or is not a valid attribute-type descriptor")
)

// parsedConfig is the once-validated, immutable form of Config produced by
// parseConfig. A *parsedConfig is what the connection-owned state (see
// session.go) actually carries — never the raw Config — so a Bind/Search
// handler never re-parses a base DN per request.
type parsedConfig struct {
	userBase  DN
	groupBase DN
	// groupBaseText is GroupBaseDN's exact configured text, carried
	// alongside groupBase because RenderGroupDN renders synthetic group DNs
	// using the configured base verbatim, never groupBase.String()'s
	// canonicalized re-rendering.
	groupBaseText string
	// rdnAttribute preserves Config.UserRDNAttribute's exact configured
	// spelling; every comparison against it must use strings.EqualFold, per
	// Config.UserRDNAttribute's doc comment.
	rdnAttribute string
	rolePrefix   string
}

// parseConfig validates cfg against every ValidateConfig rule and, only on
// success, returns the immutable parsedConfig a connection carries for its
// whole lifetime. ValidateConfig itself is a thin wrapper over this
// function; New's defensive revalidation calls parseConfig directly so it
// gets the parsed form to store, not just a yes/no answer.
func parseConfig(cfg Config) (parsedConfig, error) {
	if strings.TrimSpace(cfg.UserBaseDN) == "" {
		return parsedConfig{}, errUserBaseDNInvalid
	}
	userBase, err := ParseDN(cfg.UserBaseDN)
	if err != nil {
		return parsedConfig{}, errUserBaseDNInvalid
	}

	if strings.TrimSpace(cfg.GroupBaseDN) == "" {
		return parsedConfig{}, errGroupBaseDNInvalid
	}
	groupBase, err := ParseDN(cfg.GroupBaseDN)
	if err != nil {
		return parsedConfig{}, errGroupBaseDNInvalid
	}

	if cfg.UserRDNAttribute == "" || !ValidAttributeDescriptor(cfg.UserRDNAttribute) {
		return parsedConfig{}, errUserRDNAttributeInvalid
	}

	return parsedConfig{
		userBase:      userBase,
		groupBase:     groupBase,
		groupBaseText: cfg.GroupBaseDN,
		rdnAttribute:  cfg.UserRDNAttribute,
		rolePrefix:    cfg.RoleCNPrefix,
	}, nil
}

// ValidateConfig reports whether cfg is valid, applying every rule
// parseConfig enforces:
//
//   - UserBaseDN and GroupBaseDN must be non-empty/non-whitespace-only and
//     parse under the restricted profile DN grammar (ParseDN) — this
//     rejects, among other malformed forms, a base using an unescaped '+'
//     (multi-valued RDN), a ';' RDN separator, a '#' BER-hexstring value, or
//     a dotted-decimal/OID attribute type;
//   - UserRDNAttribute must be non-empty and match the descriptor grammar
//     ^[A-Za-z][A-Za-z0-9-]*$ (ValidAttributeDescriptor) — a
//     Phase-3-visible narrowing versus current production, see
//     errUserRDNAttributeInvalid;
//   - RoleCNPrefix gets no semantic validation.
//
// New's defensive revalidation must apply this same check before any
// server can Serve.
func ValidateConfig(cfg Config) error {
	_, err := parseConfig(cfg)
	return err
}

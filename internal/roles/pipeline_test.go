package roles

import (
	"testing"

	"github.com/altinity/go-mcp-oauth-sdk/oauth"
	"github.com/stretchr/testify/require"
)

func claimsWithGroups(groups interface{}) *oauth.Claims {
	return &oauth.Claims{Extra: map[string]interface{}{"groups": groups}}
}

func TestRolesStringArrayGroupsClaim(t *testing.T) {
	t.Parallel()
	p, err := New(Config{})
	require.NoError(t, err)

	out, err := p.Roles(claimsWithGroups([]interface{}{"ch_readers", "ch_writers"}))
	require.NoError(t, err)
	require.Equal(t, []string{"ch_readers", "ch_writers"}, out)
}

func TestRolesAcceptsProgrammaticStringSliceGroups(t *testing.T) {
	t.Parallel()
	p, err := New(Config{})
	require.NoError(t, err)

	out, err := p.Roles(claimsWithGroups([]string{"ch_readers"}))
	require.NoError(t, err)
	require.Equal(t, []string{"ch_readers"}, out)
}

func TestRolesMissingGroupsClaimYieldsZeroRoles(t *testing.T) {
	t.Parallel()
	p, err := New(Config{})
	require.NoError(t, err)

	out, err := p.Roles(&oauth.Claims{Extra: map[string]interface{}{}})
	require.NoError(t, err)
	require.Empty(t, out)
}

func TestRolesEmptyGroupsArrayYieldsZeroRoles(t *testing.T) {
	t.Parallel()
	p, err := New(Config{})
	require.NoError(t, err)

	out, err := p.Roles(claimsWithGroups([]interface{}{}))
	require.NoError(t, err)
	require.Empty(t, out)
}

func TestRolesDeduplicatesGroupsPreservingFirstOccurrence(t *testing.T) {
	t.Parallel()
	p, err := New(Config{})
	require.NoError(t, err)

	out, err := p.Roles(claimsWithGroups([]interface{}{"a", "b", "a", "b", "c"}))
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b", "c"}, out)
}

func TestRolesRejectsMixedTypeArray(t *testing.T) {
	t.Parallel()
	p, err := New(Config{})
	require.NoError(t, err)

	_, err = p.Roles(claimsWithGroups([]interface{}{"a", 42}))
	require.ErrorIs(t, err, ErrMalformedGroupsClaim)
}

func TestRolesRejectsScalarGroupsClaim(t *testing.T) {
	t.Parallel()
	p, err := New(Config{})
	require.NoError(t, err)

	_, err = p.Roles(claimsWithGroups("not-an-array"))
	require.ErrorIs(t, err, ErrMalformedGroupsClaim)
}

func TestRolesRejectsObjectGroupsClaim(t *testing.T) {
	t.Parallel()
	p, err := New(Config{})
	require.NoError(t, err)

	_, err = p.Roles(claimsWithGroups(map[string]interface{}{"x": "y"}))
	require.ErrorIs(t, err, ErrMalformedGroupsClaim)
}

func TestRolesCustomGroupsClaimName(t *testing.T) {
	t.Parallel()
	p, err := New(Config{GroupsClaim: "https://clickhouse/groups"})
	require.NoError(t, err)

	claims := &oauth.Claims{Extra: map[string]interface{}{
		"https://clickhouse/groups": []interface{}{"ch_admins"},
	}}
	out, err := p.Roles(claims)
	require.NoError(t, err)
	require.Equal(t, []string{"ch_admins"}, out)
}

// TestRolesMappingHappensBeforeFilter proves an IdP group name that would
// NOT itself pass the filter still becomes a role once mapped to a
// filter-passing candidate — i.e. mapping runs first, and the filter sees
// the mapped candidate, not the raw group.
func TestRolesMappingHappensBeforeFilter(t *testing.T) {
	t.Parallel()
	p, err := New(Config{
		Mapping: map[string]string{"idp-readers-group": "ch_readers"},
		Filter:  `^ch_[A-Za-z0-9_]+$`,
	})
	require.NoError(t, err)

	out, err := p.Roles(claimsWithGroups([]interface{}{"idp-readers-group"}))
	require.NoError(t, err)
	require.Equal(t, []string{"ch_readers"}, out)
}

// TestRolesUnmappedGroupPassesThroughToFilter proves an unmapped group is
// NOT dropped at the mapping step — it reaches the filter unchanged, and the
// filter (not the mapping step) decides whether it survives.
func TestRolesUnmappedGroupPassesThroughToFilter(t *testing.T) {
	t.Parallel()
	p, err := New(Config{
		Mapping: map[string]string{"idp-readers-group": "ch_readers"},
		// No filter configured: the unmapped group must appear verbatim.
	})
	require.NoError(t, err)

	out, err := p.Roles(claimsWithGroups([]interface{}{"idp-readers-group", "unmapped_group"}))
	require.NoError(t, err)
	require.Equal(t, []string{"ch_readers", "unmapped_group"}, out)
}

// TestRolesFilterIsFullMatchNotSubstring is the fail-closed regression: a
// restrictive-looking filter must not be satisfied by a candidate that
// merely CONTAINS the pattern. regexp.MatchString-style substring semantics
// would let "ch_admins_evil" through a `^ch_[A-Za-z0-9_]+$`-shaped filter if
// implemented incorrectly (it wouldn't here, since the anchors already
// prevent that specific case) — the real risk is an unanchored operator
// filter like `ch_readers`, which substring-matches "not_ch_readers_at_all".
func TestRolesFilterIsFullMatchNotSubstring(t *testing.T) {
	t.Parallel()
	p, err := New(Config{Filter: `ch_readers`})
	require.NoError(t, err)

	out, err := p.Roles(claimsWithGroups([]interface{}{"not_ch_readers_at_all", "ch_readers"}))
	require.NoError(t, err)
	require.Equal(t, []string{"ch_readers"}, out, "full-match semantics must reject a candidate that only contains the pattern")
}

func TestRolesFilterDropsNonMatches(t *testing.T) {
	t.Parallel()
	p, err := New(Config{Filter: `^ch_[A-Za-z0-9_]+$`})
	require.NoError(t, err)

	out, err := p.Roles(claimsWithGroups([]interface{}{"ch_readers", "not-allowed"}))
	require.NoError(t, err)
	require.Equal(t, []string{"ch_readers"}, out)
}

// TestRolesDangerousUnexpectedIdPGroupProducesNoRole is the fail-closed
// regression fixture the plan calls out explicitly: a restrictive filter
// must produce zero roles for an unexpected IdP group value, not "pass it
// through as-is."
func TestRolesDangerousUnexpectedIdPGroupProducesNoRole(t *testing.T) {
	t.Parallel()
	p, err := New(Config{Filter: `^ch_[A-Za-z0-9_]+$`})
	require.NoError(t, err)

	out, err := p.Roles(claimsWithGroups([]interface{}{"../../etc/passwd", "'; DROP ROLE default; --"}))
	require.NoError(t, err)
	require.Empty(t, out)
}

func TestRolesInvalidFilterRegexFailsConstruction(t *testing.T) {
	t.Parallel()
	_, err := New(Config{Filter: `(unterminated`})
	require.Error(t, err)
}

// TestRolesTransformRunsAfterFilter is order-sensitive: a candidate that
// would NOT pass the filter in its pre-transform form, but WOULD only look
// like it passes if the transform ran first, must still be dropped —
// proving transform strictly follows filtering.
func TestRolesTransformRunsAfterFilter(t *testing.T) {
	t.Parallel()
	p, err := New(Config{
		Filter:    `^ch_[A-Za-z0-9_]+$`,
		Transform: `s/^raw_/ch_/`,
	})
	require.NoError(t, err)

	// "raw_readers" does not match the filter as-is (it doesn't start with
	// ch_ yet) so it must be dropped even though the transform, if applied
	// before filtering, would have turned it into "ch_readers".
	out, err := p.Roles(claimsWithGroups([]interface{}{"raw_readers", "ch_writers"}))
	require.NoError(t, err)
	require.Equal(t, []string{"ch_writers"}, out)
}

func TestRolesTransformAppliesAfterFilterSurvives(t *testing.T) {
	t.Parallel()
	p, err := New(Config{
		Filter:    `^ch_[A-Za-z0-9_]+$`,
		Transform: `s/^ch_/role_/`,
	})
	require.NoError(t, err)

	out, err := p.Roles(claimsWithGroups([]interface{}{"ch_readers"}))
	require.NoError(t, err)
	require.Equal(t, []string{"role_readers"}, out)
}

func TestRolesTransformGlobalFlag(t *testing.T) {
	t.Parallel()
	p, err := New(Config{Transform: `s/a/X/g`})
	require.NoError(t, err)

	out, err := p.Roles(claimsWithGroups([]interface{}{"banana"}))
	require.NoError(t, err)
	require.Equal(t, []string{"bXnXnX"}, out)
}

func TestRolesTransformWithoutGlobalFlagReplacesOnlyFirst(t *testing.T) {
	t.Parallel()
	p, err := New(Config{Transform: `s/a/X/`})
	require.NoError(t, err)

	out, err := p.Roles(claimsWithGroups([]interface{}{"banana"}))
	require.NoError(t, err)
	require.Equal(t, []string{"bXnana"}, out)
}

func TestRolesTransformSupportsEscapedDelimiter(t *testing.T) {
	t.Parallel()
	// Pattern and replacement both need a literal "/" — escaped with \/.
	p, err := New(Config{Transform: `s/a\/b/c\/d/`})
	require.NoError(t, err)

	out, err := p.Roles(claimsWithGroups([]interface{}{"xa/by"}))
	require.NoError(t, err)
	require.Equal(t, []string{"xc/dy"}, out)
}

func TestRolesTransformSupportsCaptureGroupExpansion(t *testing.T) {
	t.Parallel()
	p, err := New(Config{Transform: `s/^ch_(.+)$/role_${1}/`})
	require.NoError(t, err)

	out, err := p.Roles(claimsWithGroups([]interface{}{"ch_readers"}))
	require.NoError(t, err)
	require.Equal(t, []string{"role_readers"}, out)
}

func TestRolesTransformIdentityWhenEmpty(t *testing.T) {
	t.Parallel()
	p, err := New(Config{})
	require.NoError(t, err)

	out, err := p.Roles(claimsWithGroups([]interface{}{"unchanged"}))
	require.NoError(t, err)
	require.Equal(t, []string{"unchanged"}, out)
}

func TestRolesTransformInvalidSyntaxFailsConstruction(t *testing.T) {
	t.Parallel()
	_, err := New(Config{Transform: `not-a-transform`})
	require.Error(t, err)
}

func TestRolesTransformMissingFieldFailsConstruction(t *testing.T) {
	t.Parallel()
	_, err := New(Config{Transform: `s/a/b`}) // missing trailing flags field
	require.Error(t, err)
}

func TestRolesTransformUnsupportedFlagFailsConstruction(t *testing.T) {
	t.Parallel()
	_, err := New(Config{Transform: `s/a/b/i`}) // "i" is not supported
	require.Error(t, err)
}

func TestRolesTransformDuplicateFlagFailsConstruction(t *testing.T) {
	t.Parallel()
	_, err := New(Config{Transform: `s/a/b/gg`})
	require.Error(t, err)
}

func TestRolesTransformInvalidRegexFailsConstruction(t *testing.T) {
	t.Parallel()
	_, err := New(Config{Transform: `s/(unterminated/b/`})
	require.Error(t, err)
}

// TestRolesMultipleGroupsConvergeOnSameRoleDeduplicated proves the FINAL
// dedup step (after mapping/filter/transform) collapses distinct source
// groups that end up as the same role string.
func TestRolesMultipleGroupsConvergeOnSameRoleDeduplicated(t *testing.T) {
	t.Parallel()
	p, err := New(Config{
		Mapping: map[string]string{
			"idp-group-a": "ch_readers",
			"idp-group-b": "ch_readers",
		},
	})
	require.NoError(t, err)

	out, err := p.Roles(claimsWithGroups([]interface{}{"idp-group-a", "idp-group-b"}))
	require.NoError(t, err)
	require.Equal(t, []string{"ch_readers"}, out)
}

func TestRolesNilClaimsYieldsZeroRoles(t *testing.T) {
	t.Parallel()
	p, err := New(Config{})
	require.NoError(t, err)

	out, err := p.Roles(nil)
	require.NoError(t, err)
	require.Empty(t, out)
}

package identity

import (
	"strings"
	"testing"

	"github.com/altinity/go-mcp-oauth-sdk/oauth"
	"github.com/stretchr/testify/require"
)

func TestNewPolicyDefaults(t *testing.T) {
	t.Parallel()
	p, err := NewPolicy(Config{})
	require.NoError(t, err)
	require.Equal(t, "email", p.usernameClaim)
	require.Equal(t, "lowercase_equal", p.matchMode)
}

func TestNewPolicyRejectsUnknownMatchMode(t *testing.T) {
	t.Parallel()
	_, err := NewPolicy(Config{MatchMode: "bogus"})
	require.Error(t, err)
}

func TestBindEmailUsernameClaim(t *testing.T) {
	t.Parallel()
	p, err := NewPolicy(Config{UsernameClaim: "email", MatchMode: "lowercase_equal"})
	require.NoError(t, err)

	claims := &oauth.Claims{Email: "Alice@Example.com", Subject: "u-1", Issuer: "https://idp.example.com"}
	principal, err := p.Bind("alice@example.com", claims)
	require.NoError(t, err)
	require.Equal(t, "alice@example.com", principal.Username)
	require.Equal(t, "Alice@Example.com", principal.Email)

	iss, sub, ok := principal.StableSubject()
	require.True(t, ok)
	require.Equal(t, "https://idp.example.com", iss)
	require.Equal(t, "u-1", sub)
}

func TestBindExactMatchModeRejectsCaseDifference(t *testing.T) {
	t.Parallel()
	p, err := NewPolicy(Config{UsernameClaim: "email", MatchMode: "exact"})
	require.NoError(t, err)

	claims := &oauth.Claims{Email: "Alice@Example.com"}
	_, err = p.Bind("alice@example.com", claims)
	require.ErrorIs(t, err, ErrUsernameMismatch)
}

func TestBindRejectsUsernameMismatch(t *testing.T) {
	t.Parallel()
	p, err := NewPolicy(Config{UsernameClaim: "email", MatchMode: "lowercase_equal"})
	require.NoError(t, err)

	claims := &oauth.Claims{Email: "alice@example.com"}
	_, err = p.Bind("bob@example.com", claims)
	require.ErrorIs(t, err, ErrUsernameMismatch)
}

// TestBindEmailMissingUnderEmailClaim is the no-sub-equivalent compatibility
// regression for the email path: a token with no email claim at all under
// username_claim: email must fail closed with ErrClaimMissing, not silently
// authenticate as "".
func TestBindEmailMissingUnderEmailClaim(t *testing.T) {
	t.Parallel()
	p, err := NewPolicy(Config{UsernameClaim: "email"})
	require.NoError(t, err)

	claims := &oauth.Claims{Subject: "u-1"}
	_, err = p.Bind("alice@example.com", claims)
	require.ErrorIs(t, err, ErrClaimMissing)
}

// TestBindSubUsernameClaimMissingSub proves the sub path fails closed when
// sub is empty, and the symmetric compatibility case
// (TestBindSucceedsWithoutSubUnderEmailClaim below) proves an email-claim
// deployment is unaffected by an absent sub.
func TestBindSubUsernameClaimMissingSub(t *testing.T) {
	t.Parallel()
	p, err := NewPolicy(Config{UsernameClaim: "sub"})
	require.NoError(t, err)

	claims := &oauth.Claims{Email: "alice@example.com"}
	_, err = p.Bind("u-1", claims)
	require.ErrorIs(t, err, ErrClaimMissing)
}

// TestBindSucceedsWithoutSubUnderEmailClaim is the compatibility regression
// from the plan's review responses: existing ch-jwt-verify deployments using
// username_claim: email never required sub, and JWKS-only (no configured
// issuer) deployments never required iss. Phase 1 must not add either as a
// new authentication prerequisite — StableSubject must simply report
// ok == false, never an error.
func TestBindSucceedsWithoutSubUnderEmailClaim(t *testing.T) {
	t.Parallel()
	p, err := NewPolicy(Config{UsernameClaim: "email"})
	require.NoError(t, err)

	claims := &oauth.Claims{Email: "alice@example.com"} // no sub, no iss
	principal, err := p.Bind("alice@example.com", claims)
	require.NoError(t, err)

	_, _, ok := principal.StableSubject()
	require.False(t, ok, "StableSubject must report ok=false rather than erroring or synthesizing an identity")
}

func TestBindCustomUsernameClaim(t *testing.T) {
	t.Parallel()
	p, err := NewPolicy(Config{UsernameClaim: "clickhouse_user", MatchMode: "exact"})
	require.NoError(t, err)

	claims := &oauth.Claims{
		Email: "alice@example.com",
		Extra: map[string]interface{}{"clickhouse_user": "ch-tenant-a"},
	}
	principal, err := p.Bind("ch-tenant-a", claims)
	require.NoError(t, err)
	require.Equal(t, "ch-tenant-a", principal.Username)
}

func TestBindCustomUsernameClaimMissingFailsClosed(t *testing.T) {
	t.Parallel()
	p, err := NewPolicy(Config{UsernameClaim: "clickhouse_user"})
	require.NoError(t, err)

	claims := &oauth.Claims{Email: "alice@example.com"}
	_, err = p.Bind("ch-tenant-a", claims)
	require.ErrorIs(t, err, ErrClaimMissing)
}

func TestBindEnforcesEmailVerifiedPolicy(t *testing.T) {
	t.Parallel()
	p, err := NewPolicy(Config{
		UsernameClaim: "email",
		ClaimPolicy:   oauth.IdentityPolicy{RequireEmailVerified: true},
	})
	require.NoError(t, err)

	claims := &oauth.Claims{Email: "alice@example.com", EmailVerified: false}
	_, err = p.Bind("alice@example.com", claims)
	require.ErrorIs(t, err, oauth.ErrEmailNotVerified)
}

func TestBindEnforcesAllowedEmailDomains(t *testing.T) {
	t.Parallel()
	p, err := NewPolicy(Config{
		UsernameClaim: "email",
		ClaimPolicy:   oauth.IdentityPolicy{AllowedEmailDomains: []string{"altinity.com"}},
	})
	require.NoError(t, err)

	claims := &oauth.Claims{Email: "alice@example.com"}
	_, err = p.Bind("alice@example.com", claims)
	require.ErrorIs(t, err, oauth.ErrUnauthorizedDomain)
}

func TestBindEnforcesAllowedHostedDomains(t *testing.T) {
	t.Parallel()
	p, err := NewPolicy(Config{
		UsernameClaim: "email",
		ClaimPolicy:   oauth.IdentityPolicy{AllowedHostedDomains: []string{"altinity.com"}},
	})
	require.NoError(t, err)

	claims := &oauth.Claims{Email: "alice@example.com", HostedDomain: "example.com"}
	_, err = p.Bind("alice@example.com", claims)
	require.ErrorIs(t, err, oauth.ErrUnauthorizedDomain)
}

// TestBindRejectsReservedUsername proves the reserved-username deny check
// fires on an otherwise-completely-valid token/claim set — reservation is a
// standalone gate, not a side effect of any other failure.
func TestBindRejectsReservedUsername(t *testing.T) {
	t.Parallel()
	p, err := NewPolicy(Config{
		UsernameClaim:   "sub",
		DeniedUsernames: []string{"default", "admin"},
	})
	require.NoError(t, err)

	claims := &oauth.Claims{Subject: "Default"} // matches "default" case-insensitively
	_, err = p.Bind("Default", claims)
	require.ErrorIs(t, err, ErrReservedUsername)
}

// TestBindReservedUsernameCheckIsCaseInsensitiveRegardlessOfMatchMode proves
// the deny-list comparison is independent of the configured MatchMode
// (trimmed, case-insensitive) even when MatchMode is "exact".
func TestBindReservedUsernameCheckIsCaseInsensitiveRegardlessOfMatchMode(t *testing.T) {
	t.Parallel()
	p, err := NewPolicy(Config{
		UsernameClaim:   "sub",
		MatchMode:       "exact",
		DeniedUsernames: []string{" Operator "},
	})
	require.NoError(t, err)

	claims := &oauth.Claims{Subject: "operator"}
	_, err = p.Bind("operator", claims)
	require.ErrorIs(t, err, ErrReservedUsername)
}

// TestDeniedUsernamesDefaultEmpty proves merely constructing a Policy without
// configuring DeniedUsernames does not begin denying any username — the
// deny-list defaults to empty so upgrading an existing sidecar deployment
// can't newly reject a previously-accepted user.
func TestDeniedUsernamesDefaultEmpty(t *testing.T) {
	t.Parallel()
	p, err := NewPolicy(Config{UsernameClaim: "sub"})
	require.NoError(t, err)

	claims := &oauth.Claims{Subject: "default"}
	_, err = p.Bind("default", claims)
	require.NoError(t, err)
}

func TestStableSubjectRequiresBothIssuerAndSubject(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		p    Principal
		ok   bool
	}{
		{"both present", Principal{Issuer: "iss", Subject: "sub"}, true},
		{"missing subject", Principal{Issuer: "iss"}, false},
		{"missing issuer", Principal{Subject: "sub"}, false},
		{"neither", Principal{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, ok := tc.p.StableSubject()
			require.Equal(t, tc.ok, ok)
		})
	}
}

func TestBindRejectsNilClaims(t *testing.T) {
	t.Parallel()
	p, err := NewPolicy(Config{})
	require.NoError(t, err)
	_, err = p.Bind("alice@example.com", nil)
	require.Error(t, err)
}

// jwtShapedMarker is a credential-shaped string that must never appear
// verbatim in any error text or log line produced from an untrusted,
// unauthenticated requested username — it has the three-dot-separated shape
// of a compact JWT (header.payload.signature) without needing to be a real
// signed token, since RedactUsername's guard is purely shape/length based.
const jwtShapedMarker = "SECRET-HEADER-MARKER.SECRET-PAYLOAD-MARKER.SECRET-SIG-MARKER"

func TestRedactUsernameLeavesPlainUsernamesUnchanged(t *testing.T) {
	t.Parallel()
	require.Equal(t, "alice@example.com", RedactUsername("alice@example.com"))
	require.Equal(t, "ch-tenant-a", RedactUsername("ch-tenant-a"))
}

// TestRedactUsernameRedactsJWTShapedValue proves the specific attack shape
// from the review finding: a Basic-auth "user" half that is itself an
// arbitrary JWT-like string (three non-empty dot-separated segments) is
// never returned verbatim.
func TestRedactUsernameRedactsJWTShapedValue(t *testing.T) {
	t.Parallel()
	redacted := RedactUsername(jwtShapedMarker)
	require.NotEqual(t, jwtShapedMarker, redacted)
	require.NotContains(t, redacted, "SECRET-HEADER-MARKER")
	require.NotContains(t, redacted, "SECRET-PAYLOAD-MARKER")
	require.NotContains(t, redacted, "SECRET-SIG-MARKER")
}

// TestRedactUsernameRedactsOverlongValue proves the length guard fires
// independently of the JWT dot-shape check — an implausibly long requested
// username (e.g. any credential-shaped value that doesn't happen to be
// exactly three dot-separated segments) is still redacted, and the redaction
// never leaks a prefix of the original.
func TestRedactUsernameRedactsOverlongValue(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", maxLoggedUsernameLen+1)
	redacted := RedactUsername(long)
	require.NotEqual(t, long, redacted)
	require.NotContains(t, redacted, strings.Repeat("a", 16))
}

func TestRedactUsernameLeavesTwoSegmentValueUnchanged(t *testing.T) {
	t.Parallel()
	// Only three non-empty dot-separated segments count as JWT-shaped; two
	// segments (or an empty one) is not, by itself, unsafe to log.
	require.Equal(t, "a.b", RedactUsername("a.b"))
	require.Equal(t, "a..b", RedactUsername("a..b"))
}

// TestBindUsernameMismatchErrorRedactsCredentialShapedRequestedUsername is
// the regression for the review finding: an attacker (or a confused client)
// can put an arbitrary JWT-shaped string in the Basic-auth username slot,
// and ErrUsernameMismatch's message must never echo it verbatim.
func TestBindUsernameMismatchErrorRedactsCredentialShapedRequestedUsername(t *testing.T) {
	t.Parallel()
	p, err := NewPolicy(Config{UsernameClaim: "email"})
	require.NoError(t, err)

	claims := &oauth.Claims{Email: "alice@example.com"}
	_, err = p.Bind(jwtShapedMarker, claims)
	require.ErrorIs(t, err, ErrUsernameMismatch)
	require.NotContains(t, err.Error(), "SECRET-HEADER-MARKER")
	require.NotContains(t, err.Error(), "SECRET-PAYLOAD-MARKER")
	require.NotContains(t, err.Error(), "SECRET-SIG-MARKER")
}

// TestBindReservedUsernameErrorRedactsCredentialShapedRequestedUsername is
// the ErrReservedUsername counterpart: the deny-list check runs after
// requestedUsername is already known safe-shaped-or-not, but the error
// constructor must still redact it independently, since a JWT-shaped string
// could coincidentally normalize to a denied entry.
func TestBindReservedUsernameErrorRedactsCredentialShapedRequestedUsername(t *testing.T) {
	t.Parallel()
	deniedShaped := "SECRET-DENIED-A.SECRET-DENIED-B.SECRET-DENIED-C"
	p, err := NewPolicy(Config{
		UsernameClaim:   "sub",
		DeniedUsernames: []string{deniedShaped},
	})
	require.NoError(t, err)

	claims := &oauth.Claims{Subject: deniedShaped}
	_, err = p.Bind(deniedShaped, claims)
	require.ErrorIs(t, err, ErrReservedUsername)
	require.NotContains(t, err.Error(), "SECRET-DENIED-A")
	require.NotContains(t, err.Error(), "SECRET-DENIED-B")
	require.NotContains(t, err.Error(), "SECRET-DENIED-C")
}

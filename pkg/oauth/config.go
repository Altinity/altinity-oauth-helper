package oauth

import "time"

// OAuthConfig defines the verifier-side configuration needed to validate a
// JWT against an OAuth 2.0 / OIDC authorization server. It deliberately
// carries only fields the JWKS-based verifier consumes; broker / forward-mode
// fields (client_id, client_secret, token_url, …) live in callers that need
// them and are not part of this leaf-level package.
type OAuthConfig struct {
	// Issuer is the OAuth token issuer URL for token validation
	// (e.g. "https://accounts.google.com"). Used both as the expected `iss`
	// claim and — when JWKSURL is unset — as the base for discovering the
	// JWKS endpoint via /.well-known/oauth-authorization-server and
	// /.well-known/openid-configuration.
	Issuer string `json:"issuer" yaml:"issuer"`

	// JWKSURL is the URL to fetch the JSON Web Key Set for signature
	// verification. If empty it is discovered from Issuer's well-known
	// metadata.
	JWKSURL string `json:"jwks_url" yaml:"jwks_url"`

	// Audience is the expected audience claim in the token. Compared
	// byte-equal (RFC 8707), with trailing-slash tolerance for URLs.
	Audience string `json:"audience" yaml:"audience"`

	// RequiredScopes is the list of scopes the token must carry (the token's
	// scopes must be a superset). Comparison is exact (case- and
	// whitespace-sensitive) per RFC 6749 §3.3.
	RequiredScopes []string `json:"required_scopes" yaml:"required_scopes"`

	// JWKSCacheTTL bounds how long a JWKS document (and its sibling
	// auth-server metadata response) stays cached before the Verifier
	// re-fetches. Zero falls back to the package default (5 minutes).
	JWKSCacheTTL time.Duration `json:"jwks_cache_ttl" yaml:"jwks_cache_ttl"`
}

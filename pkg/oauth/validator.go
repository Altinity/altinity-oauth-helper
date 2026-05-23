package oauth

import (
	"context"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// ValidateToken validates an OAuth bearer JWT and returns claims.
//
// Validation is JWKS-based: signature against the discovered/configured key
// set, plus issuer, audience (slash-normalised), exp/nbf/iat (with
// clockSkewSecs tolerance), and required scopes.
//
// Returns ErrInvalidToken for non-JWT bearers (no opaque-token soft-pass —
// this package is the verifier, not a passthrough) and ErrMissingToken for
// empty input.
func (v *Verifier) ValidateToken(ctx context.Context, token string) (*Claims, error) {
	if token == "" {
		return nil, ErrMissingToken
	}
	if !looksLikeJWT(token) {
		log.Error().Msg("OAuth token is not a JWT; verifier requires a signed JWT")
		return nil, ErrInvalidToken
	}
	if strings.TrimSpace(v.cfg.JWKSURL) == "" && strings.TrimSpace(v.cfg.Issuer) == "" {
		return nil, ErrInvalidToken
	}
	claims, err := v.parseAndVerifyExternalJWT(ctx, token, v.cfg.Audience)
	if err != nil {
		log.Error().Err(err).Msg("Failed to validate OAuth token")
		return nil, err
	}
	return v.validateClaims(claims)
}

// validateClaims applies post-signature checks: audience (slash-normalised),
// exp/nbf/iat (with clockSkewSecs tolerance), and required scopes. Identity
// policy (verified-email, allowed domains) is the caller's responsibility.
func (v *Verifier) validateClaims(claims *Claims) (*Claims, error) {
	if v.cfg.Audience != "" {
		if len(claims.Audience) == 0 {
			log.Error().Str("expected", v.cfg.Audience).Msg("OAuth token missing audience claim")
			return nil, ErrInvalidToken
		}
		if !audienceMatchesResource(claims.Audience, v.cfg.Audience) {
			log.Error().Str("expected", v.cfg.Audience).Strs("got", claims.Audience).Msg("OAuth token audience mismatch")
			return nil, ErrInvalidToken
		}
	}

	now := time.Now().Unix()
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt+clockSkewSecs {
		log.Error().Int64("exp", claims.ExpiresAt).Msg("OAuth token expired")
		return nil, ErrTokenExpired
	}
	if claims.NotBefore > 0 && now+clockSkewSecs < claims.NotBefore {
		log.Error().Int64("nbf", claims.NotBefore).Msg("OAuth token not yet valid")
		return nil, ErrInvalidToken
	}
	if claims.IssuedAt > 0 && claims.IssuedAt > now+clockSkewSecs {
		log.Error().Int64("iat", claims.IssuedAt).Msg("OAuth token issued in the future")
		return nil, ErrInvalidToken
	}

	if len(v.cfg.RequiredScopes) > 0 {
		if !HasRequiredScopes(claims.Scopes, v.cfg.RequiredScopes) {
			log.Error().Strs("required", v.cfg.RequiredScopes).Strs("got", claims.Scopes).Msg("OAuth token missing required scopes")
			return nil, ErrInsufficientScopes
		}
	}

	return claims, nil
}

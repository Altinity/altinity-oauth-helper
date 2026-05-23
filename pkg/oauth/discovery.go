package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog/log"
)

// authServerMeta holds the subset of RFC 8414 / OpenID Connect Discovery
// fields the verifier consumes. Other fields are intentionally ignored —
// this package validates JWTs against a JWKS, it does not act as an OAuth
// client, so endpoints like token_endpoint or registration_endpoint are out
// of scope here.
//
// Vendored (with the surface trimmed) from
// github.com/modelcontextprotocol/go-sdk/oauthex.AuthServerMeta so the
// module has no MCP-named dependencies.
type authServerMeta struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// authorizationServerMetadataURLs returns the well-known URLs to probe for
// authorization-server metadata, in the order required by the MCP
// authorization spec (RFC 8414 first, then OIDC Discovery; with the
// path-aware variants when the issuer carries a path).
func authorizationServerMetadataURLs(issuerURL string) []string {
	baseURL, err := url.Parse(issuerURL)
	if err != nil {
		return nil
	}

	var urls []string
	if baseURL.Path == "" || baseURL.Path == "/" {
		baseURL.Path = "/.well-known/oauth-authorization-server"
		urls = append(urls, baseURL.String())
		baseURL.Path = "/.well-known/openid-configuration"
		urls = append(urls, baseURL.String())
		return urls
	}

	originalPath := baseURL.Path
	baseURL.Path = "/.well-known/oauth-authorization-server/" + strings.TrimLeft(originalPath, "/")
	urls = append(urls, baseURL.String())
	baseURL.Path = "/.well-known/openid-configuration/" + strings.TrimLeft(originalPath, "/")
	urls = append(urls, baseURL.String())
	baseURL.Path = "/" + strings.Trim(originalPath, "/") + "/.well-known/openid-configuration"
	urls = append(urls, baseURL.String())
	return urls
}

// getAuthServerMetadata probes each well-known URL for issuerURL in order
// and returns the first success.
//
// Semantics match go-sdk's auth.GetAuthServerMetadata:
//   - 4xx on a probe URL → fall through to the next URL
//   - 5xx / network error → bail with the error wrapped in ErrTransient
//   - 200 with a valid metadata document whose `issuer` matches → return it
//   - All probes 4xx → return (nil, nil) so the caller can decide
//
// PKCE / endpoint-URL-scheme validation is intentionally not performed:
// this package verifies JWTs against a JWKS, it does not act as an OAuth
// client, so the broader RFC 8414 client-side checks don't apply.
func getAuthServerMetadata(ctx context.Context, issuerURL string, c *http.Client) (*authServerMeta, error) {
	for _, metadataURL := range authorizationServerMetadataURLs(issuerURL) {
		asm, err := fetchAuthServerMetaOnce(ctx, metadataURL, issuerURL, c)
		if err != nil {
			return nil, err
		}
		if asm != nil {
			return asm, nil
		}
	}
	return nil, nil
}

// fetchAuthServerMetaOnce hits a single well-known URL. Returns (nil, nil)
// on 4xx so the caller can move on to the next candidate; (nil, err) on
// network/5xx errors; (asm, nil) on success.
func fetchAuthServerMetaOnce(ctx context.Context, metadataURL, expectedIssuer string, c *http.Client) (*authServerMeta, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build metadata request for %q: %w", metadataURL, err)
	}
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch metadata %q: %w: %w", metadataURL, ErrTransient, err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn().Stack().Err(closeErr).Msgf("can't close metadata response body for %s", metadataURL)
		}
	}()

	switch {
	case resp.StatusCode >= 500:
		return nil, fmt.Errorf("metadata endpoint %q returned status %d: %w", metadataURL, resp.StatusCode, ErrTransient)
	case resp.StatusCode >= 400:
		return nil, nil
	case resp.StatusCode >= 300:
		return nil, fmt.Errorf("metadata endpoint %q returned status %d", metadataURL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read metadata response from %q: %w: %w", metadataURL, ErrTransient, err)
	}
	var asm authServerMeta
	if err := json.Unmarshal(body, &asm); err != nil {
		return nil, fmt.Errorf("parse metadata response from %q: %w", metadataURL, err)
	}
	if asm.Issuer != expectedIssuer {
		return nil, fmt.Errorf("metadata issuer %q does not match issuer URL %q", asm.Issuer, expectedIssuer)
	}
	return &asm, nil
}

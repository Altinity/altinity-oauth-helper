package securitytest

import (
	"fmt"
	"runtime/debug"
	"testing"

	// Imported so this test binary transitively links
	// github.com/altinity/go-mcp-oauth-sdk (internal/verification imports
	// github.com/altinity/go-mcp-oauth-sdk/oauth) — required for
	// runtime/debug.ReadBuildInfo below to have anything to resolve. Only
	// the import matters; verification.New is referenced merely so the
	// import isn't flagged unused, and to document exactly which package
	// this contract is protecting.
	"github.com/altinity/altinity-oauth-helper/internal/verification"
)

// resolvedSDKModule inspects the current test binary's build info for
// sdkModulePath, falling back to parsing go.mod's require line (A6) if the
// module is somehow absent from build info. It never returns a vacuous
// "not found, but let's pass anyway" result: both paths failing is a hard
// error for the caller.
func resolvedSDKModule(root string) (version string, replaced bool, source string, err error) {
	if info, ok := debug.ReadBuildInfo(); ok {
		var matches []*debug.Module
		for i := range info.Deps {
			if info.Deps[i].Path == sdkModulePath {
				matches = append(matches, info.Deps[i])
			}
		}
		if len(matches) == 1 {
			m := matches[0]
			return m.Version, m.Replace != nil, "runtime/debug.ReadBuildInfo", nil
		}
		if len(matches) > 1 {
			return "", false, "runtime/debug.ReadBuildInfo", fmt.Errorf("securitytest: %d resolved modules for %s, want exactly 1", len(matches), sdkModulePath)
		}
		// len(matches) == 0: fall through to the go.mod fallback below.
	}

	v, ferr := resolveSDKVersionFromGoMod(root)
	if ferr != nil {
		return "", false, "", fmt.Errorf("securitytest: %s absent from build info, and go.mod fallback failed: %w", sdkModulePath, ferr)
	}
	return v, false, "go.mod require line", nil
}

// TestSDKContract_ExactlyOneResolvedModuleAtAuditedVersion is the plan
// §5.3 gate: exactly one github.com/altinity/go-mcp-oauth-sdk module must
// resolve, its version must equal auditedSDKVersion, and it must carry no
// module replacement. This repo's own third_party goldap/ldapserver
// replaces are a different module entirely and are correctly untouched by
// this check (A6).
func TestSDKContract_ExactlyOneResolvedModuleAtAuditedVersion(t *testing.T) {
	// Reference the linked package so the import above is genuinely used,
	// not merely present for its side effect.
	var _ verification.Config

	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("securitytest: locate module root: %v", err)
	}

	version, replaced, source, err := resolvedSDKModule(root)
	if err != nil {
		t.Fatalf("securitytest: resolve %s version: %v", sdkModulePath, err)
	}
	if version != auditedSDKVersion {
		t.Fatalf("securitytest: %s resolved to %s (via %s), want the audited version %s — bumping this "+
			"dependency requires re-auditing every external-pinned row in testdata/redaction-sites.tsv and "+
			"updating auditedSDKVersion in doc.go in the same change", sdkModulePath, version, source, auditedSDKVersion)
	}
	if replaced {
		t.Fatalf("securitytest: %s carries a module replace directive — that must not happen without a "+
			"deliberate, re-audited exception (this check intentionally does not look at the repo's own "+
			"third_party goldap/ldapserver replaces, which are a different module and expected)", sdkModulePath)
	}
}

// TestSDKContract_VerifyUncachedCallsExactlyOneValidateStrictJWT AST-asserts
// plan §5.4's strict-entrypoint invariant: internal/verification's
// verifyUncached must call v.oauthVer.ValidateStrictJWT exactly once. Every
// other redaction claim about the strict JWT path (§5.5's sanitized-error
// rows, the marker matrices) depends on this being the one and only way a
// token reaches the SDK.
func TestSDKContract_VerifyUncachedCallsExactlyOneValidateStrictJWT(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("securitytest: locate module root: %v", err)
	}
	fd, err := parseVerifyUncached(root)
	if err != nil {
		t.Fatalf("securitytest: parse verifyUncached: %v", err)
	}
	if fd == nil {
		t.Fatal("securitytest: internal/verification/verifier.go no longer declares a verifyUncached function")
	}
	if n := countValidateStrictJWTCalls(fd); n != 1 {
		t.Fatalf("securitytest: verifyUncached contains %d call(s) to v.oauthVer.ValidateStrictJWT, want exactly 1", n)
	}
}

// TestSDKContract_NoValidateTokenSelectorInVerification AST-asserts the
// other half of plan §5.4: no `.ValidateToken` selector (the SDK's legacy,
// non-strict entrypoint) exists anywhere in internal/verification. Its
// reappearance would reopen exactly the log/error surfaces the "Review
// responses" section of plan-19p5.md rejected as reachable from the strict
// path.
func TestSDKContract_NoValidateTokenSelectorInVerification(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("securitytest: locate module root: %v", err)
	}
	found, err := findValidateTokenSelectors(root)
	if err != nil {
		t.Fatalf("securitytest: scan internal/verification for ValidateToken: %v", err)
	}
	if len(found) > 0 {
		t.Fatalf("securitytest: internal/verification references the legacy .ValidateToken selector at %v — "+
			"the strict-entrypoint invariant (plan §5.4) requires ValidateStrictJWT be the only SDK JWT entrypoint "+
			"this package ever calls", found)
	}
}

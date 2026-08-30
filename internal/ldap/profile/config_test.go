package profile

import (
	"strings"
	"testing"
)

// ---- base DN validation -----------------------------------------------

func TestValidateConfig_UserBaseDN(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		wantErr bool
	}{
		{"valid", "ou=users,dc=profile,dc=test", false},
		{"empty", "", true},
		{"whitespace only", "   ", true},
		{"semicolon separator", "ou=users;dc=profile,dc=test", true},
		{"unescaped plus (multi-valued RDN)", "ou=users+description=x,dc=profile,dc=test", true},
		{"OID attribute type", "0.9.2342.19200300.100.1.1=users,dc=profile,dc=test", true},
		{"hash BER-hexstring value", "ou=#04024869,dc=profile,dc=test", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newTestConfig()
			cfg.UserBaseDN = tc.base
			err := ValidateConfig(cfg)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateConfig(%q): want error, got nil", tc.base)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateConfig(%q): want nil, got %v", tc.base, err)
			}
			if tc.wantErr && err != nil {
				assertFixedNonCredentialError(t, err, tc.base)
			}
		})
	}
}

func TestValidateConfig_GroupBaseDN(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		wantErr bool
	}{
		{"valid", "ou=groups,dc=profile,dc=test", false},
		{"empty", "", true},
		{"whitespace only", "\t\t", true},
		{"semicolon separator", "ou=groups;dc=profile,dc=test", true},
		{"unescaped plus (multi-valued RDN)", "ou=groups+description=x,dc=profile,dc=test", true},
		{"OID attribute type", "0.9.2342.19200300.100.1.1=groups,dc=profile,dc=test", true},
		{"hash BER-hexstring value", "ou=#04024869,dc=profile,dc=test", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newTestConfig()
			cfg.GroupBaseDN = tc.base
			err := ValidateConfig(cfg)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateConfig(%q): want error, got nil", tc.base)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateConfig(%q): want nil, got %v", tc.base, err)
			}
			if tc.wantErr && err != nil {
				assertFixedNonCredentialError(t, err, tc.base)
			}
		})
	}
}

// assertFixedNonCredentialError checks that err's text never echoes the
// invalid configured value verbatim — see config.go's sentinel-error doc
// comment: "config text never echoed".
func assertFixedNonCredentialError(t *testing.T, err error, configuredValue string) {
	t.Helper()
	if configuredValue == "" {
		return // nothing to accidentally echo
	}
	if strings.Contains(err.Error(), configuredValue) {
		t.Fatalf("error %q echoes the invalid configured value %q; construction errors must be fixed, non-credential text", err.Error(), configuredValue)
	}
}

// ---- UserRDNAttribute validation ----------------------------------------

func TestValidateConfig_UserRDNAttribute(t *testing.T) {
	rejected := []string{
		"",      // empty
		" ",     // whitespace only
		"1uid",  // leading digit
		"ui d",  // embedded space
		"-uid",  // leading '-'
		"uid_x", // '_' not in [A-Za-z0-9-]
	}
	for _, attr := range rejected {
		t.Run("rejected/"+attr, func(t *testing.T) {
			cfg := newTestConfig()
			cfg.UserRDNAttribute = attr
			if err := ValidateConfig(cfg); err == nil {
				t.Fatalf("ValidateConfig with UserRDNAttribute %q: want error, got nil", attr)
			}
		})
	}

	accepted := []string{"uid", "UID", "mail-1"}
	for _, attr := range accepted {
		t.Run("accepted/"+attr, func(t *testing.T) {
			cfg := newTestConfig()
			cfg.UserRDNAttribute = attr
			if err := ValidateConfig(cfg); err != nil {
				t.Fatalf("ValidateConfig with UserRDNAttribute %q: want nil, got %v", attr, err)
			}
		})
	}
}

// TestParseConfig_UserRDNAttributeSpellingPreservedCaseInsensitiveCompare
// proves parsedConfig keeps UserRDNAttribute's exact configured spelling
// (so it can be echoed back in operator-facing output unchanged) while
// every comparison against it is defined to be case-insensitive
// (strings.EqualFold), per Config.UserRDNAttribute's doc comment.
func TestParseConfig_UserRDNAttributeSpellingPreservedCaseInsensitiveCompare(t *testing.T) {
	cfg := newTestConfig()
	cfg.UserRDNAttribute = "UID"

	parsed, err := parseConfig(cfg)
	if err != nil {
		t.Fatalf("parseConfig: unexpected error: %v", err)
	}
	if parsed.rdnAttribute != "UID" {
		t.Fatalf("rdnAttribute spelling not preserved: got %q, want %q", parsed.rdnAttribute, "UID")
	}
	if !strings.EqualFold(parsed.rdnAttribute, "uid") {
		t.Fatalf("EqualFold(%q, %q) = false, want true", parsed.rdnAttribute, "uid")
	}
	if parsed.rdnAttribute == "uid" {
		t.Fatalf("rdnAttribute was lowercased at parse time; spelling must be preserved verbatim")
	}
}

// TestParseConfig_GroupBaseTextPreservedVerbatim proves parseConfig keeps
// GroupBaseDN's exact configured text (for RenderGroupDN, which uses it
// verbatim) alongside the parsed structural form.
func TestParseConfig_GroupBaseTextPreservedVerbatim(t *testing.T) {
	cfg := newTestConfig()
	cfg.GroupBaseDN = "ou=groups, dc=profile,dc=test" // insignificant space after comma
	parsed, err := parseConfig(cfg)
	if err != nil {
		t.Fatalf("parseConfig: unexpected error: %v", err)
	}
	if parsed.groupBaseText != cfg.GroupBaseDN {
		t.Fatalf("groupBaseText = %q, want exact configured text %q", parsed.groupBaseText, cfg.GroupBaseDN)
	}
}

// TestValidateConfig_RoleCNPrefixUnvalidated proves RoleCNPrefix gets no
// semantic validation: any string, including empty, is accepted.
func TestValidateConfig_RoleCNPrefixUnvalidated(t *testing.T) {
	for _, prefix := range []string{"", "clickhouse_", "anything at all !! + , ="} {
		cfg := newTestConfig()
		cfg.RoleCNPrefix = prefix
		if err := ValidateConfig(cfg); err != nil {
			t.Fatalf("ValidateConfig with RoleCNPrefix %q: want nil, got %v", prefix, err)
		}
	}
}

// ---- sabotage-detecting anchor ------------------------------------------

// TestValidateConfig_UserRDNAttributeRegexNotJustNonEmpty is the doneWhen
// check named by this sub-task: it must fail if UserRDNAttribute
// validation is weakened from the full descriptor-grammar regex down to a
// bare non-empty check (plan sabotage list: "UserRDNAttribute validation
// weakened to non-empty only"). Every value below is non-empty, so a
// weakened non-empty-only check would wrongly accept all of them.
func TestValidateConfig_UserRDNAttributeRegexNotJustNonEmpty(t *testing.T) {
	for _, attr := range []string{"1uid", "ui d", "-uid", "uid_x", " "} {
		cfg := newTestConfig()
		cfg.UserRDNAttribute = attr
		if err := ValidateConfig(cfg); err == nil {
			t.Fatalf("ValidateConfig with UserRDNAttribute %q (non-empty but grammar-invalid): want error, got nil — UserRDNAttribute validation may have regressed to a bare non-empty check", attr)
		}
	}
}

package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// decodeClaims parses the raw JWT compact serialization returned by
// signHandler and decodes its payload segment into a generic claims map,
// without verifying the signature (these tests only care about claim
// shape, not cryptographic validity).
func decodeClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWT with 3 segments, got %d: %q", len(parts), token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to base64-decode JWT payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("failed to unmarshal JWT payload as JSON: %v", err)
	}
	return claims
}

// sign invokes signHandler directly (bypassing the network) with the given
// raw query string (e.g. "email=alice@example.com&role=idp-readers") and
// returns the decoded claims of the minted token. It fails the test if the
// handler does not respond 200 OK.
func sign(t *testing.T, rawQuery string) map[string]any {
	t.Helper()
	req := httptest.NewRequest("POST", "/sign?"+rawQuery, nil)
	rec := httptest.NewRecorder()
	signHandler(rec, req)
	if rec.Code != 200 {
		t.Fatalf("signHandler returned status %d, body %q", rec.Code, rec.Body.String())
	}
	return decodeClaims(t, rec.Body.String())
}

func TestMain(m *testing.M) {
	// signHandler needs at least one signing key present.
	if err := mintKey("k1"); err != nil {
		panic(err)
	}
	m.Run()
}

func TestSignHandler_NoRoleParameter_RolesClaimAbsent(t *testing.T) {
	claims := sign(t, "email=alice@example.com")
	if v, present := claims["roles"]; present {
		t.Fatalf("expected no roles claim when no role parameter is supplied, got %#v", v)
	}
}

func TestSignHandler_OneRole(t *testing.T) {
	claims := sign(t, "email=alice@example.com&role=idp-readers")
	assertRolesClaim(t, claims, []string{"idp-readers"})
}

func TestSignHandler_MultipleRepeatedRoles(t *testing.T) {
	v := url.Values{}
	v.Set("email", "alice@example.com")
	v.Add("role", "idp-readers")
	v.Add("role", "idp-engineers")
	claims := sign(t, v.Encode())
	assertRolesClaim(t, claims, []string{"idp-readers", "idp-engineers"})
}

func TestSignHandler_RolesClaimIsJSONArrayOfStrings(t *testing.T) {
	v := url.Values{}
	v.Set("email", "alice@example.com")
	v.Add("role", "idp-readers")
	v.Add("role", "idp-engineers")
	req := httptest.NewRequest("POST", "/sign?"+v.Encode(), nil)
	rec := httptest.NewRecorder()
	signHandler(rec, req)
	if rec.Code != 200 {
		t.Fatalf("signHandler returned status %d, body %q", rec.Code, rec.Body.String())
	}

	parts := strings.Split(rec.Body.String(), ".")
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWT with 3 segments, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to base64-decode JWT payload: %v", err)
	}

	// Decode into raw JSON to inspect the concrete JSON type of "roles",
	// rather than relying on Go's map[string]any unmarshaling behavior.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatalf("failed to unmarshal JWT payload: %v", err)
	}
	rolesRaw, present := raw["roles"]
	if !present {
		t.Fatalf("expected roles claim to be present")
	}

	var asStringSlice []string
	if err := json.Unmarshal(rolesRaw, &asStringSlice); err != nil {
		t.Fatalf("roles claim did not decode as a JSON array of strings: %v (raw: %s)", err, rolesRaw)
	}
	if len(asStringSlice) != 2 || asStringSlice[0] != "idp-readers" || asStringSlice[1] != "idp-engineers" {
		t.Fatalf("unexpected roles claim contents: %#v", asStringSlice)
	}

	// Also confirm the raw JSON is actually an array ('[') and not, say,
	// an object or a single string.
	trimmed := strings.TrimSpace(string(rolesRaw))
	if !strings.HasPrefix(trimmed, "[") {
		t.Fatalf("expected roles claim to be a JSON array, got: %s", trimmed)
	}
}

func assertRolesClaim(t *testing.T, claims map[string]any, want []string) {
	t.Helper()
	rawRoles, present := claims["roles"]
	if !present {
		t.Fatalf("expected roles claim to be present, got claims: %#v", claims)
	}
	rolesAny, ok := rawRoles.([]any)
	if !ok {
		t.Fatalf("expected roles claim to decode as a JSON array, got %T: %#v", rawRoles, rawRoles)
	}
	if len(rolesAny) != len(want) {
		t.Fatalf("expected %d roles, got %d: %#v", len(want), len(rolesAny), rolesAny)
	}
	for i, r := range rolesAny {
		s, ok := r.(string)
		if !ok {
			t.Fatalf("expected roles[%d] to be a string, got %T: %#v", i, r, r)
		}
		if s != want[i] {
			t.Fatalf("expected roles[%d] = %q, got %q", i, want[i], s)
		}
	}
}

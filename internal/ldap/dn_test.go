package ldap

import "testing"

const dnTestUserBase = "ou=users,dc=altinity,dc=internal"

func newTestUserBase(t *testing.T) *UserBaseDN {
	t.Helper()
	b, err := NewUserBaseDN(dnTestUserBase, "uid")
	if err != nil {
		t.Fatalf("NewUserBaseDN: %v", err)
	}
	return b
}

func TestNewUserBaseDN_InvalidConfiguredBase(t *testing.T) {
	if _, err := NewUserBaseDN("not-a-dn-no-equals-sign", "uid"); err == nil {
		t.Fatalf("NewUserBaseDN with unparsable base DN: want error, got nil")
	}
}

func TestNewUserBaseDN_EmptyRDNAttribute(t *testing.T) {
	if _, err := NewUserBaseDN(dnTestUserBase, ""); err == nil {
		t.Fatalf("NewUserBaseDN with empty rdnAttribute: want error, got nil")
	}
}

func TestExtractUsername_Valid(t *testing.T) {
	b := newTestUserBase(t)
	got, err := b.ExtractUsername("uid=alice," + dnTestUserBase)
	if err != nil {
		t.Fatalf("ExtractUsername: unexpected error: %v", err)
	}
	if got != "alice" {
		t.Fatalf("ExtractUsername = %q, want %q", got, "alice")
	}
}

func TestExtractUsername_EscapedCharactersPreserved(t *testing.T) {
	b := newTestUserBase(t)
	cases := map[string]struct {
		bindDN string
		want   string
	}{
		"escaped comma": {
			bindDN: `uid=alice\, jones,` + dnTestUserBase,
			want:   "alice, jones",
		},
		"escaped plus": {
			bindDN: `uid=alice\+bob,` + dnTestUserBase,
			want:   "alice+bob",
		},
		"escaped backslash": {
			bindDN: `uid=alice\\bob,` + dnTestUserBase,
			want:   `alice\bob`,
		},
		"escaped equals (injection attempt)": {
			bindDN: `uid=alice\=admin,` + dnTestUserBase,
			want:   "alice=admin",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := b.ExtractUsername(tc.bindDN)
			if err != nil {
				t.Fatalf("ExtractUsername(%q): unexpected error: %v", tc.bindDN, err)
			}
			if got != tc.want {
				t.Fatalf("ExtractUsername(%q) = %q, want %q", tc.bindDN, got, tc.want)
			}
		})
	}
}

func TestExtractUsername_Rejects(t *testing.T) {
	b := newTestUserBase(t)
	cases := map[string]string{
		"extra RDN above the base": "uid=alice,ou=sub," + dnTestUserBase,
		"multivalued leading RDN":  "uid=alice+cn=Alice," + dnTestUserBase,
		"wrong RDN attribute":      "cn=alice," + dnTestUserBase,
		"wrong base":               "uid=alice,ou=other,dc=altinity,dc=internal",
		"missing base entirely":    "uid=alice",
		"too many RDNs below base": "uid=alice,ou=extra,ou=sub," + dnTestUserBase,
		"malformed DN":             "not-a-dn-no-equals-sign",
		"empty username value":     "uid=," + dnTestUserBase,
		"injection via extra unescaped RDN appended to base": "uid=alice," + dnTestUserBase + "," + dnTestUserBase,
	}
	for name, bindDN := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := b.ExtractUsername(bindDN); err == nil {
				t.Fatalf("ExtractUsername(%q) = (%q, nil), want an error", bindDN, got)
			}
		})
	}
}

func TestGroupBaseDN_Equal(t *testing.T) {
	g, err := NewGroupBaseDN("ou=groups,dc=altinity,dc=internal")
	if err != nil {
		t.Fatalf("NewGroupBaseDN: %v", err)
	}

	if !g.Equal("ou=groups,dc=altinity,dc=internal") {
		t.Fatalf("Equal on identical base DN = false, want true")
	}
	if !g.Equal("ou =  groups , dc=altinity, dc=internal") {
		t.Fatalf("Equal on structurally-equal spaced base DN = false, want true")
	}
	if g.Equal("ou=users,dc=altinity,dc=internal") {
		t.Fatalf("Equal on a different base DN = true, want false")
	}
	if g.Equal("not-a-dn-no-equals-sign") {
		t.Fatalf("Equal on unparsable candidate = true, want false")
	}
}

func TestNewGroupBaseDN_InvalidConfiguredBase(t *testing.T) {
	if _, err := NewGroupBaseDN("not-a-dn-no-equals-sign"); err == nil {
		t.Fatalf("NewGroupBaseDN with unparsable base DN: want error, got nil")
	}
}

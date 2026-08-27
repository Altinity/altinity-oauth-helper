package ldap

import (
	"reflect"
	"testing"
)

func newTestGroupBase(t *testing.T) *GroupBaseDN {
	t.Helper()
	g, err := NewGroupBaseDN("ou=groups,dc=altinity,dc=internal")
	if err != nil {
		t.Fatalf("NewGroupBaseDN: %v", err)
	}
	return g
}

func TestNewGroupEntry_Fields(t *testing.T) {
	g := newTestGroupBase(t)
	entry, err := NewGroupEntry(g, "clickhouse_", "ch_engineer", "uid=alice,ou=users,dc=altinity,dc=internal")
	if err != nil {
		t.Fatalf("NewGroupEntry: %v", err)
	}

	if entry.CN != "clickhouse_ch_engineer" {
		t.Fatalf("CN = %q, want %q", entry.CN, "clickhouse_ch_engineer")
	}
	wantDN := "cn=clickhouse_ch_engineer,ou=groups,dc=altinity,dc=internal"
	if entry.DN != wantDN {
		t.Fatalf("DN = %q, want %q", entry.DN, wantDN)
	}
	if entry.Member != "uid=alice,ou=users,dc=altinity,dc=internal" {
		t.Fatalf("Member = %q, want the exact bound DN", entry.Member)
	}
}

func TestNewGroupEntry_SpecialCharacterRoleEscaping(t *testing.T) {
	g := newTestGroupBase(t)

	cases := map[string]struct {
		role    string
		wantCN  string
		wantDN  string
	}{
		"comma in role": {
			role:   `ch_a,b`,
			wantCN: `clickhouse_ch_a,b`,
			wantDN: `cn=clickhouse_ch_a\,b,ou=groups,dc=altinity,dc=internal`,
		},
		"plus in role": {
			role:   `ch_a+b`,
			wantCN: `clickhouse_ch_a+b`,
			wantDN: `cn=clickhouse_ch_a\+b,ou=groups,dc=altinity,dc=internal`,
		},
		"equals in role (unescaped in value position per RFC 4514)": {
			role:   `ch_a=b`,
			wantCN: `clickhouse_ch_a=b`,
			wantDN: `cn=clickhouse_ch_a=b,ou=groups,dc=altinity,dc=internal`,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			entry, err := NewGroupEntry(g, "clickhouse_", tc.role, "uid=alice,ou=users,dc=altinity,dc=internal")
			if err != nil {
				t.Fatalf("NewGroupEntry(%q): unexpected error: %v", tc.role, err)
			}
			if entry.CN != tc.wantCN {
				t.Fatalf("CN = %q, want %q", entry.CN, tc.wantCN)
			}
			if entry.DN != tc.wantDN {
				t.Fatalf("DN = %q, want %q (role must be structurally escaped, never concatenated raw)", entry.DN, tc.wantDN)
			}
		})
	}
}

func TestNewGroupEntry_RejectsInvalidInput(t *testing.T) {
	g := newTestGroupBase(t)

	if _, err := NewGroupEntry(nil, "clickhouse_", "ch_engineer", "uid=alice,ou=users,dc=altinity,dc=internal"); err == nil {
		t.Fatalf("NewGroupEntry with nil group base: want error, got nil")
	}
	if _, err := NewGroupEntry(g, "clickhouse_", "", "uid=alice,ou=users,dc=altinity,dc=internal"); err == nil {
		t.Fatalf("NewGroupEntry with empty role: want error, got nil")
	}
}

func TestGroupEntry_ProjectedAttributes(t *testing.T) {
	g := newTestGroupBase(t)
	entry, err := NewGroupEntry(g, "clickhouse_", "ch_engineer", "uid=alice,ou=users,dc=altinity,dc=internal")
	if err != nil {
		t.Fatalf("NewGroupEntry: %v", err)
	}

	full := []groupAttribute{
		{name: "objectClass", values: []string{"groupOfNames"}},
		{name: "cn", values: []string{"clickhouse_ch_engineer"}},
		{name: "member", values: []string{"uid=alice,ou=users,dc=altinity,dc=internal"}},
	}

	cases := map[string]struct {
		requested []string
		want      []groupAttribute
	}{
		"empty selection returns full entry": {
			requested: nil,
			want:      full,
		},
		"star returns full entry": {
			requested: []string{"*"},
			want:      full,
		},
		"explicit subset cn only": {
			requested: []string{"cn"},
			want:      []groupAttribute{{name: "cn", values: []string{"clickhouse_ch_engineer"}}},
		},
		"explicit subset case-insensitive": {
			requested: []string{"OBJECTCLASS", "Member"},
			want: []groupAttribute{
				{name: "objectClass", values: []string{"groupOfNames"}},
				{name: "member", values: []string{"uid=alice,ou=users,dc=altinity,dc=internal"}},
			},
		},
		"1.1 returns nothing": {
			requested: []string{"1.1"},
			want:      nil,
		},
		"unknown attribute returns nothing new": {
			requested: []string{"description"},
			want:      []groupAttribute{},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := entry.projectedAttributes(tc.requested)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("projectedAttributes(%v) = %+v, want %+v", tc.requested, got, tc.want)
			}
		})
	}
}

func TestGroupEntry_Render_DoesNotPanic(t *testing.T) {
	// message.SearchResultEntry exposes no exported way to read back its
	// contents (only SetObjectName/AddAttribute setters), so a genuine
	// content assertion on the rendered wire type belongs to the real TCP
	// protocol harness (a later phase's protocol_test.go), not here. This
	// exercises Render's call shape across every projection/typesOnly
	// combination to prove it constructs a valid entry without panicking.
	g := newTestGroupBase(t)
	entry, err := NewGroupEntry(g, "clickhouse_", "ch_engineer", "uid=alice,ou=users,dc=altinity,dc=internal")
	if err != nil {
		t.Fatalf("NewGroupEntry: %v", err)
	}

	selections := [][]string{nil, {"*"}, {"cn"}, {"1.1"}, {"unknown"}}
	for _, sel := range selections {
		for _, typesOnly := range []bool{false, true} {
			_ = entry.Render(sel, typesOnly)
		}
	}
}

package profile

import "testing"

// mustParse parses raw and fails the test immediately on error.
func mustParse(t *testing.T, raw string) DN {
	t.Helper()
	dn, err := ParseDN(raw)
	if err != nil {
		t.Fatalf("ParseDN(%q): unexpected error: %v", raw, err)
	}
	return dn
}

// TestParseDN_Accepted covers every accepted form named in dn.go's grammar
// doc comment: comma-separated RDNs, case-insensitive descriptors, the
// first unescaped '=' separator, simple and hex escapes, multi-byte UTF-8,
// insignificant unescaped boundary spaces, and significant escaped
// leading/trailing spaces.
func TestParseDN_Accepted(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		wantCount  int
		checkIndex int // which RDN to check attrType/value against
		wantType   string
		wantValue  string
	}{
		{"simple single RDN", "cn=alice", 1, 0, "cn", "alice"},
		{"multiple RDNs", "cn=alice,dc=example,dc=com", 3, 0, "cn", "alice"},
		{"hyphenated descriptor", "user-id=alice", 1, 0, "user-id", "alice"},
		{"digits after first letter", "cn2=alice", 1, 0, "cn2", "alice"},
		{"uppercase descriptor", "CN=alice", 1, 0, "CN", "alice"},
		{"simple escape comma", `cn=al\,ice`, 1, 0, "cn", "al,ice"},
		{"simple escape plus", `cn=al\+ice`, 1, 0, "cn", "al+ice"},
		{"simple escape semicolon", `cn=al\;ice`, 1, 0, "cn", "al;ice"},
		{"simple escape quote", `cn=al\"ice`, 1, 0, "cn", `al"ice`},
		{"simple escape lt/gt", `cn=\<alice\>`, 1, 0, "cn", "<alice>"},
		{"simple escape equals", `cn=al\=ice`, 1, 0, "cn", "al=ice"},
		{"simple escape backslash", `cn=al\\ice`, 1, 0, "cn", `al\ice`},
		{"simple escape hash mid-value", `cn=al\#ice`, 1, 0, "cn", "al#ice"},
		{"hex escape ascii", `cn=\61\6c\69\63\65`, 1, 0, "cn", "alice"},
		{"hex escape mixed with raw", `cn=al\69ce`, 1, 0, "cn", "alice"},
		{"hex escape multi-byte UTF-8", `cn=\c3\a9`, 1, 0, "cn", "é"}, // é
		{"raw multi-byte UTF-8", "cn=café", 1, 0, "cn", "café"},
		{"insignificant space before type", "cn=alice, dc=example", 2, 1, "dc", "example"},
		{"insignificant space around equals", "cn = alice", 1, 0, "cn", "alice"},
		{"insignificant leading space in value", "cn=  alice", 1, 0, "cn", "alice"},
		{"insignificant trailing space in value", "cn=alice  ", 1, 0, "cn", "alice"},
		{"insignificant trailing space before comma", "cn=alice ,dc=com", 2, 0, "cn", "alice"},
		{"escaped leading space significant", `cn=\ alice`, 1, 0, "cn", " alice"},
		{"escaped trailing space significant", `cn=alice\ `, 1, 0, "cn", "alice "},
		{"escaped leading space via hex", `cn=\20alice`, 1, 0, "cn", " alice"},
		{"escaped trailing space via hex", `cn=alice\20`, 1, 0, "cn", "alice "},
		{"literal interior space", "cn=alice bob", 1, 0, "cn", "alice bob"},
		{"empty DN", "", 0, 0, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dn := mustParse(t, tc.raw)
			if dn.RDNCount() != tc.wantCount {
				t.Fatalf("ParseDN(%q).RDNCount() = %d, want %d", tc.raw, dn.RDNCount(), tc.wantCount)
			}
			if tc.wantCount == 0 {
				return
			}
			got := dn.rdns[tc.checkIndex]
			if got.attrType != tc.wantType || got.value != tc.wantValue {
				t.Fatalf("ParseDN(%q) RDN[%d] = {%q,%q}, want {%q,%q}", tc.raw, tc.checkIndex, got.attrType, got.value, tc.wantType, tc.wantValue)
			}
		})
	}
}

// TestParseDN_Rejected covers every unsupported form named in dn.go's
// grammar doc comment, plus hostile/malformed inputs: invalid UTF-8, NUL,
// malformed/odd-length hex escapes, and a trailing backslash.
func TestParseDN_Rejected(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"unescaped plus multi-valued RDN", "cn=alice+sn=smith"},
		{"semicolon RDN separator", "cn=alice;dc=com"},
		{"leading hash BER hexstring", "cn=#04024869"},
		{"dotted-decimal OID type", "0.9.2342.19200300.100.1.1=alice"},
		{"escaped attribute type", `\63n=alice`},
		{"empty attribute type", "=alice"},
		{"missing equals", "cnalice"},
		{"space inside descriptor", "c n=alice"},
		{"descriptor starting with digit", "1cn=alice"},
		{"invalid UTF-8 via hex escape", `cn=\ff\fe`},
		{"NUL via hex escape", `cn=al\00ice`},
		{"trailing backslash", `cn=alice\`},
		{"odd-length hex escape at end", `cn=alice\4`},
		{"non-hex second escape digit", `cn=alice\4z`},
		{"malformed hex escape both non-hex", `cn=alice\zz`},
		{"trailing comma with nothing after", "cn=alice,"},
		{"empty RDN between commas", "cn=alice,,dc=com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseDN(tc.raw); err == nil {
				t.Fatalf("ParseDN(%q): expected error, got success", tc.raw)
			}
		})
	}
}

// TestParseDN_LargeButBounded proves the parser handles a syntactically
// well-formed, deliberately large DN without panicking, looping, or
// otherwise misbehaving — dn.go imposes no artificial length cap of its
// own (any wire-level body-size bound belongs to the framing layer).
func TestParseDN_LargeButBounded(t *testing.T) {
	raw := "cn=alice"
	for i := 0; i < 500; i++ {
		raw += ",dc=example"
	}
	dn, err := ParseDN(raw)
	if err != nil {
		t.Fatalf("ParseDN(large DN): unexpected error: %v", err)
	}
	if got, want := dn.RDNCount(), 501; got != want {
		t.Fatalf("RDNCount() = %d, want %d", got, want)
	}
}

// TestDN_Equal covers the equivalence table: equivalent escaping/type-case
// spellings compare equal, different decoded values compare unequal, and a
// candidate whose raw text ends with the base's text as a byte-for-byte
// substring — but whose RDN structure genuinely differs — compares
// unequal. This last group is also this file's sabotage-detecting case for
// "structural DN comparison replaced with suffix text" (see the parent
// plan's sabotage checklist): sabotaging Equal (or ParseBindDN) into any
// form of rendered-text/suffix comparison must make these fail.
func TestDN_Equal(t *testing.T) {
	t.Run("equivalent escaping and type-case spellings are equal", func(t *testing.T) {
		a := mustParse(t, "cn=alice,dc=example,dc=com")
		b := mustParse(t, `CN=\61lice,DC=example,Dc=com`)
		if !a.Equal(b) {
			t.Fatalf("expected %q and %q to be structurally equal", a.String(), b.String())
		}
		if !b.Equal(a) {
			t.Fatalf("Equal must be symmetric")
		}
	})

	t.Run("different decoded values are unequal", func(t *testing.T) {
		a := mustParse(t, "cn=alice,dc=example,dc=com")
		b := mustParse(t, "cn=alicia,dc=example,dc=com")
		if a.Equal(b) {
			t.Fatalf("expected different values to compare unequal")
		}
	})

	t.Run("different RDN counts are unequal", func(t *testing.T) {
		a := mustParse(t, "dc=example,dc=com")
		b := mustParse(t, "dc=com")
		if a.Equal(b) {
			t.Fatalf("expected different RDN counts to compare unequal")
		}
	})

	t.Run("suffix-only match is unequal", func(t *testing.T) {
		// base's rendered text is exactly "dc=example,dc=com" (17 bytes,
		// unmodified by escaping since neither "example" nor "com" needs
		// it). The raw candidate literal below is deliberately built so it
		// ends with that exact text as a byte-for-byte substring
		// ("cn=Xdc=example,dc=com" ends with "dc=example,dc=com"), while
		// its actual RDN structure is a completely different 2-RDN DN —
		// [{cn,"Xdc=example"},{dc,"com"}] versus base's
		// [{dc,"example"},{dc,"com"}] — because the parser only treats the
		// comma before "dc=com" as an RDN boundary, not the '=' inside
		// "Xdc=example". A HasSuffix(rawCandidate, base.String())-shaped
		// comparison would wrongly call these equal; structural comparison
		// must not.
		const rawCandidate = "cn=Xdc=example,dc=com"
		base := mustParse(t, "dc=example,dc=com")
		candidate := mustParse(t, rawCandidate)

		wantSuffix := base.String()
		if len(rawCandidate) < len(wantSuffix) || rawCandidate[len(rawCandidate)-len(wantSuffix):] != wantSuffix {
			t.Fatalf("test fixture invariant broken: %q does not end with %q", rawCandidate, wantSuffix)
		}
		if candidate.Equal(base) {
			t.Fatalf("suffix-only text match %q must not be structurally equal to base %q", rawCandidate, wantSuffix)
		}
	})
}

// TestDN_String_RoundTrip proves String()+ParseDN round-trips to a
// structurally equal DN for every accepted form.
func TestDN_String_RoundTrip(t *testing.T) {
	inputs := []string{
		"cn=alice,dc=example,dc=com",
		`cn=al\,ice\+bob\;carol\"dave\<eve\>frank\=grace\\henry`,
		`cn=\ leading and trailing\ `,
		"cn=a#notleadinghash", // '#' not at value start: literal, no escaping needed
		"cn=café",
	}
	for _, raw := range inputs {
		t.Run(raw, func(t *testing.T) {
			dn := mustParse(t, raw)
			rendered := dn.String()
			reparsed, err := ParseDN(rendered)
			if err != nil {
				t.Fatalf("re-parsing rendered form %q: %v", rendered, err)
			}
			if !dn.Equal(reparsed) {
				t.Fatalf("round-trip mismatch: original %+v, rendered %q, reparsed %+v", dn, rendered, reparsed)
			}
		})
	}
}

// TestParseBindDN covers the Bind-shape helper's positive and negative
// cases: exact shape acceptance, an extra RDN, wrong base, wrong
// attribute, empty username, and the suffix-only-match rejection (this
// function's own sabotage-detecting case, exercised through the actual
// production entry point rather than only DN.Equal directly).
func TestParseBindDN(t *testing.T) {
	base := mustParse(t, "dc=example,dc=com")

	t.Run("exact shape succeeds", func(t *testing.T) {
		username, err := ParseBindDN("cn=alice,dc=example,dc=com", base, "cn")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if username != "alice" {
			t.Fatalf("username = %q, want %q", username, "alice")
		}
	})

	t.Run("case-insensitive configured attribute", func(t *testing.T) {
		username, err := ParseBindDN("CN=alice,dc=example,dc=com", base, "cn")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if username != "alice" {
			t.Fatalf("username = %q, want %q", username, "alice")
		}
	})

	t.Run("extra RDN above base rejected", func(t *testing.T) {
		if _, err := ParseBindDN("ou=people,cn=alice,dc=example,dc=com", base, "cn"); err == nil {
			t.Fatalf("expected error for extra RDN above base")
		}
	})

	t.Run("wrong base rejected", func(t *testing.T) {
		if _, err := ParseBindDN("cn=alice,dc=other,dc=com", base, "cn"); err == nil {
			t.Fatalf("expected error for wrong base")
		}
	})

	t.Run("wrong leading attribute rejected", func(t *testing.T) {
		if _, err := ParseBindDN("uid=alice,dc=example,dc=com", base, "cn"); err == nil {
			t.Fatalf("expected error for wrong leading attribute")
		}
	})

	t.Run("empty username rejected", func(t *testing.T) {
		if _, err := ParseBindDN("cn=,dc=example,dc=com", base, "cn"); err == nil {
			t.Fatalf("expected error for empty username")
		}
	})

	t.Run("malformed candidate rejected", func(t *testing.T) {
		if _, err := ParseBindDN("cn=alice+sn=x,dc=example,dc=com", base, "cn"); err == nil {
			t.Fatalf("expected error for malformed candidate")
		}
	})

	t.Run("suffix-only match rejected", func(t *testing.T) {
		// Same construction as TestDN_Equal's suffix-only case: raw text
		// ends with base's rendered text, but the RDN count (2, not 3)
		// and structure are wrong. A suffix/text-based Bind-shape check
		// would wrongly accept this; ParseBindDN must not.
		if _, err := ParseBindDN("cn=Xdc=example,dc=com", base, "cn"); err == nil {
			t.Fatalf("expected error for suffix-only match")
		}
	})
}

func TestValidAttributeDescriptor(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"cn", true},
		{"user-id", true},
		{"cn2", true},
		{"CN", true},
		{"", false},
		{"1cn", false},
		{"cn.1", false},
		{"0.9.2342.19200300.100.1.1", false},
		{"cn ", false},
		{" cn", false},
	}
	for _, tc := range cases {
		if got := ValidAttributeDescriptor(tc.s); got != tc.want {
			t.Errorf("ValidAttributeDescriptor(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

// TestEscapeDNValue_SpecialValues covers the renderer's special-value
// cases named in the sub-task description: ',', '+', '"', '\', '<', '>',
// ';', '=', leading/trailing space, and leading '#'.
func TestEscapeDNValue_SpecialValues(t *testing.T) {
	cases := []struct {
		name  string
		value string
	}{
		{"comma", "a,b"},
		{"plus", "a+b"},
		{"quote", `a"b`},
		{"backslash", `a\b`},
		{"less-than", "a<b"},
		{"greater-than", "a>b"},
		{"semicolon", "a;b"},
		{"equals", "a=b"},
		{"leading space", " ab"},
		{"trailing space", "ab "},
		{"leading and trailing space", " ab "},
		{"leading hash", "#ab"},
		{"hash mid-value", "a#b"},
		{"empty", ""},
		{"single space", " "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			escaped := EscapeDNValue(tc.value)
			dn, err := ParseDN("cn=" + escaped)
			if err != nil {
				t.Fatalf("EscapeDNValue(%q) = %q, which failed to re-parse: %v", tc.value, escaped, err)
			}
			if dn.RDNCount() != 1 || dn.rdns[0].value != tc.value {
				got := ""
				if dn.RDNCount() == 1 {
					got = dn.rdns[0].value
				}
				t.Fatalf("EscapeDNValue(%q) = %q, round-tripped to %q", tc.value, escaped, got)
			}
		})
	}
}

func TestRenderGroupDN(t *testing.T) {
	t.Run("empty role is skipped, not an error", func(t *testing.T) {
		dn, ok := RenderGroupDN("dc=example,dc=com", "clickhouse_", "")
		if ok || dn != "" {
			t.Fatalf("RenderGroupDN with empty role = (%q, %v), want (\"\", false)", dn, ok)
		}
	})

	t.Run("non-empty role renders and re-parses to expected shape", func(t *testing.T) {
		dn, ok := RenderGroupDN("dc=example,dc=com", "clickhouse_", "ch_readonly")
		if !ok {
			t.Fatalf("expected RenderGroupDN to succeed")
		}
		const want = "cn=clickhouse_ch_readonly,dc=example,dc=com"
		if dn != want {
			t.Fatalf("RenderGroupDN = %q, want %q", dn, want)
		}
		parsed, err := ParseDN(dn)
		if err != nil {
			t.Fatalf("rendered group DN failed to re-parse: %v", err)
		}
		base := mustParse(t, "dc=example,dc=com")
		if parsed.RDNCount() != base.RDNCount()+1 {
			t.Fatalf("rendered group DN has %d RDNs, want %d", parsed.RDNCount(), base.RDNCount()+1)
		}
		if parsed.rdns[0].attrType != "cn" || parsed.rdns[0].value != "clickhouse_ch_readonly" {
			t.Fatalf("rendered group DN leading RDN = %+v, want cn=clickhouse_ch_readonly", parsed.rdns[0])
		}
	})

	t.Run("special-value role escapes safely and round-trips", func(t *testing.T) {
		dn, ok := RenderGroupDN("dc=example,dc=com", "", `weird,role+with"special<chars>;and=backslash\`)
		if !ok {
			t.Fatalf("expected RenderGroupDN to succeed")
		}
		parsed, err := ParseDN(dn)
		if err != nil {
			t.Fatalf("rendered group DN failed to re-parse: %v", err)
		}
		if got, want := parsed.rdns[0].value, `weird,role+with"special<chars>;and=backslash\`; got != want {
			t.Fatalf("round-tripped role = %q, want %q", got, want)
		}
	})
}

// --- Sabotage checks -------------------------------------------------
//
// These are documented here (not run automatically as part of the normal
// suite) so the exact mutation and expected failure are reproducible on
// demand, per the sub-task's definition of done:
//
//   (a) Replace DN.Equal's per-RDN structural comparison with a rendered-
//       text suffix/substring comparison (e.g.
//       `return strings.HasSuffix(d.String(), other.String())`) and confirm
//       TestDN_Equal's "suffix-only match is unequal" subtest and
//       TestParseBindDN's "suffix-only match rejected" subtest both fail.
//   (b) In ParseDN's RDN-separator switch, change `case '+':` to fall
//       through to the ',' case (i.e. accept an unescaped '+' as another
//       RDN separator instead of rejecting it) and confirm
//       TestParseDN_Rejected's "unescaped plus multi-valued RDN" subtest
//       fails.
//
// Both were exercised manually against this file during implementation
// (mutate dn.go in place, `go test ./internal/ldap/profile -run
// TestDN_Equal|TestParseBindDN|TestParseDN_Rejected`, confirm failure,
// restore dn.go from saved bytes) and are not re-run automatically because
// they require editing production source, which this suite must not do
// implicitly.

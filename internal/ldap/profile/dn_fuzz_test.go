package profile

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// This file provides the two DN-grammar native fuzz targets named in the
// Phase 2 plan's "Native fuzzing" section: FuzzRestrictedDN (the general
// grammar, exercised through ParseDN) and FuzzMemberAssertionDN (the same
// grammar, seeded to emphasize member-assertion-shaped inputs — a bound
// DN's exact text, as it appears inside the fixed membership filter's
// equalityMatch assertion value). Both use the same parser (ParseDN is the
// package's sole parse entry point) and the same body, since the grammar
// itself does not distinguish its callers; only the seed corpora differ in
// intent.
//
// Both fuzz bodies assert:
//  1. ParseDN never panics on any input;
//  2. an accepted input round-trips: ParseDN(raw) -> dn ->
//     ParseDN(dn.String()) -> dn2, and dn.Equal(dn2) holds;
//  3. no accepted (successfully parsed) input contains a NUL byte or is
//     not valid UTF-8 anywhere in its decoded RDN values.
//
// Run as a short documented smoke, e.g.:
//
//	go test ./internal/ldap/profile -run '^$' -fuzz=FuzzRestrictedDN -fuzztime=15s
//	go test ./internal/ldap/profile -run '^$' -fuzz=FuzzMemberAssertionDN -fuzztime=15s
//
// Every committed seed below runs during ordinary `go test` too (fuzz seed
// corpora are executed as regular subtests when -fuzz is not passed), so
// neither target adds to the suite's runtime beyond that.

func fuzzRestrictedDNBody(t *testing.T, raw string) {
	dn, err := ParseDN(raw)
	if err != nil {
		return // malformed input is a valid, non-panicking outcome
	}

	for i := 0; i < dn.RDNCount(); i++ {
		value := dn.rdns[i].value
		if strings.IndexByte(value, 0) != -1 {
			t.Fatalf("ParseDN(%q) accepted a value containing NUL: RDN[%d] = %q", raw, i, value)
		}
		if !utf8.ValidString(value) {
			t.Fatalf("ParseDN(%q) accepted a value that is not valid UTF-8: RDN[%d] = %q", raw, i, value)
		}
	}

	rendered := dn.String()
	reparsed, err := ParseDN(rendered)
	if err != nil {
		t.Fatalf("ParseDN(%q) succeeded, but re-parsing its rendered form %q failed: %v", raw, rendered, err)
	}
	if !dn.Equal(reparsed) {
		t.Fatalf("round-trip mismatch for %q: parsed %+v, rendered %q, reparsed %+v", raw, dn, rendered, reparsed)
	}
}

// dnFuzzSeeds are the shared committed seeds for both DN fuzz targets,
// covering: supported simple and hex escapes, multi-byte UTF-8, invalid
// UTF-8/NUL, unescaped '+'/';'/'#' (rejected forms), an OID-shaped type
// (rejected), whitespace around type/value separators, and edge (leading/
// trailing/escaped) spaces — the exact set named in the sub-task
// description's "DN seeds" list.
var dnFuzzSeeds = []string{
	// Accepted forms.
	"cn=alice",
	"cn=alice,dc=example,dc=com",
	"CN=Alice,DC=Example,DC=Com",
	`cn=al\,ice\+bob\;carol\"dave\<eve\>frank\=grace\\henry`,
	`cn=\61\6c\69\63\65`,                 // hex escapes spelling "alice"
	`cn=\c3\a9`,                          // hex escapes forming multi-byte UTF-8 (é)
	"cn=café",                            // raw multi-byte UTF-8
	"cn=alice, dc=example",               // insignificant space before type
	"cn = alice",                         // insignificant space around '='
	"cn=  alice  ",                       // insignificant leading/trailing space
	`cn=\ alice\ `,                       // escaped, significant leading/trailing space
	`cn=\20alice\20`,                     // same, via hex escape
	"",                                   // empty DN
	"o=x",                                // minimal single-letter type/value
	strings.Repeat("dc=x,", 64) + "dc=y", // large-but-bounded

	// Deliberately rejected forms (must not panic).
	"cn=alice+sn=smith",               // unescaped '+' — multi-valued RDN
	"cn=alice;dc=com",                 // ';' RDN separator
	"cn=#04024869",                    // leading '#' BER-hexstring value
	"0.9.2342.19200300.100.1.1=alice", // dotted-decimal OID type
	`\63n=alice`,                      // escaped attribute-type name
	`cn=\ff\fe`,                       // hex escapes decoding to invalid UTF-8
	`cn=al\00ice`,                     // hex escape decoding to NUL
	`cn=alice\`,                       // trailing backslash
	`cn=alice\4`,                      // odd-length hex escape
	`cn=alice\zz`,                     // malformed (non-hex) escape
	"cn=alice,",                       // trailing comma, nothing after
	"cn=alice,,dc=com",                // empty RDN between commas
	"cnalice",                         // missing '='
	"=alice",                          // empty attribute type
	"1cn=alice",                       // type starting with a digit
}

// FuzzRestrictedDN fuzzes ParseDN directly over the general restricted DN
// grammar (configured bases and Bind DNs are its main callers).
func FuzzRestrictedDN(f *testing.F) {
	for _, seed := range dnFuzzSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		fuzzRestrictedDNBody(t, raw)
	})
}

// memberAssertionFuzzSeeds layers member-assertion-flavored inputs (typical
// bound-DN shapes as they would appear inside the fixed membership filter's
// member equalityMatch assertion value) on top of the shared seed corpus.
var memberAssertionFuzzSeeds = append(append([]string{}, dnFuzzSeeds...),
	"cn=alice,ou=users,dc=example,dc=com",
	"CN=Bob,OU=Users,DC=Example,DC=Com",
	`cn=al\69ce,dc=example,dc=com`,
	"cn=alice+uid=alice,dc=example,dc=com", // unescaped '+' member DN
)

// FuzzMemberAssertionDN fuzzes ParseDN over member-assertion-shaped inputs.
// It uses exactly the same grammar and the same body as FuzzRestrictedDN
// (the plan requires one parser used uniformly for every caller); this
// target exists to seed and explore the corpus from the member-assertion
// angle specifically, per the plan's separately named fuzz target.
func FuzzMemberAssertionDN(f *testing.F) {
	for _, seed := range memberAssertionFuzzSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		fuzzRestrictedDNBody(t, raw)
	})
}

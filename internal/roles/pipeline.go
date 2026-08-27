// Package roles implements the Antalya-aligned groups-to-roles derivation
// pipeline shared by ch-jwt-verify and the future LDAP helper: extract a
// string-array groups claim, map group names to role candidates, keep only
// candidates that fully match an operator-configured regex, and optionally
// rewrite surviving candidates with a sed-style transform. All configuration
// (mapping keys aside) is compiled once at construction so no malformed
// operator input can silently degrade to "authenticate anyway" at request
// time.
package roles

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/altinity/go-mcp-oauth-sdk/oauth"
)

// ErrMalformedGroupsClaim means the configured groups claim was present but
// was not a string, nor an array whose every element is a string. Malformed
// groups claims are authentication failures for consumers of this package —
// never silently coerced to zero roles or to a stringified fallback.
var ErrMalformedGroupsClaim = errors.New("roles: groups claim is present but malformed")

// Config configures a Pipeline. GroupsClaim defaults to "groups" (Antalya's
// vocabulary) when empty. Mapping translates an IdP group name to a role
// candidate; groups with no mapping entry pass through unchanged so the
// filter (not the mapping step) is the fail-closed control. Filter, when
// non-empty, is a regex that a role candidate must match in its entirety
// (not merely contain) to survive. Transform, when non-empty, is an
// Antalya-style `s/pattern/replacement/flags` rewrite applied to surviving
// candidates, after filtering.
type Config struct {
	GroupsClaim string
	Mapping     map[string]string
	Filter      string
	Transform   string
}

// Pipeline is the immutable, compiled form of Config produced by New.
type Pipeline struct {
	groupsClaim string
	mapping     map[string]string
	filter      *regexp.Regexp // nil = no filtering
	transform   *sedTransform  // nil = identity
}

// New compiles cfg into a Pipeline. Any invalid filter regex or malformed
// transform syntax fails construction — no authentication-time fallback ever
// activates a pipeline whose configuration didn't compile.
func New(cfg Config) (*Pipeline, error) {
	groupsClaim := cfg.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}

	p := &Pipeline{groupsClaim: groupsClaim, mapping: cfg.Mapping}

	if strings.TrimSpace(cfg.Filter) != "" {
		re, err := regexp.Compile(cfg.Filter)
		if err != nil {
			return nil, fmt.Errorf("roles: invalid roles_filter regex: %w", err)
		}
		p.filter = re
	}

	if strings.TrimSpace(cfg.Transform) != "" {
		t, err := parseSedTransform(cfg.Transform)
		if err != nil {
			return nil, fmt.Errorf("roles: invalid roles_transform: %w", err)
		}
		p.transform = t
	}

	return p, nil
}

// Roles derives the final role list from claims: extract -> dedupe ->
// map -> full-match filter -> transform -> dedupe. Mapping happens before
// filtering, and transform happens after filtering, per the Antalya-aligned
// pipeline order — that ordering is normative, not an implementation detail.
func (p *Pipeline) Roles(claims *oauth.Claims) ([]string, error) {
	groups, err := p.extractGroups(claims)
	if err != nil {
		return nil, err
	}
	groups = dedupePreserveOrder(groups)

	mapped := make([]string, 0, len(groups))
	for _, g := range groups {
		candidate, ok := p.mapping[g]
		if !ok {
			candidate = g
		}
		mapped = append(mapped, candidate)
	}

	filtered := make([]string, 0, len(mapped))
	for _, candidate := range mapped {
		if p.matchesFilter(candidate) {
			filtered = append(filtered, candidate)
		}
	}

	transformed := make([]string, 0, len(filtered))
	for _, candidate := range filtered {
		if p.transform == nil {
			transformed = append(transformed, candidate)
			continue
		}
		transformed = append(transformed, p.transform.apply(candidate))
	}

	return dedupePreserveOrder(transformed), nil
}

// matchesFilter reports whether candidate survives the configured filter. An
// empty (unconfigured) filter means no filtering. The match must consume the
// entire candidate — regexp.MatchString-style substring matching would let
// an unexpected IdP group value pass through a restrictive-looking filter by
// merely containing the pattern somewhere inside a longer string.
func (p *Pipeline) matchesFilter(candidate string) bool {
	if p.filter == nil {
		return true
	}
	loc := p.filter.FindStringIndex(candidate)
	return loc != nil && loc[0] == 0 && loc[1] == len(candidate)
}

// extractGroups reads the configured groups claim from claims.Extra. A
// missing claim or an empty array yields an empty (nil) role list — not an
// error. Any other shape that isn't a string array is ErrMalformedGroupsClaim.
func (p *Pipeline) extractGroups(claims *oauth.Claims) ([]string, error) {
	if claims == nil {
		return nil, nil
	}
	raw, ok := claims.Extra[p.groupsClaim]
	if !ok {
		return nil, nil
	}
	switch v := raw.(type) {
	case []string:
		out := make([]string, len(v))
		copy(out, v)
		return out, nil
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%w: claim %q contains a non-string element", ErrMalformedGroupsClaim, p.groupsClaim)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: claim %q is not a string array", ErrMalformedGroupsClaim, p.groupsClaim)
	}
}

// dedupePreserveOrder removes duplicate strings, keeping the first
// occurrence's position. Used both after claim extraction (deduplicate
// groups) and after the full pipeline (deduplicate final roles, since
// distinct groups may map/transform onto the same role).
func dedupePreserveOrder(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// sedTransform is a compiled Antalya-style `s/pattern/replacement/flags`
// rewrite.
type sedTransform struct {
	re          *regexp.Regexp
	replacement string
	global      bool
}

// parseSedTransform parses and compiles spec. Supported forms:
//   - s<delim>pattern<delim>replacement<delim>flags
//   - flags is empty or exactly "g" (global replacement); any other flag, or
//     a repeated flag, is rejected.
//   - the delimiter may be escaped inside pattern/replacement as \<delim> to
//     include a literal delimiter character.
//
// Any other structure, or a pattern/replacement the delimiter-splitter can't
// resolve into exactly three fields, fails — this parser implements exactly
// the documented Antalya subset, not general sed.
func parseSedTransform(spec string) (*sedTransform, error) {
	if len(spec) < 2 || spec[0] != 's' {
		return nil, fmt.Errorf("must have the form s<delim>pattern<delim>replacement<delim>flags")
	}
	delim := spec[1]
	if delim == '\\' {
		return nil, fmt.Errorf("delimiter must not be a backslash")
	}

	fields, err := splitOnUnescapedDelim(spec[2:], delim, 3)
	if err != nil {
		return nil, err
	}
	pattern, replacement, flags := fields[0], fields[1], fields[2]

	global := false
	seenFlag := make(map[byte]bool, len(flags))
	for i := 0; i < len(flags); i++ {
		f := flags[i]
		if seenFlag[f] {
			return nil, fmt.Errorf("duplicate flag %q", string(f))
		}
		seenFlag[f] = true
		switch f {
		case 'g':
			global = true
		default:
			return nil, fmt.Errorf("unsupported flag %q", string(f))
		}
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern: %w", err)
	}

	return &sedTransform{re: re, replacement: replacement, global: global}, nil
}

// splitOnUnescapedDelim splits s into exactly n fields separated by
// unescaped occurrences of delim, unescaping \<delim> to a literal delim
// byte within each field as it goes. Returns an error if the number of
// unescaped delimiters found doesn't produce exactly n fields.
func splitOnUnescapedDelim(s string, delim byte, n int) ([]string, error) {
	var fields []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) && s[i+1] == delim {
			cur.WriteByte(delim)
			i++
			continue
		}
		if c == delim {
			fields = append(fields, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	fields = append(fields, cur.String())
	if len(fields) != n {
		return nil, fmt.Errorf("expected %d delimiter-separated fields, got %d", n, len(fields))
	}
	return fields, nil
}

// apply rewrites s according to the transform: every non-overlapping match
// when global, otherwise only the first match. Capture-group expansion in
// replacement uses Go regexp replacement syntax ($1, ${name}, etc.).
func (t *sedTransform) apply(s string) string {
	if t.global {
		return t.re.ReplaceAllString(s, t.replacement)
	}
	loc := t.re.FindStringIndex(s)
	if loc == nil {
		return s
	}
	// Replacing within the exact matched span applies the regex expansion
	// to precisely that one match, since the span is by construction the
	// leftmost match and therefore matches starting at its own position 0.
	return s[:loc[0]] + t.re.ReplaceAllString(s[loc[0]:loc[1]], t.replacement) + s[loc[1]:]
}

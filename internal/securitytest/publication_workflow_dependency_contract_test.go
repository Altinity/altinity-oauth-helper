package securitytest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// publicationWorkflowDependencyTarget ties a published command to the
// workflow whose push paths must rebuild its image when any first-party
// package in the command's dependency closure changes.
type publicationWorkflowDependencyTarget struct {
	command  string
	workflow string
}

var publicationWorkflowDependencyTargets = []publicationWorkflowDependencyTarget{
	{command: "./cmd/ch-jwt-verify", workflow: ".github/workflows/build-ch-jwt-verify.yml"},
	{command: "./cmd/ch-oauth-ldap", workflow: ".github/workflows/build-ch-oauth-ldap.yml"},
}

// goListDependencyPackage is the subset of `go list -json` data needed to
// identify first-party packages and to select a representative source file.
// Module.Main is deliberately the authority here: import-path prefixes can be
// fooled by a replacement or a future module-path change.
type goListDependencyPackage struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	Module     *struct {
		Main bool
	}
}

type firstPartyDependencyPackage struct {
	importPath string
	directory  string // repository-relative, slash-separated
	sourcePath string // an actual representative source file
}

func TestPublicationWorkflowDependencyContract(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("publication workflow dependency contract: resolve module root: %v", err)
	}

	for _, target := range publicationWorkflowDependencyTargets {
		t.Run(strings.TrimPrefix(target.command, "./"), func(t *testing.T) {
			packages, err := firstPartyDependencyClosure(t, root, target.command)
			if err != nil {
				t.Fatalf("publication workflow dependency contract: derive first-party dependency closure for command %s: %v", target.command, err)
			}
			patterns, err := publicationWorkflowPushPaths(root, target.workflow)
			if err != nil {
				t.Fatalf("publication workflow dependency contract: read push paths for command %s workflow %s: %v", target.command, target.workflow, err)
			}

			if uncovered := uncoveredPublicationWorkflowPackages(packages, patterns); len(uncovered) != 0 {
				var failures []string
				for _, pkg := range uncovered {
					failures = append(failures, fmt.Sprintf("uncovered import path %s (package directory %s; representative source %s)", pkg.importPath, pkg.directory, pkg.sourcePath))
				}
				t.Fatalf("publication workflow dependency contract: command %s workflow %s does not select every first-party dependency package:\n  %s\nconfigured on.push.paths patterns:\n  %s", target.command, target.workflow, strings.Join(failures, "\n  "), strings.Join(patterns, "\n  "))
			}
		})
	}
}

// firstPartyDependencyClosure runs the fixed, host-independent go-list
// command used by the dependency contracts, retaining exactly packages whose
// resolved module is the main module.
func firstPartyDependencyClosure(t *testing.T, root, command string) ([]firstPartyDependencyPackage, error) {
	t.Helper()
	goBin := resolveGoBin(t)
	cmd := exec.Command(goBin, "list", "-mod=readonly", "-deps", "-json", command) //nolint:gosec // fixed go binary and argv
	cmd.Dir = root
	cmd.Env = deterministicGoListEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s list -mod=readonly -deps -json %s: %w\nstderr:\n%s", filepath.Base(goBin), command, err, stderr.String())
	}

	decoder := json.NewDecoder(&stdout)
	byImportPath := make(map[string]firstPartyDependencyPackage)
	for {
		var listed goListDependencyPackage
		err := decoder.Decode(&listed)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode go list output for %s: %w", command, err)
		}
		if listed.Module == nil || !listed.Module.Main {
			continue
		}
		if listed.ImportPath == "" || listed.Dir == "" {
			return nil, fmt.Errorf("go list returned incomplete main-module package for %s: import path %q directory %q", command, listed.ImportPath, listed.Dir)
		}
		relDir, err := filepath.Rel(root, listed.Dir)
		if err != nil || relDir == ".." || strings.HasPrefix(relDir, ".."+string(filepath.Separator)) || filepath.IsAbs(relDir) {
			return nil, fmt.Errorf("go list package %s directory %s is outside module root %s", listed.ImportPath, listed.Dir, root)
		}
		relDir = filepath.ToSlash(relDir)
		if len(listed.GoFiles) == 0 {
			return nil, fmt.Errorf("go list main-module package %s (%s) has no buildable GoFiles to use as a representative source", listed.ImportPath, relDir)
		}
		goFiles := append([]string(nil), listed.GoFiles...)
		sort.Strings(goFiles)
		byImportPath[listed.ImportPath] = firstPartyDependencyPackage{
			importPath: listed.ImportPath,
			directory:  relDir,
			sourcePath: path.Join(relDir, goFiles[0]),
		}
	}

	packages := make([]firstPartyDependencyPackage, 0, len(byImportPath))
	for _, pkg := range byImportPath {
		packages = append(packages, pkg)
	}
	sort.Slice(packages, func(i, j int) bool { return packages[i].importPath < packages[j].importPath })
	if len(packages) == 0 {
		return nil, fmt.Errorf("go list found no main-module packages for %s", command)
	}
	return packages, nil
}

// publicationWorkflowPushPaths parses the literal `on` mapping through YAML
// nodes, avoiding YAML 1.1's tendency to coerce that key to a boolean.
func publicationWorkflowPushPaths(root, workflow string) ([]string, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(workflow)))
	if err != nil {
		return nil, err
	}
	var document yaml.Node
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected one YAML document with a top-level mapping")
	}
	push := yamlMapValue(yamlMapValue(document.Content[0], "on"), "push")
	paths := yamlMapValue(push, "paths")
	if paths == nil || paths.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("on.push.paths must be a sequence")
	}
	patterns := make([]string, 0, len(paths.Content))
	for _, pattern := range paths.Content {
		if pattern.Kind != yaml.ScalarNode || pattern.Value == "" {
			return nil, fmt.Errorf("on.push.paths must contain non-empty scalar patterns")
		}
		patterns = append(patterns, pattern.Value)
	}
	return patterns, nil
}

// uncoveredPublicationWorkflowPackages requires both a real source file and
// an otherwise-unlisted probe below the same directory. The latter prevents
// an incidental one-file pattern from claiming to cover a package generally.
func uncoveredPublicationWorkflowPackages(packages []firstPartyDependencyPackage, patterns []string) []firstPartyDependencyPackage {
	var uncovered []firstPartyDependencyPackage
	for _, pkg := range packages {
		probe := path.Join(pkg.directory, ".publication-workflow-dependency-contract-probe.go")
		if !githubPathSelected(pkg.sourcePath, patterns) || !githubPathSelected(probe, patterns) {
			uncovered = append(uncovered, pkg)
		}
	}
	return uncovered
}

// githubPathSelected applies GitHub Actions path patterns in declaration
// order. A matching negative pattern excludes a path; a later positive one
// can include it again.
func githubPathSelected(candidate string, patterns []string) bool {
	selected := false
	for _, pattern := range patterns {
		negative := strings.HasPrefix(pattern, "!")
		if negative {
			pattern = strings.TrimPrefix(pattern, "!")
		}
		if githubPathPatternMatches(pattern, candidate) {
			selected = !negative
		}
	}
	return selected
}

// githubPathPatternMatches supports the Actions path glob behavior needed by
// publication workflows: normal per-segment glob syntax plus ** matching zero
// or more complete path segments.
func githubPathPatternMatches(pattern, candidate string) bool {
	pattern = strings.Trim(pattern, "/")
	candidate = strings.Trim(candidate, "/")
	if pattern == "" || candidate == "" {
		return pattern == candidate
	}
	return githubPathSegmentsMatch(strings.Split(pattern, "/"), strings.Split(candidate, "/"))
}

func githubPathSegmentsMatch(pattern, candidate []string) bool {
	if len(pattern) == 0 {
		return len(candidate) == 0
	}
	if pattern[0] == "**" {
		for consumed := 0; consumed <= len(candidate); consumed++ {
			if githubPathSegmentsMatch(pattern[1:], candidate[consumed:]) {
				return true
			}
		}
		return false
	}
	if len(candidate) == 0 {
		return false
	}
	matched, err := path.Match(pattern[0], candidate[0])
	return err == nil && matched && githubPathSegmentsMatch(pattern[1:], candidate[1:])
}

func TestPublicationWorkflowDependencyContract_GitHubPathMatcher(t *testing.T) {
	tests := []struct {
		name      string
		candidate string
		patterns  []string
		want      bool
	}{
		{name: "direct", candidate: "cmd/ch-jwt-verify/main.go", patterns: []string{"cmd/ch-jwt-verify/**"}, want: true},
		{name: "nested recursive", candidate: "internal/identity/keys/cache.go", patterns: []string{"internal/**"}, want: true},
		{name: "unmatched", candidate: "internal/verification/verify.go", patterns: []string{"internal/identity/**"}, want: false},
		{name: "negated", candidate: "internal/identity/identity.go", patterns: []string{"internal/**", "!internal/identity/**"}, want: false},
		{name: "re-included after negation", candidate: "internal/identity/identity.go", patterns: []string{"internal/**", "!internal/identity/**", "internal/identity/**"}, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := githubPathSelected(test.candidate, test.patterns); got != test.want {
				t.Fatalf("githubPathSelected(%q, %q) = %t, want %t", test.candidate, test.patterns, got, test.want)
			}
		})
	}
}

func TestPublicationWorkflowDependencyContract_MissingPackageGlobReportsPackage(t *testing.T) {
	packages := []firstPartyDependencyPackage{
		{importPath: "example.test/project/internal/identity", directory: "internal/identity", sourcePath: "internal/identity/identity.go"},
		{importPath: "example.test/project/internal/verification", directory: "internal/verification", sourcePath: "internal/verification/verify.go"},
	}
	// This is the coverage set after the internal/verification glob is removed.
	uncovered := uncoveredPublicationWorkflowPackages(packages, []string{"internal/identity/**"})
	if len(uncovered) != 1 || uncovered[0].importPath != "example.test/project/internal/verification" {
		t.Fatalf("removing required package glob must report internal/verification; uncovered = %#v", uncovered)
	}
}

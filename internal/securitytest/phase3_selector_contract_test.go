package securitytest

// This file implements issue #33 phase 3's Docker-free integration/
// publication selector contracts (plan "Integration selection contract").
// It is mechanical, no-Docker-daemon-required proof that the temporary
// phase3profile build tag (see dependency_contract_test.go's
// phase3ReplacementTag) is wired into exactly the one place it belongs — the
// integration helper's own Dockerfile's ch-oauth-ldap build line — and
// appears nowhere else that could either accidentally fall back the Docker
// gates to legacy or accidentally cut production over early.
//
// Four assertions, each guarding a distinct invariant-map row:
//
//   - TestPhase3SelectorContract_IntegrationDockerfileTagsOnlyTheHelperBuild:
//     "integration helper always uses profile" — integration/clickhouse/
//     Dockerfile's ch-oauth-ldap `go build` line contains -tags=phase3profile,
//     and that line is the ONLY `go build` invocation in the file carrying
//     the tag.
//   - TestPhase3SelectorContract_ProductionDockerfileRemainsUntagged:
//     "publication image remains legacy" — Dockerfile.ch-oauth-ldap never
//     mentions phase3profile.
//   - TestPhase3SelectorContract_BuildScriptDoesNotRequestTheTag: the same
//     invariant over scripts/build-ch-oauth-ldap-image.sh, the manual
//     multi-arch publication path.
//   - TestPhase3SelectorContract_PublicationWorkflowDoesNotIntroduceTheTag:
//     the same invariant over .github/workflows/build-ch-oauth-ldap.yml, the
//     automated push-to-main publication path.
//
// None of these run Docker, `docker build`, or any external process — they
// are plain string/line assertions over the checked-in files, in the same
// spirit as docs_contract_test.go's and pr_gate_contract_test.go's own
// workflow/Dockerfile text checks elsewhere in this package. The tagged
// dependency-closure proof (profile present, legacy/general-LDAP absent
// under -tags=phase3profile) and the tagged real-compile proof both live in
// dependency_contract_test.go (TestDependencyContract_
// Phase3ReplacementClosureHasNoGeneralLDAP and TestDependencyContract_
// Phase3ReplacementCommandBuilds respectively) — this file only proves
// where the tag textually does, and does not, appear across the
// integration/publication surface.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// phase3IntegrationDockerfileRelPath is the integration helper image's
// Dockerfile, relative to the module root — the one and only build artifact
// the phase3profile tag may appear in during Phase 3 (plan "Integration
// image").
const phase3IntegrationDockerfileRelPath = "integration/clickhouse/Dockerfile"

// phase3ProductionDockerfileRelPath is the published ch-oauth-ldap image's
// Dockerfile. It must stay untagged/legacy throughout Phase 3 (plan "Files
// and subsystem boundaries › Expected unchanged").
const phase3ProductionDockerfileRelPath = "Dockerfile.ch-oauth-ldap"

// phase3BuildScriptRelPath is the manual multi-arch publication script for
// the ch-oauth-ldap image.
const phase3BuildScriptRelPath = "scripts/build-ch-oauth-ldap-image.sh"

// phase3PublicationWorkflowRelPath is the automated push-to-main publication
// workflow for the ch-oauth-ldap image.
const phase3PublicationWorkflowRelPath = ".github/workflows/build-ch-oauth-ldap.yml"

// phase3TaggedBuildMarker is the exact selector substring that must appear
// on the integration helper's ch-oauth-ldap build line, and must appear
// nowhere in any of the three untagged/publication-path files checked below.
const phase3TaggedBuildMarker = "-tags=" + phase3ReplacementTag

// readRepoFile reads relPath relative to the module root, failing the test
// on any error — shared by every check in this file.
func readRepoFile(t *testing.T, relPath string) string {
	t.Helper()
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("phase3_selector_contract: resolve module root: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relPath)))
	if err != nil {
		t.Fatalf("phase3_selector_contract: read %s: %v", relPath, err)
	}
	return string(raw)
}

// assertFileNeverMentionsPhase3Tag fails the test if relPath's content
// mentions the phase3profile selector anywhere — used for every file that
// must stay untagged/legacy throughout Phase 3.
func assertFileNeverMentionsPhase3Tag(t *testing.T, relPath string) {
	t.Helper()
	content := readRepoFile(t, relPath)
	if strings.Contains(content, phase3ReplacementTag) {
		t.Fatalf("phase3_selector_contract: %s must remain untagged/legacy during Phase 3, but it mentions %q", relPath, phase3ReplacementTag)
	}
}

// TestPhase3SelectorContract_IntegrationDockerfileTagsOnlyTheHelperBuild
// requires integration/clickhouse/Dockerfile's ch-oauth-ldap `go build` line
// to carry -tags=phase3profile, and requires that line to be the ONLY
// `go build` invocation in the file carrying that tag (plan "Integration
// selection contract": "the integration Dockerfile's ch-oauth-ldap build to
// contain -tags=phase3profile; exactly that binary's build to receive the
// tag"). synthetic-idp, ldap-session-probe, and ldap-wire-recorder must stay
// untagged.
func TestPhase3SelectorContract_IntegrationDockerfileTagsOnlyTheHelperBuild(t *testing.T) {
	content := readRepoFile(t, phase3IntegrationDockerfileRelPath)

	var helperBuildLines, otherTaggedBuildLines []string
	for _, line := range strings.Split(content, "\n") {
		if !strings.Contains(line, "go build") {
			continue
		}
		tagged := strings.Contains(line, phase3TaggedBuildMarker)
		isHelperBuild := strings.Contains(line, "./cmd/ch-oauth-ldap")
		switch {
		case isHelperBuild && tagged:
			helperBuildLines = append(helperBuildLines, line)
		case !isHelperBuild && tagged:
			otherTaggedBuildLines = append(otherTaggedBuildLines, line)
		}
	}

	if len(helperBuildLines) != 1 {
		t.Fatalf("phase3_selector_contract: expected exactly one ch-oauth-ldap `go build` line in %s carrying %s, found %d: %v",
			phase3IntegrationDockerfileRelPath, phase3TaggedBuildMarker, len(helperBuildLines), helperBuildLines)
	}
	if len(otherTaggedBuildLines) != 0 {
		t.Fatalf("phase3_selector_contract: %s must be the ONLY build in %s carrying %s, but it also appears on non-ch-oauth-ldap build line(s): %v",
			phase3TaggedBuildMarker, phase3IntegrationDockerfileRelPath, phase3TaggedBuildMarker, otherTaggedBuildLines)
	}
}

// TestPhase3SelectorContract_ProductionDockerfileRemainsUntagged requires
// Dockerfile.ch-oauth-ldap — the published production image's own
// Dockerfile — to never mention phase3profile (plan "Files and subsystem
// boundaries › Expected unchanged": "production Dockerfile.ch-oauth-ldap").
func TestPhase3SelectorContract_ProductionDockerfileRemainsUntagged(t *testing.T) {
	assertFileNeverMentionsPhase3Tag(t, phase3ProductionDockerfileRelPath)
}

// TestPhase3SelectorContract_BuildScriptDoesNotRequestTheTag requires
// scripts/build-ch-oauth-ldap-image.sh — the manual multi-arch publication
// path — to never request the phase3profile tag (plan "Integration
// selection contract": "scripts/build-ch-oauth-ldap-image.sh not to request
// the tag").
func TestPhase3SelectorContract_BuildScriptDoesNotRequestTheTag(t *testing.T) {
	assertFileNeverMentionsPhase3Tag(t, phase3BuildScriptRelPath)
}

// TestPhase3SelectorContract_PublicationWorkflowDoesNotIntroduceTheTag
// requires .github/workflows/build-ch-oauth-ldap.yml — the automated
// push-to-main publication workflow — to never introduce the phase3profile
// tag (plan "Integration selection contract": ".github/workflows/
// build-ch-oauth-ldap.yml not to introduce the tag").
func TestPhase3SelectorContract_PublicationWorkflowDoesNotIntroduceTheTag(t *testing.T) {
	assertFileNeverMentionsPhase3Tag(t, phase3PublicationWorkflowRelPath)
}

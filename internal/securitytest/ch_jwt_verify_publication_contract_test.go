package securitytest

import (
	"strings"
	"testing"
)

// These are static publication contracts rather than Docker integration tests:
// they make the release-safety conditions reviewable and run without registry
// credentials. The checks deliberately assert ordering around the mutating
// commands so a future refactor cannot retain an inspect helper but move it
// back before a long build.
const (
	jwtBuildScriptRelPath = "scripts/build-image.sh"
	jwtWorkflowRelPath    = ".github/workflows/build-ch-jwt-verify.yml"
	jwtDockerfileRelPath  = "Dockerfile"
)

func TestJWTVerifyPublicationContract_ManualScriptUsesCommittedPrivateSource(t *testing.T) {
	script := readRepoFile(t, jwtBuildScriptRelPath)

	for _, required := range []string{
		"git show HEAD:scripts/build-image.sh",
		"_CH_JWT_VERIFY_IMAGE_SELF_VERIFIED",
		"git status --porcelain --untracked-files=all",
		"do not add --ignored=matching",
		"git archive --format=tar HEAD | tar -x -C \"$SRC_DIR\"",
		"RUN_TMP_DIR=\"$TMPDIR/ch-jwt-verify-image.$suffix\"",
		"mkdir -m 700 \"$RUN_TMP_DIR\"",
		"cd \"$SRC_DIR\"",
		"-o \"$ctx/ch-jwt-verify\" ./cmd/ch-jwt-verify",
		"cp \"$SRC_DIR/Dockerfile\" \"$ctx/Dockerfile\"",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("JWT publication script must retain committed/private-source guarantee %q", required)
		}
	}
	if strings.Contains(script, "git status --porcelain --untracked-files=all --ignored=matching") {
		t.Fatal("JWT publication script must mirror the hardened LDAP path: ignored files are excluded by git archive HEAD, so --ignored=matching only adds false-positive dirty-tree failures")
	}
	if strings.Contains(script, "-o ch-jwt-verify ./cmd/ch-jwt-verify") {
		t.Fatal("JWT publication script must not compile its binary into the checkout")
	}
}

func TestJWTVerifyPublicationContract_ManualScriptReportsOnlyPublishedTags(t *testing.T) {
	script := readRepoFile(t, jwtBuildScriptRelPath)
	assertPublicationOrder(t, script,
		"echo \"✓ pushed:\"",
		"echo \"    ${FULL}:${TAG}-${arch}\"",
		"if [[ $# -gt 1 ]]; then",
		"echo \"    ${FULL}:${TAG}     (multi-arch manifest)\"")
}

func TestJWTVerifyPublicationContract_ManualScriptRefusesExistingOrAmbiguousTags(t *testing.T) {
	script := readRepoFile(t, jwtBuildScriptRelPath)

	for _, required := range []string{
		"_TAG_NOT_FOUND_PATTERN='no such manifest|manifest unknown|name unknown|not found|404'",
		"if out=$(docker manifest inspect \"$ref\" 2>&1); then",
		"cannot prove ${ref} is absent",
		"${FULL}:${TAG}",
		"${FULL}:${TAG}-${arch}",
		"there is no force override",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("JWT publication script must reject existing/ambiguous registry state; missing %q", required)
		}
	}

	// The re-inspection must be adjacent to the registry mutations, not merely
	// present as a pre-build check. These positions are within their respective
	// functions/manifest block, which is the meaningful TOCTOU boundary.
	assertPublicationOrder(t, script,
		"if ! check_tag_absent \"${FULL}:${TAG}-${arch}\"; then",
		"docker push \"${FULL}:${TAG}-${arch}\"")
	assertPublicationOrder(t, script,
		"docker manifest create \"${FULL}:${TAG}\" \"${manifest_args[@]}\"",
		"if ! check_tag_absent \"${FULL}:${TAG}\"; then",
		"docker manifest push \"${FULL}:${TAG}\"")
}

func TestJWTVerifyPublicationContract_WorkflowBuildsAndPushesSafely(t *testing.T) {
	workflow := readRepoFile(t, jwtWorkflowRelPath)

	for _, required := range []string{
		"default: \"sidecar\"",
		"IMAGE: altinity/ch-jwt-verify",
		"scripts/build-image.sh",
		"mktemp -d \"$RUNNER_TEMP/ch-jwt-verify-${ARCH}.XXXXXX\"",
		"git archive --format=tar HEAD | tar -x -C \"$context/src\"",
		"working-directory: ${{ steps.context.outputs.path }}/src",
		"${FULL}:${TAG}-amd64",
		"${FULL}:${TAG}-arm64",
		"NOT_FOUND_PATTERN='no such manifest|manifest unknown|name unknown|not found|404'",
		"cannot prove ${CANDIDATE} is absent",
		"docker buildx build --platform \"linux/${ARCH}\" --load",
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("JWT publication workflow must retain safety contract %q", required)
		}
	}
	assertPublicationOrder(t, workflow,
		"- name: Build per-arch image from owned context",
		"- name: Recheck and push per-arch image",
		"docker push \"$CANDIDATE\"")
	assertPublicationOrder(t, workflow,
		"- name: Recheck and publish multi-arch manifest",
		"docker buildx imagetools create -t \"${FULL}:${TAG}\"")
}

func TestJWTVerifyPublicationContract_BaseIsPinnedToMinorRelease(t *testing.T) {
	dockerfile := readRepoFile(t, jwtDockerfileRelPath)
	if !strings.Contains(dockerfile, "FROM alpine:3.24") {
		t.Fatalf("JWT image must pin Alpine to a minor tag or digest; Dockerfile has no alpine:3.24 FROM")
	}
	if strings.Contains(dockerfile, "alpine:latest") {
		t.Fatal("JWT image must not use mutable alpine:latest")
	}
}

func assertPublicationOrder(t *testing.T, content string, ordered ...string) {
	t.Helper()
	offset := 0
	for _, fragment := range ordered {
		pos := strings.Index(content[offset:], fragment)
		if pos < 0 {
			t.Fatalf("publication contract: missing ordered fragment %q", fragment)
		}
		offset += pos + len(fragment)
	}
}

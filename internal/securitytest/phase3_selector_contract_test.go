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
// Six assertions, each guarding a distinct invariant-map row:
//
//   - TestPhase3SelectorContract_IntegrationDockerfileTagsOnlyTheHelperBuild:
//     "integration helper always uses profile" — integration/clickhouse/
//     Dockerfile contains EXACTLY ONE `./cmd/ch-oauth-ldap` `go build` line
//     overall (tagged or not — see classifyDockerfileHelperBuildLines'
//     doc comment for why the total count is checked separately from the
//     tagged count), that one line contains -tags=phase3profile, that line
//     is the ONLY `go build` invocation in the file carrying the tag, AND
//     (the fix for review pass 1's P1 finding, tightened further by review
//     pass 3's P1 finding) it is the ONLY command in the whole Dockerfile
//     that writes to the build stage's /out/ch-oauth-ldap artifact path, AND
//     that sole writer is exactly phase3ExpectedHelperBuildCommand — not
//     merely a command containing "go build" and the tag substring — see
//     dockerfileArtifactWriters' and commandWritesTo's doc comments for why
//     that is a distinct check from the `go build`-line classifier above it,
//     not a redundant one, and for how commandWritesTo now also recognizes
//     a `GOBIN=<dir> go install <pkg>` overwrite, which has no `-o` flag and
//     so is invisible to every other write-detection shape.
//     TestPhase3SelectorContract_ClassifierCatchesSecondUntaggedHelperBuild,
//     TestPhase3SelectorContract_ArtifactWriterDetectionCatchesCompoundRunOverwrite,
//     TestPhase3SelectorContract_ArtifactWriterDetectionCatchesNonGoBuildOverwrite,
//     and
//     TestPhase3SelectorContract_ArtifactWriterDetectionCatchesGoInstallOverwrite
//     are this check's sabotage cases, against synthetic content.
//   - TestPhase3SelectorContract_IntegrationDockerfileRuntimeCopyIsSole:
//     the runtime-stage half of the same invariant — exactly one COPY
//     instruction writes the final image's /bin/ch-oauth-ldap, and (review
//     pass 3's P1 finding, second point) that COPY is exactly
//     phase3ExpectedRuntimeCopyInstruction — sourcing /out/ch-oauth-ldap
//     from the tagged build stage by name, not merely a COPY whose line
//     happens to contain that path from some other `--from=` stage.
//     TestPhase3SelectorContract_RuntimeCopyDetectionCatchesDuplicate and
//     TestPhase3SelectorContract_RuntimeCopyDetectionRejectsWrongFromStage
//     are this check's sabotage cases.
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
// are plain string/instruction assertions over the checked-in files, in the
// same spirit as docs_contract_test.go's and pr_gate_contract_test.go's own
// workflow/Dockerfile text checks elsewhere in this package. The tagged
// dependency-closure proof (profile present, legacy/general-LDAP absent
// under -tags=phase3profile) and the tagged real-compile/real-test proofs
// both live in dependency_contract_test.go (TestDependencyContract_
// Phase3ReplacementClosureHasNoGeneralLDAP,
// TestDependencyContract_Phase3ReplacementCommandBuilds, and
// TestDependencyContract_Phase3ReplacementCommandTests respectively) — this
// file only proves where the tag textually does, and does not, appear
// across the integration/publication surface, and that the artifact it
// selects is the one that actually reaches the shipped image.

import (
	"os"
	"path"
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

// phase3HelperArtifactPath is the build-stage output path
// integration/clickhouse/Dockerfile's tagged `go build` writes
// ch-oauth-ldap to. It must have exactly one writer in the whole Dockerfile.
const phase3HelperArtifactPath = "/out/ch-oauth-ldap"

// phase3HelperRuntimePath is the final runtime-stage path the build-stage
// artifact above is COPYed to in the shipped image.
const phase3HelperRuntimePath = "/bin/ch-oauth-ldap"

// phase3ExpectedHelperBuildCommand is the exact shell command (RUN prefix
// stripped, as dockerfileRunShellCommands returns it) that must be the sole
// writer of phase3HelperArtifactPath in phase3IntegrationDockerfileRelPath.
// Review pass 3's P1 finding: asserting only `strings.Contains(sole, "go
// build")` and `strings.Contains(sole, phase3TaggedBuildMarker)` approximates
// shell-write semantics rather than pinning the one command this contract
// actually promises — asserting exact equality here is what makes the check
// a real tuple assertion instead of two independent substring checks that
// could each pass against an unrelated command.
const phase3ExpectedHelperBuildCommand = `CGO_ENABLED=0 go build -tags=phase3profile -ldflags="-s -w -X main.version=integration-test" -o /out/ch-oauth-ldap ./cmd/ch-oauth-ldap`

// phase3ExpectedRuntimeCopyInstruction is the exact COPY instruction that
// must be the sole write into phase3HelperRuntimePath in
// phase3IntegrationDockerfileRelPath. Review pass 3's P1 finding (second
// point): the prior check only asserted the sole COPY's line contained the
// substring phase3HelperArtifactPath, never that it sourced that path from
// the correct build stage — so `COPY --from=legacy /out/ch-oauth-ldap
// /bin/ch-oauth-ldap` would have satisfied it just as well as the real,
// tagged-build stage's COPY. Asserting exact equality (including
// `--from=build`) closes that gap.
const phase3ExpectedRuntimeCopyInstruction = "COPY --from=build /out/ch-oauth-ldap /bin/ch-oauth-ldap"

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

// dockerfileInstructions parses raw Dockerfile content into its logical
// instructions: blank and comment-only lines are dropped, backslash
// line-continuations are joined into the one instruction they belong to,
// and each instruction is returned as a single string beginning with its
// keyword (RUN, COPY, FROM, ...). Every check in this file builds on this
// shared parsing step so a compound instruction — this Dockerfile's actual
// style is `&&`-chaining several shell commands on one physical RUN line —
// is analyzed as the ONE instruction Docker itself executes it as, rather
// than as an opaque substring match against a raw "\n"-split physical line.
func dockerfileInstructions(content string) []string {
	var instructions []string
	var current strings.Builder
	continuing := false
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if !continuing {
			if trimmed := strings.TrimSpace(line); trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			current.Reset()
		}
		if strings.HasSuffix(line, "\\") {
			current.WriteString(strings.TrimSuffix(line, "\\"))
			current.WriteString(" ")
			continuing = true
			continue
		}
		current.WriteString(strings.TrimSpace(line))
		instructions = append(instructions, current.String())
		continuing = false
	}
	return instructions
}

// dockerfileRunShellCommands returns every RUN instruction's shell body,
// split into its constituent sub-commands on &&, ||, ;, and | — the shell
// operators that let one Dockerfile RUN instruction execute more than one
// command. This is what lets the checks below see through a line like
// `go build -tags=phase3profile -o /out/x ./cmd/x && go build -o /out/x
// ./cmd/x` as the two separate commands Docker's shell actually runs in
// sequence, rather than as one opaque line that happens to contain the
// substrings being matched for (the exact bypass review pass 1's P1
// finding described).
func dockerfileRunShellCommands(instructions []string) []string {
	replacer := strings.NewReplacer("&&", "\x00", "||", "\x00", ";", "\x00", "|", "\x00")
	var commands []string
	for _, instr := range instructions {
		if !strings.HasPrefix(instr, "RUN ") {
			continue
		}
		body := strings.TrimPrefix(instr, "RUN ")
		for _, part := range strings.Split(replacer.Replace(body), "\x00") {
			if part = strings.TrimSpace(part); part != "" {
				commands = append(commands, part)
			}
		}
	}
	return commands
}

// TestPhase3SelectorContract_IntegrationDockerfileTagsOnlyTheHelperBuild
// requires integration/clickhouse/Dockerfile to contain EXACTLY ONE
// `./cmd/ch-oauth-ldap` `go build` command overall, and requires that one
// command to carry -tags=phase3profile, and requires that command to be the
// ONLY `go build` invocation in the file carrying that tag (plan
// "Integration selection contract": "the integration Dockerfile's
// ch-oauth-ldap build to contain -tags=phase3profile; exactly that binary's
// build to receive the tag"). synthetic-idp, ldap-session-probe, and
// ldap-wire-recorder must stay untagged.
//
// The total-count check on allHelperBuildLines is deliberate, not
// redundant with the tagged-count check below: a bucketing scheme that only
// classifies "helper AND tagged" versus "not-helper AND tagged" silently
// drops a THIRD, unbucketed case — an untagged `./cmd/ch-oauth-ldap` build
// command appearing anywhere in the file. Docker executes RUN instructions
// (and, within one RUN, `&&`-chained commands) in order, and each writes to
// the same /out/ch-oauth-ldap path, so a second, untagged helper build
// placed anywhere after the tagged one — on its own line OR chained into
// the same RUN — would silently overwrite the profile binary with the
// legacy one before the final COPY, while a bucketing scheme with no
// default case would stay green throughout, since that command is neither
// "helper && tagged" nor "!helper && tagged". Asserting
// len(allHelperBuildLines) == 1 up front closes that hole: it forces every
// `./cmd/ch-oauth-ldap` build command, tagged or not, to be counted, so a
// second build of any kind fails this test immediately.
//
// That said, the `go build`-line classifier is structurally blind to any
// overwrite mechanism that is not itself a `go build` invocation — a
// chained `go install`, `cp`, or `mv` targeting the same output path would
// satisfy every bucket above with zero matches. The artifact-writer check
// below closes that remaining gap by inspecting what actually writes to
// /out/ch-oauth-ldap, independent of how.
func TestPhase3SelectorContract_IntegrationDockerfileTagsOnlyTheHelperBuild(t *testing.T) {
	content := readRepoFile(t, phase3IntegrationDockerfileRelPath)
	allHelperBuildLines, taggedHelperBuildLines, otherTaggedBuildLines := classifyDockerfileHelperBuildLines(content)

	if len(allHelperBuildLines) != 1 {
		t.Fatalf("phase3_selector_contract: expected exactly one `./cmd/ch-oauth-ldap` `go build` command in %s (tagged or not — a second, untagged build would silently overwrite the tagged binary), found %d: %v",
			phase3IntegrationDockerfileRelPath, len(allHelperBuildLines), allHelperBuildLines)
	}
	if len(taggedHelperBuildLines) != 1 {
		t.Fatalf("phase3_selector_contract: expected the one ch-oauth-ldap `go build` command in %s to carry %s, found %d matching command(s): %v",
			phase3IntegrationDockerfileRelPath, phase3TaggedBuildMarker, len(taggedHelperBuildLines), taggedHelperBuildLines)
	}
	if len(otherTaggedBuildLines) != 0 {
		t.Fatalf("phase3_selector_contract: %s must be the ONLY build in %s carrying %s, but it also appears on non-ch-oauth-ldap build command(s): %v",
			phase3TaggedBuildMarker, phase3IntegrationDockerfileRelPath, phase3TaggedBuildMarker, otherTaggedBuildLines)
	}

	// Bound the actual artifact writer, not just `go build` occurrences
	// (review pass 1 P1): exactly one command in the whole Dockerfile may
	// write to /out/ch-oauth-ldap, by ANY mechanism — go build, go install,
	// cp, mv, or a shell redirect — and that command must be the tagged go
	// build proved above.
	writers := dockerfileArtifactWriters(content, phase3HelperArtifactPath)
	if len(writers) != 1 {
		t.Fatalf("phase3_selector_contract: expected exactly one command writing to %s in %s (a second writer — another `go build`, a `go install`, `cp`, `mv`, or a shell redirect — would silently overwrite the tagged binary before the runtime-stage COPY), found %d: %v",
			phase3HelperArtifactPath, phase3IntegrationDockerfileRelPath, len(writers), writers)
	}
	if sole := writers[0]; sole != phase3ExpectedHelperBuildCommand {
		t.Fatalf("phase3_selector_contract: the sole writer of %s in %s must be exactly the tagged helper build command, got: %q, want: %q",
			phase3HelperArtifactPath, phase3IntegrationDockerfileRelPath, sole, phase3ExpectedHelperBuildCommand)
	}
}

// classifyDockerfileHelperBuildLines scans every `go build` command in a
// Dockerfile's content — after dockerfileRunShellCommands has split each RUN
// instruction on its shell operators, so a `&&`-chained compound RUN line is
// seen as its constituent commands rather than one opaque line — and buckets
// each one three ways: allHelperBuildLines is EVERY `./cmd/ch-oauth-ldap`
// build command regardless of tag (the total-count proof),
// taggedHelperBuildLines is the subset of those that also carry
// -tags=phase3profile, and otherTaggedBuildLines is every tagged build
// command for a DIFFERENT binary. Extracted from
// TestPhase3SelectorContract_IntegrationDockerfileTagsOnlyTheHelperBuild so
// TestPhase3SelectorContract_ClassifierCatchesSecondUntaggedHelperBuild can
// exercise it directly against synthetic content, without needing a second
// checked-in Dockerfile fixture.
func classifyDockerfileHelperBuildLines(content string) (allHelperBuildLines, taggedHelperBuildLines, otherTaggedBuildLines []string) {
	for _, command := range dockerfileRunShellCommands(dockerfileInstructions(content)) {
		if !strings.Contains(command, "go build") {
			continue
		}
		tagged := strings.Contains(command, phase3TaggedBuildMarker)
		isHelperBuild := strings.Contains(command, "./cmd/ch-oauth-ldap")
		if isHelperBuild {
			allHelperBuildLines = append(allHelperBuildLines, command)
		}
		switch {
		case isHelperBuild && tagged:
			taggedHelperBuildLines = append(taggedHelperBuildLines, command)
		case !isHelperBuild && tagged:
			otherTaggedBuildLines = append(otherTaggedBuildLines, command)
		}
	}
	return allHelperBuildLines, taggedHelperBuildLines, otherTaggedBuildLines
}

// commandWritesTo reports whether a single shell command's output target is
// outputPath: an `-o outputPath` flag (as used by both `go build` and `go
// install -o`), a `>`/`>>` shell redirect to outputPath, outputPath as the
// command's own last positional argument (the destination shape of
// `cp src dst`/`mv src dst`), or — review pass 3's P1 finding — a `go
// install` invocation GOBIN-redirected to outputPath's directory for a
// package whose import path's last element is outputPath's base name (see
// goInstallWritesTo). It deliberately does not care what the command
// otherwise is — that is exactly the point: it is the mechanism
// dockerfileArtifactWriters uses to catch an overwrite performed by
// something other than a recognizable `go build` invocation.
func commandWritesTo(command, outputPath string) bool {
	if strings.Contains(command, "-o "+outputPath) {
		return true
	}
	if strings.Contains(command, ">"+outputPath) || strings.Contains(command, "> "+outputPath) {
		return true
	}
	fields := strings.Fields(command)
	if len(fields) > 0 && fields[len(fields)-1] == outputPath {
		return true
	}
	return goInstallWritesTo(command, outputPath)
}

// goInstallWritesTo reports whether command is a `go install` invocation
// that writes outputPath by GOBIN redirection. `go install` has no `-o`
// flag: the standard way to control where it writes is the GOBIN
// environment variable, and the installed binary is named after the last
// path element of the package argument (e.g. `GOBIN=/out go install
// ./cmd/ch-oauth-ldap` installs a binary literally at /out/ch-oauth-ldap) —
// see https://pkg.go.dev/cmd/go#hdr-Compile_and_install_packages_and_dependencies.
// This is review pass 3's P1 finding, reproduced exactly:
// commandWritesTo's three original shapes all miss this because the written
// path never appears verbatim in the command text — only its directory (as
// a GOBIN value) and its base name (as the package argument's last path
// element) do, separately. Matching is done on whitespace-separated tokens,
// not raw substring containment, so a GOBIN value that merely has
// outputPath's directory as a prefix (e.g. GOBIN=/out2) does not
// false-positive.
func goInstallWritesTo(command, outputPath string) bool {
	if !strings.Contains(command, "go install") {
		return false
	}
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return false
	}
	dir, base := path.Dir(outputPath), path.Base(outputPath)
	gobinToken := "GOBIN=" + dir
	sawGOBIN := false
	for _, f := range fields {
		if f == gobinToken {
			sawGOBIN = true
			break
		}
	}
	if !sawGOBIN {
		return false
	}
	pkg := fields[len(fields)-1]
	return path.Base(pkg) == base
}

// dockerfileArtifactWriters returns every RUN sub-command in content that
// writes to outputPath, by any mechanism commandWritesTo recognizes. Unlike
// classifyDockerfileHelperBuildLines, which only ever recognizes `go build`
// commands, this function is blind to what kind of command it is — it
// exists specifically to close the gap review pass 1's P1 finding
// identified: a single Dockerfile RUN could perform the required tagged
// `go build` and then silently overwrite the binary via a NON-`go build`
// command (`go install`, `cp`, `mv`, a shell redirect) chained into the
// same RUN, which every `go build`-line classifier — however carefully it
// splits compound lines — can never see, because it never stops filtering
// on the substring "go build" in the first place.
func dockerfileArtifactWriters(content, outputPath string) []string {
	var writers []string
	for _, command := range dockerfileRunShellCommands(dockerfileInstructions(content)) {
		if commandWritesTo(command, outputPath) {
			writers = append(writers, command)
		}
	}
	return writers
}

// dockerfileCopyInstructionsInto returns every COPY instruction in content
// whose destination (its last field) is exactly destPath.
func dockerfileCopyInstructionsInto(content, destPath string) []string {
	var matches []string
	for _, instr := range dockerfileInstructions(content) {
		if !strings.HasPrefix(instr, "COPY ") {
			continue
		}
		fields := strings.Fields(instr)
		if len(fields) > 0 && fields[len(fields)-1] == destPath {
			matches = append(matches, instr)
		}
	}
	return matches
}

// TestPhase3SelectorContract_ClassifierCatchesSecondUntaggedHelperBuild is
// the sabotage case for the total-count check added above: it reproduces,
// against synthetic Dockerfile content, the exact regression the prior
// two-bucket classifier missed — a second, untagged `./cmd/ch-oauth-ldap`
// build line appended after the tagged one, on its own separate RUN
// instruction (e.g. Docker overwriting /out/ch-oauth-ldap with the legacy
// binary before the final COPY). Under the old classifier (only "helper &&
// tagged" vs "!helper && tagged" buckets, no default case) that second line
// was silently dropped and both buckets stayed exactly as they were with a
// single build — this test fails if that regression is ever reintroduced.
func TestPhase3SelectorContract_ClassifierCatchesSecondUntaggedHelperBuild(t *testing.T) {
	const sabotaged = `RUN CGO_ENABLED=0 go build -tags=phase3profile -o /out/ch-oauth-ldap ./cmd/ch-oauth-ldap
RUN CGO_ENABLED=0 go build -o /out/ch-oauth-ldap ./cmd/ch-oauth-ldap
`
	all, tagged, other := classifyDockerfileHelperBuildLines(sabotaged)
	if len(all) != 2 {
		t.Fatalf("classifyDockerfileHelperBuildLines: expected the sabotaged content's two `./cmd/ch-oauth-ldap` build lines to both be counted, got %d: %v", len(all), all)
	}
	if len(tagged) != 1 {
		t.Fatalf("classifyDockerfileHelperBuildLines: expected exactly one tagged helper build line, got %d: %v", len(tagged), tagged)
	}
	if len(other) != 0 {
		t.Fatalf("classifyDockerfileHelperBuildLines: expected no other-binary tagged build lines, got %d: %v", len(other), other)
	}

	// The invariant this test exists to protect: a caller that only checks
	// len(all) == 1 (as the real contract test above does) must reject this
	// synthetic content, even though len(tagged) == 1 and len(other) == 0
	// both look clean on their own.
	if len(all) == 1 {
		t.Fatalf("classifyDockerfileHelperBuildLines: sabotage case must produce more than one helper build line, got exactly one — the sabotage failed to reproduce the regression")
	}
}

// TestPhase3SelectorContract_ArtifactWriterDetectionCatchesCompoundRunOverwrite
// reproduces, against synthetic content, the exact bypass review pass 1's
// P1 finding described: a single Dockerfile RUN instruction that performs
// the required tagged `go build` and then, `&&`-chained on the SAME
// physical line, silently overwrites /out/ch-oauth-ldap with a second,
// untagged `go build`. Split on "\n" this is one line containing both "go
// build" and the tag — exactly the shape the finding showed sails through a
// line-based classifier. dockerfileArtifactWriters, built on
// dockerfileRunShellCommands' `&&`-aware split, must see it as two separate
// writers of the same path instead of one clean tagged build.
func TestPhase3SelectorContract_ArtifactWriterDetectionCatchesCompoundRunOverwrite(t *testing.T) {
	const sabotaged = "RUN CGO_ENABLED=0 go build -tags=phase3profile -o /out/ch-oauth-ldap ./cmd/ch-oauth-ldap && CGO_ENABLED=0 go build -o /out/ch-oauth-ldap ./cmd/ch-oauth-ldap\n"
	writers := dockerfileArtifactWriters(sabotaged, phase3HelperArtifactPath)
	if len(writers) != 2 {
		t.Fatalf("dockerfileArtifactWriters: expected the compound RUN's two writers of %s to both be detected, got %d: %v", phase3HelperArtifactPath, len(writers), writers)
	}
}

// TestPhase3SelectorContract_ArtifactWriterDetectionCatchesNonGoBuildOverwrite
// covers the review finding's other named bypass vector: a non-`go build`
// overwrite (a bare `cp`, standing in for `go install` + copy, or `mv`)
// chained after the tagged build in the same RUN instruction.
// classifyDockerfileHelperBuildLines is structurally blind to this — it
// only ever recognizes commands containing the substring "go build", by
// design (see its doc comment) — so this is exactly the gap
// dockerfileArtifactWriters exists to close, since commandWritesTo does not
// filter on command shape at all, only on output target.
func TestPhase3SelectorContract_ArtifactWriterDetectionCatchesNonGoBuildOverwrite(t *testing.T) {
	const sabotaged = "RUN CGO_ENABLED=0 go build -tags=phase3profile -o /out/ch-oauth-ldap ./cmd/ch-oauth-ldap && cp /legacy/ch-oauth-ldap /out/ch-oauth-ldap\n"
	writers := dockerfileArtifactWriters(sabotaged, phase3HelperArtifactPath)
	if len(writers) != 2 {
		t.Fatalf("dockerfileArtifactWriters: expected both the tagged go build and the trailing `cp` overwrite of %s to be detected, got %d: %v", phase3HelperArtifactPath, len(writers), writers)
	}
	sawGoBuild, sawCopy := false, false
	for _, w := range writers {
		switch {
		case strings.Contains(w, "go build"):
			sawGoBuild = true
		case strings.HasPrefix(w, "cp "):
			sawCopy = true
		}
	}
	if !sawGoBuild || !sawCopy {
		t.Fatalf("dockerfileArtifactWriters: expected one go-build writer and one cp writer, got: %v", writers)
	}
}

// TestPhase3SelectorContract_ArtifactWriterDetectionCatchesGoInstallOverwrite
// reproduces review pass 3's P1 finding exactly: a single Dockerfile RUN
// instruction that performs the required tagged `go build` and then, on the
// same physical line, silently overwrites /out/ch-oauth-ldap via
// `GOBIN=/out go install ./cmd/ch-oauth-ldap` — a genuinely realistic
// single-command sabotage, since `go install` has no `-o` flag at all.
// ChatGPT reproduced the prior helper's blindness to exactly this against
// the real pass-2 compound RUN (`all=1 tagged=1 other=0 writers=1`, meaning
// the trailing `go install` was invisible to both the `go build` classifier
// AND the old commandWritesTo). dockerfileArtifactWriters must now report
// both writers.
func TestPhase3SelectorContract_ArtifactWriterDetectionCatchesGoInstallOverwrite(t *testing.T) {
	const sabotaged = "RUN CGO_ENABLED=0 go build -tags=phase3profile -o /out/ch-oauth-ldap ./cmd/ch-oauth-ldap && GOBIN=/out go install ./cmd/ch-oauth-ldap\n"
	writers := dockerfileArtifactWriters(sabotaged, phase3HelperArtifactPath)
	if len(writers) != 2 {
		t.Fatalf("dockerfileArtifactWriters: expected both the tagged go build and the trailing `GOBIN=... go install` overwrite of %s to be detected, got %d: %v", phase3HelperArtifactPath, len(writers), writers)
	}
	sawGoBuild, sawGoInstall := false, false
	for _, w := range writers {
		switch {
		case strings.Contains(w, "go build"):
			sawGoBuild = true
		case strings.Contains(w, "go install"):
			sawGoInstall = true
		}
	}
	if !sawGoBuild || !sawGoInstall {
		t.Fatalf("dockerfileArtifactWriters: expected one go-build writer and one go-install writer, got: %v", writers)
	}
}

// TestCommandWritesTo_GoInstallGOBIN unit-tests goInstallWritesTo's token
// matching directly, including the negative cases a naive substring match
// would get wrong: a GOBIN value that merely has outputPath's directory as a
// prefix, and a `go install` of a different package under the same GOBIN.
func TestCommandWritesTo_GoInstallGOBIN(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    bool
	}{
		{"GOBIN dir and package basename match", "GOBIN=/out go install ./cmd/ch-oauth-ldap", true},
		{"env-prefixed form still matches", "env GOBIN=/out go install ./cmd/ch-oauth-ldap", true},
		{"different GOBIN dir does not match", "GOBIN=/elsewhere go install ./cmd/ch-oauth-ldap", false},
		{"GOBIN dir with outputPath's dir as a mere prefix does not match", "GOBIN=/out2 go install ./cmd/ch-oauth-ldap", false},
		{"go install of a different package does not match", "GOBIN=/out go install ./cmd/synthetic-idp", false},
		{"go install with no GOBIN does not match", "go install ./cmd/ch-oauth-ldap", false},
		{"plain go build with -o is unaffected by the new case", "go build -o /out/ch-oauth-ldap ./cmd/ch-oauth-ldap", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := commandWritesTo(tc.command, phase3HelperArtifactPath); got != tc.want {
				t.Fatalf("commandWritesTo(%q, %q) = %v, want %v", tc.command, phase3HelperArtifactPath, got, tc.want)
			}
		})
	}
}

// TestPhase3SelectorContract_IntegrationDockerfileRuntimeCopyIsSole requires
// integration/clickhouse/Dockerfile's runtime stage to contain EXACTLY ONE
// COPY instruction writing to /bin/ch-oauth-ldap, and requires that COPY to
// source it from /out/ch-oauth-ldap — the same build-stage path
// TestPhase3SelectorContract_IntegrationDockerfileTagsOnlyTheHelperBuild
// just proved has exactly one, tagged writer. Together the two tests bound
// both halves of the pipeline review pass 1's P1 finding identified as
// unbounded: what writes the tagged artifact, and what promotes it into
// the shipped image. The artifact-writer check alone cannot prove this half
// — it never inspects COPY instructions at all — and a Dockerfile could in
// principle build the one correct tagged binary yet still ship the wrong
// bits via a second COPY, or one sourcing a different build-stage path.
func TestPhase3SelectorContract_IntegrationDockerfileRuntimeCopyIsSole(t *testing.T) {
	content := readRepoFile(t, phase3IntegrationDockerfileRelPath)
	copies := dockerfileCopyInstructionsInto(content, phase3HelperRuntimePath)
	if len(copies) != 1 {
		t.Fatalf("phase3_selector_contract: expected exactly one COPY instruction writing to %s in %s (a second COPY, or a later one from a different source, would silently ship the wrong binary), found %d: %v",
			phase3HelperRuntimePath, phase3IntegrationDockerfileRelPath, len(copies), copies)
	}
	if sole := copies[0]; sole != phase3ExpectedRuntimeCopyInstruction {
		t.Fatalf("phase3_selector_contract: the sole COPY writing to %s in %s must be exactly %q (sourcing %s from the tagged build stage), got: %q",
			phase3HelperRuntimePath, phase3IntegrationDockerfileRelPath, phase3ExpectedRuntimeCopyInstruction, phase3HelperArtifactPath, sole)
	}
}

// TestPhase3SelectorContract_RuntimeCopyDetectionCatchesDuplicate reproduces
// the runtime-stage half of the same bypass class: two COPY instructions
// both targeting /bin/ch-oauth-ldap — the second sourcing, say, a stray
// legacy artifact left in the build stage — would ship whichever COPY
// Docker executes last, and Dockerfile COPY has no failure mode for
// "destination already exists" that would otherwise catch this.
// dockerfileCopyInstructionsInto must report both matches, not silently
// stop at the first.
func TestPhase3SelectorContract_RuntimeCopyDetectionCatchesDuplicate(t *testing.T) {
	const sabotaged = "COPY --from=build /out/ch-oauth-ldap /bin/ch-oauth-ldap\nCOPY --from=build /out/ch-oauth-ldap-legacy /bin/ch-oauth-ldap\n"
	copies := dockerfileCopyInstructionsInto(sabotaged, phase3HelperRuntimePath)
	if len(copies) != 2 {
		t.Fatalf("dockerfileCopyInstructionsInto: expected both duplicate COPY instructions into %s to be detected, got %d: %v", phase3HelperRuntimePath, len(copies), copies)
	}
}

// TestPhase3SelectorContract_RuntimeCopyDetectionRejectsWrongFromStage
// reproduces review pass 3's P1 finding's second point: the prior real
// check only asserted `strings.Contains(sole, phase3HelperArtifactPath)`,
// never that the sole COPY's `--from=` stage was the actual tagged build
// stage — so a COPY sourcing the identical build-stage path from a
// different, untagged stage (e.g. a leftover `--from=legacy`) would have
// satisfied it. This asserts the production check's real guard —
// phase3ExpectedRuntimeCopyInstruction equality — correctly rejects that
// shape even though the old substring check would not have.
func TestPhase3SelectorContract_RuntimeCopyDetectionRejectsWrongFromStage(t *testing.T) {
	const sabotaged = "COPY --from=legacy /out/ch-oauth-ldap /bin/ch-oauth-ldap\n"
	copies := dockerfileCopyInstructionsInto(sabotaged, phase3HelperRuntimePath)
	if len(copies) != 1 {
		t.Fatalf("dockerfileCopyInstructionsInto: expected exactly one COPY match in the sabotaged content, got %d: %v", len(copies), copies)
	}
	if !strings.Contains(copies[0], phase3HelperArtifactPath) {
		t.Fatalf("dockerfileCopyInstructionsInto: sabotage case must still source %s (that is what made the old substring check pass), got: %q", phase3HelperArtifactPath, copies[0])
	}
	if copies[0] == phase3ExpectedRuntimeCopyInstruction {
		t.Fatalf("dockerfileCopyInstructionsInto: sabotage case must NOT equal the expected exact instruction (its --from stage differs) — got an exact match, so the sabotage failed to reproduce the gap")
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

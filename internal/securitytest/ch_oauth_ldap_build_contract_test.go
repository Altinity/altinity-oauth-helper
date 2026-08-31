package securitytest

// This file implements issue #33 phase 4's permanent build-composition
// contract (plan "Permanent build-composition contract"). It is the direct
// successor of the retired phase3_selector_contract_test.go: that file's
// artifact-writer protection (what actually writes the integration helper's
// build artifact and what promotes it into the shipped image) is a genuine,
// permanent invariant this repository still needs — a Dockerfile sabotage
// that duplicates the helper build, chains a non-`go build` overwrite, or
// ships the wrong binary via a stray COPY/ADD is just as dangerous with a
// single untagged backend as it was with the temporary phase3profile
// selector. What the old file's tag-selection half proved (exactly one
// build carries -tags=phase3profile, and it is ch-oauth-ldap's) has no
// successor to prove, because there is no tag left to select: this file's
// job is only to prove the sole ch-oauth-ldap build is untagged, and that
// nothing downstream of it silently swaps in a second writer.
//
// Five assertions, each guarding a distinct invariant-map row:
//
//   - TestBuildContract_IntegrationDockerfileBuildsHelperOnceUntagged:
//     integration/clickhouse/Dockerfile contains EXACTLY ONE
//     `./cmd/ch-oauth-ldap` `go build` line, that line carries no -tags=
//     flag at all (in particular never phase3profile — see
//     assertFileNeverMentionsSelectorTag below), AND (unchanged from the
//     retired file) it is the ONLY instruction in the whole Dockerfile —
//     across both RUN shell sub-commands (commandWritesTo) and COPY/ADD
//     instructions (copyOrAddWritesTo) — that writes to the build stage's
//     /out/ch-oauth-ldap artifact path, and that sole writer is exactly
//     expectedHelperBuildCommand. See dockerfileArtifactWriters',
//     commandWritesTo's, and copyOrAddWritesTo's doc comments (carried
//     over verbatim from the retired file) for the exact sabotage
//     boundary this closes: a second `go build`, a `go install`
//     (including its GOBIN/directory-destination forms), a `cp`/`mv`
//     (including a directory destination), or a first-class COPY/ADD
//     (including its JSON-array form) all count as writers.
//   - TestBuildContract_IntegrationDockerfileRuntimeCopyIsSole: the
//     runtime-stage half of the same invariant — exactly one COPY
//     instruction writes the final image's /bin/ch-oauth-ldap, and that
//     COPY is exactly expectedRuntimeCopyInstruction — sourcing
//     /out/ch-oauth-ldap from the build stage by name, not merely a COPY
//     whose line happens to contain that path from some other `--from=`
//     stage.
//   - TestBuildContract_ProductionDockerfileNeverMentionsSelector: the
//     published Dockerfile.ch-oauth-ldap must never mention phase3profile
//     — retained as a permanent regression guard even though nothing
//     should ever reintroduce it.
//   - TestBuildContract_BuildScriptNeverMentionsSelector /
//     TestBuildContract_PublicationWorkflowNeverMentionsSelector: the same
//     guard over scripts/build-ch-oauth-ldap-image.sh and
//     .github/workflows/build-ch-oauth-ldap.yml.
//
// None of these run Docker, `docker build`, or any external process — they
// are plain string/instruction assertions over the checked-in files, in the
// same spirit as docs_contract_test.go's and pr_gate_contract_test.go's own
// workflow/Dockerfile text checks elsewhere in this package.
//
// The Dockerfile-parsing machinery below (dockerfileInstructions,
// dockerfileRunShellCommands, commandWritesTo, goInstallWritesTo,
// dockerfileArtifactWriters, copyOrAddDestination, copyOrAddWritesTo,
// dockerfileCopyInstructionsInto, readRepoFile) and every sabotage test
// exercising it are carried over from the retired phase3_selector_contract_
// test.go essentially unchanged — only the tag-bucketing half
// (classifyDockerfileHelperBuildLines' "tagged" bucket) is gone, since there
// is no longer a second, tagged build to distinguish from the sole one.

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// integrationDockerfileRelPath is the integration helper image's Dockerfile,
// relative to the module root.
const integrationDockerfileRelPath = "integration/clickhouse/Dockerfile"

// productionDockerfileRelPath is the published ch-oauth-ldap image's
// Dockerfile. It must never mention the retired phase3profile selector.
const productionDockerfileRelPath = "Dockerfile.ch-oauth-ldap"

// buildScriptRelPath is the manual multi-arch publication script for the
// ch-oauth-ldap image.
const buildScriptRelPath = "scripts/build-ch-oauth-ldap-image.sh"

// publicationWorkflowRelPath is the automated push-to-main publication
// workflow for the ch-oauth-ldap image.
const publicationWorkflowRelPath = ".github/workflows/build-ch-oauth-ldap.yml"

// retiredSelectorMarker is the retired issue #33 phase 3 compile-time
// selector. It must never reappear in any of the three files
// assertFileNeverMentionsSelectorTag checks below, and the integration
// Dockerfile's sole ch-oauth-ldap build must never carry it either — see
// TestBuildContract_IntegrationDockerfileBuildsHelperOnceUntagged. This is a
// permanent regression guard, a policy literal, not a stale reference to a
// live build tag (there is none).
const retiredSelectorMarker = "phase3profile"

// helperArtifactPath is the build-stage output path
// integration/clickhouse/Dockerfile's ch-oauth-ldap `go build` writes to. It
// must have exactly one writer in the whole Dockerfile.
const helperArtifactPath = "/out/ch-oauth-ldap"

// helperRuntimePath is the final runtime-stage path the build-stage artifact
// above is COPYed to in the shipped image.
const helperRuntimePath = "/bin/ch-oauth-ldap"

// expectedHelperBuildCommand is the exact shell command (RUN prefix
// stripped, as dockerfileRunShellCommands returns it) that must be the sole
// writer of helperArtifactPath in integrationDockerfileRelPath. Asserting
// exact equality is what makes this a real tuple assertion instead of
// independent substring checks that could each pass against an unrelated
// command.
const expectedHelperBuildCommand = `CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=integration-test" -o /out/ch-oauth-ldap ./cmd/ch-oauth-ldap`

// expectedRuntimeCopyInstruction is the exact COPY instruction that must be
// the sole write into helperRuntimePath in integrationDockerfileRelPath —
// including `--from=build`, so a COPY sourcing the same path from a
// different (hypothetical, stray) build stage is rejected.
const expectedRuntimeCopyInstruction = "COPY --from=build /out/ch-oauth-ldap /bin/ch-oauth-ldap"

// readRepoFile reads relPath relative to the module root, failing the test
// on any error — shared by every check in this file.
func readRepoFile(t *testing.T, relPath string) string {
	t.Helper()
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("build_contract: resolve module root: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relPath)))
	if err != nil {
		t.Fatalf("build_contract: read %s: %v", relPath, err)
	}
	return string(raw)
}

// assertFileNeverMentionsSelectorTag fails the test if relPath's content
// mentions the retired phase3profile selector anywhere — a permanent
// regression guard over the three publication-path files that must never
// select a build tag.
func assertFileNeverMentionsSelectorTag(t *testing.T, relPath string) {
	t.Helper()
	content := readRepoFile(t, relPath)
	if strings.Contains(content, retiredSelectorMarker) {
		t.Fatalf("build_contract: %s must never mention the retired selector %q", relPath, retiredSelectorMarker)
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
// `go build -o /out/x ./cmd/x && go build -o /out/x ./cmd/x` as the two
// separate commands Docker's shell actually runs in sequence, rather than as
// one opaque line that happens to contain the substrings being matched for.
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

// TestBuildContract_IntegrationDockerfileBuildsHelperOnceUntagged requires
// integration/clickhouse/Dockerfile to contain EXACTLY ONE
// `./cmd/ch-oauth-ldap` `go build` command overall, requires that command to
// carry no `-tags=` flag at all (in particular, never the retired
// phase3profile selector), and requires it to be the sole writer of
// /out/ch-oauth-ldap in the whole file — by ANY mechanism, not just another
// `go build` (see dockerfileArtifactWriters).
//
// The total-count check is deliberate: Docker executes RUN instructions (and,
// within one RUN, `&&`-chained commands) in order, and each writes to the
// same /out/ch-oauth-ldap path, so a second `./cmd/ch-oauth-ldap` build
// placed anywhere after the first — on its own line OR chained into the same
// RUN — would silently overwrite the intended binary before the final COPY.
//
// The `go build`-line classifier is structurally blind to any overwrite
// mechanism that is not itself a `go build` invocation — a chained
// `go install`, `cp`, or `mv` targeting the same output path would satisfy
// "exactly one go-build line" with zero matches. The artifact-writer check
// below closes that remaining gap by inspecting what actually writes to
// /out/ch-oauth-ldap, independent of how.
func TestBuildContract_IntegrationDockerfileBuildsHelperOnceUntagged(t *testing.T) {
	content := readRepoFile(t, integrationDockerfileRelPath)
	helperBuildLines := helperBuildCommands(content)

	if len(helperBuildLines) != 1 {
		t.Fatalf("build_contract: expected exactly one `./cmd/ch-oauth-ldap` `go build` command in %s, found %d: %v",
			integrationDockerfileRelPath, len(helperBuildLines), helperBuildLines)
	}
	if strings.Contains(helperBuildLines[0], "-tags=") {
		t.Fatalf("build_contract: the sole ch-oauth-ldap `go build` command in %s must be untagged, got: %q",
			integrationDockerfileRelPath, helperBuildLines[0])
	}

	// Bound the actual artifact writer, not just `go build` occurrences:
	// exactly one command in the whole Dockerfile may write to
	// /out/ch-oauth-ldap, by ANY mechanism — go build, go install, cp, mv, or
	// a first-class COPY/ADD — and that command must be exactly the build
	// proved above.
	writers := dockerfileArtifactWriters(content, helperArtifactPath)
	if len(writers) != 1 {
		t.Fatalf("build_contract: expected exactly one command writing to %s in %s (a second writer — another `go build`, a `go install`, `cp`, `mv`, or a COPY/ADD — would silently overwrite the binary before the runtime-stage COPY), found %d: %v",
			helperArtifactPath, integrationDockerfileRelPath, len(writers), writers)
	}
	if sole := writers[0]; sole != expectedHelperBuildCommand {
		t.Fatalf("build_contract: the sole writer of %s in %s must be exactly the expected helper build command, got: %q, want: %q",
			helperArtifactPath, integrationDockerfileRelPath, sole, expectedHelperBuildCommand)
	}
}

// helperBuildCommands scans every `go build` command in a Dockerfile's
// content — after dockerfileRunShellCommands has split each RUN instruction
// on its shell operators, so a `&&`-chained compound RUN line is seen as its
// constituent commands rather than one opaque line — and returns every
// `./cmd/ch-oauth-ldap` build command found, tagged or not. Extracted so
// TestBuildContract_ClassifierCatchesSecondUntaggedHelperBuild can exercise
// it directly against synthetic content, without needing a second
// checked-in Dockerfile fixture.
func helperBuildCommands(content string) []string {
	var found []string
	for _, command := range dockerfileRunShellCommands(dockerfileInstructions(content)) {
		if strings.Contains(command, "go build") && strings.Contains(command, "./cmd/ch-oauth-ldap") {
			found = append(found, command)
		}
	}
	return found
}

// commandWritesTo reports whether a single shell command's output target is
// outputPath: an `-o outputPath` flag (as used by both `go build` and `go
// install -o`), a `>`/`>>` shell redirect to outputPath, outputPath as the
// command's own last positional argument (the destination shape of
// `cp src dst`/`mv src dst`), a directory-destination form of that same
// `cp`/`mv` shape whose source argument's basename is outputPath's basename
// (`cp /legacy/ch-oauth-ldap /out/` overwrites outputPath just as
// effectively as the exact-file form, with or without a trailing slash on
// the directory), or a `go install` invocation GOBIN-redirected to
// outputPath's directory for a package whose import path's last element is
// outputPath's base name (see goInstallWritesTo). It deliberately does not
// care what the command otherwise is — that is exactly the point: it is the
// mechanism dockerfileArtifactWriters uses to catch an overwrite performed
// by something other than a recognizable `go build` invocation.
func commandWritesTo(command, outputPath string) bool {
	if strings.Contains(command, "-o "+outputPath) {
		return true
	}
	if strings.Contains(command, ">"+outputPath) || strings.Contains(command, "> "+outputPath) {
		return true
	}
	fields := strings.Fields(command)
	if len(fields) > 0 {
		dest := fields[len(fields)-1]
		if dest == outputPath {
			return true
		}
		// Directory-destination form of cp/mv (`cp src /out` or
		// `cp src /out/`): recognized only when the destination is exactly
		// outputPath's parent directory (trailing slash normalized away)
		// AND the command's source argument's basename is outputPath's
		// basename — otherwise a `cp foo /out/` writing some unrelated file
		// would false-positive as overwriting outputPath.
		dir, base := path.Dir(outputPath), path.Base(outputPath)
		if strings.TrimSuffix(dest, "/") == dir && len(fields) > 1 {
			if src := fields[len(fields)-2]; path.Base(src) == base {
				return true
			}
		}
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
// commandWritesTo's other shapes all miss this because the written path
// never appears verbatim in the command text — only its directory (as a
// GOBIN value) and its base name (as the package argument's last path
// element) do, separately. Matching is done on whitespace-separated tokens,
// not raw substring containment, so a GOBIN value that merely has
// outputPath's directory as a prefix (e.g. GOBIN=/out2) does not
// false-positive. The GOBIN value's own trailing slash is normalized away
// before comparison (`GOBIN=/out/ go install ./cmd/ch-oauth-ldap` is the
// identical overwrite as `GOBIN=/out`, and Go itself treats the two
// identically) — a normalization the surrounding prefix check does not
// otherwise weaken, since it still compares the full directory token, not a
// substring.
func goInstallWritesTo(command, outputPath string) bool {
	if !strings.Contains(command, "go install") {
		return false
	}
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return false
	}
	dir, base := path.Dir(outputPath), path.Base(outputPath)
	sawGOBIN := false
	for _, f := range fields {
		val, ok := strings.CutPrefix(f, "GOBIN=")
		if !ok {
			continue
		}
		if strings.TrimSuffix(val, "/") == dir {
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

// dockerfileArtifactWriters returns every instruction in content that writes
// to outputPath: every RUN sub-command commandWritesTo recognizes, plus
// every COPY/ADD instruction copyOrAddWritesTo recognizes. Unlike
// helperBuildCommands, which only ever recognizes `go build` commands, this
// function is blind to what kind of command or instruction it is — it
// exists specifically to catch a Dockerfile RUN that performs the required
// `go build` and then silently overwrites the binary via a NON-`go build`
// command (`go install`, `cp`, `mv`) chained into the same RUN, or via a
// first-class `COPY --from=<stage> <src> /out/ch-oauth-ldap` (or an `ADD`
// with that destination) — an instruction with its own destination syntax,
// not a shell command at all.
func dockerfileArtifactWriters(content, outputPath string) []string {
	instructions := dockerfileInstructions(content)
	var writers []string
	for _, command := range dockerfileRunShellCommands(instructions) {
		if commandWritesTo(command, outputPath) {
			writers = append(writers, command)
		}
	}
	for _, instr := range instructions {
		if copyOrAddWritesTo(instr, outputPath) {
			writers = append(writers, instr)
		}
	}
	return writers
}

// copyOrAddDestination extracts a single COPY or ADD instruction's
// destination argument, handling both of Dockerfile's instruction forms.
// isCopyOrAdd is false when instr is not a COPY/ADD instruction at all.
//
// In the ordinary shell form, the destination is the instruction's last
// whitespace-separated field (COPY/ADD's own syntax always puts it last,
// after any `--from=`/`--chown=` flags and every source argument).
//
// In Dockerfile's JSON-array ("exec") form — `COPY ["<src>", ...,
// "<dest>"]`, with the same optional flags preceding the bracket —
// whitespace-splitting is meaningless: for
// `COPY --from=legacy ["/legacy/ch-oauth-ldap", "/out/ch-oauth-ldap"]` the
// last whitespace-separated token is `"/out/ch-oauth-ldap"]`, quote and
// bracket still attached, which matches neither comparison a caller would
// make against a bare path. This form is detected by the presence of `[`
// anywhere in the instruction and decoded as JSON. malformed is true when
// the JSON-array form is present but fails to decode as a non-empty JSON
// string array: callers must treat that as "destination unknown, assume the
// worst" (a writer / a match) rather than silently reporting no destination
// — an unparseable-but-present exec-form array is exactly the shape that
// would otherwise let a COPY/ADD sabotage go undetected by this checker.
func copyOrAddDestination(instr string) (dest string, isCopyOrAdd, malformed bool) {
	if !strings.HasPrefix(instr, "COPY ") && !strings.HasPrefix(instr, "ADD ") {
		return "", false, false
	}
	if idx := strings.IndexByte(instr, '['); idx >= 0 {
		var elems []string
		if err := json.Unmarshal([]byte(instr[idx:]), &elems); err != nil || len(elems) == 0 {
			return "", true, true
		}
		return elems[len(elems)-1], true, false
	}
	fields := strings.Fields(instr)
	if len(fields) < 3 {
		// keyword + at least one source + one destination.
		return "", true, false
	}
	return fields[len(fields)-1], true, false
}

// copyOrAddWritesTo reports whether a single COPY or ADD Dockerfile
// instruction writes to outputPath — in either the shell form or the
// JSON-array ("exec") form; see copyOrAddDestination. Given a destination,
// this recognizes exactly two shapes: outputPath itself, or outputPath's
// parent directory written in trailing-slash directory-destination form
// (e.g. `COPY --from=legacy /legacy/ch-oauth-ldap /out/`). The second shape
// is deliberately coarse, not a path resolver: it flags ANY COPY/ADD landing
// directly in outputPath's parent directory, regardless of what the source
// is actually named, rather than computing the resulting filename from the
// source's basename. A COPY/ADD into any deeper subdirectory, or one whose
// effect on outputPath depends on a later RUN `mv`/symlink, is out of scope.
// A JSON-array form that fails to parse is treated as a writer
// unconditionally (fail closed), regardless of outputPath.
func copyOrAddWritesTo(instr, outputPath string) bool {
	dest, isCopyOrAdd, malformed := copyOrAddDestination(instr)
	if !isCopyOrAdd {
		return false
	}
	if malformed {
		return true
	}
	return dest == outputPath || dest == path.Dir(outputPath)+"/"
}

// dockerfileCopyInstructionsInto returns every COPY instruction in content
// whose destination is exactly destPath — recognizing both the shell form
// and the JSON-array form (see copyOrAddDestination). A COPY whose
// JSON-array destination fails to parse is included unconditionally (fail
// closed): this function backs the runtime-stage "exactly one COPY writes
// here" check, so an unparseable exec-form COPY must count as a possible
// second writer rather than being silently invisible to it.
func dockerfileCopyInstructionsInto(content, destPath string) []string {
	var matches []string
	for _, instr := range dockerfileInstructions(content) {
		if !strings.HasPrefix(instr, "COPY ") {
			continue
		}
		dest, isCopyOrAdd, malformed := copyOrAddDestination(instr)
		if !isCopyOrAdd {
			continue
		}
		if malformed || dest == destPath {
			matches = append(matches, instr)
		}
	}
	return matches
}

// TestBuildContract_ClassifierCatchesSecondUntaggedHelperBuild is the
// sabotage case for the total-count check above: two
// `./cmd/ch-oauth-ldap` build lines, both untagged, must both be counted so
// the real contract's `len(helperBuildLines) != 1` guard catches the second
// one.
func TestBuildContract_ClassifierCatchesSecondUntaggedHelperBuild(t *testing.T) {
	const sabotaged = `RUN CGO_ENABLED=0 go build -o /out/ch-oauth-ldap ./cmd/ch-oauth-ldap
RUN CGO_ENABLED=0 go build -o /out/ch-oauth-ldap ./cmd/ch-oauth-ldap
`
	found := helperBuildCommands(sabotaged)
	if len(found) != 2 {
		t.Fatalf("helperBuildCommands: expected both `./cmd/ch-oauth-ldap` build lines to be counted, got %d: %v", len(found), found)
	}
}

// TestBuildContract_ArtifactWriterDetectionCatchesCompoundRunOverwrite
// reproduces a single Dockerfile RUN instruction that performs the required
// `go build` and then, `&&`-chained on the SAME physical line, silently
// overwrites /out/ch-oauth-ldap with a second `go build`. Split on "\n" this
// is one line containing "go build" twice — dockerfileArtifactWriters, built
// on dockerfileRunShellCommands' `&&`-aware split, must see it as two
// separate writers of the same path.
func TestBuildContract_ArtifactWriterDetectionCatchesCompoundRunOverwrite(t *testing.T) {
	const sabotaged = "RUN CGO_ENABLED=0 go build -o /out/ch-oauth-ldap ./cmd/ch-oauth-ldap && CGO_ENABLED=0 go build -o /out/ch-oauth-ldap ./cmd/other\n"
	writers := dockerfileArtifactWriters(sabotaged, helperArtifactPath)
	if len(writers) != 2 {
		t.Fatalf("dockerfileArtifactWriters: expected the compound RUN's two writers of %s to both be detected, got %d: %v", helperArtifactPath, len(writers), writers)
	}
}

// TestBuildContract_ArtifactWriterDetectionCatchesNonGoBuildOverwrite covers
// a non-`go build` overwrite (a bare `cp`, standing in for `go install` +
// copy, or `mv`) chained after the build in the same RUN instruction.
// helperBuildCommands is structurally blind to this — it only ever
// recognizes commands containing the substring "go build" — so this is
// exactly the gap dockerfileArtifactWriters exists to close, since
// commandWritesTo does not filter on command shape at all, only on output
// target.
func TestBuildContract_ArtifactWriterDetectionCatchesNonGoBuildOverwrite(t *testing.T) {
	const sabotaged = "RUN CGO_ENABLED=0 go build -o /out/ch-oauth-ldap ./cmd/ch-oauth-ldap && cp /legacy/ch-oauth-ldap /out/ch-oauth-ldap\n"
	writers := dockerfileArtifactWriters(sabotaged, helperArtifactPath)
	if len(writers) != 2 {
		t.Fatalf("dockerfileArtifactWriters: expected both the go build and the trailing `cp` overwrite of %s to be detected, got %d: %v", helperArtifactPath, len(writers), writers)
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

// TestBuildContract_ArtifactWriterDetectionCatchesGoInstallOverwrite
// reproduces a single Dockerfile RUN instruction that performs the required
// `go build` and then, on the same physical line, silently overwrites
// /out/ch-oauth-ldap via `GOBIN=/out go install ./cmd/ch-oauth-ldap` — a
// genuinely realistic single-command sabotage, since `go install` has no
// `-o` flag at all. dockerfileArtifactWriters must report both writers.
func TestBuildContract_ArtifactWriterDetectionCatchesGoInstallOverwrite(t *testing.T) {
	const sabotaged = "RUN CGO_ENABLED=0 go build -o /out/ch-oauth-ldap ./cmd/ch-oauth-ldap && GOBIN=/out go install ./cmd/ch-oauth-ldap\n"
	writers := dockerfileArtifactWriters(sabotaged, helperArtifactPath)
	if len(writers) != 2 {
		t.Fatalf("dockerfileArtifactWriters: expected both the go build and the trailing `GOBIN=... go install` overwrite of %s to be detected, got %d: %v", helperArtifactPath, len(writers), writers)
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
			if got := commandWritesTo(tc.command, helperArtifactPath); got != tc.want {
				t.Fatalf("commandWritesTo(%q, %q) = %v, want %v", tc.command, helperArtifactPath, got, tc.want)
			}
		})
	}
}

// TestCommandWritesTo_DirectoryDestinationNormalization covers both a
// `cp`/`mv` directory destination (with or without a trailing slash) and a
// `GOBIN=` directory value with a trailing slash, which must both still be
// detected because the checks compare normalized directory tokens, not
// exact-string equality against outputPath (or the untrimmed GOBIN token).
// Includes the negative case a careless normalization would get wrong: a
// directory-destination cp/mv whose source is unrelated to outputPath's
// basename must NOT be treated as a writer merely because it lands in the
// same directory.
func TestCommandWritesTo_DirectoryDestinationNormalization(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    bool
	}{
		{"cp into directory destination with trailing slash matches", "cp /legacy/ch-oauth-ldap /out/", true},
		{"cp into directory destination without trailing slash matches", "cp /legacy/ch-oauth-ldap /out", true},
		{"mv into directory destination with trailing slash matches", "mv /legacy/ch-oauth-ldap /out/", true},
		{"cp into directory destination with an unrelated source does not match", "cp /legacy/other-binary /out/", false},
		{"GOBIN with trailing slash still matches", "GOBIN=/out/ go install ./cmd/ch-oauth-ldap", true},
		{"GOBIN with trailing slash and different package does not match", "GOBIN=/out/ go install ./cmd/synthetic-idp", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := commandWritesTo(tc.command, helperArtifactPath); got != tc.want {
				t.Fatalf("commandWritesTo(%q, %q) = %v, want %v", tc.command, helperArtifactPath, got, tc.want)
			}
		})
	}
}

// TestBuildContract_ArtifactWriterDetectionCatchesDirectoryDestinationOverwrite
// uses a compound example: a `go build` in one RUN, followed by a second RUN
// chaining an untagged `GOBIN=/legacy go install` (which writes
// /legacy/ch-oauth-ldap, NOT outputPath — it must not be counted) into a
// `cp /legacy/ch-oauth-ldap /out/` directory-destination overwrite of
// outputPath (which must be counted).
func TestBuildContract_ArtifactWriterDetectionCatchesDirectoryDestinationOverwrite(t *testing.T) {
	const sabotaged = "RUN CGO_ENABLED=0 go build -o /out/ch-oauth-ldap ./cmd/ch-oauth-ldap\n" +
		"RUN CGO_ENABLED=0 GOBIN=/legacy go install ./cmd/ch-oauth-ldap && cp /legacy/ch-oauth-ldap /out/\n"
	writers := dockerfileArtifactWriters(sabotaged, helperArtifactPath)
	if len(writers) != 2 {
		t.Fatalf("dockerfileArtifactWriters: expected both the go build and the trailing directory-destination `cp` overwrite of %s to be detected, got %d: %v", helperArtifactPath, len(writers), writers)
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
		t.Fatalf("dockerfileArtifactWriters: expected one go-build writer and one directory-destination cp writer, got: %v", writers)
	}
}

// TestBuildContract_ArtifactWriterDetectionCatchesCopyOverwrite reproduces a
// first-class Dockerfile `COPY --from=legacy /legacy/ch-oauth-ldap
// /out/ch-oauth-ldap` (an `ADD` with the same destination is equivalent)
// placed after the canonical `go build`, replacing the intermediate
// artifact. dockerfileArtifactWriters only ever scanned RUN instructions'
// shell sub-commands until copyOrAddWritesTo was added, so this COPY was
// previously invisible to it.
func TestBuildContract_ArtifactWriterDetectionCatchesCopyOverwrite(t *testing.T) {
	const sabotaged = "RUN CGO_ENABLED=0 go build -o /out/ch-oauth-ldap ./cmd/ch-oauth-ldap\n" +
		"COPY --from=legacy /legacy/ch-oauth-ldap /out/ch-oauth-ldap\n"
	writers := dockerfileArtifactWriters(sabotaged, helperArtifactPath)
	if len(writers) != 2 {
		t.Fatalf("dockerfileArtifactWriters: expected both the go build and the trailing COPY overwrite of %s to be detected, got %d: %v", helperArtifactPath, len(writers), writers)
	}
	sawGoBuild, sawCopy := false, false
	for _, w := range writers {
		switch {
		case strings.Contains(w, "go build"):
			sawGoBuild = true
		case strings.HasPrefix(w, "COPY "):
			sawCopy = true
		}
	}
	if !sawGoBuild || !sawCopy {
		t.Fatalf("dockerfileArtifactWriters: expected one go-build writer and one COPY writer, got: %v", writers)
	}
}

// TestBuildContract_ArtifactWriterDetectionCatchesJSONArrayCopyOverwrite
// reproduces a COPY (an ADD is equivalent) written in Dockerfile's
// JSON-array ("exec") form — `COPY --from=legacy ["/legacy/ch-oauth-ldap",
// "/out/ch-oauth-ldap"]` — placed after the canonical `go build`. Before
// copyOrAddDestination parsed the JSON-array form, copyOrAddWritesTo's
// `strings.Fields(instr)` last-token logic computed
// `"/out/ch-oauth-ldap"]` (quote and closing bracket still attached), which
// matched neither outputPath nor its trailing-slash directory form.
func TestBuildContract_ArtifactWriterDetectionCatchesJSONArrayCopyOverwrite(t *testing.T) {
	const sabotaged = "RUN CGO_ENABLED=0 go build -o /out/ch-oauth-ldap ./cmd/ch-oauth-ldap\n" +
		`COPY --from=legacy ["/legacy/ch-oauth-ldap", "/out/ch-oauth-ldap"]` + "\n"
	writers := dockerfileArtifactWriters(sabotaged, helperArtifactPath)
	if len(writers) != 2 {
		t.Fatalf("dockerfileArtifactWriters: expected both the go build and the trailing JSON-array COPY overwrite of %s to be detected, got %d: %v", helperArtifactPath, len(writers), writers)
	}
	sawGoBuild, sawCopy := false, false
	for _, w := range writers {
		switch {
		case strings.Contains(w, "go build"):
			sawGoBuild = true
		case strings.HasPrefix(w, "COPY "):
			sawCopy = true
		}
	}
	if !sawGoBuild || !sawCopy {
		t.Fatalf("dockerfileArtifactWriters: expected one go-build writer and one JSON-array COPY writer, got: %v", writers)
	}
}

// TestCopyOrAddWritesTo unit-tests copyOrAddWritesTo's destination matching
// directly, including the ADD form, the trailing-slash directory-destination
// form, the JSON-array ("exec") form (with and without a preceding
// `--from=` flag), the fail-closed behavior for a malformed JSON-array
// instruction, and the negative cases that prove it does not over-match a
// COPY/ADD that does not target /out/ch-oauth-ldap at all.
func TestCopyOrAddWritesTo(t *testing.T) {
	cases := []struct {
		name  string
		instr string
		want  bool
	}{
		{"COPY exact destination match", "COPY --from=legacy /legacy/ch-oauth-ldap /out/ch-oauth-ldap", true},
		{"ADD exact destination match", "ADD --from=legacy /legacy/ch-oauth-ldap /out/ch-oauth-ldap", true},
		{"COPY trailing-slash directory destination match", "COPY --from=legacy /legacy/ch-oauth-ldap /out/", true},
		{"the real runtime COPY (different destination) does not match", expectedRuntimeCopyInstruction, false},
		{"COPY into an unrelated directory does not match", "COPY --from=legacy /legacy/ch-oauth-ldap /elsewhere/ch-oauth-ldap", false},
		{"COPY into a deeper subdirectory of /out does not match (out of scope by design)", "COPY --from=legacy /legacy/ch-oauth-ldap /out/nested/ch-oauth-ldap", false},
		{"a RUN instruction is not a COPY/ADD at all", expectedHelperBuildCommand, false},
		{"JSON-array COPY with --from= exact destination match", `COPY --from=legacy ["/legacy/ch-oauth-ldap", "/out/ch-oauth-ldap"]`, true},
		{"JSON-array ADD exact destination match", `ADD ["/legacy/ch-oauth-ldap", "/out/ch-oauth-ldap"]`, true},
		{"JSON-array COPY trailing-slash directory destination match", `COPY --from=legacy ["/legacy/ch-oauth-ldap", "/out/"]`, true},
		{"JSON-array COPY into an unrelated directory does not match", `COPY --from=legacy ["/legacy/ch-oauth-ldap", "/elsewhere/ch-oauth-ldap"]`, false},
		{"malformed JSON-array COPY fails closed (reported as a writer)", `COPY --from=legacy ["/legacy/ch-oauth-ldap", "/out/ch-oauth-ldap"`, true},
		{"empty JSON-array COPY fails closed (reported as a writer)", `COPY []`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := copyOrAddWritesTo(tc.instr, helperArtifactPath); got != tc.want {
				t.Fatalf("copyOrAddWritesTo(%q, %q) = %v, want %v", tc.instr, helperArtifactPath, got, tc.want)
			}
		})
	}
}

// TestBuildContract_RealDockerfileHasNoCopyOrAddArtifactWriters is the
// negative control: it proves the real, checked-in
// integration/clickhouse/Dockerfile genuinely contains zero COPY/ADD
// instructions writing to /out/ch-oauth-ldap, rather than merely happening
// to pass the count/equality assertions in
// TestBuildContract_IntegrationDockerfileBuildsHelperOnceUntagged for some
// other reason.
func TestBuildContract_RealDockerfileHasNoCopyOrAddArtifactWriters(t *testing.T) {
	content := readRepoFile(t, integrationDockerfileRelPath)
	for _, instr := range dockerfileInstructions(content) {
		if copyOrAddWritesTo(instr, helperArtifactPath) {
			t.Fatalf("build_contract: unexpected COPY/ADD writer of %s in the real Dockerfile: %q", helperArtifactPath, instr)
		}
	}
}

// TestBuildContract_IntegrationDockerfileRuntimeCopyIsSole requires
// integration/clickhouse/Dockerfile's runtime stage to contain EXACTLY ONE
// COPY instruction writing to /bin/ch-oauth-ldap, and requires that COPY to
// source it from /out/ch-oauth-ldap — the same build-stage path
// TestBuildContract_IntegrationDockerfileBuildsHelperOnceUntagged just
// proved has exactly one writer. Together the two tests bound both halves of
// the pipeline: what writes the artifact, and what promotes it into the
// shipped image.
func TestBuildContract_IntegrationDockerfileRuntimeCopyIsSole(t *testing.T) {
	content := readRepoFile(t, integrationDockerfileRelPath)
	copies := dockerfileCopyInstructionsInto(content, helperRuntimePath)
	if len(copies) != 1 {
		t.Fatalf("build_contract: expected exactly one COPY instruction writing to %s in %s (a second COPY, or a later one from a different source, would silently ship the wrong binary), found %d: %v",
			helperRuntimePath, integrationDockerfileRelPath, len(copies), copies)
	}
	if sole := copies[0]; sole != expectedRuntimeCopyInstruction {
		t.Fatalf("build_contract: the sole COPY writing to %s in %s must be exactly %q (sourcing %s from the build stage), got: %q",
			helperRuntimePath, integrationDockerfileRelPath, expectedRuntimeCopyInstruction, helperArtifactPath, sole)
	}
}

// TestBuildContract_RuntimeCopyDetectionCatchesDuplicate reproduces the
// runtime-stage half of the same bypass class: two COPY instructions both
// targeting /bin/ch-oauth-ldap — the second sourcing, say, a stray artifact
// left in the build stage — would ship whichever COPY Docker executes last,
// and Dockerfile COPY has no failure mode for "destination already exists"
// that would otherwise catch this. dockerfileCopyInstructionsInto must
// report both matches, not silently stop at the first.
func TestBuildContract_RuntimeCopyDetectionCatchesDuplicate(t *testing.T) {
	const sabotaged = "COPY --from=build /out/ch-oauth-ldap /bin/ch-oauth-ldap\nCOPY --from=build /out/ch-oauth-ldap-other /bin/ch-oauth-ldap\n"
	copies := dockerfileCopyInstructionsInto(sabotaged, helperRuntimePath)
	if len(copies) != 2 {
		t.Fatalf("dockerfileCopyInstructionsInto: expected both duplicate COPY instructions into %s to be detected, got %d: %v", helperRuntimePath, len(copies), copies)
	}
}

// TestBuildContract_RuntimeCopyDetectionCatchesJSONArrayDuplicate reproduces
// the same fields[-1]-on-whitespace bypass that let a JSON-array COPY hide
// from the build-stage artifact-writer check (see
// TestBuildContract_ArtifactWriterDetectionCatchesJSONArrayCopyOverwrite)
// also defeating dockerfileCopyInstructionsInto, which backs the
// final-image "exactly one COPY writes /bin/ch-oauth-ldap" check.
func TestBuildContract_RuntimeCopyDetectionCatchesJSONArrayDuplicate(t *testing.T) {
	const sabotaged = "COPY --from=build /out/ch-oauth-ldap /bin/ch-oauth-ldap\n" +
		`COPY --from=build ["/out/ch-oauth-ldap-other", "/bin/ch-oauth-ldap"]` + "\n"
	copies := dockerfileCopyInstructionsInto(sabotaged, helperRuntimePath)
	if len(copies) != 2 {
		t.Fatalf("dockerfileCopyInstructionsInto: expected both the shell-form and JSON-array-form COPY instructions into %s to be detected, got %d: %v", helperRuntimePath, len(copies), copies)
	}
}

// TestBuildContract_RuntimeCopyDetectionRejectsWrongFromStage proves the
// production check's real guard — expectedRuntimeCopyInstruction equality —
// correctly rejects a COPY sourcing the identical build-stage path from a
// different, unexpected stage (e.g. a leftover `--from=legacy`), which a
// mere substring check on helperArtifactPath would not reject.
func TestBuildContract_RuntimeCopyDetectionRejectsWrongFromStage(t *testing.T) {
	const sabotaged = "COPY --from=legacy /out/ch-oauth-ldap /bin/ch-oauth-ldap\n"
	copies := dockerfileCopyInstructionsInto(sabotaged, helperRuntimePath)
	if len(copies) != 1 {
		t.Fatalf("dockerfileCopyInstructionsInto: expected exactly one COPY match in the sabotaged content, got %d: %v", len(copies), copies)
	}
	if !strings.Contains(copies[0], helperArtifactPath) {
		t.Fatalf("dockerfileCopyInstructionsInto: sabotage case must still source %s (that is what made a mere substring check pass), got: %q", helperArtifactPath, copies[0])
	}
	if copies[0] == expectedRuntimeCopyInstruction {
		t.Fatalf("dockerfileCopyInstructionsInto: sabotage case must NOT equal the expected exact instruction (its --from stage differs) — got an exact match, so the sabotage failed to reproduce the gap")
	}
}

// TestBuildContract_ProductionDockerfileNeverMentionsSelector requires
// Dockerfile.ch-oauth-ldap — the published production image's own
// Dockerfile — to never mention the retired phase3profile selector.
func TestBuildContract_ProductionDockerfileNeverMentionsSelector(t *testing.T) {
	assertFileNeverMentionsSelectorTag(t, productionDockerfileRelPath)
}

// TestBuildContract_BuildScriptNeverMentionsSelector requires
// scripts/build-ch-oauth-ldap-image.sh — the manual multi-arch publication
// path — to never mention the retired phase3profile selector.
func TestBuildContract_BuildScriptNeverMentionsSelector(t *testing.T) {
	assertFileNeverMentionsSelectorTag(t, buildScriptRelPath)
}

// TestBuildContract_PublicationWorkflowNeverMentionsSelector requires
// .github/workflows/build-ch-oauth-ldap.yml — the automated push-to-main
// publication workflow — to never mention the retired phase3profile
// selector.
func TestBuildContract_PublicationWorkflowNeverMentionsSelector(t *testing.T) {
	assertFileNeverMentionsSelectorTag(t, publicationWorkflowRelPath)
}

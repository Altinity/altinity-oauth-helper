package securitytest

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

const dependabotConfigRelPath = ".github/dependabot.yml"

// TestDependabotContract_GitHubActionsWeeklyAtRoot keeps Dependabot watching
// every workflow in .github/workflows. The PR gate pins its actions to commit
// SHAs and depends on its version comments staying current; without this
// entry, those pins can silently become stale.
func TestDependabotContract_GitHubActionsWeeklyAtRoot(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("dependabot contract: locate module root: %v", err)
	}
	path := filepath.Join(root, filepath.FromSlash(dependabotConfigRelPath))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("dependabot contract: read %s: %v", dependabotConfigRelPath, err)
	}

	var config struct {
		Version int `yaml:"version"`
		Updates []struct {
			PackageEcosystem string `yaml:"package-ecosystem"`
			Directory        string `yaml:"directory"`
			Schedule         struct {
				Interval string `yaml:"interval"`
			} `yaml:"schedule"`
		} `yaml:"updates"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatalf("dependabot contract: parse %s: %v", dependabotConfigRelPath, err)
	}
	if config.Version != 2 {
		t.Fatalf("dependabot contract: %s version = %d, want 2", dependabotConfigRelPath, config.Version)
	}

	found := 0
	for _, update := range config.Updates {
		if update.PackageEcosystem != "github-actions" {
			continue
		}
		found++
		if update.Directory != "/" || update.Schedule.Interval != "weekly" {
			t.Errorf("dependabot contract: github-actions entry = directory %q, interval %q; want root directory and weekly checks", update.Directory, update.Schedule.Interval)
		}
	}
	if found != 1 {
		t.Fatalf("dependabot contract: found %d github-actions entries in %s, want exactly 1 root weekly entry", found, dependabotConfigRelPath)
	}
}

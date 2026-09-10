package testredis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSQLTenantRuntimeCIInstallsRedisBeforeBroadTests(t *testing.T) {
	for _, name := range []string{"release.yml", "workload-identity.yml"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", name))
			if err != nil {
				t.Fatal(err)
			}
			var workflow struct {
				Jobs map[string]struct {
					Steps []struct {
						Run string `yaml:"run"`
					} `yaml:"steps"`
				} `yaml:"jobs"`
			}
			if err := yaml.Unmarshal(raw, &workflow); err != nil {
				t.Fatal(err)
			}
			found := false
			for job, config := range workflow.Jobs {
				installed := false
				for _, step := range config.Steps {
					if strings.Contains(step.Run, "apt-get install") && strings.Contains(step.Run, "redis-server") {
						installed = true
					}
					if strings.Contains(step.Run, "go test ") && strings.Contains(step.Run, "./...") {
						found = true
						if !installed {
							t.Errorf("job %s runs real Redis contract tests before installing redis-server", job)
						}
					}
				}
			}
			if !found {
				t.Fatal("workflow no longer executes the expected full test suite")
			}
		})
	}
}

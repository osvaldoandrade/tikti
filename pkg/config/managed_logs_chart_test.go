package config

import (
	"os/exec"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestManagedLogsHelmContract(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is verified by the chart job")
	}
	for _, enabled := range []bool{false, true} {
		args := []string{"template", "logs-contract", "../../helm/tikti"}
		if enabled {
			args = append(args, "--set", "config.workloadIdentity.managedLogs.enabled=true", "--set", "config.issuerBaseUrl=https://tikti.example.test", "--set", "config.workloadIdentity.managedLogs.authorityUrl=http://code-admin-api.code-admin.svc.cluster.local:8080/internal/v1/logs-grants:authorize", "--set-json", `config.workloadIdentity.providers=[{"clusterRef":"conveste-hostgator","issuer":"https://kubernetes.default.svc.cluster.local","jwksUrl":"https://kubernetes.default.svc.cluster.local/keys"}]`)
		}
		raw, err := exec.Command("helm", args...).Output()
		if err != nil {
			t.Fatal("chart refused bounded Logs exchange configuration")
		}
		d := yaml.NewDecoder(strings.NewReader(string(raw)))
		found := false
		for {
			var object map[string]any
			if d.Decode(&object) != nil {
				break
			}
			if object == nil || object["kind"] != "ConfigMap" {
				continue
			}
			body, _ := object["data"].(map[string]any)["tikti.yaml"].(string)
			if body == "" {
				continue
			}
			var cfg Config
			if err = yaml.Unmarshal([]byte(body), &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.WorkloadIdentity.ManagedLogs.Enabled != enabled {
				t.Fatal("chart omitted Logs exchange flag")
			}
			if enabled && cfg.ValidateManagedLogs() != nil {
				t.Fatal("rendered Logs exchange cannot start")
			}
			found = true
		}
		if !found {
			t.Fatal("Tikti configuration not rendered")
		}
	}
}
